//! The check API (`--check-api`): one prompt or answer in, the route's
//! verdict out, as the npm package calls it.

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use http::{header, Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde_json::{json, Value};

async fn start(token: Option<&str>, check_api: bool) -> SocketAddr {
    let config = pw_mock_upstream::Config {
        delay: Duration::ZERO,
        ..Default::default()
    };
    let mock = pw_mock_upstream::spawn("127.0.0.1:0".parse().unwrap(), config)
        .await
        .unwrap();
    let yaml = format!(
        r#"
version: 1
upstreams: {{ mock: {{ url: "http://{mock}" }} }}
routes:
  - name: default
    upstream: mock
    input:
      - {{ detector: secrets, action: block }}
      - {{ detector: pii, entities: [email], action: redact }}
    output:
      - {{ detector: pii, entities: [email], action: redact }}
  - name: other
    upstream: mock
"#
    );
    let proxy =
        promptwall::Proxy::with_policy(promptwall::Policy::from_yaml(&yaml).unwrap()).unwrap();
    if check_api {
        proxy.enable_check_api(token.map(str::to_owned));
    }
    let (listener, addr) = promptwall::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    tokio::spawn(proxy.serve(listener, std::future::pending()));
    addr
}

async fn call(proxy: SocketAddr, token: Option<&str>, body: Value) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{proxy}{}", promptwall::CHECK_PATH))
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = token {
        req = req.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let req = req.body(Full::new(Bytes::from(body.to_string()))).unwrap();
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(HttpConnector::new());
    let resp = client.request(req).await.unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

#[tokio::test]
async fn returns_the_verdict_of_a_route() {
    let proxy = start(None, true).await;
    let (status, v) = call(proxy, None, json!({"text": "mail jane@corp.io"})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["route"], "default");
    assert_eq!(v["action"], "redact");
    assert_eq!(v["text"], "mail [REDACTED:EMAIL]");
    assert_eq!(v["findings"]["pii.email"], 1);

    let (_, v) = call(
        proxy,
        None,
        json!({"direction": "output", "text": "it is jane@corp.io"}),
    )
    .await;
    assert_eq!(v["text"], "it is [REDACTED:EMAIL]");

    // A blocked prompt is still a successful check.
    let (status, v) = call(
        proxy,
        None,
        json!({"text": "key AKIAIOSFODNN7EXAMPLE", "route": "default"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["action"], "block");

    let (_, v) = call(proxy, None, json!({"text": "hi", "route": "other"})).await;
    assert_eq!(v["action"], Value::Null);

    let (status, _) = call(proxy, None, json!({"text": "hi", "route": "nope"})).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = call(proxy, None, json!({"txt": "hi"})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn needs_the_token_when_one_is_set() {
    let proxy = start(Some("s3cret"), true).await;
    let (status, _) = call(proxy, None, json!({"text": "hi"})).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = call(proxy, Some("wrong"), json!({"text": "hi"})).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = call(proxy, Some("s3cret"), json!({"text": "hi"})).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn is_off_unless_turned_on() {
    // The path is then an ordinary request, forwarded to the provider.
    let proxy = start(None, false).await;
    let (_, v) = call(proxy, None, json!({"text": "hi"})).await;
    assert!(v.get("action").is_none(), "{v}");
}
