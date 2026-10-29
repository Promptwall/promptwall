use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use http::{header, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde_json::Value;

const OPENAI_KEY: &str = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz012345";

async fn start_mock() -> SocketAddr {
    let config = pw_mock_upstream::Config {
        delay: Duration::ZERO,
        ..Default::default()
    };
    pw_mock_upstream::spawn("127.0.0.1:0".parse().unwrap(), config)
        .await
        .unwrap()
}

/// A port with nothing listening: a request forwarded there would get a 502.
fn closed_port() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

async fn start_proxy(yaml: &str) -> SocketAddr {
    let policy = promptwall::Policy::from_yaml(yaml).unwrap();
    let proxy = promptwall::Proxy::with_policy(policy).unwrap();
    let (listener, addr) = promptwall::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    tokio::spawn(proxy.serve(listener, std::future::pending()));
    addr
}

fn policy(upstream: SocketAddr, route_extra: &str) -> String {
    format!(
        r#"
version: 1
upstreams:
  mock: {{ url: "http://{upstream}" }}
routes:
  - name: chat
    upstream: mock
{route_extra}
    input:
      - detector: secrets
        action: block
      - detector: pii
        entities: [email, iban]
        action: redact
      - detector: pii
        entities: [phone]
        action: flag
"#
    )
}

async fn send(proxy: SocketAddr, content: &str, headers: &[(&str, &str)]) -> Response<Incoming> {
    let body = serde_json::json!({
        "model": "mock",
        "messages": [{"role": "user", "content": content}],
    });
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{proxy}/v1/chat/completions"))
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-echo-body", "1");
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(HttpConnector::new());
    client
        .request(req.body(Full::new(Bytes::from(body.to_string()))).unwrap())
        .await
        .unwrap()
}

async fn json(resp: Response<Incoming>) -> Value {
    serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

fn action(resp: &Response<Incoming>) -> Option<&str> {
    resp.headers()
        .get("x-promptwall-action")
        .map(|v| v.to_str().unwrap())
}

#[tokio::test]
async fn redacts_pii_before_it_reaches_the_upstream() {
    let proxy = start_proxy(&policy(start_mock().await, "")).await;

    let resp = send(
        proxy,
        "I am jane@example.com, IBAN DE89 3704 0044 0532 0130 00",
        &[],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(action(&resp), Some("redact"));
    let seen = json(resp).await;
    assert_eq!(
        seen["messages"][0]["content"],
        "I am [REDACTED:EMAIL], IBAN [REDACTED:IBAN]"
    );
}

#[tokio::test]
async fn blocks_secrets_without_contacting_the_upstream() {
    let proxy = start_proxy(&policy(closed_port(), "")).await;

    let resp = send(proxy, &format!("my key is {OPENAI_KEY}"), &[]).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(action(&resp), Some("block"));
    let err = json(resp).await;
    assert_eq!(err["error"]["type"], "promptwall_policy_violation");
    assert_eq!(
        err["error"]["findings"],
        serde_json::json!(["secret.openai_key"])
    );
    assert!(
        !err.to_string().contains(OPENAI_KEY),
        "the secret must not be echoed back"
    );
}

#[tokio::test]
async fn flags_without_changing_the_request() {
    let proxy = start_proxy(&policy(start_mock().await, "")).await;

    let resp = send(proxy, "call +49 151 23456789", &[]).await;
    assert_eq!(action(&resp), Some("flag"));
    assert_eq!(
        json(resp).await["messages"][0]["content"],
        "call +49 151 23456789"
    );
}

#[tokio::test]
async fn clean_requests_pass_unchanged() {
    let proxy = start_proxy(&policy(start_mock().await, "")).await;

    let resp = send(proxy, "Summarise this report in three bullet points.", &[]).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(action(&resp), None);
    assert_eq!(
        json(resp).await["messages"][0]["content"],
        "Summarise this report in three bullet points."
    );
}

#[tokio::test]
async fn shadow_mode_only_logs() {
    let proxy = start_proxy(&policy(start_mock().await, "    shadow: true")).await;

    let content = format!("key {OPENAI_KEY} and jane@example.com");
    let resp = send(proxy, &content, &[]).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(action(&resp), None);
    assert_eq!(json(resp).await["messages"][0]["content"], content.as_str());
}

#[tokio::test]
async fn fail_mode_decides_what_happens_to_uninspectable_bodies() {
    let mock = start_mock().await;
    let gzip = [("content-encoding", "gzip")];

    let closed = start_proxy(&policy(mock, "    fail_mode: closed")).await;
    let resp = send(closed, "anything", &gzip).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        json(resp).await["error"]["type"],
        "promptwall_uninspectable"
    );

    let open = start_proxy(&policy(mock, "    fail_mode: open")).await;
    assert_eq!(send(open, "anything", &gzip).await.status(), StatusCode::OK);
}

#[tokio::test]
async fn unmatched_requests_get_404() {
    let mock = start_mock().await;
    let yaml = format!(
        "version: 1\nupstreams: {{ mock: {{ url: 'http://{mock}' }} }}\n\
         routes: [{{ name: r, upstream: mock, match: {{ path: /v1/embeddings }} }}]"
    );
    let proxy = start_proxy(&yaml).await;

    let resp = send(proxy, "hi", &[]).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(json(resp).await["error"]["type"], "promptwall_no_route");
}
