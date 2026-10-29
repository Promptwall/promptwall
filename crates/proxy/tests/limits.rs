//! End-to-end tests for rate and token limits against the mock upstream.
//! Day limits are used so that no window ends during a test.

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use http::{header, Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

async fn start(limits: &str) -> SocketAddr {
    let config = pw_mock_upstream::Config {
        delay: Duration::ZERO,
        ..Default::default()
    };
    let mock = pw_mock_upstream::spawn("127.0.0.1:0".parse().unwrap(), config)
        .await
        .unwrap();
    let yaml = format!(
        "version: 1\nupstreams: {{ mock: {{ url: 'http://{mock}' }} }}\n\
         routes:\n  - name: chat\n    upstream: mock\n    limits: {limits}\n"
    );
    let proxy =
        promptwall::Proxy::with_policy(promptwall::Policy::from_yaml(&yaml).unwrap()).unwrap();
    let (listener, addr) = promptwall::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    tokio::spawn(proxy.serve(listener, std::future::pending()));
    addr
}

/// Sends a request as `user`; returns the status and the Retry-After header.
async fn send(proxy: SocketAddr, user: &str) -> (StatusCode, Option<String>) {
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{proxy}/v1/chat/completions"))
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-user", user)
        .body(Full::new(Bytes::from_static(br#"{"messages":[]}"#)))
        .unwrap();
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(HttpConnector::new());
    let resp = client.request(req).await.unwrap();
    let status = resp.status();
    let retry = resp
        .headers()
        .get(header::RETRY_AFTER)
        .map(|v| v.to_str().unwrap().to_owned());
    resp.into_body().collect().await.unwrap();
    // The proxy adds the answer's tokens once it has finished sending it.
    tokio::time::sleep(Duration::from_millis(50)).await;
    (status, retry)
}

#[tokio::test]
async fn limits_requests_per_user() {
    let proxy = start("{ key: 'header:x-user', requests_per_day: 2 }").await;
    assert_eq!(send(proxy, "alice").await.0, StatusCode::OK);
    assert_eq!(send(proxy, "alice").await.0, StatusCode::OK);
    let (status, retry) = send(proxy, "alice").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    let retry: u64 = retry.unwrap().parse().unwrap();
    assert!((1..=86_400).contains(&retry));
    assert_eq!(send(proxy, "bob").await.0, StatusCode::OK);
}

#[tokio::test]
async fn limits_tokens_from_the_reported_usage() {
    // The mock's answer reports 1 prompt and 6 completion tokens.
    let proxy = start("{ tokens_per_day: 10 }").await;
    assert_eq!(send(proxy, "a").await.0, StatusCode::OK); // 7 used
    assert_eq!(send(proxy, "b").await.0, StatusCode::OK); // 14 used
    assert_eq!(send(proxy, "c").await.0, StatusCode::TOO_MANY_REQUESTS);
}

#[test]
fn rejects_empty_or_unclear_limits() {
    let err = |limits: &str| {
        let yaml = format!(
            "version: 1\nupstreams: {{ a: {{ url: 'http://x' }} }}\n\
             routes: [{{ name: r, upstream: a, limits: {limits} }}]"
        );
        format!("{:#}", promptwall::Policy::from_yaml(&yaml).unwrap_err())
    };
    assert!(err("{ key: api_key }").contains("at least one limit"));
    assert!(err("{ key: user, requests_per_day: 1 }").contains("key must be"));
    assert!(err("{ requests_per_minute: 0 }").contains("above 0"));
}
