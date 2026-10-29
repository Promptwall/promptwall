use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{header, Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

type TestClient = Client<HttpConnector, Full<Bytes>>;

fn client() -> TestClient {
    Client::builder(TokioExecutor::new()).build(HttpConnector::new())
}

async fn start_proxy(upstream: &str) -> SocketAddr {
    let proxy = promptwall::Proxy::new(upstream).unwrap();
    let (listener, addr) = promptwall::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    tokio::spawn(proxy.serve(listener, std::future::pending()));
    addr
}

async fn start_mock(config: pw_mock_upstream::Config) -> SocketAddr {
    pw_mock_upstream::spawn("127.0.0.1:0".parse().unwrap(), config)
        .await
        .unwrap()
}

fn chat(addr: SocketAddr, stream: bool) -> Request<Full<Bytes>> {
    let body = serde_json::json!({
        "model": "mock",
        "stream": stream,
        "messages": [{"role": "user", "content": "hi"}],
    });
    Request::builder()
        .method(Method::POST)
        .uri(format!("http://{addr}/v1/chat/completions?api-version=1"))
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-echo", "kept")
        .header(header::CONNECTION, "keep-alive, x-hop")
        .header("x-hop", "must-not-forward")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}

#[tokio::test]
async fn forwards_request_and_response_unchanged() {
    let mock = start_mock(pw_mock_upstream::Config {
        delay: Duration::ZERO,
        ..Default::default()
    })
    .await;
    let proxy = start_proxy(&format!("http://{mock}")).await;

    let direct = client().request(chat(mock, false)).await.unwrap();
    assert!(
        direct.headers().contains_key("x-saw-hop"),
        "mock should see x-hop when called directly"
    );
    let direct_len = direct.headers()["x-request-bytes"].clone();
    let direct_body = direct.into_body().collect().await.unwrap().to_bytes();

    let resp = client().request(chat(proxy, false)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["x-echo"], "kept");
    assert!(
        !resp.headers().contains_key("x-saw-hop"),
        "hop-by-hop header was forwarded"
    );
    assert_eq!(resp.headers()["x-request-bytes"], direct_len);
    assert_eq!(resp.headers()[header::CONTENT_TYPE], "application/json");
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, direct_body);
}

#[tokio::test]
async fn streams_chunks_without_buffering() {
    let config = pw_mock_upstream::Config {
        delay: Duration::ZERO,
        chunks: 5,
        chunk_interval: Duration::from_millis(100),
    };
    let mock = start_mock(config).await;
    let proxy = start_proxy(&format!("http://{mock}")).await;

    let start = Instant::now();
    let resp = client().request(chat(proxy, true)).await.unwrap();
    assert_eq!(resp.headers()[header::CONTENT_TYPE], "text/event-stream");
    let mut body = resp.into_body();
    let mut first_chunk = None;
    let mut collected = Vec::new();
    while let Some(frame) = body.frame().await {
        if let Ok(data) = frame.unwrap().into_data() {
            first_chunk.get_or_insert_with(|| start.elapsed());
            collected.extend_from_slice(&data);
        }
    }
    let total = start.elapsed();
    let text = String::from_utf8(collected).unwrap();

    assert_eq!(text.matches("chat.completion.chunk").count(), 5);
    assert!(text.ends_with("data: [DONE]\n\n"));
    // The first chunk must arrive long before the stream ends (400 ms of chunk gaps).
    let first_chunk = first_chunk.unwrap();
    assert!(
        first_chunk < Duration::from_millis(200) && total >= Duration::from_millis(400),
        "first chunk after {first_chunk:?}, total {total:?}"
    );
}

#[tokio::test]
async fn returns_bad_gateway_when_upstream_is_down() {
    // Bind and drop a listener to get a port with nothing behind it.
    let closed = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let proxy = start_proxy(&format!("http://{closed}")).await;

    let resp = client().request(chat(proxy, false)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn answers_health_check_locally() {
    let closed = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let proxy = start_proxy(&format!("http://{closed}")).await;

    let req = Request::get(format!("http://{proxy}/healthz"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = client().request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[test]
fn rejects_upstream_with_path_or_without_scheme() {
    assert!(promptwall::Proxy::new("https://api.openai.com").is_ok());
    assert!(promptwall::Proxy::new("https://api.openai.com/v1").is_err());
    assert!(promptwall::Proxy::new("api.openai.com").is_err());
}
