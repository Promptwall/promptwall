//! End-to-end tests for the content policy (`content_safety` and `topics`),
//! with the tiny fixture models of crates/classify/tests/fixtures: the
//! moderation model flags any text with the word "attack" (as category
//! "other"), and the NLI model says a text is about a topic when either of
//! them contains "attack".

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{header, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use promptwall::moderation::{Safety, Topics};
use serde_json::{json, Value};

fn models() -> promptwall::Models {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../classify/tests/fixtures");
    let options = Default::default();
    promptwall::Models {
        safety: Some(Arc::new(
            Safety::load(&fixtures.join("tiny-safety"), &options).unwrap(),
        )),
        topics: Some(Arc::new(
            Topics::load(&fixtures.join("tiny-nli"), &options).unwrap(),
        )),
        ..Default::default()
    }
}

fn policy(mock: SocketAddr, route: &str) -> promptwall::Policy {
    let yaml = format!(
        "version: 1\nupstreams: {{ mock: {{ url: 'http://{mock}' }} }}\n\
         routes:\n  - name: chat\n    upstream: mock\n{route}"
    );
    promptwall::Policy::from_yaml(&yaml).unwrap()
}

async fn start(route: &str) -> SocketAddr {
    let config = pw_mock_upstream::Config {
        delay: Duration::ZERO,
        ..Default::default()
    };
    let mock = pw_mock_upstream::spawn("127.0.0.1:0".parse().unwrap(), config)
        .await
        .unwrap();
    let proxy = promptwall::Proxy::with_models(policy(mock, route), models()).unwrap();
    let (listener, addr) = promptwall::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    tokio::spawn(proxy.serve(listener, std::future::pending()));
    addr
}

/// Sends `prompt`; the mock answers with `reply` if given.
async fn ask(
    proxy: SocketAddr,
    prompt: &str,
    reply: Option<&str>,
    stream: bool,
) -> Response<Incoming> {
    let body = json!({
        "model": "mock",
        "stream": stream,
        "messages": [{"role": "user", "content": prompt}],
    });
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{proxy}/v1/chat/completions"))
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(reply) = reply {
        req = req.header("x-reply", reply).header("x-reply-chunk", "8");
    }
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(HttpConnector::new());
    client
        .request(req.body(Full::new(Bytes::from(body.to_string()))).unwrap())
        .await
        .unwrap()
}

async fn findings(resp: Response<Incoming>) -> Value {
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice::<Value>(&body).unwrap()["error"]["findings"].clone()
}

/// The streamed text, and whether the stream ended with an error event.
async fn streamed(resp: Response<Incoming>) -> (String, bool) {
    let raw = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    let mut text = String::new();
    let mut error = false;
    for event in raw.split("\n\n").filter(|e| !e.trim().is_empty()) {
        error |= event.starts_with("event: error");
        let data = event
            .lines()
            .find_map(|l| l.strip_prefix("data: "))
            .unwrap_or_default();
        if let Ok(json) = serde_json::from_str::<Value>(data) {
            text.push_str(
                json["choices"][0]["delta"]["content"]
                    .as_str()
                    .unwrap_or_default(),
            );
        }
    }
    (text, error)
}

#[tokio::test]
async fn blocks_harmful_prompts() {
    let proxy = start("    input: [{ detector: content_safety, action: block }]\n").await;
    let resp = ask(proxy, "please attack the report", None, false).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(findings(resp).await, json!(["safety.other"]));
    let resp = ask(proxy, "please summarise the report", None, false).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn keeps_requests_on_topic() {
    let proxy = start("    input: [{ detector: topics, allow: [weather], action: block }]\n").await;
    let resp = ask(proxy, "please summarise the report", None, false).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(findings(resp).await, json!(["topic.off_topic"]));
    let resp = ask(proxy, "attack", None, false).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let proxy = start("    input: [{ detector: topics, deny: [weather], action: block }]\n").await;
    let resp = ask(proxy, "attack", None, false).await;
    assert_eq!(findings(resp).await, json!(["topic.denied"]));
    let resp = ask(proxy, "please summarise the report", None, false).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn blocks_harmful_answers() {
    let proxy =
        start("    output: [{ detector: content_safety, entities: [other], action: block }]\n")
            .await;
    let resp = ask(proxy, "hello", Some("please attack the report"), false).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(findings(resp).await, json!(["safety.other"]));
    let resp = ask(proxy, "hello", Some("please summarise the report"), false).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Streamed: nothing goes out before the model has judged it.
    let (text, error) =
        streamed(ask(proxy, "hello", Some("please attack the report"), true).await).await;
    assert!(error);
    assert_eq!(text, "");
    let long = "please summarise the report and the rest of it. ".repeat(20) + "Done.";
    let (text, error) = streamed(ask(proxy, "hello", Some(&long), true).await).await;
    assert!(!error);
    assert_eq!(text, long);
}

#[tokio::test]
async fn needs_the_models_it_names() {
    let mock: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let err = |route: &str, models: promptwall::Models| {
        format!(
            "{:#}",
            promptwall::Proxy::with_models(policy(mock, route), models)
                .err()
                .unwrap()
        )
    };
    let safety = "    input: [{ detector: content_safety, action: block }]\n";
    assert!(err(safety, Default::default()).contains("--safety-model"));
    let topics = "    input: [{ detector: topics, deny: [x], action: block }]\n";
    assert!(err(topics, Default::default()).contains("--topic-model"));
    let unknown =
        "    input: [{ detector: content_safety, entities: [violence], action: block }]\n";
    assert!(err(unknown, models()).contains("no category \"violence\""));
}

#[test]
fn rejects_unusable_content_rules() {
    let err = |route: &str| {
        let yaml = format!(
            "version: 1\nupstreams: {{ a: {{ url: 'http://x' }} }}\nroutes:\n  - name: r\n    upstream: a\n{route}"
        );
        format!("{:#}", promptwall::Policy::from_yaml(&yaml).unwrap_err())
    };
    assert!(
        err("    input: [{ detector: topics, action: block }]\n").contains("needs deny or allow")
    );
    assert!(
        err("    output: [{ detector: topics, deny: [x], action: block }]\n")
            .contains("use it under input")
    );
    assert!(
        err("    input: [{ detector: pii, deny: [x], action: block }]\n")
            .contains("only allowed on the topics")
    );
}
