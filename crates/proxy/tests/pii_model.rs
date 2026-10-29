//! End-to-end tests for `pii` entities found by a token-classification model,
//! with the tiny fixture model of crates/classify/tests/fixtures: it tags
//! "anna" as the start of a person's name and "smith" as its continuation.

// These tests load ONNX models, so they need the `models` feature.
#![cfg(feature = "models")]

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
use promptwall::ner::PiiModel;
use serde_json::{json, Value};

fn models() -> promptwall::Models {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../classify/tests/fixtures/tiny-ner");
    promptwall::Models {
        pii: Some(Arc::new(PiiModel::load(&dir, &Default::default()).unwrap())),
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

/// Sends `prompt` and returns what the provider received.
async fn received(proxy: SocketAddr, prompt: &str) -> Value {
    let body = json!({"model": "mock", "messages": [
        {"role": "system", "content": "You help Anna Smith's customers."},
        {"role": "user", "content": prompt},
    ]});
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{proxy}/v1/chat/completions"))
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-echo-body", "1")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap();
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(HttpConnector::new());
    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["x-promptwall-action"], "redact");
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn redacts_names_in_the_request_with_built_in_entities() {
    let proxy = start(
        "    input:\n      - detector: pii\n        entities: [email, person]\n        action: redact\n",
    )
    .await;
    let sent = received(proxy, "Hi, mail anna smith at jane@example.com").await;
    assert_eq!(
        sent["messages"][1]["content"],
        "Hi, mail [REDACTED:PERSON] at [REDACTED:EMAIL]"
    );
    // The app's own instructions are redacted too.
    assert_eq!(
        sent["messages"][0]["content"],
        "You help [REDACTED:PERSON]'s customers."
    );
    assert_eq!(sent["model"], "mock");
}

#[tokio::test]
async fn blocks_or_flags_by_entity_and_threshold() {
    let proxy = start(
        "    input:\n      - detector: pii\n        entities: [person]\n        action: block\n",
    )
    .await;
    let resp = ask(proxy, "this is anna", None, false).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(findings(resp).await, json!(["pii.person"]));
    assert_eq!(
        ask(proxy, "this is a report", None, false).await.status(),
        StatusCode::OK
    );

    // The fixture is sure of its names (0.9999): a threshold above that lets them pass.
    let proxy = start(
        "    input:\n      - detector: pii\n        entities: [person]\n        threshold: 0.99999\n        action: block\n",
    )
    .await;
    assert_eq!(
        ask(proxy, "this is anna", None, false).await.status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn redacts_names_in_whole_and_streamed_answers() {
    let route =
        "    output:\n      - detector: pii\n        entities: [person]\n        action: redact\n";
    let proxy = start(route).await;
    let resp = ask(proxy, "who?", Some("Ask Anna Smith. Done."), false).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["x-promptwall-action"], "redact");
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        json["choices"][0]["message"]["content"],
        "Ask [REDACTED:PERSON]. Done."
    );

    // Long enough that the model checks it several times while it streams,
    // with names on both sides of those points.
    let filler = "hello please summarise this report ".repeat(9);
    let reply =
        format!("Anna Smith wrote {filler}and then anna smith {filler}signed as Anna. End.");
    let (text, error) = streamed(ask(proxy, "who?", Some(&reply), true).await).await;
    assert!(!error);
    assert_eq!(
        text,
        format!("[REDACTED:PERSON] wrote {filler}and then [REDACTED:PERSON] {filler}signed as [REDACTED:PERSON]. End.")
    );
}

#[tokio::test]
async fn checks_entities_against_the_loaded_model() {
    let mock: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let route = "    input:\n      - detector: pii\n        entities: [street_address]\n        action: redact\n";
    let err = promptwall::Proxy::with_models(policy(mock, route), Default::default())
        .err()
        .unwrap();
    assert!(
        format!("{err:#}").contains("need a PII model (--pii-model)"),
        "{err:#}"
    );
    let err = promptwall::Proxy::with_models(policy(mock, route), models())
        .err()
        .unwrap();
    assert!(
        format!("{err:#}").contains("The PII model has: person"),
        "{err:#}"
    );
}
