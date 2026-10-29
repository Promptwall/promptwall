//! The decision log: one JSON line per request, without prompt or answer text.

use std::time::Duration;

use bytes::Bytes;
use http::{header, Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde_json::Value;

#[tokio::test]
async fn writes_one_line_per_request_without_text() {
    let config = pw_mock_upstream::Config {
        delay: Duration::ZERO,
        chunk_interval: Duration::ZERO,
        ..Default::default()
    };
    let mock = pw_mock_upstream::spawn("127.0.0.1:0".parse().unwrap(), config)
        .await
        .unwrap();
    let yaml = format!(
        "version: 1\nupstreams: {{ mock: {{ url: 'http://{mock}' }} }}\n\
         routes:\n  - name: chat\n    upstream: mock\n    input:\n      - detector: pii\n        action: redact\n      - detector: secrets\n        action: block\n    output:\n      - detector: pii\n        action: redact\n"
    );
    let policy = promptwall::Policy::from_yaml(&yaml).unwrap();
    let digest = policy.digest.clone();
    let proxy = promptwall::Proxy::with_policy(policy).unwrap();
    let log = std::env::temp_dir().join(format!("pw-decisions-{}.jsonl", std::process::id()));
    let _ = std::fs::remove_file(&log);
    promptwall::decision::init(&log).unwrap();
    let (listener, addr) = promptwall::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    tokio::spawn(proxy.serve(listener, std::future::pending()));
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(HttpConnector::new());

    let mut ids = Vec::new();
    for (prompt, reply, stream, status) in [
        ("hello", None, false, StatusCode::OK),
        ("mail jane@example.com", None, false, StatusCode::OK),
        (
            "key AKIAIOSFODNN7EXAMPLE",
            None,
            false,
            StatusCode::FORBIDDEN,
        ),
        (
            "who to call?",
            Some("Call +49 30 1234567 now"),
            true,
            StatusCode::OK,
        ),
    ] {
        let body =
            format!(r#"{{"stream":{stream},"messages":[{{"role":"user","content":"{prompt}"}}]}}"#);
        let mut req = Request::builder()
            .method(Method::POST)
            .uri(format!("http://{addr}/v1/chat/completions"))
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(reply) = reply {
            req = req.header("x-reply", reply).header("x-reply-chunk", "5");
        }
        let resp = client
            .request(req.body(Full::new(Bytes::from(body))).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), status);
        ids.push(
            resp.headers()["x-promptwall-request-id"]
                .to_str()
                .unwrap()
                .to_owned(),
        );
        resp.into_body().collect().await.unwrap();
    }

    // Lines are written by a background thread once each response is done.
    let mut text = String::new();
    for _ in 0..50 {
        text = std::fs::read_to_string(&log).unwrap_or_default();
        if text.lines().count() == 4 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let events: Vec<Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(events.len(), 4, "{text}");
    for (event, id) in events.iter().zip(&ids) {
        assert_eq!(event["id"], id.as_str());
        assert_eq!(event["route"], "chat");
        assert_eq!(event["policy"], digest.as_str());
        assert!(event["ts"].as_str().unwrap().ends_with('Z'));
        assert!(event["duration_ms"].as_f64().unwrap() >= event["latency_ms"].as_f64().unwrap());
        assert!(event["check_ms"]["rules"].as_f64().is_some());
    }
    assert_eq!(events[0]["action"], "allow");
    assert_eq!(events[0]["request"], serde_json::json!({}));
    assert_eq!(events[1]["action"], "redact");
    assert_eq!(events[1]["request"]["findings"]["pii.email"], 1);
    assert_eq!(events[2]["action"], "block");
    assert_eq!(events[2]["status"], 403);
    assert_eq!(events[2]["request"]["findings"]["secret.aws_access_key"], 1);
    assert_eq!(events[3]["response"]["action"], "redact");
    assert_eq!(events[3]["response"]["findings"]["pii.phone"], 1);
    for secret in [
        "jane@example.com",
        "AKIAIOSFODNN7EXAMPLE",
        "1234567",
        "hello",
    ] {
        assert!(!text.contains(secret), "{secret} in the decision log");
    }
    std::fs::remove_file(&log).unwrap();
}
