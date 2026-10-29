//! End-to-end tests for the tool-call firewall, against the mock upstream's
//! `x-tool-call` answers.

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use http::{header, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde_json::{json, Value};

const TOOLS: &str = "    tools:
      allow: [get_weather, send_email]
      action: block
      arguments:
        - tool: send_email
          field: to
          allow: ['*@acme.example']
";

async fn start(tools: &str) -> SocketAddr {
    let config = pw_mock_upstream::Config {
        delay: Duration::ZERO,
        ..Default::default()
    };
    let mock = pw_mock_upstream::spawn("127.0.0.1:0".parse().unwrap(), config)
        .await
        .unwrap();
    let yaml = format!(
        "version: 1\nupstreams: {{ mock: {{ url: 'http://{mock}' }} }}\n\
         routes:\n  - name: chat\n    upstream: mock\n{tools}"
    );
    let policy = promptwall::Policy::from_yaml(&yaml).unwrap();
    let proxy = promptwall::Proxy::with_policy(policy).unwrap();
    let (listener, addr) = promptwall::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    tokio::spawn(proxy.serve(listener, std::future::pending()));
    addr
}

/// Sends a chat request offering `offered` tools; the mock answers with the
/// call `call` (`<name> <arguments>`), if any.
async fn ask(
    proxy: SocketAddr,
    offered: &[&str],
    call: Option<&str>,
    stream: bool,
) -> Response<Incoming> {
    let tools: Vec<Value> = offered
        .iter()
        .map(|n| json!({"type": "function", "function": {"name": n, "parameters": {}}}))
        .collect();
    let body = json!({
        "model": "mock",
        "stream": stream,
        "tools": tools,
        "messages": [{"role": "user", "content": "hello"}],
    });
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{proxy}/v1/chat/completions"))
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-reply", "Let me check.")
        .header("x-reply-chunk", "4");
    if let Some(call) = call {
        req = req.header("x-tool-call", call);
    }
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(HttpConnector::new());
    client
        .request(req.body(Full::new(Bytes::from(body.to_string()))).unwrap())
        .await
        .unwrap()
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

/// The joined text deltas, the joined tool-call arguments, and whether the
/// stream ended with an error event.
async fn streamed(resp: Response<Incoming>) -> (String, String, bool) {
    let raw = body_text(resp).await;
    let (mut text, mut args, mut error) = (String::new(), String::new(), false);
    for event in raw.split("\n\n").filter(|e| !e.trim().is_empty()) {
        error |= event.starts_with("event: error");
        let data = event
            .lines()
            .find_map(|l| l.strip_prefix("data: "))
            .unwrap_or_default();
        let Ok(json) = serde_json::from_str::<Value>(data) else {
            continue;
        };
        let delta = &json["choices"][0]["delta"];
        text.push_str(delta["content"].as_str().unwrap_or_default());
        args.push_str(
            delta["tool_calls"][0]["function"]["arguments"]
                .as_str()
                .unwrap_or_default(),
        );
    }
    (text, args, error)
}

#[tokio::test]
async fn blocks_requests_that_offer_other_tools() {
    let proxy = start(TOOLS).await;
    let resp = ask(proxy, &["get_weather", "delete_account"], None, false).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(body_text(resp).await.contains("tool.not_allowed"));

    let resp = ask(proxy, &["get_weather", "send_email"], None, false).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn checks_tool_calls_in_whole_answers() {
    let proxy = start(TOOLS).await;
    let offered = ["get_weather", "send_email"];

    let resp = ask(
        proxy,
        &offered,
        Some(r#"send_email {"to":"bob@acme.example"}"#),
        false,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let answer: Value = serde_json::from_str(&body_text(resp).await).unwrap();
    assert_eq!(
        answer["choices"][0]["message"]["tool_calls"][0]["function"]["name"],
        "send_email"
    );

    let resp = ask(
        proxy,
        &offered,
        Some(r#"send_email {"to":"x@evil.example"}"#),
        false,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let err = body_text(resp).await;
    assert!(
        err.contains("tool.argument") && !err.contains("evil.example"),
        "{err}"
    );

    // A tool the request did not offer, and arguments that are not JSON.
    let resp = ask(proxy, &offered, Some(r#"delete_account {}"#), false).await;
    assert!(body_text(resp).await.contains("tool.not_allowed"));
    let resp = ask(proxy, &offered, Some(r#"send_email {"to": "#), false).await;
    assert!(body_text(resp).await.contains("tool.malformed_arguments"));
}

#[tokio::test]
async fn holds_streamed_tool_calls_until_checked() {
    let proxy = start(TOOLS).await;
    let offered = ["get_weather", "send_email"];

    let resp = ask(
        proxy,
        &offered,
        Some(r#"send_email {"to":"bob@acme.example"}"#),
        true,
    )
    .await;
    let (text, args, error) = streamed(resp).await;
    assert!(!error);
    assert_eq!(text, "Let me check.");
    assert_eq!(args, r#"{"to":"bob@acme.example"}"#);

    let resp = ask(
        proxy,
        &offered,
        Some(r#"send_email {"to":"x@evil.example"}"#),
        true,
    )
    .await;
    let (text, args, error) = streamed(resp).await;
    assert!(error, "the stream must end with an error event");
    assert_eq!(text, "Let me check.");
    assert_eq!(args, "", "no part of the rejected call may reach the app");
}

#[tokio::test]
async fn flag_and_shadow_only_log() {
    let flag = TOOLS.replace("action: block", "action: flag");
    let proxy = start(&flag).await;
    let resp = ask(proxy, &["get_weather"], Some(r#"delete_account {}"#), false).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["x-promptwall-action"], "flag");

    let proxy = start(&format!("    shadow: true\n{TOOLS}")).await;
    let resp = ask(
        proxy,
        &["delete_account"],
        Some(r#"delete_account {}"#),
        true,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let (_, args, error) = streamed(resp).await;
    assert!(!error);
    assert_eq!(args, "{}");
}

#[test]
fn rejects_unusable_tool_rules() {
    let err = |tools: &str| {
        let yaml = format!(
            "version: 1\nupstreams: {{ a: {{ url: 'http://x' }} }}\nroutes:\n  - name: r\n    upstream: a\n    tools: {tools}\n"
        );
        format!("{:#}", promptwall::Policy::from_yaml(&yaml).unwrap_err())
    };
    assert!(err("{ allow: [a], action: redact }").contains("block or flag"));
    assert!(err("{ action: block }").contains("at least one of"));
    assert!(err("{ arguments: [{ tool: a, field: x }], action: block }")
        .contains("needs allow, deny or allow_domains"));
}
