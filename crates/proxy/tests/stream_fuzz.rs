//! Randomised streams through the output checks: answers with a secret or an
//! email address split at random points, mixed with comments, unknown events,
//! malformed JSON, invalid UTF-8 and CRLF line ends, delivered in random
//! pieces. Whatever arrives, the proxy must answer, and the secret and the
//! address must never get through.

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use http::{header, Method, Request};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

const SECRET: &str = "AKIAIOSFODNN7EXAMPLE";
const EMAIL: &str = "jane.doe@corp.io";
const CASES: u64 = 200;

/// xorshift64*: deterministic, so a failing seed can be replayed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}

async fn start() -> SocketAddr {
    let config = pw_mock_upstream::Config {
        delay: Duration::ZERO,
        ..Default::default()
    };
    let mock = pw_mock_upstream::spawn("127.0.0.1:0".parse().unwrap(), config)
        .await
        .unwrap();
    let yaml = format!(
        "version: 1\nupstreams: {{ mock: {{ url: 'http://{mock}' }} }}\n\
         routes:\n  - name: chat\n    upstream: mock\n    output:\n\
         \x20     - {{ detector: secrets, action: block }}\n\
         \x20     - {{ detector: pii, entities: [email], action: redact }}\n"
    );
    let proxy =
        promptwall::Proxy::with_policy(promptwall::Policy::from_yaml(&yaml).unwrap()).unwrap();
    let (listener, addr) = promptwall::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    tokio::spawn(proxy.serve(listener, std::future::pending()));
    addr
}

/// A random stream; returns its bytes and what the answer text holds.
fn stream(rng: &mut Rng) -> (Vec<u8>, bool, bool) {
    let words = [
        "the",
        "invoice",
        "is",
        "ready",
        "für",
        "Köln",
        "😀",
        "ok",
        "\"quoted\"",
        "a\\b",
    ];
    let mut text = String::new();
    let (secret, email) = (rng.chance(40), rng.chance(40));
    for i in 0..rng.below(30) + 5 {
        if secret && i == 2 {
            text.push_str(SECRET);
            text.push(' ');
        }
        if email && i == 4 {
            text.push_str(EMAIL);
            text.push(' ');
        }
        text.push_str(words[rng.below(words.len() as u64) as usize]);
        text.push(' ');
    }
    let crlf = rng.chance(20);
    let nl = if crlf { "\r\n" } else { "\n" };
    let mut out = Vec::new();
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let n = (rng.below(6) + 1) as usize;
        let piece: String = chars[i..(i + n).min(chars.len())].iter().collect();
        i += n;
        let delta = serde_json::json!({"choices": [{"index": 0, "delta": {"content": piece}}]});
        out.extend(format!("data: {delta}{nl}{nl}").as_bytes());
        // Noise between the events that carry text.
        match rng.below(12) {
            0 => out.extend(format!(": keep-alive{nl}{nl}").as_bytes()),
            1 => out.extend(format!("event: ping{nl}data: {{}}{nl}{nl}").as_bytes()),
            2 => out.extend(format!("data: {{not json{nl}{nl}").as_bytes()),
            3 => out.extend(b"data: \xff\xfe broken utf-8\n\n"),
            4 => out.extend(format!("data: {}{nl}{nl}", "x".repeat(5000)).as_bytes()),
            5 => out.extend(format!("id: 7{nl}retry: 10{nl}{nl}").as_bytes()),
            _ => {}
        }
    }
    out.extend(format!("data: [DONE]{nl}{nl}").as_bytes());
    (out, secret, email)
}

#[tokio::test]
async fn random_streams_never_leak_the_secret_or_the_address() {
    let proxy = start().await;
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(HttpConnector::new());
    let seed = std::env::var("PW_FUZZ_SEED").map_or(0x5EED, |s| s.parse().unwrap());
    let mut rng = Rng(seed);
    for case in 0..CASES {
        let (raw, secret, email) = stream(&mut rng);
        let chunk = rng.below(64) + 1;
        let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        let req = Request::builder()
            .method(Method::POST)
            .uri(format!("http://{proxy}/v1/chat/completions"))
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-raw-hex", hex)
            .header("x-reply-chunk", chunk.to_string())
            .body(Full::new(Bytes::from_static(
                br#"{"stream":true,"messages":[{"role":"user","content":"hi"}]}"#,
            )))
            .unwrap();
        let resp = tokio::time::timeout(Duration::from_secs(10), client.request(req))
            .await
            .unwrap_or_else(|_| panic!("case {case}: no answer"))
            .unwrap();
        let body = tokio::time::timeout(Duration::from_secs(10), resp.into_body().collect())
            .await
            .unwrap_or_else(|_| panic!("case {case}: the stream did not end"))
            .unwrap()
            .to_bytes();
        let body = String::from_utf8_lossy(&body);
        let context = format!("case {case} (seed {seed}, chunk {chunk})");
        if secret {
            assert!(!body.contains("AKIAIOSFODNN7"), "{context}: secret leaked");
            assert!(body.contains("event: error"), "{context}: not blocked");
        }
        if email {
            assert!(!body.contains("jane.doe@"), "{context}: address leaked");
        }
    }
}
