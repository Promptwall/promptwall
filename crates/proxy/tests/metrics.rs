//! Metrics recorded by the proxy for real requests.

use std::time::Duration;

use bytes::Bytes;
use http::{header, Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

#[tokio::test]
async fn counts_requests_findings_and_check_time() {
    let config = pw_mock_upstream::Config {
        delay: Duration::ZERO,
        ..Default::default()
    };
    let mock = pw_mock_upstream::spawn("127.0.0.1:0".parse().unwrap(), config)
        .await
        .unwrap();
    let yaml = format!(
        "version: 1\nupstreams: {{ mock: {{ url: 'http://{mock}' }} }}\n\
         routes:\n  - name: metrics-test\n    upstream: mock\n    input:\n      - detector: pii\n        action: redact\n      - detector: secrets\n        action: block\n"
    );
    let proxy =
        promptwall::Proxy::with_policy(promptwall::Policy::from_yaml(&yaml).unwrap()).unwrap();
    let (listener, addr) = promptwall::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    tokio::spawn(proxy.serve(listener, std::future::pending()));
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(HttpConnector::new());
    for (prompt, status) in [
        ("hello", StatusCode::OK),
        ("mail jane@example.com", StatusCode::OK),
        ("key AKIAIOSFODNN7EXAMPLE", StatusCode::FORBIDDEN),
    ] {
        let body = format!(r#"{{"messages":[{{"role":"user","content":"{prompt}"}}]}}"#);
        let req = Request::builder()
            .method(Method::POST)
            .uri(format!("http://{addr}/v1/chat/completions"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body)))
            .unwrap();
        let resp = client.request(req).await.unwrap();
        assert_eq!(resp.status(), status);
        resp.into_body().collect().await.unwrap();
    }

    let (metrics, maddr) = promptwall::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    tokio::spawn(promptwall::metrics::serve(metrics));
    let resp = client
        .get(format!("http://{maddr}/metrics").parse().unwrap())
        .await
        .unwrap();
    let text = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    for line in [
        r#"promptwall_requests_total{route="metrics-test",action="allow"} 1"#,
        r#"promptwall_requests_total{route="metrics-test",action="redact"} 1"#,
        r#"promptwall_requests_total{route="metrics-test",action="block"} 1"#,
        r#"promptwall_findings_total{route="metrics-test",finding="pii.email",direction="request"} 1"#,
        r#"promptwall_findings_total{route="metrics-test",finding="secret.aws_access_key",direction="request"} 1"#,
        r#"promptwall_check_duration_seconds_count{route="metrics-test",stage="rules"} 3"#,
    ] {
        assert!(text.contains(line), "missing {line} in\n{text}");
    }
    assert!(!text.contains("jane@example.com"), "no values in metrics");
}
