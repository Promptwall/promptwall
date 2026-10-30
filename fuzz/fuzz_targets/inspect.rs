//! Any request body: inspection must not panic, and a redacted body must be
//! valid JSON when the original was.
#![no_main]

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use promptwall_engine::inspect::{inspect, Collect};
use promptwall_engine::policy::Policy;

static POLICY: LazyLock<Policy> = LazyLock::new(|| {
    Policy::from_yaml(
        r#"
version: 1
upstreams: { a: { url: "http://x" } }
routes:
  - name: r
    upstream: a
    input:
      - { detector: prompt_injection, action: flag }
      - { detector: secrets, action: redact }
      - { detector: pii, action: redact }
      - { detector: custom, name: falcon, keywords: [falcon], action: redact }
"#,
    )
    .unwrap()
});

fuzz_target!(|body: &[u8]| {
    let route = &POLICY.routes[0];
    let collect = Collect {
        untrusted: true,
        trusted: true,
    };
    let Ok(outcome) = inspect(&route.detector, &route.input, body, collect, &route.except) else {
        return;
    };
    if let Some(redacted) = outcome.redacted_body {
        let was_json = serde_json::from_slice::<serde_json::Value>(
            String::from_utf8_lossy(body).as_bytes(),
        )
        .is_ok();
        if was_json {
            serde_json::from_slice::<serde_json::Value>(&redacted).expect("redacted JSON");
        }
    }
});
