//! Policy test cases (`tests:` in a policy file) and offline checks with
//! `Proxy::check`, as `promptwall test` and `promptwall scan` run them.

use std::path::Path;

use promptwall::{Action, Policy, Proxy, Sample};

#[test]
fn the_example_policy_passes_its_own_tests() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/policy.yaml");
    let proxy = Proxy::with_policy(Policy::load(&path).unwrap()).unwrap();
    let results = proxy.run_tests();
    assert!(results.len() >= 6);
    for result in results {
        assert!(
            result.failure.is_none(),
            "{}: {:?}",
            result.name,
            result.failure
        );
    }
}

const POLICY: &str = r#"
version: 1
upstreams: { a: { url: "http://127.0.0.1:9" } }
routes:
  - name: chat
    upstream: a
    input:
      - detector: pii
        entities: [email]
        except: ["*@example.com", "help@corp.io"]
        action: redact
      - detector: pii
        entities: [ip_address]
        action: allow
      - detector: pii
        action: flag
    output:
      - detector: secrets
        except: ["AKIAIOSFODNN7EXAMPLE"]
        action: block
tests:
  - name: passes
    route: chat
    input: mail jane@corp.io
    expect: { action: redact, text: "mail [REDACTED:EMAIL]" }
  - name: wrong action
    route: chat
    input: mail jane@corp.io
    expect: block
  - name: missing finding
    route: chat
    input: call +49 151 23456789
    expect: { action: flag, findings: [pii.email] }
"#;

#[test]
fn exceptions_and_allow_entries() {
    let proxy = Proxy::with_policy(Policy::from_yaml(POLICY).unwrap()).unwrap();
    let check = |text| proxy.check("chat", Sample::Input(text)).unwrap();

    let v = check("mail jane@corp.io, support@example.com or HELP@corp.io");
    assert_eq!(v.action, Some(Action::Redact));
    assert_eq!(v.findings["pii.email"], 1);
    assert_eq!(
        v.text,
        "mail [REDACTED:EMAIL], support@example.com or HELP@corp.io"
    );

    // `allow` keeps the catch-all flag below it off IP addresses only.
    assert_eq!(check("server 10.0.0.1 is down").action, None);
    assert_eq!(check("call +49 151 23456789").action, Some(Action::Flag));

    let answer = |text| proxy.check("chat", Sample::Output(text)).unwrap();
    assert_eq!(answer("the docs use AKIAIOSFODNN7EXAMPLE").action, None);
    assert_eq!(
        answer("your key is AKIAI44QH8DHBEXAMPLE").action,
        Some(Action::Block)
    );
}

#[test]
fn failing_tests_say_why() {
    let proxy = Proxy::with_policy(Policy::from_yaml(POLICY).unwrap()).unwrap();
    let results = proxy.run_tests();
    assert_eq!(results[0].failure, None);
    let wrong = results[1].failure.as_deref().unwrap();
    assert!(wrong.contains("expected block, got redact"), "{wrong}");
    assert!(wrong.contains("found pii.email"), "{wrong}");
    let missing = results[2].failure.as_deref().unwrap();
    assert!(missing.contains("missing findings pii.email"), "{missing}");
}

#[test]
fn rejects_broken_tests_and_exceptions() {
    let err = |yaml: &str| format!("{:#}", Policy::from_yaml(yaml).unwrap_err());
    let base = "version: 1\nupstreams: { a: { url: 'http://x' } }\nroutes:\n  - name: r\n    upstream: a\n";
    assert!(err(&format!(
        "{base}tests: [{{ route: nope, input: hi, expect: allow }}]"
    ))
    .contains("unknown route \"nope\""));
    assert!(err(&format!(
        "{base}tests: [{{ route: r, input: hi, output: hi, expect: allow }}]"
    ))
    .contains("either input or output"));
    assert!(err(&format!(
        "{base}    input: [{{ detector: pii, except: [x], action: allow }}]"
    ))
    .contains("except is meaningless"));
    assert!(err(&format!(
        "{base}    input: [{{ detector: content_safety, action: allow }}]"
    ))
    .contains("not available on content_safety"));
    assert!(
        err(&format!("{base}    tools: {{ allow: [x], action: allow }}"))
            .contains("unknown variant")
    );
}
