//! Reloading the policy file while the proxy runs.

use std::sync::Arc;

use promptwall::reload::{Reload, Watcher};
use promptwall::{Action, Policy, Proxy, Sample};

fn policy(pii_action: &str, requests_per_minute: u64) -> String {
    format!(
        r#"
version: 1
upstreams: {{ a: {{ url: "http://127.0.0.1:9" }} }}
routes:
  - name: chat
    upstream: a
    input:
      - detector: pii
        entities: [email]
        action: {pii_action}
    limits:
      requests_per_minute: {requests_per_minute}
"#
    )
}

fn email_action(proxy: &Proxy) -> Option<Action> {
    proxy
        .check("chat", Sample::Input("write to jane@corp.io"))
        .unwrap()
        .action
}

#[test]
fn applies_changes_and_keeps_the_old_policy_on_errors() {
    let dir = std::env::temp_dir().join(format!("pw-reload-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("policy.yaml");
    std::fs::write(&path, policy("redact", 10)).unwrap();
    let proxy = Proxy::with_policy(Policy::load(&path).unwrap()).unwrap();
    let mut watcher = Watcher::new(&path);
    let limiter = |p: &Proxy| p.policy().routes[0].limits.clone().unwrap();
    let first = limiter(&proxy);

    assert_eq!(watcher.check(&proxy), Reload::Unchanged);
    assert_eq!(email_action(&proxy), Some(Action::Redact));

    std::fs::write(&path, policy("block", 10)).unwrap();
    assert_eq!(watcher.check(&proxy), Reload::Reloaded);
    assert_eq!(email_action(&proxy), Some(Action::Block));
    assert!(
        Arc::ptr_eq(&first, &limiter(&proxy)),
        "unchanged limits keep their counters"
    );

    std::fs::write(&path, "version: 1\nroutes: [").unwrap();
    assert!(matches!(watcher.check(&proxy), Reload::Rejected(_)));
    assert_eq!(watcher.check(&proxy), Reload::Unchanged, "rejected once");
    assert_eq!(email_action(&proxy), Some(Action::Block));

    // A model the proxy has not loaded.
    std::fs::write(
        &path,
        policy("block", 10).replace("[email]", "[email, person]"),
    )
    .unwrap();
    let Reload::Rejected(why) = watcher.check(&proxy) else {
        panic!("needs a PII model")
    };
    assert!(why.contains("person"), "{why}");

    std::fs::write(&path, policy("flag", 20)).unwrap();
    assert_eq!(watcher.check(&proxy), Reload::Reloaded);
    assert_eq!(email_action(&proxy), Some(Action::Flag));
    assert!(
        !Arc::ptr_eq(&first, &limiter(&proxy)),
        "changed limits start new counters"
    );

    let metrics = promptwall::metrics::render();
    assert!(metrics.contains("promptwall_policy_reloads_total{result=\"ok\"} 2"));
    assert!(metrics.contains("promptwall_policy_reloads_total{result=\"error\"} 2"));
    std::fs::remove_dir_all(&dir).unwrap();
}
