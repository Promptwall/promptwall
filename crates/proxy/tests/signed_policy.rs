//! Signed policies (`--policy-public-key`), at startup and on reload.

use promptwall::reload::{Reload, Watcher};
use promptwall::{Action, Proxy, Sample};

fn policy(pii_action: &str) -> String {
    format!(
        "version: 1\nupstreams: {{ a: {{ url: 'http://127.0.0.1:9' }} }}\nroutes:\n  - name: chat\n    upstream: a\n    input:\n      - detector: pii\n        entities: [email]\n        action: {pii_action}\n"
    )
}

fn email_action(proxy: &Proxy) -> Option<Action> {
    proxy
        .check("chat", Sample::Input("write to jane@corp.io"))
        .unwrap()
        .action
}

#[test]
fn with_signing_only_signed_policies_load() {
    use promptwall::signing::{self, PublicKey};
    let dir = std::env::temp_dir().join(format!("pw-signed-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("policy.yaml");
    let sig = signing::signature_path(&path);
    let (private, public) = signing::generate().unwrap();
    let key = PublicKey::parse(&public).unwrap();
    let write_signed = |yaml: &str| {
        std::fs::write(&path, yaml).unwrap();
        std::fs::write(&sig, signing::sign(&private, yaml.as_bytes()).unwrap()).unwrap();
    };

    std::fs::write(&path, policy("redact")).unwrap();
    let err = promptwall::signing::load_policy(&path, Some(&key)).unwrap_err();
    assert!(format!("{err:#}").contains("no signature"), "{err:#}");

    write_signed(&policy("redact"));
    let proxy =
        Proxy::with_policy(promptwall::signing::load_policy(&path, Some(&key)).unwrap()).unwrap();
    let mut watcher = Watcher::new(&path, Some(key));

    // Changed without a new signature: rejected, the old policy stays.
    std::fs::write(&path, policy("flag")).unwrap();
    let Reload::Rejected(why) = watcher.check(&proxy) else {
        panic!("unsigned change must be rejected")
    };
    assert!(why.contains("signature does not match"), "{why}");
    assert_eq!(email_action(&proxy), Some(Action::Redact));

    // Signed afterwards (the signature file changes too): loaded.
    write_signed(&policy("flag"));
    assert_eq!(watcher.check(&proxy), Reload::Reloaded);
    assert_eq!(email_action(&proxy), Some(Action::Flag));
    std::fs::remove_dir_all(&dir).unwrap();
}
