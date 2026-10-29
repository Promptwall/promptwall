//! Policy format v1 is frozen: what loads today keeps loading.

use std::path::Path;

fn manifest(path: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

#[test]
fn every_v1_field_still_loads() {
    let text = std::fs::read_to_string(manifest("tests/fixtures/policy-v1-full.yaml")).unwrap();
    let policy = promptwall::Policy::from_yaml(&text).unwrap();
    assert_eq!(policy.routes.len(), 2);
    assert_eq!(policy.tests.len(), 2);
    assert!(policy.digest.starts_with("sha256:"));
}

#[test]
fn the_published_schema_is_current() {
    let published =
        std::fs::read_to_string(manifest("../../docs/specs/policy-v1.schema.json")).unwrap();
    assert!(
        published == promptwall::policy::json_schema(),
        "docs/specs/policy-v1.schema.json is out of date; run \
         `cargo run -p promptwall -- schema > docs/specs/policy-v1.schema.json`"
    );
}

#[test]
fn unknown_fields_and_versions_are_rejected() {
    let base =
        "upstreams: { a: { url: 'http://127.0.0.1:9' } }\nroutes: [{ name: r, upstream: a }]\n";
    assert!(promptwall::Policy::from_yaml(&format!("version: 1\n{base}")).is_ok());
    assert!(promptwall::Policy::from_yaml(&format!("version: 2\n{base}")).is_err());
    assert!(promptwall::Policy::from_yaml(&format!("version: 1\nextra: true\n{base}")).is_err());
}
