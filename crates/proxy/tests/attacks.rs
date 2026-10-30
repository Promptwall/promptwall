//! The attack corpus (tests/attack-corpus.yaml): bypasses the pattern checks
//! must keep catching, and ordinary text they must let through.

use std::path::Path;

use promptwall::{Policy, Proxy};

#[test]
fn the_attack_corpus_passes() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/attack-corpus.yaml");
    let proxy = Proxy::with_policy(Policy::load(&path).unwrap()).unwrap();
    let results = proxy.run_tests();
    assert!(results.len() >= 70, "{} cases", results.len());
    let failed: Vec<String> = results
        .into_iter()
        .filter_map(|r| r.failure.map(|why| format!("{}: {why}", r.name)))
        .collect();
    assert!(failed.is_empty(), "{}", failed.join("\n"));
}
