//! Any request to the WebAssembly interface of the npm package: an answer or
//! an error, never a panic (which would abort the module).
#![no_main]

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use serde_json::{json, Value};

/// A policy loaded once; compiling one per run would leave no time to fuzz.
static HANDLE: LazyLock<Value> = LazyLock::new(|| {
    let policy = "version: 1\nupstreams: {a: {url: 'http://x'}}\nroutes:\n  - {name: r, upstream: a, input: [{detector: pii, action: redact}], output: [{detector: secrets, action: block}]}\n";
    promptwall_wasm::call(json!({"op": "load", "policy": policy}).to_string().as_bytes()).unwrap()["handle"].clone()
});

fuzz_target!(|data: &[u8]| {
    // Raw requests, but not `load` or `drop`, which would make each run slow
    // or free the policy the others use.
    if let Ok(Value::Object(req)) = serde_json::from_slice::<Value>(data) {
        if req.get("op").and_then(Value::as_str).is_some_and(|op| op == "load" || op == "drop") {
            return;
        }
    }
    let _ = promptwall_wasm::call(data);
    let text = String::from_utf8_lossy(data);
    for op in ["check", "inspect"] {
        let req = json!({"op": op, "handle": *HANDLE, "direction": "output", "text": text, "body": text});
        promptwall_wasm::call(req.to_string().as_bytes()).ok();
    }
});
