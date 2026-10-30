//! Any policy file: it is accepted or rejected, never a panic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use promptwall_engine::policy::Policy;

fuzz_target!(|yaml: &str| {
    let _ = Policy::from_yaml(yaml);
});
