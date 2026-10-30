//! Any text: findings must be in order, apart, on character boundaries, and
//! redacting them must work.
#![no_main]

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use promptwall_detect::Detector;

static DETECTOR: LazyLock<Detector> = LazyLock::new(Detector::new);

fuzz_target!(|text: &str| {
    let found = DETECTOR.scan(text);
    let mut end = 0;
    for f in &found {
        assert!(f.start >= end && f.start < f.end && f.end <= text.len());
        assert!(text.is_char_boundary(f.start) && text.is_char_boundary(f.end));
        end = f.end;
    }
    let _ = DETECTOR.redact(text, &found);
    for f in DETECTOR.scan_evasions(text, &found) {
        assert!(text.is_char_boundary(f.start) && text.is_char_boundary(f.end));
    }
});
