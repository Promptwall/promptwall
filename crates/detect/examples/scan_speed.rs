//! Measures how long one scan takes on prompts of different sizes.
//! Run with: cargo run --release -p promptwall-detect --example scan_speed

use std::time::Instant;

use promptwall_detect::Detector;

fn main() {
    let detector = Detector::new();
    let words = [
        "the", "quick", "brown", "fox", "jumps", "over", "lazy", "dog",
    ];
    for tokens in [200, 2_000, 8_000, 32_000] {
        let mut clean = String::new();
        for i in 0..tokens {
            clean.push_str(words[i % words.len()]);
            clean.push(' ');
        }
        let dirty = format!("{clean} contact jane@example.com, IBAN DE89 3704 0044 0532 0130 00");
        // Non-ASCII text takes the slower Unicode paths of the injection rules.
        let german = "Grüße für Jürgen über die Änderungen ".repeat(tokens / 6);
        for (label, text) in [("clean", &clean), ("with PII", &dirty), ("German", &german)] {
            let runs = 200;
            let start = Instant::now();
            let mut found = 0;
            for _ in 0..runs {
                found += detector.scan(text).len();
            }
            let per_scan = start.elapsed() / runs;
            println!(
                "{tokens:>6} tokens ({:>7} bytes), {label:<8}: {per_scan:>10.2?} per scan, {} findings",
                text.len(),
                found / runs as usize
            );
        }
    }
}
