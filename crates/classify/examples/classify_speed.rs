//! Measures classifier latency on prompts of different sizes.
//! Run with: cargo run --release -p promptwall-classify --example classify_speed -- <model dir>

use std::path::PathBuf;
use std::time::{Duration, Instant};

use promptwall_classify::{Classifier, Options};

fn main() -> anyhow::Result<()> {
    let dir = PathBuf::from(
        std::env::args()
            .nth(1)
            .expect("usage: classify_speed <model dir>"),
    );
    let sentence = "Please summarise the attached quarterly report for the board and list the three main risks. ";
    for threads in [1, 4] {
        let model = Classifier::load(
            &dir,
            &Options {
                sessions: 1,
                threads_per_session: threads,
                max_windows: 8,
            },
        )?;
        // About 18 tokens per sentence.
        for (label, sentences) in [
            ("~20 tokens", 1),
            ("~130 tokens", 7),
            ("~500 tokens", 28),
            ("~2,000 tokens", 110),
        ] {
            let text = sentence.repeat(sentences);
            model.score(&text)?;
            let runs = if sentences > 28 { 5 } else { 20 };
            let mut times: Vec<Duration> = (0..runs)
                .map(|_| {
                    let start = Instant::now();
                    model.score(&text).unwrap();
                    start.elapsed()
                })
                .collect();
            times.sort();
            println!(
                "threads={threads} {label:<14} p50 {:>8.1?}  max {:>8.1?}",
                times[runs / 2],
                times[runs - 1]
            );
        }
    }
    Ok(())
}
