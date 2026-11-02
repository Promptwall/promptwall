//! Writes the classifier's raw score for every row of a labelled set, so the
//! benchmark can sweep thresholds without running the model again.
//! Run with: cargo run --release -p promptwall-classify --example classify_scores -- <model dir> <in.jsonl> <out.jsonl> [--all]
//! Each output line is {"i": row number, "score": 0 to 1, "ms": time to score}.
//! `--all` scores every part of long texts, not only the last 8 windows as the
//! firewall does today: the text is cut into overlapping pieces of about 2,000
//! tokens and the highest piece score is kept. (One batch of every window at
//! once needs too much memory for 32k-token texts.)

use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use promptwall_classify::{Classifier, Options};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [dir, input, output, ..] = &args[..] else {
        anyhow::bail!("usage: classify_scores <model dir> <in.jsonl> <out.jsonl> [--all]");
    };
    let all = args.iter().any(|a| a == "--all");
    let max_windows = 8;
    let workers = std::thread::available_parallelism().map_or(1, |n| n.get());
    let model = Classifier::load(
        &PathBuf::from(dir),
        &Options {
            sessions: workers,
            threads_per_session: 1,
            max_windows,
            ..Options::default()
        },
    )?;
    let texts: Vec<String> = std::fs::read_to_string(input)?
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let row: serde_json::Value = serde_json::from_str(l)?;
            Ok(row["text"].as_str().unwrap_or_default().to_owned())
        })
        .collect::<anyhow::Result<_>>()?;

    let next = AtomicUsize::new(0);
    let results = Mutex::new(vec![(0.0f32, 0.0f64); texts.len()]);
    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some(text) = texts.get(i) else { break };
                let start = Instant::now();
                let score = if all {
                    pieces(text)
                        .map(|p| model.score(p).unwrap_or(f32::NAN))
                        .fold(0.0f32, f32::max)
                } else {
                    model.score(text).unwrap_or(f32::NAN)
                };
                let ms = start.elapsed().as_secs_f64() * 1000.0;
                results.lock().unwrap()[i] = (score, ms);
                if (i + 1) % 500 == 0 {
                    eprintln!("{} of {}", i + 1, texts.len());
                }
            });
        }
    });

    let mut out = std::io::BufWriter::new(std::fs::File::create(output)?);
    for (i, (score, ms)) in results.into_inner().unwrap().into_iter().enumerate() {
        writeln!(
            out,
            "{}",
            serde_json::json!({ "i": i, "score": score, "ms": ms })
        )?;
    }
    Ok(())
}

/// Overlapping pieces of about 8,000 bytes (2,000 tokens), cut at char boundaries.
fn pieces(text: &str) -> impl Iterator<Item = &str> {
    const PIECE: usize = 8_000;
    const OVERLAP: usize = 1_000;
    let mut start = 0;
    std::iter::from_fn(move || {
        if start >= text.len() {
            return None;
        }
        let mut end = (start + PIECE).min(text.len());
        while !text.is_char_boundary(end) {
            end += 1;
        }
        let piece = &text[start..end];
        start = if end == text.len() {
            end
        } else {
            end - OVERLAP
        };
        while start < text.len() && !text.is_char_boundary(start) {
            start += 1;
        }
        Some(piece)
    })
}
