//! Prints a model's label probabilities for one text, optionally scored
//! together with a second text, and the time it took.
//! Run with: cargo run --release -p promptwall-classify --example classify_text -- <model dir> <text> [--before <text> | --after <text>]

use std::path::PathBuf;
use std::time::Instant;

use promptwall_classify::{Classifier, Options, Pair};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let model = Classifier::load(&PathBuf::from(&args[0]), &Options::default())?;
    let pair = match args.get(2).map(String::as_str) {
        Some("--before") => Pair::Before(&args[3]),
        Some("--after") => Pair::After(&args[3]),
        _ => Pair::None,
    };
    let started = Instant::now();
    let scores = model.scores(&args[1], pair)?;
    let took = started.elapsed();
    for (i, score) in scores.iter().enumerate() {
        let label = model.labels().get(i).map_or("?", String::as_str);
        println!("{label:<20} {score:.3}");
    }
    println!("took {took:.1?}");
    Ok(())
}
