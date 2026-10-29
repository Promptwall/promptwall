//! Prints the entities a token-classification (NER) model finds in each text,
//! and the time it took.
//! Run with: cargo run --release -p promptwall-classify --example tag_text -- <model dir> <text>...
//! `THREADS=4` lets one inference use four threads.

use std::path::PathBuf;
use std::time::Instant;

use promptwall_classify::{Classifier, Options};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut options = Options::default();
    if let Some(threads) = std::env::var("THREADS").ok().and_then(|t| t.parse().ok()) {
        options.threads_per_session = threads;
    }
    let model = Classifier::load(&PathBuf::from(&args[0]), &options)?;
    let texts: Vec<&str> = args[1..].iter().map(String::as_str).collect();
    // The first run warms the model up.
    model.entities(&texts)?;
    let started = Instant::now();
    let found = model.entities(&texts)?;
    let took = started.elapsed();
    for (text, entities) in texts.iter().zip(found) {
        println!("{text}");
        for e in entities {
            println!(
                "  {:<16} {:.2}  {:?}",
                e.label,
                e.score,
                &text[e.start..e.end]
            );
        }
    }
    println!("took {took:.1?}");
    Ok(())
}
