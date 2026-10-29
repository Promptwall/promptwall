//! Detection and false-positive rates on a labelled set, for Tier 1 patterns,
//! the classifier, and both together.
//! Run with: cargo run --release -p promptwall-classify --example classify_eval -- <model dir> <set.jsonl>
//! Each line of the set is {"text": "...", "label": 0 or 1, "set": "name"}.

use std::collections::BTreeMap;
use std::path::PathBuf;

use promptwall_classify::{Classifier, Options};
use promptwall_detect::{Category, Detector};

#[derive(Default)]
struct Counts {
    attacks: usize,
    benign: usize,
    /// Per method: (attacks caught, benign flagged).
    hits: BTreeMap<String, (usize, usize)>,
}

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let dir = PathBuf::from(args.next().expect("model dir"));
    let set = std::fs::read_to_string(args.next().expect("set.jsonl"))?;
    let model = Classifier::load(&dir, &Options::default())?;
    let detector = Detector::new();

    let mut sets: BTreeMap<String, Counts> = BTreeMap::new();
    for line in set.lines().filter(|l| !l.trim().is_empty()) {
        let row: serde_json::Value = serde_json::from_str(line)?;
        let text = row["text"].as_str().unwrap_or_default();
        let attack = row["label"].as_i64() == Some(1);
        let name = row["set"].as_str().unwrap_or("all").to_owned();
        let tier1 = detector
            .scan(text)
            .iter()
            .any(|f| f.kind.category() == Category::Injection);
        let score = model.score(text)?;
        for counts in [sets.entry(name).or_default()] {
            if attack {
                counts.attacks += 1;
            } else {
                counts.benign += 1;
            }
            let mut record = |method: String, flagged: bool| {
                let hit = counts.hits.entry(method).or_default();
                if flagged && attack {
                    hit.0 += 1;
                } else if flagged {
                    hit.1 += 1;
                }
            };
            record("1. tier 1 patterns".into(), tier1);
            for t in [0.5, 0.9, 0.99] {
                record(format!("2. classifier >= {t}"), score >= t);
                record(format!("3. both, classifier >= {t}"), tier1 || score >= t);
            }
        }
    }
    for (name, c) in &sets {
        println!("{name}: {} attacks, {} benign", c.attacks, c.benign);
        for (method, (caught, false_pos)) in &c.hits {
            println!(
                "  {method:<32} detection {:>5.1}%   false positives {:>5.1}%",
                100.0 * *caught as f64 / c.attacks.max(1) as f64,
                100.0 * *false_pos as f64 / c.benign.max(1) as f64
            );
        }
    }
    Ok(())
}
