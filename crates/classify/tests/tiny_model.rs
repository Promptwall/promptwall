//! Runs the tiny fixture model (see fixtures/make_tiny.py): it scores a text
//! as an attack when it contains the word "attack".

use std::path::Path;

use promptwall_classify::{Classifier, Options};

fn tiny(options: Options) -> Classifier {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tiny");
    Classifier::load(&dir, &options).unwrap()
}

#[test]
fn scores_short_texts() {
    let model = tiny(Options::default());
    assert!(model.score("please attack the report").unwrap() > 0.95);
    assert!(model.score("please summarise the report").unwrap() < 0.05);
    assert_eq!(model.score("   ").unwrap(), 0.0);
}

#[test]
fn finds_an_attack_anywhere_in_a_long_text() {
    // The fixture's windows are 16 tokens; this text is about 40 windows long.
    let model = tiny(Options {
        max_windows: 64,
        ..Options::default()
    });
    let filler = "hello please summarise this report ".repeat(60);
    for text in [
        format!("attack {filler}"),
        format!("{filler} attack {filler}"),
        format!("{filler} attack"),
    ] {
        assert!(
            model.score(&text).unwrap() > 0.95,
            "missed in {} bytes",
            text.len()
        );
    }
    assert!(model.score(&filler).unwrap() < 0.05);
}

#[test]
fn caps_the_windows_it_scores_to_the_end_of_the_text() {
    let model = tiny(Options {
        max_windows: 2,
        ..Options::default()
    });
    let filler = "hello please summarise this report ".repeat(60);
    assert!(model.score(&format!("{filler} attack")).unwrap() > 0.95);
    assert!(model.score(&format!("attack {filler}")).unwrap() < 0.05);
}

#[test]
fn rejects_a_directory_without_a_model() {
    let err = Classifier::load(Path::new("/nonexistent"), &Options::default()).unwrap_err();
    assert!(format!("{err:#}").contains("tokenizer.json"));
}
