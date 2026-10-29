//! Runs the tiny fixture model (see fixtures/make_tiny.py): it scores a text
//! as an attack when it contains the word "attack".

use std::path::Path;

use promptwall_classify::{Classifier, Options, Pair};

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

fn fixture(name: &str) -> Classifier {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    Classifier::load(&dir, &Options::default()).unwrap()
}

#[test]
fn multi_label_models_score_each_label_on_its_own() {
    let model = fixture("tiny-safety");
    assert_eq!(model.labels(), ["other", "unsafe"]);
    let scores = model
        .scores("please attack the report", Pair::None)
        .unwrap();
    // Sigmoids, not a softmax: the constant label stays at 0.5.
    assert!(
        (scores[0] - 0.5).abs() < 1e-6 && scores[1] > 0.95,
        "{scores:?}"
    );
}

#[test]
fn scores_a_text_together_with_a_second_one() {
    let model = fixture("tiny-nli");
    let entail = |text: &str, pair| model.scores(text, pair).unwrap()[1];
    assert!(
        entail(
            "please summarise the report",
            Pair::After("this is about attack")
        ) > 0.95
    );
    assert!(entail("please summarise the report", Pair::Before("attack")) > 0.95);
    assert!(
        entail(
            "please summarise the report",
            Pair::After("this is about the weather")
        ) < 0.05
    );
    // One batch for several hypotheses, in order.
    let each = model
        .scores_each("hello", &[Pair::After("attack"), Pair::After("report")])
        .unwrap();
    assert!(each[0][1] > 0.95 && each[1][1] < 0.05);
    // Long texts are windowed; the hypothesis is in every window.
    let long = format!(
        "{} attack",
        "hello please summarise this report ".repeat(30)
    );
    assert!(entail(&long, Pair::After("report")) > 0.95);
}

#[test]
fn tags_entities_in_short_and_long_texts() {
    // Tags "anna" as B-PERSON and "smith" as I-PERSON; its windows are 6 tokens.
    let model = fixture("tiny-ner");
    assert_eq!(model.entity_types(), ["PERSON"]);
    let filler = "hello please summarise this report ".repeat(5);
    let texts = [
        "Hi Anna Smith lives in Berlin".to_owned(),
        format!("{filler}anna smith is here {filler} Anna"),
        "nothing to see".to_owned(),
    ];
    let texts: Vec<&str> = texts.iter().map(String::as_str).collect();
    let found = model.entities(&texts).unwrap();
    let spans: Vec<Vec<&str>> = found
        .iter()
        .zip(&texts)
        .map(|(es, t)| es.iter().map(|e| &t[e.start..e.end]).collect())
        .collect();
    assert_eq!(spans[0], ["Anna Smith"]);
    assert_eq!(spans[1], ["anna smith", "Anna"]);
    assert!(spans[2].is_empty());
    assert_eq!(found[0][0].label, "PERSON");
    assert!(found[0][0].score > 0.99);
}

#[test]
fn refuses_to_tag_more_than_the_token_limit() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tiny-ner");
    let model = Classifier::load(
        &dir,
        &Options {
            max_tag_tokens: 12,
            ..Options::default()
        },
    )
    .unwrap();
    assert!(model.entities(&["anna smith"]).is_ok());
    let long = "hello please summarise this report ".repeat(5);
    let err = model.entities(&[&long]).unwrap_err();
    assert!(format!("{err}").contains("more than the limit"));
    // A classification model has no entity labels.
    assert!(fixture("tiny").entities(&["anna"]).is_err());
}
