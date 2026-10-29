//! Tier 2 detectors: small transformer classifiers on CPU with ONNX Runtime.
//!
//! A model directory holds:
//!
//! - `model.onnx`: a sequence-classification model with an `input_ids` and an
//!   `attention_mask` input (and `token_type_ids` if it has one), whose first
//!   output is the logits, shaped `[batch, labels]`.
//! - `tokenizer.json`: the matching Hugging Face tokenizer.
//! - `config.json` (optional): the Hugging Face config. Its `id2label` picks the
//!   label that means "attack" (one containing `injection`, `jailbreak`,
//!   `malicious` or `unsafe`; otherwise label 1), and `max_position_embeddings`
//!   caps the window length.
//!
//! Long texts are split into overlapping windows, and the score is the highest
//! window score, so an attack hidden in a long document is not averaged away.
//!
//! Models with `"problem_type": "multi_label_classification"` in their config
//! give every label an independent probability (sigmoid); others a softmax
//! over the labels. A text can be scored together with a second text, as in
//! natural language inference (premise and hypothesis) or a moderation model
//! that judges an answer together with its prompt: see [`Pair`].
//!
//! Token-classification (NER) models, whose logits are shaped
//! `[batch, tokens, labels]` with `B-`/`I-` labels such as `B-PERSON`, find
//! entities in a text instead: see [`Classifier::entities`].

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use anyhow::{bail, ensure, Context};
use ort::session::builder::GraphOptimizationLevel;
use ort::session::Session;
use ort::value::Tensor;
use tokenizers::Tokenizer;

/// Longest window the classifier sees, in tokens.
const MAX_WINDOW: usize = 512;
/// Tokens shared by neighbouring windows, so a phrase on a boundary is seen
/// whole. Smaller for models with short windows.
const STRIDE: usize = 64;
/// Longest second text of a [`Pair`], in tokens.
const MAX_PAIR: usize = 128;

/// A second text scored together with the windowed one.
#[derive(Clone, Copy, Debug)]
pub enum Pair<'a> {
    None,
    /// Comes first, such as the prompt when judging an answer. Long ones keep
    /// their end.
    Before(&'a str),
    /// Comes second, such as an NLI hypothesis. Long ones keep their start.
    After(&'a str),
}

/// Special tokens of a two-text input: `[CLS] a [SEP] b [SEP]` and similar,
/// with the token type of each part.
#[derive(Debug)]
struct PairTemplate {
    prefix: Vec<u32>,
    mid: Vec<u32>,
    suffix: Vec<u32>,
    /// Token types of the prefix and first text, of `mid`, and of the second
    /// text and suffix.
    types: [i64; 3],
}

#[derive(Clone, Debug)]
pub struct Options {
    /// Sessions that run in parallel. Each one holds its own copy of the model.
    pub sessions: usize,
    /// Threads each session may use for one inference.
    pub threads_per_session: usize,
    /// Most windows scored per text. Longer texts are scored on their last
    /// windows, where the newest user input is.
    pub max_windows: usize,
    /// Most tokens [`Classifier::entities`] tags in one call, over all its
    /// texts and counting window overlaps. Entities must be found everywhere,
    /// so a call that needs more fails instead of skipping text.
    pub max_tag_tokens: usize,
}

impl Default for Options {
    fn default() -> Self {
        let cpus = std::thread::available_parallelism().map_or(1, |n| n.get());
        Self {
            sessions: cpus.min(4),
            threads_per_session: 1,
            max_windows: 8,
            max_tag_tokens: 32_768,
        }
    }
}

pub struct Classifier {
    sessions: Vec<Mutex<Session>>,
    next: AtomicUsize,
    tokenizer: Tokenizer,
    positive: usize,
    labels: Vec<String>,
    multi_label: bool,
    pad_id: u32,
    /// Special tokens before and after each window's text.
    prefix: Vec<u32>,
    suffix: Vec<u32>,
    /// Text tokens per window, and how far each window starts after the last.
    body: usize,
    stride: usize,
    max_len: usize,
    pair: Option<PairTemplate>,
    token_type_ids: bool,
    max_windows: usize,
    max_tag_tokens: usize,
}

impl std::fmt::Debug for Classifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Classifier")
            .field("sessions", &self.sessions.len())
            .field("positive_label", &self.positive)
            .finish()
    }
}

impl Classifier {
    pub fn load(dir: &Path, options: &Options) -> anyhow::Result<Self> {
        let config: serde_json::Value = match std::fs::read(dir.join("config.json")) {
            Ok(bytes) => serde_json::from_slice(&bytes).context("invalid config.json")?,
            Err(_) => serde_json::Value::Null,
        };
        let positive = positive_label(&config);
        let multi_label = config["problem_type"] == "multi_label_classification";
        let max_len = config["max_position_embeddings"]
            .as_u64()
            .map_or(MAX_WINDOW, |n| (n as usize).min(MAX_WINDOW));

        let mut tokenizer = Tokenizer::from_file(dir.join("tokenizer.json"))
            .map_err(|e| anyhow::anyhow!("cannot load tokenizer.json: {e}"))?;
        let pad_id = tokenizer
            .get_padding()
            .map(|p| p.pad_id)
            .or_else(|| {
                ["[PAD]", "<pad>"]
                    .iter()
                    .find_map(|t| tokenizer.token_to_id(t))
            })
            .unwrap_or(0);
        tokenizer.with_padding(None);
        tokenizer
            .with_truncation(None)
            .map_err(|e| anyhow::anyhow!("cannot configure the tokenizer: {e}"))?;
        // Windows are cut here rather than by the tokenizer, whose overflow
        // handling is unreliable; the special tokens around a single text
        // ([CLS] ... [SEP], <s> ... </s>) are learnt from a probe.
        let (prefix, suffix) = special_tokens(&tokenizer)?;
        let pair = pair_template(&tokenizer);
        let body = max_len.saturating_sub(prefix.len() + suffix.len());
        ensure!(body >= 4, "model windows of {max_len} tokens are too short");
        let stride = (body / 8).min(STRIDE);

        let model = dir.join("model.onnx");
        let sessions = (0..options.sessions.max(1))
            .map(|_| {
                Session::builder()?
                    .with_optimization_level(GraphOptimizationLevel::Level3)?
                    .with_intra_threads(options.threads_per_session.max(1))?
                    .commit_from_file(&model)
                    .map(Mutex::new)
            })
            .collect::<Result<Vec<_>, _>>()
            .with_context(|| format!("cannot load {}", model.display()))?;
        let inputs: Vec<String> = sessions[0]
            .lock()
            .expect("not shared yet")
            .inputs
            .iter()
            .map(|i| i.name.clone())
            .collect();
        for required in ["input_ids", "attention_mask"] {
            ensure!(
                inputs.iter().any(|n| n == required),
                "model.onnx has no {required} input"
            );
        }
        if let Some(other) = inputs.iter().find(|n| {
            !matches!(
                n.as_str(),
                "input_ids" | "attention_mask" | "token_type_ids"
            )
        }) {
            bail!("model.onnx has an unsupported input {other:?}");
        }

        Ok(Self {
            token_type_ids: inputs.iter().any(|n| n == "token_type_ids"),
            sessions,
            next: AtomicUsize::new(0),
            tokenizer,
            positive,
            labels: labels(&config),
            multi_label,
            pad_id,
            prefix,
            suffix,
            body,
            stride,
            max_len,
            pair,
            max_windows: options.max_windows.max(1),
            max_tag_tokens: options.max_tag_tokens.max(1),
        })
    }

    /// Label names from the config (`id2label`), in output order. Empty if
    /// the config has none.
    pub fn labels(&self) -> &[String] {
        &self.labels
    }

    /// Probability from 0 to 1 that `text` is an attack. Blocking and CPU-bound:
    /// call it from a blocking thread, not directly on an async runtime.
    pub fn score(&self, text: &str) -> anyhow::Result<f32> {
        if text.trim().is_empty() {
            return Ok(0.0);
        }
        let scores = self.scores(text, Pair::None)?;
        scores
            .get(self.positive)
            .or(scores.first())
            .copied()
            .context("model has no outputs")
    }

    /// Probability of each label for `text`, the highest over its windows.
    /// Blocking and CPU-bound, like [`Classifier::score`].
    pub fn scores(&self, text: &str, pair: Pair) -> anyhow::Result<Vec<f32>> {
        Ok(self.scores_each(text, &[pair])?.remove(0))
    }

    /// [`Classifier::scores`] for several second texts at once (one batch), such
    /// as one hypothesis per topic.
    pub fn scores_each(&self, text: &str, pairs: &[Pair]) -> anyhow::Result<Vec<Vec<f32>>> {
        let encoding = self
            .tokenizer
            .encode(text, false)
            .map_err(|e| anyhow::anyhow!("tokenization failed: {e}"))?;
        let tokens = encoding.get_ids();
        // Rows of (token ids, token types), and which pair each row belongs to.
        let mut rows: Vec<(Vec<u32>, Vec<i64>)> = Vec::new();
        let mut owner = Vec::new();
        for (p, pair) in pairs.iter().enumerate() {
            let second = match pair {
                Pair::None => None,
                Pair::Before(s) | Pair::After(s) => {
                    let ids = self
                        .tokenizer
                        .encode(*s, false)
                        .map_err(|e| anyhow::anyhow!("tokenization failed: {e}"))?
                        .get_ids()
                        .to_vec();
                    Some(match pair {
                        Pair::Before(_) => ids[ids.len().saturating_sub(MAX_PAIR)..].to_vec(),
                        _ => ids[..ids.len().min(MAX_PAIR)].to_vec(),
                    })
                }
            };
            let template = match (&second, &self.pair) {
                (None, _) => None,
                (Some(_), Some(t)) => Some(t),
                (Some(_), None) => bail!("the tokenizer has no template for two texts"),
            };
            let body = match (&second, template) {
                (Some(second), Some(t)) => self
                    .max_len
                    .saturating_sub(t.prefix.len() + t.mid.len() + t.suffix.len() + second.len()),
                _ => self.body,
            };
            ensure!(body >= 4, "model windows are too short for the second text");
            let step = body - (body / 8).min(self.stride);
            let mut starts: Vec<usize> = (0..tokens.len().max(1))
                .step_by(step)
                // A window is needed while the previous one stopped short of the end.
                .take_while(|&start| start == 0 || start + body - step < tokens.len())
                .collect();
            starts.drain(..starts.len().saturating_sub(self.max_windows));
            for start in starts {
                let window = &tokens[start..(start + body).min(tokens.len())];
                let row = match (pair, &second, template) {
                    (Pair::Before(_), Some(first), Some(t)) => t.join(first, window),
                    (Pair::After(_), Some(second), Some(t)) => t.join(window, second),
                    _ => {
                        let ids: Vec<u32> = self
                            .prefix
                            .iter()
                            .chain(window)
                            .chain(&self.suffix)
                            .copied()
                            .collect();
                        let types = vec![0; ids.len()];
                        (ids, types)
                    }
                };
                rows.push(row);
                owner.push(p);
            }
        }

        let probabilities = self.run(&rows)?;
        let labels = probabilities.first().map_or(0, Vec::len);
        let mut out = vec![vec![0.0f32; labels]; pairs.len()];
        for (row, p) in probabilities.into_iter().zip(owner) {
            for (best, v) in out[p].iter_mut().zip(row) {
                *best = best.max(v);
            }
        }
        Ok(out)
    }

    /// Runs the model on `rows` as one padded batch; returns each row's label
    /// probabilities.
    fn run(&self, rows: &[(Vec<u32>, Vec<i64>)]) -> anyhow::Result<Vec<Vec<f32>>> {
        let (out_shape, logits) = self.infer(rows)?;
        ensure!(
            out_shape.len() == 2 && out_shape[0] == rows.len(),
            "unexpected logits shape {out_shape:?}"
        );
        let labels = out_shape[1];
        ensure!(
            labels > 0 && self.positive < labels.max(2),
            "model has {labels} labels"
        );
        Ok(logits
            .chunks(labels)
            .map(|row| {
                if self.multi_label || row.len() == 1 {
                    row.iter().map(|&x| sigmoid(x)).collect()
                } else {
                    softmax(row)
                }
            })
            .collect())
    }

    /// Runs the model on `rows` as one padded batch; returns the shape and
    /// values of its first output.
    fn infer(&self, rows: &[(Vec<u32>, Vec<i64>)]) -> anyhow::Result<(Vec<usize>, Vec<f32>)> {
        let batch = rows.len();
        let len = rows.iter().map(|(ids, _)| ids.len()).max().unwrap_or(0);
        let mut ids = vec![i64::from(self.pad_id); batch * len];
        let mut mask = vec![0i64; batch * len];
        let mut types = vec![0i64; batch * len];
        for (r, (row_ids, row_types)) in rows.iter().enumerate() {
            for (i, (&id, &ty)) in row_ids.iter().zip(row_types).enumerate() {
                ids[r * len + i] = i64::from(id);
                mask[r * len + i] = 1;
                types[r * len + i] = ty;
            }
        }
        let shape = [batch, len];
        let mut inputs = vec![
            ("input_ids", Tensor::from_array((shape, ids))?.into_dyn()),
            (
                "attention_mask",
                Tensor::from_array((shape, mask))?.into_dyn(),
            ),
        ];
        if self.token_type_ids {
            inputs.push((
                "token_type_ids",
                Tensor::from_array((shape, types))?.into_dyn(),
            ));
        }

        let slot = self.next.fetch_add(1, Ordering::Relaxed) % self.sessions.len();
        let mut session = self.sessions[slot]
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let outputs = session.run(inputs)?;
        let (out_shape, logits) = outputs[0].try_extract_tensor::<f32>()?;
        let shape = out_shape.iter().map(|&d| d.max(0) as usize).collect();
        Ok((shape, logits.to_vec()))
    }

    /// Entity types of a token-classification model: its labels without the
    /// `B-`/`I-` prefix and without `O`, such as `PERSON`.
    pub fn entity_types(&self) -> Vec<String> {
        let mut types: Vec<String> = self
            .labels
            .iter()
            .filter_map(|l| entity_type(l).map(str::to_owned))
            .collect();
        types.dedup();
        types
    }

    /// Entities in each of `texts`, found by a token-classification model,
    /// with byte offsets into the text and the model's confidence. Long texts
    /// are tagged in overlapping windows; each token takes its label from the
    /// window where it has the most context. Blocking and CPU-bound, like
    /// [`Classifier::score`].
    pub fn entities(&self, texts: &[&str]) -> anyhow::Result<Vec<Vec<Entity>>> {
        ensure!(
            self.labels.iter().any(|l| entity_type(l).is_some()),
            "the model has no B-/I- entity labels"
        );
        let encodings = texts
            .iter()
            .map(|t| self.tokenizer.encode(*t, false))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("tokenization failed: {e}"))?;
        // Rows of (text, first token, tokens).
        let step = self.body - self.stride;
        let mut rows: Vec<(usize, usize, usize)> = Vec::new();
        for (t, encoding) in encodings.iter().enumerate() {
            let n = encoding.get_ids().len();
            let mut start = 0;
            while start < n {
                rows.push((t, start, (n - start).min(self.body)));
                if start + self.body >= n {
                    break;
                }
                start += step;
            }
        }
        let total: usize = rows.iter().map(|r| r.2).sum();
        ensure!(
            total <= self.max_tag_tokens,
            "the text has {total} tokens to tag, more than the limit of {}",
            self.max_tag_tokens
        );
        // Per text and token: (context on the tighter side, label, probability).
        let mut best: Vec<Vec<(usize, usize, f32)>> = encodings
            .iter()
            .map(|e| vec![(0, 0, 0.0); e.get_ids().len()])
            .collect();
        let mut seen: Vec<Vec<bool>> = best.iter().map(|b| vec![false; b.len()]).collect();
        // Similar lengths go together, so little of each batch is padding.
        let mut order: Vec<usize> = (0..rows.len()).collect();
        order.sort_by_key(|&r| rows[r].2);
        for batch in order.chunks(TAG_BATCH) {
            let inputs: Vec<(Vec<u32>, Vec<i64>)> = batch
                .iter()
                .map(|&r| {
                    let (t, start, len) = rows[r];
                    let ids: Vec<u32> = self
                        .prefix
                        .iter()
                        .chain(&encodings[t].get_ids()[start..start + len])
                        .chain(&self.suffix)
                        .copied()
                        .collect();
                    let types = vec![0; ids.len()];
                    (ids, types)
                })
                .collect();
            let (shape, logits) = self.infer(&inputs)?;
            ensure!(
                shape.len() == 3 && shape[0] == batch.len() && shape[2] == self.labels.len(),
                "unexpected logits shape {shape:?} for a model with {} labels",
                self.labels.len()
            );
            let (seq, labels) = (shape[1], shape[2]);
            for (b, &r) in batch.iter().enumerate() {
                let (t, start, len) = rows[r];
                for i in 0..len {
                    let at = (b * seq + self.prefix.len() + i) * labels;
                    let probs = softmax(&logits[at..at + labels]);
                    let (label, p) = probs
                        .iter()
                        .copied()
                        .enumerate()
                        .fold((0, f32::MIN), |m, (l, p)| if p > m.1 { (l, p) } else { m });
                    let context = i.min(len - 1 - i);
                    let token = start + i;
                    if !seen[t][token] || context > best[t][token].0 {
                        best[t][token] = (context, label, p);
                        seen[t][token] = true;
                    }
                }
            }
        }
        Ok(texts
            .iter()
            .zip(&encodings)
            .zip(&best)
            .map(|((text, encoding), tags)| {
                let tags = tags.iter().map(|&(_, l, p)| (self.labels[l].as_str(), p));
                group(text, encoding.get_offsets(), tags)
            })
            .collect())
    }
}

/// Windows tagged per inference.
const TAG_BATCH: usize = 16;

/// A span of text a token-classification model tagged.
#[derive(Clone, Debug, PartialEq)]
pub struct Entity {
    /// Entity type without `B-`/`I-`, such as `PERSON`.
    pub label: String,
    /// Byte offsets into the text.
    pub start: usize,
    pub end: usize,
    /// Mean probability of its tokens' labels.
    pub score: f32,
}

/// The entity type of a `B-`/`I-` label.
fn entity_type(label: &str) -> Option<&str> {
    label
        .strip_prefix("B-")
        .or_else(|| label.strip_prefix("I-"))
}

/// Joins tagged tokens into entities: a `B-` label starts one, an `I-` label
/// continues one of the same type. Pieces of one type separated only by
/// spaces or punctuation (`+49 30 1234567`) are joined, a span that ends or
/// starts inside a word is widened to the whole word, and whitespace is
/// trimmed.
fn group<'a>(
    text: &str,
    offsets: &[(usize, usize)],
    tags: impl Iterator<Item = (&'a str, f32)>,
) -> Vec<Entity> {
    // (type, start, end, score sum, tokens)
    let mut spans: Vec<(&str, usize, usize, f32, usize)> = Vec::new();
    let mut open = false;
    for (&(start, end), (label, p)) in offsets.iter().zip(tags) {
        let Some(kind) = entity_type(label) else {
            open = false;
            continue;
        };
        match spans.last_mut() {
            Some(last) if open && label.starts_with("I-") && last.0 == kind => {
                last.2 = end;
                last.3 += p;
                last.4 += 1;
            }
            _ => spans.push((kind, start, end, p, 1)),
        }
        open = true;
    }
    let mut merged: Vec<Entity> = Vec::new();
    for (kind, start, end, sum, n) in spans {
        let score = sum / n as f32;
        if let Some(last) = merged.last_mut() {
            let gap = text.get(last.end..start).unwrap_or("x");
            if last.label == kind && gap.len() <= 3 && !gap.chars().any(char::is_alphanumeric) {
                last.end = end;
                last.score = last.score.max(score);
                continue;
            }
        }
        merged.push(Entity {
            label: kind.to_owned(),
            start,
            end,
            score,
        });
    }
    for e in &mut merged {
        widen(text, e);
    }
    merged.retain(|e| e.end > e.start);
    // Widening can make neighbours touch or overlap.
    merged.dedup_by(|later, earlier| {
        if later.start < earlier.end {
            earlier.end = earlier.end.max(later.end);
            true
        } else {
            false
        }
    });
    merged
}

/// Widens `e` to whole words and trims surrounding whitespace. Scripts
/// written without spaces (Chinese, Japanese) are not widened.
fn widen(text: &str, e: &mut Entity) {
    let wordy = |c: char| c.is_alphanumeric() && c < '\u{2E80}';
    let (mut start, mut end) = (e.start.min(text.len()), e.end.min(text.len()));
    while !text.is_char_boundary(start) {
        start -= 1;
    }
    while !text.is_char_boundary(end) {
        end += 1;
    }
    while start < end && text[start..].starts_with(char::is_whitespace) {
        start += text[start..].chars().next().map_or(1, char::len_utf8);
    }
    while end > start && text[..end].ends_with(char::is_whitespace) {
        end -= text[..end].chars().next_back().map_or(1, char::len_utf8);
    }
    if start < end {
        if text[start..].starts_with(wordy) {
            while let Some(c) = text[..start].chars().next_back().filter(|&c| wordy(c)) {
                start -= c.len_utf8();
            }
        }
        if text[..end].ends_with(wordy) {
            while let Some(c) = text[end..].chars().next().filter(|&c| wordy(c)) {
                end += c.len_utf8();
            }
        }
    }
    e.start = start;
    e.end = end;
}

impl PairTemplate {
    fn join(&self, first: &[u32], second: &[u32]) -> (Vec<u32>, Vec<i64>) {
        let [a, m, b] = self.types;
        let ids = [&self.prefix[..], first, &self.mid, second, &self.suffix].concat();
        let types = std::iter::repeat_n(a, self.prefix.len() + first.len())
            .chain(std::iter::repeat_n(m, self.mid.len()))
            .chain(std::iter::repeat_n(b, second.len() + self.suffix.len()))
            .collect();
        (ids, types)
    }
}

fn sigmoid(x: f32) -> f32 {
    1.0 / (1.0 + (-x).exp())
}

fn softmax(row: &[f32]) -> Vec<f32> {
    let max = row.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let exp: Vec<f32> = row.iter().map(|x| (x - max).exp()).collect();
    let sum: f32 = exp.iter().sum();
    exp.into_iter().map(|e| e / sum).collect()
}

/// The special tokens the tokenizer puts before and after a single text.
fn special_tokens(tokenizer: &Tokenizer) -> anyhow::Result<(Vec<u32>, Vec<u32>)> {
    let encode = |special| {
        tokenizer
            .encode("hello", special)
            .map(|e| e.get_ids().to_vec())
            .map_err(|e| anyhow::anyhow!("tokenizer does not work: {e}"))
    };
    let (plain, full) = (encode(false)?, encode(true)?);
    let at = full
        .windows(plain.len())
        .position(|w| w == plain.as_slice())
        .context("cannot find the text inside the tokenizer's template")?;
    Ok((full[..at].to_vec(), full[at + plain.len()..].to_vec()))
}

/// The special tokens around two texts, learnt from a probe; `None` if the
/// tokenizer has no template for pairs.
fn pair_template(tokenizer: &Tokenizer) -> Option<PairTemplate> {
    let plain = |t: &str| {
        tokenizer
            .encode(t, false)
            .ok()
            .map(|e| e.get_ids().to_vec())
    };
    let (a, b) = (plain("hello")?, plain("world")?);
    let full = tokenizer.encode(("hello", "world"), true).ok()?;
    let ids = full.get_ids();
    let at_a = ids.windows(a.len()).position(|w| w == a.as_slice())?;
    let after_a = at_a + a.len();
    let at_b = after_a
        + ids[after_a..]
            .windows(b.len())
            .position(|w| w == b.as_slice())?;
    let ty = |i: usize| full.get_type_ids().get(i).map_or(0, |&t| i64::from(t));
    Some(PairTemplate {
        prefix: ids[..at_a].to_vec(),
        mid: ids[after_a..at_b].to_vec(),
        suffix: ids[at_b + b.len()..].to_vec(),
        types: [
            ty(at_a),
            if at_b > after_a {
                ty(after_a)
            } else {
                ty(at_a)
            },
            ty(at_b),
        ],
    })
}

/// Label names by output index, from `id2label`.
fn labels(config: &serde_json::Value) -> Vec<String> {
    let Some(map) = config["id2label"].as_object() else {
        return Vec::new();
    };
    let mut labels: Vec<(usize, String)> = map
        .iter()
        .filter_map(|(id, name)| Some((id.parse().ok()?, name.as_str()?.to_owned())))
        .collect();
    labels.sort();
    labels.into_iter().map(|(_, name)| name).collect()
}

fn positive_label(config: &serde_json::Value) -> usize {
    config["id2label"]
        .as_object()
        .and_then(|labels| {
            labels.iter().find_map(|(id, name)| {
                let name = name.as_str()?.to_ascii_lowercase();
                ["injection", "jailbreak", "malicious", "unsafe"]
                    .iter()
                    .any(|w| name.contains(w))
                    .then(|| id.parse().ok())?
            })
        })
        .unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn softmax_and_sigmoid() {
        assert!((softmax(&[0.0, 0.0])[1] - 0.5).abs() < 1e-6);
        assert!(softmax(&[0.0, 4.0])[1] > 0.98);
        assert!(sigmoid(4.0) > 0.98);
    }

    #[test]
    fn groups_tokens_into_entities() {
        let text = "Hi Anna Müller, call +49 30 1234567 now";
        // Tokens: "Hi", " Anna", " Mü", "ller", ",", " call", " +49", " 30", " 1234567", " now"
        let offsets = [
            (0, 2),
            (2, 7),
            (7, 11),
            (11, 15),
            (15, 16),
            (16, 21),
            (21, 25),
            (25, 28),
            (28, 36),
            (36, 40),
        ];
        let tags = [
            "O", "B-PERSON", "I-PERSON", "O", "O", "O", "B-PHONE", "B-PHONE", "I-PHONE", "O",
        ];
        let found = group(text, &offsets, tags.iter().map(|&t| (t, 0.9)));
        let spans: Vec<(&str, &str)> = found
            .iter()
            .map(|e| (e.label.as_str(), &text[e.start..e.end]))
            .collect();
        // "ller" was missed by the model, but a name is never cut in half.
        assert_eq!(
            spans,
            [("PERSON", "Anna Müller"), ("PHONE", "+49 30 1234567")]
        );
        // An I- label after O starts an entity of its own.
        let found = group(
            "a b",
            &[(0, 1), (1, 3)],
            ["O", "I-PERSON"].into_iter().map(|t| (t, 0.8)),
        );
        assert_eq!((found[0].start, found[0].end), (2, 3));
    }

    #[test]
    fn finds_the_attack_label() {
        let config = serde_json::json!({"id2label": {"0": "INJECTION", "1": "SAFE"}});
        assert_eq!(positive_label(&config), 0);
        assert_eq!(positive_label(&serde_json::Value::Null), 1);
    }
}
