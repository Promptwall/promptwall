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
}

impl Default for Options {
    fn default() -> Self {
        let cpus = std::thread::available_parallelism().map_or(1, |n| n.get());
        Self {
            sessions: cpus.min(4),
            threads_per_session: 1,
            max_windows: 8,
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
        ensure!(
            out_shape.len() == 2 && out_shape[0] as usize == batch,
            "unexpected logits shape {out_shape:?}"
        );
        let labels = out_shape[1] as usize;
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
    fn finds_the_attack_label() {
        let config = serde_json::json!({"id2label": {"0": "INJECTION", "1": "SAFE"}});
        assert_eq!(positive_label(&config), 0);
        assert_eq!(positive_label(&serde_json::Value::Null), 1);
    }
}
