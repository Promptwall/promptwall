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
    pad_id: u32,
    /// Special tokens before and after each window's text.
    prefix: Vec<u32>,
    suffix: Vec<u32>,
    /// Text tokens per window, and how far each window starts after the last.
    body: usize,
    step: usize,
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
            pad_id,
            prefix,
            suffix,
            body,
            step: body - stride,
            max_windows: options.max_windows.max(1),
        })
    }

    /// Probability from 0 to 1 that `text` is an attack. Blocking and CPU-bound:
    /// call it from a blocking thread, not directly on an async runtime.
    pub fn score(&self, text: &str) -> anyhow::Result<f32> {
        if text.trim().is_empty() {
            return Ok(0.0);
        }
        let encoding = self
            .tokenizer
            .encode(text, false)
            .map_err(|e| anyhow::anyhow!("tokenization failed: {e}"))?;
        let tokens = encoding.get_ids();
        let mut starts: Vec<usize> = (0..tokens.len().max(1))
            .step_by(self.step)
            // A window is needed while the previous one stopped short of the end.
            .take_while(|&start| start == 0 || start + self.body - self.step < tokens.len())
            .collect();
        starts.drain(..starts.len().saturating_sub(self.max_windows));

        let batch = starts.len();
        let len = self.prefix.len() + self.body.min(tokens.len()) + self.suffix.len();
        let mut ids = vec![i64::from(self.pad_id); batch * len];
        let mut mask = vec![0i64; batch * len];
        for (row, &start) in starts.iter().enumerate() {
            let window = &tokens[start..(start + self.body).min(tokens.len())];
            let row_ids = self.prefix.iter().chain(window).chain(&self.suffix);
            for (i, &id) in row_ids.enumerate() {
                ids[row * len + i] = i64::from(id);
                mask[row * len + i] = 1;
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
            let types = vec![0i64; batch * len];
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
            .map(|row| probability(row, self.positive))
            .fold(0.0, f32::max))
    }
}

/// Probability of label `positive` from one row of logits: softmax, or a sigmoid
/// for single-logit models.
fn probability(row: &[f32], positive: usize) -> f32 {
    if row.len() == 1 {
        return 1.0 / (1.0 + (-row[0]).exp());
    }
    let max = row.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let sum: f32 = row.iter().map(|x| (x - max).exp()).sum();
    (row[positive] - max).exp() / sum
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
        assert!((probability(&[0.0, 0.0], 1) - 0.5).abs() < 1e-6);
        assert!(probability(&[0.0, 4.0], 1) > 0.98);
        assert!(probability(&[4.0], 0) > 0.98);
    }

    #[test]
    fn finds_the_attack_label() {
        let config = serde_json::json!({"id2label": {"0": "INJECTION", "1": "SAFE"}});
        assert_eq!(positive_label(&config), 0);
        assert_eq!(positive_label(&serde_json::Value::Null), 1);
    }
}
