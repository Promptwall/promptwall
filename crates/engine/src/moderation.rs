//! Content policy with Tier 2 models: harmful or toxic content (a moderation
//! classifier) and topics (a zero-shot NLI classifier).

use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use promptwall_classify::{Classifier, Options, Pair};

use crate::policy::{SafetyRule, TopicRule};

/// Default for `threshold` on `content_safety` and `topics`.
pub const DEFAULT_THRESHOLD: f32 = 0.5;
/// The hypothesis each topic is turned into for the zero-shot model.
const TOPIC_TEMPLATE: &str = "This text is about {}.";

/// A moderation model: either one with an overall `unsafe` label plus harm
/// categories (content-safety guards), or one whose labels are each a kind of
/// harm (Detoxify-style toxicity models).
#[derive(Debug)]
pub struct Safety {
    model: Arc<Classifier>,
    /// Index and default threshold of the overall label, if the model has one.
    gate: Option<(usize, f32)>,
    /// Name, index and threshold of each category.
    categories: Vec<(String, usize, f32)>,
}

impl Safety {
    /// Loads a model directory. Category thresholds come from `thresholds.json`
    /// (`{"unsafe": 0.5, "categories": {"hate": 0.2, ...}}`) when present.
    pub fn load(dir: &Path, options: &Options) -> anyhow::Result<Self> {
        let model = Classifier::load(dir, options)?;
        let thresholds: serde_json::Value = match std::fs::read(dir.join("thresholds.json")) {
            Ok(bytes) => serde_json::from_slice(&bytes).context("invalid thresholds.json")?,
            Err(_) => serde_json::Value::Null,
        };
        let labels = model.labels().to_vec();
        anyhow::ensure!(!labels.is_empty(), "the model config has no id2label");
        let threshold = |v: &serde_json::Value| v.as_f64().map_or(DEFAULT_THRESHOLD, |t| t as f32);
        let gate = labels
            .iter()
            .position(|l| l == "unsafe")
            .map(|i| (i, threshold(&thresholds["unsafe"])));
        let categories = labels
            .into_iter()
            .enumerate()
            .filter(|(i, _)| gate.is_none_or(|(g, _)| g != *i))
            .map(|(i, name)| {
                let t = threshold(&thresholds["categories"][&name]);
                (name, i, t)
            })
            .collect();
        Ok(Self {
            model: Arc::new(model),
            gate,
            categories,
        })
    }

    /// Category names a policy can list as entities.
    pub fn categories(&self) -> impl Iterator<Item = &str> {
        self.categories.iter().map(|(name, _, _)| name.as_str())
    }

    /// Finding labels (`safety.<category>`, or `safety.unsafe` when no single
    /// category stands out) for `text` under `rule`. `prompt` is the request
    /// the text answers, if it is an answer. Blocking and CPU-bound.
    pub fn check(
        &self,
        text: &str,
        prompt: Option<&str>,
        rule: &SafetyRule,
    ) -> anyhow::Result<Vec<String>> {
        if text.trim().is_empty() {
            return Ok(Vec::new());
        }
        let pair = prompt
            .filter(|p| !p.trim().is_empty())
            .map_or(Pair::None, Pair::Before);
        let scores = self.model.scores(text, pair)?;
        let score = |i: usize| scores.get(i).copied().unwrap_or(0.0);
        if let Some((i, default)) = self.gate {
            if score(i) < rule.threshold.unwrap_or(default) {
                return Ok(Vec::new());
            }
        }
        // Without an overall label, the route's threshold applies to every category.
        let flagged: Vec<&str> = self
            .categories
            .iter()
            .filter(|(_, i, t)| {
                score(*i)
                    >= if self.gate.is_some() {
                        *t
                    } else {
                        rule.threshold.unwrap_or(*t)
                    }
            })
            .map(|(name, _, _)| name.as_str())
            .collect();
        if rule.categories.is_empty() {
            if flagged.is_empty() && self.gate.is_some() {
                return Ok(vec!["safety.unsafe".to_owned()]);
            }
            return Ok(flagged.iter().map(|c| format!("safety.{c}")).collect());
        }
        Ok(flagged
            .iter()
            .filter(|c| rule.categories.iter().any(|r| r == *c))
            .map(|c| format!("safety.{c}"))
            .collect())
    }
}

/// A zero-shot classifier (NLI model) that tells whether a text is about a topic.
#[derive(Debug)]
pub struct Topics {
    model: Arc<Classifier>,
    entailment: usize,
}

impl Topics {
    pub fn load(dir: &Path, options: &Options) -> anyhow::Result<Self> {
        let model = Classifier::load(dir, options)?;
        let entailment = model
            .labels()
            .iter()
            .position(|l| l.eq_ignore_ascii_case("entailment"))
            .context("the topic model must be an NLI model with an \"entailment\" label")?;
        Ok(Self {
            model: Arc::new(model),
            entailment,
        })
    }

    /// `topic.denied` when `text` is about a denied topic, `topic.off_topic`
    /// when the rule has allowed topics and the text is about none of them.
    /// Blocking and CPU-bound.
    pub fn check(&self, text: &str, rule: &TopicRule) -> anyhow::Result<Vec<String>> {
        if text.trim().is_empty() {
            return Ok(Vec::new());
        }
        let hypotheses: Vec<String> = rule
            .deny
            .iter()
            .chain(&rule.allow)
            .map(|t| TOPIC_TEMPLATE.replace("{}", t))
            .collect();
        let pairs: Vec<Pair> = hypotheses.iter().map(|h| Pair::After(h)).collect();
        let scores = self.model.scores_each(text, &pairs)?;
        let about =
            |i: usize| scores[i].get(self.entailment).copied().unwrap_or(0.0) >= rule.threshold;
        let mut found = Vec::new();
        if let Some(i) = (0..rule.deny.len()).find(|&i| about(i)) {
            tracing::debug!(topic = %rule.deny[i], "denied topic");
            found.push("topic.denied".to_owned());
        }
        let allowed = rule.deny.len()..hypotheses.len();
        if !rule.allow.is_empty() && !allowed.clone().any(about) {
            found.push("topic.off_topic".to_owned());
        }
        Ok(found)
    }
}
