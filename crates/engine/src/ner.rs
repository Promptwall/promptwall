//! Names, addresses and other personal data without a fixed pattern, found by
//! a Tier 2 token-classification (NER) model. A policy names these entities
//! under the `pii` detector next to the built-in ones, in lower case
//! (`person`, `street_address`), and they are flagged, redacted or blocked
//! like any other finding.

use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, HashMap};
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::sync::Mutex;

use promptwall_classify::{Classifier, Entity, Options};
use serde_json::Value;

use crate::policy::{Action, PiiRule};

/// Default for `threshold` on `pii` entries with model entities.
pub const DEFAULT_THRESHOLD: f32 = 0.5;

/// Texts whose entities are remembered. Chat clients send the whole
/// conversation with every request, so most messages were tagged before.
const CACHE_ENTRIES: usize = 10_000;

/// A token-classification model, with a cache of the entities it found.
#[derive(Debug)]
pub struct PiiModel {
    model: Classifier,
    /// Entity names a policy can list, in lower case.
    entities: Vec<String>,
    /// Entities by a hash of the text. Only offsets and labels are kept,
    /// never the text.
    cache: Mutex<HashMap<(u64, usize), Vec<Entity>>>,
}

/// One entity a rule acts on, in byte offsets of its text.
#[derive(Clone, Debug, PartialEq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
    /// Lower-case entity name, such as `person`.
    pub entity: String,
    pub action: Action,
}

impl Span {
    pub fn label(&self) -> String {
        format!("pii.{}", self.entity)
    }

    pub fn marker(&self) -> String {
        format!("[REDACTED:{}]", self.entity.to_ascii_uppercase())
    }
}

/// What tagging a body found.
#[derive(Debug, Default)]
pub struct Tagged {
    pub findings: BTreeMap<String, usize>,
    pub action: Option<Action>,
    /// Whether something was redacted.
    pub changed: bool,
}

impl PiiModel {
    pub fn load(dir: &Path, options: &Options) -> anyhow::Result<Self> {
        Self::new(Classifier::load(dir, options)?)
    }

    pub fn new(model: Classifier) -> anyhow::Result<Self> {
        let entities: Vec<String> = model
            .entity_types()
            .iter()
            .map(|t| t.to_ascii_lowercase())
            .collect();
        anyhow::ensure!(
            !entities.is_empty(),
            "the PII model must be a token-classification model with B-/I- labels"
        );
        Ok(Self {
            model,
            entities,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// Entity names a policy can list.
    pub fn entities(&self) -> &[String] {
        &self.entities
    }

    /// The entities in each text that `rule` acts on. Blocking and CPU-bound.
    pub fn find(&self, texts: &[&str], rule: &PiiRule) -> anyhow::Result<Vec<Vec<Span>>> {
        let keys: Vec<(u64, usize)> = texts.iter().map(|t| key(t)).collect();
        let mut found: Vec<Option<Vec<Entity>>> = {
            let cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
            keys.iter().map(|k| cache.get(k).cloned()).collect()
        };
        let missing: Vec<usize> = (0..texts.len())
            .filter(|&i| found[i].is_none() && !texts[i].trim().is_empty())
            .collect();
        if !missing.is_empty() {
            let batch: Vec<&str> = missing.iter().map(|&i| texts[i]).collect();
            let tagged = self.model.entities(&batch)?;
            let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
            if cache.len() + tagged.len() > CACHE_ENTRIES {
                cache.clear();
            }
            for (i, entities) in missing.into_iter().zip(tagged) {
                cache.insert(keys[i], entities.clone());
                found[i] = Some(entities);
            }
        }
        Ok(found
            .into_iter()
            .zip(texts)
            .map(|(entities, text)| {
                entities
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|e| {
                        let entity = e.label.to_ascii_lowercase();
                        let rule = rule.entities.get(&entity)?;
                        let value = text.get(e.start..e.end)?;
                        let excepted = rule
                            .except
                            .iter()
                            .any(|p| crate::tools::glob(p, value.trim()));
                        (e.score >= rule.threshold && !excepted).then_some(Span {
                            start: e.start,
                            end: e.end,
                            entity,
                            action: rule.action,
                        })
                    })
                    .collect()
            })
            .collect())
    }

    /// Tags the strings under `keys` in `json`; redacts the spans whose
    /// action is redact. Blocking and CPU-bound.
    pub fn tag_json(
        &self,
        rule: &PiiRule,
        json: &mut Value,
        keys: &[&str],
    ) -> anyhow::Result<Tagged> {
        let wanted = |key: Option<&str>| key.is_some_and(|k| keys.contains(&k));
        // The text of attachments is tagged like any other prompt text.
        let opened = crate::attachments::open(json);
        let mut texts = Vec::new();
        crate::inspect::visit_strings(json, None, false, &mut |s, key, _| {
            if wanted(key) {
                texts.push(s.clone());
            }
        });
        let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
        let mut spans = match self.find(&refs, rule) {
            Ok(spans) => spans.into_iter(),
            Err(err) => {
                crate::attachments::close(json, opened);
                return Err(err);
            }
        };
        let mut tagged = Tagged::default();
        crate::inspect::visit_strings(json, None, false, &mut |s, key, _| {
            if wanted(key) {
                apply(s, &spans.next().unwrap_or_default(), &mut tagged);
            }
        });
        tagged.changed |= crate::attachments::close(json, opened);
        Ok(tagged)
    }

    /// Tags a plain-text body. Blocking and CPU-bound.
    pub fn tag_text(&self, rule: &PiiRule, text: &mut String) -> anyhow::Result<Tagged> {
        let spans = self.find(&[text.as_str()], rule)?.remove(0);
        let mut tagged = Tagged::default();
        apply(text, &spans, &mut tagged);
        Ok(tagged)
    }
}

/// Records `spans` found in `s` and redacts those whose action is redact.
fn apply(s: &mut String, spans: &[Span], tagged: &mut Tagged) {
    let mut out = String::new();
    let mut pos = 0;
    for span in spans {
        *tagged.findings.entry(span.label()).or_default() += 1;
        tagged.action = tagged.action.max(Some(span.action));
        if span.action == Action::Redact && span.start >= pos {
            out.push_str(&s[pos..span.start]);
            out.push_str(&span.marker());
            pos = span.end;
        }
    }
    if pos > 0 {
        out.push_str(&s[pos..]);
        *s = out;
        tagged.changed = true;
    }
}

fn key(text: &str) -> (u64, usize) {
    let mut hasher = DefaultHasher::new();
    text.hash(&mut hasher);
    (hasher.finish(), text.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_only_the_spans_to_redact() {
        let mut s = "Hi Anna Smith from Acme".to_owned();
        let spans = [
            Span {
                start: 3,
                end: 13,
                entity: "person".into(),
                action: Action::Redact,
            },
            Span {
                start: 19,
                end: 23,
                entity: "organization".into(),
                action: Action::Flag,
            },
        ];
        let mut tagged = Tagged::default();
        apply(&mut s, &spans, &mut tagged);
        assert_eq!(s, "Hi [REDACTED:PERSON] from Acme");
        assert_eq!(tagged.action, Some(Action::Redact));
        assert_eq!(tagged.findings["pii.organization"], 1);
        assert!(tagged.changed);
    }
}
