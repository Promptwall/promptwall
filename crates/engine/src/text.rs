//! Pattern checks (Tier 1) on one prompt or answer, as plain text. The proxy
//! adds the Tier 2 models on top; the WebAssembly build runs these alone.

use std::collections::BTreeMap;

use bytes::Bytes;
use promptwall_detect::{Category, Finding, Kind, SystemPromptIndex};
use serde::Serialize;

use crate::inspect::{self, Collect, Outcome};
use crate::policy::{Action, OutputRules, Route};

/// A prompt or an answer to check.
#[derive(Clone, Copy, Debug)]
pub enum Sample<'a> {
    Input(&'a str),
    Output(&'a str),
}

/// What a route does with one prompt or answer.
#[derive(Debug, Default, Serialize)]
pub struct Verdict {
    /// The most severe action, if anything was found.
    pub action: Option<Action>,
    /// Finding labels and how often each was found.
    pub findings: BTreeMap<String, usize>,
    /// The text as it would be sent on, with redactions.
    pub text: String,
}

/// Checks `sample` with the route's patterns, without the Tier 2 models.
pub fn check(route: &Route, sample: Sample) -> anyhow::Result<Verdict> {
    match sample {
        Sample::Input(text) => {
            let (outcome, _) = inspect_input(route, text, false)?;
            input_verdict(outcome, text)
        }
        Sample::Output(text) => Ok(match &route.output {
            Some(rules) => check_output(rules, text),
            None => Verdict {
                text: text.to_owned(),
                ..Verdict::default()
            },
        }),
    }
}

/// Inspects a prompt as the user message of a chat request, the way the proxy
/// inspects request bodies; returns the outcome and the body it built.
pub fn inspect_input(
    route: &Route,
    text: &str,
    untrusted: bool,
) -> anyhow::Result<(Outcome, Bytes)> {
    let body = serde_json::json!({"messages": [{"role": "user", "content": text}]});
    let body = Bytes::from(body.to_string());
    let collect = Collect {
        untrusted,
        trusted: false,
    };
    let outcome = inspect::inspect(&route.detector, &route.input, &body, collect, &route.except)
        .map_err(|_| anyhow::anyhow!("the text could not be inspected"))?;
    Ok((outcome, body))
}

/// The verdict for a prompt inspected with [`inspect_input`]: the redacted
/// prompt when the action is redact, the original otherwise.
pub fn input_verdict(outcome: Outcome, text: &str) -> anyhow::Result<Verdict> {
    let text = match (&outcome.redacted_body, outcome.action) {
        (Some(body), Some(Action::Redact)) => serde_json::from_slice::<serde_json::Value>(body)?
            ["messages"][0]["content"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
        _ => text.to_owned(),
    };
    Ok(Verdict {
        action: outcome.action,
        findings: outcome.findings,
        text,
    })
}

/// Checks an answer with the route's output patterns: the redacted answer
/// when the action is redact, the original otherwise.
pub fn check_output(rules: &OutputRules, text: &str) -> Verdict {
    let mut verdict = Verdict {
        text: text.to_owned(),
        ..Default::default()
    };
    let mut spans = Vec::new();
    for (f, action) in scan_output(rules, None, text) {
        *verdict
            .findings
            .entry(rules.detector.label(f.kind))
            .or_insert(0) += 1;
        verdict.action = verdict.action.max(Some(action));
        if action == Action::Redact {
            spans.push((f.start, f.end, marker(rules, f.kind)));
        }
    }
    if verdict.action == Some(Action::Redact) {
        verdict.text = rewrite(text, 0, &spans);
    }
    verdict
}

/// Findings in `text` that the output rules act on, sorted and without
/// overlaps. `system` is the request's system prompt, for the leak check.
pub fn scan_output(
    rules: &OutputRules,
    system: Option<&SystemPromptIndex>,
    text: &str,
) -> Vec<(Finding, Action)> {
    if rules.actions.is_empty() {
        return Vec::new(); // only tool calls are checked
    }
    let mut found: Vec<Finding> = rules
        .detector
        .scan(text)
        .into_iter()
        .filter(|f| rules.actions.contains_key(&f.kind))
        .filter(|f| {
            f.kind.category() != Category::Exfiltration
                || !allowed(&text[f.start..f.end], &rules.allow_domains)
        })
        .filter(|f| !inspect::excepted(&rules.except, f.kind, &text[f.start..f.end]))
        .collect();
    if let Some(index) = system {
        if rules.actions.contains_key(&Kind::SystemPromptLeak) {
            found.extend(index.find(text));
            found.sort_by_key(|f| (f.start, std::cmp::Reverse(f.end)));
            let mut merged: Vec<Finding> = Vec::with_capacity(found.len());
            for f in found {
                if merged.last().is_none_or(|last| f.start >= last.end) {
                    merged.push(f);
                }
            }
            found = merged;
        }
    }
    found
        .into_iter()
        .map(|f| (f, rules.actions[&f.kind]))
        .collect()
}

/// What a redacted value of `kind` is replaced with in an answer.
pub fn marker(rules: &OutputRules, kind: Kind) -> String {
    match kind {
        Kind::Custom(_) => format!(
            "[REDACTED:{}]",
            rules
                .detector
                .label(kind)
                .trim_start_matches("custom.")
                .to_ascii_uppercase()
        ),
        kind => format!("[REDACTED:{}]", kind.entity().to_ascii_uppercase()),
    }
}

/// Rewrites `text`, which starts at offset `base` of the whole answer, with
/// the redactions `spans` (in whole-answer offsets). A span's marker goes where
/// the span starts; the rest of the span is dropped, including the parts that
/// fall into other chunks.
pub fn rewrite(text: &str, base: usize, spans: &[(usize, usize, String)]) -> String {
    let end = base + text.len();
    let mut out = String::with_capacity(text.len());
    let mut pos = base;
    for (s, e, marker) in spans {
        if *e <= pos || *s >= end {
            continue;
        }
        if *s >= pos {
            out.push_str(&text[pos - base..*s - base]);
            out.push_str(marker);
        }
        pos = (*e).min(end);
    }
    out.push_str(&text[pos - base..]);
    out
}

/// Whether the host of `url` is one of `domains` or a subdomain of one.
fn allowed(url: &str, domains: &[String]) -> bool {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority
        .rsplit('@')
        .next()
        .unwrap_or_default()
        .split(':')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    domains
        .iter()
        .any(|d| host == *d || host.ends_with(&format!(".{d}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrite_spans_across_chunks() {
        let spans = vec![(4, 13, "[X]".to_string())];
        // Whole answer: "abc jane@x.io def", split into three chunks.
        assert_eq!(rewrite("abc ja", 0, &spans), "abc [X]");
        assert_eq!(rewrite("ne@x.", 6, &spans), "");
        assert_eq!(rewrite("io def", 11, &spans), " def");
    }

    #[test]
    fn allowed_domains() {
        let domains = vec!["example.com".to_string()];
        assert!(allowed("https://cdn.example.com/a.png", &domains));
        assert!(allowed("https://example.com:8443/a.png?x=1", &domains));
        assert!(!allowed("https://example.com.evil.io/a.png", &domains));
        assert!(!allowed("https://evil.io/?u=example.com", &domains));
    }
}
