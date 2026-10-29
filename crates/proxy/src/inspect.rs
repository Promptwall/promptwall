//! Request body inspection with the Tier 1 detectors.

use std::collections::{BTreeMap, HashMap};

use bytes::Bytes;
use promptwall_detect::{redact, Detector, Kind};
use serde_json::Value;

use crate::policy::Action;

/// Result of inspecting one body.
#[derive(Debug, Default)]
pub struct Outcome {
    /// Most severe action triggered, if anything was found.
    pub action: Option<Action>,
    /// How often each kind was found. Values are never kept.
    pub findings: BTreeMap<Kind, usize>,
    /// The rewritten body, when something was redacted and nothing blocked.
    pub redacted_body: Option<Bytes>,
}

/// The body could not be read as JSON or UTF-8 text.
#[derive(Debug)]
pub struct Unscannable;

/// Scans every string in a JSON body (or the whole body if it is plain text)
/// and applies `actions`. JSON keys are not scanned, only values. A redacted
/// JSON body is re-serialized compactly with its key order preserved.
pub fn inspect(
    detector: &Detector,
    actions: &HashMap<Kind, Action>,
    body: &[u8],
) -> Result<Outcome, Unscannable> {
    let mut outcome = Outcome::default();
    if let Ok(mut json) = serde_json::from_slice::<Value>(body) {
        let mut changed = false;
        visit_strings(&mut json, &mut |s| {
            changed |= scan_string(detector, actions, s, &mut outcome);
        });
        if changed && outcome.action == Some(Action::Redact) {
            // Serializing a parsed Value cannot fail.
            outcome.redacted_body = Some(serde_json::to_vec(&json).unwrap_or_default().into());
        }
    } else if let Ok(text) = std::str::from_utf8(body) {
        let mut text = text.to_owned();
        if scan_string(detector, actions, &mut text, &mut outcome)
            && outcome.action == Some(Action::Redact)
        {
            outcome.redacted_body = Some(text.into());
        }
    } else {
        return Err(Unscannable);
    }
    Ok(outcome)
}

/// Scans one string, records findings and redacts in place. Returns whether it changed.
fn scan_string(
    detector: &Detector,
    actions: &HashMap<Kind, Action>,
    s: &mut String,
    outcome: &mut Outcome,
) -> bool {
    let findings: Vec<_> = detector
        .scan(s)
        .into_iter()
        .filter(|f| actions.contains_key(&f.kind))
        .collect();
    if findings.is_empty() {
        return false;
    }
    for f in &findings {
        let action = actions[&f.kind];
        *outcome.findings.entry(f.kind).or_default() += 1;
        outcome.action = outcome.action.max(Some(action));
    }
    let to_redact: Vec<_> = findings
        .into_iter()
        .filter(|f| actions[&f.kind] == Action::Redact)
        .collect();
    if to_redact.is_empty() {
        return false;
    }
    *s = redact(s, &to_redact);
    true
}

fn visit_strings(value: &mut Value, f: &mut impl FnMut(&mut String)) {
    match value {
        Value::String(s) => f(s),
        Value::Array(items) => items.iter_mut().for_each(|v| visit_strings(v, f)),
        Value::Object(map) => map.values_mut().for_each(|v| visit_strings(v, f)),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn actions(pairs: &[(Kind, Action)]) -> HashMap<Kind, Action> {
        pairs.iter().copied().collect()
    }

    #[test]
    fn redacts_inside_nested_json_and_keeps_structure() {
        let body = br#"{"model":"m","messages":[{"role":"user","content":[{"type":"text","text":"mail jane@example.com"}]}]}"#;
        let out = inspect(
            &Detector::new(),
            &actions(&[(Kind::Email, Action::Redact)]),
            body,
        )
        .unwrap();
        assert_eq!(out.action, Some(Action::Redact));
        assert_eq!(out.findings[&Kind::Email], 1);
        let redacted = out.redacted_body.unwrap();
        assert!(
            redacted.starts_with(br#"{"model":"m","messages""#),
            "key order is kept"
        );
        let json: Value = serde_json::from_slice(&redacted).unwrap();
        assert_eq!(
            json["messages"][0]["content"][0]["text"],
            "mail [REDACTED:EMAIL]"
        );
        assert_eq!(json["model"], "m");
    }

    #[test]
    fn block_wins_over_redact() {
        let body = br#"{"messages":[{"content":"jane@example.com AKIAIOSFODNN7EXAMPLE"}]}"#;
        let acts = actions(&[
            (Kind::Email, Action::Redact),
            (Kind::AwsAccessKey, Action::Block),
        ]);
        let out = inspect(&Detector::new(), &acts, body).unwrap();
        assert_eq!(out.action, Some(Action::Block));
        assert!(out.redacted_body.is_none());
    }

    #[test]
    fn flag_and_unlisted_kinds_leave_body_untouched() {
        let body = br#"{"content":"call +49 151 23456789, mail jane@example.com"}"#;
        let out = inspect(
            &Detector::new(),
            &actions(&[(Kind::Phone, Action::Flag)]),
            body,
        )
        .unwrap();
        assert_eq!(out.action, Some(Action::Flag));
        assert_eq!(
            out.findings.len(),
            1,
            "email is not in the policy, so it is not reported"
        );
        assert!(out.redacted_body.is_none());
    }

    #[test]
    fn handles_plain_text_and_rejects_binary() {
        let acts = actions(&[(Kind::Email, Action::Redact)]);
        let out = inspect(&Detector::new(), &acts, b"hi jane@example.com").unwrap();
        assert_eq!(&out.redacted_body.unwrap()[..], b"hi [REDACTED:EMAIL]");
        assert!(inspect(&Detector::new(), &acts, &[0xff, 0xfe, 0x00]).is_err());
    }
}
