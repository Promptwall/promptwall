//! Response inspection: the `output` detectors of a route.
//!
//! JSON and text responses are read whole, scanned and redacted or blocked.
//! Streamed responses (server-sent events) are scanned as they pass: text
//! deltas are collected from each event, and the last `holdback` characters
//! are held back so that a value split across chunks is still seen whole
//! before any of it is sent on. A block ends the stream with an error event;
//! a redaction rewrites the events that carry the value.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use http::header::{self, HeaderValue};
use http::response::Parts;
use http::{Response, StatusCode};
use http_body_util::{BodyExt, Limited, StreamBody};
use hyper::body::{Frame, Incoming};
use promptwall_detect::{Category, Finding, Kind, SystemPromptIndex};
use serde_json::Value;

use crate::policy::{Action, OutputRules};
use crate::{full, json_error, ProxyBody, ACTION_HEADER, MAX_BODY_BYTES, MAX_SCAN_BYTES};

/// What one request needs for checking its response.
#[derive(Debug)]
pub struct OutputCheck {
    pub route: String,
    pub rules: Arc<OutputRules>,
    pub shadow: bool,
    pub fail_closed: bool,
    /// The request's system prompt, when the leak check is on.
    pub system: Option<SystemPromptIndex>,
}

impl OutputCheck {
    /// Findings in `text` that the route acts on, sorted and without overlaps.
    fn scan(&self, text: &str) -> Vec<(Finding, Action)> {
        let rules = &self.rules;
        let mut found: Vec<Finding> = rules
            .detector
            .scan(text)
            .into_iter()
            .filter(|f| rules.actions.contains_key(&f.kind))
            .filter(|f| {
                f.kind.category() != Category::Exfiltration
                    || !allowed(&text[f.start..f.end], &rules.allow_domains)
            })
            .collect();
        if let Some(index) = &self.system {
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

    fn label(&self, kind: Kind) -> String {
        self.rules.detector.label(kind)
    }

    fn marker(&self, kind: Kind) -> String {
        match kind {
            Kind::Custom(_) => format!(
                "[REDACTED:{}]",
                self.label(kind)
                    .trim_start_matches("custom.")
                    .to_ascii_uppercase()
            ),
            kind => format!("[REDACTED:{}]", kind.entity().to_ascii_uppercase()),
        }
    }

    fn log(&self, action: Action, findings: &BTreeMap<String, usize>, streamed: bool) {
        tracing::info!(
            route = %self.route,
            action = action.as_str(),
            shadow = self.shadow,
            streamed,
            findings = ?findings.iter().map(|(k, n)| format!("{k}={n}")).collect::<Vec<_>>(),
            "sensitive data in response"
        );
    }
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

/// Applies the route's output detectors to a response from the provider.
pub async fn check(check: Arc<OutputCheck>, parts: Parts, body: Incoming) -> Response<ProxyBody> {
    let content_type = parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let encoded = parts
        .headers
        .get(header::CONTENT_ENCODING)
        .is_some_and(|v| v != "identity");
    let textual = content_type.contains("json") || content_type.starts_with("text/");
    if !textual {
        // Images, audio and other binary answers have nothing to scan.
        return Response::from_parts(parts, body.boxed());
    }
    if encoded {
        return unscannable(&check, parts, body.boxed());
    }
    if content_type.starts_with("text/event-stream") {
        return stream(check, parts, body);
    }
    whole(check, parts, body).await
}

fn unscannable(check: &OutputCheck, parts: Parts, body: ProxyBody) -> Response<ProxyBody> {
    tracing::warn!(route = %check.route, fail_closed = check.fail_closed, "response could not be inspected");
    if check.fail_closed && !check.shadow {
        return json_error(
            StatusCode::BAD_GATEWAY,
            "promptwall_uninspectable",
            "Response blocked by Promptwall: it could not be inspected",
            &[],
        );
    }
    Response::from_parts(parts, body)
}

/// A response read whole: JSON (every string value) or plain text.
async fn whole(check: Arc<OutputCheck>, mut parts: Parts, body: Incoming) -> Response<ProxyBody> {
    let bytes = match Limited::new(body, MAX_BODY_BYTES).collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return json_error(
                StatusCode::BAD_GATEWAY,
                "promptwall_upstream_body",
                "The provider's response could not be read",
                &[],
            )
        }
    };
    if bytes.len() > MAX_SCAN_BYTES {
        return unscannable(&check, parts, full(bytes));
    }

    let mut findings = BTreeMap::new();
    let mut action = None;
    let mut changed = false;
    let mut apply = |s: &mut String| {
        let found = check.scan(s);
        if found.is_empty() {
            return;
        }
        for (f, a) in &found {
            *findings.entry(check.label(f.kind)).or_insert(0) += 1;
            action = action.max(Some(*a));
        }
        let spans: Vec<(usize, usize, String)> = found
            .iter()
            .filter(|(_, a)| *a == Action::Redact)
            .map(|(f, _)| (f.start, f.end, check.marker(f.kind)))
            .collect();
        if !spans.is_empty() {
            *s = rewrite(s, 0, &spans);
            changed = true;
        }
    };
    let new_body = if let Ok(mut json) = serde_json::from_slice::<Value>(&bytes) {
        crate::inspect::visit_strings(&mut json, None, false, &mut |s, _, _| apply(s));
        changed.then(|| Bytes::from(serde_json::to_vec(&json).unwrap_or_default()))
    } else if let Ok(text) = std::str::from_utf8(&bytes) {
        let mut text = text.to_owned();
        apply(&mut text);
        changed.then(|| Bytes::from(text))
    } else {
        return unscannable(&check, parts, full(bytes));
    };

    let Some(action) = action else {
        return Response::from_parts(parts, full(bytes));
    };
    check.log(action, &findings, false);
    if check.shadow {
        return Response::from_parts(parts, full(bytes));
    }
    if action == Action::Block {
        return blocked_response(&findings);
    }
    let body = match (action, new_body) {
        (Action::Redact, Some(b)) => b,
        _ => bytes,
    };
    parts.headers.remove(header::CONTENT_LENGTH);
    parts
        .headers
        .insert(header::CONTENT_LENGTH, HeaderValue::from(body.len()));
    let previous = parts.headers.get(ACTION_HEADER).cloned();
    if previous.is_none() || action == Action::Redact {
        parts
            .headers
            .insert(ACTION_HEADER, HeaderValue::from_static(action.as_str()));
    }
    Response::from_parts(parts, full(body))
}

fn blocked_response(findings: &BTreeMap<String, usize>) -> Response<ProxyBody> {
    let kinds: Vec<String> = findings.keys().cloned().collect();
    json_error(
        StatusCode::FORBIDDEN,
        "promptwall_policy_violation",
        &format!(
            "Response blocked by Promptwall policy: {}",
            kinds.join(", ")
        ),
        &kinds,
    )
}

/// Rewrites `text`, which starts at offset `base` of the whole answer, with
/// the redactions `spans` (in whole-answer offsets). A span's marker goes where
/// the span starts; the rest of the span is dropped, including the parts that
/// fall into other chunks.
fn rewrite(text: &str, base: usize, spans: &[(usize, usize, String)]) -> String {
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

/// One server-sent event, held until its text may be released.
struct Event {
    /// The event's lines other than `data:`, such as `event:` and `id:`.
    head: String,
    body: EventBody,
    /// End of this event's text in the whole answer; it can be sent once the
    /// release point has passed it.
    text_end: usize,
}

enum EventBody {
    /// Sent unchanged: comments, `[DONE]`, events without text.
    Raw(Bytes),
    /// JSON with text deltas at `fields` (JSON path, start offset in the answer).
    Delta {
        json: Value,
        fields: Vec<(Vec<PathPart>, usize)>,
    },
}

#[derive(Clone)]
enum PathPart {
    Key(String),
    Index(usize),
}

struct Sse {
    check: Arc<OutputCheck>,
    upstream: Option<Incoming>,
    /// Bytes received but not yet split into events.
    buf: BytesMut,
    pending: VecDeque<Event>,
    /// All text deltas so far, the answer as the user will read it.
    text: String,
    /// Text up to here has been sent.
    released: usize,
    /// Redactions in the unsent part, from the latest scan.
    redactions: Vec<(usize, usize, String)>,
    seen: HashSet<(Kind, usize)>,
    findings: BTreeMap<String, usize>,
    action: Option<Action>,
    finished: bool,
}

/// JSON keys whose string values are answer text in streamed events (OpenAI
/// chat `delta.content`, Responses `delta`, Anthropic `delta.text`, Gemini
/// `parts[].text`).
const DELTA_KEYS: [&str; 3] = ["content", "text", "delta"];

fn stream(check: Arc<OutputCheck>, mut parts: Parts, body: Incoming) -> Response<ProxyBody> {
    parts.headers.remove(header::CONTENT_LENGTH);
    let state = Sse {
        check,
        upstream: Some(body),
        buf: BytesMut::new(),
        pending: VecDeque::new(),
        text: String::new(),
        released: 0,
        redactions: Vec::new(),
        seen: HashSet::new(),
        findings: BTreeMap::new(),
        action: None,
        finished: false,
    };
    let events = futures_util::stream::unfold(state, |mut state| async move {
        loop {
            if state.finished {
                return None;
            }
            let Some(upstream) = state.upstream.as_mut() else {
                state.finished = true;
                state.finish_log();
                return None;
            };
            match upstream.frame().await {
                Some(Ok(frame)) => match frame.into_data() {
                    Ok(data) => {
                        state.buf.extend_from_slice(&data);
                        let out = state.take_events(false);
                        if !out.is_empty() {
                            return Some((Ok(Frame::data(out)), state));
                        }
                    }
                    Err(_) => continue, // trailers: not used by SSE
                },
                Some(Err(err)) => {
                    state.finished = true;
                    return Some((Err(err), state));
                }
                None => {
                    state.upstream = None;
                    let out = state.take_events(true);
                    if !out.is_empty() {
                        return Some((Ok(Frame::data(out)), state));
                    }
                }
            }
        }
    });
    Response::from_parts(parts, StreamBody::new(events).boxed())
}

impl Sse {
    /// Parses complete events from the buffer, scans, and returns what may be sent.
    fn take_events(&mut self, at_end: bool) -> Bytes {
        while let Some(raw) = next_event(&mut self.buf, at_end) {
            self.push(raw);
        }
        self.scan(at_end);
        if self.action == Some(Action::Block) && !self.check.shadow {
            // Drop the held-back text, end the stream with an error event and
            // stop reading from the provider, which closes that connection.
            self.pending.clear();
            self.upstream = None;
            self.finished = true;
            self.finish_log();
            let kinds: Vec<String> = self.findings.keys().cloned().collect();
            let error = serde_json::json!({"error": {
                "type": "promptwall_policy_violation",
                "message": format!("Response blocked by Promptwall policy: {}", kinds.join(", ")),
                "findings": kinds,
            }});
            return Bytes::from(format!("event: error\ndata: {error}\n\n"));
        }
        let release_to = if at_end {
            self.text.len()
        } else {
            floor_char(
                &self.text,
                self.text.len().saturating_sub(self.check.rules.holdback),
            )
        };
        let mut out = BytesMut::new();
        while self
            .pending
            .front()
            .is_some_and(|e| e.text_end <= release_to)
        {
            let event = self.pending.pop_front().expect("checked");
            self.released = self.released.max(event.text_end);
            self.write(event, &mut out);
        }
        if at_end {
            self.finished = true;
            self.finish_log();
        }
        out.freeze()
    }

    fn push(&mut self, raw: Bytes) {
        let Ok(block) = std::str::from_utf8(&raw) else {
            return self.pending.push_back(Event {
                head: String::new(),
                body: EventBody::Raw(raw),
                text_end: self.text.len(),
            });
        };
        let mut head = String::new();
        let mut data = String::new();
        for line in block.lines() {
            if let Some(d) = line.strip_prefix("data:") {
                if !data.is_empty() {
                    data.push('\n');
                }
                data.push_str(d.strip_prefix(' ').unwrap_or(d));
            } else if !line.is_empty() {
                head.push_str(line);
                head.push('\n');
            }
        }
        let json = serde_json::from_str::<Value>(&data).ok();
        let Some(mut json) = json else {
            return self.pending.push_back(Event {
                head: String::new(),
                body: EventBody::Raw(raw),
                text_end: self.text.len(),
            });
        };
        // Final events (OpenAI Responses `*.done`, `response.completed`) repeat
        // the whole answer: check them on their own instead of adding them
        // to the running text.
        let snapshot = json["type"]
            .as_str()
            .is_some_and(|t| t.ends_with(".done") || t.ends_with(".completed"));
        if snapshot {
            self.snapshot(&mut json);
            let text = format!("{head}data: {json}\n\n");
            return self.pending.push_back(Event {
                head: String::new(),
                body: EventBody::Raw(Bytes::from(text)),
                text_end: self.text.len(),
            });
        }
        let mut fields = Vec::new();
        collect_deltas(&json, &mut Vec::new(), None, &mut |path, s| {
            fields.push((path.to_vec(), self.text.len()));
            self.text.push_str(s);
        });
        let body = if fields.is_empty() {
            EventBody::Raw(raw)
        } else {
            EventBody::Delta { json, fields }
        };
        self.pending.push_back(Event {
            head,
            body,
            text_end: self.text.len(),
        });
    }

    /// Scans the unsent text plus some context before it.
    fn scan(&mut self, at_end: bool) {
        let holdback = self.check.rules.holdback;
        let from = floor_char(&self.text, self.released.saturating_sub(holdback));
        let window = &self.text[from..];
        self.redactions.clear();
        for (f, action) in self.check.scan(window) {
            let (start, end) = (from + f.start, from + f.end);
            if end <= self.released {
                continue; // already sent: too late to act on
            }
            if !at_end && end == self.text.len() && f.kind.category() == Category::Exfiltration {
                continue; // the link may still be growing: its host is not known yet
            }
            if self.seen.insert((f.kind, start)) {
                *self.findings.entry(self.check.label(f.kind)).or_insert(0) += 1;
            }
            self.action = self.action.max(Some(action));
            if action == Action::Redact && !self.check.shadow {
                self.redactions
                    .push((start, end, self.check.marker(f.kind)));
            }
        }
    }

    /// Checks a self-contained event (a final event repeating the answer).
    fn snapshot(&mut self, json: &mut Value) {
        let check = self.check.clone();
        crate::inspect::visit_strings(json, None, false, &mut |s, _, _| {
            let found = check.scan(s);
            let mut spans = Vec::new();
            for (f, action) in found {
                self.action = self.action.max(Some(action));
                if action == Action::Redact && !check.shadow {
                    spans.push((f.start, f.end, check.marker(f.kind)));
                }
                // The same value usually streamed as deltas before: count it once.
                self.findings.entry(check.label(f.kind)).or_insert(1);
            }
            if !spans.is_empty() {
                *s = rewrite(s, 0, &spans);
            }
        });
    }

    fn write(&self, event: Event, out: &mut BytesMut) {
        match event.body {
            EventBody::Raw(raw) => out.extend_from_slice(&raw),
            EventBody::Delta { mut json, fields } => {
                if !self.redactions.is_empty() {
                    for (path, start) in &fields {
                        if let Some(Value::String(s)) = pointer_mut(&mut json, path) {
                            *s = rewrite(s, *start, &self.redactions);
                        }
                    }
                }
                out.extend_from_slice(event.head.as_bytes());
                out.extend_from_slice(format!("data: {json}\n\n").as_bytes());
            }
        }
    }

    fn finish_log(&self) {
        if let Some(action) = self.action {
            self.check.log(action, &self.findings, true);
        }
    }
}

/// Splits the next complete event (up to a blank line) off `buf`.
fn next_event(buf: &mut BytesMut, at_end: bool) -> Option<Bytes> {
    let end = buf
        .windows(2)
        .position(|w| w == b"\n\n")
        .map(|i| i + 2)
        .or_else(|| buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4));
    match end {
        Some(end) => Some(buf.split_to(end).freeze()),
        None if at_end && !buf.is_empty() => Some(buf.split().freeze()),
        None => None,
    }
}

fn collect_deltas(
    value: &Value,
    path: &mut Vec<PathPart>,
    key: Option<&str>,
    f: &mut impl FnMut(&[PathPart], &str),
) {
    match value {
        Value::String(s) if key.is_some_and(|k| DELTA_KEYS.contains(&k)) => f(path, s),
        Value::Array(items) => {
            for (i, v) in items.iter().enumerate() {
                path.push(PathPart::Index(i));
                collect_deltas(v, path, key, f);
                path.pop();
            }
        }
        Value::Object(map) => {
            for (k, v) in map {
                path.push(PathPart::Key(k.clone()));
                collect_deltas(v, path, Some(k), f);
                path.pop();
            }
        }
        _ => {}
    }
}

fn pointer_mut<'a>(value: &'a mut Value, path: &[PathPart]) -> Option<&'a mut Value> {
    path.iter().try_fold(value, |v, part| match part {
        PathPart::Key(k) => v.get_mut(k.as_str()),
        PathPart::Index(i) => v.get_mut(*i),
    })
}

fn floor_char(s: &str, mut i: usize) -> usize {
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
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
