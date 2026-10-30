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
use promptwall_engine::text::{self, rewrite};
use serde_json::Value;

use crate::moderation::Safety;
use crate::ner::{PiiModel, Span, Tagged};
use crate::policy::{Action, OutputRules, PiiRule, SafetyRule};
use crate::tools::{StreamCalls, ToolCall, ToolRules};
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
    /// Limits on the tool calls in the answer.
    pub tools: Option<Arc<ToolRules>>,
    /// Harmful content in the answer, with the model that judges it.
    pub safety: Option<(SafetyRule, Arc<Safety>)>,
    /// Names, addresses and other entities in the answer, with the model that
    /// finds them.
    pub pii: Option<(Arc<PiiRule>, Arc<PiiModel>)>,
    /// The end of the request's prompt, to judge the answer in context.
    pub prompt: String,
    /// The request's decision log event, if the log is on.
    pub decision: Option<crate::decision::Record>,
}

impl OutputCheck {
    /// Findings in `text` that the route acts on, sorted and without overlaps.
    fn scan(&self, text: &str) -> Vec<(Finding, Action)> {
        text::scan_output(&self.rules, self.system.as_ref(), text)
    }

    /// Records the tool calls that break the route's tool rules; returns the
    /// action they call for.
    fn check_tools(
        &self,
        calls: &[ToolCall],
        findings: &mut BTreeMap<String, usize>,
    ) -> Option<Action> {
        let rules = self.tools.as_ref()?;
        let mut hit = false;
        for call in calls {
            for label in rules.check(call) {
                tracing::debug!(route = %self.route, tool = %call.name, label, "tool call rejected");
                *findings.entry(label.to_owned()).or_insert(0) += 1;
                hit = true;
            }
        }
        hit.then_some(rules.action)
    }

    fn label(&self, kind: Kind) -> String {
        self.rules.detector.label(kind)
    }

    fn marker(&self, kind: Kind) -> String {
        text::marker(&self.rules, kind)
    }

    /// Whether a Tier 2 model must see answer text before it is sent.
    fn models_gate(&self) -> bool {
        self.safety.is_some() || self.pii.is_some()
    }

    fn log(&self, action: Action, findings: &BTreeMap<String, usize>, streamed: bool) {
        crate::metrics::findings(&self.route, "response", findings);
        if let Some(record) = &self.decision {
            record.update(|e| e.response.record(action, findings));
        }
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

/// Checks one answer text the way [`whole`] checks an answer, for
/// [`crate::Proxy::check`]. Blocking: the models run inline.
pub(crate) fn check_text(check: &OutputCheck, text: &str) -> anyhow::Result<crate::Verdict> {
    let mut verdict = text::check_output(&check.rules, text);
    if let Some((rule, model)) = &check.safety {
        let labels = model.check(text, None, rule)?;
        if !labels.is_empty() {
            verdict.action = verdict.action.max(Some(rule.action));
        }
        for label in labels {
            *verdict.findings.entry(label).or_insert(0) += 1;
        }
    }
    if let Some((rule, model)) = &check.pii {
        let tagged = model.tag_text(rule, &mut verdict.text)?;
        for (label, n) in tagged.findings {
            *verdict.findings.entry(label).or_insert(0) += n;
        }
        verdict.action = verdict.action.max(tagged.action);
    }
    if verdict.action != Some(Action::Redact) {
        verdict.text = text.to_owned();
    }
    Ok(verdict)
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
    crate::metrics::count(
        "promptwall_uninspected_total",
        &[("route", &check.route), ("direction", "response")],
        1,
    );
    if let Some(record) = &check.decision {
        record.update(|e| e.response.uninspected = true);
    }
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
    let mut tool_action = None;
    // The answer's text, for the moderation model.
    let mut answer = String::new();
    let doc = if let Ok(mut json) = serde_json::from_slice::<Value>(&bytes) {
        crate::inspect::visit_strings(&mut json, None, false, &mut |s, key, _| {
            if check.safety.is_some() && key.is_some_and(|k| ANSWER_KEYS.contains(&k)) {
                answer.push_str(s);
                answer.push('\n');
            }
            apply(s)
        });
        let mut tool_findings = BTreeMap::new();
        tool_action = check.check_tools(&crate::tools::calls(&json), &mut tool_findings);
        findings.extend(tool_findings);
        Doc::Json(json)
    } else if let Ok(text) = std::str::from_utf8(&bytes) {
        let mut text = text.to_owned();
        if check.safety.is_some() {
            answer = text.clone();
        }
        apply(&mut text);
        Doc::Text(text)
    } else {
        return unscannable(&check, parts, full(bytes));
    };
    let (doc, pii_action) = match tag_answer(&check, doc).await {
        Ok((doc, tagged)) => {
            changed |= tagged.changed;
            for (label, n) in tagged.findings {
                *findings.entry(label).or_insert(0) += n;
            }
            (doc, tagged.action)
        }
        Err(_) if check.fail_closed && !check.shadow => return unjudged(),
        Err(Some(doc)) => (doc, None),
        // The model panicked and took the answer with it: without it, the
        // redactions made so far cannot be sent.
        Err(None) if changed && !check.shadow => return unjudged(),
        Err(None) => return Response::from_parts(parts, full(bytes)),
    };
    let new_body = match doc {
        Doc::Json(json) if changed => {
            Some(Bytes::from(serde_json::to_vec(&json).unwrap_or_default()))
        }
        Doc::Text(text) if changed => Some(Bytes::from(text)),
        _ => None,
    };
    let safety_action = match judge(&check, answer).await {
        Ok(Some((labels, action))) => {
            for label in labels {
                *findings.entry(label).or_insert(0) += 1;
            }
            Some(action)
        }
        Ok(None) => None,
        Err(()) if check.fail_closed && !check.shadow => return unjudged(),
        Err(()) => None,
    };

    let Some(action) = action.max(tool_action).max(safety_action).max(pii_action) else {
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

/// JSON keys whose strings are the text of an answer (`content`, `text`),
/// as opposed to IDs, roles or tool arguments.
const ANSWER_KEYS: [&str; 2] = ["content", "text"];

/// A whole answer, parsed.
enum Doc {
    Json(Value),
    Text(String),
}

/// Runs the PII model on a whole answer, if the route has model entities on
/// its answers, and redacts. When the model fails, `Err` holds the answer
/// as it was, or `None` if it was lost to a panic.
async fn tag_answer(check: &Arc<OutputCheck>, doc: Doc) -> Result<(Doc, Tagged), Option<Doc>> {
    let Some((rule, model)) = check.pii.clone() else {
        return Ok((doc, Tagged::default()));
    };
    let task = tokio::task::spawn_blocking(move || {
        let mut doc = doc;
        let tagged = match &mut doc {
            Doc::Json(json) => model.tag_json(&rule, json, &ANSWER_KEYS),
            Doc::Text(text) => model.tag_text(&rule, text),
        };
        (doc, tagged)
    });
    match task.await {
        Ok((doc, Ok(tagged))) => Ok((doc, tagged)),
        Ok((doc, Err(err))) => {
            tracing::warn!(route = %check.route, error = %format!("{err:#}"), "PII model failed on the answer");
            Err(Some(doc))
        }
        Err(err) => {
            tracing::warn!(route = %check.route, error = %err, "PII model panicked on the answer");
            Err(None)
        }
    }
}

/// Runs the moderation model on `text`, if the route has `content_safety` on
/// its answers. `Ok(None)` when the text is fine, `Err` when the model failed.
async fn judge(
    check: &Arc<OutputCheck>,
    text: String,
) -> Result<Option<(Vec<String>, Action)>, ()> {
    let Some((rule, model)) = check.safety.clone() else {
        return Ok(None);
    };
    let prompt = check.prompt.clone();
    let action = rule.action;
    let task = tokio::task::spawn_blocking(move || model.check(&text, Some(&prompt), &rule));
    match task.await {
        Ok(Ok(labels)) if labels.is_empty() => Ok(None),
        Ok(Ok(labels)) => Ok(Some((labels, action))),
        Ok(Err(err)) => {
            tracing::warn!(route = %check.route, error = %format!("{err:#}"), "safety model failed on the answer");
            Err(())
        }
        Err(err) => {
            tracing::warn!(route = %check.route, error = %err, "safety model panicked on the answer");
            Err(())
        }
    }
}

fn unjudged() -> Response<ProxyBody> {
    json_error(
        StatusCode::BAD_GATEWAY,
        "promptwall_uninspectable",
        "Response blocked by Promptwall: it could not be checked",
        &[],
    )
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

/// One server-sent event, held until its text may be released.
struct Event {
    /// The event's lines other than `data:`, such as `event:` and `id:`.
    head: String,
    body: EventBody,
    /// End of this event's text in the whole answer; it can be sent once the
    /// release point has passed it.
    text_end: usize,
    /// Part of or after a tool call, held until the calls are checked at the
    /// end of the stream.
    held: bool,
}

enum EventBody {
    /// Sent unchanged: comments, `[DONE]`, events without text.
    Raw(Bytes),
    /// JSON with text deltas at `fields` (JSON path, start offset in the answer).
    Delta {
        json: Value,
        fields: Vec<(Vec<PathPart>, usize)>,
    },
    /// A final event that repeats the whole answer, waiting for the PII model.
    Snapshot(Value),
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
    /// Tool calls seen so far, when the route limits them.
    calls: StreamCalls,
    /// Text up to here has passed the Tier 2 models.
    judged: usize,
    /// Entities the PII model found in the unsent part, in answer offsets.
    entities: Vec<Span>,
    seen_entities: HashSet<(String, usize)>,
}

/// How much new answer text the Tier 2 models wait for before they check a
/// streamed answer again, in bytes. Text is released only once checked.
const JUDGE_EVERY: usize = 256;

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
        calls: StreamCalls::default(),
        judged: 0,
        entities: Vec::new(),
        seen_entities: HashSet::new(),
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
                        let out = state.take_events(false).await;
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
                    let out = state.take_events(true).await;
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
    async fn take_events(&mut self, at_end: bool) -> Bytes {
        while let Some(raw) = next_event(&mut self.buf, at_end) {
            self.push(raw);
        }
        let due = at_end || self.text.len() >= self.judged + JUDGE_EVERY;
        if self.check.models_gate() && due && self.text.len() > self.judged {
            if self.check.safety.is_some() {
                match judge(&self.check, self.text.clone()).await {
                    Ok(Some((labels, action))) => {
                        for label in labels {
                            *self.findings.entry(label).or_insert(0) += 1;
                        }
                        self.action = self.action.max(Some(action));
                    }
                    Ok(None) => {}
                    Err(()) => self.unchecked("safety.unchecked"),
                }
            }
            if self.tag().await.is_err() {
                self.unchecked("pii.unchecked");
            }
            self.judged = self.text.len();
        }
        if self.tag_snapshots().await.is_err() {
            self.unchecked("pii.unchecked");
        }
        self.scan(at_end);
        let text_blocked = self.action == Some(Action::Block);
        if at_end && !self.calls.is_empty() {
            let action = self
                .check
                .check_tools(&self.calls.finish(), &mut self.findings);
            self.action = self.action.max(action);
        }
        if self.action == Some(Action::Block) && !self.check.shadow {
            // End the stream with an error event and stop reading from the
            // provider, which closes that connection. Held-back text goes too,
            // unless only a tool call was rejected: then the text before it
            // is fine and is sent first.
            let mut out = BytesMut::new();
            if !text_blocked {
                while let Some(event) = self.pending.pop_front().filter(|e| !e.held) {
                    self.write(event, &mut out);
                }
            }
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
            out.extend_from_slice(format!("event: error\ndata: {error}\n\n").as_bytes());
            return out.freeze();
        }
        let mut release_to = if at_end {
            self.text.len()
        } else {
            floor_char(
                &self.text,
                self.text.len().saturating_sub(self.check.rules.holdback),
            )
        };
        if self.check.models_gate() {
            // Only text the models have seen goes out.
            release_to = release_to.min(self.judged);
        }
        let mut out = BytesMut::new();
        while self
            .pending
            .front()
            .is_some_and(|e| e.text_end <= release_to && (at_end || !e.held))
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

    /// A Tier 2 model failed: on a fail-closed route, the answer is blocked.
    fn unchecked(&mut self, label: &str) {
        if self.check.fail_closed {
            *self.findings.entry(label.to_owned()).or_insert(0) += 1;
            self.action = Some(Action::Block);
        }
    }

    /// Runs the PII model on the unsent text plus some context before it.
    async fn tag(&mut self) -> Result<(), ()> {
        let Some((rule, model)) = self.check.pii.clone() else {
            return Ok(());
        };
        let from = floor_char(
            &self.text,
            self.released.saturating_sub(self.check.rules.holdback),
        );
        let window = self.text[from..].to_owned();
        let task = tokio::task::spawn_blocking(move || model.find(&[&window], &rule));
        let spans = match task.await {
            Ok(Ok(mut spans)) => spans.remove(0),
            Ok(Err(err)) => {
                tracing::warn!(route = %self.check.route, error = %format!("{err:#}"), "PII model failed on the answer");
                return Err(());
            }
            Err(err) => {
                tracing::warn!(route = %self.check.route, error = %err, "PII model panicked on the answer");
                return Err(());
            }
        };
        self.entities.clear();
        for span in spans {
            let span = Span {
                start: from + span.start,
                end: from + span.end,
                ..span
            };
            if span.end <= self.released {
                continue; // already sent: too late to act on
            }
            if self.seen_entities.insert((span.entity.clone(), span.start)) {
                *self.findings.entry(span.label()).or_insert(0) += 1;
            }
            self.action = self.action.max(Some(span.action));
            self.entities.push(span);
        }
        Ok(())
    }

    /// Runs the PII model on final events that repeat the whole answer.
    async fn tag_snapshots(&mut self) -> Result<(), ()> {
        let Some((rule, model)) = self.check.pii.clone() else {
            return Ok(());
        };
        for i in 0..self.pending.len() {
            let EventBody::Snapshot(json) = &mut self.pending[i].body else {
                continue;
            };
            let mut json = std::mem::take(json);
            // Shadow mode only reports.
            let keep = self.check.shadow.then(|| json.clone());
            let (rule, model) = (rule.clone(), model.clone());
            let task = tokio::task::spawn_blocking(move || {
                let tagged = model.tag_json(&rule, &mut json, &DELTA_KEYS);
                (json, tagged)
            });
            let (json, tagged) = match task.await {
                Ok((json, Ok(tagged))) => (json, tagged),
                Ok((json, Err(err))) => {
                    tracing::warn!(route = %self.check.route, error = %format!("{err:#}"), "PII model failed on the answer");
                    self.pending[i].body = EventBody::Snapshot(json);
                    return Err(());
                }
                Err(err) => {
                    tracing::warn!(route = %self.check.route, error = %err, "PII model panicked on the answer");
                    return Err(());
                }
            };
            for label in tagged.findings.into_keys() {
                // The same entity usually streamed as deltas before: count it once.
                self.findings.entry(label).or_insert(1);
            }
            self.action = self.action.max(tagged.action);
            let event = &mut self.pending[i];
            let json = keep.unwrap_or(json);
            event.body = EventBody::Raw(Bytes::from(format!("{}data: {json}\n\n", event.head)));
        }
        Ok(())
    }

    fn push(&mut self, raw: Bytes) {
        let held = !self.calls.is_empty();
        let Ok(block) = std::str::from_utf8(&raw) else {
            return self.pending.push_back(Event {
                head: String::new(),
                body: EventBody::Raw(raw),
                text_end: self.text.len(),
                held,
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
                held,
            });
        };
        // From the first tool call on, events wait for the end of the stream.
        let held = (self.check.tools.is_some() && self.calls.feed(&json)) || held;
        // Final events (OpenAI Responses `*.done`, `response.completed`) repeat
        // the whole answer: check them on their own instead of adding them
        // to the running text.
        let snapshot = json["type"]
            .as_str()
            .is_some_and(|t| t.ends_with(".done") || t.ends_with(".completed"));
        if snapshot {
            self.snapshot(&mut json);
            let (head, body) = if self.check.pii.is_some() {
                (head, EventBody::Snapshot(json))
            } else {
                let text = format!("{head}data: {json}\n\n");
                (String::new(), EventBody::Raw(Bytes::from(text)))
            };
            return self.pending.push_back(Event {
                head,
                body,
                text_end: self.text.len(),
                held,
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
            held,
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
        if !self.check.shadow && !self.entities.is_empty() {
            self.redactions.extend(
                self.entities
                    .iter()
                    .filter(|e| e.action == Action::Redact)
                    .map(|e| (e.start, e.end, e.marker())),
            );
            // Keep them sorted and without overlaps, as rewriting needs.
            self.redactions.sort_by_key(|r| r.0);
            let mut merged: Vec<(usize, usize, String)> = Vec::new();
            for r in self.redactions.drain(..) {
                match merged.last_mut() {
                    Some(last) if r.0 < last.1 => last.1 = last.1.max(r.1),
                    _ => merged.push(r),
                }
            }
            self.redactions = merged;
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
            EventBody::Snapshot(json) => {
                out.extend_from_slice(event.head.as_bytes());
                out.extend_from_slice(format!("data: {json}\n\n").as_bytes());
            }
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
