//! The decision log: one JSON line per request saying what Promptwall did,
//! for SIEMs (Splunk, Elasticsearch, Loki) and the enterprise dashboard.
//!
//! An event holds the route, the action, finding labels with counts and
//! timings, never prompt or answer text, API keys or other header values.
//! Events are written by a background thread, so a slow disk never delays a
//! request; when the queue is full, events are dropped and counted in
//! `promptwall_decision_log_dropped_total`.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use serde::Serialize;

use crate::{metrics, Action};

/// Events waiting to be written before new ones are dropped.
const QUEUE: usize = 10_000;

static SINK: OnceLock<SyncSender<String>> = OnceLock::new();

/// Writes the decision log to `target`: a file (appended to) or `-` for
/// standard output. Call once, before serving.
pub fn init(target: &Path) -> anyhow::Result<()> {
    let out: Box<dyn Write + Send> = if target == Path::new("-") {
        Box::new(std::io::stdout())
    } else {
        Box::new(
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(target)
                .with_context(|| format!("cannot open decision log {}", target.display()))?,
        )
    };
    let (tx, rx) = sync_channel(QUEUE);
    anyhow::ensure!(SINK.set(tx).is_ok(), "decision log already set up");
    std::thread::Builder::new()
        .name("decision-log".into())
        .spawn(move || write_all(rx, out))?;
    Ok(())
}

/// Whether the decision log is on.
pub fn enabled() -> bool {
    SINK.get().is_some()
}

fn write_all(rx: Receiver<String>, out: Box<dyn Write + Send>) {
    let mut out = std::io::BufWriter::new(out);
    while let Ok(line) = rx.recv() {
        let mut line = Some(line);
        // Write what is queued, then flush once.
        while let Some(l) = line {
            if let Err(err) = out.write_all(l.as_bytes()) {
                tracing::error!(error = %err, "cannot write the decision log");
            }
            line = rx.try_recv().ok();
        }
        let _ = out.flush();
    }
}

/// What Promptwall did with one request, filled in while it is handled.
#[derive(Debug, Default, Serialize)]
pub struct Event {
    /// When the request arrived, RFC 3339 in UTC.
    pub ts: String,
    /// Also sent to the client as `x-promptwall-request-id`.
    pub id: String,
    /// Empty when no route matched.
    pub route: String,
    /// `allow`, `flag`, `redact`, `block`, `rate_limited`, `no_route` or `error`.
    pub action: &'static str,
    pub shadow: bool,
    pub status: u16,
    /// Hash of the policy in force, such as `sha256:3f2a…`.
    pub policy: String,
    pub request: Direction,
    pub response: Direction,
    /// Milliseconds until the response headers were sent.
    pub latency_ms: f64,
    /// Milliseconds until the whole response was sent.
    pub duration_ms: f64,
    /// Milliseconds Promptwall spent checking the request: `rules` and `models`.
    pub check_ms: BTreeMap<&'static str, f64>,
}

/// Findings in a request or response.
#[derive(Debug, Default, Serialize)]
pub struct Direction {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<&'static str>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub findings: BTreeMap<String, usize>,
    /// Could not be inspected (compressed, too large, model failure).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub uninspected: bool,
}

impl Direction {
    pub fn record(&mut self, action: Action, findings: &BTreeMap<String, usize>) {
        let now = self.action.map_or(0, rank);
        if rank(action.as_str()) > now {
            self.action = Some(action.as_str());
        }
        for (label, n) in findings {
            let count = self.findings.entry(label.clone()).or_default();
            *count = (*count).max(*n);
        }
    }
}

fn rank(action: &str) -> u8 {
    match action {
        "flag" => 1,
        "redact" => 2,
        "block" => 3,
        _ => 0,
    }
}

/// An event shared by the parts of the proxy that handle one request. It is
/// written when the last of them lets go of it.
#[derive(Clone, Debug)]
pub struct Record(Arc<Mutex<Pending>>);

#[derive(Debug)]
struct Pending {
    event: Event,
    started: Instant,
}

impl Record {
    pub fn new(policy: &str) -> Self {
        Record(Arc::new(Mutex::new(Pending {
            event: Event {
                ts: rfc3339(SystemTime::now()),
                id: request_id(),
                policy: policy.to_owned(),
                ..Event::default()
            },
            started: Instant::now(),
        })))
    }

    pub fn update(&self, f: impl FnOnce(&mut Event)) {
        f(&mut self.0.lock().unwrap_or_else(|p| p.into_inner()).event);
    }

    pub fn id(&self) -> String {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .event
            .id
            .clone()
    }

    /// Notes that the response headers are being sent now.
    pub fn headers_sent(&self) {
        let mut p = self.0.lock().unwrap_or_else(|p| p.into_inner());
        p.event.latency_ms = ms(p.started.elapsed());
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        let Some(sink) = SINK.get() else { return };
        self.event.duration_ms = ms(self.started.elapsed());
        let Ok(mut line) = serde_json::to_string(&self.event) else {
            return;
        };
        line.push('\n');
        if let Err(TrySendError::Full(_)) = sink.try_send(line) {
            metrics::count("promptwall_decision_log_dropped_total", &[], 1);
        }
    }
}

tokio::task_local! {
    static CURRENT: Record;
}

/// Runs `f` with `record` as the request's record, for [`note`] and [`current`].
pub async fn scope<F: std::future::Future>(record: Record, f: F) -> F::Output {
    CURRENT.scope(record, f).await
}

/// Changes the record of the request being handled, if there is one.
pub fn note(f: impl FnOnce(&mut Event)) {
    let _ = CURRENT.try_with(|r| r.update(f));
}

/// The record of the request being handled, for work that outlives the
/// handler, such as checking a streamed answer.
pub fn current() -> Option<Record> {
    CURRENT.try_with(Record::clone).ok()
}

/// Adds to a stage of the request's check time.
pub fn check_time(stage: &'static str, took: Duration) {
    note(|e| *e.check_ms.entry(stage).or_default() += ms(took));
}

fn ms(d: Duration) -> f64 {
    (d.as_secs_f64() * 1_000_000.0).round() / 1000.0
}

/// 16 random hex digits.
fn request_id() -> String {
    let mut bytes = [0u8; 8];
    if ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes).is_err() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64);
        bytes = nanos.to_be_bytes();
    }
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `2026-10-29T21:40:00.123Z`.
pub fn rfc3339(t: SystemTime) -> String {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs();
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        d.subsec_millis()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_utc_timestamps() {
        let t = UNIX_EPOCH + Duration::from_millis(1_793_309_400_123);
        assert_eq!(rfc3339(t), "2026-10-29T21:30:00.123Z");
        assert_eq!(rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00.000Z");
        let leap = UNIX_EPOCH + Duration::from_secs(951_782_400); // 2000-02-29
        assert_eq!(rfc3339(leap), "2000-02-29T00:00:00.000Z");
    }

    #[test]
    fn keeps_the_strongest_action_and_largest_counts() {
        let mut d = Direction::default();
        d.record(Action::Redact, &BTreeMap::from([("pii.email".into(), 2)]));
        d.record(
            Action::Flag,
            &BTreeMap::from([("pii.email".into(), 2), ("pii.iban".into(), 1)]),
        );
        assert_eq!(d.action, Some("redact"));
        assert_eq!(d.findings.len(), 2);
        assert_eq!(d.findings["pii.email"], 2);
    }
}
