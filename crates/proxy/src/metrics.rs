//! Prometheus metrics, served on their own address (`--metrics-listen`).
//!
//! Counters and histograms are kept in one process-wide registry. Labels are
//! route names, actions and finding labels such as `pii.email`, never values
//! from requests or answers.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::fmt::Write as _;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use bytes::Bytes;
use http::{header, HeaderValue, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::net::TcpListener;

/// Upper bounds of the latency histogram buckets, in seconds.
const BUCKETS: [f64; 14] = [
    0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

type Labels = Vec<(&'static str, String)>;

#[derive(Default)]
struct Registry {
    counters: BTreeMap<&'static str, BTreeMap<Labels, u64>>,
    histograms: BTreeMap<&'static str, BTreeMap<Labels, Histogram>>,
}

#[derive(Default)]
struct Histogram {
    buckets: [u64; BUCKETS.len()],
    count: u64,
    sum: f64,
}

/// Help text of each metric.
const HELP: [(&str, &str); 9] = [
    (
        "promptwall_requests_total",
        "Requests by route and what Promptwall did: allow, flag, redact, block, rate_limited or no_route.",
    ),
    (
        "promptwall_checks_total",
        "Calls of the check API by route and verdict: allow, flag, redact or block.",
    ),
    (
        "promptwall_findings_total",
        "Findings by route, label (such as pii.email) and direction (request or response).",
    ),
    (
        "promptwall_request_duration_seconds",
        "Time until the response headers were sent, including the provider.",
    ),
    (
        "promptwall_check_duration_seconds",
        "Time Promptwall spent checking a request, by stage: rules (Tier 1) or models (Tier 2).",
    ),
    (
        "promptwall_upstream_errors_total",
        "Requests whose provider could not be reached.",
    ),
    (
        "promptwall_uninspected_total",
        "Requests or responses that could not be inspected, by route and direction.",
    ),
    (
        "promptwall_attachments_total",
        "Attachments in requests by route, format (text, pdf, image, audio, file or remote) and whether their text was checked.",
    ),
    (
        "promptwall_policy_reloads_total",
        "Policy reloads by result: ok or error.",
    ),
];

fn registry() -> &'static Mutex<Registry> {
    static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
    REGISTRY.get_or_init(Default::default)
}

fn labels(pairs: &[(&'static str, &str)]) -> Labels {
    pairs.iter().map(|(k, v)| (*k, (*v).to_owned())).collect()
}

/// Adds `n` to a counter.
pub fn count(name: &'static str, pairs: &[(&'static str, &str)], n: u64) {
    let mut r = registry().lock().unwrap_or_else(|p| p.into_inner());
    *r.counters
        .entry(name)
        .or_default()
        .entry(labels(pairs))
        .or_default() += n;
}

/// Records one duration in a histogram.
pub fn observe(name: &'static str, pairs: &[(&'static str, &str)], took: Duration) {
    let secs = took.as_secs_f64();
    let mut r = registry().lock().unwrap_or_else(|p| p.into_inner());
    let h = r
        .histograms
        .entry(name)
        .or_default()
        .entry(labels(pairs))
        .or_default();
    for (bucket, bound) in h.buckets.iter_mut().zip(BUCKETS) {
        if secs <= bound {
            *bucket += 1;
        }
    }
    h.count += 1;
    h.sum += secs;
}

/// Counts the findings of one request or response.
pub fn findings<'a>(
    route: &str,
    direction: &str,
    found: impl IntoIterator<Item = (&'a String, &'a usize)>,
) {
    for (label, n) in found {
        count(
            "promptwall_findings_total",
            &[
                ("route", route),
                ("finding", label),
                ("direction", direction),
            ],
            *n as u64,
        );
    }
}

/// All metrics in the Prometheus text format.
pub fn render() -> String {
    let r = registry().lock().unwrap_or_else(|p| p.into_inner());
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# HELP promptwall_build_info Promptwall version.\n# TYPE promptwall_build_info gauge\npromptwall_build_info{{version=\"{}\"}} 1",
        env!("CARGO_PKG_VERSION")
    );
    for (name, help) in HELP {
        if let Some(series) = r.counters.get(name) {
            let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} counter");
            for (l, v) in series {
                let _ = writeln!(out, "{name}{} {v}", format_labels(l, None));
            }
        }
        if let Some(series) = r.histograms.get(name) {
            let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} histogram");
            for (l, h) in series {
                for (bound, n) in BUCKETS.iter().zip(h.buckets) {
                    let le = bound.to_string();
                    let _ = writeln!(out, "{name}_bucket{} {n}", format_labels(l, Some(&le)));
                }
                let _ = writeln!(
                    out,
                    "{name}_bucket{} {}",
                    format_labels(l, Some("+Inf")),
                    h.count
                );
                let _ = writeln!(out, "{name}_sum{} {}", format_labels(l, None), h.sum);
                let _ = writeln!(out, "{name}_count{} {}", format_labels(l, None), h.count);
            }
        }
    }
    out
}

fn format_labels(labels: &Labels, le: Option<&str>) -> String {
    let mut parts: Vec<String> = labels
        .iter()
        .map(|(k, v)| format!("{k}=\"{}\"", escape(v)))
        .collect();
    if let Some(le) = le {
        parts.push(format!("le=\"{le}\""));
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!("{{{}}}", parts.join(","))
    }
}

fn escape(v: &str) -> String {
    v.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Serves `GET /metrics` on `listener` forever.
pub async fn serve(listener: TcpListener) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        tokio::spawn(async move {
            let service = service_fn(|req: Request<Incoming>| async move {
                let resp = if req.uri().path() == "/metrics" {
                    let mut resp = Response::new(Full::new(Bytes::from(render())));
                    resp.headers_mut().insert(
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("text/plain; version=0.0.4"),
                    );
                    resp
                } else {
                    let mut resp = Response::new(Full::new(Bytes::from_static(b"not found\n")));
                    *resp.status_mut() = StatusCode::NOT_FOUND;
                    resp
                };
                Ok::<_, Infallible>(resp)
            });
            let _ = auto::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_counters_and_histograms() {
        count(
            "promptwall_requests_total",
            &[("route", "unit-test"), ("action", "block")],
            2,
        );
        observe(
            "promptwall_check_duration_seconds",
            &[("route", "unit-test"), ("stage", "rules")],
            Duration::from_micros(300),
        );
        let text = render();
        assert!(text.contains("# TYPE promptwall_requests_total counter"));
        assert!(text.contains("promptwall_requests_total{route=\"unit-test\",action=\"block\"} 2"));
        assert!(text.contains(
            "promptwall_check_duration_seconds_bucket{route=\"unit-test\",stage=\"rules\",le=\"0.0005\"} 1"
        ));
        assert!(text.contains(
            "promptwall_check_duration_seconds_count{route=\"unit-test\",stage=\"rules\"} 1"
        ));
        assert_eq!(escape("a\"b\\c"), "a\\\"b\\\\c");
    }
}
