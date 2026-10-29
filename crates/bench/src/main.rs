//! Measures the latency Promptwall adds.
//!
//! Sends the same chat completion requests at a constant arrival rate first
//! directly to an upstream, then through the proxy, and reports added latency
//! as the difference of the two percentiles. Latency is measured from each
//! request's scheduled send time, so a slow system cannot hide its own delay
//! by sending fewer requests (coordinated omission).

use std::time::{Duration, Instant};

use anyhow::{bail, Context};
use bytes::Bytes;
use clap::Parser;
use http::{header, Method, Request, Uri};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

/// Promptwall latency benchmark.
#[derive(Parser)]
struct Args {
    /// Upstream base URL called directly (the mock upstream).
    #[arg(long, default_value = "http://127.0.0.1:9000")]
    direct: String,
    /// Promptwall base URL in front of the same upstream.
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    proxy: String,
    /// Requests per second (constant arrival rate).
    #[arg(long, default_value_t = 200.0)]
    rate: f64,
    /// Measured seconds per target.
    #[arg(long, default_value_t = 10.0)]
    duration: f64,
    /// Warm-up seconds per target, not measured.
    #[arg(long, default_value_t = 2.0)]
    warmup: f64,
    /// Approximate prompt size in tokens (about 4 characters each).
    #[arg(long, default_value_t = 2000)]
    prompt_tokens: usize,
    /// Request a streamed (SSE) response and also report time to first token.
    #[arg(long)]
    stream: bool,
    /// Exit with an error if added p95 latency exceeds this many milliseconds.
    #[arg(long)]
    max_p95_added_ms: Option<f64>,
    /// Print results as JSON.
    #[arg(long)]
    json: bool,
}

struct Sample {
    first_byte: Duration,
    total: Duration,
}

#[derive(Clone, Copy)]
struct Percentiles {
    p50: f64,
    p95: f64,
    p99: f64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    if args.rate <= 0.0 || args.duration <= 0.0 {
        bail!("--rate and --duration must be positive");
    }
    let body = Bytes::from(request_body(args.prompt_tokens, args.stream));

    let direct = run_target(&args, &args.direct, &body)
        .await
        .context("direct run failed")?;
    let proxied = run_target(&args, &args.proxy, &body)
        .await
        .context("proxied run failed")?;

    let total = (
        summarize(&direct, |s| s.total),
        summarize(&proxied, |s| s.total),
    );
    let first = (
        summarize(&direct, |s| s.first_byte),
        summarize(&proxied, |s| s.first_byte),
    );
    let added_total = diff(total.1, total.0);
    let added_first = diff(first.1, first.0);
    let first_label = if args.stream {
        "first token"
    } else {
        "first byte"
    };

    if args.json {
        let row =
            |p: Percentiles| serde_json::json!({"p50_ms": p.p50, "p95_ms": p.p95, "p99_ms": p.p99});
        let out = serde_json::json!({
            "rate_rps": args.rate,
            "duration_s": args.duration,
            "prompt_tokens": args.prompt_tokens,
            "stream": args.stream,
            "requests_per_target": direct.len(),
            "total": {"direct": row(total.0), "proxied": row(total.1), "added": row(added_total)},
            "first_byte": {"direct": row(first.0), "proxied": row(first.1), "added": row(added_first)},
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!(
            "{} requests per target at {} req/s, prompt ~{} tokens, stream={}",
            direct.len(),
            args.rate,
            args.prompt_tokens,
            args.stream
        );
        println!("{:<26}{:>10}{:>10}{:>10}", "", "p50 ms", "p95 ms", "p99 ms");
        for (label, p) in [
            ("direct, total", total.0),
            ("proxied, total", total.1),
            ("added, total", added_total),
            (&*format!("added, {first_label}"), added_first),
        ] {
            println!("{label:<26}{:>10.2}{:>10.2}{:>10.2}", p.p50, p.p95, p.p99);
        }
    }

    if let Some(max) = args.max_p95_added_ms {
        if added_total.p95 > max {
            bail!(
                "added p95 latency {:.2} ms exceeds the limit of {max} ms",
                added_total.p95
            );
        }
    }
    Ok(())
}

async fn run_target(args: &Args, base: &str, body: &Bytes) -> anyhow::Result<Vec<Sample>> {
    let uri: Uri = format!("{}/v1/chat/completions", base.trim_end_matches('/')).parse()?;
    let mut http = HttpConnector::new();
    http.set_nodelay(true);
    let client: Client<HttpConnector, Full<Bytes>> = Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(1024)
        .build(http);

    if args.warmup > 0.0 {
        run_open_loop(&client, &uri, body, args.rate, args.warmup).await?;
    }
    run_open_loop(&client, &uri, body, args.rate, args.duration).await
}

async fn run_open_loop(
    client: &Client<HttpConnector, Full<Bytes>>,
    uri: &Uri,
    body: &Bytes,
    rate: f64,
    seconds: f64,
) -> anyhow::Result<Vec<Sample>> {
    let count = (rate * seconds).round().max(1.0) as usize;
    let interval = Duration::from_secs_f64(1.0 / rate);
    let start = tokio::time::Instant::now();
    let mut tasks = Vec::with_capacity(count);
    for i in 0..count {
        let scheduled = start + interval.mul_f64(i as f64);
        tokio::time::sleep_until(scheduled).await;
        let (client, uri, body) = (client.clone(), uri.clone(), body.clone());
        tasks.push(tokio::spawn(async move {
            send(&client, uri, body, scheduled.into_std()).await
        }));
    }
    let mut samples = Vec::with_capacity(count);
    for task in tasks {
        samples.push(task.await??);
    }
    Ok(samples)
}

async fn send(
    client: &Client<HttpConnector, Full<Bytes>>,
    uri: Uri,
    body: Bytes,
    scheduled: Instant,
) -> anyhow::Result<Sample> {
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, "Bearer bench")
        .body(Full::new(body))?;
    let resp = client.request(req).await?;
    if !resp.status().is_success() {
        bail!("unexpected status {}", resp.status());
    }
    let mut body = resp.into_body();
    let mut first_byte = None;
    while let Some(frame) = body.frame().await {
        if frame?.is_data() && first_byte.is_none() {
            first_byte = Some(scheduled.elapsed());
        }
    }
    let total = scheduled.elapsed();
    Ok(Sample {
        first_byte: first_byte.unwrap_or(total),
        total,
    })
}

fn request_body(prompt_tokens: usize, stream: bool) -> String {
    // About 4 characters per token of plain English-like text.
    let words = [
        "the", "quick", "brown", "fox", "jumps", "over", "lazy", "dog",
    ];
    let mut prompt = String::with_capacity(prompt_tokens * 4);
    for i in 0..prompt_tokens {
        prompt.push_str(words[i % words.len()]);
        prompt.push(' ');
    }
    serde_json::json!({
        "model": "mock",
        "stream": stream,
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": prompt.trim_end()},
        ],
    })
    .to_string()
}

fn summarize(samples: &[Sample], pick: impl Fn(&Sample) -> Duration) -> Percentiles {
    let mut ms: Vec<f64> = samples
        .iter()
        .map(|s| pick(s).as_secs_f64() * 1000.0)
        .collect();
    ms.sort_by(f64::total_cmp);
    Percentiles {
        p50: percentile(&ms, 0.50),
        p95: percentile(&ms, 0.95),
        p99: percentile(&ms, 0.99),
    }
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    let rank = (p * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

fn diff(a: Percentiles, b: Percentiles) -> Percentiles {
    Percentiles {
        p50: a.p50 - b.p50,
        p95: a.p95 - b.p95,
        p99: a.p99 - b.p99,
    }
}

#[cfg(test)]
mod tests {
    use super::percentile;

    #[test]
    fn percentile_uses_nearest_rank() {
        let data: Vec<f64> = (1..=100).map(f64::from).collect();
        assert_eq!(percentile(&data, 0.50), 50.0);
        assert_eq!(percentile(&data, 0.95), 95.0);
        assert_eq!(percentile(&data, 0.99), 99.0);
        assert_eq!(percentile(&[7.0], 0.99), 7.0);
    }
}
