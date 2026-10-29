# Benchmark

**Status:** draft for review. The benchmark is the gate for every change: no pull request merges if it breaks the latency budget or lowers detection quality.

It has two parts: **latency** (what the firewall costs) and **accuracy** (what it catches).

## Latency

### Method

- A mock upstream returns a fixed response after a fixed delay (default 200 ms), both non-streamed and streamed (SSE, 20 ms per chunk).
- **Added latency** = time through Promptwall minus time directly to the mock, measured by the same load generator on the same host.
- For streams, measure added time to first token and added time to last token separately.
- Load generator: an open-loop tool (constant arrival rate) to avoid coordinated omission, for example `oha` or `k6` in constant-arrival mode.

### Matrix

| Dimension | Values |
| --- | --- |
| Prompt size | 200, 2,000 and 8,000 tokens |
| Concurrency | 1, 64, 512 requests in flight |
| Detectors | none (pass-through), Tier 1 only, Tier 1 + Tier 2 |
| Mode | non-streamed, streamed |

### Running it

`scripts/bench.sh` builds release binaries, starts the mock upstream (50 ms delay) and the proxy, then runs `pw-bench`. Pass `--stream`, `--rate`, `--duration`, `--prompt-tokens` or `--max-p95-added-ms` through to `pw-bench`. Added latency is reported as the proxied percentile minus the direct percentile.

First measurement of the pass-through proxy (29 Oct 2026, 4 vCPU cloud VM, mock and proxy on the same host, non-streamed):

| Load | Added p50 | Added p95 |
| --- | --- | --- |
| 200 req/s, 2,000-token prompts | 0.54 ms | 0.63 ms |
| 1,000 req/s, 8,000-token prompts | 0.26 ms | 0.42 ms |

With PII and secret detection on (`BENCH_POLICY=scripts/bench-policy.yaml`), the added latency stays inside the measurement noise of about ±0.5 ms. The detectors on their own (`cargo run --release -p promptwall-detect --example scan_speed`) take about 25 µs for a 2,000-token prompt and 100 µs for 8,000 tokens; with findings to validate, about twice that.

Streamed runs add about 0.2 ms at p50; their tail percentiles are dominated by timer jitter in the mock's 20 ms chunk gaps, so the gate uses non-streamed runs for now.

### Reference hardware

Results are reported for a 2 vCPU, 4 GB x86 VM and a 2 vCPU ARM VM. CI runs a reduced matrix on a fixed runner type.

### Targets and CI gate

| Configuration | p50 | p95 | p99 |
| --- | --- | --- | --- |
| Pass-through | ≤ 1 ms | ≤ 2 ms | ≤ 5 ms |
| Tier 1 + Tier 2, 2,000 tokens, concurrency 64 | ≤ 10 ms | ≤ 20 ms | ≤ 40 ms |

CI fails a pull request if p95 regresses by more than 10% against `main`, or exceeds a target.

Current state: CI fails if the proxy adds more than 5 ms at p95 on a shared GitHub runner, both as a pass-through and with PII and secret detection on. The regression-against-`main` comparison and the tighter targets come with dedicated benchmark runners.

## Accuracy

### Datasets

- **Attack set:** prompt injection and jailbreak prompts from public datasets, plus indirect-injection documents written for this project. Candidates to evaluate (check licences before use): Hugging Face datasets such as `deepset/prompt-injections`, `jackhhao/jailbreak-classification` and Lakera's Gandalf sets, and the OWASP LLM examples.
- **Benign set:** normal user prompts of similar length and style (support questions, coding help, RAG queries), including hard negatives that mention "instructions" or "system prompt" innocently.
- **DLP set:** synthetic PII and secrets in realistic text, EU formats first, with labeled spans.
- Datasets are versioned. A held-out test split is never used for training or tuning.

### Metrics

| Metric | Why |
| --- | --- |
| Detection rate at 1% false-positive rate | The number that matters in production |
| False-positive rate on the benign set | Users leave when real prompts are blocked |
| Precision, recall, F1 per category | Shows where each detector is weak |
| Span-level precision and recall for DLP | Redaction must hit the right characters |

### Publishing

Results are published with each release, together with the scripts and dataset versions, so anyone can reproduce them and compare other tools on the same data.
