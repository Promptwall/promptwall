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

### Reference hardware

Results are reported for a 2 vCPU, 4 GB x86 VM and a 2 vCPU ARM VM. CI runs a reduced matrix on a fixed runner type.

### Targets and CI gate

| Configuration | p50 | p95 | p99 |
| --- | --- | --- | --- |
| Pass-through | ≤ 1 ms | ≤ 2 ms | ≤ 5 ms |
| Tier 1 + Tier 2, 2,000 tokens, concurrency 64 | ≤ 10 ms | ≤ 20 ms | ≤ 40 ms |

CI fails a pull request if p95 regresses by more than 10% against `main`, or exceeds a target.

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
