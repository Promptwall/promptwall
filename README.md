# Promptwall

**An open source AI firewall.** Promptwall sits between your application and any LLM and blocks prompt injection, jailbreaks and data leaks in both directions, while adding only single-digit milliseconds of latency.

> **Status: early Phase 1.** Promptwall routes requests by a YAML policy and can block secrets and redact personal data in prompts (pattern-based, Tier 1). It blocks prompt injection, including encoded and disguised attacks, many-shot jailbreaks and instructions planted in documents (patterns plus an optional ONNX classifier), checks the provider's answers, streamed or not, for leaked secrets, personal data, exfiltration links and system-prompt leaks, and limits which tools the model may call and with which arguments.

## Goals

- **Fast:** under 10 ms added at p50 and under 20 ms at p95 for prompts up to 2,000 tokens.
- **Drop-in:** speaks the OpenAI and Anthropic APIs, so adoption is a base URL change. An npm package covers Vercel, Next.js and Supabase Edge Functions.
- **Two-way protection:** inspects prompts, retrieved documents, tool calls and streamed responses.
- **Policy as code:** versioned YAML policies that can be tested in CI.
- **Runs anywhere:** one binary, a Docker image, a Helm chart, or embedded in your app.

## Quick start

Requires a recent stable Rust toolchain.

```sh
cargo run --release -p promptwall -- --listen 127.0.0.1:8080 --upstream https://api.openai.com
```

Then point your OpenAI client at `http://127.0.0.1:8080/v1`. Requests and streamed responses pass through unchanged; `GET /healthz` answers locally.

To inspect requests, start it with a policy instead:

```sh
cargo run --release -p promptwall -- --policy examples/policy.yaml
```

With [`examples/policy.yaml`](examples/policy.yaml), a prompt containing an API key or private key is rejected with `403`, prompt-injection phrasing ("ignore all previous instructions", also as base64, leetspeak or look-alike letters; hidden Unicode, forged chat tokens) is blocked, and emails, IBANs, card numbers, national IDs and company-specific patterns are replaced with markers such as `[REDACTED:EMAIL]` before the request reaches the provider. The response header `x-promptwall-action` says what happened. Logs record which kinds were found, never the values.

To measure the latency the proxy adds:

```sh
scripts/bench.sh                 # non-streamed, 2,000-token prompts, 200 req/s
scripts/bench.sh --stream        # streamed responses
BENCH_POLICY=scripts/bench-policy.yaml scripts/bench.sh   # with detectors on
```

## Repository layout

| Path | What it is |
| --- | --- |
| `crates/proxy` | The `promptwall` data plane (library and binary): routing, policy, inspection |
| `crates/detect` | Tier 1 detectors for PII, secrets and prompt injection; no I/O, so it can also build for WebAssembly |
| `crates/classify` | Tier 2 classifiers on CPU with ONNX Runtime (prompt injection) |
| `crates/mock-upstream` | Mock OpenAI-compatible upstream used by tests and benchmarks |
| `crates/bench` | `pw-bench`, the latency benchmark |

## Documentation

| Document | What it covers |
| --- | --- |
| [Architecture](docs/architecture.md) | Components, request path, latency budget, deployment modes |
| [Threat model](docs/specs/threat-model.md) | What the MVP protects against and what it does not |
| [Policy format](docs/specs/policy-format.md) | Draft of the YAML policy language |
| [Benchmark](docs/specs/benchmark.md) | How latency and detection accuracy are measured |
| [Models](docs/models.md) | Tier 2 classifiers: model format, latency and accuracy of open models |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: see [SECURITY.md](SECURITY.md).

## Licence

[Apache License 2.0](LICENSE).
