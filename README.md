# Promptwall

**An open source AI firewall.** Promptwall sits between your application and any LLM and blocks prompt injection, jailbreaks and data leaks in both directions, while adding only single-digit milliseconds of latency.

> **Status: early Phase 1.** Promptwall currently runs as a transparent pass-through proxy with a latency benchmark. No detectors are active yet, so it does not block anything.

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

To measure the latency the proxy adds:

```sh
scripts/bench.sh                 # non-streamed, 2,000-token prompts, 200 req/s
scripts/bench.sh --stream        # streamed responses
```

## Repository layout

| Path | What it is |
| --- | --- |
| `crates/proxy` | The `promptwall` data plane (library and binary) |
| `crates/mock-upstream` | Mock OpenAI-compatible upstream used by tests and benchmarks |
| `crates/bench` | `pw-bench`, the latency benchmark |

## Documentation

| Document | What it covers |
| --- | --- |
| [Architecture](docs/architecture.md) | Components, request path, latency budget, deployment modes |
| [Threat model](docs/specs/threat-model.md) | What the MVP protects against and what it does not |
| [Policy format](docs/specs/policy-format.md) | Draft of the YAML policy language |
| [Benchmark](docs/specs/benchmark.md) | How latency and detection accuracy are measured |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: see [SECURITY.md](SECURITY.md).

## Licence

[Apache License 2.0](LICENSE).
