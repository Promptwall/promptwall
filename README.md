# Promptwall

**An open source AI firewall.** Promptwall sits between your application and any LLM and blocks prompt injection, jailbreaks and data leaks in both directions, while adding only single-digit milliseconds of latency.

> **Status: v0.1, the first public release.** The policy format (version 1) is stable; the command line and the check API may still change before 1.0. See the [changelog](CHANGELOG.md) and the [benchmark](docs/benchmark.md) for what it catches today.

**What it does**

- **Data leaks:** blocks secrets (API keys of 13 providers, private keys, passwords) and redacts personal data (emails, IBANs, card numbers, national IDs; names and addresses with an optional model) in prompts, before they reach the provider.
- **Prompt injection and jailbreaks:** blocks known phrasings, also encoded or disguised, many-shot attacks and instructions planted in documents, plus an optional classifier for freely worded attacks.
- **Answers:** checks what the model sends back, streamed or not, for leaked secrets and personal data, links that smuggle data out and system-prompt leaks.
- **Tools, content and limits:** which tools the model may call and how, harmful content and off-limits topics (optional models), and rate and token limits per route, key or user.

## Goals

- **Fast:** under 10 ms added at p50 and under 20 ms at p95 for prompts up to 2,000 tokens.
- **Drop-in:** speaks the OpenAI and Anthropic APIs, so adoption is a base URL change. An npm package covers Vercel, Next.js and Supabase Edge Functions.
- **Two-way protection:** inspects prompts, retrieved documents, tool calls and streamed responses.
- **Policy as code:** versioned YAML policies that can be tested in CI.
- **Runs anywhere:** one binary, a Docker image, a Helm chart, or embedded in your app.

## Quick start

Download `promptwall` for Windows, macOS or Linux from the [releases page](https://github.com/Promptwall/promptwall/releases), or use Docker or Helm; see [install](docs/install.md). From source, with a recent stable Rust toolchain:

```sh
cargo run --release -p promptwall -- --listen 127.0.0.1:8080 --upstream https://api.openai.com
```

Then point your OpenAI client at `http://127.0.0.1:8080/v1`. Requests and streamed responses pass through unchanged; `GET /healthz` answers locally.

To inspect requests, start it with a policy. `promptwall init` asks a few questions (provider, what to block or redact, limits) and writes one for you:

```sh
cargo run --release -p promptwall -- init my-policy.yaml
```

Or start from the example policy:

```sh
cargo run --release -p promptwall -- --policy examples/policy.yaml
```

With [`examples/policy.yaml`](examples/policy.yaml), a prompt containing an API key or private key is rejected with `403`, prompt-injection phrasing ("ignore all previous instructions", also as base64, leetspeak or look-alike letters; hidden Unicode, forged chat tokens) is blocked, and emails, IBANs, card numbers, national IDs and company-specific patterns are replaced with markers such as `[REDACTED:EMAIL]` before the request reaches the provider. The response header `x-promptwall-action` says what happened. Logs record which kinds were found, never the values.

Changes to the policy file apply within two seconds, without a restart (`--reload-interval`, 0 turns it off). A file with an error is logged and ignored; the previous policy stays in force. Rate-limit counters carry over for routes whose limits did not change.

To check a policy without running the proxy:

```sh
cargo run --release -p promptwall -- validate --policy examples/policy.yaml
cargo run --release -p promptwall -- test --policy examples/policy.yaml    # the tests in the file
cargo run --release -p promptwall -- scan --policy examples/policy.yaml --route openai "mail jane@corp.io"
```

To see what it does on a dashboard, start Promptwall with Prometheus and Grafana (needs Docker; sends sample traffic to a mock provider):

```sh
cd deploy/compose && docker compose --profile demo up --build    # then open http://localhost:3000
```

See [monitoring](docs/monitoring.md) for the metrics.

Without a proxy, in a JavaScript app (Node, Vercel, Supabase or Cloudflare functions, the browser), the [npm package](packages/sdk/README.md) runs the same policy in-process as WebAssembly:

```js
import { Promptwall } from "@promptwall/sdk";
import { wrapOpenAI } from "@promptwall/sdk/openai";

const pw = await Promptwall.load({ policyFile: "promptwall.yaml" });
const openai = wrapOpenAI(new OpenAI(), pw);   // prompts and answers are now checked
```

To measure the latency the proxy adds:

```sh
scripts/bench.sh                 # non-streamed, 2,000-token prompts, 200 req/s
scripts/bench.sh --stream        # streamed responses
BENCH_POLICY=scripts/bench-policy.yaml scripts/bench.sh   # with detectors on
```

## Benchmark

On public datasets, with scripts in [`benchmark`](benchmark) that anyone can rerun ([full results](docs/benchmark.md)):

| | Patterns only | Patterns + classifier |
| --- | --- | --- |
| Prompt injection caught (deepset / jackhhao / Lakera gandalf) | 3% / 21% / 50% | 68% / 90% / 96% |
| Harmless prompts blocked (deepset / jackhhao) | 0% / 0% | 0% / 1.9% |
| Personal data and secrets found (690 values, 23 kinds) | 98.1% | |
| Latency added, p50 | < 1 ms | 6 ms at 130 tokens, 180 ms at 500 (beyond a 50 ms provider) |

## Repository layout

| Path | What it is |
| --- | --- |
| `crates/proxy` | The `promptwall` data plane (library and binary): HTTP, routing, streaming, models, metrics |
| `crates/engine` | The policy format and the checks it configures, with no async runtime, so the proxy and the npm package share it |
| `crates/detect` | Tier 1 detectors for PII, secrets and prompt injection; no I/O, so it can also build for WebAssembly |
| `crates/wasm` | The engine as a WebAssembly module, for the npm package |
| `packages/sdk` | `@promptwall/sdk`: the same policy in Node, edge runtimes and browsers, with OpenAI and Vercel AI SDK wrappers |
| `crates/classify` | Tier 2 classifiers on CPU with ONNX Runtime (prompt injection) |
| `crates/mock-upstream` | Mock OpenAI-compatible upstream used by tests and benchmarks |
| `crates/bench` | `pw-bench`, the latency benchmark (`scripts/bench.sh`; load test: `scripts/soak.sh`) |
| `benchmark` | The public accuracy and latency benchmark ([results](docs/benchmark.md)) |
| `tests/attack-corpus.yaml` | Attacks and evasions the checks must keep catching, run in CI |
| `fuzz` | libFuzzer targets (nightly Rust and `cargo fuzz`), run weekly in CI |

## Documentation

| Document | What it covers |
| --- | --- |
| [Install](docs/install.md) | Downloads, Docker, Helm, building from source (with or without models) |
| [npm package](packages/sdk/README.md) | `@promptwall/sdk`: checks in your app, without a proxy; the check API for model checks |
| [Architecture](docs/architecture.md) | Components, request path, latency budget, deployment modes |
| [Threat model](docs/specs/threat-model.md) | What the MVP protects against and what it does not |
| [Policy format](docs/specs/policy-format.md) | The YAML policy language (version 1, stable) and its [JSON Schema](docs/specs/policy-v1.schema.json) |
| [Benchmark results](docs/benchmark.md) | What it catches, what it flags by mistake and what it costs, on public datasets |
| [Benchmark spec](docs/specs/benchmark.md) | How latency and detection accuracy are measured |
| [Models](docs/models.md) | Tier 2 classifiers: model format, latency and accuracy of open models |
| [Monitoring](docs/monitoring.md) | Prometheus metrics, the Grafana dashboard and the decision log |
| [Signed policies](docs/policy-signing.md) | Accepting only policies signed by your management server or CI |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: see [SECURITY.md](SECURITY.md).

## Licence

[Apache License 2.0](LICENSE).
