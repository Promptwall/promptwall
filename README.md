# Promptwall

**An open source AI firewall.** Promptwall sits between your application and any LLM and blocks prompt injection, jailbreaks and data leaks in both directions, while adding only single-digit milliseconds of latency.

> **Status: Phase 0 (design).** There is no runnable code yet. This repository currently holds the architecture overview and the specs the first implementation will be built against.

## Goals

- **Fast:** under 10 ms added at p50 and under 20 ms at p95 for prompts up to 2,000 tokens.
- **Drop-in:** speaks the OpenAI and Anthropic APIs, so adoption is a base URL change. An npm package covers Vercel, Next.js and Supabase Edge Functions.
- **Two-way protection:** inspects prompts, retrieved documents, tool calls and streamed responses.
- **Policy as code:** versioned YAML policies that can be tested in CI.
- **Runs anywhere:** one binary, a Docker image, a Helm chart, or embedded in your app.

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
