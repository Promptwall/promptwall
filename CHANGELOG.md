# Changelog

All notable changes to Promptwall. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/): until 1.0, a minor version may change the command line or the check API, but never policy format version 1.

## [Unreleased]

### Proxy

- `block_message` on a route or under `defaults`: your own text in the error a blocked request or answer gets; the findings are still listed.
- Fixed: redacting or flagging a whole (not streamed) answer that the provider sent chunked made the response unreadable for the client.
- Fixed: per-key limits (`key: api_key`) did not read Azure OpenAI's `api-key` header, so all Azure keys shared one count.
- The error event that ends a blocked stream now has `"type": "error"`, as Anthropic's SDKs expect.
- Tests with recorded Anthropic Messages and Azure OpenAI requests and answers, streamed and whole.

### Checks

- **Attachments:** text files and PDFs attached to a request (OpenAI, Anthropic, Gemini) are read and checked like any prompt text, so personal data, secrets and injections in them are redacted or blocked. A redacted text file stays a file; a redacted PDF is sent as its text. The new `attachments` detector flags, blocks or removes what cannot be read: images, audio, scanned or binary files, and links or file IDs. New metric `promptwall_attachments_total`.

## [0.1.0] - unreleased

The first public release.

### Proxy

- An HTTP proxy for the OpenAI and Anthropic APIs (and any provider with the same request shapes), streamed or not, adding under a millisecond with the pattern checks on ([benchmark](docs/benchmark.md)).
- Routing by a YAML policy, [format version 1](docs/specs/policy-format.md), with a [JSON Schema](docs/specs/policy-v1.schema.json). Each check can block, redact, flag or only log (`shadow`); `fail_mode` decides what happens when a check cannot run.
- The policy file is reloaded without a restart. Signed policies (`--policy-public-key`) accept only files signed by your CI or management server.
- Limits on concurrent connections, slow clients and HTTP/2 streams.

### Checks

- **Personal data:** emails, phone numbers, IBANs, BICs, card numbers, IP addresses, VAT IDs, and national ID and tax numbers of eight countries, with check digits where the format has them. An optional ONNX model finds names, addresses and other free-form personal data.
- **Secrets:** API keys of 13 providers, private keys, JWTs, passwords and credentials in URLs.
- **Prompt injection and jailbreaks:** patterns for the known phrasings, also when encoded (base64, hex, leetspeak, look-alike letters, hidden Unicode), many-shot and planted in documents or tool results, plus an optional ONNX classifier that runs while the request is with the provider.
- **Answers:** leaked secrets and personal data, links that smuggle data out, and system-prompt leaks, checked as the answer streams.
- **Tools:** which tools the model may call, and with which arguments.
- **Content:** harmful content and allowed or denied topics (optional ONNX models).
- **Custom patterns and keyword lists**, exceptions (`except`) and `allow` entries per route.
- **Rate and token limits** per route, API key or user.

### Tools

- `promptwall init` writes a policy from a few questions; `validate`, `test` (the tests in the policy file) and `scan` check one without running the proxy.
- Prometheus metrics, a Grafana dashboard and a Docker Compose demo; a JSON decision log.
- `POST /promptwall/v1/check` (`--check-api`) checks one text, for other languages and for the npm package.

### npm package

- `@promptwall-ai/sdk`: the same policy and checks in Node, edge functions and the browser, compiled to WebAssembly, with wrappers for the OpenAI client and the Vercel AI SDK. Model checks run on your Promptwall server through the check API.

### Install

- Downloads for Linux (x86_64 and arm64), macOS (Apple silicon) and Windows, a Docker image on ghcr.io, a Helm chart, and a build without ONNX Runtime for the pattern checks only.

[0.1.0]: https://github.com/Promptwall/promptwall/releases/tag/v0.1.0
