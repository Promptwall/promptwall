# Monitoring

Promptwall exposes Prometheus metrics on a separate address, so they are never reachable through the proxy port:

```sh
promptwall --policy policy.yaml --metrics-listen 127.0.0.1:9464   # or PROMPTWALL_METRICS_LISTEN
curl http://127.0.0.1:9464/metrics
```

Labels are route names, actions and finding labels such as `pii.email`. Prompt and answer text never appears in metrics or logs.

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `promptwall_requests_total` | counter | `route`, `action` | Requests and what Promptwall did: `allow`, `flag`, `redact`, `block`, `rate_limited`, `no_route`, `error` (provider unreachable) |
| `promptwall_findings_total` | counter | `route`, `finding`, `direction` | Findings in requests and responses |
| `promptwall_check_duration_seconds` | histogram | `route`, `stage` | Time spent checking a request: `rules` (Tier 1) or `models` (Tier 2); `check_api` for a whole call of the [check API](../packages/sdk/README.md#check-api) |
| `promptwall_checks_total` | counter | `route`, `action` | Calls of the check API and their verdict: `allow`, `flag`, `redact`, `block` |
| `promptwall_request_duration_seconds` | histogram | `route` | Time until the response headers were sent, including the provider |
| `promptwall_attachments_total` | counter | `route`, `format`, `checked` | Attachments in requests by format (`text`, `pdf`, `image`, `audio`, `file`, `remote`) and whether their text was checked |
| `promptwall_uninspected_total` | counter | `route`, `direction` | Requests or responses that could not be inspected (compressed, too large, model failure) |
| `promptwall_upstream_errors_total` | counter | | Requests whose provider could not be reached |
| `promptwall_policy_reloads_total` | counter | `result` | Policy file reloads: `ok`, or `error` when the changed file was rejected and the previous policy stayed in force |
| `promptwall_decision_log_dropped_total` | counter | | Decision log lines dropped because the disk could not keep up |
| `promptwall_build_info` | gauge | `version` | Always 1 |

Shadow-mode findings are counted too; `action` then says what was let through.

## Grafana dashboard

[`deploy/compose/grafana/dashboards/promptwall.json`](../deploy/compose/grafana/dashboards/promptwall.json) is a ready-made dashboard: request rate, share blocked, redacted and rate limited, requests by action and route, top findings, findings in requests and answers, Promptwall's own check time, request duration with the provider, and errors. Import it in Grafana (Dashboards, New, Import) and pick your Prometheus data source. It only shows metrics; configuration stays in the policy file.

## Try it with Docker

[`deploy/compose`](../deploy/compose) starts Promptwall, a mock provider, Prometheus and Grafana with the dashboard:

```sh
cd deploy/compose
docker compose --profile demo up --build
```

Then open http://localhost:3000. The `demo` profile adds a container that sends a mix of normal, sensitive and malicious prompts every second; leave `--profile demo` out to send your own requests to http://localhost:8080. The demo policy is in `deploy/compose/policy.yaml`; change its upstream URL to use a real provider (for Ollama on the same machine: `http://host.docker.internal:11434`).

## Decision log

Metrics count; the decision log records each request. Start the proxy with `--decision-log <file>` (or `-` for standard output; `PROMPTWALL_DECISION_LOG`) and it writes one JSON line per request once its response has been sent:

```json
{"ts":"2026-10-29T21:40:05.360Z","id":"e5d356b711bc5483","route":"openai","action":"redact","shadow":false,"status":200,"policy":"sha256:c629bc99…","request":{"action":"redact","findings":{"pii.email":1}},"response":{},"latency_ms":12.4,"duration_ms":850.2,"check_ms":{"rules":0.3}}
```

| Field | Meaning |
| --- | --- |
| `ts` | When the request arrived (UTC) |
| `id` | Random ID, also sent to the client in the `x-promptwall-request-id` header |
| `route`, `action`, `shadow`, `status` | The route, what Promptwall did (as in `promptwall_requests_total`), and the HTTP status sent |
| `policy` | SHA-256 of the policy file in force, to tell which version decided |
| `request`, `response` | `action`, `findings` (label and count) and `uninspected: true` for each direction; empty when nothing was found |
| `latency_ms`, `duration_ms` | Until the response headers, and until the whole response, were sent |
| `check_ms` | Time Promptwall spent on `rules` and `models` |

The log never contains prompt or answer text, API keys or header values. Lines are written by a background thread, so a slow disk never delays a request; if 10,000 lines are waiting, new ones are dropped and counted in `promptwall_decision_log_dropped_total`. Ship the file with any log shipper (Filebeat, Fluent Bit, Vector, the Splunk forwarder); rotate it with `copytruncate`, since the proxy keeps the file open.
