#!/usr/bin/env bash
# Latency benchmark: what Promptwall adds to each request in front of a mock
# provider (50 ms to answer), for each setup. Writes benchmark/results/latency.json.
#   benchmark/latency.sh                         # pass-through and patterns
#   INJECTION_MODEL=models/injection benchmark/latency.sh   # also the classifier
# Each run sends constant-rate traffic for 20 s; see scripts/bench.sh.
set -euo pipefail
cd "$(dirname "$0")/.."
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
policy=scripts/bench-policy.yaml
stream="--chunks 100 --chunk-ms 12"   # about 80 tokens/s, like a fast provider
bench() { name=$1; shift; echo "$name" >&2; env "$@" > "$out/$name.json"; }

bench passthrough scripts/bench.sh --json --rate 100 --duration 20 --prompt-tokens 500
bench patterns BENCH_POLICY=$policy scripts/bench.sh --json --rate 100 --duration 20 --prompt-tokens 500
bench passthrough_stream MOCK_ARGS="$stream" scripts/bench.sh --stream --json --rate 100 --duration 20 --prompt-tokens 500
bench patterns_stream BENCH_POLICY=$policy MOCK_ARGS="$stream" scripts/bench.sh --stream --json --rate 100 --duration 20 --prompt-tokens 500
if [[ -n "${INJECTION_MODEL:-}" ]]; then
  model=(BENCH_POLICY=$policy PROMPTWALL_INJECTION_MODEL=$INJECTION_MODEL PROMPTWALL_MODEL_THREADS=4)
  bench classifier_20_tokens "${model[@]}" scripts/bench.sh --json --rate 5 --duration 20 --prompt-tokens 20
  bench classifier_130_tokens "${model[@]}" scripts/bench.sh --json --rate 5 --duration 20 --prompt-tokens 130
  bench classifier_500_tokens "${model[@]}" scripts/bench.sh --json --rate 1 --duration 20 --prompt-tokens 500
fi

mkdir -p benchmark/results
python3 - "$out" > benchmark/results/latency.json <<'PY'
import json, os, sys, time
runs = {f[:-5]: json.load(open(os.path.join(sys.argv[1], f))) for f in sorted(os.listdir(sys.argv[1]))}
print(json.dumps({"date": time.strftime("%Y-%m-%d"), "cpus": os.cpu_count(), "runs": runs}, indent=2))
PY
python3 -c "
import json
for k, r in json.load(open('benchmark/results/latency.json'))['runs'].items():
    a, f = r['total']['added'], r['first_byte']['added']
    print(f\"{k:<24} added p50 {a['p50_ms']:7.1f} ms  p95 {a['p95_ms']:7.1f} ms  first token p50 {f['p50_ms']:7.1f} ms\")"
