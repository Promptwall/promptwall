#!/usr/bin/env bash
# Runs the pass-through latency benchmark locally: mock upstream, proxy, then pw-bench.
# Extra arguments go to pw-bench, e.g. scripts/bench.sh --stream --max-p95-added-ms 2
# Set BENCH_POLICY to a policy file to benchmark with detectors on, e.g.
#   BENCH_POLICY=scripts/bench-policy.yaml scripts/bench.sh
set -euo pipefail

cargo build --release --quiet
bin=target/release

"$bin/pw-mock-upstream" --listen 127.0.0.1:9000 --delay-ms 50 2>/dev/null &
mock=$!
if [[ -n "${BENCH_POLICY:-}" ]]; then
  target=(--policy "$BENCH_POLICY")
else
  target=(--upstream http://127.0.0.1:9000)
fi
RUST_LOG=warn "$bin/promptwall" --listen 127.0.0.1:8080 "${target[@]}" &
proxy=$!
trap 'kill $mock $proxy 2>/dev/null || true' EXIT

for _ in $(seq 50); do
  curl -sf http://127.0.0.1:8080/healthz >/dev/null && break
  sleep 0.1
done

"$bin/pw-bench" --direct http://127.0.0.1:9000 --proxy http://127.0.0.1:8080 "$@"
