#!/usr/bin/env bash
# Load test: many long streams at once through Promptwall with every Tier 1
# check on, in two rounds. Reports errors and the proxy's memory (RSS) at its
# peak and after each round, to show that it stays bounded and is given back.
#   scripts/soak.sh                       # 300 req/s of 5 s streams: ~1,500 open at once
#   RATE=1000 SECONDS_PER_ROUND=60 scripts/soak.sh
#   SOAK_POLICY=none scripts/soak.sh      # pass-through, for comparison
# Linux only (reads /proc). Needs about 3 file handles per open stream.
set -euo pipefail

rate=${RATE:-300}
duration=${SECONDS_PER_ROUND:-20}

cargo build --release --quiet -p promptwall -p pw-mock-upstream -p pw-bench
bin=target/release

# 100 chunks 50 ms apart: each answer streams for about 5 seconds.
"$bin/pw-mock-upstream" --listen 127.0.0.1:9000 --delay-ms 50 --chunks 100 --chunk-ms 50 2>/dev/null &
mock=$!
policy=${SOAK_POLICY:-scripts/bench-policy.yaml}
if [[ "$policy" == none ]]; then
  target=(--upstream http://127.0.0.1:9000)
else
  target=(--policy "$policy")
fi
RUST_LOG=warn "$bin/promptwall" --listen 127.0.0.1:8080 "${target[@]}" &
proxy=$!
trap 'kill $mock $proxy $sampler 2>/dev/null || true' EXIT
for _ in $(seq 50); do
  curl -sf http://127.0.0.1:8080/healthz >/dev/null && break
  sleep 0.1
done

rss() { awk '/VmRSS/ { print int($2 / 1024) }' "/proc/$proxy/status"; }
peak_file=$(mktemp)
echo 0 > "$peak_file"
sampler=
( while kill -0 "$proxy" 2>/dev/null; do
    now=$(rss); [[ $now -gt $(cat "$peak_file") ]] && echo "$now" > "$peak_file"
    sleep 0.2
  done ) &
sampler=$!

echo "idle: $(rss) MiB"
for round in 1 2; do
  "$bin/pw-bench" --direct http://127.0.0.1:9000 --proxy http://127.0.0.1:8080 \
    --stream --rate "$rate" --duration "$duration" --warmup 1 --prompt-tokens 500
  sleep 3   # let the last streams finish
  echo "round $round: peak $(cat "$peak_file") MiB, after $(rss) MiB, open files $(ls /proc/$proxy/fd | wc -l)"
done
