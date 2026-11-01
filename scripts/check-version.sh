#!/usr/bin/env bash
# Checks that the crates, the npm package and the Helm chart all carry the
# given version (the release tag without its "v"). Used by the release workflow.
#   scripts/check-version.sh 0.1.0
set -euo pipefail
want=$1
cd "$(dirname "$0")/.."
cargo=$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)
npm=$(grep -m1 '"version"' packages/sdk/package.json | cut -d'"' -f4)
chart=$(grep -m1 '^version:' deploy/helm/promptwall/Chart.yaml | awk '{print $2}')
app=$(grep -m1 '^appVersion:' deploy/helm/promptwall/Chart.yaml | awk '{print $2}' | tr -d '"')
ok=true
for pair in "Cargo.toml:$cargo" "packages/sdk/package.json:$npm" "Chart.yaml version:$chart" "Chart.yaml appVersion:${app#v}"; do
  if [[ "${pair##*:}" != "$want" ]]; then echo "${pair%:*} is ${pair##*:}, not $want"; ok=false; fi
done
$ok && echo "all versions are $want"
$ok
