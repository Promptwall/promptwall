# Contributing to Promptwall

Thanks for your interest in Promptwall. Bug reports, detector bypasses, false alarms and pull requests are all welcome; open an issue first for larger changes, so we can agree on the approach.

## Building and testing

```sh
cargo test --workspace                          # needs ONNX Runtime; see docs/install.md
cargo test --workspace --no-default-features    # without the model checks
cargo fmt --all && cargo clippy --workspace --all-targets
cd packages/sdk && npm run build && npm test    # the npm package
```

A prompt that should be blocked but is not belongs in [`tests/attack-corpus.yaml`](tests/attack-corpus.yaml), together with the fix.

## Contributor Licence Agreement

All contributions need a signed [Contributor Licence Agreement](CLA.md) before they can be merged. You keep the copyright to your work; the agreement lets the project offer your contribution under other licences too, for example in a commercial edition, and protects you and users with a patent licence. On your first pull request, a bot asks you to sign by posting a comment; it takes a minute and covers all your later contributions.

## How changes flow

- This repository is the single source of truth for the engine, the open rules and detectors, the policy format and the plugin interface.
- Commercial modules live in a separate private repository. They depend on a pinned release of this one and never modify its code or rules. Changes to anything shared always land here first.

## Pull requests

- Keep each pull request focused on one change.
- Specs and docs use plain, short sentences.
- Every change must pass CI, including the latency gate. Changes to detectors should not lower the [benchmark](docs/benchmark.md) results; rerun it with `benchmark/run.py` and say what changed.
