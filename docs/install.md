# Installing Promptwall

Promptwall is one program, `promptwall`, plus a policy file. Pick whichever way of running it suits you; they all behave the same.

## Download

Every release on the [releases page](https://github.com/Promptwall/promptwall/releases) has ready-made downloads, with `SHA256SUMS` to check them:

| System | File |
| --- | --- |
| Windows (x64) | `promptwall-<version>-x86_64-pc-windows-msvc.zip` |
| macOS (Apple silicon) | `promptwall-<version>-aarch64-apple-darwin.tar.gz` |
| Linux (x64) | `promptwall-<version>-x86_64-unknown-linux-gnu.tar.gz` |
| Linux (ARM64) | `promptwall-<version>-aarch64-unknown-linux-gnu.tar.gz` |

Unpack it and run it; nothing else is needed. ONNX Runtime, for the optional models, is built in.

```sh
promptwall init                       # asks a few questions, writes promptwall.yaml
promptwall test --policy promptwall.yaml
promptwall --policy promptwall.yaml   # listens on http://127.0.0.1:8080
```

On Windows, run the same commands as `promptwall.exe` in PowerShell. On macOS, if Gatekeeper refuses the file, allow it once with `xattr -d com.apple.quarantine promptwall`.

## Docker

```sh
docker run --rm -p 8080:8080 -v "$PWD/policy.yaml:/policy.yaml:ro" \
  ghcr.io/promptwall/promptwall --policy /policy.yaml
```

The image (`linux/amd64` and `linux/arm64`) runs as an unprivileged user, listens on `0.0.0.0:8080` and also contains `pw-mock-upstream`, a fake provider for trying things out. Tags: the release (`v0.1.0`) and `latest`. Models are not in the image; mount them:

```sh
docker run --rm -p 8080:8080 -v "$PWD/policy.yaml:/policy.yaml:ro" -v "$PWD/models:/models:ro" \
  ghcr.io/promptwall/promptwall --policy /policy.yaml --injection-model /models/injection
```

[`deploy/compose`](../deploy/compose) runs it with Prometheus and Grafana; see [monitoring](monitoring.md).

## Kubernetes (Helm)

```sh
helm install promptwall deploy/helm/promptwall --set-file policy=policy.yaml
```

Apps then use `http://promptwall.<namespace>.svc:8080`. Policy changes (`helm upgrade --set-file policy=...`, or your own ConfigMap with `existingPolicyConfigMap`) are applied by the running pods within a minute, without a restart. [`values.yaml`](../deploy/helm/promptwall/values.yaml) has the rest: replicas, metrics, the decision log on standard output, signed policies, and models from a volume.

## Build from source

Needs a recent stable [Rust](https://rustup.rs).

```sh
cargo build --release -p promptwall      # target/release/promptwall
```

The build downloads a prebuilt ONNX Runtime for the models. Where that is not possible or not wanted, build without it:

```sh
cargo build --release -p promptwall --no-default-features
```

That build has every check except the Tier 2 models (`--injection-model`, `--safety-model`, `--topic-model`, `--pii-model`, which then fail with a clear error); prompt injection is still caught by its patterns. It also avoids the one build problem seen on Windows: the prebuilt ONNX Runtime needs Visual Studio 2022 17.14 or newer, and older versions fail to link with `unresolved external symbol __std_find_last_of_trivial_pos_1`. Update Visual Studio, use the download above, or build with `--no-default-features`.

## Models

The optional models are separate downloads (about 270 MB each); [models](models.md) says where to get them and how to lay out their directories.

## Sizing

[`scripts/soak.sh`](../scripts/soak.sh) measures a machine: it keeps many 5-second streams open through Promptwall with every Tier 1 check on, and reports latency, memory and open files. On 4 shared vCPUs (with the load generator and the mock provider on the same machine):

| Streams open at once | Added latency (p95) | Memory |
| --- | --- | --- |
| about 1,500 | 5 ms | 210 MiB |
| about 5,000 | seconds: the CPUs are saturated | 900 MiB |

Checking a streamed answer costs CPU for each event the provider sends, so plan about one vCPU per 400 to 500 streams open at once with output checks on, and scale out behind a load balancer beyond that. Without output checks, streams cost little more than forwarding. Memory grows with the request and answer bodies being checked: `--max-connections` (default 10,000) caps how many are open at once, and each checked request can hold up to 32 MiB.
