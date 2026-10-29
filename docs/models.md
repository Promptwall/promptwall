# Models (Tier 2)

Tier 2 detectors are small transformer classifiers that run on CPU with ONNX Runtime. Today there is one: the prompt-injection classifier, loaded with `--injection-model <dir>` (or `PROMPTWALL_INJECTION_MODEL`).

## Model directory

| File | Content |
| --- | --- |
| `model.onnx` | A sequence-classification model. Inputs `input_ids` and `attention_mask` (and `token_type_ids` if the model has one); first output the logits, shaped `[batch, labels]`. |
| `tokenizer.json` | The matching Hugging Face tokenizer. |
| `config.json` | Optional. `id2label` picks the label that means "attack" (one containing `injection`, `jailbreak`, `malicious` or `unsafe`, otherwise label 1); `max_position_embeddings` caps the window length (at most 512 tokens). |

Any Hugging Face text classifier exported to ONNX fits, for example with `optimum-cli export onnx --model <id> --task text-classification <dir>`.

Long texts are split into overlapping windows of up to 512 tokens. The score is the highest window score, so an attack inside a long document is not averaged away. At most 8 windows are scored, taken from the end of the text, where the newest user input is.

## Latency

Transformer classifiers are far slower than the Tier 1 patterns. Measured with `crates/classify/examples/classify_speed.rs` on a 4-core 2.1 GHz cloud VM:

| Model | 20 tokens | 130 tokens | 500 tokens |
| --- | --- | --- | --- |
| ProtectAI DeBERTa-v3 base, fp32, 4 threads | 30 ms | 97 ms | 430 ms |
| Horizon-Labs mmBERT-small, int8, 4 threads | 12 ms | 40 ms | 176 ms |

So the classifier does not sit in front of the provider call. By default (`parallel: true`) the request is forwarded as soon as the Tier 1 checks pass, and the classifier runs at the same time. The provider's response is held until the classifier has decided: on a block, the provider call is cancelled and the app gets `403`, so neither the answer nor any tool call in it reaches the app. Because providers take hundreds of milliseconds to the first token, the classifier usually adds no latency.

The prompt itself has reached the provider by then, which is harmless for injection (the damage is done through the answer) but costs the tokens generated before the cancel. PII and secret checks always run before forwarding. Routes that use tools the provider runs itself (hosted web search, code execution, remote MCP servers) should set `parallel: false`, so the classifier finishes before anything is sent.

## Accuracy

Measured with `crates/classify/examples/classify_eval.rs` on the test splits of [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections) (English and German, 116 prompts) and [jackhhao/jailbreak-classification](https://huggingface.co/datasets/jackhhao/jailbreak-classification) (262 prompts), both Apache 2.0. Detection rate / false-positive rate, threshold 0.5:

| | deepset | jailbreak |
| --- | --- | --- |
| Tier 1 patterns only | 3% / 0% | 30% / 0% |
| ProtectAI DeBERTa-v3 base (fp32) | 37% / 0% | 87% / 2% |
| Horizon-Labs mmBERT-small (int8) | 68% / 0% | 89% / 4% |

Small public sets; treat these as a sanity check, not a benchmark. Notes:

- [Horizon-Labs/prompt-injection-guard-small](https://huggingface.co/Horizon-Labs/prompt-injection-guard-small) (Apache 2.0) is multilingual, which matters for the German half of the deepset set, and ships an int8 ONNX file. It is the current recommendation.
- [protectai/deberta-v3-base-prompt-injection-v2](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2) (Apache 2.0) is English-only, and dynamic int8 quantisation breaks it (its detection drops to almost zero), so it only runs in fp32.
- Llama Prompt Guard 2 is not recommended as a default: its licence restricts very large companies, which matters for an acquirer.

A smaller in-house model, distilled from these and trained on our own multilingual data, is planned; it is the way to get Tier 2 under 10 ms.
