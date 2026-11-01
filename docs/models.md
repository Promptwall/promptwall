# Models (Tier 2)

Tier 2 detectors are small transformer classifiers that run on CPU with ONNX Runtime. Each is loaded from a directory at startup:

| Flag (environment variable) | Detector | Recommended model |
| --- | --- | --- |
| `--injection-model` (`PROMPTWALL_INJECTION_MODEL`) | `prompt_injection` (entity `classifier`) | [Horizon-Labs/prompt-injection-guard-small](https://huggingface.co/Horizon-Labs/prompt-injection-guard-small) |
| `--safety-model` (`PROMPTWALL_SAFETY_MODEL`) | `content_safety` | [Horizon-Labs/content-safety-guard-small](https://huggingface.co/Horizon-Labs/content-safety-guard-small) |
| `--topic-model` (`PROMPTWALL_TOPIC_MODEL`) | `topics` | [Horizon-Labs/multilingual-zeroshot-small](https://huggingface.co/Horizon-Labs/multilingual-zeroshot-small) |
| `--pii-model` (`PROMPTWALL_PII_MODEL`) | `pii` entities such as `person` and `street_address` | [Horizon-Labs/pii-redactor-small](https://huggingface.co/Horizon-Labs/pii-redactor-small) |

All four are Apache 2.0, multilingual, about 140M parameters, and ship an int8 ONNX file (`onnx/model_quantized.onnx`, about 270 MB). A route that uses a detector whose model is not loaded is an error at startup.

## Model directory

| File | Content |
| --- | --- |
| `model.onnx` | A sequence-classification model. Inputs `input_ids` and `attention_mask` (and `token_type_ids` if the model has one); first output the logits, shaped `[batch, labels]`. The PII model is a token-classification model instead, with logits shaped `[batch, tokens, labels]`. |
| `tokenizer.json` | The matching Hugging Face tokenizer. |
| `config.json` | Optional for the injection model, required for the others. `id2label` names the labels: for injection, the label that means "attack" (one containing `injection`, `jailbreak`, `malicious` or `unsafe`, otherwise label 1); for safety, the categories; for topics, an `entailment` label; for PII, `O` and `B-`/`I-` labels such as `B-PERSON`. `problem_type: multi_label_classification` gives each label its own probability (sigmoid) instead of a softmax. `max_position_embeddings` caps the window length (at most 512 tokens). |
| `thresholds.json` | Safety model only, optional: `{"unsafe": 0.5, "categories": {"hate": 0.2, ...}}`. |

To see what a model makes of a text: `cargo run --release -p promptwall-classify --example classify_text -- <dir> "<text>" [--before <prompt> | --after <hypothesis>]`.

Any Hugging Face text classifier exported to ONNX fits, for example with `optimum-cli export onnx --model <id> --task text-classification <dir>`.

Long texts are split into overlapping windows of up to 512 tokens. The score is the highest window score, so an attack inside a long document is not averaged away. At most 8 windows are scored, taken from the end of the text, where the newest user input is.

## Content safety

`content_safety` works with two kinds of moderation model:

- **A guard with an `unsafe` label plus harm categories**, like content-safety-guard. A text is harmful when `unsafe` reaches the threshold: the route's `threshold`, else the one in `thresholds.json`, else 0.5. Findings then name the categories above their own thresholds (`safety.weapons`, `safety.criminal_planning`), or `safety.unsafe` when none stands out. Its categories are `hate`, `harassment`, `violence`, `weapons`, `sexual`, `sexual_minors`, `self_harm`, `criminal_planning`, `drugs`, `privacy`, `profanity`, `fraud_manipulation`, `misinformation`, `unauthorized_advice` and `other`.
- **A model whose labels are each a harm**, like the Detoxify toxicity models ([Horizon-Labs/multilingual-toxicity-small](https://huggingface.co/Horizon-Labs/multilingual-toxicity-small): `toxicity`, `insult`, `threat`, `obscene`, ...). Every label at or above the threshold is a finding.

On answers, the model judges the answer together with the end of the prompt it answers.

False alarms: on the 179 benign prompts of the evaluation set above, content-safety-guard-small (int8) flags 7 (3.9%) at its default threshold of 0.5. At 0.8 it flags 3 (1.7%), and at 0.9 one. The flagged prompts are mostly villain role-play ("Pretend to be Vicious, threatening a rival"). It also flags some harmless questions in other languages, such as "Wie kann ich meine Kreditkarte sperren lassen?" ("How do I block my credit card?") at 0.58. Start with `shadow: true` or `action: flag`, then block with a threshold around 0.8.

## Topics

`topics` uses a zero-shot classifier: a natural language inference model that judges whether the prompt entails "This text is about {topic}." for each topic in `deny` and `allow`. All topics are scored in one batch. Topic names are best written in English, as plain descriptions ("personal finance", "medical advice"), even when prompts are in other languages. Broader names score more reliably than narrow ones: for "Wie kann ich meine Kreditkarte sperren lassen?" the model gives 0.69 for "banking" and 0.98 for "money and banking".

## Names and addresses

The PII model tags each token of a text, and tokens with the same entity type are joined into a value: "Thomas Schneider", "Hauptstraße 5", "10115". A value that ends or starts inside a word is widened to the whole word, so a name is never redacted by half. Its entity types become `pii` entities in lower case (`B-STREET_ADDRESS` is `street_address`). pii-redactor-small has `person`, `street_address`, `postcode`, `location`, `organization`, `date`, `date_of_birth`, `age`, `phone`, `email`, `url`, `ip_address`, `mac_address`, `coordinate`, `username`, `password`, `secret`, `account_id`, `bank_account`, `credit_card`, `credit_card_cvv`, `national_id`, `tax_id`, `passport`, `driver_license`, `license_number`, `medical_id`, `vehicle_id` and `device_id`. Where a built-in entity has the same name (`email`, `phone`, `credit_card`, `ip_address`, `password`), the built-in one is used: it is exact and costs nothing.

Some results with the int8 model:

| Text | Found |
| --- | --- |
| Bitte schick die Rechnung an Herrn Thomas Schneider, Hauptstraße 5, 10115 Berlin. | person, street_address, postcode, location |
| Bonjour, je m'appelle Jean Dupont, j'habite 12 rue de la Paix, 75002 Paris. | person, street_address, postcode, location |
| 张伟住在北京市朝阳区建国路88号。 | person, location, street_address |
| Summarise the quarterly report and list the three main risks. | nothing |

On the 179 benign prompts of the evaluation set below (threshold 0.5) it finds a person in 55 prompts and a street address in 5. Most of these are real names: authors, public figures, fictional characters ("Helmut Schmidt", "Misato Katsuragi", "Boulevard Saint Germain"). A few are wrong, such as the news site "Breitbart" as a person or "Hill" as a street. The model cannot tell a customer from a famous person, so redacting `person` also redacts public figures and characters, and `location` (82 findings) is common in harmless text. Redact `person`, `street_address` and `postcode` where personal data must not leave, and start with `flag` or `shadow: true` for the rest.

Every model entity is found before the request is forwarded, so unlike the classifiers below its latency adds to each request. Through the proxy on a 4-core 2.1 GHz VM, a whole request took about 40 ms with a short prompt, 110 ms with 130 tokens and 220 ms with 500 tokens (`--model-threads 4`; with the default of one thread, 40, 125 and 400 ms). Chat apps resend the whole conversation with each request, so the entities of every text are cached (by a hash of the text; the text itself is not kept): in a test, a 10-turn conversation took 330 ms the first time and 35 ms for the next turn. A single call checks at most 32,768 tokens; a larger request follows `fail_mode`.

Streamed answers are checked like content safety: every 256 bytes and at the end, with only checked text sent on.

## Latency

Transformer classifiers are far slower than the Tier 1 patterns. `--model-sessions` sets how many checks can run at the same time (each session holds a copy of the model) and `--model-threads` how many threads each may use. Measured with `crates/classify/examples/classify_speed.rs` on a 4-core 2.1 GHz cloud VM:

| Model | 20 tokens | 130 tokens | 500 tokens |
| --- | --- | --- | --- |
| ProtectAI DeBERTa-v3 base, fp32, 4 threads | 30 ms | 97 ms | 430 ms |
| Horizon-Labs mmBERT-small, int8, 4 threads | 12 ms | 40 ms | 176 ms |

The content-safety and zero-shot models are the same size as the mmBERT-small injection model. Through the proxy, a route with `content_safety` and four topics took about 90 ms for a short prompt on this VM.

So the classifiers do not sit in front of the provider call. By default (`parallel: true`) the request is forwarded as soon as the Tier 1 checks pass, and the classifier runs at the same time. The provider's response is held until the classifier has decided: on a block, the provider call is cancelled and the app gets `403`, so neither the answer nor any tool call in it reaches the app. Because providers take hundreds of milliseconds to the first token, the classifier usually adds no latency.

The prompt itself has reached the provider by then, which is harmless for injection (the damage is done through the answer) but costs the tokens generated before the cancel. PII and secret checks always run before forwarding. Routes that use tools the provider runs itself (hosted web search, code execution, remote MCP servers) should set `parallel: false`, so the classifier finishes before anything is sent. The `parallel` setting of `prompt_injection` applies to all of a route's Tier 2 checks on requests.

Answers are different: they cannot be released before they are checked. With `content_safety` or model `pii` entities on a route's output, a whole answer waits for the model. A streamed answer is judged each time about 256 more bytes of text have arrived, and at the end. Only judged text is sent on, so streaming arrives in steps, each delayed by one model run.

## Accuracy

Measured with `crates/classify/examples/classify_eval.rs` on the test splits of [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections) (English and German, 116 prompts) and [jackhhao/jailbreak-classification](https://huggingface.co/datasets/jackhhao/jailbreak-classification) (262 prompts), both Apache 2.0. Detection rate / false-positive rate, threshold 0.5:

| | deepset | jailbreak |
| --- | --- | --- |
| Tier 1 patterns only | 3% / 0% | 30% / 0% |
| ProtectAI DeBERTa-v3 base (fp32) | 37% / 0% | 87% / 2% |
| Horizon-Labs mmBERT-small (int8) | 68% / 0% | 89% / 4% |

Small public sets; treat these as a sanity check. The [benchmark](benchmark.md) measures the whole firewall on more data. Notes:

- [Horizon-Labs/prompt-injection-guard-small](https://huggingface.co/Horizon-Labs/prompt-injection-guard-small) (Apache 2.0) is multilingual, which matters for the German half of the deepset set, and ships an int8 ONNX file. It is the current recommendation.
- [protectai/deberta-v3-base-prompt-injection-v2](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2) (Apache 2.0) is English-only, and dynamic int8 quantisation breaks it (its detection drops to almost zero), so it only runs in fp32.
- Llama Prompt Guard 2 is not recommended as a default: its licence restricts very large companies, which rules it out for some adopters.

A smaller in-house model, distilled from these and trained on our own multilingual data, is planned; it is the way to get Tier 2 under 10 ms.
