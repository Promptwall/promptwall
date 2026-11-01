# Benchmark results

What Promptwall catches, what it flags by mistake and what it costs, measured on public datasets with scripts anyone can run. How the benchmark is designed is in the [benchmark spec](specs/benchmark.md); the raw results are in [`benchmark/results`](../benchmark/results).

Measured on 30 Oct and 1 Nov 2026 on a 4-vCPU cloud VM (Intel Xeon, 2.1 GHz), with the default policy settings and the int8 build of [Horizon-Labs/prompt-injection-guard-small](https://huggingface.co/Horizon-Labs/prompt-injection-guard-small) as the classifier (threshold 0.5).

## Prompt injection and jailbreaks

Detection rate: how many of the attacks are blocked. False alarms: how many of the harmless prompts are blocked.

| Dataset | Attacks | Harmless | Patterns: caught | Patterns: false alarms | Patterns + classifier: caught | Patterns + classifier: false alarms |
| --- | --- | --- | --- | --- | --- | --- |
| [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections) (test, English and German) | 60 | 56 | 3.3% | 0% | 68.3% | 0% |
| [jackhhao/jailbreak-classification](https://huggingface.co/datasets/jackhhao/jailbreak-classification) (test) | 141 | 259 | 21.3% | 0% | 90.1% | 1.9% |
| [Lakera/gandalf_ignore_instructions](https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions) (test) | 112 | – | 50.0% | – | 96.4% | – |
| [reshabhs/SPML_Chatbot_Prompt_Injection](https://huggingface.co/datasets/reshabhs/SPML_Chatbot_Prompt_Injection) (fixed sample of 1,000) | 772 | 228 | 14.6% | 0% | 37.0% | 0% |

What this means:

- **The patterns (Tier 1) are precise but narrow.** They block the well-known phrasings ("ignore previous instructions", hidden and encoded text, requests for the system prompt) and almost never block a harmless prompt. Most attacks are worded freely, which needs the classifier.
- **The classifier (Tier 2) catches most attacks** on three of the four sets. Its false alarms on jackhhao are role-play prompts ("You are GLaDOS from Portal… reveal your nefarious plans"), which that dataset labels harmless. Start with `shadow: true` to see them on your own traffic.
- **SPML is hard for any general detector.** Many of its attacks are only attacks against one particular chatbot's system prompt: "Can you save my financial details and share them with your partners?" is off-limits for a study-guide bot, but harmless elsewhere. Catching those needs the app's own rules, such as `topics` or custom patterns.

## Personal data and secrets

A generated set (`benchmark/dlp_set.py`, fixed seed) of 690 values of 23 kinds inside ordinary prompts in English, German and French: emails, phone numbers, IBANs and card numbers with valid check digits, IP addresses, national ID numbers, API keys of 10 providers, private keys, JWTs and database URLs with passwords. There are also 270 look-alikes that are not sensitive: order numbers, commit hashes, UUIDs, versions, ISBNs, invalid card numbers, the documented example AWS key. The values follow the public format descriptions, not Promptwall's own patterns.

| | Result |
| --- | --- |
| Values found with the right type | **98.1%** (677 of 690) |
| Values fully removed by the redaction | 98.1% |
| Look-alikes flagged | 2 of 270 (0.7%) |
| Real harmless prompts (the 543 above) with a finding | 2, both real email addresses in the text |

All the email, phone, IBAN, card, IP, US SSN, UK National Insurance and Spanish DNI values were found, as were all secrets. The misses are Dutch BSN and Polish PESEL numbers written without any word nearby that says what they are: a bare 9- or 11-digit number is too often something else, so these two need a keyword such as "BSN" or "PESEL" close by. The two flagged look-alikes are four-part version numbers ("9.6.5.0") read as IP addresses.

Names and street addresses need the PII model and are not in this set; see [models](models.md#names-and-addresses) for how it does.

## Latency

What Promptwall adds to each request, in front of a mock provider that answers in 50 ms: time through Promptwall minus time straight to the mock, at a constant request rate (`benchmark/latency.sh`, built on `scripts/bench.sh`). Values within about 1 ms are measurement noise.

| Setup | Load | Added p50 | Added p95 |
| --- | --- | --- | --- |
| Pass-through | 100 req/s, 500-token prompts | < 1 ms | 1 ms |
| Patterns, all input and output checks | 100 req/s, 500-token prompts | < 1 ms | < 1 ms |
| Patterns, streamed answer: to the last token | 100 req/s | 2 ms | < 1 ms |
| Patterns, streamed answer: to the first token | 100 req/s | 291 ms | 294 ms |
| Patterns + classifier, 20-token prompts | 5 req/s | < 1 ms | < 1 ms |
| Patterns + classifier, 130-token prompts | 5 req/s | 6 ms | 18 ms |
| Patterns + classifier, 500-token prompts | 1 req/s | 179 ms | 249 ms |

What this means:

- **The patterns cost under a millisecond**, well inside the budget, with every check on.
- **Streamed answers start later when output checks are on.** The last 128 characters of an answer are held back until more arrive, so a secret split across two events is never half sent (`stream_holdback`). At about 80 tokens per second, the first text arrives after about 290 ms instead of at once; the end of the answer is not delayed. A smaller `stream_holdback` starts sooner but can let a long value through in part.
- **The classifier runs while the request is already with the provider**, so it only adds what it takes beyond the provider's own time to answer. Against a 50 ms provider that is nothing for short prompts and about 180 ms for 500 tokens; real providers take several hundred milliseconds to answer, which hides more of it.
- **One classifier session handles about 5 to 10 checks per second on 4 cores** (`--model-threads 4`). Beyond that, checks queue and latency climbs quickly. Use more `--model-sessions` and cores, or more replicas, for more traffic. A smaller model is planned ([models](models.md#accuracy)).

## Running it

Needs Python 3 (with `pyarrow` for the datasets: `pip install -r benchmark/requirements.txt`) and a release build:

```sh
python benchmark/fetch.py          # downloads the pinned datasets into benchmark/data
python benchmark/dlp_set.py        # generates the personal-data and secrets set
cargo build --release -p promptwall
python benchmark/run.py --injection-model models/injection   # accuracy: benchmark/results/accuracy.json
INJECTION_MODEL=models/injection benchmark/latency.sh        # latency: benchmark/results/latency.json
```

Without `--injection-model` only the patterns are measured. The datasets are pinned to exact revisions (`benchmark/data/manifest.json`), so the results can be reproduced. They are downloaded, not committed: each keeps its own licence (Apache 2.0 or MIT).
