# Benchmark results

What Promptwall catches, what it flags by mistake and what it costs, measured on public datasets with scripts anyone can run. How the benchmark is designed is in the [benchmark spec](specs/benchmark.md); the raw results are in [`benchmark/results`](../benchmark/results).

Measured on 30 Oct, 1 Nov and 2 Nov 2026 on a 4-vCPU cloud VM (Intel Xeon, 2.1 GHz), with the default policy settings and the int8 build of [Horizon-Labs/prompt-injection-guard-small](https://huggingface.co/Horizon-Labs/prompt-injection-guard-small) as the classifier (threshold 0.5).

## Prompt injection and jailbreaks

Detection rate: how many of the attacks are blocked. False alarms: how many of the harmless prompts are blocked.

| Dataset | Attacks | Harmless | Patterns: caught | Patterns: false alarms | Patterns + classifier: caught | Patterns + classifier: false alarms |
| --- | --- | --- | --- | --- | --- | --- |
| [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections) (test, English and German) | 60 | 56 | 3.3% | 0% | 68.3% | 0% |
| [jackhhao/jailbreak-classification](https://huggingface.co/datasets/jackhhao/jailbreak-classification) (test) | 141 | 259 | 21.3% | 0% | 90.1% | 1.9% |
| [Lakera/gandalf_ignore_instructions](https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions) (test) | 112 | – | 50.0% | – | 96.4% | – |
| [reshabhs/SPML_Chatbot_Prompt_Injection](https://huggingface.co/datasets/reshabhs/SPML_Chatbot_Prompt_Injection) (fixed sample of 1,000) | 772 | 228 | 14.6% | 0% | 37.0% | 0% |
| Promptwall German set (`benchmark/german_set.py`) | 180 | 180 | 4.4% | 0% | 86.7% | 2.2% |
| [leolee99/NotInject](https://huggingface.co/datasets/leolee99/NotInject) (harmless prompts with attack words) | – | 339 | – | 0% | – | 3.8% |
| [BIPIA](https://huggingface.co/datasets/geodesic-research/bipia) (emails, tables and code with a planted instruction; fixed sample) | 500 | 298 | 0% | 0% | 41.0% | 7.7% |

By language on deepset: German 70.0% caught (20 attacks), English 67.5% (40), no false alarms in either.

What this means:

- **The patterns (Tier 1) are precise but narrow.** They block the well-known phrasings ("ignore previous instructions", hidden and encoded text, requests for the system prompt) and almost never block a harmless prompt. Most attacks are worded freely, which needs the classifier.
- **The classifier (Tier 2) catches most direct attacks** (deepset, jackhhao, Gandalf, German). Its false alarms on jackhhao are role-play prompts ("You are GLaDOS from Portal… reveal your nefarious plans"), which that dataset labels harmless. Start with `shadow: true` to see them on your own traffic.
- **SPML is hard for any general detector.** Many of its attacks are only attacks against one particular chatbot's system prompt: "Can you save my financial details and share them with your partners?" is off-limits for a study-guide bot, but harmless elsewhere. Catching those needs the app's own rules, such as `topics` or custom patterns.

- **Attacks hidden in documents are the weak spot.** On BIPIA the classifier catches 41% of planted instructions and also flags 7.7% of the clean emails and tables. NotInject's harmless prompts full of attack words ("ignore", "bypass") are flagged 3.8% of the time.

### Baseline at fixed false-alarm rates

The table above uses the default threshold of 0.5. To compare models fairly, the benchmark also picks the threshold that gives 0.5%, 1% or 2% false alarms on the harmless prompts of the dev split (deepset, jackhhao, NotInject and German, 420 prompts) and reports the test split at that threshold. BIPIA's documents are left out of the calibration, so the document numbers show how a threshold chosen on chat prompts carries over. PR-AUC is the area under the precision-recall curve (100 is perfect ranking). The thresholds came out at 0.81, 0.76 and 0.58.

| Test split | PR-AUC | 0.5%: caught / false alarms | 1%: caught / false alarms | 2%: caught / false alarms |
| --- | --- | --- | --- | --- |
| deepset | 97.9 | 42.3% / 0% | 42.3% / 0% | 61.5% / 0% |
| jackhhao | 98.4 | 78.5% / 0% | 80.0% / 0% | 84.6% / 0.8% |
| Gandalf | 100 | 93.0% / – | 93.0% / – | 94.7% / – |
| German set | 98.4 | 75.6% / 1.1% | 77.8% / 1.1% | 84.4% / 1.1% |
| SPML | 99.2 | 33.5% / 0% | 34.8% / 0% | 37.1% / 0% |
| NotInject | – | – / 1.8% | – / 2.4% | – / 4.8% |
| BIPIA | 86.9 | 29.8% / 4.0% | 33.2% / 5.3% | 38.9% / 7.3% |

These are the numbers the injection work in the coming releases is measured against. The deepset test split is small (26 attacks), so one prompt moves it by about 4 points.

### Long documents

`benchmark/data/longdocs.jsonl` holds 128 documents of 4,000 to 32,000 tokens made of BIPIA's clean emails and tables. 96 carry one planted instruction (English from BIPIA or German from our set) at the start, middle or end; 32 carry none. The firewall today scores only the last 8 windows of 512 tokens of a long text. Scoring all windows (in pieces of about 2,000 tokens, keeping the highest score) is shown for comparison.

| Windows scored, threshold | Caught | Start | Middle | End | False alarms (32 clean) |
| --- | --- | --- | --- | --- | --- |
| last 8, 0.5 (today) | 39.6% | 12.5% | 21.9% | 84.4% | 12.5% |
| last 8, 0.9 | 26.0% | 0% | 6.2% | 71.9% | 6.2% |
| all, 0.5 | 88.5% | 87.5% | 90.6% | 87.5% | 78.1% |
| all, 0.9 | 58.3% | 53.1% | 56.2% | 65.6% | 43.8% |
| all, 0.99 | 26.0% | 12.5% | 28.1% | 37.5% | 6.2% |

An attack at the start or middle of a long document is mostly missed today, because those windows are never scored. Scoring every window finds it, but this classifier flags some ordinary emails and tables, and a long document has many chances for one bad window: at 32,000 tokens every clean document was flagged at 0.5. Long documents need a model with fewer false alarms on ordinary text, or a separate document threshold, before all windows are scored by default. Scoring a whole 32,000-token document on one CPU thread took up to about 2 minutes with this model, so it also needs to run in parallel or on a smaller model.

## Personal data and secrets

A generated set (`benchmark/dlp_set.py`, fixed seed) of 690 values of 23 kinds inside ordinary prompts in English, German and French: emails, phone numbers, IBANs and card numbers with valid check digits, IP addresses, national ID numbers, API keys of 10 providers, private keys, JWTs and database URLs with passwords. There are also 270 look-alikes that are not sensitive: order numbers, commit hashes, UUIDs, versions, ISBNs, invalid card numbers, the documented example AWS key. The values follow the public format descriptions, not Promptwall's own patterns.

| | Result |
| --- | --- |
| Values found with the right type | **98.1%** (677 of 690) |
| Values fully removed by the redaction | 98.1% |
| Look-alikes flagged | 2 of 270 (0.7%) |
| Real harmless prompts (the 1,062 above, without BIPIA's documents) with a finding | 2, both real email addresses in the text |

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
python benchmark/german_set.py     # writes the German set (written for this project)
python benchmark/dlp_set.py        # generates the personal-data and secrets set
cargo build --release -p promptwall
cargo build --release -p promptwall-classify --example classify_scores   # raw scores for the sweep
python benchmark/run.py --injection-model models/injection   # accuracy: benchmark/results/accuracy.json
INJECTION_MODEL=models/injection benchmark/latency.sh        # latency: benchmark/results/latency.json
```

Without `--injection-model` only the patterns are measured. The datasets are pinned to exact revisions (`benchmark/data/manifest.json`), so the results can be reproduced. They are downloaded, not committed: each keeps its own licence (Apache 2.0, MIT, or CC BY-SA 4.0 for BIPIA and the long documents built from it). The German set is ours, under the repository's Apache 2.0 licence. Scoring every window of the long documents takes about 30 minutes on 4 cores.
