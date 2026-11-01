"""Downloads the public datasets of the accuracy benchmark, pinned to exact
revisions, into benchmark/data/ as JSON lines: {"text", "label", "set"}, where
label 1 is an attack and 0 an ordinary prompt.

    pip install pyarrow
    python benchmark/fetch.py
"""

import csv
import io
import json
import random
import sys
import urllib.request
from pathlib import Path

import pyarrow.parquet as pq

DATA = Path(__file__).parent / "data"

# (name, Hugging Face dataset, revision, file, licence)
SOURCES = [
    ("deepset", "deepset/prompt-injections", "4f61ecb038e9c3fb77e21034b22511b523772cdd",
     "data/test-00000-of-00001-701d16158af87368.parquet", "Apache-2.0"),
    ("jackhhao", "jackhhao/jailbreak-classification", "2f2ceeb39658696fd3f462403562b6eea5306287",
     "default/jailbreak_dataset_test.csv", "Apache-2.0"),
    ("gandalf", "Lakera/gandalf_ignore_instructions", "04737b65e90a6794ec227012e4a255a7def6344b",
     "data/test-00000-of-00001-bc92128b9288a6d1.parquet", "MIT"),
    ("spml", "reshabhs/SPML_Chatbot_Prompt_Injection", "02ce8084e979bc7d4c24ee35d22ecb7f2db96ff5",
     "spml_prompt_injection.csv", "MIT"),
]
# SPML has 16,000 rows; a fixed sample keeps a run short.
SPML_SAMPLE = 1000


def download(dataset, revision, path):
    url = f"https://huggingface.co/datasets/{dataset}/resolve/{revision}/{path}"
    with urllib.request.urlopen(url, timeout=60) as resp:
        return resp.read()


def rows(name, raw, path):
    if path.endswith(".parquet"):
        table = pq.read_table(io.BytesIO(raw)).to_pylist()
    else:
        csv.field_size_limit(sys.maxsize)
        table = list(csv.DictReader(io.StringIO(raw.decode("utf-8"))))
    if name == "deepset":
        return [(r["text"], int(r["label"])) for r in table]
    if name == "jackhhao":
        return [(r["prompt"], int(r["type"] == "jailbreak")) for r in table]
    if name == "gandalf":
        # Attacks only: people trying to make Gandalf reveal its password.
        return [(r["text"], 1) for r in table]
    if name == "spml":
        picked = random.Random(7).sample(table, SPML_SAMPLE)
        return [(r["User Prompt"], int(r["Prompt injection"])) for r in picked]
    raise ValueError(name)


def main():
    DATA.mkdir(exist_ok=True)
    manifest = []
    with open(DATA / "injection.jsonl", "w", encoding="utf-8") as out:
        for name, dataset, revision, path, licence in SOURCES:
            items = [(t, l) for t, l in rows(name, download(dataset, revision, path), path) if t and t.strip()]
            for text, label in items:
                out.write(json.dumps({"text": text, "label": label, "set": name}, ensure_ascii=False) + "\n")
            attacks = sum(l for _, l in items)
            manifest.append({"set": name, "dataset": dataset, "revision": revision, "file": path,
                             "licence": licence, "attacks": attacks, "benign": len(items) - attacks})
            print(f"{name}: {attacks} attacks, {len(items) - attacks} benign")
    (DATA / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
