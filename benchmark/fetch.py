"""Downloads the public datasets of the accuracy benchmark, pinned to exact
revisions, into benchmark/data/ as JSON lines.

    pip install -r benchmark/requirements.txt
    python benchmark/fetch.py
    python benchmark/german_set.py     # our own German set (no download)

benchmark/data/injection.jsonl gets one row per prompt:
    {"text", "label", "set", "split", "lang", "context"?, "kind"?}
label 1 is an attack and 0 an ordinary prompt. split is "dev" (for choosing
thresholds and tuning) or "test" (for published numbers); it is fixed by a
hash of the text, or of the system prompt for SPML, so the same row always
lands in the same split. lang is "de" or "en". context is the app's system
prompt where the dataset has one (SPML).

benchmark/data/longdocs.jsonl gets long documents (4k to 32k tokens) built
from BIPIA's clean emails and tables, with and without one planted attack at
the start, middle or end. It tests that an attack anywhere in a long
retrieved document is found.
"""

import csv
import hashlib
import io
import json
import random
import re
import sys
import urllib.request
from pathlib import Path

import pyarrow.parquet as pq

DATA = Path(__file__).parent / "data"

# (name, Hugging Face dataset, revision, files, licence)
SOURCES = [
    ("deepset", "deepset/prompt-injections", "4f61ecb038e9c3fb77e21034b22511b523772cdd",
     ["data/test-00000-of-00001-701d16158af87368.parquet"], "Apache-2.0"),
    ("jackhhao", "jackhhao/jailbreak-classification", "2f2ceeb39658696fd3f462403562b6eea5306287",
     ["default/jailbreak_dataset_test.csv"], "Apache-2.0"),
    ("gandalf", "Lakera/gandalf_ignore_instructions", "04737b65e90a6794ec227012e4a255a7def6344b",
     ["data/test-00000-of-00001-bc92128b9288a6d1.parquet"], "MIT"),
    ("spml", "reshabhs/SPML_Chatbot_Prompt_Injection", "02ce8084e979bc7d4c24ee35d22ecb7f2db96ff5",
     ["spml_prompt_injection.csv"], "MIT"),
    ("notinject", "leolee99/NotInject", "847ae76cf8fea5ed325429e569ae8cfef022d2e0",
     ["data/NotInject_one-00000-of-00001.parquet", "data/NotInject_two-00000-of-00001.parquet",
      "data/NotInject_three-00000-of-00001.parquet"], "MIT"),
    ("bipia", "geodesic-research/bipia", "003f58372e1696726b7cddde274a74bee0b1938a",
     ["bipia/train-00000-of-00001.parquet"], "CC-BY-SA-4.0"),
]
# SPML has 16,000 rows and BIPIA 41,250; fixed samples keep a run short.
SPML_SAMPLE = 1000
BIPIA_ATTACKS = 500
# Long documents: lengths in tokens (about 4 characters each) and how many of each.
LONG_LENGTHS = [4_000, 8_000, 16_000, 32_000]
LONG_PER_LENGTH = 32

# Common German words that are rare in English, to tell deepset's two languages apart.
GERMAN = set("der die das und ist nicht ich du sie wir ihr ein eine einen mit auf für "
             "von zu den dem des sich auch wie was wer wo bitte jetzt alle alles oder "
             "aber wenn dass mir mich dir dich habe hast hat sind wird werden kann "
             "können über nach bei aus noch nur sehr gibt mein meine dein deine".split())
ENGLISH = set("the and is are not you we they a an with on for of to in it this that what how who "
              "please now all or but if your my have has be will can about after from only very".split())


def download(dataset, revision, path):
    url = f"https://huggingface.co/datasets/{dataset}/resolve/{revision}/{path}"
    with urllib.request.urlopen(url, timeout=120) as resp:
        return resp.read()


def table(raw, path):
    if path.endswith(".parquet"):
        return pq.read_table(io.BytesIO(raw)).to_pylist()
    csv.field_size_limit(sys.maxsize)
    return list(csv.DictReader(io.StringIO(raw.decode("utf-8"))))


def split_of(key):
    return "dev" if hashlib.sha1(key.encode()).digest()[0] % 2 == 0 else "test"


def lang_of(text):
    words = re.findall(r"[a-zäöüß]+", text.lower())
    if not words:
        return "en"
    german = sum(w in GERMAN for w in words)
    english = sum(w in ENGLISH for w in words)
    german += sum(bool(re.search(r"[äöüß]", w) or (len(w) >= 6 and re.search(r"(ung|keit|heit|lich|schaft)$", w))) for w in words)
    return "de" if german > english else "en"


def row(text, label, name, **extra):
    return {"text": text, "label": label, "set": name, "split": split_of(text), "lang": lang_of(text), **extra}


def rows(name, tables):
    t = [r for part in tables for r in part]
    if name == "deepset":
        return [row(r["text"], int(r["label"]), name) for r in t]
    if name == "jackhhao":
        return [row(r["prompt"], int(r["type"] == "jailbreak"), name) for r in t]
    if name == "gandalf":
        # Attacks only: people trying to make Gandalf reveal its password.
        return [row(r["text"], 1, name) for r in t]
    if name == "spml":
        picked = random.Random(7).sample(t, SPML_SAMPLE)
        # Split by system prompt, so the test split holds apps never seen in dev.
        return [{**row(r["User Prompt"], int(r["Prompt injection"]), name),
                 "split": split_of(r["System Prompt"]), "context": r["System Prompt"]} for r in picked]
    if name == "notinject":
        # Harmless prompts full of words that attacks use ("ignore", "bypass").
        return [row(r["prompt"], 0, name, kind=r["category"]) for r in t]
    if name == "bipia":
        return bipia(t)
    raise ValueError(name)


def clean_context(r):
    return re.sub(r"\n{3,}", "\n\n", r["context"].replace(r["attack_str"], "")).strip()


def bipia(t):
    """Emails, tables and code with an instruction planted in them (attacks),
    and the same texts with the instruction taken out (harmless)."""
    rnd = random.Random(11)
    attacks = rnd.sample(t, BIPIA_ATTACKS)
    clean = sorted({clean_context(r) for r in t})
    harmless = rnd.sample(clean, min(len(clean), BIPIA_ATTACKS))
    out = [row(r["context"], 1, "bipia", kind=f"{r['task_name']}/{r['attack_category']}/{r['position']}")
           for r in attacks]
    out += [row(text, 0, "bipia", kind="clean") for text in harmless]
    # Split by the clean document, so an attacked text and its clean twin share a split.
    for r, src in zip(out, attacks):
        r["split"] = split_of(clean_context(src))
    for r in out[len(attacks):]:
        r["split"] = split_of(r["text"])
    return out


def long_documents(bipia_table, german_attacks):
    """Long retrieved documents made of many clean BIPIA texts, with one attack
    planted at the start, middle or end (label 1), or none (label 0)."""
    rnd = random.Random(13)
    clean = sorted({clean_context(r) for r in bipia_table})
    english = sorted({r["attack_str"] for r in bipia_table if r["attack_category"] != "code"})
    out = []
    for tokens in LONG_LENGTHS:
        for i in range(LONG_PER_LENGTH):
            parts, size = [], 0
            while size < tokens * 4:
                p = rnd.choice(clean)
                parts.append(p)
                size += len(p) + 2
            # Three in four documents carry an attack, in turn at the start,
            # middle and end; every other group of four plants a German one.
            position = ["start", "middle", "end", None][i % 4]
            attack = position is not None
            lang = "de" if attack and (i // 4) % 2 and german_attacks else "en"
            if attack:
                planted = rnd.choice(german_attacks if lang == "de" else english)
                at = {"start": 1, "middle": len(parts) // 2, "end": len(parts) - 1}[position]
                parts.insert(at, planted)
            text = "\n\n".join(parts)
            key = f"{tokens}-{i}"
            out.append({"text": text, "label": int(attack), "set": "longdocs", "split": split_of(key),
                        "lang": lang, "tokens": tokens, "position": position})
    return out


def main():
    DATA.mkdir(exist_ok=True)
    manifest, raw_tables = [], {}
    with open(DATA / "injection.jsonl", "w", encoding="utf-8") as out:
        for name, dataset, revision, paths, licence in SOURCES:
            tables = [table(download(dataset, revision, p), p) for p in paths]
            raw_tables[name] = [r for part in tables for r in part]
            items = [r for r in rows(name, tables) if r["text"] and r["text"].strip()]
            for r in items:
                out.write(json.dumps(r, ensure_ascii=False) + "\n")
            attacks = sum(r["label"] for r in items)
            manifest.append({"set": name, "dataset": dataset, "revision": revision, "files": paths,
                             "licence": licence, "attacks": attacks, "benign": len(items) - attacks})
            print(f"{name}: {attacks} attacks, {len(items) - attacks} benign")

    # German attacks for planting come from german_set.py, written for this project.
    sys.path.insert(0, str(Path(__file__).parent))
    from german_set import ATTACKS
    german = ATTACKS["indirect"] + ATTACKS["hijack"]
    docs = long_documents(raw_tables["bipia"], german)
    with open(DATA / "longdocs.jsonl", "w", encoding="utf-8") as out:
        for d in docs:
            out.write(json.dumps(d, ensure_ascii=False) + "\n")
    attacks = sum(d["label"] for d in docs)
    manifest.append({"set": "longdocs", "dataset": "built from geodesic-research/bipia and benchmark/german_set.py",
                     "licence": "CC-BY-SA-4.0", "attacks": attacks, "benign": len(docs) - attacks})
    print(f"longdocs: {attacks} attacks, {len(docs) - attacks} benign")
    (DATA / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
