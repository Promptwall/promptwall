"""Runs the accuracy benchmark: starts Promptwall with its check API, sends
every text of benchmark/data through it, and writes the results to
benchmark/results/accuracy.json (and a summary to stdout).

    python benchmark/fetch.py && python benchmark/german_set.py && python benchmark/dlp_set.py
    cargo build --release -p promptwall
    cargo build --release -p promptwall-classify --example classify_scores
    python benchmark/run.py [--injection-model DIR]

Without --injection-model only the patterns (Tier 1) are measured; with it,
also patterns plus the classifier (Tier 2) at threshold 0.5 through the
firewall, a threshold sweep at fixed false-alarm rates (thresholds chosen on
the dev split, results on the test split), and long documents scored on
their last 8 windows (today's limit) and on all windows. Only the standard
library is used.
"""

import argparse
import json
import os
import platform
import socket
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
POLICIES = ROOT / "policies"
RESULTS = ROOT / "results"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Server:
    """A Promptwall process with the check API on a free local port."""

    def __init__(self, binary, policy, extra=()):
        self.url = f"http://127.0.0.1:{free_port()}"
        args = [binary, "--listen", self.url[7:], "--policy", str(policy), "--check-api", *extra]
        env = {**os.environ, "RUST_LOG": "warn"}
        self.proc = subprocess.Popen(args, env=env)
        for _ in range(600):
            try:
                urllib.request.urlopen(self.url + "/healthz", timeout=1)
                return
            except OSError:
                if self.proc.poll() is not None:
                    sys.exit(f"promptwall exited with {self.proc.returncode}")
                time.sleep(0.1)
        sys.exit("promptwall did not start")

    def check(self, text, route):
        body = json.dumps({"route": route, "text": text}).encode()
        req = urllib.request.Request(self.url + "/promptwall/v1/check", body, {"content-type": "application/json"})
        start = time.perf_counter()
        with urllib.request.urlopen(req, timeout=60) as resp:
            out = json.load(resp)
        out["ms"] = (time.perf_counter() - start) * 1000
        return out

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.proc.terminate()
        self.proc.wait()


def load(name):
    with open(DATA / name, encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def run_all(server, rows, route, workers):
    with ThreadPoolExecutor(workers) as pool:
        return list(pool.map(lambda r: server.check(r["text"], route), rows))


def pct(n, d):
    return round(100 * n / d, 1) if d else None


def latency(results):
    ms = sorted(r["ms"] for r in results)
    return {"p50_ms": round(statistics.median(ms), 2), "p95_ms": round(ms[int(0.95 * (len(ms) - 1))], 2)}


def rates(rows, hits):
    """Detection and false-alarm rate of `hits` (one bool per row)."""
    s = {"attacks": 0, "caught": 0, "benign": 0, "false_alarms": 0}
    for row, hit in zip(rows, hits):
        if row["label"] == 1:
            s["attacks"] += 1
            s["caught"] += hit
        else:
            s["benign"] += 1
            s["false_alarms"] += hit
    return {**s, "detection_rate": pct(s["caught"], s["attacks"]),
            "false_positive_rate": pct(s["false_alarms"], s["benign"])}


def by(rows, values, key):
    groups = defaultdict(lambda: ([], []))
    for row, v in zip(rows, values):
        groups[key(row)][0].append(row)
        groups[key(row)][1].append(v)
    return dict(sorted(groups.items()))


def injection(server, rows):
    """Detection rate and false-positive rate for each dataset, and for each
    language where a set has more than one. Returns the hits as well."""
    results = run_all(server, rows, "injection", workers=1)
    hits = [r["action"] == "block" for r in results]
    out = {}
    for name, (rs, hs) in by(rows, hits, lambda r: r["set"]).items():
        out[name] = rates(rs, hs)
        langs = by(rs, hs, lambda r: r.get("lang", "en"))
        if len(langs) > 1:
            out[name]["by_language"] = {lang: rates(*v) for lang, v in langs.items() if len(v[0]) >= 10}
        out[name]["false_alarm_examples"] = [r["text"][:160] for r, h in zip(rs, hs) if h and r["label"] == 0][:5]
    return out, latency(results), hits


# Sets whose harmless prompts decide the thresholds at a fixed false-alarm rate:
# ordinary prompts, not the app-specific SPML ones or documents (BIPIA, long
# documents), which are reported at the same thresholds.
CALIBRATION_SETS = {"deepset", "jackhhao", "notinject", "german"}
TARGET_FPR = [0.5, 1.0, 2.0]


def average_precision(labels, scores):
    pairs = sorted(zip(scores, labels), key=lambda p: -p[0])
    positives = sum(labels)
    if not positives:
        return None
    tp, total = 0, 0.0
    for k, (_, label) in enumerate(pairs, 1):
        if label:
            tp += 1
            total += tp / k
    return round(100 * total / positives, 1)


def sweep(rows, tier1, scores):
    """Patterns or classifier at the threshold that keeps false alarms at 0.5%,
    1% and 2% on the dev split's harmless prompts; results on the test split."""
    combined = [max(float(t), s) for t, s in zip(tier1, scores)]
    benign_dev = sorted((c for r, c in zip(rows, combined)
                         if r["split"] == "dev" and r["label"] == 0 and r["set"] in CALIBRATION_SETS), reverse=True)
    thresholds = {}
    for target in TARGET_FPR:
        allowed = int(len(benign_dev) * target / 100)
        # The lowest threshold that flags no more than `allowed` harmless dev prompts.
        t = benign_dev[allowed] + 1e-6 if allowed < len(benign_dev) else 0.0
        thresholds[f"{target}%"] = round(min(t, 1.0), 6)
    test = [(r, c) for r, c in zip(rows, combined) if r["split"] == "test"]
    out = {"thresholds": thresholds, "calibration": {"sets": sorted(CALIBRATION_SETS), "harmless_dev_prompts": len(benign_dev)},
           "test": {}}
    groups = by([r for r, _ in test], [c for _, c in test], lambda r: r["set"])
    for name, (rs, cs) in groups.items():
        entry = {"pr_auc": average_precision([r["label"] for r in rs], cs)}
        for label, t in thresholds.items():
            entry[f"at {label} false alarms"] = rates(rs, [c >= t for c in cs])
        langs = by(rs, cs, lambda r: r.get("lang", "en"))
        if len(langs) > 1:
            t = thresholds["1.0%"]
            entry["by_language at 1.0%"] = {lang: rates(lr, [c >= t for c in lc])
                                            for lang, (lr, lc) in langs.items() if len(lr) >= 10}
        out["test"][name] = entry
    return out


def long_documents(rows, tier1, scores_tail, scores_all, thresholds=(0.5, 0.9, 0.99)):
    """Long documents by planted position, scoring only the last 8 windows
    (what the firewall does today) and scoring every window, at several
    thresholds: with many windows per document, false alarms add up."""
    out = {}
    for name, scores in (("last 8 windows", scores_tail), ("all windows", scores_all)):
        for t in thresholds:
            hits = [t1 or s >= t for t1, s in zip(tier1, scores)]
            entry = {"all": rates(rows, hits)}
            for pos, (rs, hs) in by(rows, hits, lambda r: r["position"] or "none").items():
                entry[pos] = rates(rs, hs)
            for tokens, (rs, hs) in by(rows, hits, lambda r: r["tokens"]).items():
                entry[f"{tokens} tokens"] = rates(rs, hs)
            out[f"{name}, threshold {t}"] = entry
    return out


def classifier_scores(binary, model, rows, all_windows=False):
    """Raw classifier scores for `rows`, from the classify_scores example."""
    with tempfile.TemporaryDirectory() as tmp:
        src, dst = Path(tmp) / "in.jsonl", Path(tmp) / "out.jsonl"
        src.write_text("".join(json.dumps({"text": r["text"]}, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
        subprocess.run([binary, model, str(src), str(dst), *(["--all"] if all_windows else [])], check=True)
        out = [json.loads(line) for line in dst.read_text().splitlines()]
    return [o["score"] for o in out], [o["ms"] for o in out]


def dlp(server, rows, benign_prompts):
    """Per entity: found with the right label, value fully removed; look-alikes
    and real benign prompts that should produce nothing."""
    results = run_all(server, rows, "dlp", workers=4)
    per = defaultdict(lambda: {"values": 0, "found": 0, "redacted": 0})
    wrong_label = defaultdict(int)
    look_alikes, look_alike_hits, misses, false_alarms = 0, 0, [], []
    for row, r in zip(rows, results):
        findings = r.get("findings") or {}
        if row["label"] is None:
            look_alikes += 1
            if findings:
                look_alike_hits += 1
                false_alarms.append({"text": row["text"][:160], "findings": findings})
            continue
        p = per[row["label"]]
        p["values"] += 1
        if row["label"] in findings:
            p["found"] += 1
            if row["value"] not in r.get("text", row["text"]) and r["action"] in ("redact", "block"):
                p["redacted"] += 1
        else:
            if findings:
                wrong_label[row["label"]] += 1
            if len(misses) < 20:
                misses.append({"label": row["label"], "text": row["text"][:160], "findings": findings})
    entities = {
        label: {**p, "recall": pct(p["found"], p["values"]), "wrong_label": wrong_label[label]}
        for label, p in sorted(per.items())
    }
    # Real prompts with no personal data or secrets in them (the benign side of
    # the injection sets): anything found there is very likely a false alarm.
    real = run_all(server, benign_prompts, "dlp", workers=4)
    real_hits = [
        {"text": row["text"][:160], "findings": r["findings"]}
        for row, r in zip(benign_prompts, real)
        if r.get("findings")
    ]
    total = sum(p["values"] for p in per.values())
    return {
        "values": total,
        "found": sum(p["found"] for p in per.values()),
        "recall": pct(sum(p["found"] for p in per.values()), total),
        "redacted": pct(sum(p["redacted"] for p in per.values()), total),
        "look_alikes": look_alikes,
        "look_alike_false_alarms": look_alike_hits,
        "benign_prompts": len(benign_prompts),
        "benign_prompts_flagged": len(real_hits),
        "entities": entities,
        "misses": misses,
        "false_alarms": false_alarms + real_hits[:20],
    }, latency(results)


def main():
    ap = argparse.ArgumentParser()
    release = ROOT.parent / "target" / "release"
    exe = ".exe" if os.name == "nt" else ""
    ap.add_argument("--binary", default=str(release / f"promptwall{exe}"))
    ap.add_argument("--scores-binary", default=str(release / "examples" / f"classify_scores{exe}"),
                    help="build with: cargo build --release -p promptwall-classify --example classify_scores")
    ap.add_argument("--injection-model", help="directory of the prompt-injection classifier (Tier 2)")
    ap.add_argument("--model-name", default="Horizon-Labs/prompt-injection-guard-small (int8)")
    args = ap.parse_args()

    inj, dlp_rows = load("injection.jsonl"), load("dlp.jsonl")
    if (DATA / "german.jsonl").exists():
        inj += load("german.jsonl")
    docs = load("longdocs.jsonl") if (DATA / "longdocs.jsonl").exists() else []
    benign = [r for r in inj if r["label"] == 0 and r["set"] not in ("bipia",)]
    setups = {}
    with Server(args.binary, POLICIES / "patterns.yaml") as s:
        inj_res, inj_lat, tier1 = injection(s, inj)
        doc_res, _, doc_tier1 = injection(s, docs) if docs else ({}, None, [])
        dlp_res, dlp_lat = dlp(s, dlp_rows, benign)
        setups["patterns"] = {"injection": {**inj_res, **doc_res}, "dlp": dlp_res,
                              "latency": {"injection": inj_lat, "dlp": dlp_lat}}
    if args.injection_model:
        extra = ["--injection-model", args.injection_model]
        with Server(args.binary, POLICIES / "classifier.yaml", extra) as s:
            inj_res, inj_lat, _ = injection(s, inj)
            setups["patterns+classifier"] = {"injection": inj_res, "model": args.model_name, "latency": {"injection": inj_lat}}
        scores, _ = classifier_scores(args.scores_binary, args.injection_model, inj)
        setups["patterns+classifier"]["sweep"] = sweep(inj, tier1, scores)
        if docs:
            tail, _ = classifier_scores(args.scores_binary, args.injection_model, docs)
            full, _ = classifier_scores(args.scores_binary, args.injection_model, docs, all_windows=True)
            setups["patterns+classifier"]["long_documents"] = long_documents(docs, doc_tier1, tail, full)

    RESULTS.mkdir(exist_ok=True)
    version = subprocess.run([args.binary, "--version"], capture_output=True, text=True).stdout.strip()
    out = {
        "promptwall": version,
        "date": time.strftime("%Y-%m-%d"),
        "machine": f"{platform.system()} {platform.machine()}, {os.cpu_count()} CPUs",
        "datasets": json.loads((DATA / "manifest.json").read_text()),
        "setups": setups,
    }
    (RESULTS / "accuracy.json").write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    for name, setup in setups.items():
        print(f"\n{name}")
        for ds, r in setup["injection"].items():
            print(f"  {ds:<12} caught {r['detection_rate']}% of {r['attacks']}, false alarms {r['false_positive_rate']}% of {r['benign']}")
            for lang, l in r.get("by_language", {}).items():
                print(f"    {lang}: caught {l['detection_rate']}% of {l['attacks']}, false alarms {l['false_positive_rate']}% of {l['benign']}")
        print(f"  check latency p50 {setup['latency']['injection']['p50_ms']} ms, p95 {setup['latency']['injection']['p95_ms']} ms")
        if "sweep" in setup:
            sw = setup["sweep"]
            print(f"  thresholds for 0.5/1/2% false alarms on dev: {list(sw['thresholds'].values())}")
            for ds, e in sw["test"].items():
                cells = "  ".join(f"{k.split()[1]}: {v['detection_rate']}%/{v['false_positive_rate']}%"
                                  for k, v in e.items() if k.startswith("at "))
                print(f"    test {ds:<10} PR-AUC {e['pr_auc']}  {cells}")
        for kind, e in setup.get("long_documents", {}).items():
            print(f"  long documents, {kind}: caught {e['all']['detection_rate']}%, false alarms {e['all']['false_positive_rate']}%")
        if "dlp" in setup:
            d = setup["dlp"]
            print(f"  dlp: found {d['recall']}% of {d['values']} values, fully redacted {d['redacted']}%, "
                  f"look-alikes flagged {d['look_alike_false_alarms']}/{d['look_alikes']}, "
                  f"real benign prompts flagged {d['benign_prompts_flagged']}/{d['benign_prompts']}")
            for label, e in d["entities"].items():
                if e["recall"] < 100:
                    print(f"    {label:<28} {e['recall']}% ({e['found']}/{e['values']})")


if __name__ == "__main__":
    main()
