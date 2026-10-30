"""Runs the accuracy benchmark: starts Promptwall with its check API, sends
every text of benchmark/data through it, and writes the results to
benchmark/results/accuracy.json (and a summary to stdout).

    python benchmark/fetch.py && python benchmark/dlp_set.py
    cargo build --release -p promptwall
    python benchmark/run.py [--injection-model DIR]

Without --injection-model only the patterns (Tier 1) are measured; with it,
also patterns plus the classifier (Tier 2). Only the standard library is used.
"""

import argparse
import json
import os
import platform
import socket
import statistics
import subprocess
import sys
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


def injection(server, rows):
    """Detection rate and false-positive rate for each dataset."""
    results = run_all(server, rows, "injection", workers=1)
    by_set = defaultdict(lambda: {"attacks": 0, "caught": 0, "benign": 0, "false_alarms": 0})
    examples = defaultdict(list)
    for row, r in zip(rows, results):
        s = by_set[row["set"]]
        hit = r["action"] == "block"
        if row["label"] == 1:
            s["attacks"] += 1
            s["caught"] += hit
        else:
            s["benign"] += 1
            s["false_alarms"] += hit
            if hit and len(examples[row["set"]]) < 5:
                examples[row["set"]].append(row["text"][:160])
    out = {}
    for name, s in sorted(by_set.items()):
        out[name] = {
            **s,
            "detection_rate": pct(s["caught"], s["attacks"]),
            "false_positive_rate": pct(s["false_alarms"], s["benign"]),
            "false_alarm_examples": examples[name],
        }
    return out, latency(results)


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
    ap.add_argument("--binary", default=str(ROOT.parent / "target" / "release" / ("promptwall.exe" if os.name == "nt" else "promptwall")))
    ap.add_argument("--injection-model", help="directory of the prompt-injection classifier (Tier 2)")
    ap.add_argument("--model-name", default="Horizon-Labs/prompt-injection-guard-small (int8)")
    args = ap.parse_args()

    inj, dlp_rows = load("injection.jsonl"), load("dlp.jsonl")
    benign = [r for r in inj if r["label"] == 0]
    setups = {}
    with Server(args.binary, POLICIES / "patterns.yaml") as s:
        inj_res, inj_lat = injection(s, inj)
        dlp_res, dlp_lat = dlp(s, dlp_rows, benign)
        setups["patterns"] = {"injection": inj_res, "dlp": dlp_res, "latency": {"injection": inj_lat, "dlp": dlp_lat}}
    if args.injection_model:
        extra = ["--injection-model", args.injection_model]
        with Server(args.binary, POLICIES / "classifier.yaml", extra) as s:
            inj_res, inj_lat = injection(s, inj)
            setups["patterns+classifier"] = {"injection": inj_res, "model": args.model_name, "latency": {"injection": inj_lat}}

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
            print(f"  {ds:<40} caught {r['detection_rate']}% of {r['attacks']}, false alarms {r['false_positive_rate']}% of {r['benign']}")
        print(f"  check latency p50 {setup['latency']['injection']['p50_ms']} ms, p95 {setup['latency']['injection']['p95_ms']} ms")
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
