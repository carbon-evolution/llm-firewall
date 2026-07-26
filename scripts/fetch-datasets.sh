#!/usr/bin/env bash
# Download standardized benchmark corpora and normalize to datasets/*.jsonl
# ({"text","label"} where label=true means malicious/attack).
# Requires: pip install datasets
set -euo pipefail
mkdir -p datasets

python3 - <<'PY'
from datasets import load_dataset
import json, os

def dump(rows, path):
    with open(path, "w") as f:
        for text, label in rows:
            f.write(json.dumps({"text": text, "label": bool(label)}) + "\n")
    print(f"wrote {path} ({len(rows)} rows)")

# A. Malicious detection — deepset/prompt-injections (label 1 = injection)
ds = load_dataset("deepset/prompt-injections", split="test")
dump([(r["text"], int(r["label"]) == 1) for r in ds], "datasets/deepset_injection.jsonl")

# B. Over-defense / FPR — NotInject (all benign; label = False)
try:
    nj = load_dataset("SaFoLab-WISC/NotInject", split="train")
    dump([(r.get("text") or r.get("prompt"), False) for r in nj], "datasets/notinject_benign.jsonl")
except Exception as e:
    print("NotInject fetch skipped:", e)

# C. Jailbreak — JailbreakBench behaviors (label = True)
try:
    jb = load_dataset("JailbreakBench/JBB-Behaviors", "behaviors", split="harmful")
    dump([(r["Goal"], True) for r in jb], "datasets/jailbreakbench.jsonl")
except Exception as e:
    print("JailbreakBench fetch skipped:", e)
PY
echo "Datasets ready in ./datasets"
