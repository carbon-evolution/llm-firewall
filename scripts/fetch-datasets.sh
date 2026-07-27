#!/usr/bin/env bash
# Download standardized benchmark corpora and normalize to datasets/*.jsonl
# ({"text","label"} where label=true means malicious/attack).
#
# Uses the Hugging Face datasets-server REST API (JSON) via the Python standard
# library only -- no `pip install datasets`, no pyarrow, no network auth.
set -euo pipefail
mkdir -p datasets

python3 - <<'PY'
import json, urllib.request, urllib.parse, time

def fetch_split(dataset, config, split):
    rows, offset = [], 0
    while True:
        q = urllib.parse.urlencode(
            {"dataset": dataset, "config": config, "split": split,
             "offset": offset, "length": 100})
        url = "https://datasets-server.huggingface.co/rows?" + q
        with urllib.request.urlopen(url, timeout=30) as r:
            d = json.load(r)
        batch = d.get("rows", [])
        if not batch:
            break
        rows += [item["row"] for item in batch]
        total = d.get("num_rows_total", 0)
        offset += len(batch)
        if offset >= total:
            break
        time.sleep(0.2)
    return rows

def dump(pairs, path):
    with open(path, "w") as f:
        for text, label in pairs:
            f.write(json.dumps({"text": text, "label": bool(label)}) + "\n")
    n_mal = sum(1 for _, l in pairs if l)
    print(f"wrote {path}: {len(pairs)} rows ({n_mal} malicious / {len(pairs)-n_mal} benign)")

# deepset/prompt-injections -- label 1 = injection, 0 = benign.
# Both train and test splits carry both classes, so this single corpus yields
# BOTH the malicious-accuracy (recall) and the over-defense (FPR) metrics.
pairs = []
for split in ("train", "test"):
    for row in fetch_split("deepset/prompt-injections", "default", split):
        pairs.append((row["text"], int(row["label"]) == 1))
dump(pairs, "datasets/deepset_injection.jsonl")
PY
echo "Datasets ready in ./datasets"
