#!/usr/bin/env bash
# Fetch the prompt-injection classifier into models/injection/.
#
# Downloads config.json + tokenizer.json + model.safetensors with plain curl
# (resumable, no huggingface CLI, no auth needed for this open model). If the
# primary host is slow/throttled, set HF_HOST=https://hf-mirror.com for a mirror.
set -euo pipefail

MODEL_REPO="${MODEL_REPO:-protectai/deberta-v3-base-prompt-injection-v2}"
DEST="${DEST:-models/injection}"
HF_HOST="${HF_HOST:-https://huggingface.co}"

mkdir -p "$DEST"
echo "Fetching $MODEL_REPO from $HF_HOST -> $DEST"

for f in config.json tokenizer.json model.safetensors; do
  echo "  - $f"
  curl -L -C - --retry 8 --retry-delay 3 --fail \
    -o "$DEST/$f" \
    "$HF_HOST/$MODEL_REPO/resolve/main/$f"
done

echo "Done. Files:"
ls -la "$DEST"
