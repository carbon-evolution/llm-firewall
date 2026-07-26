#!/usr/bin/env bash
# Fetch the prompt-injection classifier into models/injection/.
# Default model: an open BERT-family injection classifier exported to safetensors.
set -euo pipefail

MODEL_REPO="${MODEL_REPO:-protectai/deberta-v3-base-prompt-injection-v2}"
DEST="${DEST:-models/injection}"

mkdir -p "$DEST"
echo "Fetching $MODEL_REPO -> $DEST"

# Requires: pip install "huggingface_hub[cli]"
hf download "$MODEL_REPO" \
  config.json model.safetensors tokenizer.json \
  --local-dir "$DEST"

echo "Done. Files:"
ls -la "$DEST"
