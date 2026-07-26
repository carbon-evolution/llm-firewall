# Injection classifier model card

- **Model:** `protectai/deberta-v3-base-prompt-injection-v2` (or any **DeBERTa-v2/v3**
  sequence classifier with labels `{0: SAFE, 1: INJECTION}`). The runtime uses candle's
  `DebertaV2SeqClassificationModel`, so the checkpoint must be a DeBERTa-v2/v3
  architecture (not plain BERT). Meta `Prompt-Guard`, deepset injection models also fit.
- **Source:** Hugging Face; fetched by `scripts/fetch-model.sh`.
- **License:** verify the upstream model license before redistribution; we do NOT
  vendor weights in git except via LFS with the upstream license noted here.
- **Runtime:** loaded by `candle` from `config.json` + `model.safetensors` +
  `tokenizer.json` under `models/injection/`. **`config.json` must contain `id2label`**
  (candle reads the label count from it); a `tokenizer.json` (fast tokenizer) is required.
- **Label convention:** index 1 = injection; `predict()` runs softmax over the logits
  and returns `P(injection)`.
- **Prerequisites to fetch (manual):** install git-lfs (`brew install git-lfs && git lfs install`)
  and the HF CLI (`pip install "huggingface_hub[cli]"`), then run `./scripts/fetch-model.sh`.
