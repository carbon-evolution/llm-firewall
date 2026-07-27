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
- **How to fetch:** run `./scripts/fetch-model.sh` (plain resumable `curl`, no HF CLI or
  auth required for this open model, ~703 MB fp32). If the primary host throttles,
  re-run with a mirror: `HF_HOST=https://hf-mirror.com ./scripts/fetch-model.sh`.
