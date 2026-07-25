# Injection classifier model card

- **Model:** `protectai/deberta-v3-base-prompt-injection-v2` (or any BERT/DeBERTa
  sequence classifier with labels `{0: SAFE, 1: INJECTION}`).
- **Source:** Hugging Face; fetched by `scripts/fetch-model.sh`.
- **License:** verify the upstream model license before redistribution; we do NOT
  vendor weights in git except via LFS with the upstream license noted here.
- **Runtime:** loaded by `candle` from `config.json` + `model.safetensors` +
  `tokenizer.json` under `models/injection/`.
- **Label convention:** index 1 = injection; `predict()` returns `P(injection)`.
- **Prerequisites to fetch (manual):** install git-lfs (`brew install git-lfs && git lfs install`)
  and the HF CLI (`pip install "huggingface_hub[cli]"`), then run `./scripts/fetch-model.sh`.
