# Model cards

## Injection classifier

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
- **How to fetch:** run `./scripts/fetch-model.sh injection` (plain resumable `curl`, no
  HF CLI or auth required, ~703 MB fp32). If the primary host throttles, re-run with a
  mirror: `HF_HOST=https://hf-mirror.com ./scripts/fetch-model.sh`.

## Content-moderation classifier (Trust & Safety)

- **Model:** `domenicrosati/deberta-v3-xsmall-beavertails-harmful-qa-classifier` — a
  DeBERTa-v3 binary harmful-request classifier trained on BeaverTails (~283 MB fp32).
  Any DeBERTa-v2/v3 sequence classifier works; the runtime reads labels from `config.json`
  `id2label` when present, else you pass them (`load_with_labels`).
- **Label convention:** this checkpoint omits `id2label`; we load it with labels
  `["harmful", "safe"]` (**index 0 = harmful**, verified empirically). The detector applies
  a sigmoid per label, ignores "safe"-type labels, and flags the top harmful category at/
  above its threshold (default 0.5).
- **Scope & limits:** detects *harmful content / harmful requests* (a Trust & Safety
  control, distinct from prompt injection). It is NOT a full safety system and makes **no
  claim** to detect illegal material such as CSAM (which requires specialized hash-matching).
  A multi-category toxicity model (e.g. `duanyu027/moderation_0703_deberta_v3_small`, OpenAI
  taxonomy) is a drop-in alternative — set `MODERATION_REPO` and load its `id2label`.
- **How to fetch:** `./scripts/fetch-model.sh moderation` -> `models/moderation/`.
