# LLM Firewall

A pure-Rust **firewall for LLMs** — a drop-in, OpenAI-compatible reverse proxy that inspects, scores,
and filters the prompts and responses flowing between your app and an LLM (GPT/Claude). Point your
app at it instead of `api.openai.com` and every request is checked, scored, and logged — no app
changes required.

![CI](https://github.com/carbon-evolution/llm-firewall/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-Apache--2.0-blue)

## What it does

- **Prompt-injection / jailbreak detection** — a 3-stage detector (regex signatures → heuristics →
  optional pure-Rust ML classifier).
- **Secret detection** — AWS/GitHub/Slack tokens, JWTs, private keys, plus a high-entropy gate.
- **PII detection + masking** — emails, SSNs, IPs, Luhn-validated credit cards, redacted to typed
  tokens (e.g. `‹EMAIL›`).
- **Risk score (0–100)** — a weighted, diminishing-returns aggregate of all findings.
- **Policy engine** — a flat, first-match YAML rule set: `allow` / `mask` / `block` / `flag`, scoped
  by direction (input vs. output).
- **Response scanning + streaming** — inspects model output too, including SSE token streams
  (verbatim byte passthrough with a sliding-window scan).
- **Structured audit log** — one JSON line per request (decision, score, reasons, latency).

## How it works

```
      Your app
         │  (points its base_url here instead of api.openai.com)
         ▼
   ┌─────────────────────────────┐
   │        LLM Firewall         │
   │  input:  inject/PII/secret  │
   │          → score → policy   │
   │          → block / mask     │
   │  forward (with your API key)│
   │  output: leak scan          │
   └─────────────────────────────┘
         │
         ▼
      OpenAI / Claude
```

## Quickstart

### Docker
```bash
docker build -f deploy/Dockerfile -t llm-firewall .
docker run -p 8080:8080 -e LLM_FW_OPENAI_BASE=https://api.openai.com llm-firewall
```
Then point your OpenAI client's base URL at `http://localhost:8080/v1`. Your `Authorization: Bearer`
key is forwarded upstream.

### From source
```bash
cargo run -p llm-firewall     # reads ./firewall.yaml + ./policies/default.yaml
```

Kubernetes sidecar: see `deploy/k8s-sidecar.yaml` (app talks to `localhost:8080`, firewall egresses
to the real LLM API).

## Configuration

`firewall.yaml` sets the bind address, upstream base URL, policy file, fail mode (`fail_closed`
default), and stream window. Env overrides: `LLM_FW_BIND`, `LLM_FW_OPENAI_BASE`. Policies live in
`policies/*.yaml` — see `policies/default.yaml`.

## Benchmark scorecard

The field-standard way to score a prompt-injection guard is **two numbers reported together**:
**malicious accuracy** (attacks caught) and **over-defense FPR** (benign inputs wrongly flagged).
Run the head-to-head harness against a standardized corpus. We use
[`deepset/prompt-injections`](https://huggingface.co/datasets/deepset/prompt-injections)
(662 prompts, both classes), which yields both metrics from one labeled set:

```bash
./scripts/fetch-datasets.sh                       # -> datasets/deepset_injection.jsonl

# Default build (regex + heuristics only, no ML):
cargo run --release -p llm-firewall-bench -- \
  --dataset datasets/deepset_injection.jsonl --out results.json

# Full system (adds the DeBERTa ML stage):
./scripts/fetch-model.sh                           # -> models/injection/ (~703 MB)
cargo run --release -p llm-firewall-bench --features ml -- \
  --dataset datasets/deepset_injection.jsonl --out results-ml.json
```

<!-- BENCHMARK:START -->
Measured on **`deepset/prompt-injections`** (662 prompts: 263 injection / 399 benign),
Apple Silicon CPU, single-threaded. Higher malicious accuracy is better; **lower
over-defense FPR is better**.

| Configuration | Malicious accuracy | Over-defense FPR | F1 | p50 latency | p99 latency |
|---|---|---|---|---|---|
| Default (regex + heuristics, no ML) | 1.9% | **0.0%** | 0.037 | **0.006 ms** | 0.10 ms |
| Full system (+ DeBERTa ML stage) | **38.8%** | 1.0% | 0.553 | 95 ms | 352 ms |

**How to read this.** The two tiers are a deliberate cost/coverage tradeoff. The default
build is a signature filter: it fires only on explicit override phrases, so it never
false-flags a benign prompt (0.0% FPR) and answers in **microseconds**. Enabling the ML
stage escalates the *inconclusive* prompts to a DeBERTa-v3 classifier, lifting recall ~20×
while holding false positives to 1.0%.

The ML classifier's own fidelity is high — it scores textbook attacks (`ignore all previous
instructions…`, DAN jailbreaks) at **P(injection) ≈ 1.00** and clean prompts at **≈ 0.00**.
The 38.8% figure reflects that `deepset` labels a broad set of roleplay / capability /
foreign-language prompts as "injection" that the classifier (reasonably) scores as safe —
i.e. it's a conservative ground truth, not muted inference. See `docs/methodology.md`.
<!-- BENCHMARK:END -->

Fairness rules: `docs/methodology.md`.

## Testing

```bash
cargo test --all        # 80+ tests across the 3 crates
cargo clippy --all-targets -- -D warnings
```

The optional ML stage builds with `--features ml` (pulls `candle`); the default build is ML-free.

## Project layout

- `crates/core` — the detection engine (detectors, risk scoring, policy, masking). Pure, no I/O.
- `crates/proxy` — the OpenAI-compatible reverse proxy (`llm-firewall` binary).
- `crates/bench` — the standardized benchmark harness (`llm-firewall-bench`).

## License

Apache-2.0.
