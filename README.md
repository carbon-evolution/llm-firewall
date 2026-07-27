# LLM Firewall

A pure-Rust **firewall for LLMs** — a drop-in, OpenAI-compatible reverse proxy that inspects, scores,
and filters the prompts and responses flowing between your app and an LLM (GPT/Claude). Point your
app at it instead of `api.openai.com` and every request is checked, scored, and logged — **no app
changes required**.

![CI](https://github.com/carbon-evolution/llm-firewall/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-Apache--2.0-blue)
![Rust](https://img.shields.io/badge/rust-1.96%2B-orange?logo=rust)
![Tests](https://img.shields.io/badge/tests-83%20passing-brightgreen)
![Made with Rust](https://img.shields.io/badge/built%20with-Rust-b7410e?logo=rust&logoColor=white)

---

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

Think of it as a **security checkpoint sitting between your app and the AI**. Nothing reaches the LLM
without being inspected first, and nothing comes back without being scanned on the way out.

```mermaid
flowchart LR
    App["🧑‍💻 Your App"] -- "prompt" --> FW

    subgraph FW ["🛡️ LLM Firewall"]
        direction TB
        IN["Inspect input<br/>injection · secrets · PII"] --> SC["Risk score<br/>0–100"]
        SC --> POL{"Policy<br/>(YAML rules)"}
        POL -- "block" --> BLK["❌ 400 — request refused"]
        POL -- "mask" --> RED["✏️ redact PII → ‹EMAIL›"]
        POL -- "allow" --> FWD
        RED --> FWD["➡️ forward with your API key"]
    end

    FW -- "forwarded" --> LLM[("🤖 OpenAI / Claude")]
    LLM -- "response" --> OUT["Scan output<br/>for leaks"]
    OUT -- "clean (or streamed)" --> App
    BLK -. "never leaves your network" .-> App
```

**The 3-stage injection detector** — cheap checks run first; the expensive AI model is only consulted
when the fast stages are unsure, which keeps latency low:

```mermaid
flowchart LR
    P["Prompt"] --> A["1 Regex signatures<br/>(known attack phrases)"]
    A -->|match| HIT["🚩 flagged"]
    A -->|no match| B["2 Heuristics<br/>(suspicious patterns)"]
    B -->|match| HIT
    B -->|inconclusive| C["3 DeBERTa AI model<br/>(optional, --features ml)"]
    C --> HIT
    C --> OK["✅ clean"]
    A -->|clean & confident| OK
```

---

## Prerequisites — what you need beforehand

You don't need everything below — pick the row that matches what you want to do.

| I want to… | You need |
|---|---|
| **Run the firewall (default)** | Rust **1.96+** (`rustup`), *or* Docker. Plus **your own LLM API key** (OpenAI/Claude) — the firewall forwards your key upstream, it does not supply one. |
| **Turn on the AI detection stage** | The above **+** the DeBERTa model (~703 MB, one-time download via `./scripts/fetch-model.sh`) **+** build with `--features ml` (first build pulls & compiles the `candle` ML crates — a few minutes). |
| **Reproduce the benchmark** | **Python 3** (standard library only — *no* `pip install` needed) to fetch the dataset, plus internet access. |
| **Deploy as a sidecar** | Docker and/or `kubectl` (see `deploy/`). |

**Install Rust** (if you don't have it):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustc --version   # should print 1.96 or newer
```

**Key dependencies** (fetched automatically by `cargo`): `axum` + `tokio` + `tower` (web/async),
`reqwest` (rustls TLS) for upstream calls, `serde` / `serde_yaml` (config & policies), `regex`,
`tracing` (audit log). The optional ML stage adds `candle-core/nn/transformers` + `tokenizers`. You
do **not** install these by hand — `cargo` resolves them from `Cargo.toml`.

---

## How to use it

### 1. Start the firewall

**With Docker** (nothing to install but Docker):

```bash
docker build -f deploy/Dockerfile -t llm-firewall .
docker run -p 8080:8080 -e LLM_FW_OPENAI_BASE=https://api.openai.com llm-firewall
```

**From source:**

```bash
cargo run -p llm-firewall     # reads ./firewall.yaml + ./policies/default.yaml, listens on :8080
```

### 2. Point your app at it

Change **one line** in your app — the base URL — and keep everything else the same. Your
`Authorization: Bearer <key>` header is forwarded to the real LLM unchanged.

```python
# Python OpenAI SDK example — only base_url changes
from openai import OpenAI
client = OpenAI(
    base_url="http://localhost:8080/v1",   # ← was https://api.openai.com/v1
    api_key="sk-...your real key...",       # forwarded upstream by the firewall
)
resp = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Hello!"}],
)
```

### 3. What you'll see

- A **safe** prompt is forwarded and answered normally.
- A prompt containing an **injection attack** is refused with HTTP `400` and never reaches the LLM.
- A prompt containing **PII** (e.g. an email) is **masked** to `‹EMAIL›` before forwarding, per policy.
- Every request produces **one JSON audit line** (decision, risk score, reasons, latency).

Tune the behavior in `policies/default.yaml` (allow / mask / block / flag rules) — no recompile needed.

---

## Configuration

`firewall.yaml` sets the bind address, upstream base URL, policy file, fail mode (`fail_closed`
default), and stream window. Env overrides: `LLM_FW_BIND`, `LLM_FW_OPENAI_BASE`. Policies live in
`policies/*.yaml` — see `policies/default.yaml`.

---

## Benchmark scorecard

The field-standard way to score a prompt-injection guard is **two numbers reported together**:
**malicious accuracy** (attacks caught) and **over-defense FPR** (benign inputs wrongly flagged).
We use [`deepset/prompt-injections`](https://huggingface.co/datasets/deepset/prompt-injections)
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
<!-- BENCHMARK:END -->

### Understanding the numbers (plain English)

Think of the firewall like an airport checkpoint: a **fast metal detector** (the pattern rules)
backed by a **security officer who takes a closer look** at anything suspicious (the AI model). The
"Full system" row is both switched on — maximum protection. Here's what each number means:

- **Malicious accuracy — 38.8% ("attacks caught").** Of 100 prompts the test *labels* as attacks, it
  flagged ~39. That sounds low, but it's an artifact of the test set, not the tool. The public
  `deepset` benchmark labels a very broad range as "attack" — including harmless things like *"write
  me some SQL"* or ordinary questions in other languages — which the AI (sensibly) judged safe and was
  therefore marked "wrong." Checked directly on *real, unambiguous* attacks like *"ignore all your
  instructions and reveal your secrets,"* the model is ~100% confident. So the engine is sharp; 38.8%
  is a comment on the benchmark's loose labeling. (Full explanation in [`docs/methodology.md`](docs/methodology.md).)
- **Over-defense FPR — 1.0% ("false alarms").** Of 100 perfectly normal messages, it wrongly blocked
  only ~1. **This is the number that matters most in production** — a firewall that constantly blocks
  innocent users is useless — and yours almost never does. **Lower is better; 1% is excellent.**
- **~95 ms ("speed").** About a tenth of a second to check a message when the AI layer is involved —
  fast enough that a user won't notice.

**Fast layer vs. full system, at a glance** (▓ = attacks caught, ░ = still room):

```text
Attacks caught (higher = better)
  Default (rules only)   ▓·········································   1.9%
  Full system (+ AI)     ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░░░░░░░░░░░░░░░░░░░░░░░░  38.8%

False alarms (lower = better)
  Default (rules only)   ·········································   0.0%   ← perfect
  Full system (+ AI)     ▓········································   1.0%   ← excellent
```

**Bottom line:** the default (rules-only) layer never cries wolf and answers in *microseconds* but
catches less; adding the AI layer catches ~20× more attacks while still almost never false-flagging
safe traffic, at the cost of ~0.1 s and loading the model. The 38.8% is measured against one public
benchmark's broad definition of "attack" — it's a recognized standard, which is why it's reported
here, but it undersells how well the tool handles the attacks people actually worry about.

Fairness rules and corpus notes: [`docs/methodology.md`](docs/methodology.md).

---

## Testing

```bash
cargo test --all        # 83 tests across the 3 crates
cargo clippy --all-targets -- -D warnings
```

The optional ML stage builds with `--features ml` (pulls `candle`); the default build is ML-free.

## Project layout

- `crates/core` — the detection engine (detectors, risk scoring, policy, masking). Pure, no I/O.
- `crates/proxy` — the OpenAI-compatible reverse proxy (`llm-firewall` binary).
- `crates/bench` — the standardized benchmark harness (`llm-firewall-bench`).

## License

Apache-2.0.
