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
Run the head-to-head harness against standardized corpora:

```bash
./scripts/fetch-datasets.sh   # pulls deepset/prompt-injections, NotInject, JailbreakBench
cargo run -p llm-firewall-bench -- \
  --dataset datasets/deepset_injection.jsonl \
  --dataset datasets/notinject_benign.jsonl \
  --rival "llm-guard=python3 rivals/llm_guard_adapter.py"
```

<!-- BENCHMARK:START -->
_Run the benchmark to populate this table._
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
