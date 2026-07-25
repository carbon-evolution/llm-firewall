# LLM Firewall — Design & Decision Record

> **Status:** Design COMPLETE — all sections approved; awaiting final user spec review before implementation plan
> **Date started:** 2026-07-25
> **Owner:** Arthur (GitHub: `carbon-evolution`)
> **Purpose:** A next-generation Web Application Firewall, but for LLMs — a Rust reverse proxy that
> inspects, scores, and filters prompts/responses flowing between a client and GPT/Claude. To be
> open-sourced on GitHub and showcased with a published head-to-head benchmark and scorecard.

This document records **how we planned it and why** — the brainstorming Q&A, every decision with its
rationale, and the full design. Keep it updated as implementation proceeds so future-us knows the
reasoning behind each choice.

---

## 1. Vision (as stated by the user)

Imagine a next-generation Web Application Firewall — but for LLMs.

```
      User
        │
        ▼
  Rust LLM Firewall
        │
 ┌──────┼───────┐
 │ Prompt Inspection │
 │ PII Detection     │
 │ Injection Detection │
 │ Policy Engine     │
 │ Output Filtering  │
 └──────┼───────┘
        ▼
     GPT / Claude
```

**Feature wishlist:** Prompt Injection Detection · Secret Detection · Prompt Risk Score ·
Regex + ML detection · PII masking · Token counting · Cost estimation · Block malicious prompts ·
Audit logging · Streaming support.

**Target Rust libraries:** `axum`, `tokio`, `tower`, `serde`, `regex`, `reqwest`.
**Bonus:** run it as a Kubernetes sidecar.

**Headline goal:** publish on GitHub with **test results + a score** that highlight the project to users.

---

## 2. Decision Log (brainstorming Q&A)

Each row is a question posed during brainstorming, the answer chosen, and why it matters.

| # | Decision | Choice | Rationale / trade-off |
|---|----------|--------|-----------------------|
| D1 | **v1 scope** | **Full WAF vision** — build all ~10 features (injection, PII, secrets, policy engine, output filtering, token counting, cost estimation, streaming, audit, k8s sidecar) | User wants the complete product, not an MVP slice. Longer road to first benchmark; mitigated by building in phases within one cohesive binary. |
| D2 | **ML detection approach** | **Pure Rust via `candle`** (Hugging Face's native-Rust tensor lib) for the ML stage, inside a 3-stage hybrid (regex → heuristics → ML) | No C++/ONNX-Runtime native dependency; clean "pure-Rust" story for the showcase. Cost: fewer off-the-shelf models, more model-loading wiring. |
| D3 | **Benchmark & scoring** | **Head-to-head vs rivals on standardized, recognized benchmarks** — run the industry-standard test suites through our firewall *and* published baselines, publish a comparison matrix + scorecard | Most compelling *and* credible showcase. Cost: must install/run competitors *fairly* (same corpora, isolated, warm caches). |
| D9 | **Scoring standard** | Report **two headline numbers**: malicious-detection accuracy **AND** over-defense / false-positive rate on benign inputs (plus F1, latency) | This is the field's common standard (per InjecGuard/PIGuard). Most guards quietly over-flag benign prompts; a one-sided "we catch attacks" score isn't credible. Reporting both is honest and how we look good legitimately. |
| D10 | **Benchmark datasets** | Adopt recognized suites (see §6) rather than ad-hoc corpora | Makes our score directly comparable to what Lakera/InjecGuard/JailbreakBench publish. |
| D4 | **Codebase structure** | **Approach A — Cargo workspace**: `core` (engine, no I/O) + `proxy` (axum binary) + `bench` (harness) | Clean testable boundaries; `core` doubles as an embeddable crate; benchmark tests the same code the proxy runs. Slightly more wiring than a monolith. |
| D5 | **candle model sourcing** | **Vendor a converted open model** — fine-tune/convert an existing open prompt-injection classifier to candle format, ship weights via **git-lfs** | Far cheaper than training from scratch; reproducible. |
| D6 | **Risk score formula** | **Weighted diminishing-returns** aggregation (not naive sum or max-severity) | Ten low-severity hits shouldn't outweigh one Critical; weights are config-tunable for precision/recall. |
| D7 | **Policy format** | **Flat, first-match YAML rules** (not a richer expression language) | Policy stays *data* not code; simple, diffable, no recompile to tune. |
| D8 | **Failure mode** | **fail_closed** by default (block on internal/model error), `fail_open` opt-in | Safe default for a security tool; surfaced clearly in config. |

**Defaults set without a blocking question (user may override in spec review):**
- Proxy is an **OpenAI/Anthropic-compatible reverse proxy** (client swaps `base_url`); not score-only.
- **Policy rules in YAML** config.
- **License:** Apache-2.0. **Repo:** public, under `carbon-evolution`.

---

## 3. Architecture & Request Lifecycle  *(Section 1 — APPROVED)*

### Repo layout (Cargo workspace)

```
llm-firewall/
├── crates/
│   ├── core/     (llm-firewall-core)   engine, no I/O — detectors, scoring, policy, filters
│   ├── proxy/    (llm-firewall)        axum/tokio reverse-proxy binary
│   └── bench/    (llm-firewall-bench)  benchmark + rival harness
├── models/       candle weights + tokenizer (git-lfs)
├── policies/     example YAML policy files
├── datasets/     benchmark corpora (or a fetch script)
├── deploy/       Dockerfile, k8s sidecar manifests
└── docs/         README scorecard, methodology, this design doc
```

### What the proxy is

A drop-in, OpenAI/Anthropic-compatible reverse proxy. A client points its `base_url` at the firewall
instead of `api.openai.com`; the firewall inspects, decides, then forwards upstream (or blocks).
Streaming (SSE) is passed through with output inspection on the token stream.

### Request lifecycle (data flow)

```
Client ──▶ [ Ingress: parse OpenAI/Anthropic body, extract messages ]
             │
             ▼
        ┌─ INPUT PIPELINE (ordered stages, short-circuit on block) ─┐
        │  1. Injection detector  (regex → heuristics → candle ML)  │
        │  2. Secret detector     (regex/entropy)                    │
        │  3. PII detector        (regex → optional NER) + masking   │
        │  4. Token counter + cost estimator                         │
        │  5. Risk aggregator     → score 0–100                      │
        │  6. Policy engine       → allow / mask / block decision    │
        └────────────────────────────────────────────────────────────┘
             │ allow/mask                    │ block
             ▼                               ▼
     [ Forward upstream GPT/Claude ]   [ 4xx + reason + risk score ]
             │
             ▼
        ┌─ OUTPUT PIPELINE (on response / stream chunks) ─┐
        │  secret/PII leak scan, output policy filtering   │
        └──────────────────────────────────────────────────┘
             │
             ▼
   [ Audit log (structured JSON) ] ──▶ Client
```

**Key idea:** every stage implements a common `Stage`/`Detector` trait; the pipeline is an ordered
`Vec` of stages configured from YAML. Blocking stages short-circuit; masking stages rewrite the
payload and continue. Each stage is independently unit-testable.

---

## 4. Detection Engine & Risk Scoring  *(Section 2 — APPROVED)*

### The `Detector` trait (in `core`)

```rust
pub struct Finding {
    detector: &'static str,       // "injection", "pii.email", "secret.aws_key"
    severity: Severity,           // Info | Low | Medium | High | Critical
    confidence: f32,              // 0.0–1.0
    span: Option<Range<usize>>,   // where in the text (for masking/highlighting)
    label: String,                // human-readable
}

pub trait Detector: Send + Sync {
    fn name(&self) -> &'static str;
    fn inspect(&self, ctx: &Context) -> Vec<Finding>;
}
```

Every detector returns structured `Finding`s (never a bare bool) so scoring, masking, and audit all
consume one uniform shape.

### 1. Injection detector — 3-stage hybrid (short-circuits early on cheap wins)

- **Stage A — signatures/regex:** curated library of known override phrases/patterns ("ignore
  previous instructions", "you are now DAN", system-prompt-leak probes, role/delimiter injection like
  `<|im_start|>`, base64/hex blobs). Fast, explainable, high-precision.
- **Stage B — heuristics:** imperative-override scoring, instruction density, unusual delimiters,
  encoded-payload entropy, language/script mixing. Cheap floats; catches novel phrasings.
- **Stage C — candle ML classifier:** small fine-tuned transformer (DistilBERT-class) loaded via
  `candle` + `tokenizers`, run only when A/B are inconclusive (keeps p99 low). Outputs `P(injection)`.

### 2. Secret detector

Regex ruleset (AWS keys, GitHub/Slack tokens, JWTs, private-key headers, connection strings) +
Shannon-entropy gate to cut false positives on random-but-benign strings.

### 3. PII detector

Regex for structured PII (email, phone, SSN, credit card w/ Luhn check, IP) → optional candle NER
pass for names/addresses. Produces spans so the masker replaces in-place with `‹EMAIL›`, `‹SSN›`, etc.

### Risk aggregator → score 0–100

Not a naive sum. Each `Finding` contributes `severity_weight × confidence`; the aggregator combines
them with **diminishing returns** (ten low-severity hits can't outweigh one Critical), normalizes to
0–100, and attaches the top contributing findings as "reasons." Weights live in config for
precision/recall tuning. Score + reasons feed both the policy engine and the API response.

**Determinism & explainability:** every block/mask response carries the score and the specific
findings that caused it — essential for user trust and honest benchmarking.

---

## 5. Policy Engine, Output Filtering, Proxy Runtime  *(Section 3 — APPROVED)*

### Policy engine (YAML, flat first-match)

Score + findings feed a small declarative rule set. Rules evaluate top-to-bottom; **first match wins**.

```yaml
policies:
  - name: block-critical-injection
    when: { detector: injection, min_severity: high }
    action: block
    message: "Prompt blocked: possible injection"
  - name: mask-pii
    when: { detector: pii }
    action: mask            # replace spans, then continue upstream
  - name: block-high-risk
    when: { risk_score_gte: 80 }
    action: block
  - name: secrets-out
    when: { detector: secret, direction: output }
    action: block           # never let a secret leave in the response
default: allow
```

Actions: `allow` · `mask` (rewrite spans, continue) · `block` (short-circuit, 4xx + reasons) ·
`flag` (allow but mark audit as suspicious). Rules can scope to `direction: input|output`.
Policy is **data, not code** — tune without recompiling, diffable in git.

### Output filtering

The output pipeline reuses the same detectors on the model's response (catch secrets/PII the model
regurgitated; apply output-scoped policies). For **streaming (SSE)** we buffer a small **sliding
window** over chunks so a secret split across token boundaries is still caught, then forward cleaned
chunks — a few ms latency for leak safety; window size configurable.

### Proxy runtime (`proxy` crate)

- `axum` router exposes OpenAI (`/v1/chat/completions`, `/v1/embeddings`) and Anthropic
  (`/v1/messages`) shapes; `reqwest` forwards upstream with the caller's key.
- `tower` layers for concurrency limit, timeout, per-route middleware; `tokio` runtime.
- **Config:** one `firewall.yaml` (upstream URLs, enabled detectors + weights, policy file path,
  model paths, audit sink, streaming window). Env-var overrides for secrets/ports.
- **Audit log:** structured JSON per request — timestamp, request id, decision, score, findings
  (redacted), token counts, estimated cost, latency. Writes to stdout (container-friendly) or file;
  also the raw material the benchmark reads.
- **Fail mode:** `fail_closed` default (block on detector/model error), `fail_open` opt-in.

## 6. Benchmark Harness, Testing, Deployment, Repo/License  *(Section 4 — APPROVED)*

### Benchmark harness (`bench` crate) — the showcase engine

Runs the **standardized, recognized** test suites through our firewall and published rivals, then
emits a comparison matrix + scorecard. Datasets are fetched by script into `datasets/` (not vendored)
to respect licensing and size.

**The common standard is TWO headline numbers** — malicious-detection accuracy *and* over-defense /
false-positive rate on benign inputs — because most guards quietly over-flag benign prompts. We
report both, matching how Lakera / InjecGuard / JailbreakBench present results.

**Standardized test sources**

| Category | Sources | Measures |
|----------|---------|----------|
| A. Malicious detection | `deepset/prompt-injections`; **PINT** (Lakera Prompt Injection Test — public sample + leaderboard; full set private to avoid contamination); **Open-Prompt-Injection** (Liu et al.) | Detection rate / recall on attacks |
| B. Over-defense / FPR | **NotInject** (339 benign w/ trigger words); **OR-Bench**; optional ToxicChat / AlpacaEval benign | False-positive rate on benign input |
| C. Jailbreak | **JailbreakBench** (JBB-Behaviors, 100 behaviors + leaderboard); **HarmBench** (400 text behaviors); **StrongREJECT** (automated grader) | Jailbreak catch rate |
| D. PII | **AI4Privacy `pii-masking-200k`**; Microsoft **Presidio** eval set | PII detect + mask precision/recall |
| E. Secrets | **gitleaks** test fixtures / **secretbench** (labeled) | Secret detection precision/recall |

**Rivals for head-to-head** (same published guardrails, so it's apples-to-apples): Meta **Prompt
Guard / Llama Guard / LlamaFirewall**, **ProtectAI deberta prompt-injection-v2**, **deepset**
classifier, **Fmops**, open **InjecGuard / PIGuard**, plus **LLM Guard** and **Rebuff**. Several
publish numbers on these exact datasets, so we can chart against published results without re-running
every tool. Rivals we do run go in isolated venvs, warmed before timing, same hardware/inputs;
fairness rules documented in `docs/methodology.md`.

**Reporting format** (matches the leaderboards):
```
Combined scorecard
                        Ours   PromptGuard  LlamaGuard3  LLMGuard  Rebuff
Malicious accuracy       xx%       xx%         xx%         xx%      xx%
Over-defense acc (FPR)   xx%       xx%         xx%         xx%      xx%
F1                       0.xx      0.xx        0.xx        0.xx     0.xx
p50 / p99 latency       x/y ms    …           …           …        …
Local / no-API            ✓         ✓           ✓           ✓        ✗
                       → Overall grade: A / ★★★★★
```
Output: machine-readable `results.json` + generated Markdown the README embeds. One `make bench`.

### Testing strategy

- **Unit** per detector: labeled true/false fixtures; precision/recall asserted against a floor so
  regressions fail CI.
- **Golden tests** for scoring: fixed findings → expected score (locks the diminishing-returns math).
- **Policy tests:** rule set + input → expected action.
- **Integration:** proxy against a mock upstream; assert allow/mask/block end-to-end incl. a
  streaming leak case.
- **CI (GitHub Actions):** fmt + clippy + tests every push; light benchmark smoke run in CI, full
  benchmark manual/nightly to keep CI fast.

### Deployment (`deploy/`)

- Multi-stage `Dockerfile` → small runtime image (candle model via git-lfs or downloaded on build).
- **K8s sidecar:** manifest patch injecting the firewall next to an app pod; app talks to
  `localhost:<port>`, firewall egresses to the real LLM API. README quickstart for standalone
  `docker run` and sidecar.

### Repo & licensing

- Public repo **`carbon-evolution/llm-firewall`**, **Apache-2.0**.
- README leads with the scorecard/comparison matrix + architecture diagram; badges (CI, license,
  crates.io once `core` is published).
- *Note:* standing IP-strategy preference is to keep proprietary-moat code private from day one — but
  this project's purpose is a public showcase, so public + permissive is the deliberate right call.

---

## Changelog

- **2026-07-25:** Doc created. Decisions D1–D10 recorded; **all four design sections approved**
  (architecture, detection+scoring, policy+proxy runtime, benchmark+testing+deploy). Benchmark
  refined to standardized recognized suites with dual malicious-accuracy + over-defense reporting.
  Ready for spec review → implementation plan.
