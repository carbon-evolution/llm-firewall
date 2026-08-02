# Phase 13: Model-Agnostic Output Moderation ("the true LLM firewall")

**Status:** design drafted 2026-07-31, ready for review → plan. Concept approved by the user in
conversation (2026-07-30).

**Parent:** extends the text firewall ([[project-llm-firewall]]) and its existing opt-in
content-moderation layer. Independent of the agent-firewall arc (phases 08–12).

**Branch:** `feat/phase-13-output-moderation`.

---

## 1. Goal

Make the reverse proxy a **model-agnostic output enforcement point**: inspect the LLM's *response* and
restrict harmful content **regardless of which model produced it** — a censored provider, a local model,
or an employee's private **uncensored** model. Because enforcement lives in the firewall, not the model,
a company deploying llm-firewall can hold every LLM call to one output policy even when the backend has
no guardrails of its own. This is the positioning the user calls *"the true LLM firewall."*

The canonical example: a user asks an uncensored model "how do I hack into this website?"; the model
answers; the firewall catches the harmful answer on the way out and refuses (or flags) it.

## 2. What already exists (build on, do not rebuild)

- `core::ModerationDetector` + `ModerationClassifier` (DeBERTa harmful-content, `ml` feature) — detects
  harmful *content* in either direction; `predict(text) -> Vec<(label, score)>`.
- The proxy's `decide_output` already scans model replies via `fw.run(text, Direction::Output)`.
- `build_firewall` already lists `ModerationDetector::new()` — **but inert**: the proxy never enables the
  `ml` feature nor calls `.with_model()`, and no policy rule/enforcement targets it on output.
- The bench measured moderation on JailbreakBench (0% → **58%** with the layer) and recorded its
  over-defense cost, which is exactly the tension this phase must manage.

So the new work is **wiring + enforcement + measurement**, not a new detector.

## 3. The deciding metric (this phase lives or dies on it)

Output moderation's danger is **over-blocking legitimate content** — and for this user specifically,
that means *their own work*: pentest guides, CTF writeups, OSINT methodology, exploit-dev notes,
security research. A filter that blocks "how to hack a website" will also block a legitimate
penetration-testing tutorial.

So the two-number standard is mandatory and the **over-block FPR is the headline**, not the catch rate:

- **Harmful-catch rate** — of genuinely harmful responses, how many are caught.
- **Over-block FPR on benign *security* content** — of legitimate security/technical responses, how many
  are wrongly blocked. **This is the deciding number.** A filter that flags ordinary pentest documentation
  gets switched off (or, worse, silently mangles a professional's work).

A benign corpus of *generic* prose is not enough — it must include the hard security-adjacent content,
the same discipline the judge corpus and agent benchmark follow.

## 4. Design

### 4.1 Enforcement in the output path
When output moderation is enabled, the proxy loads the harmful-content model into the output firewall and
`decide_output` applies its verdict to the model's reply **before it reaches the client**:

- `block` → refuse the response with a safe refusal message (the client never sees the harmful text).
- `flag` → forward the response but record the verdict + categories in the audit log.
- `allow` → forward untouched.

Same shape as the existing text-layer block, and it works identically whatever backend produced the text.

### 4.2 Config — off by default, flag-first
```yaml
output_moderation:
  enabled: false          # opt-in
  action: flag            # flag | block; flag is the safe default (audit, don't refuse)
  threshold: 0.8          # classifier score at/above which a category counts
  model_path: models/moderation
  # Optional: restrict to specific harm categories (default: all the model emits).
  categories: []          # e.g. ["hacking", "malware"] for an AUP-narrow deployment
```
**Default `flag`, not `block`** — on general traffic, block over-defends; the enterprise-AUP scenario
("employees cannot get hacking instructions from the gateway") is where hard `block` is correct, and the
config makes that an explicit operator choice.

### 4.3 The `ml` feature
Loading the classifier needs `core/ml` (candle + the DeBERTa model). Add an `ml` feature to the proxy
that pulls `llm-firewall-core/ml`; without it, `output_moderation` degrades to a no-op with a startup
warning (never a hard failure). Same pattern the bench uses.

### 4.4 Category coverage — verify, don't assume
The user's target is *cyber-offense instructions* ("how to hack"). Whether the shipped model has a
category that fires on that is an **empirical question the corpus answers** — the harmful corpus includes
cyber-offense samples, and the scorecard reports per-category catch. If coverage is weak, that is a
documented limitation and a model-choice follow-up (a model with an explicit "cybercrime/hacking"
category), not a silent gap.

## 5. Components

| File | Responsibility |
|---|---|
| `crates/proxy/Cargo.toml` | *(modify)* an `ml` feature → `llm-firewall-core/ml` |
| `crates/proxy/src/config.rs` | *(modify)* the `output_moderation` block |
| `crates/proxy/src/lib.rs` (`build_firewall`) | *(modify)* load the moderation model + a moderation-on-output policy rule when enabled |
| `crates/proxy/src/handlers.rs` / `pipeline.rs` | *(modify)* apply `block`/`flag` on the moderated output verdict |
| `crates/bench/corpora/output_moderation/*.jsonl` | **new** — harmful + benign-security corpora |
| `crates/bench` `--moderation-scorecard` (or reuse `--dataset` + `--moderation`) | *(modify/new)* report catch rate + over-block FPR, headline the FPR |

## 6. Testing

- Config: `output_moderation` off by default; `action` parses `flag`/`block`.
- Output path: a harmful reply with `action: block` → refused; with `action: flag` → forwarded + audited;
  a benign reply → untouched; feature-off → no-op with warning, never a 500.
- The scorecard (ml-gated, like the injection ML tests): harmful-catch rate + over-block FPR on the
  benign-security corpus, FPR reported first.

## 7. Honesty framing

Output moderation is **not** a full safety system and makes no claim to catch every harmful response or
to detect illegal material. It is a best-effort, **opt-in**, flag-first control whose over-block cost is
measured and published. The README states this and reports the over-block FPR on benign security content
as the headline — because a firewall that mangles a professional's legitimate work gets turned off, and
then protects nothing.

## 8. YAGNI / out of scope

No new classifier training. No streaming-response moderation in v1 (non-streaming replies only; streamed
replies fall back to the existing sliding-window text scan, documented). No per-user policy. No
input-side harmful-request blocking beyond what the injection/moderation layers already do (this phase is
about **output**).

## 9. Open decisions for the plan

1. Whether `block` returns a fixed refusal string or the provider's own refusal shape — default: a fixed,
   configurable refusal message in the provider's error/response envelope.
2. Whether to reuse the bench's existing `--moderation` path for the scorecard or add a dedicated
   `--moderation-scorecard` mode — default: reuse `--dataset ... --moderation` with the new corpora, add a
   thin over-block-FPR summary.
3. Model choice if cyber-offense coverage is weak — default: ship with the current model, document the
   measured coverage, and leave a model-swap as a follow-up rather than blocking this phase.
