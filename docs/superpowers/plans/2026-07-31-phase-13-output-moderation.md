# Phase 13: Output Moderation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Make the reverse proxy a model-agnostic output enforcement point — restrict harmful LLM responses regardless of backend — off by default, flag-first, with the over-block FPR on benign security content as the headline number.

**Architecture:** A dedicated **moderation gate** (`crates/proxy/src/moderation.rs`) wraps the harmful-content classifier and applies a configured `flag`/`block` action to the model's reply in the output path — decoupled from the policy engine, so no policy-YAML merging. Feature-gated on `ml`: without it, the gate is always a no-op (startup warning, never a failure). A benign-security corpus + scorecard measure the over-block cost.

**Tech Stack:** Rust 2021, `llm-firewall-core` (`ModerationClassifier`, `ml` feature = candle + DeBERTa), serde, axum.

**Spec:** `docs/superpowers/specs/2026-07-31-phase-13-output-moderation-design.md`

**Branch:** `feat/phase-13-output-moderation`.

## Decisions locked in (spec §9)

1. `block` returns a fixed, configurable refusal message in the provider's response/error envelope.
2. The scorecard reuses the bench's `--dataset ... --moderation` path with the new corpora, adding an over-block-FPR summary.
3. Ship with the current moderation model; document measured cyber-offense coverage; a model swap is a follow-up, not a blocker.

## File Structure

| File | Responsibility |
|------|---------------|
| `crates/proxy/Cargo.toml` | *(modify)* an `ml` feature → `llm-firewall-core/ml` |
| `crates/proxy/src/config.rs` | *(modify)* the `output_moderation` block |
| `crates/proxy/src/moderation.rs` | **new** — the `ModerationGate`: load model (ml), `check(text) -> GateVerdict` |
| `crates/proxy/src/lib.rs` | *(modify)* `mod moderation;`, build the gate |
| `crates/proxy/src/handlers.rs` | *(modify)* `AppState` gains the gate; apply block/flag on the reply |
| `crates/bench/corpora/output_moderation/{harmful,benign_security}.jsonl` | **new** — corpora |

---

### Task 1: The `output_moderation` config block

**Files:** Modify `crates/proxy/src/config.rs`

- [ ] **Step 1: Write the failing test**

Add to `config.rs`'s test module (mirror the `agent_inspection` config test added in phase 11b):

```rust
    #[test]
    fn output_moderation_is_off_and_flag_first_by_default() {
        let c = Config::from_yaml("upstream: {}").unwrap();
        assert!(!c.output_moderation.enabled, "opt-in");
        assert_eq!(c.output_moderation.action, ModerationAction::Flag, "flag-first");
    }

    #[test]
    fn output_moderation_parses_block_action() {
        let c = Config::from_yaml(
            "upstream: {}\noutput_moderation:\n  enabled: true\n  action: block\n  threshold: 0.9\n",
        )
        .unwrap();
        assert!(c.output_moderation.enabled);
        assert_eq!(c.output_moderation.action, ModerationAction::Block);
        assert!((c.output_moderation.threshold - 0.9).abs() < 1e-6);
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p llm-firewall config::output_moderation`
Expected: FAIL — no field `output_moderation`.

- [ ] **Step 3: Implement**

In `crates/proxy/src/config.rs`, add:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModerationAction {
    /// Forward the response, but record the verdict + categories in the audit log.
    Flag,
    /// Refuse the response with a safe message; the client never sees the harmful text.
    Block,
}

fn default_mod_threshold() -> f32 {
    0.8
}
fn default_mod_model() -> String {
    "models/moderation".into()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct OutputModeration {
    /// Run the harmful-content classifier on model replies. Off by default.
    pub enabled: bool,
    /// What to do on a harmful reply. `flag` (default) audits; `block` refuses.
    pub action: ModerationAction,
    /// Classifier score at/above which a category counts as harmful.
    pub threshold: f32,
    /// Directory of the moderation model.
    pub model_path: String,
    /// Restrict to these harm categories (empty = every category the model emits).
    pub categories: Vec<String>,
    /// Refusal message returned to the client when `action: block`.
    pub refusal_message: String,
}

impl Default for OutputModeration {
    fn default() -> Self {
        Self {
            enabled: false,
            action: ModerationAction::Flag,
            threshold: default_mod_threshold(),
            model_path: default_mod_model(),
            categories: Vec::new(),
            refusal_message: "This response was withheld by the output content policy.".into(),
        }
    }
}
```

Add to the `Config` struct: `#[serde(default)] pub output_moderation: OutputModeration,`. Update the `test_config` helper in `crates/proxy/src/lib.rs` to add `output_moderation: config::OutputModeration::default(),`.

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p llm-firewall config::`, then `cargo build -p llm-firewall` (fix the `test_config` literal). clippy + fmt clean.

- [ ] **Step 5: Commit**

```bash
git add crates/proxy/src/config.rs crates/proxy/src/lib.rs
git commit -m "feat(proxy): output_moderation config block, off + flag-first by default

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 2: The moderation gate (feature-gated)

**Files:** Create `crates/proxy/src/moderation.rs`; modify `crates/proxy/Cargo.toml`, `crates/proxy/src/lib.rs`

- [ ] **Step 1: Add the `ml` feature**

In `crates/proxy/Cargo.toml`:

```toml
[features]
ml = ["llm-firewall-core/ml"]
```

- [ ] **Step 2: Write the failing test**

Create `crates/proxy/src/moderation.rs`:

```rust
// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! The output moderation gate: runs the harmful-content classifier on a model reply
//! and returns a verdict. Feature-gated on `ml`; without it, always `Allow` (no-op).

use crate::config::{ModerationAction, OutputModeration};

/// What the gate decided about a reply.
#[derive(Debug, Clone, PartialEq)]
pub enum GateVerdict {
    /// Forward untouched.
    Allow,
    /// Harmful categories at/above threshold. `block` = refuse; `flag` = audit + forward.
    Harmful { categories: Vec<String>, action: ModerationAction },
}

/// Decide the verdict from the classifier's `(category, score)` output. Pure, so the
/// policy is unit-testable without the model. A category counts if its score ≥ threshold
/// and (when `categories` is non-empty) it is in the allowlist.
pub fn verdict_from_scores(
    scores: &[(String, f32)],
    cfg: &OutputModeration,
) -> GateVerdict {
    let hits: Vec<String> = scores
        .iter()
        .filter(|(cat, score)| {
            *score >= cfg.threshold
                && cat != "safe"
                && cat != "OK"
                && (cfg.categories.is_empty() || cfg.categories.iter().any(|c| c == cat))
        })
        .map(|(cat, _)| cat.clone())
        .collect();
    if hits.is_empty() {
        GateVerdict::Allow
    } else {
        GateVerdict::Harmful { categories: hits, action: cfg.action }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(action: ModerationAction, threshold: f32, categories: Vec<String>) -> OutputModeration {
        OutputModeration { enabled: true, action, threshold, categories, ..Default::default() }
    }

    #[test]
    fn a_high_scoring_harmful_category_is_flagged() {
        let scores = vec![("harmful".into(), 0.95), ("safe".into(), 0.05)];
        let v = verdict_from_scores(&scores, &cfg(ModerationAction::Block, 0.8, vec![]));
        assert!(matches!(v, GateVerdict::Harmful { .. }));
    }

    #[test]
    fn a_below_threshold_score_is_allowed() {
        let scores = vec![("harmful".into(), 0.5)];
        assert_eq!(verdict_from_scores(&scores, &cfg(ModerationAction::Block, 0.8, vec![])), GateVerdict::Allow);
    }

    #[test]
    fn the_safe_category_never_counts() {
        let scores = vec![("safe".into(), 0.99)];
        assert_eq!(verdict_from_scores(&scores, &cfg(ModerationAction::Flag, 0.8, vec![])), GateVerdict::Allow);
    }

    #[test]
    fn the_category_allowlist_narrows_what_counts() {
        let scores = vec![("hate".into(), 0.95), ("hacking".into(), 0.95)];
        // Only "hacking" is in the allowlist -> flagged on hacking, not hate.
        let v = verdict_from_scores(&scores, &cfg(ModerationAction::Block, 0.8, vec!["hacking".into()]));
        match v {
            GateVerdict::Harmful { categories, .. } => assert_eq!(categories, vec!["hacking".to_string()]),
            _ => panic!("expected harmful"),
        }
    }
}
```

- [ ] **Step 3: Run to verify it fails, then passes**

Run: `cargo test -p llm-firewall moderation`. Add `pub mod moderation;` to `crates/proxy/src/lib.rs`.
Expected: PASS.

- [ ] **Step 4: Add the model-loading gate (ml-gated)**

Append to `moderation.rs` — the stateful gate that owns the classifier. Under `#[cfg(feature="ml")]` it
loads and predicts; otherwise it is a zero-field no-op. Note the real API:
`ModerationClassifier::load_with_labels(dir, labels) -> Result<Self>` and `predict(text) -> Result<Vec<(String,f32)>>` (confirm the label set the shipped model expects by reading `crates/core/src/detectors/moderation.rs` before finalizing — do not guess the labels).

```rust
/// Holds the loaded classifier (ml only) + the config. `check` returns the verdict for
/// a reply. Built once at startup.
pub struct ModerationGate {
    cfg: OutputModeration,
    #[cfg(feature = "ml")]
    classifier: Option<llm_firewall_core::ModerationClassifier>,
}

impl ModerationGate {
    /// Build from config. When enabled + `ml` + the model loads, the gate is live;
    /// otherwise it degrades to a no-op with a warning (never a hard failure).
    pub fn new(cfg: OutputModeration) -> Self {
        #[cfg(feature = "ml")]
        {
            if !cfg.enabled {
                return Self { cfg, classifier: None };
            }
            let labels = vec!["harmful".to_string(), "safe".to_string()]; // confirm vs model card
            match llm_firewall_core::ModerationClassifier::load_with_labels(&cfg.model_path, labels) {
                Ok(clf) => {
                    tracing::info!(path = %cfg.model_path, "output moderation model loaded");
                    Self { cfg, classifier: Some(clf) }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "output moderation enabled but model unavailable; disabled");
                    Self { cfg, classifier: None }
                }
            }
        }
        #[cfg(not(feature = "ml"))]
        {
            if cfg.enabled {
                tracing::warn!("output_moderation.enabled but the proxy was built without the `ml` feature; no-op");
            }
            Self { cfg }
        }
    }

    /// The verdict for a model reply. Always `Allow` when the gate is not live.
    pub fn check(&self, _text: &str) -> GateVerdict {
        if !self.cfg.enabled {
            return GateVerdict::Allow;
        }
        #[cfg(feature = "ml")]
        {
            if let Some(clf) = &self.classifier {
                match clf.predict(_text) {
                    Ok(scores) => return verdict_from_scores(&scores, &self.cfg),
                    Err(e) => {
                        tracing::warn!(error = %e, "moderation predict failed; allowing (fail open)");
                        return GateVerdict::Allow;
                    }
                }
            }
        }
        GateVerdict::Allow
    }

    pub fn refusal_message(&self) -> &str {
        &self.cfg.refusal_message
    }
}
```

- [ ] **Step 5: Run to verify it builds both ways**

Run: `cargo build -p llm-firewall` (no ml) and `cargo build -p llm-firewall --features ml`. Both clean.
clippy (default features) + fmt clean.

- [ ] **Step 6: Commit**

```bash
git add crates/proxy/src/moderation.rs crates/proxy/src/lib.rs crates/proxy/Cargo.toml
git commit -m "feat(proxy): output moderation gate (ml-gated, no-op without the model)

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 3: Wire the gate into the output path

**Files:** Modify `crates/proxy/src/handlers.rs`, `crates/proxy/src/main.rs`

- [ ] **Step 1: Add the gate to AppState**

In `handlers.rs`, extend `AppState`:

```rust
    /// Output content moderation gate. `check` is a no-op unless enabled + `ml` + model.
    pub moderation: crate::moderation::ModerationGate,
```

Construct it wherever `AppState` is built (`main.rs`, and the test/`test_state` helpers): `moderation: crate::moderation::ModerationGate::new(cfg.output_moderation.clone()),`.

- [ ] **Step 2: Apply on both response paths**

In `chat_completions`, after the existing `decide_output` passes and (if present) the agent-inspection
block, before `audit_allow`:

```rust
    if !req.stream {
        if let crate::moderation::GateVerdict::Harmful { categories, action } =
            state.moderation.check(assistant)
        {
            tracing::warn!(?categories, ?action, "output moderation: harmful reply");
            if action == crate::config::ModerationAction::Block {
                let msg = state.moderation.refusal_message().to_string();
                audit_output_block(&request_id, &msg, started);
                return (StatusCode::OK, Json(error_body(&msg))).into_response();
            }
        }
    }
```

Mirror it in `messages` (Anthropic) using the concatenated `assistant` text already computed there and
`anthropic_error_body`. `flag` forwards (the `tracing::warn!` + audit is the record); `block` refuses.

- [ ] **Step 3: Verify**

Run: `cargo test -p llm-firewall`, `cargo build -p llm-firewall --features ml`, clippy + fmt. All clean.
(The block/flag behavior is unit-tested via `verdict_from_scores` in Task 2; an end-to-end test with a
stub gate is added in Task 4.)

- [ ] **Step 4: Commit**

```bash
git add crates/proxy/src/handlers.rs crates/proxy/src/main.rs
git commit -m "feat(proxy): apply output moderation on the reply (block refuses, flag audits)

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 4: End-to-end test with a forced verdict

**Files:** Create `crates/proxy/tests/output_moderation.rs`

Because the model is ml-gated and heavy, test the *enforcement wiring* deterministically: drive the router
with a mock upstream returning a reply, and assert the block/flag/off behavior via `verdict_from_scores`
plus a handler-level check. Since `check` is a no-op without ml, the end-to-end block path is exercised by
constructing a config whose gate would block **only** through `verdict_from_scores` — so this task's
integration test asserts: (a) with moderation **off**, the reply passes byte-for-byte; (b) `verdict_from_scores`
maps a harmful score to `Harmful` and a benign one to `Allow` (already in Task 2). Document that the live
model path is verified by the Task 6 scorecard run under `--features ml`.

- [ ] **Step 1: Write the test**

```rust
// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Output moderation wiring: off-by-default passthrough. The verdict logic is unit-
//! tested in `moderation.rs`; the live model is exercised by the phase-13 scorecard.

use std::sync::Arc;

use axum::body::to_bytes;
use axum::http::{Request, StatusCode};
use llm_firewall::handlers::AppState;
use llm_firewall::{app, test_config};
use llm_firewall_core::{Firewall, InjectionDetector, PolicySet};
use tower::ServiceExt;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn moderation_off_by_default_passes_the_reply_through() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "choices": [{"message": {"role":"assistant","content":"here is a detailed answer"}}]
        })))
        .mount(&server)
        .await;

    let policy = PolicySet::from_yaml("default: allow").unwrap();
    let fw = Firewall::new(vec![Box::new(InjectionDetector::new())], policy);
    let cfg = test_config(server.uri()); // output_moderation default = off
    let state = Arc::new(AppState {
        firewall: fw,
        http: reqwest::Client::new(),
        agent: std::sync::Mutex::new(llm_firewall_agent::AgentFirewall::with_default_policy()),
        moderation: llm_firewall::moderation::ModerationGate::new(cfg.output_moderation.clone()),
        config: cfg,
    });

    let body = serde_json::json!({"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]});
    let resp = app(state)
        .oneshot(
            Request::post("/v1/chat/completions")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    assert!(String::from_utf8_lossy(&bytes).contains("detailed answer"));
}
```

Confirm the exact `AppState` field list against the current struct (agent, moderation, config order may
differ) before running — match it exactly.

- [ ] **Step 2: Run + commit**

Run: `cargo test -p llm-firewall --test output_moderation`. Then:

```bash
git add crates/proxy/tests/output_moderation.rs
git commit -m "test(proxy): output moderation off-by-default passthrough

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 5: The corpora — harmful + benign-security

**Files:** Create `crates/bench/corpora/output_moderation/harmful.jsonl`, `.../benign_security.jsonl`

Reuse the existing bench dataset format (`{"text": "...", "label": true|false}`; `true` = harmful).

- [ ] **Step 1: Author the corpora**

- `harmful.jsonl` (~25, `label:true`): model *responses* that give operational harmful help — step-by-step
  intrusion of a specific system, working malware/ransomware code, credential-theft phishing kits,
  instructions to exploit a named target. Focus on **cyber-offense** (the user's stated target) plus a few
  other clear-harm categories the model may cover.
- `benign_security.jsonl` (~25, `label:false`): the **hard** legitimate security content that must NOT be
  blocked — a penetration-testing methodology writeup, a CTF solution, OSINT reconnaissance steps for an
  authorized engagement, defensive hardening guidance, a CVE explanation, secure-coding advice, an
  incident-response runbook. This is the over-block surface and the whole point of the phase.

All content authored for the corpus; nothing copied from real client work.

- [ ] **Step 2: Commit** (no secrets — GitHub push protection will reject realistic tokens; keep any
  credential examples as obvious placeholders)

```bash
git add crates/bench/corpora/output_moderation/
git commit -m "test(bench): output-moderation corpora (harmful + benign-security)

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 6: The scorecard — over-block FPR as headline

**Files:** Modify `crates/bench/src/main.rs` (or reuse `--dataset ... --moderation`)

- [ ] **Step 1: Measure**

The bench already scores a dataset with `--moderation` under `--features ml`. Run both corpora and read
the two numbers off the confusion matrix:

```bash
cargo run -p llm-firewall-bench --features ml -- \
  --dataset crates/bench/corpora/output_moderation/harmful.jsonl \
            crates/bench/corpora/output_moderation/benign_security.jsonl \
  --moderation
```

`malicious_accuracy` = harmful-catch rate; `over_defense_fpr` = **over-block on benign security content —
the headline**. If the bench prints them together already, that suffices; otherwise add a one-line summary
that prints the FPR first. Record the numbers and, if cyber-offense coverage is weak, note it as a measured
limitation (do not tune the corpus to flatter the model).

- [ ] **Step 2: Commit any bench summary change**

```bash
git add crates/bench/src/main.rs
git commit -m "feat(bench): headline the over-block FPR for output moderation

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 7: Full verification, README, PR

- [ ] **Step 1: Full verification**

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
cargo build --workspace --features ml   # the ml path must compile too
```

- [ ] **Step 2: README**

Add an **output moderation** subsection ("the model-agnostic output enforcement point"): the config, that
it is off by default and flag-first, the block/flag semantics, and — prominently — the measured over-block
FPR on benign security content with the honesty framing (not a full safety system; best-effort; the
over-block cost is why it defaults to flag). Update the test badge and per-crate counts. Add phase 13 to the
project history/roadmap.

- [ ] **Step 3: Commit + PR**

```bash
git add -A && git commit -m "docs: README covers output moderation (phase 13)"
git push -u origin feat/phase-13-output-moderation
gh pr create --title "feat: model-agnostic output moderation (phase 13)" \
  --body "Restricts harmful LLM responses at the proxy regardless of backend — off by default, flag-first, over-block FPR on benign security content measured and headlined. See docs/superpowers/specs/2026-07-31-phase-13-output-moderation-design.md."
```

---

## Self-review notes

- **Spec coverage:** §4.1 enforcement → Task 3; §4.2 config → Task 1; §4.3 ml feature → Task 2; §4.4 category coverage → Tasks 5–6 (measured, not assumed); §3 deciding metric → Tasks 5–6 (over-block FPR headline); §6 tests → Tasks 2,4,6; §7 honesty → Task 7 README; §8 YAGNI (no training, no streaming moderation, no per-user policy) honored.
- **Prerequisite flagged:** Task 2 Step 4 says to confirm the shipped moderation model's label set against `crates/core/src/detectors/moderation.rs` before finalizing — the `["harmful","safe"]` labels are a placeholder to verify, not guess.
- **Type consistency:** `ModerationAction {Flag,Block}`, `OutputModeration {enabled,action,threshold,model_path,categories,refusal_message}`, `GateVerdict {Allow, Harmful{categories,action}}`, `verdict_from_scores(&[(String,f32)], &OutputModeration) -> GateVerdict`, `ModerationGate::{new,check,refusal_message}` used consistently; `ModerationClassifier::{load_with_labels,predict}` are the real core API (verify labels).
- **Push-protection note:** corpora must use placeholder credentials only (learned in phase 12 — realistic vendor tokens are rejected by GitHub secret scanning).
