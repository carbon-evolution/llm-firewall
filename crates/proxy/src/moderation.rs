// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! The output moderation gate: runs the harmful-content classifier on a model reply
//! and returns a verdict. Feature-gated on `ml`; without it, always `Allow` (no-op),
//! so a proxy built without the model never fails — it just does not moderate.

use crate::config::{ModerationAction, OutputModeration};

/// What the gate decided about a reply.
#[derive(Debug, Clone, PartialEq)]
pub enum GateVerdict {
    /// Forward untouched.
    Allow,
    /// Harmful categories at/above threshold. `block` = refuse; `flag` = audit + forward.
    Harmful {
        categories: Vec<String>,
        action: ModerationAction,
    },
}

/// Decide the verdict from the classifier's `(category, score)` output. Pure, so the
/// policy is unit-testable without the model. A category counts if its score is at or
/// above the threshold, it is not a "safe"/"OK" label, and (when `categories` is
/// non-empty) it is in the operator's allowlist.
pub fn verdict_from_scores(scores: &[(String, f32)], cfg: &OutputModeration) -> GateVerdict {
    let hits: Vec<String> = scores
        .iter()
        .filter(|(cat, score)| {
            *score >= cfg.threshold
                && !cat.eq_ignore_ascii_case("safe")
                && !cat.eq_ignore_ascii_case("ok")
                && (cfg.categories.is_empty() || cfg.categories.iter().any(|c| c == cat))
        })
        .map(|(cat, _)| cat.clone())
        .collect();
    if hits.is_empty() {
        GateVerdict::Allow
    } else {
        GateVerdict::Harmful {
            categories: hits,
            action: cfg.action,
        }
    }
}

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
                return Self {
                    cfg,
                    classifier: None,
                };
            }
            // Binary harmful/safe head, same label assignment the benchmark uses.
            let labels = vec!["harmful".to_string(), "safe".to_string()];
            match llm_firewall_core::ModerationClassifier::load_with_labels(&cfg.model_path, labels)
            {
                Ok(clf) => {
                    tracing::info!(path = %cfg.model_path, "output moderation model loaded");
                    Self {
                        cfg,
                        classifier: Some(clf),
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "output moderation enabled but model unavailable; disabled");
                    Self {
                        cfg,
                        classifier: None,
                    }
                }
            }
        }
        #[cfg(not(feature = "ml"))]
        {
            if cfg.enabled {
                tracing::warn!(
                    "output_moderation.enabled but the proxy was built without the `ml` feature; no-op"
                );
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

    /// Strict constructor used at startup: when moderation is enabled but cannot run
    /// (built without `ml`, or the model fails to load) this is an error — the proxy
    /// refuses to start — unless `optional: true`, which keeps the old warn-and-continue.
    pub fn from_config(cfg: OutputModeration) -> anyhow::Result<Self> {
        let optional = cfg.optional;
        let enabled = cfg.enabled;
        let gate = Self::new(cfg);
        if enabled && !gate.is_live() && !optional {
            anyhow::bail!(
                "output_moderation is enabled but the moderation model is not available ({}); \
                 refusing to start. Build with `--features ml`, fetch it with \
                 `./scripts/fetch-model.sh moderation`, or set `output_moderation.enabled: false` / \
                 `output_moderation.optional: true`",
                if cfg!(feature = "ml") {
                    "model failed to load; see the warning above"
                } else {
                    "binary built without the `ml` feature"
                }
            );
        }
        Ok(gate)
    }

    /// True when the gate is live (enabled, built with `ml`, model loaded).
    pub fn is_live(&self) -> bool {
        #[cfg(feature = "ml")]
        {
            self.cfg.enabled && self.classifier.is_some()
        }
        #[cfg(not(feature = "ml"))]
        {
            false
        }
    }

    /// True when a harmful reply would be refused (`action: block` on a live gate).
    /// Streams are then held in full until moderated, since a refusal after most of
    /// the text was delivered would be meaningless.
    pub fn blocks(&self) -> bool {
        self.is_live() && self.cfg.action == ModerationAction::Block
    }

    /// One-word status for the startup log.
    pub fn status(&self) -> &'static str {
        match (self.cfg.enabled, self.is_live()) {
            (false, _) => "off",
            (true, true) => "on",
            (true, false) => "unavailable (optional)",
        }
    }

    pub fn refusal_message(&self) -> &str {
        &self.cfg.refusal_message
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(action: ModerationAction, threshold: f32, categories: Vec<String>) -> OutputModeration {
        OutputModeration {
            enabled: true,
            action,
            threshold,
            categories,
            ..Default::default()
        }
    }

    #[test]
    fn a_high_scoring_harmful_category_is_flagged() {
        let scores = vec![("harmful".to_string(), 0.95), ("safe".to_string(), 0.05)];
        let v = verdict_from_scores(&scores, &cfg(ModerationAction::Block, 0.8, vec![]));
        assert!(matches!(v, GateVerdict::Harmful { .. }));
    }

    #[test]
    fn a_below_threshold_score_is_allowed() {
        let scores = vec![("harmful".to_string(), 0.5)];
        assert_eq!(
            verdict_from_scores(&scores, &cfg(ModerationAction::Block, 0.8, vec![])),
            GateVerdict::Allow
        );
    }

    #[test]
    fn the_safe_category_never_counts() {
        let scores = vec![("safe".to_string(), 0.99)];
        assert_eq!(
            verdict_from_scores(&scores, &cfg(ModerationAction::Flag, 0.8, vec![])),
            GateVerdict::Allow
        );
    }

    #[test]
    fn the_category_allowlist_narrows_what_counts() {
        let scores = vec![("hate".to_string(), 0.95), ("hacking".to_string(), 0.95)];
        let v = verdict_from_scores(
            &scores,
            &cfg(ModerationAction::Block, 0.8, vec!["hacking".to_string()]),
        );
        match v {
            GateVerdict::Harmful { categories, .. } => {
                assert_eq!(categories, vec!["hacking".to_string()])
            }
            _ => panic!("expected harmful"),
        }
    }

    #[test]
    fn an_enabled_but_unloadable_gate_refuses_startup() {
        let cfg = OutputModeration {
            enabled: true,
            model_path: "/nonexistent/llm-firewall-moderation-model".into(),
            ..Default::default()
        };
        let err = ModerationGate::from_config(cfg.clone())
            .err()
            .expect("must fail closed");
        assert!(err.to_string().contains("refusing to start"), "{err}");
        // `optional: true` restores warn-and-continue.
        let gate = ModerationGate::from_config(OutputModeration {
            optional: true,
            ..cfg
        })
        .unwrap();
        assert!(!gate.is_live());
        assert_eq!(gate.status(), "unavailable (optional)");
        // Disabled never fails.
        assert!(ModerationGate::from_config(OutputModeration::default()).is_ok());
    }

    #[test]
    fn a_disabled_gate_is_a_no_op() {
        let gate = ModerationGate::new(OutputModeration::default());
        assert_eq!(gate.check("anything at all"), GateVerdict::Allow);
    }
}
