// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! LLM Firewall proxy — library surface (also used by integration tests).

pub mod agent_scan;
pub mod anthropic;
pub mod audit;
pub mod config;
pub mod handlers;
pub mod moderation;
pub mod openai;
pub mod pipeline;
pub mod stream;

use axum::{routing::post, Router};
use llm_firewall_core::{
    Firewall, InjectionDetector, ModerationDetector, OutputDetector, PiiDetector, PolicySet,
    SecretDetector,
};

pub use config::{Config, FailMode};
pub use handlers::{chat_completions, messages, AppState, Shared};

/// Which detection stages a built firewall actually runs (logged at startup).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveStages {
    /// The DeBERTa injection classifier is attached (`Some(model_dir)`), or not.
    pub injection_ml: Option<String>,
    /// Why the injection classifier is off, when it is.
    pub injection_ml_off_reason: Option<String>,
    pub normalize: bool,
}

impl std::fmt::Display for ActiveStages {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "injection rules+heuristics: on; injection ML: ")?;
        match (&self.injection_ml, &self.injection_ml_off_reason) {
            (Some(dir), _) => write!(f, "on ({dir})")?,
            (None, Some(why)) => write!(f, "off ({why})")?,
            (None, None) => write!(f, "off")?,
        }
        write!(
            f,
            "; secret, PII, output: on; normalization: {}",
            if self.normalize { "on" } else { "off" }
        )
    }
}

/// Build the injection detector per `injection.ml`. Fails (refusing startup) when the
/// classifier is wanted but unavailable, unless `optional: true`.
fn build_injection(cfg: &config::InjectionMl) -> anyhow::Result<(InjectionDetector, ActiveStages)> {
    let mut stages = ActiveStages {
        injection_ml: None,
        injection_ml_off_reason: None,
        normalize: false,
    };
    if !cfg.wanted() {
        stages.injection_ml_off_reason = Some(if cfg!(feature = "ml") {
            "disabled by injection.ml.enabled: false".into()
        } else {
            "binary built without the `ml` feature".into()
        });
        return Ok((InjectionDetector::new(), stages));
    }
    match load_injection_ml(cfg) {
        Ok(det) => {
            stages.injection_ml = Some(cfg.model_dir.clone());
            Ok((det, stages))
        }
        Err(e) if cfg.optional => {
            tracing::warn!(
                error = %e,
                "injection.ml is enabled but unavailable; continuing WITHOUT the ML stage (optional: true)"
            );
            stages.injection_ml_off_reason = Some(format!("unavailable, optional: {e}"));
            Ok((InjectionDetector::new(), stages))
        }
        Err(e) => Err(e.context(
            "injection.ml is enabled but the classifier could not be loaded; refusing to start. \
             Fetch it with `./scripts/fetch-model.sh injection`, point `injection.ml.model_dir` at it, \
             or set `injection.ml.enabled: false` (rules only) / `injection.ml.optional: true`",
        )),
    }
}

#[cfg(feature = "ml")]
fn load_injection_ml(cfg: &config::InjectionMl) -> anyhow::Result<InjectionDetector> {
    let clf = llm_firewall_core::MlClassifier::load(&cfg.model_dir)
        .map_err(|e| anyhow::anyhow!("load {}: {e:#}", cfg.model_dir))?;
    Ok(InjectionDetector::new()
        .with_ml(clf)
        .with_ml_threshold(cfg.threshold))
}

#[cfg(not(feature = "ml"))]
fn load_injection_ml(_cfg: &config::InjectionMl) -> anyhow::Result<InjectionDetector> {
    anyhow::bail!("this binary was built without the `ml` feature (rebuild with `--features ml`)")
}

/// Build the `Firewall` (detectors + policy) from config.
pub fn build_firewall(cfg: &Config) -> anyhow::Result<Firewall> {
    build_firewall_with_stages(cfg).map(|(fw, _)| fw)
}

/// Build the `Firewall` and report which detection stages are active.
pub fn build_firewall_with_stages(cfg: &Config) -> anyhow::Result<(Firewall, ActiveStages)> {
    let policy = match &cfg.policy_file {
        Some(p) => PolicySet::from_yaml(&std::fs::read_to_string(p)?)?,
        None => PolicySet::from_yaml("default: allow")?,
    };
    let (injection, mut stages) = build_injection(&cfg.injection.ml)?;
    let mut fw = Firewall::new(
        vec![
            Box::new(injection),
            Box::new(SecretDetector::new()),
            Box::new(PiiDetector::new()),
            Box::new(OutputDetector::new()),
            // Inert placeholder: replies are moderated by `ModerationGate`, not here.
            Box::new(ModerationDetector::new()),
        ],
        policy,
    );
    if let Some(n) = cfg.normalize.to_normalizer() {
        fw = fw.with_normalizer(n);
        stages.normalize = true;
    }
    Ok((fw, stages))
}

/// The axum router.
pub fn app(state: Shared) -> Router {
    Router::new()
        .route("/v1/chat/completions", post(chat_completions))
        .route("/v1/messages", post(messages))
        .with_state(state)
}

/// Test helper: a `Config` pointing upstream at `base`, fail_closed, no policy file.
pub fn test_config(base: String) -> Config {
    Config {
        bind: "127.0.0.1:0".into(),
        upstream: config::Upstream {
            openai_base: base.clone(),
            anthropic_base: base,
        },
        policy_file: None,
        fail_mode: FailMode::FailClosed,
        stream_window: 64,
        stream_holdback_bytes: 256,
        normalize: config::NormalizeCfg::default(),
        agent_inspection: config::AgentInspection::default(),
        output_moderation: config::OutputModeration::default(),
        injection: config::InjectionCfg {
            ml: config::InjectionMl::disabled(),
        },
        input: config::InputCfg::default(),
    }
}
