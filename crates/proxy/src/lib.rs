//! LLM Firewall proxy — library surface (also used by integration tests).

pub mod anthropic;
pub mod audit;
pub mod config;
pub mod handlers;
pub mod openai;
pub mod pipeline;

use axum::{routing::post, Router};
use llm_firewall_core::{
    Firewall, InjectionDetector, ModerationDetector, OutputDetector, PiiDetector, PolicySet,
    SecretDetector,
};

pub use config::{Config, FailMode};
pub use handlers::{chat_completions, messages, AppState, Shared};

/// Build the `Firewall` (detectors + policy) from config.
pub fn build_firewall(cfg: &Config) -> anyhow::Result<Firewall> {
    let policy = match &cfg.policy_file {
        Some(p) => PolicySet::from_yaml(&std::fs::read_to_string(p)?)?,
        None => PolicySet::from_yaml("default: allow")?,
    };
    Ok(Firewall::new(
        vec![
            Box::new(InjectionDetector::new()),
            Box::new(SecretDetector::new()),
            Box::new(PiiDetector::new()),
            Box::new(OutputDetector::new()),
            // Inert without the `ml` feature + a fetched model (same as injection ML).
            Box::new(ModerationDetector::new()),
        ],
        policy,
    ))
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
    }
}
