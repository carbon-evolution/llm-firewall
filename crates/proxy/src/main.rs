// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

use std::sync::Arc;

use llm_firewall::config::Config;
use llm_firewall::handlers::{AppState, Shared};
use llm_firewall::{app, build_firewall_with_stages};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().json().init();

    let cfg = Config::from_yaml(&std::fs::read_to_string("firewall.yaml")?)?;
    // Both fail closed: a configured-but-unloadable model refuses startup.
    let (firewall, stages) = build_firewall_with_stages(&cfg)?;
    let moderation =
        llm_firewall::moderation::ModerationGate::from_config(cfg.output_moderation.clone())?;
    tracing::info!(
        output_moderation = moderation.status(),
        agent_inspection = cfg.agent_inspection.enabled,
        agent_enforce = cfg.agent_inspection.enforce,
        "detection stages: {stages}"
    );
    let state: Shared = Arc::new(AppState {
        firewall,
        http: reqwest::Client::new(),
        config: cfg.clone(),
        agent: std::sync::Mutex::new(llm_firewall_agent::AgentFirewall::with_default_policy()),
        moderation,
    });

    let listener = tokio::net::TcpListener::bind(&cfg.bind).await?;
    tracing::info!("llm-firewall listening on {}", cfg.bind);
    axum::serve(listener, app(state)).await?;
    Ok(())
}
