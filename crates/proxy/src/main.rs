use std::sync::Arc;

use llm_firewall::config::Config;
use llm_firewall::handlers::{AppState, Shared};
use llm_firewall::{app, build_firewall};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().json().init();

    let cfg = Config::from_yaml(&std::fs::read_to_string("firewall.yaml")?)?;
    let firewall = build_firewall(&cfg)?;
    let state: Shared = Arc::new(AppState {
        firewall,
        http: reqwest::Client::new(),
        config: cfg.clone(),
    });

    let listener = tokio::net::TcpListener::bind(&cfg.bind).await?;
    tracing::info!("llm-firewall listening on {}", cfg.bind);
    axum::serve(listener, app(state)).await?;
    Ok(())
}
