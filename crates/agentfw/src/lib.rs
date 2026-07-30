// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! `agentfw` — the agent firewall daemon. The only crate performing I/O for the
//! agent layer; all verdict logic lives in `llm-firewall-agent`.

pub mod audit;
pub mod config;
pub mod decision;
pub mod handlers;
pub mod hook;
pub mod map;
pub mod provenance;
pub mod replay;
pub mod token;

use axum::routing::{get, post};
use axum::Router;

pub use config::Config;
pub use handlers::{AppState, Shared};

/// The axum router. Exposed so integration tests can drive it without a socket.
pub fn app(state: Shared) -> Router {
    Router::new()
        .route("/hook", post(handlers::hook))
        .route("/health", get(handlers::health))
        .with_state(state)
}
