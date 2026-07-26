//! HTTP handlers: OpenAI-compatible chat completions (non-streaming path).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use llm_firewall_core::Firewall;

use crate::audit::AuditRecord;
use crate::config::{Config, FailMode};
use crate::openai::ChatRequest;
use crate::pipeline::{decide_input, decide_output};

pub struct AppState {
    pub firewall: Firewall,
    pub http: reqwest::Client,
    pub config: Config,
}

pub type Shared = Arc<AppState>;

static REQUEST_SEQ: AtomicU64 = AtomicU64::new(1);

fn next_request_id() -> String {
    format!("req-{}", REQUEST_SEQ.fetch_add(1, Ordering::Relaxed))
}

fn error_body(msg: &str) -> serde_json::Value {
    serde_json::json!({ "error": { "message": msg, "type": "llm_firewall_block" } })
}

pub async fn chat_completions(
    State(state): State<Shared>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ChatRequest>,
) -> impl IntoResponse {
    let started = Instant::now();
    let request_id = next_request_id();

    // INPUT pipeline
    let decision = decide_input(&state.firewall, req);
    if let Some(reason) = decision.block_reason {
        AuditRecord {
            request_id,
            direction: "input".into(),
            decision: "block".into(),
            score: decision.score,
            reasons: decision.reasons,
            latency_ms: started.elapsed().as_millis(),
        }
        .emit();
        return (StatusCode::BAD_REQUEST, Json(error_body(&reason))).into_response();
    }

    // FORWARD upstream
    let url = format!("{}/v1/chat/completions", state.config.upstream.openai_base);
    let mut builder = state.http.post(&url).json(&decision.request);
    // Propagate the caller's auth + OpenAI passthrough headers to upstream.
    for name in [
        "authorization",
        "openai-organization",
        "openai-project",
        "openai-beta",
    ] {
        if let Some(v) = headers.get(name) {
            builder = builder.header(name, v.clone());
        }
    }
    let upstream = builder.send().await;

    let resp = match upstream {
        Ok(r) => r,
        Err(e) => {
            let (code, body) = match state.config.fail_mode {
                FailMode::FailClosed => (
                    StatusCode::BAD_GATEWAY,
                    error_body(&format!("upstream error (fail_closed): {e}")),
                ),
                FailMode::FailOpen => (StatusCode::BAD_GATEWAY, error_body("upstream error")),
            };
            return (code, Json(body)).into_response();
        }
    };

    let status = resp.status();
    let body: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(error_body(&format!("bad upstream body: {e}"))),
            )
                .into_response()
        }
    };

    // OUTPUT pipeline: scan assistant text
    let assistant = body["choices"][0]["message"]["content"]
        .as_str()
        .unwrap_or("");
    if let Some(reason) = decide_output(&state.firewall, assistant) {
        AuditRecord {
            request_id,
            direction: "output".into(),
            decision: "block".into(),
            score: 0,
            reasons: vec![reason.clone()],
            latency_ms: started.elapsed().as_millis(),
        }
        .emit();
        return (StatusCode::BAD_GATEWAY, Json(error_body(&reason))).into_response();
    }

    AuditRecord {
        request_id,
        direction: "input".into(),
        decision: "allow".into(),
        score: decision.score,
        reasons: decision.reasons,
        latency_ms: started.elapsed().as_millis(),
    }
    .emit();

    (
        StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::OK),
        Json(body),
    )
        .into_response()
}
