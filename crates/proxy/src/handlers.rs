//! HTTP handlers: OpenAI-compatible chat completions (non-streaming path).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::response::Response;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use futures_util::StreamExt;
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

    // Streaming path: forward the SSE stream, scanning output as it flows.
    if decision.request.stream {
        return stream_completions(
            state.clone(),
            decision.request,
            headers,
            request_id,
            started,
        )
        .await;
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

/// Forward the upstream SSE stream VERBATIM (byte-for-byte), scanning a sliding tail
/// window for output-policy violations. On violation we emit a terminal error frame
/// and stop; otherwise upstream framing is preserved exactly.
async fn stream_completions(
    state: Shared,
    request: ChatRequest,
    headers: axum::http::HeaderMap,
    request_id: String,
    started: Instant,
) -> Response {
    let url = format!("{}/v1/chat/completions", state.config.upstream.openai_base);
    let mut builder = state.http.post(&url).json(&request);
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
    let upstream = match builder.send().await {
        Ok(r) => r,
        Err(_) => {
            return (StatusCode::BAD_GATEWAY, Json(error_body("upstream error"))).into_response()
        }
    };

    let content_type = upstream
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("text/event-stream")
        .to_string();

    let window = state.config.stream_window.max(16);
    let mut byte_stream = upstream.bytes_stream();

    let body = async_stream::stream! {
        let mut acc = String::new();
        while let Some(chunk) = byte_stream.next().await {
            let Ok(bytes) = chunk else { break };
            acc.push_str(&String::from_utf8_lossy(&bytes));
            // Keep only the tail window; trim on a char boundary so we never panic.
            if acc.len() > window * 4 {
                let mut cut = acc.len() - window * 4;
                while cut < acc.len() && !acc.is_char_boundary(cut) {
                    cut += 1;
                }
                acc.drain(..cut);
            }
            if decide_output(&state.firewall, &acc).is_some() {
                AuditRecord {
                    request_id: request_id.clone(),
                    direction: "output".into(),
                    decision: "block".into(),
                    score: 0,
                    reasons: vec!["output policy violation".into()],
                    latency_ms: started.elapsed().as_millis(),
                }
                .emit();
                // Terminal OpenAI-style error frame, then stop.
                yield Ok::<_, std::convert::Infallible>(axum::body::Bytes::from_static(
                    b"data: {\"error\":{\"message\":\"blocked by llm-firewall output policy\",\"type\":\"llm_firewall_block\"}}\n\ndata: [DONE]\n\n",
                ));
                return;
            }
            // Pass the upstream chunk through VERBATIM (preserves SSE framing).
            yield Ok(bytes);
        }
        AuditRecord {
            request_id,
            direction: "output".into(),
            decision: "stream_done".into(),
            score: 0,
            reasons: vec![],
            latency_ms: started.elapsed().as_millis(),
        }
        .emit();
    };

    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, content_type)
        .body(Body::from_stream(body))
        .unwrap()
}
