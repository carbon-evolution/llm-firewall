//! HTTP handlers: OpenAI-compatible chat completions + native Anthropic messages.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::HeaderMap;
use axum::response::Response;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use futures_util::StreamExt;
use llm_firewall_core::Firewall;

use crate::anthropic::AnthropicRequest;
use crate::audit::AuditRecord;
use crate::config::{Config, FailMode};
use crate::openai::ChatRequest;
use crate::pipeline::{decide_input, decide_input_anthropic, decide_output};

pub struct AppState {
    pub firewall: Firewall,
    pub http: reqwest::Client,
    pub config: Config,
    /// Agent-layer firewall for tool-block inspection. Behind a Mutex because
    /// `inspect` takes `&mut self`. Only consulted when `agent_inspection.enabled`.
    pub agent: std::sync::Mutex<llm_firewall_agent::AgentFirewall>,
    /// Output content moderation gate. `check` is a no-op unless enabled + `ml` + model.
    pub moderation: crate::moderation::ModerationGate,
}

/// Run agent inspection over a response's tool calls against the request's tool
/// results. Returns `Some(reason)` only when the verdict is `Deny` *and* enforcement
/// is on — the caller then refuses the response. Otherwise the verdict is audited
/// (via the tracing warning) and the response passes: shadow-first.
fn agent_refuse_reason(
    state: &AppState,
    request_id: &str,
    results: Vec<String>,
    calls: Vec<crate::agent_scan::ToolCall>,
) -> Option<String> {
    if calls.is_empty() {
        return None;
    }
    let v = {
        let mut fw = state.agent.lock().expect("agent mutex");
        crate::agent_scan::inspect_cycle(&mut fw, request_id, &results, &calls)
    };
    if matches!(v.verdict, llm_firewall_agent::Verdict::Allow) {
        return None;
    }
    tracing::warn!(
        cycle = %request_id,
        verdict = ?v.verdict,
        reason = ?v.reason,
        "agent verdict on a response tool_use"
    );
    if state.config.agent_inspection.enforce
        && matches!(v.verdict, llm_firewall_agent::Verdict::Deny)
    {
        return Some(
            v.reason
                .unwrap_or_else(|| "agent policy denied a tool call".into()),
        );
    }
    None
}

pub type Shared = Arc<AppState>;

static REQUEST_SEQ: AtomicU64 = AtomicU64::new(1);

fn next_request_id() -> String {
    format!("req-{}", REQUEST_SEQ.fetch_add(1, Ordering::Relaxed))
}

/// OpenAI-style error envelope.
fn error_body(msg: &str) -> serde_json::Value {
    serde_json::json!({ "error": { "message": msg, "type": "llm_firewall_block" } })
}

/// Anthropic-style error envelope.
fn anthropic_error_body(msg: &str) -> serde_json::Value {
    serde_json::json!({ "type": "error", "error": { "type": "invalid_request_error", "message": msg } })
}

/// Propagate the listed caller headers to the upstream request (case-insensitive).
fn forward_headers(
    mut builder: reqwest::RequestBuilder,
    headers: &HeaderMap,
    names: &[&str],
) -> reqwest::RequestBuilder {
    for name in names {
        if let Some(v) = headers.get(*name) {
            builder = builder.header(*name, v.clone());
        }
    }
    builder
}

const OPENAI_HEADERS: &[&str] = &[
    "authorization",
    "openai-organization",
    "openai-project",
    "openai-beta",
];
const ANTHROPIC_HEADERS: &[&str] = &[
    "x-api-key",
    "anthropic-version",
    "anthropic-beta",
    "authorization",
];

// ------------------------------------------------------------------ OpenAI path

pub async fn chat_completions(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(req): Json<ChatRequest>,
) -> impl IntoResponse {
    let started = Instant::now();
    let request_id = next_request_id();

    let decision = decide_input(&state.firewall, req);
    if let Some(reason) = decision.block_reason {
        audit_block(
            &request_id,
            decision.score,
            decision.reasons,
            decision.owasp,
            decision.atlas,
            started,
        );
        return (StatusCode::BAD_REQUEST, Json(error_body(&reason))).into_response();
    }

    let url = format!("{}/v1/chat/completions", state.config.upstream.openai_base);
    if decision.request.stream {
        let builder = forward_headers(
            state.http.post(&url).json(&decision.request),
            &headers,
            OPENAI_HEADERS,
        );
        return proxy_stream(
            state.clone(),
            builder,
            request_id,
            started,
            OPENAI_BLOCK_FRAME,
        )
        .await;
    }

    let builder = forward_headers(
        state.http.post(&url).json(&decision.request),
        &headers,
        OPENAI_HEADERS,
    );
    let (status, body) = match forward_json(&state, builder).await {
        Ok(pair) => pair,
        Err(resp) => return resp,
    };
    if status != StatusCode::OK {
        return (status, Json(body)).into_response();
    }

    let assistant = body["choices"][0]["message"]["content"]
        .as_str()
        .unwrap_or("");
    if let Some(reason) = decide_output(&state.firewall, assistant) {
        audit_output_block(&request_id, &reason, started);
        return (StatusCode::BAD_GATEWAY, Json(error_body(&reason))).into_response();
    }

    // Agent layer: inspect the response's tool calls against the request's tool
    // results. Non-streaming only (this is past the stream early-return).
    if state.config.agent_inspection.enabled {
        let results = crate::agent_scan::openai_tool_results(&decision.request);
        let calls = crate::agent_scan::openai_tool_calls(&body);
        if let Some(reason) = agent_refuse_reason(&state, &request_id, results, calls) {
            audit_output_block(&request_id, &reason, started);
            return (StatusCode::BAD_GATEWAY, Json(error_body(&reason))).into_response();
        }
    }

    // Output content moderation: restrict a harmful reply regardless of backend.
    // Non-streaming only (v1); `block` refuses, `flag` audits and forwards.
    if !decision.request.stream {
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

    audit_allow(
        &request_id,
        decision.score,
        decision.reasons,
        decision.owasp,
        decision.atlas,
        started,
    );
    (StatusCode::OK, Json(body)).into_response()
}

// --------------------------------------------------------------- Anthropic path

pub async fn messages(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(req): Json<AnthropicRequest>,
) -> impl IntoResponse {
    let started = Instant::now();
    let request_id = next_request_id();

    let decision = decide_input_anthropic(&state.firewall, req);
    if let Some(reason) = decision.block_reason {
        audit_block(
            &request_id,
            decision.score,
            decision.reasons,
            decision.owasp,
            decision.atlas,
            started,
        );
        return (StatusCode::BAD_REQUEST, Json(anthropic_error_body(&reason))).into_response();
    }

    let url = format!("{}/v1/messages", state.config.upstream.anthropic_base);
    if decision.request.stream {
        let builder = forward_headers(
            state.http.post(&url).json(&decision.request),
            &headers,
            ANTHROPIC_HEADERS,
        );
        return proxy_stream(
            state.clone(),
            builder,
            request_id,
            started,
            ANTHROPIC_BLOCK_FRAME,
        )
        .await;
    }

    let builder = forward_headers(
        state.http.post(&url).json(&decision.request),
        &headers,
        ANTHROPIC_HEADERS,
    );
    let (status, body) = match forward_json(&state, builder).await {
        Ok(pair) => pair,
        Err(resp) => return resp,
    };
    if status != StatusCode::OK {
        return (status, Json(body)).into_response();
    }

    // Anthropic replies carry an array of content blocks; scan the concatenated text.
    let assistant = body["content"]
        .as_array()
        .map(|blocks| {
            blocks
                .iter()
                .filter(|b| b["type"] == "text")
                .filter_map(|b| b["text"].as_str())
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default();
    if let Some(reason) = decide_output(&state.firewall, &assistant) {
        audit_output_block(&request_id, &reason, started);
        return (StatusCode::BAD_GATEWAY, Json(anthropic_error_body(&reason))).into_response();
    }

    // Agent layer: inspect the response's tool_use blocks against the request's
    // tool_result blocks. Non-streaming only.
    if state.config.agent_inspection.enabled {
        let req_value = serde_json::to_value(&decision.request).unwrap_or_default();
        let results = crate::agent_scan::anthropic_tool_results(&req_value);
        let calls = crate::agent_scan::anthropic_tool_calls(&body);
        if let Some(reason) = agent_refuse_reason(&state, &request_id, results, calls) {
            audit_output_block(&request_id, &reason, started);
            return (StatusCode::BAD_GATEWAY, Json(anthropic_error_body(&reason))).into_response();
        }
    }

    // Output content moderation (see the OpenAI path). Non-streaming only.
    if !decision.request.stream {
        if let crate::moderation::GateVerdict::Harmful { categories, action } =
            state.moderation.check(&assistant)
        {
            tracing::warn!(?categories, ?action, "output moderation: harmful reply");
            if action == crate::config::ModerationAction::Block {
                let msg = state.moderation.refusal_message().to_string();
                audit_output_block(&request_id, &msg, started);
                return (StatusCode::OK, Json(anthropic_error_body(&msg))).into_response();
            }
        }
    }

    audit_allow(
        &request_id,
        decision.score,
        decision.reasons,
        decision.owasp,
        decision.atlas,
        started,
    );
    (StatusCode::OK, Json(body)).into_response()
}

// ------------------------------------------------------------------- shared bits

/// Send a non-streaming upstream request and parse the JSON body. On transport/body
/// failure returns a ready `Response` (respecting fail mode) via `Err`.
async fn forward_json(
    state: &Shared,
    builder: reqwest::RequestBuilder,
) -> Result<(StatusCode, serde_json::Value), Response> {
    let resp = match builder.send().await {
        Ok(r) => r,
        Err(e) => {
            let msg = match state.config.fail_mode {
                FailMode::FailClosed => format!("upstream error (fail_closed): {e}"),
                FailMode::FailOpen => "upstream error".to_string(),
            };
            return Err((StatusCode::BAD_GATEWAY, Json(error_body(&msg))).into_response());
        }
    };
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    match resp.json::<serde_json::Value>().await {
        Ok(v) => Ok((status, v)),
        Err(e) => Err((
            StatusCode::BAD_GATEWAY,
            Json(error_body(&format!("bad upstream body: {e}"))),
        )
            .into_response()),
    }
}

const OPENAI_BLOCK_FRAME: &[u8] =
    b"data: {\"error\":{\"message\":\"blocked by llm-firewall output policy\",\"type\":\"llm_firewall_block\"}}\n\ndata: [DONE]\n\n";
const ANTHROPIC_BLOCK_FRAME: &[u8] =
    b"event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"invalid_request_error\",\"message\":\"blocked by llm-firewall output policy\"}}\n\n";

/// Forward the upstream SSE stream VERBATIM (byte-for-byte), scanning a sliding tail
/// window for output-policy violations. On violation we emit `block_frame` and stop;
/// otherwise upstream framing is preserved exactly.
async fn proxy_stream(
    state: Shared,
    builder: reqwest::RequestBuilder,
    request_id: String,
    started: Instant,
    block_frame: &'static [u8],
) -> Response {
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
                    owasp: Vec::new(),
                    atlas: Vec::new(),
                    latency_ms: started.elapsed().as_millis(),
                }
                .emit();
                yield Ok::<_, std::convert::Infallible>(axum::body::Bytes::from_static(block_frame));
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
            owasp: Vec::new(),
            atlas: Vec::new(),
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

#[allow(clippy::too_many_arguments)]
fn audit_input(
    request_id: &str,
    decision: &str,
    score: u8,
    reasons: Vec<String>,
    owasp: Vec<String>,
    atlas: Vec<String>,
    started: Instant,
) {
    AuditRecord {
        request_id: request_id.to_string(),
        direction: "input".into(),
        decision: decision.into(),
        score,
        reasons,
        owasp,
        atlas,
        latency_ms: started.elapsed().as_millis(),
    }
    .emit();
}

fn audit_block(
    request_id: &str,
    score: u8,
    reasons: Vec<String>,
    owasp: Vec<String>,
    atlas: Vec<String>,
    started: Instant,
) {
    audit_input(request_id, "block", score, reasons, owasp, atlas, started);
}

fn audit_allow(
    request_id: &str,
    score: u8,
    reasons: Vec<String>,
    owasp: Vec<String>,
    atlas: Vec<String>,
    started: Instant,
) {
    audit_input(request_id, "allow", score, reasons, owasp, atlas, started);
}

fn audit_output_block(request_id: &str, reason: &str, started: Instant) {
    AuditRecord {
        request_id: request_id.to_string(),
        direction: "output".into(),
        decision: "block".into(),
        score: 0,
        reasons: vec![reason.to_string()],
        owasp: Vec::new(),
        atlas: Vec::new(),
        latency_ms: started.elapsed().as_millis(),
    }
    .emit();
}
