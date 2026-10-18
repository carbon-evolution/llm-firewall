//! HTTP handlers: OpenAI-compatible chat completions + native Anthropic messages.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::extract::rejection::JsonRejection;
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
use crate::pipeline::{
    decide_error_body, decide_input_anthropic_with, decide_input_with, decide_output,
};
use crate::stream::{block_frame, scan_reply, Protocol, StreamInspector};

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

/// The protocol's own error envelope.
fn envelope(protocol: Protocol, msg: &str) -> serde_json::Value {
    match protocol {
        Protocol::OpenAi => error_body(msg),
        Protocol::Anthropic => anthropic_error_body(msg),
    }
}

/// Firewall refusal of an upstream reply: 502 with the protocol's error envelope.
fn refuse_output(protocol: Protocol, msg: &str) -> Response {
    (StatusCode::BAD_GATEWAY, Json(envelope(protocol, msg))).into_response()
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

/// A request body axum could not accept (malformed JSON, schema mismatch, wrong
/// content type, over the size limit): audit it, then return axum's own response.
/// The audit reason carries only the status — never the serde message, which can
/// quote request content.
fn reject(request_id: &str, rejection: JsonRejection, started: Instant) -> Response {
    let status = rejection.status();
    audit_input(
        request_id,
        "reject",
        0,
        vec![format!("request rejected: HTTP {}", status.as_u16())],
        Vec::new(),
        Vec::new(),
        started,
    );
    rejection.into_response()
}

// ------------------------------------------------------------------ OpenAI path

pub async fn chat_completions(
    State(state): State<Shared>,
    headers: HeaderMap,
    payload: Result<Json<ChatRequest>, JsonRejection>,
) -> Response {
    let started = Instant::now();
    let request_id = next_request_id();
    let req = match payload {
        Ok(Json(req)) => req,
        Err(rejection) => return reject(&request_id, rejection, started),
    };

    let decision = decide_input_with(&state.firewall, req, state.config.input);
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

    // The input verdict is final here; record it before the request is forwarded.
    audit_allow(
        &request_id,
        decision.score,
        decision.reasons,
        decision.owasp,
        decision.atlas,
        started,
    );
    let tool_results = if state.config.agent_inspection.enabled {
        crate::agent_scan::openai_tool_results(&decision.request)
    } else {
        Vec::new()
    };
    let url = format!("{}/v1/chat/completions", state.config.upstream.openai_base);
    let builder = forward_headers(
        state.http.post(&url).json(&decision.request),
        &headers,
        OPENAI_HEADERS,
    );
    if decision.request.stream {
        return proxy_stream(
            state.clone(),
            builder,
            request_id,
            started,
            Protocol::OpenAi,
            tool_results,
        )
        .await;
    }
    proxy_json(
        &state,
        builder,
        &request_id,
        started,
        Protocol::OpenAi,
        tool_results,
    )
    .await
}

// --------------------------------------------------------------- Anthropic path

pub async fn messages(
    State(state): State<Shared>,
    headers: HeaderMap,
    payload: Result<Json<AnthropicRequest>, JsonRejection>,
) -> Response {
    let started = Instant::now();
    let request_id = next_request_id();
    let req = match payload {
        Ok(Json(req)) => req,
        Err(rejection) => return reject(&request_id, rejection, started),
    };

    let decision = decide_input_anthropic_with(&state.firewall, req, state.config.input);
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

    audit_allow(
        &request_id,
        decision.score,
        decision.reasons,
        decision.owasp,
        decision.atlas,
        started,
    );
    let tool_results = if state.config.agent_inspection.enabled {
        let req_value = serde_json::to_value(&decision.request).unwrap_or_default();
        crate::agent_scan::anthropic_tool_results(&req_value)
    } else {
        Vec::new()
    };
    let url = format!("{}/v1/messages", state.config.upstream.anthropic_base);
    let builder = forward_headers(
        state.http.post(&url).json(&decision.request),
        &headers,
        ANTHROPIC_HEADERS,
    );
    if decision.request.stream {
        return proxy_stream(
            state.clone(),
            builder,
            request_id,
            started,
            Protocol::Anthropic,
            tool_results,
        )
        .await;
    }
    proxy_json(
        &state,
        builder,
        &request_id,
        started,
        Protocol::Anthropic,
        tool_results,
    )
    .await
}

// ------------------------------------------------------------------- shared bits

/// Forward a non-streaming request and inspect the reply before it reaches the client:
/// a non-200 body is scanned as an error body; a 200 reply has every output surface
/// scanned ([`scan_reply`]), then agent inspection and output moderation run.
async fn proxy_json(
    state: &Shared,
    builder: reqwest::RequestBuilder,
    request_id: &str,
    started: Instant,
    protocol: Protocol,
    tool_results: Vec<String>,
) -> Response {
    let (status, body) = match forward_json(state, builder, protocol).await {
        Ok(pair) => pair,
        Err(resp) => {
            audit_output(request_id, "upstream_error", "upstream failure", started);
            return *resp;
        }
    };

    if status != StatusCode::OK {
        // Error bodies can echo request content or carry upstream detail.
        if let Some(reason) = decide_error_body(&state.firewall, &body) {
            audit_output_block(request_id, &reason, started);
            return refuse_output(protocol, &reason);
        }
        audit_output(
            request_id,
            "upstream_error",
            &format!("upstream status {}", status.as_u16()),
            started,
        );
        return (status, Json(body)).into_response();
    }

    let reply = match scan_reply(protocol, &state.firewall, &body) {
        Ok(reply) => reply,
        Err(reason) => {
            audit_output_block(request_id, &reason, started);
            return refuse_output(protocol, &reason);
        }
    };

    // Agent layer: inspect the response's tool calls against the request's tool
    // results. (Streams run the same check at end of stream in `proxy_stream`.)
    if state.config.agent_inspection.enabled {
        let calls = match protocol {
            Protocol::OpenAi => crate::agent_scan::openai_tool_calls(&body),
            Protocol::Anthropic => crate::agent_scan::anthropic_tool_calls(&body),
        };
        if let Some(reason) = agent_refuse_reason(state, request_id, tool_results, calls) {
            audit_output_block(request_id, &reason, started);
            return refuse_output(protocol, &reason);
        }
    }

    // Output content moderation: restrict a harmful reply regardless of backend.
    // `block` refuses (502, like any other output block), `flag` audits and forwards.
    if let crate::moderation::GateVerdict::Harmful { categories, action } =
        state.moderation.check(&reply)
    {
        tracing::warn!(?categories, ?action, "output moderation: harmful reply");
        if action == crate::config::ModerationAction::Block {
            let msg = state.moderation.refusal_message().to_string();
            audit_output_block(request_id, &msg, started);
            return refuse_output(protocol, &msg);
        }
    }

    (StatusCode::OK, Json(body)).into_response()
}

/// Send a non-streaming upstream request and parse the JSON body. On transport/body
/// failure returns a ready `Response` (respecting fail mode) via `Err`, boxed so the
/// cold-path error does not bloat the `Result` (clippy::result_large_err). The client
/// gets a generic message; the detail (which names the upstream URL) is only logged.
async fn forward_json(
    state: &Shared,
    builder: reqwest::RequestBuilder,
    protocol: Protocol,
) -> Result<(StatusCode, serde_json::Value), Box<Response>> {
    let resp = match builder.send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "upstream request failed");
            let msg = match state.config.fail_mode {
                FailMode::FailClosed => "upstream error (fail_closed)",
                FailMode::FailOpen => "upstream error",
            };
            return Err(Box::new(refuse_output(protocol, msg)));
        }
    };
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    match resp.json::<serde_json::Value>().await {
        Ok(v) => Ok((status, v)),
        Err(e) => {
            tracing::warn!(error = %e, upstream_status = status.as_u16(), "unreadable upstream body");
            Err(Box::new(refuse_output(protocol, "bad upstream body")))
        }
    }
}

/// Proxy an upstream SSE stream through the [`StreamInspector`]: events are parsed,
/// their text reassembled per choice / content block and scanned with the same output
/// policy as non-streamed replies, and released (verbatim, in order) only once the
/// text they carry is outside the hold-back window. On a block the client gets a
/// terminal error event in the protocol's format and the upstream is dropped.
async fn proxy_stream(
    state: Shared,
    builder: reqwest::RequestBuilder,
    request_id: String,
    started: Instant,
    protocol: Protocol,
    tool_results: Vec<String>,
) -> Response {
    let upstream = match builder.send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "upstream request failed");
            audit_output(&request_id, "upstream_error", "upstream failure", started);
            return refuse_output(protocol, "upstream error");
        }
    };

    let status =
        StatusCode::from_u16(upstream.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let content_type = upstream
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("text/event-stream")
        .to_string();

    if status != StatusCode::OK {
        // An error reply is a plain (JSON) body, not an event stream: read it whole,
        // scan it like a non-streamed error body, and forward it verbatim if clean.
        let bytes = match upstream.bytes().await {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, "unreadable upstream error body");
                audit_output(&request_id, "upstream_error", "upstream failure", started);
                return refuse_output(protocol, "bad upstream body");
            }
        };
        let verdict = match serde_json::from_slice::<serde_json::Value>(&bytes) {
            Ok(v) => decide_error_body(&state.firewall, &v),
            Err(_) => {
                let text = String::from_utf8_lossy(&bytes);
                (!text.trim().is_empty())
                    .then(|| decide_output(&state.firewall, &text))
                    .flatten()
            }
        };
        if let Some(reason) = verdict {
            audit_output_block(&request_id, &reason, started);
            return refuse_output(protocol, &reason);
        }
        audit_output(
            &request_id,
            "upstream_error",
            &format!("upstream status {}", status.as_u16()),
            started,
        );
        return Response::builder()
            .status(status)
            .header(CONTENT_TYPE, content_type)
            .body(Body::from(bytes))
            .unwrap();
    }

    let agent_enforce =
        state.config.agent_inspection.enabled && state.config.agent_inspection.enforce;
    let mut inspector = StreamInspector::new(
        protocol,
        state.config.effective_holdback(),
        agent_enforce,
        state.moderation.blocks(),
    );
    let mut byte_stream = upstream.bytes_stream();

    let body = async_stream::stream! {
        let mut upstream_failed = false;
        loop {
            match byte_stream.next().await {
                Some(Ok(bytes)) => match inspector.push(&state.firewall, &bytes) {
                    Ok(out) => {
                        if !out.is_empty() {
                            yield Ok::<_, std::convert::Infallible>(axum::body::Bytes::from(out));
                        }
                    }
                    Err(reason) => {
                        // Returning drops `byte_stream`, which closes the upstream.
                        audit_output_block(&request_id, &reason, started);
                        yield Ok(block_frame(protocol, &reason).into());
                        return;
                    }
                },
                Some(Err(e)) => {
                    tracing::warn!(error = %e, request_id = %request_id, "upstream stream error");
                    upstream_failed = true;
                    break;
                }
                None => break,
            }
        }

        // End of upstream: full scan of every channel, then the end-of-reply checks.
        if let Err(reason) = inspector.finish(&state.firewall) {
            audit_output_block(&request_id, &reason, started);
            yield Ok(block_frame(protocol, &reason).into());
            return;
        }
        if state.config.agent_inspection.enabled {
            let calls = inspector.tool_calls();
            if let Some(reason) = agent_refuse_reason(&state, &request_id, tool_results, calls) {
                audit_output_block(&request_id, &reason, started);
                yield Ok(block_frame(protocol, &reason).into());
                return;
            }
        }
        let reply = inspector.reply_text();
        if !reply.is_empty() {
            if let crate::moderation::GateVerdict::Harmful { categories, action } =
                state.moderation.check(&reply)
            {
                tracing::warn!(?categories, ?action, "output moderation: harmful streamed reply");
                if action == crate::config::ModerationAction::Block {
                    let msg = state.moderation.refusal_message().to_string();
                    audit_output_block(&request_id, &msg, started);
                    yield Ok(block_frame(protocol, &msg).into());
                    return;
                }
            }
        }

        let rest = inspector.drain_all();
        if !rest.is_empty() {
            yield Ok(rest.into());
        }
        let decision = if upstream_failed && state.config.fail_mode == FailMode::FailClosed {
            // Everything received was scanned and released; tell the client the reply
            // is truncated rather than ending as if it were complete.
            yield Ok(block_frame(protocol, "upstream stream interrupted").into());
            "stream_error"
        } else {
            "stream_done"
        };
        AuditRecord {
            request_id,
            direction: "output".into(),
            decision: decision.into(),
            score: 0,
            reasons: vec![],
            owasp: Vec::new(),
            atlas: Vec::new(),
            latency_ms: started.elapsed().as_millis(),
        }
        .emit();
    };

    Response::builder()
        .status(status)
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

/// An output-direction audit record with one reason label.
fn audit_output(request_id: &str, decision: &str, reason: &str, started: Instant) {
    AuditRecord {
        request_id: request_id.to_string(),
        direction: "output".into(),
        decision: decision.into(),
        score: 0,
        reasons: vec![reason.to_string()],
        owasp: Vec::new(),
        atlas: Vec::new(),
        latency_ms: started.elapsed().as_millis(),
    }
    .emit();
}

fn audit_output_block(request_id: &str, reason: &str, started: Instant) {
    audit_output(request_id, "block", reason, started);
}
