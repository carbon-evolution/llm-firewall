// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! HTTP surface: `POST /hook` for every hook event, `GET /health` for liveness.
//! No detection logic lives here — verdicts come from `llm-firewall-agent`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use llm_firewall_agent::AgentFirewall;

use crate::audit::{AuditFinding, AuditLine, AuditSink, AuditTaint};
use crate::config::Config;
use crate::decision;
use crate::hook::{HookEvent, HookPayload};
use crate::map;

/// Per-session monotonic sequence numbers.
#[derive(Default)]
pub struct Sessions {
    counters: Mutex<HashMap<String, u64>>,
}

impl Sessions {
    pub fn next(&self, session: &str) -> u64 {
        let mut m = self.counters.lock().expect("sessions mutex");
        let c = m.entry(session.to_string()).or_insert(0);
        *c += 1;
        *c
    }

    pub fn end(&self, session: &str) {
        self.counters
            .lock()
            .expect("sessions mutex")
            .remove(session);
    }
}

/// All state shared across hook requests.
pub struct AppState {
    pub firewall: Mutex<AgentFirewall>,
    pub sessions: Sessions,
    pub audit: AuditSink,
    pub config: Config,
    pub token: String,
}

pub type Shared = Arc<AppState>;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Liveness probe. Also reports whether enforcement is on, so `curl`ing it tells
/// an operator at a glance whether a blocked call is expected behavior.
pub async fn health(State(st): State<Shared>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "enforce": st.config.enforce,
    }))
}

/// Every hook event lands here. On ANY internal failure this returns 200 with an
/// empty body, which Claude Code treats as "no opinion" — a security tool that
/// wedges the agent loop gets uninstalled the same day.
pub async fn hook(
    State(st): State<Shared>,
    headers: HeaderMap,
    body: String,
) -> (StatusCode, Json<serde_json::Value>) {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !crate::token::verify(&st.token, auth) {
        tracing::warn!("rejected an unauthenticated hook request");
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({})));
    }

    if body.len() > st.config.max_body_bytes {
        tracing::warn!(
            len = body.len(),
            "hook body over cap; proceeding without inspection"
        );
        return (StatusCode::OK, Json(serde_json::json!({})));
    }

    let started = Instant::now();

    let payload: HookPayload = match serde_json::from_str(&body) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "unparsable hook payload; proceeding");
            return (StatusCode::OK, Json(serde_json::json!({})));
        }
    };

    // An event kind this build does not know about, or a session id too degenerate
    // to key taint by (see `map::to_event`): record it with its raw bytes (a
    // re-serialized `Unknown` would be lossy) and proceed.
    let seq = st.sessions.next(&payload.session_id);
    let Some(event) = map::to_event(&payload, seq, now_ms(), st.config.max_record_bytes) else {
        tracing::warn!(session = %payload.session_id, "unrecognized hook event");
        let _ = st.audit.write(&AuditLine {
            at_ms: now_ms(),
            session: payload.session_id.clone(),
            seq,
            event: "unknown".into(),
            tool: payload.tool_name.clone(),
            verdict: "allow".into(),
            shadow: !st.config.enforce,
            rule: None,
            risk_score: 0,
            findings: vec![],
            taint: None,
            egress_hosts: vec![],
            latency_us: started.elapsed().as_micros(),
            truncated: false,
            raw: Some(body),
        });
        return (StatusCode::OK, Json(serde_json::json!({})));
    };

    let is_pre = payload.event == HookEvent::PreToolUse;
    if payload.event == HookEvent::SessionEnd {
        st.sessions.end(&payload.session_id);
    }

    // `AgentFirewall::inspect` takes `&mut self`, so the guard must be held across
    // the call. Scoped in its own block so the `std::sync::Mutex` guard is dropped
    // before the function's first `.await` — nothing here awaits while it is held.
    let outcome = {
        let mut fw = st.firewall.lock().expect("firewall mutex");
        fw.inspect(&event)
    };

    let d = decision::decide(
        outcome.verdict,
        outcome.rule.as_deref(),
        outcome.message.as_deref(),
        st.config.enforce,
    );

    let _ = st.audit.write(&AuditLine {
        at_ms: event.at_ms,
        session: payload.session_id.clone(),
        seq,
        event: format!("{:?}", payload.event).to_lowercase(),
        tool: payload.tool_name.clone(),
        verdict: format!("{:?}", d.would_have_been).to_lowercase(),
        shadow: d.shadow,
        rule: outcome.rule.clone(),
        risk_score: outcome.risk_score,
        findings: outcome
            .findings
            .iter()
            .map(|(_, f)| AuditFinding {
                detector: f.detector.clone(),
                severity: format!("{:?}", f.severity).to_lowercase(),
                owasp: f.owasp.clone(),
                atlas: f.atlas.clone(),
            })
            .collect(),
        taint: outcome.taint.as_ref().map(|t| AuditTaint {
            source: t.source.label(),
            seq: t.seq,
        }),
        egress_hosts: outcome.egress_hosts.clone(),
        latency_us: started.elapsed().as_micros(),
        truncated: false,
        raw: None,
    });

    // Only PreToolUse carries a decision. Everything else mutates state only —
    // this is what "detect and gate, never rewrite" means concretely.
    if is_pre && d.permission_decision != "defer" {
        let out =
            serde_json::to_value(d.to_hook_output()).unwrap_or_else(|_| serde_json::json!({}));
        return (StatusCode::OK, Json(out));
    }
    (StatusCode::OK, Json(serde_json::json!({})))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_sequence_numbers_are_monotonic_and_per_session() {
        let s = Sessions::default();
        assert_eq!(s.next("a"), 1);
        assert_eq!(s.next("a"), 2);
        assert_eq!(
            s.next("b"),
            1,
            "sequences must not be shared across sessions"
        );
        assert_eq!(s.next("a"), 3);
    }

    #[test]
    fn ending_a_session_resets_its_sequence() {
        let s = Sessions::default();
        s.next("a");
        s.next("a");
        s.end("a");
        assert_eq!(s.next("a"), 1);
    }
}
