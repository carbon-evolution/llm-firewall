// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! The wire schema every collector produces. One shape for hooks, API traffic, and MCP.

use serde::{Deserialize, Serialize};

/// Stable id for one Claude Code session or one API conversation.
pub type SessionId = String;
/// `"main"` or a subagent name, e.g. `"osint-agent"`.
pub type AgentId = String;

/// How far content is trusted, derived from where it came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Trust {
    /// Third-party content. Never an instruction.
    Untrusted,
    /// Local, but not typed by the human.
    Semi,
    /// The human said it.
    Trusted,
}

/// Where a piece of content entered the session from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum Provenance {
    UserPrompt,
    LocalProject,
    LocalSystem,
    Network { host: String },
    McpServer { name: String },
    Subagent { name: String },
}

impl Provenance {
    pub fn trust(&self) -> Trust {
        match self {
            Provenance::UserPrompt => Trust::Trusted,
            Provenance::LocalProject | Provenance::LocalSystem => Trust::Semi,
            Provenance::Network { .. }
            | Provenance::McpServer { .. }
            | Provenance::Subagent { .. } => Trust::Untrusted,
        }
    }

    /// Short label used in policy conditions and operator messages.
    pub fn label(&self) -> String {
        match self {
            Provenance::UserPrompt => "user".into(),
            Provenance::LocalProject => "project".into(),
            Provenance::LocalSystem => "system".into(),
            Provenance::Network { host } => format!("network:{host}"),
            Provenance::McpServer { name } => format!("mcp:{name}"),
            Provenance::Subagent { name } => format!("subagent:{name}"),
        }
    }
}

/// One tool declared by an MCP server at handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolDecl {
    pub name: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventKind {
    /// A tool is about to run. This is the blockable moment.
    ToolCall {
        tool: String,
        args: serde_json::Value,
    },
    /// A tool returned; this content is about to re-enter the model's context.
    ToolResult {
        tool: String,
        content: String,
        source: Provenance,
    },
    SubagentSpawn {
        name: String,
        instructions: String,
        #[serde(default)]
        granted_tools: Vec<String>,
    },
    SubagentReport {
        name: String,
        content: String,
    },
    ManifestSeen {
        server: String,
        tools: Vec<ToolDecl>,
    },
    SessionStart,
    SessionEnd,
}

/// One observation from any collector.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentEvent {
    pub session: SessionId,
    pub agent: AgentId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<AgentId>,
    pub seq: u64,
    /// Milliseconds since the Unix epoch. Supplied by the collector; this crate has no clock.
    pub at_ms: u64,
    #[serde(flatten)]
    pub kind: EventKind,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provenance_trust_levels() {
        assert_eq!(Provenance::UserPrompt.trust(), Trust::Trusted);
        assert_eq!(Provenance::LocalProject.trust(), Trust::Semi);
        assert_eq!(Provenance::LocalSystem.trust(), Trust::Semi);
        assert_eq!(
            Provenance::Network {
                host: "evil.com".into()
            }
            .trust(),
            Trust::Untrusted
        );
        assert_eq!(
            Provenance::McpServer {
                name: "shodan".into()
            }
            .trust(),
            Trust::Untrusted
        );
        assert_eq!(
            Provenance::Subagent {
                name: "osint-agent".into()
            }
            .trust(),
            Trust::Untrusted
        );
    }

    #[test]
    fn event_round_trips_through_json() {
        let ev = AgentEvent {
            session: "s1".into(),
            agent: "main".into(),
            parent: None,
            seq: 7,
            at_ms: 1_753_000_000_000,
            kind: EventKind::ToolCall {
                tool: "Bash".into(),
                args: serde_json::json!({ "command": "ls -la" }),
            },
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: AgentEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ev);
    }

    #[test]
    fn event_kind_tag_is_snake_case() {
        let ev = EventKind::SubagentSpawn {
            name: "osint-agent".into(),
            instructions: "recon example.com".into(),
            granted_tools: vec!["WebFetch".into()],
        };
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains(r#""kind":"subagent_spawn""#), "got {json}");
    }
}
