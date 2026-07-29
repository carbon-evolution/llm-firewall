// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! `llm-firewall-agent` — agent-loop inspection. No I/O lives here.

pub mod event;

pub use event::{AgentEvent, AgentId, EventKind, Provenance, SessionId, ToolDecl, Trust};
