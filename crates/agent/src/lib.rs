// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! `llm-firewall-agent` — agent-loop inspection. No I/O lives here.

pub mod action;
pub mod event;
pub mod facet;
pub mod fingerprint;
pub mod taint;

pub use action::{classify, ActionClass};
pub use event::{AgentEvent, AgentId, EventKind, Provenance, SessionId, ToolDecl, Trust};
pub use facet::{facets, Facet};
pub use fingerprint::{fingerprints, overlap};
pub use taint::{TaintMark, TaintTracker};
