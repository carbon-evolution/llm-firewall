// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! `agentfw` — the agent firewall daemon. The only crate performing I/O for the
//! agent layer; all verdict logic lives in `llm-firewall-agent`.

pub mod config;

pub use config::Config;
