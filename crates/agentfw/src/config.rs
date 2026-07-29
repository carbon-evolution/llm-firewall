// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Daemon configuration: `~/.agentfw/config.yaml` with safe defaults.

use std::path::PathBuf;

use serde::Deserialize;

fn default_bind() -> String {
    "127.0.0.1".into()
}
fn default_port() -> u16 {
    8787
}
fn default_max_record_bytes() -> usize {
    262_144
}
fn default_timeout_ms() -> u64 {
    100
}
fn default_max_body_bytes() -> usize {
    8 * 1024 * 1024
}

/// Daemon configuration. Every field has a safe default, so an absent config file
/// is equivalent to an empty one.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Loopback only. A non-loopback value is rejected at parse time.
    #[serde(default = "default_bind")]
    pub bind: String,
    #[serde(default = "default_port")]
    pub port: u16,
    /// `false` = shadow mode: verdicts are computed and logged but never enforced.
    #[serde(default)]
    pub enforce: bool,
    #[serde(default)]
    pub policy: Option<PathBuf>,
    #[serde(default)]
    pub audit: Option<PathBuf>,
    /// Cap on content handed to the taint recorder. Measured: 10 MB costs 532 ms,
    /// far past the budget for a synchronous hook. 256 KB costs roughly 13 ms.
    #[serde(default = "default_max_record_bytes")]
    pub max_record_bytes: usize,
    #[serde(default = "default_timeout_ms")]
    pub deterministic_timeout_ms: u64,
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            port: default_port(),
            enforce: false,
            policy: None,
            audit: None,
            max_record_bytes: default_max_record_bytes(),
            deterministic_timeout_ms: default_timeout_ms(),
            max_body_bytes: default_max_body_bytes(),
        }
    }
}

impl Config {
    pub fn from_yaml(s: &str) -> anyhow::Result<Self> {
        let c: Config = serde_yaml::from_str(s)?;
        c.validate()?;
        Ok(c)
    }

    /// Reject anything that would expose the daemon beyond this machine.
    fn validate(&self) -> anyhow::Result<()> {
        let ok = self.bind == "127.0.0.1" || self.bind == "::1" || self.bind == "localhost";
        anyhow::ensure!(
            ok,
            "bind must be a loopback address (127.0.0.1, ::1, localhost); got {:?}. \
             The daemon holds session data and taint state and must never be reachable off-host.",
            self.bind
        );
        Ok(())
    }

    /// `~/.agentfw`, created if absent.
    pub fn home() -> anyhow::Result<PathBuf> {
        let dir = dirs::home_dir()
            .ok_or_else(|| anyhow::anyhow!("cannot determine home directory"))?
            .join(".agentfw");
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_safe() {
        let c = Config::default();
        assert_eq!(c.bind, "127.0.0.1", "must never bind a public interface");
        assert_eq!(c.port, 8787);
        assert!(
            !c.enforce,
            "shadow mode is the default; enforcement is opt-in"
        );
        assert_eq!(c.max_record_bytes, 262_144);
        assert_eq!(c.deterministic_timeout_ms, 100);
    }

    #[test]
    fn parses_a_partial_file_and_keeps_defaults() {
        let c = Config::from_yaml("enforce: true\nport: 9001\n").unwrap();
        assert!(c.enforce);
        assert_eq!(c.port, 9001);
        assert_eq!(c.bind, "127.0.0.1");
        assert_eq!(c.max_record_bytes, 262_144);
    }

    #[test]
    fn an_empty_file_is_all_defaults() {
        let c = Config::from_yaml("{}").unwrap();
        assert_eq!(c, Config::default());
    }

    #[test]
    fn a_non_loopback_bind_is_rejected() {
        // Binding a public interface would expose session data and let any host
        // poison taint state. This must be impossible via config.
        let err = Config::from_yaml("bind: 0.0.0.0\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("loopback"), "got: {err}");
    }
}
