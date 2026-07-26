//! Proxy configuration: `firewall.yaml` with env-var overrides.

use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailMode {
    FailClosed,
    FailOpen,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Upstream {
    #[serde(default = "default_openai")]
    pub openai_base: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_bind")]
    pub bind: String,
    #[serde(default)]
    pub upstream: Upstream,
    #[serde(default)]
    pub policy_file: Option<String>,
    #[serde(default = "default_fail")]
    pub fail_mode: FailMode,
    #[serde(default = "default_window")]
    pub stream_window: usize,
}

fn default_bind() -> String {
    "0.0.0.0:8080".into()
}
fn default_openai() -> String {
    "https://api.openai.com".into()
}
fn default_fail() -> FailMode {
    FailMode::FailClosed
}
fn default_window() -> usize {
    64
}

impl Default for Upstream {
    fn default() -> Self {
        Self {
            openai_base: default_openai(),
        }
    }
}

impl Config {
    pub fn from_yaml(s: &str) -> anyhow::Result<Self> {
        let mut cfg: Config = serde_yaml::from_str(s)?;
        cfg.apply_env();
        Ok(cfg)
    }

    /// Env overrides win over the file (12-factor).
    fn apply_env(&mut self) {
        if let Ok(v) = std::env::var("LLM_FW_BIND") {
            self.bind = v;
        }
        if let Ok(v) = std::env::var("LLM_FW_OPENAI_BASE") {
            self.upstream.openai_base = v;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_defaults() {
        let c = Config::from_yaml("upstream: {}").unwrap();
        assert_eq!(c.bind, "0.0.0.0:8080");
        assert_eq!(c.fail_mode, FailMode::FailClosed);
        assert_eq!(c.stream_window, 64);
    }

    #[test]
    fn env_override_wins() {
        std::env::set_var("LLM_FW_OPENAI_BASE", "http://localhost:9999");
        let c = Config::from_yaml("upstream: { openai_base: https://api.openai.com }").unwrap();
        assert_eq!(c.upstream.openai_base, "http://localhost:9999");
        std::env::remove_var("LLM_FW_OPENAI_BASE");
    }
}
