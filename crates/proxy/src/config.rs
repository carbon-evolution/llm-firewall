//! Proxy configuration: `firewall.yaml` with env-var overrides.

use llm_firewall_core::Normalizer;
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
    /// Base URL for the native Anthropic Messages API (`/v1/messages`).
    #[serde(default = "default_anthropic")]
    pub anthropic_base: String,
}

/// Obfuscation/evasion normalization pre-pass config (all default on except base64).
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct NormalizeCfg {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub strip_zero_width: bool,
    #[serde(default = "default_true")]
    pub fold_homoglyphs: bool,
    #[serde(default)]
    pub decode_encoded: bool,
}

impl Default for NormalizeCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            strip_zero_width: true,
            fold_homoglyphs: true,
            decode_encoded: false,
        }
    }
}

/// Agent-layer inspection of tool blocks in proxied traffic. Off by default, and
/// shadow-first (`enforce` off) when enabled — verdicts are audited but not applied.
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct AgentInspection {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub enforce: bool,
}

impl Default for AgentInspection {
    fn default() -> Self {
        Self {
            enabled: false,
            enforce: false,
        }
    }
}

impl NormalizeCfg {
    /// Build a `Normalizer` when enabled; `None` disables the pre-pass entirely.
    pub fn to_normalizer(&self) -> Option<Normalizer> {
        self.enabled.then_some(Normalizer {
            strip_zero_width: self.strip_zero_width,
            fold_homoglyphs: self.fold_homoglyphs,
            decode_encoded: self.decode_encoded,
        })
    }
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
    #[serde(default)]
    pub normalize: NormalizeCfg,
    #[serde(default)]
    pub agent_inspection: AgentInspection,
}

fn default_bind() -> String {
    "0.0.0.0:8080".into()
}
fn default_openai() -> String {
    "https://api.openai.com".into()
}
fn default_anthropic() -> String {
    "https://api.anthropic.com".into()
}
fn default_fail() -> FailMode {
    FailMode::FailClosed
}
fn default_window() -> usize {
    64
}
fn default_true() -> bool {
    true
}

impl Default for Upstream {
    fn default() -> Self {
        Self {
            openai_base: default_openai(),
            anthropic_base: default_anthropic(),
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
        if let Ok(v) = std::env::var("LLM_FW_ANTHROPIC_BASE") {
            self.upstream.anthropic_base = v;
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
    fn agent_inspection_is_off_by_default() {
        let c = Config::from_yaml("upstream: {}").unwrap();
        assert!(!c.agent_inspection.enabled, "must be opt-in");
        assert!(!c.agent_inspection.enforce, "shadow-first");
    }

    #[test]
    fn upstream_defaults() {
        // Checked via Default (not env-influenced) to avoid racing the env-override tests.
        let u = Upstream::default();
        assert_eq!(u.openai_base, "https://api.openai.com");
        assert_eq!(u.anthropic_base, "https://api.anthropic.com");
    }

    #[test]
    fn anthropic_env_override_wins() {
        std::env::set_var("LLM_FW_ANTHROPIC_BASE", "http://localhost:8888");
        let c = Config::from_yaml("upstream: {}").unwrap();
        assert_eq!(c.upstream.anthropic_base, "http://localhost:8888");
        std::env::remove_var("LLM_FW_ANTHROPIC_BASE");
    }

    #[test]
    fn env_override_wins() {
        std::env::set_var("LLM_FW_OPENAI_BASE", "http://localhost:9999");
        let c = Config::from_yaml("upstream: { openai_base: https://api.openai.com }").unwrap();
        assert_eq!(c.upstream.openai_base, "http://localhost:9999");
        std::env::remove_var("LLM_FW_OPENAI_BASE");
    }
}
