//! Flat, first-match YAML policy engine. Policy is data, not code.

use serde::Deserialize;

// `Finding` is re-added in Task 2 when `Condition::matches` is implemented.
use crate::{Direction, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Mask,
    Block,
    Flag,
}

/// All present sub-conditions are ANDed. Absent fields are ignored.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Condition {
    #[serde(default)]
    pub detector: Option<String>,
    #[serde(default)]
    pub min_severity: Option<Severity>,
    #[serde(default)]
    pub risk_score_gte: Option<u8>,
    #[serde(default)]
    pub direction: Option<Direction>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub name: String,
    pub when: Condition,
    pub action: Action,
    #[serde(default)]
    pub message: Option<String>,
}

fn default_action() -> Action {
    Action::Allow
}

#[derive(Debug, Clone, Deserialize)]
pub struct PolicySet {
    #[serde(default)]
    pub policies: Vec<Rule>,
    #[serde(default = "default_action")]
    pub default: Action,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Decision {
    pub action: Action,
    pub rule: Option<String>,
    pub message: Option<String>,
}

impl PolicySet {
    pub fn from_yaml(s: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
policies:
  - name: block-critical-injection
    when: { detector: injection, min_severity: high }
    action: block
    message: "Prompt blocked: possible injection"
  - name: mask-pii
    when: { detector: pii }
    action: mask
default: allow
"#;

    #[test]
    fn parses_sample_policy() {
        let p = PolicySet::from_yaml(SAMPLE).expect("parse");
        assert_eq!(p.policies.len(), 2);
        assert_eq!(p.default, Action::Allow);
        assert_eq!(p.policies[0].action, Action::Block);
        assert_eq!(p.policies[0].when.detector.as_deref(), Some("injection"));
        assert_eq!(p.policies[0].when.min_severity, Some(Severity::High));
        assert_eq!(p.policies[1].action, Action::Mask);
    }
}
