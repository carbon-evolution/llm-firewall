// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Flat, first-match YAML policy over agent signals. Mirrors `core::policy` in shape
//! so operators only learn one format.

use llm_firewall_core::{Finding, Severity};
use serde::Deserialize;

use crate::action::ActionClass;
use crate::egress::is_allowed;
use crate::event::Provenance;
use crate::facet::Facet;
use crate::taint::TaintMark;

/// What to do about an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Allow,
    /// Pause and put the decision to the human.
    Ask,
    Deny,
}

/// Which untrusted source classes a rule cares about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TaintSource {
    Network,
    Mcp,
    Subagent,
}

impl TaintSource {
    fn matches(self, p: &Provenance) -> bool {
        matches!(
            (self, p),
            (TaintSource::Network, Provenance::Network { .. })
                | (TaintSource::Mcp, Provenance::McpServer { .. })
                | (TaintSource::Subagent, Provenance::Subagent { .. })
        )
    }
}

/// Everything the engine derived about one event. All fields optional; a rule matches
/// only if every condition it states holds.
#[derive(Debug, Clone, Default)]
pub struct Signals {
    pub action_class: Option<ActionClass>,
    pub taint: Option<TaintMark>,
    pub findings: Vec<(Facet, Finding)>,
    pub risk_score: u8,
    pub egress_hosts: Vec<String>,
    pub subagent_escalation: bool,
    /// The call touches a credential-shaped path. Never dangerous alone.
    pub touches_sensitive_path: bool,
}

/// All present sub-conditions are ANDed. Absent fields are ignored.
///
/// `deny_unknown_fields`: a typo'd condition key (`detecter` for `detector`) must be a
/// parse error, not a silently-ignored field. Silently ignoring it would leave `when: {}`
/// in effect, which matches every event of the rule's shape — a fat-fingered narrow rule
/// becomes a catch-all, and if its action is `allow` it disables every rule below it. A
/// security policy failing open on a typo, with no diagnostic, is worse than a hard error.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentCondition {
    #[serde(default)]
    pub taint: Option<Vec<TaintSource>>,
    /// Exact action class.
    #[serde(default)]
    pub action_class: Option<ActionClass>,
    /// Action class at or above this severity.
    #[serde(default)]
    pub min_action_class: Option<ActionClass>,
    #[serde(default)]
    pub detector: Option<String>,
    #[serde(default)]
    pub facet: Option<Facet>,
    #[serde(default)]
    pub min_severity: Option<Severity>,
    #[serde(default)]
    pub risk_score_gte: Option<u8>,
    #[serde(default)]
    pub egress_not_allowlisted: Option<bool>,
    #[serde(default)]
    pub subagent_escalation: Option<bool>,
    /// True when the call touches a path that commonly holds credentials. Reported
    /// separately from `action_class` because reading such a file is ordinary — use
    /// it only in combination with taint or egress, never alone.
    #[serde(default)]
    pub touches_sensitive_path: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRule {
    pub name: String,
    pub when: AgentCondition,
    pub action: Verdict,
    #[serde(default)]
    pub message: Option<String>,
}

fn default_verdict() -> Verdict {
    Verdict::Allow
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPolicySet {
    #[serde(default)]
    pub agent_policies: Vec<AgentRule>,
    #[serde(default)]
    pub egress_allowlist: Vec<String>,
    #[serde(default = "default_verdict")]
    pub default: Verdict,
}

/// The outcome for one event.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentDecision {
    pub verdict: Verdict,
    pub rule: Option<String>,
    pub message: Option<String>,
}

impl AgentPolicySet {
    pub fn from_yaml(s: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(s)
    }

    /// First matching rule wins; otherwise the default verdict.
    pub fn evaluate(&self, s: &Signals) -> AgentDecision {
        for rule in &self.agent_policies {
            if self.matches(&rule.when, s) {
                return AgentDecision {
                    verdict: rule.action,
                    rule: Some(rule.name.clone()),
                    message: rule.message.clone(),
                };
            }
        }
        AgentDecision {
            verdict: self.default,
            rule: None,
            message: None,
        }
    }

    fn matches(&self, c: &AgentCondition, s: &Signals) -> bool {
        if let Some(sources) = &c.taint {
            match &s.taint {
                None => return false,
                Some(mark) => {
                    if !sources.iter().any(|t| t.matches(&mark.source)) {
                        return false;
                    }
                }
            }
        }
        if let Some(exact) = c.action_class {
            if s.action_class != Some(exact) {
                return false;
            }
        }
        if let Some(min) = c.min_action_class {
            match s.action_class {
                Some(a) if a >= min => {}
                _ => return false,
            }
        }
        if let Some(min) = c.risk_score_gte {
            if s.risk_score < min {
                return false;
            }
        }
        if c.detector.is_some() || c.min_severity.is_some() || c.facet.is_some() {
            let any = s.findings.iter().any(|(facet, f)| {
                let facet_ok = c.facet.is_none_or(|want| want == *facet);
                // Segment-bounded prefix, matching core's scheme: "secret" matches
                // "secret" and "secret.aws_key" but not "secretsauce".
                let det_ok = c
                    .detector
                    .as_ref()
                    .is_none_or(|d| f.detector == *d || f.detector.starts_with(&format!("{d}.")));
                let sev_ok = c.min_severity.is_none_or(|m| f.severity >= m);
                facet_ok && det_ok && sev_ok
            });
            if !any {
                return false;
            }
        }
        if c.egress_not_allowlisted == Some(true) {
            let any_unlisted = s
                .egress_hosts
                .iter()
                .any(|h| !is_allowed(h, &self.egress_allowlist));
            if !any_unlisted {
                return false;
            }
        }
        if let Some(want) = c.subagent_escalation {
            if s.subagent_escalation != want {
                return false;
            }
        }
        if let Some(want) = c.touches_sensitive_path {
            if s.touches_sensitive_path != want {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::ActionClass;
    use crate::event::Provenance;
    use crate::taint::TaintMark;
    use llm_firewall_core::{Finding, Severity};

    const YAML: &str = r#"
agent_policies:
  - name: deny-tainted-destructive
    when: { taint: [network, mcp], action_class: destructive }
    action: deny
    message: "Blocked: destructive action derived from untrusted content"
  - name: ask-tainted-side-effect
    when: { taint: [network, mcp], min_action_class: side_effecting }
    action: ask
  - name: deny-secret-egress
    when: { detector: secret, facet: tool_args, min_action_class: network }
    action: deny
  - name: ask-unknown-host
    when: { egress_not_allowlisted: true }
    action: ask
  - name: deny-subagent-escalation
    when: { subagent_escalation: true }
    action: deny
egress_allowlist: [github.com, crates.io]
default: allow
"#;

    fn signals() -> Signals {
        Signals::default()
    }

    #[test]
    fn parses_the_shipped_shape() {
        let p = AgentPolicySet::from_yaml(YAML).expect("parse");
        assert_eq!(p.agent_policies.len(), 5);
        assert_eq!(p.default, Verdict::Allow);
        assert_eq!(p.egress_allowlist, vec!["github.com", "crates.io"]);
    }

    #[test]
    fn clean_signals_fall_through_to_the_default() {
        let p = AgentPolicySet::from_yaml(YAML).unwrap();
        assert_eq!(p.evaluate(&signals()).verdict, Verdict::Allow);
    }

    #[test]
    fn tainted_destructive_is_denied() {
        let p = AgentPolicySet::from_yaml(YAML).unwrap();
        let mut s = signals();
        s.action_class = Some(ActionClass::Destructive);
        s.taint = Some(TaintMark {
            source: Provenance::Network {
                host: "evil.com".into(),
            },
            seq: 2,
        });
        let d = p.evaluate(&s);
        assert_eq!(d.verdict, Verdict::Deny);
        assert_eq!(d.rule.as_deref(), Some("deny-tainted-destructive"));
    }

    #[test]
    fn tainted_write_is_asked_not_denied() {
        let p = AgentPolicySet::from_yaml(YAML).unwrap();
        let mut s = signals();
        s.action_class = Some(ActionClass::SideEffecting);
        s.taint = Some(TaintMark {
            source: Provenance::McpServer {
                name: "rogue".into(),
            },
            seq: 1,
        });
        assert_eq!(p.evaluate(&s).verdict, Verdict::Ask);
    }

    #[test]
    fn tainted_read_only_is_allowed() {
        let p = AgentPolicySet::from_yaml(YAML).unwrap();
        let mut s = signals();
        s.action_class = Some(ActionClass::ReadOnly);
        s.taint = Some(TaintMark {
            source: Provenance::Network {
                host: "evil.com".into(),
            },
            seq: 1,
        });
        assert_eq!(p.evaluate(&s).verdict, Verdict::Allow);
    }

    #[test]
    fn a_secret_in_a_network_call_is_denied() {
        let p = AgentPolicySet::from_yaml(YAML).unwrap();
        let mut s = signals();
        s.action_class = Some(ActionClass::Network);
        s.findings = vec![(
            crate::facet::Facet::ToolArgs,
            Finding::new("secret.aws_key", Severity::Critical, 0.99, "AWS key"),
        )];
        let d = p.evaluate(&s);
        assert_eq!(d.verdict, Verdict::Deny);
        assert_eq!(d.rule.as_deref(), Some("deny-secret-egress"));
    }

    #[test]
    fn an_unlisted_egress_host_is_asked() {
        let p = AgentPolicySet::from_yaml(YAML).unwrap();
        let mut s = signals();
        s.egress_hosts = vec!["evil.com".into()];
        assert_eq!(p.evaluate(&s).verdict, Verdict::Ask);
    }

    #[test]
    fn an_allowlisted_egress_host_is_not_asked() {
        let p = AgentPolicySet::from_yaml(YAML).unwrap();
        let mut s = signals();
        s.egress_hosts = vec!["api.github.com".into()];
        assert_eq!(p.evaluate(&s).verdict, Verdict::Allow);
    }

    #[test]
    fn subagent_escalation_is_denied() {
        let p = AgentPolicySet::from_yaml(YAML).unwrap();
        let mut s = signals();
        s.subagent_escalation = true;
        assert_eq!(p.evaluate(&s).verdict, Verdict::Deny);
    }

    #[test]
    fn first_matching_rule_wins() {
        let p = AgentPolicySet::from_yaml(YAML).unwrap();
        let mut s = signals();
        // Matches both deny-tainted-destructive and ask-tainted-side-effect.
        s.action_class = Some(ActionClass::Destructive);
        s.taint = Some(TaintMark {
            source: Provenance::Network {
                host: "e.com".into(),
            },
            seq: 1,
        });
        assert_eq!(
            p.evaluate(&s).rule.as_deref(),
            Some("deny-tainted-destructive")
        );
    }

    #[test]
    fn the_shipped_default_policy_parses() {
        let yaml = include_str!("../policies/agent-default.yaml");
        let p = AgentPolicySet::from_yaml(yaml).expect("shipped policy must parse");
        assert!(!p.agent_policies.is_empty());
    }

    #[test]
    fn a_detected_secret_over_the_network_denies_even_with_a_sensitive_path() {
        // Regression pin: deny-secret-egress must win over ask-sensitive-path-egress
        // when a single event matches both. A network send that both touches a
        // credential-shaped path AND carries a detected Critical secret finding is
        // the strongest signal the system can produce; it must never be downgraded
        // to a prompt by a weaker rule that happens to be evaluated first.
        let yaml = include_str!("../policies/agent-default.yaml");
        let p = AgentPolicySet::from_yaml(yaml).expect("shipped policy must parse");
        let mut s = signals();
        s.action_class = Some(ActionClass::Network);
        s.touches_sensitive_path = true;
        s.findings = vec![(
            crate::facet::Facet::ToolArgs,
            Finding::new("secret.aws_key", Severity::Critical, 0.99, "AWS key"),
        )];
        let d = p.evaluate(&s);
        assert_eq!(d.verdict, Verdict::Deny);
        assert_eq!(d.rule.as_deref(), Some("deny-secret-egress"));
    }

    #[test]
    fn a_typo_d_condition_key_is_a_parse_error_not_a_silent_catch_all() {
        // Before `deny_unknown_fields`: `detecter` (typo for `detector`) parsed
        // successfully, leaving `when: {}` in effect, which matches every event of
        // the rule's action-class shape. A fat-fingered narrow rule silently became
        // a catch-all. This must now be a hard parse error with no valid policy.
        let bad_yaml = r#"
agent_policies:
  - name: typo-rule
    when: { detecter: secret, min_action_class: network }
    action: deny
default: allow
"#;
        let err = AgentPolicySet::from_yaml(bad_yaml)
            .expect_err("a typo'd condition key must fail to parse, not silently match everything");
        let msg = err.to_string();
        assert!(
            msg.contains("detecter") || msg.contains("unknown field"),
            "expected the error to name the bad field, got: {msg}"
        );
    }
}
