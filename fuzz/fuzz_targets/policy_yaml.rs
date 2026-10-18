//! Every YAML document the binaries load through serde-saphyr: the content policy
//! (`PolicySet`), the agent policy (`AgentPolicySet`), the proxy config and the
//! agentfw daemon config. These are operator-supplied, but policy files get shared
//! and copied around, so a malformed one must fail cleanly — never panic, recurse
//! without bound, or blow up memory. A policy that parses is also evaluated.
#![no_main]

use libfuzzer_sys::fuzz_target;
use llm_firewall_agent::AgentPolicySet;
use llm_firewall_core::{Direction, Finding, PolicySet, Severity};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(p) = PolicySet::from_yaml(s) {
        let findings = [
            Finding::new("pii.email", Severity::Medium, 0.9, "email").with_span(0..1),
            Finding::new("injection", Severity::High, 0.9, "override"),
        ];
        for dir in [Direction::Input, Direction::Output] {
            let _ = p.evaluate(&findings, 90, dir);
            let _ = p.evaluate(&[], 0, dir);
        }
    }
    let _ = AgentPolicySet::from_yaml(s);
    let _ = llm_firewall::config::Config::from_yaml(s);
    let _ = agentfw::config::Config::from_yaml(s);
});
