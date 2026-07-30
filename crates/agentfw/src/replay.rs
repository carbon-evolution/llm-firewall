// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Summarize a recorded audit log. The question this answers is the one that
//! decides whether enforcement is safe to switch on: how often WOULD it have
//! interrupted you, and on what?
//!
//! This module does **not** re-run events through a policy engine — it summarizes
//! verdicts that were already computed and recorded by the daemon. Genuine
//! re-evaluation against a *modified* policy needs the events themselves, not just
//! their verdicts, and is out of scope here.

use std::collections::{BTreeMap, BTreeSet};

/// What a recorded run would have done.
#[derive(Debug, Default)]
pub struct Summary {
    pub total: usize,
    pub malformed: usize,
    pub sessions: usize,
    pub allow: usize,
    pub ask: usize,
    pub deny: usize,
    pub by_rule: BTreeMap<String, usize>,
    pub by_tool: BTreeMap<String, usize>,
    pub p50_us: u128,
    pub p99_us: u128,
}

impl Summary {
    /// Fraction of events that would have interrupted the operator. This is the
    /// number that decides whether enforcement is usable at all — a tool that
    /// interrupts constantly gets switched off before it proves anything.
    pub fn interruption_rate(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        (self.ask + self.deny) as f64 / self.total as f64
    }

    pub fn render(&self) -> String {
        let mut s = format!(
            "events: {}  sessions: {}  malformed: {}\n\
             allow: {}  ask: {}  deny: {}\n\
             would have interrupted: {:.1}% of events\n\
             latency p50: {} us   p99: {} us\n",
            self.total,
            self.sessions,
            self.malformed,
            self.allow,
            self.ask,
            self.deny,
            self.interruption_rate() * 100.0,
            self.p50_us,
            self.p99_us
        );
        if !self.by_rule.is_empty() {
            s.push_str("\nrules fired:\n");
            let mut rules: Vec<_> = self.by_rule.iter().collect();
            rules.sort_by(|a, b| b.1.cmp(a.1));
            for (rule, n) in rules {
                s.push_str(&format!("  {n:>6}  {rule}\n"));
            }
        }
        s
    }
}

/// Summarize an audit log. Malformed lines are counted, never fatal — a log is a
/// forensic record and a single bad line must not discard the rest.
pub fn summarize(log: &str) -> Summary {
    let mut out = Summary::default();
    let mut sessions: BTreeSet<String> = BTreeSet::new();
    let mut latencies: Vec<u128> = Vec::new();

    for line in log.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            out.malformed += 1;
            continue;
        };
        out.total += 1;
        if let Some(s) = v["session"].as_str() {
            sessions.insert(s.to_string());
        }
        match v["verdict"].as_str().unwrap_or("") {
            "allow" => out.allow += 1,
            "ask" => out.ask += 1,
            "deny" => out.deny += 1,
            _ => {}
        }
        if let Some(r) = v["rule"].as_str() {
            *out.by_rule.entry(r.to_string()).or_insert(0) += 1;
        }
        if let Some(t) = v["tool"].as_str() {
            *out.by_tool.entry(t.to_string()).or_insert(0) += 1;
        }
        if let Some(l) = v["latency_us"].as_u64() {
            latencies.push(l as u128);
        }
    }

    out.sessions = sessions.len();
    if !latencies.is_empty() {
        latencies.sort_unstable();
        out.p50_us = latencies[latencies.len() / 2];
        out.p99_us = latencies[(latencies.len() * 99 / 100).min(latencies.len() - 1)];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOG: &str = r#"{"at_ms":1,"session":"a","seq":1,"event":"pretooluse","tool":"Read","verdict":"allow","shadow":true,"risk_score":0,"findings":[],"egress_hosts":[],"latency_us":10,"truncated":false}
{"at_ms":2,"session":"a","seq":2,"event":"pretooluse","tool":"Bash","verdict":"ask","shadow":true,"rule":"ask-unknown-host","risk_score":40,"findings":[],"egress_hosts":["evil.com"],"latency_us":20,"truncated":false}
{"at_ms":3,"session":"a","seq":3,"event":"pretooluse","tool":"Bash","verdict":"deny","shadow":true,"rule":"deny-secret-egress","risk_score":93,"findings":[],"egress_hosts":[],"latency_us":30,"truncated":false}
{"at_ms":4,"session":"b","seq":1,"event":"pretooluse","tool":"Read","verdict":"allow","shadow":true,"risk_score":0,"findings":[],"egress_hosts":[],"latency_us":15,"truncated":false}
"#;

    #[test]
    fn counts_verdicts_and_sessions() {
        let s = summarize(LOG);
        assert_eq!(s.total, 4);
        assert_eq!(s.sessions, 2);
        assert_eq!(s.allow, 2);
        assert_eq!(s.ask, 1);
        assert_eq!(s.deny, 1);
    }

    #[test]
    fn reports_the_interruption_rate() {
        // The number that decides whether enforcement is usable.
        let s = summarize(LOG);
        assert!(
            (s.interruption_rate() - 0.5).abs() < 1e-9,
            "got {}",
            s.interruption_rate()
        );
    }

    #[test]
    fn ranks_rules_by_how_often_they_fired() {
        let s = summarize(LOG);
        assert_eq!(s.by_rule.get("ask-unknown-host"), Some(&1));
        assert_eq!(s.by_rule.get("deny-secret-egress"), Some(&1));
    }

    #[test]
    fn tolerates_blank_and_malformed_lines() {
        let s = summarize("not json\n\n{\"broken\":\n");
        assert_eq!(s.total, 0);
        assert_eq!(s.malformed, 2);
    }

    #[test]
    fn reports_latency_percentiles() {
        let s = summarize(LOG);
        assert!(s.p50_us > 0);
        assert!(s.p99_us >= s.p50_us);
    }

    #[test]
    fn an_empty_log_has_a_zero_interruption_rate_and_does_not_divide_by_zero() {
        let s = summarize("");
        assert_eq!(s.total, 0);
        assert_eq!(s.interruption_rate(), 0.0);
    }

    #[test]
    fn an_unrecognized_verdict_string_counts_toward_total_but_no_bucket() {
        // A future/typo'd verdict must not panic and must not be silently attributed
        // to one of the three known buckets — but this DOES mean the buckets no
        // longer sum to `total`, which is the honest reflection of an unknown value
        // rather than a false attribution.
        let log = "{\"session\":\"a\",\"seq\":1,\"verdict\":\"quarantine\",\"latency_us\":1}\n";
        let s = summarize(log);
        assert_eq!(s.total, 1);
        assert_eq!(s.allow + s.ask + s.deny, 0);
    }

    /// Hazard 1: prove key-name agreement with `audit.rs` end to end. A test built
    /// only from hand-written JSON literals (like `LOG` above) would keep passing
    /// even if the real emitter in `audit.rs` used different field names — this
    /// round-trips through the actual `AuditLine` type and its real `Serialize`
    /// impl, so a future rename in `audit.rs` breaks this test rather than making
    /// `replay` silently count zeros forever.
    #[test]
    fn round_trips_through_the_real_audit_line_serializer() {
        use crate::audit::AuditLine;

        let a = AuditLine {
            at_ms: 1,
            session: "s1".into(),
            seq: 2,
            event: "tool_call".into(),
            tool: Some("Bash".into()),
            verdict: "ask".into(),
            shadow: true,
            rule: Some("ask-unknown-host".into()),
            risk_score: 40,
            findings: vec![],
            taint: None,
            egress_hosts: vec!["evil.com".into()],
            latency_us: 20,
            truncated: false,
            raw: None,
        };
        let b = AuditLine {
            session: "s2".into(),
            verdict: "deny".into(),
            rule: Some("deny-secret-egress".into()),
            tool: Some("Bash".into()),
            latency_us: 90,
            ..a.clone()
        };

        let mut log = serde_json::to_string(&a).unwrap();
        log.push('\n');
        log.push_str(&serde_json::to_string(&b).unwrap());
        log.push('\n');

        let s = summarize(&log);
        assert_eq!(
            s.total, 2,
            "both lines must parse via the real emitter shape"
        );
        assert_eq!(s.malformed, 0);
        assert_eq!(s.sessions, 2);
        assert_eq!(s.ask, 1);
        assert_eq!(s.deny, 1);
        assert_eq!(s.by_rule.get("ask-unknown-host"), Some(&1));
        assert_eq!(s.by_rule.get("deny-secret-egress"), Some(&1));
        assert_eq!(s.by_tool.get("Bash"), Some(&2));
        // Sorted latencies are [20, 90]; index `len/2 == 1` is 90 for both p50 and
        // p99 at this tiny sample size — see the p99-arithmetic hazard notes.
        assert_eq!(s.p50_us, 90);
        assert_eq!(s.p99_us, 90);
    }
}
