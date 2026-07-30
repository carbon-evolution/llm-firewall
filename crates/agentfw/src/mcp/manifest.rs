// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Canonicalize + hash a tool manifest, and diff two of them. The hash is the pin:
//! stable under reordering, sensitive to any change in a name, description, or schema.

use std::collections::BTreeMap;

use llm_firewall_agent::ToolDecl;
use sha2::{Digest, Sha256};

/// Recursively sort object keys so semantically-equal JSON hashes equally.
fn canonical(v: &serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(m) => {
            let sorted: BTreeMap<String, serde_json::Value> = m
                .iter()
                .map(|(k, val)| (k.clone(), canonical(val)))
                .collect();
            serde_json::to_value(sorted).unwrap_or(serde_json::Value::Null)
        }
        serde_json::Value::Array(a) => serde_json::Value::Array(a.iter().map(canonical).collect()),
        other => other.clone(),
    }
}

/// A stable SHA-256 over the manifest: tools sorted by name, each contributing its
/// name, description, and canonicalized schema. Reordering does not matter; any
/// content change does.
pub fn manifest_hash(tools: &[ToolDecl]) -> String {
    let mut sorted: Vec<&ToolDecl> = tools.iter().collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    let mut h = Sha256::new();
    for t in sorted {
        h.update(t.name.as_bytes());
        h.update([0u8]);
        h.update(t.description.as_bytes());
        h.update([0u8]);
        h.update(canonical(&t.schema).to_string().as_bytes());
        h.update([0u8]);
    }
    format!("{:x}", h.finalize())
}

/// A human-readable summary of what changed between two manifests, for the audit log
/// and the `ask` reason. Lists added (`+`), removed (`-`), and content-changed (`~`)
/// tool names only.
pub fn diff(old: &[ToolDecl], new: &[ToolDecl]) -> String {
    let by_name = |ts: &[ToolDecl]| -> BTreeMap<String, ToolDecl> {
        ts.iter().map(|t| (t.name.clone(), t.clone())).collect()
    };
    let (o, n) = (by_name(old), by_name(new));
    let mut parts = Vec::new();
    for name in n.keys() {
        if !o.contains_key(name) {
            parts.push(format!("+{name}"));
        }
    }
    for name in o.keys() {
        if !n.contains_key(name) {
            parts.push(format!("-{name}"));
        }
    }
    for (name, nt) in &n {
        if let Some(ot) = o.get(name) {
            if ot != nt {
                parts.push(format!("~{name}"));
            }
        }
    }
    if parts.is_empty() {
        "no change".into()
    } else {
        parts.join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool(name: &str, desc: &str) -> ToolDecl {
        ToolDecl {
            name: name.into(),
            description: desc.into(),
            schema: serde_json::Value::Null,
        }
    }

    #[test]
    fn reordering_tools_does_not_change_the_hash() {
        let a = vec![tool("a", "one"), tool("b", "two")];
        let b = vec![tool("b", "two"), tool("a", "one")];
        assert_eq!(manifest_hash(&a), manifest_hash(&b));
    }

    #[test]
    fn a_changed_description_changes_the_hash() {
        let a = vec![tool("a", "one")];
        let b = vec![tool("a", "ONE")];
        assert_ne!(manifest_hash(&a), manifest_hash(&b));
    }

    #[test]
    fn a_changed_schema_changes_the_hash() {
        let a = vec![ToolDecl {
            name: "a".into(),
            description: "d".into(),
            schema: serde_json::json!({"type":"object"}),
        }];
        let b = vec![ToolDecl {
            name: "a".into(),
            description: "d".into(),
            schema: serde_json::json!({"type":"object","additionalProperties":true}),
        }];
        assert_ne!(manifest_hash(&a), manifest_hash(&b));
    }

    #[test]
    fn the_diff_names_added_removed_and_changed_tools() {
        let old = vec![
            tool("keep", "same"),
            tool("gone", "x"),
            tool("edit", "before"),
        ];
        let new = vec![
            tool("keep", "same"),
            tool("edit", "after"),
            tool("added", "y"),
        ];
        let d = diff(&old, &new);
        assert!(d.contains("added"), "{d}");
        assert!(d.contains("gone"), "{d}");
        assert!(d.contains("edit"), "{d}");
        assert!(!d.contains("keep"), "unchanged tools must not appear: {d}");
    }
}
