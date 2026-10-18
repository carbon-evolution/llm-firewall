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

/// Prefix of the current pin format. Pins written before it are bare hex
/// ([`legacy_manifest_hash`]) and are upgraded in place by [`pin_matches`].
pub const PIN_V2: &str = "v2:";

/// Tools in a canonical order (name, then description, then canonical schema), each
/// with its canonical schema string. Sorting by full content, not just the name, keeps
/// the hash stable when a server re-lists duplicate names in another order (found by
/// the `mcp_manifest` fuzz target).
fn sorted_tools(tools: &[ToolDecl]) -> Vec<(&ToolDecl, String)> {
    let mut sorted: Vec<(&ToolDecl, String)> = tools
        .iter()
        .map(|t| (t, canonical(&t.schema).to_string()))
        .collect();
    sorted.sort_by(|(a, sa), (b, sb)| {
        a.name
            .cmp(&b.name)
            .then_with(|| a.description.cmp(&b.description))
            .then_with(|| sa.cmp(sb))
    });
    sorted
}

/// The pin: `v2:` + SHA-256 over the canonically ordered tools, each field
/// length-prefixed (u64 little-endian), so field boundaries are unambiguous.
/// Reordering does not matter; any content change does.
pub fn manifest_hash(tools: &[ToolDecl]) -> String {
    let mut h = Sha256::new();
    h.update((tools.len() as u64).to_le_bytes());
    for (t, schema) in sorted_tools(tools) {
        for field in [
            t.name.as_bytes(),
            t.description.as_bytes(),
            schema.as_bytes(),
        ] {
            h.update((field.len() as u64).to_le_bytes());
            h.update(field);
        }
    }
    let hex: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
    format!("{PIN_V2}{hex}")
}

/// The pre-v2 pin: fields separated by NUL. JSON strings may contain NUL, so two
/// different manifests can be built to collide (found by the `mcp_manifest` fuzz
/// target). Kept only to recognise pins written by older versions.
pub fn legacy_manifest_hash(tools: &[ToolDecl]) -> String {
    let mut h = Sha256::new();
    for (t, schema) in sorted_tools(tools) {
        h.update(t.name.as_bytes());
        h.update([0u8]);
        h.update(t.description.as_bytes());
        h.update([0u8]);
        h.update(schema.as_bytes());
        h.update([0u8]);
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Whether `tools` matches a stored pin. `current` is `manifest_hash(tools)`. A legacy
/// (bare-hex) pin is compared with the legacy hash, so upgrading does not raise a false
/// drift alert; the caller then re-pins with the v2 hash.
pub fn pin_matches(pinned: &str, tools: &[ToolDecl], current: &str) -> bool {
    if pinned.starts_with(PIN_V2) {
        pinned == current
    } else {
        pinned == legacy_manifest_hash(tools)
    }
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
    fn reordering_duplicate_tool_names_does_not_change_the_hash() {
        // Found by the `mcp_manifest` fuzz target: two tools sharing a name used to
        // hash in input order, so a server re-listing them raised a false drift alert.
        let a = vec![tool("dup", "one"), tool("dup", "two"), tool("x", "")];
        let b = vec![tool("x", ""), tool("dup", "two"), tool("dup", "one")];
        assert_eq!(manifest_hash(&a), manifest_hash(&b));
    }

    #[test]
    fn legacy_hash_of_a_unique_name_manifest_is_unchanged() {
        // Pins persisted by older versions must still be recognised.
        let a = vec![tool("b", "two"), tool("a", "one")];
        assert_eq!(
            legacy_manifest_hash(&a),
            "89fbced8af075804669238a1ca78c7d170c83bb142572f3acf086f0991125058"
        );
    }

    #[test]
    fn nul_in_fields_cannot_forge_a_colliding_manifest() {
        // Found by the `mcp_manifest` fuzz target: with NUL separators these collide.
        let a = vec![tool("x\u{0}y", "")];
        let b = vec![tool("x", "y\u{0}")];
        assert_eq!(legacy_manifest_hash(&a), legacy_manifest_hash(&b));
        assert_ne!(manifest_hash(&a), manifest_hash(&b));
    }

    #[test]
    fn legacy_pin_matches_unchanged_manifest_and_detects_drift() {
        let a = vec![tool("a", "one"), tool("b", "two")];
        let legacy = legacy_manifest_hash(&a);
        let current = manifest_hash(&a);
        assert!(current.starts_with(PIN_V2));
        assert!(pin_matches(&legacy, &a, &current), "upgrade must not alert");
        assert!(pin_matches(&current, &a, &current));
        let changed = vec![tool("a", "one"), tool("b", "changed")];
        let changed_hash = manifest_hash(&changed);
        assert!(!pin_matches(&legacy, &changed, &changed_hash));
        assert!(!pin_matches(&current, &changed, &changed_hash));
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
