// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Persistent per-server manifest pins, and the in-memory cross-server tool-name
//! registry that powers shadowing detection.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Persistent per-server pin: `server_id -> manifest hash`, one file per server under
/// `dir`, mode `0600`. Small and rarely written (once per new/changed server), so a
/// file-per-server keeps it trivially correct with no locking across processes.
pub struct ManifestStore {
    dir: PathBuf,
}

impl ManifestStore {
    pub fn new(dir: &Path) -> Self {
        let _ = fs::create_dir_all(dir);
        Self {
            dir: dir.to_path_buf(),
        }
    }

    fn path(&self, server: &str) -> PathBuf {
        // Keep the filename filesystem-safe regardless of the --id value.
        let safe: String = server
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        self.dir.join(format!("{safe}.pin"))
    }

    pub fn get(&self, server: &str) -> Option<String> {
        fs::read_to_string(self.path(server))
            .ok()
            .map(|s| s.trim().to_string())
    }

    pub fn put(&self, server: &str, hash: &str) -> std::io::Result<()> {
        let path = self.path(server);
        fs::write(&path, hash)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }
}

const BUILTINS: &[&str] = &[
    "Read",
    "Write",
    "Edit",
    "Bash",
    "Glob",
    "Grep",
    "WebFetch",
    "WebSearch",
    "Task",
];

/// In-memory map of `tool name -> owning server id`, seeded with the builtins under a
/// reserved owner. A name already owned by a *different* server (or a builtin) is a
/// shadow. Rebuilt at daemon start from the pin directory.
pub struct ToolRegistry {
    owner: Mutex<HashMap<String, String>>,
}

impl ToolRegistry {
    pub fn with_builtins() -> Self {
        let mut m = HashMap::new();
        for b in BUILTINS {
            m.insert((*b).to_string(), "<builtin>".to_string());
        }
        Self {
            owner: Mutex::new(m),
        }
    }

    /// The first name in `names` already owned by someone other than `server`, if any.
    pub fn shadows(&self, server: &str, names: &[String]) -> Option<String> {
        let m = self.owner.lock().ok()?;
        names
            .iter()
            .find(|n| m.get(*n).is_some_and(|o| o != server))
            .cloned()
    }

    /// Claim these names for `server` (idempotent). Unowned names become its; names
    /// owned by others are left as-is (already flagged by `shadows`).
    pub fn record(&self, server: &str, names: &[String]) {
        if let Ok(mut m) = self.owner.lock() {
            for n in names {
                m.entry(n.clone()).or_insert_with(|| server.to_string());
            }
        }
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::with_builtins()
    }
}

/// Rebuild a registry at daemon start. Pins store the manifest hash, not the tool
/// names, so cross-server shadowing is enforced within a daemon run once each server
/// has re-handshaked (clients re-handshake every server at startup). Kept as a named
/// entry point so the startup wiring is explicit.
pub fn seed_registry(_store: &ManifestStore) -> ToolRegistry {
    ToolRegistry::with_builtins()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pin_round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let store = ManifestStore::new(dir.path());
        assert!(store.get("github").is_none(), "no pin at first sight");
        store.put("github", "hash-abc").unwrap();
        assert_eq!(store.get("github").as_deref(), Some("hash-abc"));

        // A fresh store over the same dir sees the persisted pin.
        let reopened = ManifestStore::new(dir.path());
        assert_eq!(reopened.get("github").as_deref(), Some("hash-abc"));
    }

    #[test]
    fn the_registry_flags_a_name_owned_by_another_server_or_a_builtin() {
        let reg = ToolRegistry::with_builtins();
        assert!(reg.shadows("srvA", &["safe_name".into()]).is_none());
        reg.record("srvA", &["shared".into(), "safe_name".into()]);

        // Same server re-declaring its own names is not a shadow.
        assert!(reg.shadows("srvA", &["shared".into()]).is_none());
        // A different server claiming a name srvA owns is.
        assert_eq!(
            reg.shadows("srvB", &["shared".into()]),
            Some("shared".to_string())
        );
        // Colliding with a builtin is.
        assert_eq!(
            reg.shadows("srvC", &["Bash".into()]),
            Some("Bash".to_string())
        );
    }
}
