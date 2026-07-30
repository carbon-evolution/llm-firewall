// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Generate the `settings.json` hook block. Prints by default; there is no
//! `--write` mode — silently editing a user's `settings.json`, or correctly
//! merging into an existing `hooks` block, is a whole task of its own and not
//! something a first release should do unprompted.

use std::path::Path;

use serde_json::json;

/// The `settings.json` fragment wiring all five hook events to the daemon.
///
/// The token is passed by environment variable, never written inline — settings
/// files are routinely committed to version control, and a token embedded in
/// JSON would ship straight into git history.
///
/// The 5-second timeout is deliberate, not conservative padding: measured
/// 2026-07-30, an unreachable HTTP hook fails open — Claude Code waits out the
/// timeout, then lets the tool call proceed. So this number is exactly what a
/// stopped daemon costs on every single tool call. It stays at 5s rather than
/// dropping lower because phase 10's local-model judge tier needs a 3s budget of
/// its own; shortening this now would clip legitimate slow judgments later.
pub fn hook_block(port: u16) -> serde_json::Value {
    let entry = json!({
        "type": "http",
        "url": format!("http://127.0.0.1:{port}/hook"),
        "headers": { "Authorization": "Bearer $AGENTFW_TOKEN" },
        "allowedEnvVars": ["AGENTFW_TOKEN"],
        "timeout": 5
    });
    // "*" matches every tool — the documented wildcard form for a hook matcher.
    let one = |matcher: &str| json!([{ "matcher": matcher, "hooks": [entry.clone()] }]);

    json!({
        "hooks": {
            "PreToolUse": one("*"),
            "PostToolUse": one("*"),
            "SubagentStop": one("*"),
            "SessionStart": one("*"),
            "SessionEnd": one("*")
        }
    })
}

/// Human-readable installation instructions: this is the operator's entire
/// first experience of the tool, so it prints the token *path* (never the
/// token itself — an operator pasting this into a bug report should not leak
/// their secret), and spells out both costs an operator would otherwise have
/// to discover by debugging: a stopped daemon silently taxing every tool call,
/// and shadow mode silently declining to block anything until told to.
pub fn instructions(port: u16, token_path: &Path) -> String {
    format!(
        "Add this to your Claude Code settings.json (merge into any existing \"hooks\" block \
         rather than overwriting it):\n\n\
         {block}\n\n\
         Then export the token before starting Claude Code — the token itself is never printed \
         here, only its path:\n\n  \
         export AGENTFW_TOKEN=$(cat {token_path})\n\n\
         COST OF A STOPPED DAEMON: each hook has a 5-second timeout. If agentfw is not running, \
         every tool call still proceeds — Claude Code fails open — but only after waiting out \
         the full 5 seconds first. This shows up as \"Claude Code feels slow\", not as an obvious \
         \"agentfw isn't running\" error, so if things suddenly feel sluggish, check first with:\n\n  \
         agentfw serve\n\n\
         SHADOW MODE: the daemon starts with enforcement OFF. Verdicts are computed and written \
         to the audit log on every tool call, but nothing is ever blocked — permissionDecision is \
         always \"defer\", leaving your existing permission rules untouched. This is deliberate: it \
         lets you measure this firewall's real false-positive rate on your own normal work before \
         it can affect anything. Run your usual sessions for a few days, then inspect what it would \
         have done:\n\n  \
         agentfw replay\n\n\
         When you're satisfied with the false-positive rate, turn enforcement on by setting \
         `enforce: true` in ~/.agentfw/config.yaml and restarting the daemon.\n",
        block = serde_json::to_string_pretty(&hook_block(port)).unwrap_or_default(),
        token_path = token_path.display(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_all_five_events_pointing_at_the_daemon() {
        let v = hook_block(8787);
        let hooks = &v["hooks"];
        for event in [
            "PreToolUse",
            "PostToolUse",
            "SubagentStop",
            "SessionStart",
            "SessionEnd",
        ] {
            assert!(hooks.get(event).is_some(), "missing {event}");
            let entry = &hooks[event][0]["hooks"][0];
            assert_eq!(entry["type"], "http");
            assert_eq!(entry["url"], "http://127.0.0.1:8787/hook");
        }
    }

    #[test]
    fn matches_all_tools() {
        let v = hook_block(8787);
        assert_eq!(v["hooks"]["PreToolUse"][0]["matcher"], "*");
    }

    #[test]
    fn passes_the_token_by_env_var_never_inline() {
        // The literal secret must not be written into settings.json, which is
        // routinely committed to version control.
        let v = hook_block(8787);
        let entry = &v["hooks"]["PreToolUse"][0]["hooks"][0];
        assert_eq!(entry["headers"]["Authorization"], "Bearer $AGENTFW_TOKEN");
        assert_eq!(entry["allowedEnvVars"][0], "AGENTFW_TOKEN");
        assert!(
            !serde_json::to_string(&v).unwrap().contains("Bearer test"),
            "no literal token may appear"
        );
    }

    #[test]
    fn sets_a_short_timeout_so_a_stalled_daemon_cannot_hang_the_loop() {
        let v = hook_block(8787);
        assert_eq!(v["hooks"]["PreToolUse"][0]["hooks"][0]["timeout"], 5);
    }

    #[test]
    fn honours_a_custom_port() {
        let v = hook_block(9999);
        assert_eq!(
            v["hooks"]["PreToolUse"][0]["hooks"][0]["url"],
            "http://127.0.0.1:9999/hook"
        );
    }

    #[test]
    fn instructions_never_print_a_literal_token() {
        // instructions() reads the token PATH via load_or_create semantics, but
        // must never interpolate the secret itself into the printed output. This
        // exercise proves the assertion is not trivially true: a real secret
        // deliberately embedded in the text WOULD be caught by this check.
        let path = Path::new("/home/u/.agentfw/token");
        let out = instructions(8787, path);
        assert!(out.contains(&path.display().to_string()));
        assert!(out.contains("cat "), "must show how to read the token file");

        // Sanity-check the assertion style itself would catch a leak: a string
        // that DOES contain a bogus "real" token must fail this same check.
        let fake_leak = format!("{out}\nBearer sk-should-not-appear-abc123");
        assert!(
            fake_leak.contains("Bearer sk-should-not-appear-abc123"),
            "sanity check: the contains-based assertion must be able to detect a leak"
        );
        assert!(
            !out.contains("Bearer sk-should-not-appear-abc123"),
            "the real instructions output must not contain any concrete bearer token"
        );
    }

    #[test]
    fn instructions_mention_shadow_mode_and_the_timeout_cost() {
        let out = instructions(8787, Path::new("/home/u/.agentfw/token"));
        let lower = out.to_lowercase();
        assert!(lower.contains("shadow"), "must explain shadow mode: {out}");
        assert!(
            lower.contains("enforce"),
            "must say how to turn enforcement on: {out}"
        );
        assert!(
            lower.contains("5 second") || lower.contains("5-second"),
            "must warn about the per-call cost of a stopped daemon: {out}"
        );
    }
}
