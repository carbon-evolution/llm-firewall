//! MCP manifest handling in agentfw: recognise a `tools/list` JSON-RPC response on
//! the stdio relay (`manifest_from_line`), parse the `/mcp` handshake's tool list,
//! pin it (`manifest_hash`), diff it, and run the handshake through the agent
//! firewall (injection detectors over tool descriptions).
//!
//! Properties: the pin hash must be stable under reordering of the tool list (it is
//! documented as such — a spurious change would raise a false "rug-pull" alert),
//! and diffing a manifest against itself reports no change.
#![no_main]

use agentfw::mcp::jsonrpc::manifest_from_line;
use agentfw::mcp::manifest::{diff, manifest_hash};
use libfuzzer_sys::fuzz_target;
use llm_firewall_agent::{AgentFirewall, ToolDecl};

fn check(tools: &[ToolDecl]) {
    let h = manifest_hash(tools);
    assert_eq!(h.len(), 64);
    let mut rev = tools.to_vec();
    rev.reverse();
    assert_eq!(
        h,
        manifest_hash(&rev),
        "manifest hash depends on tool order"
    );
    assert_eq!(diff(tools, tools), "no change");
    let _ = diff(tools, &[]);
    let _ = diff(&[], tools);
    let mut agent = AgentFirewall::with_default_policy();
    let _ = agent.inspect_mcp_handshake("fuzz", tools, false, false);
}

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    // stdio relay: one JSON-RPC line at a time.
    for line in s.lines() {
        if let Some(tools) = manifest_from_line(line) {
            check(&tools);
        }
    }
    // `/mcp` handshake body: `{"server": ..., "tools": [ToolDecl...]}`.
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(s) {
        if let Some(arr) = v.get("tools") {
            if let Ok(tools) = serde_json::from_value::<Vec<ToolDecl>>(arr.clone()) {
                check(&tools);
            }
        }
    }
});
