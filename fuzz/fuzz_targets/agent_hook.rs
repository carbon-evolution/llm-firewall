//! agentfw's Claude Code hook endpoint: each input line is one hook payload
//! (`HookPayload`, the `/hook` request body). Lines are mapped to `AgentEvent`s
//! (`map::to_event`, including UTF-8-safe truncation at a fuzzer-chosen limit) and
//! fed in order into ONE `AgentFirewall`, so tool results build taint that later
//! tool calls in the same input are checked against — the stateful path (taint
//! fingerprints, egress host extraction, action classification, authority).
#![no_main]

use agentfw::hook::HookPayload;
use agentfw::map::to_event;
use libfuzzer_sys::fuzz_target;
use llm_firewall_agent::AgentFirewall;

fuzz_target!(|data: &[u8]| {
    let Some((&first, rest)) = data.split_first() else {
        return;
    };
    // Small limits exercise truncation; 0 means the daemon default (256 KiB).
    let max_bytes = if first == 0 { 262_144 } else { first as usize };
    let Ok(s) = std::str::from_utf8(rest) else {
        return;
    };
    let mut agent = AgentFirewall::with_default_policy();
    for (seq, line) in s.lines().enumerate() {
        let Ok(p) = serde_json::from_str::<HookPayload>(line) else {
            continue;
        };
        let _ = p.response_text();
        if let Some(m) = to_event(&p, seq as u64, 0, max_bytes) {
            let _ = agent.inspect(&m.event);
        }
    }
});
