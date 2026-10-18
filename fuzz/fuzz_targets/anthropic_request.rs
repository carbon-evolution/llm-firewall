//! An Anthropic `POST /v1/messages` body, handled the way the proxy handles it:
//! parse into `AnthropicRequest` (string-or-blocks `system` and `content`), run
//! `decide_input_anthropic` under the shipped policy and a mask-everything policy,
//! re-serialize what would be forwarded, and run the agent-layer `tool_result` /
//! `tool_use` extraction and `inspect_cycle` (the same bytes double as a response).
//!
//! Streamed responses are covered by the `sse_stream` target.
#![no_main]

use libfuzzer_sys::fuzz_target;
use llm_firewall::agent_scan::{anthropic_tool_calls, anthropic_tool_results, inspect_cycle};
use llm_firewall::anthropic::AnthropicRequest;
use llm_firewall::pipeline::{decide_input_anthropic, decide_output};
use llm_firewall_agent::AgentFirewall;
use llm_firewall_fuzz::{DEFAULT_FW, MASK_FW};

fuzz_target!(|data: &[u8]| {
    if let Ok(req) = serde_json::from_slice::<AnthropicRequest>(data) {
        for fw in [&*DEFAULT_FW, &*MASK_FW] {
            let d = decide_input_anthropic(fw, req.clone());
            assert!(d.score <= 100);
            assert_eq!(d.request.messages.len(), req.messages.len());
            let fwd = serde_json::to_vec(&d.request).expect("forwarded request serializes");
            let back: AnthropicRequest =
                serde_json::from_slice(&fwd).expect("forwarded request re-parses");
            assert_eq!(back.messages.len(), req.messages.len());
        }
    }

    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) {
        // As a request: tool_result blocks become taint.
        let results = anthropic_tool_results(&v);
        // As a response: text blocks are output, tool_use blocks are actions.
        let calls = anthropic_tool_calls(&v);
        if let Some(blocks) = v.get("content").and_then(|c| c.as_array()) {
            let text: String = blocks
                .iter()
                .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
                .collect();
            let _ = decide_output(&DEFAULT_FW, &text);
        }
        if !results.is_empty() || !calls.is_empty() {
            let mut agent = AgentFirewall::with_default_policy();
            let _ = inspect_cycle(&mut agent, "fuzz", &results, &calls);
        }
    }
});
