//! An OpenAI `POST /v1/chat/completions` body, handled the way the proxy handles it:
//! parse into `ChatRequest`, run `decide_input` (scan + mask every message) under the
//! shipped policy and under a mask-everything policy, re-serialize what would be
//! forwarded, and run the agent-layer tool-call/tool-result extraction and
//! `inspect_cycle` (treating the same bytes as an upstream response, too).
//!
//! Streamed responses are covered by the `sse_stream` target.
#![no_main]

use libfuzzer_sys::fuzz_target;
use llm_firewall::agent_scan::{inspect_cycle, openai_tool_calls, openai_tool_results};
use llm_firewall::openai::ChatRequest;
use llm_firewall::pipeline::{decide_input, decide_output};
use llm_firewall_agent::AgentFirewall;
use llm_firewall_fuzz::{DEFAULT_FW, MASK_FW};

fuzz_target!(|data: &[u8]| {
    if let Ok(req) = serde_json::from_slice::<ChatRequest>(data) {
        let results = openai_tool_results(&req);
        for fw in [&*DEFAULT_FW, &*MASK_FW] {
            let d = decide_input(fw, req.clone());
            assert!(d.score <= 100);
            assert_eq!(d.request.messages.len(), req.messages.len());
            // What would be forwarded upstream must serialize and re-parse.
            let fwd = serde_json::to_vec(&d.request).expect("forwarded request serializes");
            let back: ChatRequest =
                serde_json::from_slice(&fwd).expect("forwarded request re-parses");
            assert_eq!(back.messages.len(), req.messages.len());
        }
        let mut agent = AgentFirewall::with_default_policy();
        let _ = inspect_cycle(&mut agent, "fuzz", &results, &[]);
    }

    // The same bytes as an upstream (non-streaming) response.
    if let Ok(resp) = serde_json::from_slice::<serde_json::Value>(data) {
        let calls = openai_tool_calls(&resp);
        if let Some(text) = resp
            .pointer("/choices/0/message/content")
            .and_then(|c| c.as_str())
        {
            let _ = decide_output(&DEFAULT_FW, text);
        }
        if !calls.is_empty() {
            let mut agent = AgentFirewall::with_default_policy();
            let _ = inspect_cycle(&mut agent, "fuzz", &[], &calls);
        }
    }
});
