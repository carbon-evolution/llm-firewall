//! Streaming (SSE) responses: `SseParser` and `StreamInspector` from
//! `crates/proxy/src/stream.rs`, fed an upstream byte stream cut into fuzzer-chosen
//! chunks, for both protocols, with fuzzer-chosen hold-back and hold flags.
//!
//! Input layout: byte 0 = flags (bit0 protocol, bit1 hold_tools, bit2 hold_all),
//! byte 1 = hold-back / 2, byte 2 = chunking seed, rest = the upstream stream.
//!
//! Properties:
//! - the parser is chunking-invariant (same events whole or split), and its events'
//!   `raw` bytes concatenate back to exactly the input;
//! - a stream that is not blocked reaches the client byte-for-byte identical;
//! - a blocked stream has released only a prefix of the upstream bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use llm_firewall::stream::{Protocol, SseEvent, SseParser, StreamInspector};
use llm_firewall_fuzz::DEFAULT_FW;

/// Split `data` into chunks of 1..=16 bytes from a tiny LCG seeded by `seed`.
fn chunks(data: &[u8], seed: u8) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut state = seed as u32 | 1;
    let mut i = 0;
    while i < data.len() {
        state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        let n = 1 + ((state >> 16) as usize % 16);
        let end = (i + n).min(data.len());
        out.push(&data[i..end]);
        i = end;
    }
    out
}

fn parse(parts: &[&[u8]]) -> Vec<SseEvent> {
    let mut p = SseParser::new();
    let mut evs = Vec::new();
    for c in parts {
        evs.extend(p.push(c));
    }
    evs.extend(p.finish());
    evs
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }
    let (hdr, body) = data.split_at(3);
    let protocol = if hdr[0] & 1 == 0 {
        Protocol::OpenAi
    } else {
        Protocol::Anthropic
    };
    let hold_tools = hdr[0] & 2 != 0;
    let hold_all = hdr[0] & 4 != 0;
    let holdback = hdr[1] as usize * 2;
    let parts = chunks(body, hdr[2]);

    // Parser: chunking-invariant and lossless.
    let whole = parse(&[body]);
    let split = parse(&parts);
    assert_eq!(whole, split, "SSE parse depends on chunking");
    let raw: Vec<u8> = whole.iter().flat_map(|e| e.raw.iter().copied()).collect();
    assert_eq!(raw, body, "SSE events do not reassemble to the input");

    // Inspector: clean streams pass through unchanged; blocked ones leak only a prefix.
    let mut insp = StreamInspector::new(protocol, holdback, hold_tools, hold_all);
    let mut sent = Vec::new();
    let mut blocked = false;
    for c in &parts {
        match insp.push(&DEFAULT_FW, c) {
            Ok(bytes) => sent.extend(bytes),
            Err(_) => {
                blocked = true;
                break;
            }
        }
    }
    if !blocked {
        match insp.finish(&DEFAULT_FW) {
            Ok(()) => {
                sent.extend(insp.drain_all());
                assert_eq!(sent, body, "clean stream was altered");
                let _ = insp.reply_text();
                let _ = insp.tool_calls();
                return;
            }
            Err(_) => blocked = true,
        }
    }
    assert!(blocked);
    assert!(
        body.starts_with(&sent),
        "blocked stream released non-prefix bytes"
    );
});
