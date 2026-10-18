// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Streaming (SSE) response inspection.
//!
//! The upstream byte stream is parsed into SSE events ([`SseParser`]); the text each
//! event carries is reassembled per *channel* — one per OpenAI choice, per OpenAI tool
//! call, per Anthropic content block — and the output policy runs on the reassembled
//! text, not on raw JSON frames ([`StreamInspector`]).
//!
//! **Hold-back.** An event is released to the client only once every byte of text it
//! carries is at least `holdback` bytes older than the newest text on its channel (or
//! the channel is finished and has been scanned in full). Every append is scanned in a
//! window that starts `holdback` bytes before the new text, so any match of length
//! `<= holdback` is seen the moment its last byte arrives — while none of its bytes
//! has been released yet. A secret split across many delta frames therefore never
//! reaches the client in part. Longer / unbounded matches (e.g. a very long
//! high-entropy token, or a risk score that only crosses the threshold over the whole
//! reply) are caught by the full scan when a channel finishes, possibly after its
//! beginning was released. The cost is latency: the client sees text roughly
//! `holdback` bytes (≈ 60 tokens at the 256-byte default) behind the upstream.
//!
//! Events are always released whole and in upstream order, so a clean stream reaches
//! the client byte-for-byte identical to what the upstream sent.

use std::collections::{HashMap, VecDeque};

use llm_firewall_core::Firewall;
use serde_json::Value;

use crate::agent_scan::ToolCall;
use crate::pipeline::decide_output;

// ------------------------------------------------------------------ SSE parsing

/// One parsed SSE event plus the exact bytes it occupied on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    /// The verbatim upstream bytes, including the terminating blank line.
    pub raw: Vec<u8>,
    /// The `event:` field, if any.
    pub event: Option<String>,
    /// The `data:` lines joined with `\n` (per the SSE spec); `None` if there were none.
    pub data: Option<String>,
}

/// Incremental SSE parser. Handles events split across arbitrary chunk boundaries,
/// `\n`, `\r\n` and bare `\r` line endings, multi-line `data:`, and comments.
#[derive(Debug, Default)]
pub struct SseParser {
    buf: Vec<u8>,
    /// Offset in `buf` of the first byte of the current (unterminated) line.
    line_start: usize,
    event: Option<String>,
    data: Vec<String>,
}

impl SseParser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed bytes; return every event completed by them.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<SseEvent> {
        self.buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        loop {
            let rest = &self.buf[self.line_start..];
            let Some(i) = rest.iter().position(|&b| b == b'\n' || b == b'\r') else {
                break;
            };
            let term = if rest[i] == b'\r' {
                match rest.get(i + 1) {
                    Some(b'\n') => 2,
                    Some(_) => 1,
                    // A trailing `\r` may be the first half of `\r\n`; wait for more.
                    None => break,
                }
            } else {
                1
            };
            let line_end = self.line_start + i;
            let next = line_end + term;
            if i == 0 {
                // Blank line: dispatch the event.
                let raw: Vec<u8> = self.buf.drain(..next).collect();
                self.line_start = 0;
                out.push(self.take_event(raw));
            } else {
                let line =
                    String::from_utf8_lossy(&self.buf[self.line_start..line_end]).into_owned();
                self.field(&line);
                self.line_start = next;
            }
        }
        out
    }

    /// End of stream: return a trailing event that never got its blank line, if any.
    pub fn finish(&mut self) -> Option<SseEvent> {
        if self.buf.is_empty() {
            return None;
        }
        if self.line_start < self.buf.len() {
            let tail = &self.buf[self.line_start..];
            let tail = tail.strip_suffix(b"\r").unwrap_or(tail);
            let line = String::from_utf8_lossy(tail).into_owned();
            if !line.is_empty() {
                self.field(&line);
            }
        }
        let raw = std::mem::take(&mut self.buf);
        self.line_start = 0;
        Some(self.take_event(raw))
    }

    fn field(&mut self, line: &str) {
        if line.starts_with(':') {
            return; // comment
        }
        let (name, value) = match line.split_once(':') {
            Some((n, v)) => (n, v.strip_prefix(' ').unwrap_or(v)),
            None => (line, ""),
        };
        match name {
            "data" => self.data.push(value.to_string()),
            "event" => self.event = Some(value.to_string()),
            _ => {}
        }
    }

    fn take_event(&mut self, raw: Vec<u8>) -> SseEvent {
        let data = if self.data.is_empty() {
            None
        } else {
            Some(std::mem::take(&mut self.data).join("\n"))
        };
        SseEvent {
            raw,
            event: self.event.take(),
            data,
        }
    }
}

// -------------------------------------------------------------- reassembly model

/// Which streaming wire format the upstream speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// OpenAI chat completions chunks (`choices[i].delta`), terminated by `[DONE]`.
    OpenAi,
    /// Anthropic Messages events (`content_block_delta`, …), terminated by `message_stop`.
    Anthropic,
}

/// A reassembly channel: one independent piece of model output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Key {
    /// OpenAI choice text (`tool: None`) or a tool call's arguments (`tool: Some(j)`).
    Choice { choice: u64, tool: Option<u64> },
    /// Anthropic content block `index`.
    Block(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// Assistant reply text (what moderation sees).
    Text,
    /// Tool-call arguments.
    Tool,
    /// Other model output that is still scanned (e.g. Anthropic `thinking`).
    Other,
}

enum Delta {
    Append {
        key: Key,
        kind: Kind,
        name: Option<String>,
        text: String,
    },
    /// The channels matching this key are complete (finish_reason / content_block_stop).
    FinishChoice(u64),
    FinishBlock(u64),
    /// The whole message is complete (`[DONE]` / `message_stop`).
    Done,
}

fn str_at<'a>(v: &'a Value, ptr: &str) -> Option<&'a str> {
    v.pointer(ptr).and_then(Value::as_str)
}

fn extract(protocol: Protocol, ev: &SseEvent) -> Vec<Delta> {
    let Some(data) = ev.data.as_deref() else {
        return Vec::new();
    };
    if data.trim() == "[DONE]" {
        return vec![Delta::Done];
    }
    let Ok(v) = serde_json::from_str::<Value>(data) else {
        return Vec::new();
    };
    match protocol {
        Protocol::OpenAi => extract_openai_choices(&v, "delta"),
        Protocol::Anthropic => extract_anthropic(&v),
    }
}

/// An OpenAI stream chunk (`part = "delta"`) or a non-streamed completion
/// (`part = "message"`): both carry the same fields, incrementally or whole.
fn extract_openai_choices(v: &Value, part: &str) -> Vec<Delta> {
    let at = |field: &str| format!("/{part}/{field}");
    let mut out = Vec::new();
    let Some(choices) = v.get("choices").and_then(Value::as_array) else {
        return out;
    };
    for (pos, ch) in choices.iter().enumerate() {
        let i = ch
            .get("index")
            .and_then(Value::as_u64)
            .unwrap_or(pos as u64);
        let text_key = Key::Choice {
            choice: i,
            tool: None,
        };
        // Chat text, and legacy completions-style `text`.
        for s in [str_at(ch, &at("content")), str_at(ch, "/text")]
            .into_iter()
            .flatten()
        {
            out.push(Delta::Append {
                key: text_key,
                kind: Kind::Text,
                name: None,
                text: s.to_string(),
            });
        }
        if let Some(s) = str_at(ch, &at("refusal")) {
            out.push(Delta::Append {
                key: text_key,
                kind: Kind::Text,
                name: None,
                text: s.to_string(),
            });
        }
        if let Some(calls) = ch.pointer(&at("tool_calls")).and_then(Value::as_array) {
            for (tpos, tc) in calls.iter().enumerate() {
                let j = tc
                    .get("index")
                    .and_then(Value::as_u64)
                    .unwrap_or(tpos as u64);
                out.push(Delta::Append {
                    key: Key::Choice {
                        choice: i,
                        tool: Some(j),
                    },
                    kind: Kind::Tool,
                    name: str_at(tc, "/function/name").map(str::to_string),
                    text: str_at(tc, "/function/arguments")
                        .unwrap_or_default()
                        .to_string(),
                });
            }
        }
        // Legacy single `function_call`.
        if let Some(fc) = ch.pointer(&at("function_call")) {
            out.push(Delta::Append {
                key: Key::Choice {
                    choice: i,
                    tool: Some(u64::MAX),
                },
                kind: Kind::Tool,
                name: str_at(fc, "/name").map(str::to_string),
                text: str_at(fc, "/arguments").unwrap_or_default().to_string(),
            });
        }
        if ch.get("finish_reason").is_some_and(|f| !f.is_null()) {
            out.push(Delta::FinishChoice(i));
        }
    }
    out
}

/// An Anthropic content block at position `idx`: as it opens a stream
/// (`content_block_start`) or, whole, in a non-streamed reply's `content[]`.
fn anthropic_block(idx: u64, block: &Value) -> Vec<Delta> {
    match block.get("type").and_then(Value::as_str) {
        Some("text") => vec![Delta::Append {
            key: Key::Block(idx),
            kind: Kind::Text,
            name: None,
            text: str_at(block, "/text").unwrap_or_default().to_string(),
        }],
        Some("tool_use") | Some("server_tool_use") => {
            // Streams usually open with `input: {}` and send the arguments as deltas;
            // a non-streamed block carries the whole input, scanned serialised.
            let input = match block.get("input") {
                Some(Value::Object(m)) if m.is_empty() => String::new(),
                Some(Value::Null) | None => String::new(),
                Some(other) => other.to_string(),
            };
            vec![Delta::Append {
                key: Key::Block(idx),
                kind: Kind::Tool,
                name: str_at(block, "/name").map(str::to_string),
                text: input,
            }]
        }
        Some("thinking") => vec![Delta::Append {
            key: Key::Block(idx),
            kind: Kind::Other,
            name: None,
            text: str_at(block, "/thinking").unwrap_or_default().to_string(),
        }],
        _ => Vec::new(),
    }
}

fn extract_anthropic(v: &Value) -> Vec<Delta> {
    let idx = v.get("index").and_then(Value::as_u64).unwrap_or(0);
    match v.get("type").and_then(Value::as_str) {
        Some("content_block_start") => anthropic_block(idx, &v["content_block"]),
        Some("content_block_delta") => {
            let d = &v["delta"];
            let (kind, text) = match d.get("type").and_then(Value::as_str) {
                Some("text_delta") => (Kind::Text, str_at(d, "/text")),
                Some("input_json_delta") => (Kind::Tool, str_at(d, "/partial_json")),
                Some("thinking_delta") => (Kind::Other, str_at(d, "/thinking")),
                _ => return Vec::new(),
            };
            vec![Delta::Append {
                key: Key::Block(idx),
                kind,
                name: None,
                text: text.unwrap_or_default().to_string(),
            }]
        }
        Some("content_block_stop") => vec![Delta::FinishBlock(idx)],
        Some("message_stop") => vec![Delta::Done],
        _ => Vec::new(),
    }
}

// ------------------------------------------------------- non-streamed replies

/// Scan a non-streamed reply with the same channel model as a stream, so both paths
/// agree on what is inspected: every OpenAI choice's text and refusal, each tool call's
/// arguments and the legacy `function_call`; every Anthropic content block (`text`,
/// `tool_use` input serialised, `thinking`). Each channel is scanned on its own, as in
/// a stream. Returns the reply text (text channels joined by `\n`) for moderation, or
/// the block reason.
pub fn scan_reply(protocol: Protocol, fw: &Firewall, body: &Value) -> Result<String, BlockReason> {
    let deltas = match protocol {
        Protocol::OpenAi => extract_openai_choices(body, "message"),
        Protocol::Anthropic => body
            .get("content")
            .and_then(Value::as_array)
            .map(|blocks| {
                blocks
                    .iter()
                    .enumerate()
                    .flat_map(|(i, b)| anthropic_block(i as u64, b))
                    .collect()
            })
            .unwrap_or_default(),
    };
    let mut channels: Vec<(Key, Kind, String)> = Vec::new();
    for d in deltas {
        if let Delta::Append {
            key, kind, text, ..
        } = d
        {
            match channels.iter_mut().find(|(k, _, _)| *k == key) {
                Some((_, _, t)) => t.push_str(&text),
                None => channels.push((key, kind, text)),
            }
        }
    }
    for (_, _, text) in &channels {
        if !text.is_empty() {
            if let Some(reason) = decide_output(fw, text) {
                return Err(reason);
            }
        }
    }
    Ok(channels
        .iter()
        .filter(|(_, kind, text)| *kind == Kind::Text && !text.is_empty())
        .map(|(_, _, text)| text.as_str())
        .collect::<Vec<_>>()
        .join("\n"))
}

// --------------------------------------------------------------- the inspector

struct Channel {
    key: Key,
    kind: Kind,
    name: Option<String>,
    text: String,
    /// Complete and scanned in full: its events no longer wait on the hold-back.
    finalized: bool,
}

struct Pending {
    raw: Vec<u8>,
    /// `(channel, text length after this event)` for every channel it appended to.
    needs: Vec<(usize, usize)>,
    /// Held until the end of the stream regardless of the hold-back.
    held: bool,
}

/// Why the stream must be stopped.
pub type BlockReason = String;

/// Reassembles and scans a streamed reply, deciding which upstream bytes may be
/// released to the client. Pure and synchronous, so it is unit-testable.
pub struct StreamInspector {
    protocol: Protocol,
    parser: SseParser,
    holdback: usize,
    /// Hold every event from the first tool-call event to the end of the stream
    /// (so agent inspection can still refuse the tool call).
    hold_tools: bool,
    /// Everything from here on waits for the end of the stream.
    hold_rest: bool,
    channels: Vec<Channel>,
    index: HashMap<Key, usize>,
    queue: VecDeque<Pending>,
}

/// How far before a window's nominal start to look for a word boundary, so a window
/// never begins mid-word (which could turn e.g. `farm -rf` into a false `rm -rf`).
const BOUNDARY_SLACK: usize = 64;

/// Start of the scan window for text whose new part begins at `from`.
fn window_start(text: &str, from: usize) -> usize {
    let mut start = from.min(text.len());
    while start > 0 && !text.is_char_boundary(start) {
        start -= 1;
    }
    let floor = start.saturating_sub(BOUNDARY_SLACK);
    let bytes = text.as_bytes();
    let mut s = start;
    while s > floor {
        if bytes[s - 1].is_ascii_whitespace() {
            return s;
        }
        s -= 1;
    }
    // No whitespace nearby: either a very long token (cutting it only shortens it) or
    // the start of the text.
    if floor == 0 {
        0
    } else {
        start
    }
}

impl StreamInspector {
    /// `holdback`: bytes of not-yet-confirmed text kept back per channel.
    /// `hold_tools`: hold from the first tool call to the end (agent enforcement).
    /// `hold_all`: hold the entire stream until the end (moderation `block`).
    pub fn new(protocol: Protocol, holdback: usize, hold_tools: bool, hold_all: bool) -> Self {
        Self {
            protocol,
            parser: SseParser::new(),
            holdback,
            hold_tools,
            hold_rest: hold_all,
            channels: Vec::new(),
            index: HashMap::new(),
            queue: VecDeque::new(),
        }
    }

    /// Feed upstream bytes. Returns the bytes that may now be sent to the client, or
    /// the reason the stream must be blocked (nothing further may be sent).
    pub fn push(&mut self, fw: &Firewall, bytes: &[u8]) -> Result<Vec<u8>, BlockReason> {
        for ev in self.parser.push(bytes) {
            self.process(fw, ev)?;
        }
        Ok(self.release())
    }

    /// Upstream finished: parse any unterminated tail and scan every channel in full.
    /// On `Ok`, call [`Self::drain_all`] to release what is still held.
    pub fn finish(&mut self, fw: &Firewall) -> Result<(), BlockReason> {
        if let Some(ev) = self.parser.finish() {
            self.process(fw, ev)?;
        }
        for ci in 0..self.channels.len() {
            self.finalize(fw, ci)?;
        }
        Ok(())
    }

    /// Release everything still held (call only after a successful [`Self::finish`]).
    pub fn drain_all(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        for p in self.queue.drain(..) {
            out.extend_from_slice(&p.raw);
        }
        out
    }

    /// The reassembled reply text (text channels joined by `\n`), for moderation.
    pub fn reply_text(&self) -> String {
        self.channels
            .iter()
            .filter(|c| c.kind == Kind::Text && !c.text.is_empty())
            .map(|c| c.text.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The reassembled tool calls, for agent inspection.
    pub fn tool_calls(&self) -> Vec<ToolCall> {
        self.channels
            .iter()
            .filter(|c| c.kind == Kind::Tool)
            .filter_map(|c| {
                let name = c.name.clone()?;
                let args = if c.text.trim().is_empty() {
                    Value::Object(Default::default())
                } else {
                    serde_json::from_str(&c.text).unwrap_or(Value::String(c.text.clone()))
                };
                Some(ToolCall { name, args })
            })
            .collect()
    }

    fn channel(&mut self, key: Key, kind: Kind) -> usize {
        if let Some(&ci) = self.index.get(&key) {
            return ci;
        }
        self.channels.push(Channel {
            key,
            kind,
            name: None,
            text: String::new(),
            finalized: false,
        });
        let ci = self.channels.len() - 1;
        self.index.insert(key, ci);
        ci
    }

    fn finalize(&mut self, fw: &Firewall, ci: usize) -> Result<(), BlockReason> {
        let ch = &mut self.channels[ci];
        if ch.finalized {
            return Ok(());
        }
        if !ch.text.is_empty() {
            if let Some(reason) = decide_output(fw, &ch.text) {
                return Err(reason);
            }
        }
        ch.finalized = true;
        Ok(())
    }

    fn process(&mut self, fw: &Firewall, ev: SseEvent) -> Result<(), BlockReason> {
        let mut needs = Vec::new();
        for d in extract(self.protocol, &ev) {
            match d {
                Delta::Append {
                    key,
                    kind,
                    name,
                    text,
                } => {
                    let ci = self.channel(key, kind);
                    if kind == Kind::Tool && self.hold_tools {
                        self.hold_rest = true;
                    }
                    let holdback = self.holdback;
                    let ch = &mut self.channels[ci];
                    if ch.name.is_none() {
                        ch.name = name;
                    }
                    if text.is_empty() {
                        continue;
                    }
                    // More text after a finish: back under the hold-back.
                    ch.finalized = false;
                    let old = ch.text.len();
                    ch.text.push_str(&text);
                    let start = window_start(&ch.text, old.saturating_sub(holdback));
                    if let Some(reason) = decide_output(fw, &ch.text[start..]) {
                        return Err(reason);
                    }
                    needs.push((ci, ch.text.len()));
                }
                Delta::FinishChoice(i) => {
                    for ci in 0..self.channels.len() {
                        if matches!(self.channels[ci].key, Key::Choice { choice, .. } if choice == i)
                        {
                            self.finalize(fw, ci)?;
                        }
                    }
                }
                Delta::FinishBlock(i) => {
                    if let Some(&ci) = self.index.get(&Key::Block(i)) {
                        self.finalize(fw, ci)?;
                    }
                }
                Delta::Done => {
                    for ci in 0..self.channels.len() {
                        self.finalize(fw, ci)?;
                    }
                }
            }
        }
        self.queue.push_back(Pending {
            raw: ev.raw,
            needs,
            held: self.hold_rest,
        });
        Ok(())
    }

    fn release(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        while let Some(p) = self.queue.front() {
            if p.held {
                break;
            }
            let ready = p.needs.iter().all(|&(ci, end)| {
                let ch = &self.channels[ci];
                ch.finalized || ch.text.len() >= end + self.holdback
            });
            if !ready {
                break;
            }
            let p = self.queue.pop_front().expect("front exists");
            out.extend_from_slice(&p.raw);
        }
        out
    }
}

/// A well-formed terminal SSE error event in the protocol's own format.
pub fn block_frame(protocol: Protocol, message: &str) -> Vec<u8> {
    match protocol {
        Protocol::OpenAi => {
            let body = serde_json::json!({
                "error": { "message": message, "type": "llm_firewall_block" }
            });
            format!("data: {body}\n\ndata: [DONE]\n\n").into_bytes()
        }
        Protocol::Anthropic => {
            let body = serde_json::json!({
                "type": "error",
                "error": { "type": "invalid_request_error", "message": message }
            });
            format!("event: error\ndata: {body}\n\n").into_bytes()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use llm_firewall_core::{OutputDetector, PolicySet, SecretDetector};

    fn data_of(evs: &[SseEvent]) -> Vec<Option<String>> {
        evs.iter().map(|e| e.data.clone()).collect()
    }

    #[test]
    fn parses_lf_events() {
        let mut p = SseParser::new();
        let evs = p.push(b"data: a\n\ndata: b\n\n");
        assert_eq!(data_of(&evs), vec![Some("a".into()), Some("b".into())]);
        assert_eq!(evs[0].raw, b"data: a\n\n");
        assert!(p.finish().is_none());
    }

    #[test]
    fn parses_crlf_events() {
        let mut p = SseParser::new();
        let evs = p.push(b"event: x\r\ndata: a\r\n\r\ndata: b\r\n\r\n");
        assert_eq!(data_of(&evs), vec![Some("a".into()), Some("b".into())]);
        assert_eq!(evs[0].event.as_deref(), Some("x"));
        assert_eq!(evs[0].raw, b"event: x\r\ndata: a\r\n\r\n");
    }

    #[test]
    fn crlf_split_between_cr_and_lf() {
        let mut p = SseParser::new();
        assert!(p.push(b"data: a\r").is_empty());
        assert!(p.push(b"\n\r").is_empty());
        let evs = p.push(b"\ndata: b\r\n\r\n");
        assert_eq!(data_of(&evs), vec![Some("a".into()), Some("b".into())]);
        assert_eq!(evs[0].raw, b"data: a\r\n\r\n");
    }

    #[test]
    fn events_split_across_chunks_at_every_byte() {
        let wire = b"event: content_block_delta\ndata: {\"x\":1}\n\n: comment\ndata: [DONE]\n\n";
        let mut p = SseParser::new();
        let mut evs = Vec::new();
        for b in wire.iter() {
            evs.extend(p.push(std::slice::from_ref(b)));
        }
        assert_eq!(
            data_of(&evs),
            vec![Some("{\"x\":1}".into()), Some("[DONE]".into())]
        );
        let rejoined: Vec<u8> = evs.iter().flat_map(|e| e.raw.clone()).collect();
        assert_eq!(rejoined, wire.to_vec(), "raw bytes must round-trip");
    }

    #[test]
    fn multi_line_data_is_joined_with_newline() {
        let mut p = SseParser::new();
        let evs = p.push(b"data: {\"a\":\ndata: 1}\n\n");
        assert_eq!(evs[0].data.as_deref(), Some("{\"a\":\n1}"));
        let v: Value = serde_json::from_str(evs[0].data.as_deref().unwrap()).unwrap();
        assert_eq!(v["a"], 1);
    }

    #[test]
    fn data_without_space_and_comments() {
        let mut p = SseParser::new();
        let evs = p.push(b": keepalive\n\ndata:x\n\n");
        assert_eq!(evs[0].data, None);
        assert_eq!(evs[1].data.as_deref(), Some("x"));
    }

    #[test]
    fn unterminated_tail_is_returned_by_finish() {
        let mut p = SseParser::new();
        assert!(p.push(b"data: tail").is_empty());
        let ev = p.finish().unwrap();
        assert_eq!(ev.data.as_deref(), Some("tail"));
        assert_eq!(ev.raw, b"data: tail");
    }

    // ---- inspector ----

    fn fw() -> Firewall {
        let policy = PolicySet::from_yaml(
            "policies:\n  - name: s\n    when: { detector: secret, direction: output }\n    action: block\n    message: \"Blocked: secret in model output\"\n  - name: o\n    when: { detector: output, direction: output, min_severity: high }\n    action: block\n    message: \"dangerous\"\ndefault: allow\n",
        )
        .unwrap();
        Firewall::new(
            vec![
                Box::new(SecretDetector::new()),
                Box::new(OutputDetector::new()),
            ],
            policy,
        )
    }

    fn oa(content: &str) -> Vec<u8> {
        let v = serde_json::json!({"choices":[{"index":0,"delta":{"content":content},"finish_reason":null}]});
        format!("data: {v}\n\n").into_bytes()
    }

    #[test]
    fn split_secret_is_blocked_before_any_part_is_released() {
        let fw = fw();
        let mut insp = StreamInspector::new(Protocol::OpenAi, 64, false, false);
        let mut released = Vec::new();
        let mut blocked = None;
        for piece in ["Here you go: AK", "IAIOSF", "ODNN7EX", "AMPLE and more"] {
            match insp.push(&fw, &oa(piece)) {
                Ok(b) => released.extend(b),
                Err(r) => {
                    blocked = Some(r);
                    break;
                }
            }
        }
        assert_eq!(blocked.as_deref(), Some("Blocked: secret in model output"));
        let s = String::from_utf8_lossy(&released);
        assert!(!s.contains("AK"), "no fragment may be released: {s}");
    }

    #[test]
    fn clean_stream_round_trips_byte_for_byte() {
        let fw = fw();
        let mut wire = Vec::new();
        wire.extend(b"data: {\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"}}]}\n\n");
        for w in "The quick brown fox jumps over the lazy dog. "
            .repeat(20)
            .split(' ')
        {
            wire.extend(oa(&format!("{w} ")));
        }
        wire.extend(
            b"data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
        );
        wire.extend(b"data: [DONE]\n\n");
        let mut insp = StreamInspector::new(Protocol::OpenAi, 64, false, false);
        let mut out = Vec::new();
        for chunk in wire.chunks(7) {
            out.extend(insp.push(&fw, chunk).unwrap());
        }
        insp.finish(&fw).unwrap();
        out.extend(insp.drain_all());
        assert_eq!(out, wire);
    }

    #[test]
    fn holdback_releases_older_text_progressively() {
        let fw = fw();
        let mut insp = StreamInspector::new(Protocol::OpenAi, 16, false, false);
        let first = insp.push(&fw, &oa("hello ")).unwrap();
        assert!(first.is_empty(), "newest text is held back");
        let second = insp
            .push(&fw, &oa("there, a long enough sentence"))
            .unwrap();
        assert_eq!(
            second,
            oa("hello "),
            "older event released once out of the window"
        );
    }

    #[test]
    fn window_never_starts_mid_word() {
        let fw = fw();
        // Hold-back 2 puts the nominal window start on the "r" of "farm".
        let mut insp = StreamInspector::new(Protocol::OpenAi, 2, false, false);
        // With a naive byte cut the window could begin at "rm -rf"; it must not block.
        insp.push(&fw, &oa("I went to the farm")).unwrap();
        assert!(insp.push(&fw, &oa(" -rfoo was printed")).is_ok());
    }

    #[test]
    fn anthropic_tool_input_is_reassembled() {
        let fw = fw();
        let mut insp = StreamInspector::new(Protocol::Anthropic, 64, false, false);
        let start = "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"t\",\"name\":\"Bash\",\"input\":{}}}\n\n";
        insp.push(&fw, start.as_bytes()).unwrap();
        for part in ["{\"cmd\":", "\"ls -la\"}"] {
            let ev = serde_json::json!({"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":part}});
            insp.push(
                &fw,
                format!("event: content_block_delta\ndata: {ev}\n\n").as_bytes(),
            )
            .unwrap();
        }
        insp.finish(&fw).unwrap();
        let calls = insp.tool_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "Bash");
        assert_eq!(calls[0].args["cmd"], "ls -la");
    }

    #[test]
    fn hold_all_releases_nothing_until_finish() {
        let fw = fw();
        let mut insp = StreamInspector::new(Protocol::OpenAi, 16, false, true);
        assert!(insp.push(&fw, &oa(&"x ".repeat(100))).unwrap().is_empty());
        assert!(insp.push(&fw, b"data: [DONE]\n\n").unwrap().is_empty());
        insp.finish(&fw).unwrap();
        assert!(!insp.drain_all().is_empty());
    }

    #[test]
    fn block_frames_are_well_formed() {
        let o = String::from_utf8(block_frame(Protocol::OpenAi, "no")).unwrap();
        assert!(o.starts_with("data: {") && o.ends_with("data: [DONE]\n\n"));
        let a = String::from_utf8(block_frame(Protocol::Anthropic, "no")).unwrap();
        assert!(a.starts_with("event: error\ndata: {") && a.ends_with("\n\n"));
        let mut p = SseParser::new();
        let evs = p.push(a.as_bytes());
        let v: Value = serde_json::from_str(evs[0].data.as_deref().unwrap()).unwrap();
        assert_eq!(v["type"], "error");
    }
}
