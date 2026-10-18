//! Minimal OpenAI chat-completions request model (enough to inspect + re-forward).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChatMessage {
    pub role: String,
    /// A string, an array of content parts (`[{"type":"text","text":…},
    /// {"type":"image_url",…}]`), or `None` for assistant tool-call messages, which
    /// carry `tool_calls` instead. Kept as raw JSON so non-text parts forward
    /// unchanged; only text is inspected (see [`content_text`]).
    #[serde(default)]
    pub content: Option<serde_json::Value>,
    /// Preserve `tool_calls` / `tool_call_id` / `name` so re-forwarding is faithful
    /// and the agent collector can read the tool blocks.
    #[serde(flatten)]
    pub rest: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChatRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    #[serde(default)]
    pub stream: bool,
    /// Preserve unknown fields (temperature, tools, …) so we forward faithfully.
    #[serde(flatten)]
    pub rest: serde_json::Map<String, serde_json::Value>,
}

/// The text a message `content` carries: the string itself, or every `text` part of a
/// content-part array, in order. Non-text parts (images, audio, files) carry none.
pub fn content_text(content: &serde_json::Value) -> Vec<&str> {
    match content {
        serde_json::Value::String(s) => vec![s.as_str()],
        serde_json::Value::Array(parts) => parts
            .iter()
            .filter(|p| p.get("type").and_then(|t| t.as_str()) == Some("text"))
            .filter_map(|p| p.get("text").and_then(|t| t.as_str()))
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_and_preserves_extra_fields() {
        let raw =
            r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"temperature":0.7}"#;
        let req: ChatRequest = serde_json::from_str(raw).unwrap();
        assert_eq!(req.model, "gpt-4o");
        assert_eq!(req.messages.len(), 1);
        assert!(!req.stream);
        // temperature preserved in `rest`
        assert!(req.rest.contains_key("temperature"));
        // re-serialize keeps it
        let out = serde_json::to_string(&req).unwrap();
        assert!(out.contains("temperature"));
    }

    #[test]
    fn a_tool_call_conversation_deserializes() {
        // Assistant with null content + tool_calls, then a tool result — must parse.
        let raw = r#"{
            "model":"gpt-4","messages":[
                {"role":"user","content":"list my repos"},
                {"role":"assistant","content":null,"tool_calls":[
                    {"id":"c1","type":"function","function":{"name":"list_repos","arguments":"{}"}}]},
                {"role":"tool","tool_call_id":"c1","content":"repo-a\nrepo-b"}
            ]}"#;
        let req: ChatRequest = serde_json::from_str(raw).expect("tool conversations must parse");
        assert_eq!(req.messages.len(), 3);
        assert_eq!(
            req.messages[1].content, None,
            "assistant tool-call content is null"
        );
        assert!(
            req.messages[1].rest.contains_key("tool_calls"),
            "tool_calls preserved in rest"
        );
        assert_eq!(req.messages[2].role, "tool");
        assert_eq!(
            req.messages[2].content,
            Some(serde_json::json!("repo-a\nrepo-b"))
        );
    }

    #[test]
    fn content_part_arrays_parse_and_round_trip() {
        let raw = r#"{"model":"gpt-4o","messages":[{"role":"user","content":[
            {"type":"text","text":"what is this?"},
            {"type":"image_url","image_url":{"url":"https://example.com/a.png"}}]}]}"#;
        let req: ChatRequest = serde_json::from_str(raw).unwrap();
        let content = req.messages[0].content.as_ref().unwrap();
        assert_eq!(content_text(content), vec!["what is this?"]);
        let back = serde_json::to_value(&req).unwrap();
        let orig: serde_json::Value = serde_json::from_str(raw).unwrap();
        assert_eq!(
            back["messages"], orig["messages"],
            "parts forward unchanged"
        );
    }
}
