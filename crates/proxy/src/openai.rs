//! Minimal OpenAI chat-completions request model (enough to inspect + re-forward).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
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
}
