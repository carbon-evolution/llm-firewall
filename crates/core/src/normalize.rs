//! Obfuscation/evasion normalization: produce a de-obfuscated copy of text so the
//! detectors catch attacks hidden by zero-width chars, Unicode confusables, or
//! encoding. PURE: no I/O. Never used to rewrite forwarded/masked text — the firewall
//! runs a dual-scan and masks only from the original-text pass (see `firewall.rs`).

/// Result of normalization. `changed` is true iff `text` differs from the input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Normalized {
    pub text: String,
    pub changed: bool,
}

/// Chars removed by Tier 1: zero-width formatters + bidi controls (Trojan-Source style).
fn is_invisible(c: char) -> bool {
    matches!(c,
        '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{2060}' | // ZWSP ZWNJ ZWJ WORD-JOINER
        '\u{FEFF}' | '\u{00AD}' | '\u{180E}' |               // BOM/ZWNBSP SOFT-HYPHEN MVS
        '\u{200E}' | '\u{200F}' |                            // LRM RLM
        '\u{202A}'..='\u{202E}' |                            // bidi embeddings/overrides
        '\u{2066}'..='\u{2069}'                              // bidi isolates
    )
}

fn strip_invisible(text: &str) -> String {
    text.chars().filter(|c| !is_invisible(*c)).collect()
}

/// Which normalization tiers to apply. Zero-width + homoglyph default on; base64 opt-in.
#[derive(Debug, Clone, Copy)]
pub struct Normalizer {
    pub strip_zero_width: bool,
    pub fold_homoglyphs: bool,
    pub decode_encoded: bool,
}

impl Default for Normalizer {
    fn default() -> Self {
        Self {
            strip_zero_width: true,
            fold_homoglyphs: true,
            decode_encoded: false,
        }
    }
}

impl Normalizer {
    /// Produce a de-obfuscated copy. Tiers 2/3 are added in later tasks.
    pub fn normalize(&self, input: &str) -> Normalized {
        let mut text = input.to_string();
        if self.strip_zero_width {
            let s = strip_invisible(&text);
            if s != text {
                text = s;
            }
        }
        // Tier 2 (fold_homoglyphs) and Tier 3 (decode_encoded) appended in Tasks 2 & 3.
        let changed = text != input;
        Normalized { text, changed }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_zero_width_between_letters() {
        let s = "ig\u{200B}no\u{200D}re";
        assert_eq!(strip_invisible(s), "ignore");
    }

    #[test]
    fn strips_bidi_controls() {
        let s = "abc\u{202E}def";
        assert_eq!(strip_invisible(s), "abcdef");
    }

    #[test]
    fn leaves_clean_text_untouched() {
        assert_eq!(
            strip_invisible("ignore all instructions"),
            "ignore all instructions"
        );
    }

    #[test]
    fn normalizer_default_strips_zero_width_and_flags_changed() {
        let n = Normalizer::default();
        let out = n.normalize("ig\u{200B}nore");
        assert_eq!(out.text, "ignore");
        assert!(out.changed);
        assert!(!n.normalize("ignore").changed);
    }
}
