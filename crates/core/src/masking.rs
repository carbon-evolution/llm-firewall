//! Replace finding spans in text with typed tokens, e.g. "alice@acme.com" -> "‹EMAIL›".
//! Overlapping spans merge into one masked region, labelled by the earliest-starting,
//! longest span: every byte covered by any valid span is replaced.

use crate::Finding;

/// Token for a finding: the last dot-segment of its detector id, upper-cased.
/// "pii.email" -> "‹EMAIL›", "secret.aws_key" -> "‹AWS_KEY›".
fn token_for(detector: &str) -> String {
    let suffix = detector.rsplit('.').next().unwrap_or(detector);
    format!("‹{}›", suffix.to_uppercase())
}

/// Return a masked copy of `text`, replacing spans of findings that have one.
pub fn mask(text: &str, findings: &[Finding]) -> String {
    // Collect (span, token), sorted by start asc then length desc.
    let mut spans: Vec<(std::ops::Range<usize>, String)> = findings
        .iter()
        .filter_map(|f| f.span.clone().map(|s| (s, token_for(&f.detector))))
        .collect();
    spans.sort_by(|a, b| a.0.start.cmp(&b.0.start).then(b.0.end.cmp(&a.0.end)));

    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    for (span, token) in spans {
        if span.start > span.end
            || span.end > text.len()
            || !text.is_char_boundary(span.start)
            || !text.is_char_boundary(span.end)
        {
            continue; // defensive: stale or non-char-boundary span (never panic on bad input)
        }
        if span.start < cursor {
            // Starts inside an already-masked region. Extend that region rather than
            // dropping this span: a partial overlap would otherwise leave the tail of
            // this finding (e.g. the rest of an email after a token) in the clear.
            cursor = cursor.max(span.end);
            continue;
        }
        out.push_str(&text[cursor..span.start]);
        out.push_str(&token);
        cursor = span.end;
    }
    out.push_str(&text[cursor..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Severity;

    #[test]
    fn masks_single_span() {
        let text = "reach me at alice@acme.com ok";
        let findings =
            vec![Finding::new("pii.email", Severity::Medium, 0.9, "email").with_span(12..26)];
        assert_eq!(mask(text, &findings), "reach me at ‹EMAIL› ok");
    }

    #[test]
    fn masks_multiple_in_order() {
        let text = "a AKIAIOSFODNN7EXAMPLE b 123-45-6789 c";
        let findings = vec![
            Finding::new("secret.aws_key", Severity::Critical, 0.95, "aws").with_span(2..22),
            Finding::new("pii.ssn", Severity::High, 0.9, "ssn").with_span(25..36),
        ];
        assert_eq!(mask(text, &findings), "a ‹AWS_KEY› b ‹SSN› c");
    }

    #[test]
    fn findings_without_spans_are_ignored() {
        let text = "nothing to mask";
        let findings = vec![Finding::new("injection", Severity::High, 0.9, "x")];
        assert_eq!(mask(text, &findings), text);
    }

    #[test]
    fn overlapping_spans_keep_longest_earliest() {
        // Nested spans: the earliest-starting longest span wins; the inner one is dropped.
        let text = "SECRETVALUE tail";
        let findings = vec![
            Finding::new("secret.aws_key", Severity::Critical, 0.95, "outer").with_span(0..11),
            Finding::new("secret.generic", Severity::Low, 0.5, "inner").with_span(2..7),
        ];
        assert_eq!(mask(text, &findings), "‹AWS_KEY› tail");
    }

    #[test]
    fn partially_overlapping_span_extends_the_masked_region() {
        // Found by the `detectors` fuzz target: a span starting inside an earlier one
        // but ending past it used to be dropped, leaving its tail unmasked.
        let text = "aaaaBBBBcccc tail";
        let findings = vec![
            Finding::new("secret.generic", Severity::Low, 0.5, "first").with_span(0..8),
            Finding::new("pii.email", Severity::Medium, 0.9, "second").with_span(4..12),
        ];
        assert_eq!(mask(text, &findings), "‹GENERIC› tail");
    }

    #[test]
    fn real_detectors_partial_overlap_leaves_nothing_in_the_clear() {
        // secret.generic stops at '@'; pii.email starts after the '/' (not an email
        // char) and runs through the domain. Before the fix the domain leaked.
        use crate::{Context, Detector, PiiDetector, SecretDetector};
        let text = "token Zq9/abcdefghijklmnopqrstuvwxyz0123@evil.example.com end";
        let ctx = Context::input(text);
        let mut findings = SecretDetector::new().inspect(&ctx);
        findings.extend(PiiDetector::new().inspect(&ctx));
        let generic = findings
            .iter()
            .find(|f| f.detector == "secret.generic")
            .and_then(|f| f.span.clone())
            .expect("generic token found");
        let email = findings
            .iter()
            .find(|f| f.detector == "pii.email")
            .and_then(|f| f.span.clone())
            .expect("email found");
        assert!(
            generic.start < email.start && email.start < generic.end && generic.end < email.end,
            "fixture must produce a partial overlap: {generic:?} {email:?}"
        );
        let masked = mask(text, &findings);
        assert_eq!(masked, "token ‹GENERIC› end");
        assert!(!masked.contains("evil.example.com"));
    }

    #[test]
    fn reversed_span_is_skipped() {
        let text = "abcdef";
        let findings = vec![Finding::new("pii.x", Severity::Low, 0.5, "x")
            .with_span(std::ops::Range { start: 4, end: 2 })];
        assert_eq!(mask(text, &findings), text);
    }

    #[test]
    fn non_char_boundary_span_is_skipped_not_panicked() {
        // A span landing inside a multibyte char must be skipped, never panic.
        let text = "héllo"; // 'é' occupies bytes 1..3
        let findings = vec![Finding::new("pii.x", Severity::Low, 0.5, "x").with_span(2..4)];
        assert_eq!(mask(text, &findings), text); // unchanged, no panic
    }
}
