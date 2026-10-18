//! Shared fixtures and invariant checks for the fuzz targets.
//!
//! Every target builds the firewall the way the proxy does (all five detectors, the
//! shipped `policies/default.yaml`), plus a second "mask everything" firewall so the
//! masking path runs on every input that produces a span, not only on PII.

use std::ops::Range;
use std::sync::LazyLock;

use llm_firewall_core::{
    Detector, Finding, Firewall, InjectionDetector, ModerationDetector, Normalizer, OutputDetector,
    PiiDetector, PolicySet, SecretDetector,
};

/// The policy the proxy ships with.
pub const DEFAULT_POLICY: &str = include_str!("../../policies/default.yaml");

/// Mask on any finding at all, so `mask()` sees every detector's spans.
const MASK_ALL_POLICY: &str =
    "policies:\n  - name: mask-all\n    when: {}\n    action: mask\ndefault: allow\n";

/// The detector set `llm_firewall::build_firewall` uses (kept in sync by hand: the
/// fuzz crate does not call into `crates/proxy/src/lib.rs`).
pub fn detectors() -> Vec<Box<dyn Detector>> {
    vec![
        Box::new(InjectionDetector::new()),
        Box::new(SecretDetector::new()),
        Box::new(PiiDetector::new()),
        Box::new(OutputDetector::new()),
        Box::new(ModerationDetector::new()),
    ]
}

/// Every normalization tier on, including the opt-in base64 decode.
pub fn full_normalizer() -> Normalizer {
    Normalizer {
        strip_zero_width: true,
        fold_homoglyphs: true,
        decode_encoded: true,
    }
}

/// Production detectors + shipped policy + full normalizer.
pub static DEFAULT_FW: LazyLock<Firewall> = LazyLock::new(|| {
    let policy = PolicySet::from_yaml(DEFAULT_POLICY).expect("shipped policy parses");
    Firewall::new(detectors(), policy).with_normalizer(full_normalizer())
});

/// Production detectors, mask on any finding.
pub static MASK_FW: LazyLock<Firewall> = LazyLock::new(|| {
    let policy = PolicySet::from_yaml(MASK_ALL_POLICY).expect("mask-all policy parses");
    Firewall::new(detectors(), policy).with_normalizer(full_normalizer())
});

/// A span is usable only if it is in bounds and on UTF-8 char boundaries.
fn span_ok(text: &str, s: &Range<usize>) -> bool {
    s.start <= s.end
        && s.end <= text.len()
        && text.is_char_boundary(s.start)
        && text.is_char_boundary(s.end)
}

/// Detectors scan the ORIGINAL text and their spans are what `mask` replaces. A span
/// that is out of bounds or splits a UTF-8 char is silently skipped by `mask`, which
/// would leave the secret/PII it points at unmasked — so treat it as a bug.
pub fn assert_spans_valid(text: &str, findings: &[Finding]) {
    for f in findings {
        if let Some(s) = &f.span {
            assert!(
                span_ok(text, s),
                "detector {} produced invalid span {s:?} for text of {} bytes",
                f.detector,
                text.len()
            );
        }
    }
}

fn token_for(detector: &str) -> String {
    let suffix = detector.rsplit('.').next().unwrap_or(detector);
    format!("‹{}›", suffix.to_uppercase())
}

/// Reference model of `mask`: every byte covered by any valid span is replaced, and
/// overlapping spans merge into one region labelled by the earliest-starting,
/// longest span. Used as a differential oracle against `llm_firewall_core::mask`.
pub fn reference_mask(text: &str, findings: &[Finding]) -> String {
    let mut spans: Vec<(Range<usize>, String)> = findings
        .iter()
        .filter_map(|f| f.span.clone().map(|s| (s, token_for(&f.detector))))
        .filter(|(s, _)| span_ok(text, s))
        .collect();
    spans.sort_by(|a, b| a.0.start.cmp(&b.0.start).then(b.0.end.cmp(&a.0.end)));
    let mut out = String::new();
    let mut cursor = 0usize;
    let mut i = 0;
    while i < spans.len() {
        let (first, token) = &spans[i];
        if first.start < cursor {
            // Starts inside an already-masked region: it only extends that region.
            cursor = cursor.max(first.end);
            i += 1;
            continue;
        }
        out.push_str(&text[cursor..first.start]);
        out.push_str(token);
        cursor = first.end;
        i += 1;
    }
    out.push_str(&text[cursor..]);
    out
}

/// `mask` must never panic, and must agree with the reference model.
pub fn check_mask(text: &str, findings: &[Finding]) {
    let got = llm_firewall_core::mask(text, findings);
    let want = reference_mask(text, findings);
    assert_eq!(got, want, "mask() disagrees with reference model");
}

/// Run `text` through both firewalls in both directions and check the invariants.
pub fn check_text(text: &str) {
    use llm_firewall_core::Direction;
    for dir in [Direction::Input, Direction::Output] {
        let out = DEFAULT_FW.run(text, dir);
        assert!(out.score.score <= 100, "score out of range");
        let out = MASK_FW.run(text, dir);
        assert!(out.score.score <= 100, "score out of range");
        // Raw (original-text) findings are what masking uses.
        let mut raw = Vec::new();
        let ctx = match dir {
            Direction::Input => llm_firewall_core::Context::input(text),
            Direction::Output => llm_firewall_core::Context::output(text),
        };
        for d in detectors() {
            raw.extend(d.inspect(&ctx));
        }
        assert_spans_valid(text, &raw);
        check_mask(text, &raw);
        if let Some(masked) = out.transformed_text {
            assert_eq!(masked, llm_firewall_core::mask(text, &raw));
        }
    }
}
