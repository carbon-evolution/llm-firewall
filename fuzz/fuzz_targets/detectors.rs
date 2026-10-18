//! The core detection pipeline on arbitrary text: injection signatures/heuristics,
//! secrets, PII, output and moderation detectors, the evasion normalizer (all tiers,
//! including base64 decode), scoring, policy and masking.
//!
//! Catches panics (UTF-8 char-boundary slicing, index arithmetic), pathological
//! slowness (libFuzzer -timeout), detector spans that `mask` would silently skip,
//! and masking that leaves part of a detected span in the clear (differential check
//! against `reference_mask`). The tail of the input also drives a set of synthetic
//! findings with arbitrary — often invalid — spans straight into `mask`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use llm_firewall_core::{Finding, Severity};
use llm_firewall_fuzz::{check_mask, check_text, full_normalizer};

const NAMES: [&str; 4] = ["pii.email", "secret.aws_key", "secret.generic", "pii"];

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    check_text(&text);

    let n = full_normalizer().normalize(&text);
    assert_eq!(n.changed, n.text != text.as_ref());

    // Synthetic findings: up to 8 (start, len) byte pairs from the end of the input,
    // scaled to land anywhere in (and just past) the text, so `mask` sees
    // out-of-bounds, reversed-looking, overlapping and mid-char spans.
    let len = text.len();
    let findings: Vec<Finding> = data
        .rchunks_exact(2)
        .take(8)
        .enumerate()
        .map(|(i, c)| {
            let start = (c[0] as usize * (len + 2)) / 256;
            let end = start + (c[1] as usize % 24);
            Finding::new(NAMES[i % NAMES.len()], Severity::Low, 0.5, "synthetic")
                .with_span(start..end)
        })
        .collect();
    check_mask(&text, &findings);
});
