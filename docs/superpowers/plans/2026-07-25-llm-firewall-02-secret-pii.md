# LLM Firewall — Plan 2: Secret + PII Detectors + Masking

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add two detectors — secret detection (regex rules + Shannon-entropy gate) and PII detection (regex + Luhn-validated cards, with byte spans) — plus a span-based masker, all reusing the `Detector`/`Finding` types from Plan 1.

**Architecture:** Two new `Detector` impls under `detectors/`, a shared `util` module (entropy + Luhn), and a `masking` module that rewrites text by replacing finding spans with typed tokens. No I/O; pure functions throughout for testability.

**Tech Stack:** Rust, `regex`, std `LazyLock`. Depends on Plan 1 (`Finding`, `Severity`, `Detector`, `Context`).

**Prerequisite:** Plan 1 merged (green `llm-firewall-core`).

---

## File Structure (created/modified by this plan)

```
crates/core/src/
├── lib.rs                         # + module wiring/re-exports (modify)
├── util.rs                        # NEW: shannon_entropy, luhn_valid
├── masking.rs                     # NEW: mask(text, &[Finding]) -> String
└── detectors/
    ├── mod.rs                     # + pub mod secret; pub mod pii; (modify)
    ├── secret.rs                  # NEW: SecretDetector
    └── pii.rs                     # NEW: PiiDetector
```

---

## Task 1: `util` module — Shannon entropy + Luhn

**Files:**
- Create: `crates/core/src/util.rs`
- Modify: `crates/core/src/lib.rs`

- [ ] **Step 1: Write the module + tests**

Create `crates/core/src/util.rs`:
```rust
//! Small pure helpers shared by detectors.

use std::collections::HashMap;

/// Shannon entropy (bits per byte) of a string. Empty -> 0.0.
pub(crate) fn shannon_entropy(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts: HashMap<u8, usize> = HashMap::new();
    for b in s.bytes() {
        *counts.entry(b).or_insert(0) += 1;
    }
    let len = s.len() as f32;
    let mut h = 0.0f32;
    for &c in counts.values() {
        let p = c as f32 / len;
        h -= p * p.log2();
    }
    h
}

/// Luhn checksum validity over the digits found in `s`. Requires 13–19 digits.
pub(crate) fn luhn_valid(s: &str) -> bool {
    let digits: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    if !(13..=19).contains(&digits.len()) {
        return false;
    }
    let mut sum = 0u32;
    let mut alt = false;
    for &d in digits.iter().rev() {
        let mut x = d;
        if alt {
            x *= 2;
            if x > 9 {
                x -= 9;
            }
        }
        sum += x;
        alt = !alt;
    }
    sum % 10 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_of_uniform_is_zero() {
        assert_eq!(shannon_entropy("aaaaaaaa"), 0.0);
    }

    #[test]
    fn entropy_of_random_is_high() {
        // 16 distinct hex-ish chars -> ~4 bits/byte
        assert!(shannon_entropy("0123456789abcdef") > 3.5);
    }

    #[test]
    fn luhn_accepts_valid_card() {
        assert!(luhn_valid("4242 4242 4242 4242"));
    }

    #[test]
    fn luhn_rejects_invalid_and_short() {
        assert!(!luhn_valid("4242 4242 4242 4241"));
        assert!(!luhn_valid("1234"));
    }
}
```

Add to `crates/core/src/lib.rs` (module section):
```rust
mod util;
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p llm-firewall-core util`
Expected: 4 tests PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/core/src/util.rs crates/core/src/lib.rs
git commit -m "feat(core): util helpers — shannon_entropy + luhn_valid"
```

---

## Task 2: `SecretDetector`

**Files:**
- Create: `crates/core/src/detectors/secret.rs`
- Modify: `crates/core/src/detectors/mod.rs`, `crates/core/src/lib.rs`

- [ ] **Step 1: Write the detector + tests**

Create `crates/core/src/detectors/secret.rs`:
```rust
//! Secret detection: high-precision provider patterns + a generic high-entropy gate.

use std::sync::LazyLock;

use regex::Regex;

use crate::util::shannon_entropy;
use crate::{Context, Detector, Finding, Severity};

struct SecretRule {
    id: &'static str,
    re: Regex,
    severity: Severity,
    label: &'static str,
}

static RULES: LazyLock<Vec<SecretRule>> = LazyLock::new(|| {
    let raw: &[(&str, &str, Severity, &str)] = &[
        ("secret.aws_key", r"AKIA[0-9A-Z]{16}", Severity::Critical, "AWS access key id"),
        ("secret.github_pat", r"ghp_[A-Za-z0-9]{36}", Severity::Critical, "GitHub personal access token"),
        ("secret.slack", r"xox[baprs]-[0-9A-Za-z-]{10,48}", Severity::High, "Slack token"),
        (
            "secret.jwt",
            r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}",
            Severity::High,
            "JWT",
        ),
        (
            "secret.private_key",
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
            Severity::Critical,
            "private key material",
        ),
    ];
    raw.iter()
        .map(|(id, p, sev, label)| SecretRule {
            id,
            re: Regex::new(p).expect("static secret regex must compile"),
            severity: *sev,
            label,
        })
        .collect()
});

/// Generic high-entropy token: long alnum/base64-ish run with entropy above threshold.
static GENERIC_TOKEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/_-]{24,}").expect("generic token regex"));

const ENTROPY_THRESHOLD: f32 = 4.0;

#[derive(Default)]
pub struct SecretDetector;

impl SecretDetector {
    pub fn new() -> Self {
        Self
    }
}

impl Detector for SecretDetector {
    fn name(&self) -> &'static str {
        "secret"
    }

    fn inspect(&self, ctx: &Context) -> Vec<Finding> {
        let text = ctx.text;
        let mut out = Vec::new();

        for rule in RULES.iter() {
            for m in rule.re.find_iter(text) {
                out.push(
                    Finding::new(rule.id, rule.severity, 0.95, rule.label)
                        .with_span(m.start()..m.end()),
                );
            }
        }

        // Generic gate: only flag long tokens whose entropy looks key-like, and that
        // weren't already covered by a specific rule span.
        for m in GENERIC_TOKEN.find_iter(text) {
            if shannon_entropy(m.as_str()) < ENTROPY_THRESHOLD {
                continue;
            }
            let overlaps = out
                .iter()
                .any(|f| f.span.as_ref().is_some_and(|s| s.start <= m.start() && m.end() <= s.end));
            if overlaps {
                continue;
            }
            out.push(
                Finding::new("secret.generic", Severity::Low, 0.5, "high-entropy token")
                    .with_span(m.start()..m.end()),
            );
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_aws_key() {
        let det = SecretDetector::new();
        let f = det.inspect(&Context::input("key=AKIAIOSFODNN7EXAMPLE end"));
        assert!(f.iter().any(|x| x.detector == "secret.aws_key"));
        assert!(f.iter().find(|x| x.detector == "secret.aws_key").unwrap().span.is_some());
    }

    #[test]
    fn flags_private_key_header() {
        let det = SecretDetector::new();
        let f = det.inspect(&Context::input("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(f.iter().any(|x| x.detector == "secret.private_key"));
    }

    #[test]
    fn benign_prose_is_clean() {
        let det = SecretDetector::new();
        let f = det.inspect(&Context::input("The quick brown fox jumps over the lazy dog."));
        assert!(f.is_empty());
    }
}
```

- [ ] **Step 2: Wire the module**

In `crates/core/src/detectors/mod.rs` add:
```rust
pub mod secret;
```
In `crates/core/src/lib.rs` re-export block add:
```rust
pub use detectors::secret::SecretDetector;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p llm-firewall-core secret`
Expected: 3 tests PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/core/src/detectors/secret.rs crates/core/src/detectors/mod.rs crates/core/src/lib.rs
git commit -m "feat(core): SecretDetector — provider patterns + entropy gate"
```

---

## Task 3: `PiiDetector`

**Files:**
- Create: `crates/core/src/detectors/pii.rs`
- Modify: `crates/core/src/detectors/mod.rs`, `crates/core/src/lib.rs`

- [ ] **Step 1: Write the detector + tests**

Create `crates/core/src/detectors/pii.rs`:
```rust
//! PII detection: structured identifiers via regex; credit cards Luhn-validated.

use std::sync::LazyLock;

use regex::Regex;

use crate::util::luhn_valid;
use crate::{Context, Detector, Finding, Severity};

struct PiiRule {
    id: &'static str,
    re: Regex,
    severity: Severity,
    label: &'static str,
    /// Extra validation beyond the regex (e.g. Luhn for cards).
    validate: fn(&str) -> bool,
}

fn always(_: &str) -> bool {
    true
}

static RULES: LazyLock<Vec<PiiRule>> = LazyLock::new(|| {
    vec![
        PiiRule {
            id: "pii.email",
            re: Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}").unwrap(),
            severity: Severity::Medium,
            label: "email address",
            validate: always,
        },
        PiiRule {
            id: "pii.ssn",
            re: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),
            severity: Severity::High,
            label: "US SSN",
            validate: always,
        },
        PiiRule {
            id: "pii.ipv4",
            re: Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap(),
            severity: Severity::Low,
            label: "IPv4 address",
            validate: always,
        },
        PiiRule {
            id: "pii.credit_card",
            re: Regex::new(r"\b(?:\d[ -]?){13,19}\b").unwrap(),
            severity: Severity::High,
            label: "credit card number",
            validate: luhn_valid,
        },
    ]
});

#[derive(Default)]
pub struct PiiDetector;

impl PiiDetector {
    pub fn new() -> Self {
        Self
    }
}

impl Detector for PiiDetector {
    fn name(&self) -> &'static str {
        "pii"
    }

    fn inspect(&self, ctx: &Context) -> Vec<Finding> {
        let mut out = Vec::new();
        for rule in RULES.iter() {
            for m in rule.re.find_iter(ctx.text) {
                if !(rule.validate)(m.as_str()) {
                    continue;
                }
                out.push(
                    Finding::new(rule.id, rule.severity, 0.9, rule.label)
                        .with_span(m.start()..m.end()),
                );
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_email_with_span() {
        let det = PiiDetector::new();
        let f = det.inspect(&Context::input("reach me at alice@acme.com please"));
        let email = f.iter().find(|x| x.detector == "pii.email").unwrap();
        assert_eq!(&"reach me at alice@acme.com please"[email.span.clone().unwrap()], "alice@acme.com");
    }

    #[test]
    fn valid_card_flagged_invalid_ignored() {
        let det = PiiDetector::new();
        assert!(det.inspect(&Context::input("card 4242 4242 4242 4242")).iter().any(|x| x.detector == "pii.credit_card"));
        assert!(!det.inspect(&Context::input("card 4242 4242 4242 4241")).iter().any(|x| x.detector == "pii.credit_card"));
    }

    #[test]
    fn finds_ssn() {
        let det = PiiDetector::new();
        assert!(det.inspect(&Context::input("ssn 123-45-6789")).iter().any(|x| x.detector == "pii.ssn"));
    }
}
```

- [ ] **Step 2: Wire the module**

In `crates/core/src/detectors/mod.rs` add:
```rust
pub mod pii;
```
In `crates/core/src/lib.rs` re-export block add:
```rust
pub use detectors::pii::PiiDetector;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p llm-firewall-core pii`
Expected: 3 tests PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/core/src/detectors/pii.rs crates/core/src/detectors/mod.rs crates/core/src/lib.rs
git commit -m "feat(core): PiiDetector — email/ssn/ipv4/luhn-validated cards"
```

---

## Task 4: Span-based masker

**Files:**
- Create: `crates/core/src/masking.rs`
- Modify: `crates/core/src/lib.rs`

- [ ] **Step 1: Write the masker + tests**

Create `crates/core/src/masking.rs`:
```rust
//! Replace finding spans in text with typed tokens, e.g. "alice@acme.com" -> "‹EMAIL›".
//! Overlapping spans are resolved by keeping the earliest-starting, longest span.

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
        if span.start < cursor {
            continue; // overlaps an already-masked region
        }
        if span.start > text.len() || span.end > text.len() {
            continue; // defensive: stale span
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
        let findings = vec![Finding::new("pii.email", Severity::Medium, 0.9, "email").with_span(12..26)];
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
}
```

- [ ] **Step 2: Wire into lib.rs**

Add to `crates/core/src/lib.rs`:
```rust
mod masking;
```
and re-export:
```rust
pub use masking::mask;
```

- [ ] **Step 3: Run tests + full gate**

Run: `cargo test -p llm-firewall-core masking`
Expected: 3 tests PASS.
Run: `cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test --all`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add crates/core/src/masking.rs crates/core/src/lib.rs
git commit -m "feat(core): span-based masker with overlap resolution"
```

---

## Self-Review

**Spec coverage (design §4 detectors 2 & 3, masking):** Secret detector (provider regex + entropy gate) → Task 2 ✓. PII detector (email/SSN/IPv4/Luhn card) with spans → Task 3 ✓. Masking with typed tokens → Task 4 ✓. Entropy + Luhn helpers → Task 1 ✓.

**Placeholder scan:** none — all steps have complete code.

**Type consistency:** all detectors return `Vec<Finding>` and implement `Detector` exactly as defined in Plan 1. `Finding.detector` is a `String` (Plan 1 Task 3), which `token_for` and the `detector ==` assertions rely on. `mask(&str, &[Finding]) -> String` is the single masker signature used everywhere. Detector ids use the `category.subtype` convention (`pii.email`, `secret.aws_key`) that `token_for` splits on.

**Next:** Plan 3 — candle ML injection stage.
