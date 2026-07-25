//! A single structured detector result. Detectors NEVER return bare bools —
//! scoring, masking, and audit all consume this one shape.

use std::ops::Range;

use serde::{Deserialize, Serialize};

use crate::Severity;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable detector id, e.g. "injection", "pii.email", "secret.aws_key".
    pub detector: String,
    pub severity: Severity,
    /// Detector confidence in `[0.0, 1.0]`.
    pub confidence: f32,
    /// Byte range in the inspected text (for masking / highlighting), if known.
    pub span: Option<Range<usize>>,
    /// Human-readable description.
    pub label: String,
}

impl Finding {
    pub fn new(
        detector: impl Into<String>,
        severity: Severity,
        confidence: f32,
        label: impl Into<String>,
    ) -> Self {
        Self {
            detector: detector.into(),
            severity,
            confidence: confidence.clamp(0.0, 1.0),
            span: None,
            label: label.into(),
        }
    }

    /// Builder: attach a byte span.
    pub fn with_span(mut self, span: Range<usize>) -> Self {
        self.span = Some(span);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamps_confidence_and_sets_fields() {
        let f = Finding::new("injection", Severity::High, 1.5, "override phrase");
        assert_eq!(f.detector, "injection");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.confidence, 1.0); // clamped
        assert_eq!(f.span, None);
        assert_eq!(f.label, "override phrase");
    }

    #[test]
    fn with_span_attaches_range() {
        let f = Finding::new("pii.email", Severity::Medium, 0.9, "email").with_span(4..17);
        assert_eq!(f.span, Some(4..17));
    }
}
