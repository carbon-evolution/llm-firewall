//! `llm-firewall-core` — the pure-Rust detection engine.
//! No I/O lives here; detectors return `Finding`s and the scorer aggregates them.

mod severity;
pub use severity::Severity;
