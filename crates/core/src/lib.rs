//! `llm-firewall-core` — the pure-Rust detection engine.
//! No I/O lives here; detectors return `Finding`s and the scorer aggregates them.

mod context;
mod detector;
mod finding;
mod firewall;
mod masking;
mod policy;
mod scoring;
mod severity;
mod util;

pub mod detectors;

pub use context::{Context, Direction};
pub use detector::Detector;
pub use detectors::injection::InjectionDetector;
pub use detectors::pii::PiiDetector;
pub use detectors::secret::SecretDetector;
pub use finding::Finding;
pub use firewall::{Firewall, Outcome};
pub use masking::mask;
pub use policy::{Action, Condition, Decision, PolicySet, Rule};
pub use scoring::{score_findings, RiskScore};
pub use severity::Severity;
