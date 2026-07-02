//! Babel-Index analytics subsystem.
//!
//! Implements the NEOTH-side half of the NEOTH ↔ delta-kosmologie
//! federation protocol.  Three concerns live here:
//!
//! 1. **Feature extraction** from the WAL event stream.
//!    Each of the seven B_d variables has a typed extractor module.
//! 2. **Rolling-window aggregation** at three granularities (300/900/3600 s),
//!    persisted in `idx_babel_windows` (SQLite).
//! 3. **Federation** — anonymised window records submitted (opt-in,
//!    Elevated+ autonomy, explicit operator consent) to the shared
//!    delta-kosmologie research pool via the existing iroh/Hyperswarm
//!    transport, signed with the cluster node key, and verified by the
//!    receiver before pooling.
//!
//! ## Design constraints respected from the review brief
//!
//! - **Async-only observer**: never blocks inference, tool calls, or routing.
//! - **No operator content**: only derived metrics, never prompts/responses.
//! - **Consent-first**: federation is disabled by default; requires
//!   `babel.federate = true` in `freedom.yaml` AND `AutonomyLevel >= Elevated`.
//! - **Epsilon governance**: log form is the primary form; multiplicative
//!   epsilon = `0.01 * median((D/A)*(H/V))` (the simplified form's actual
//!   buffer denominator — upstream ratio-form fix `a4bd367`, 2026-07-02)
//!   frozen on the first calibration batch.
//! - **Record signing**: every federated window carries an Ed25519 signature
//!   over the canonical JSON bytes, keyed by the node's cluster identity key.

pub mod anonymize;
pub mod collapse;
pub mod config;
pub mod coupling;
pub mod cron;
pub mod feature;
pub mod federation;
pub mod norm;
pub mod score;
pub mod store;
pub mod window;

pub use config::BabelConfig;
pub use feature::BabelFeatures;
pub use score::BabelScores;
pub use window::{BabelWindow, WindowGranularity};
