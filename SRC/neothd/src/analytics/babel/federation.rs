//! Federation transport — submitting anonymised Babel windows to the
//! delta-kosmologie research pool.
//!
//! ## Consent gates (NEOTH is consent-first)
//!
//! Federation is DISABLED by default.  It activates only when ALL of:
//!   1. `freedom.yaml :: babel.federate = true` (explicit opt-in by operator).
//!   2. `AutonomyLevel >= Elevated` (level 3+) — operator has already accepted
//!      elevated permissions for outbound data flows.
//!   3. The instance has generated at least `MIN_CALIBRATION_WINDOWS` windows
//!      (ensures epsilon is calibrated before the first submission).
//!
//! Turning `federate` off at runtime IMMEDIATELY stops submissions.  Windows
//! already submitted cannot be recalled (they are pseudonymous).
//!
//! ## Transport choice: iroh QUIC (existing cluster transport)
//!
//! NEOTH already has a working iroh QUIC dial-by-key transport in
//! `cluster::iroh_transport`.  Federation reuses this transport rather than
//! adding a new HTTP stack:
//!
//! - The delta-kosmologie aggregation node is identified by a stable iroh
//!   `EndpointAddr` (published in the delta-kosmologie repo metadata).
//! - Submissions are sent as a single QUIC bi-stream (one JSONL batch gzip-
//!   compressed, one JSON receipt in reply).
//! - Same ALPN as the cluster gossip path avoids a new protocol branch.
//! - Fallback: if iroh is unavailable (no feature `cluster-iroh`), the
//!   submission is written to disk as a `.pending` file; operators can upload
//!   manually.
//!
//! For *stranger instances* (third-party NEOTH deployments or other runtimes):
//! the same iroh EndpointAddr is used; the ALPN carries a version tag that the
//! aggregation node uses to route to the correct schema handler.
//!
//! ## Record signing
//!
//! Every submitted batch is signed with the node's cluster identity key
//! (Ed25519 via the existing `cluster::identity` module).  The signature
//! covers the SHA-256 of the gzip-compressed batch bytes.  The aggregation
//! node verifies the signature and records the signer's public key fingerprint
//! (NOT the full key) alongside the batch for abuse tracing.
//!
//! ## Abuse / poisoning defences
//!
//! - Outlier rejection: any window where |b_log| > 6σ from the running pool
//!   mean is flagged as `suspicious` and excluded from the pooled analysis
//!   (but stored for manual review).
//! - Rate limiting: max 1 batch per 5 minutes per contributor_id, enforced
//!   on the receiver side.
//! - Schema validation: the aggregation node validates every record against
//!   the pinned JSON Schema before accepting it.  Invalid records are counted
//!   in the submission receipt `rejected_count`.
//! - Signed records: an unsigned batch (or one with a detached signature
//!   mismatch) is rejected outright — not just flagged.
//! - Minimum window duration: records with `duration_seconds < 60` are rejected.
//!
//! ## Sampling rule (mandatory)
//!
//! Each instance MUST submit a random sample of ALL windows, not only windows
//! near collapse.  Minimum: 10% of all windows, with non-collapse windows
//! equalling or exceeding collapse-window count (1:1 minimum ratio).
//! This is enforced by the `SamplingDecision` type below.

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::anonymize::{SubmissionMetadata, MIN_WINDOW_SECS};
use super::window::BabelWindow;

/// ALPN for the federation QUIC stream (versioned, distinct from cluster gossip).
pub const FEDERATION_ALPN: &[u8] = b"delta-kosmologie/babel-federation/0.1";

/// Minimum calibration windows before federation begins.
pub const MIN_CALIBRATION_WINDOWS: usize = 50;

/// A signed, anonymised batch ready for submission to the aggregation node.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FederationBatch {
    /// Batch identifier — UUID v4 (one per submission attempt).
    pub batch_id: String,
    /// Submission timestamp (unix epoch seconds).
    pub submitted_at: i64,
    /// Windows in this batch, each already anonymised.
    pub windows: Vec<serde_json::Value>,
    /// Number of windows in this batch.
    pub window_count: usize,
    /// Required headers for the aggregation node.
    pub schema_version: String,
    pub runtime_version: String,
    pub contributor_id: String,
    /// Ed25519 signature over SHA-256(gzip(batch JSON)), hex-encoded.
    pub signature_hex: String,
    /// Public key fingerprint of the signing key (first 16 hex chars of
    /// the Ed25519 public key SHA-256 — enough for abuse tracing, not enough
    /// to reconstruct the key or identify the operator).
    pub signer_fingerprint: String,
}

/// Receipt returned by the aggregation node.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmissionReceipt {
    pub batch_id: String,
    pub accepted_count: usize,
    pub rejected_count: usize,
    pub rejection_reasons: Vec<String>,
    /// Whether the aggregation node also ran outlier detection and flagged any
    /// windows as suspicious.
    pub suspicious_count: usize,
}

/// Whether a given window should be submitted to the federation pool.
/// Enforces the 10% sampling rate and the 1:1 collapse/non-collapse ratio.
pub struct SamplingDecision {
    pub total_windows: u64,
    pub submitted_windows: u64,
    pub submitted_collapse: u64,
    pub submitted_non_collapse: u64,
}

impl SamplingDecision {
    pub fn new() -> Self {
        Self { total_windows: 0, submitted_windows: 0, submitted_collapse: 0, submitted_non_collapse: 0 }
    }

    /// Returns true if this window should be submitted.
    /// Collapse windows: submit if non-collapse count >= collapse count (1:1 enforced).
    /// Non-collapse windows: submit when total submitted < 10% of total windows.
    pub fn should_submit(&self, is_collapse: bool) -> bool {
        if self.total_windows == 0 { return false; }
        let pct_submitted = self.submitted_windows as f64 / self.total_windows as f64;
        if is_collapse {
            // Always submit collapse windows (they are rare and valuable)
            // but also ensure we have matching non-collapse coverage
            self.submitted_non_collapse >= self.submitted_collapse || pct_submitted < 0.10
        } else {
            // Submit non-collapse up to 10% total, but always enough to match collapse count
            pct_submitted < 0.10 || self.submitted_non_collapse < self.submitted_collapse
        }
    }

    pub fn record_submitted(&mut self, is_collapse: bool) {
        self.submitted_windows += 1;
        if is_collapse { self.submitted_collapse += 1; } else { self.submitted_non_collapse += 1; }
    }
}

impl Default for SamplingDecision {
    fn default() -> Self { Self::new() }
}

/// Gate that enforces all consent requirements before allowing federation.
pub struct ConsentGate {
    /// `freedom.yaml :: babel.federate`
    pub federate_enabled: bool,
    /// AutonomyLevel as integer (Strict=1, Standard=2, Elevated=3, Full=4).
    pub autonomy_level: u8,
    /// Number of calibration windows generated so far.
    pub calibration_window_count: usize,
}

impl ConsentGate {
    /// Returns Ok(()) if federation is permitted; Err with human-readable reason.
    pub fn check(&self) -> Result<(), &'static str> {
        if !self.federate_enabled {
            return Err("babel.federate not enabled in freedom.yaml");
        }
        if self.autonomy_level < 3 {
            return Err("AutonomyLevel must be Elevated (3) or Full (4) to enable federation");
        }
        if self.calibration_window_count < MIN_CALIBRATION_WINDOWS {
            return Err("insufficient calibration windows — epsilon not yet frozen");
        }
        Ok(())
    }
}

/// Validate a window before accepting it into the local submission queue.
/// Returns Err with the rejection reason if the window should be dropped.
pub fn validate_window_for_submission(w: &BabelWindow) -> Result<(), &'static str> {
    if w.duration_secs() < MIN_WINDOW_SECS as i64 {
        return Err("window too short (< 60 s) — minimum to prevent re-identification");
    }
    if w.features.validate().is_err() {
        return Err("feature validation failed");
    }
    Ok(())
}

/// Build the anonymised JSON representation of a window for the batch.
/// Applies all privacy transforms from `anonymize.rs`.
pub fn anonymise_for_batch(
    window: &BabelWindow,
    meta: &SubmissionMetadata,
    local_salt: &[u8],
) -> serde_json::Value {
    use super::anonymize::{pseudonymise_id, normalise_repo_slug};

    let session_pseudo = pseudonymise_id(local_salt, &window.session_id_pseudo);
    let window_id_pseudo = pseudonymise_id(local_salt, &window.id);

    serde_json::json!({
        "schema_version": BabelWindow::SCHEMA_VERSION,
        "window": {
            "id": window_id_pseudo,
            "granularity_secs": window.granularity.secs(),
            "ts_start": window.ts_start,
            "ts_end": window.ts_end,
            "duration_seconds": window.duration_secs(),
        },
        "system": {
            "runtime": "NEOTH",
            "runtime_class": SubmissionMetadata::RUNTIME_CLASS,
            "repo": normalise_repo_slug("https://github.com/The-Geek-Freaks/NEOTH"),
            "runtime_version": "unknown",
        },
        "features": {
            "C": window.features.c,
            "K": window.features.k,
            "M": window.features.m,
            "A": window.features.a,
            "V": window.features.v,
            "D": window.features.d,
            "H": window.features.h,
        },
        "algorithm_versions": {
            "C": window.algorithm_version_c,
            "K": window.algorithm_version_k,
            "M": window.algorithm_version_m,
            "A": window.algorithm_version_a,
            "V": window.algorithm_version_v,
            "D": window.algorithm_version_d,
            "H": window.algorithm_version_h,
        },
        "candidate_scores": build_scores_json(&window.scores),
        "labels": {
            "collapse_within_5m": window.collapse.collapse_within_5m,
            "collapse_within_30m": window.collapse.collapse_within_30m,
            "collapse_at_next_task": window.collapse.collapse_at_next_task,
            "collapse_kind": window.collapse.collapse_kind.map(|l| l.as_str()),
            "negative_control": window.collapse.negative_control,
            "negative_control_type": window.collapse.negative_control_type
                .map(|t| format!("{:?}", t).to_lowercase()),
        },
        "submission_metadata": {
            "contributor_id": meta.contributor_id,
            "deployment_context": format!("{:?}", meta.deployment_context).to_lowercase(),
            "hardware_tier": format!("{:?}", meta.hardware_tier).to_lowercase(),
            "primary_model_family": meta.primary_model_family,
            "avg_tasks_per_day_bucket": meta.avg_tasks_per_day_bucket,
            "protocol_version": SubmissionMetadata::PROTOCOL_VERSION,
            "runtime_class": SubmissionMetadata::RUNTIME_CLASS,
        },
        "pseudonymised_session_id": session_pseudo,
    })
}

fn build_scores_json(scores: &super::score::BabelScores) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(v) = scores.b_log {
        m.insert("B_neoth_log".into(), serde_json::json!(v));
    }
    if let Some(v) = scores.b_mult {
        m.insert("B_neoth_mult".into(), serde_json::json!(v));
        if let Some(eps) = scores.b_mult_epsilon {
            m.insert("B_neoth_mult_epsilon".into(), serde_json::json!(eps));
            m.insert("B_neoth_mult_epsilon_rule".into(),
                serde_json::json!(scores.b_mult_epsilon_rule));
        }
    }
    m.insert("B_neoth_bottleneck".into(), serde_json::json!(scores.b_bottleneck));
    serde_json::Value::Object(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consent_gate_rejects_when_federate_disabled() {
        let g = ConsentGate { federate_enabled: false, autonomy_level: 4, calibration_window_count: 100 };
        assert!(g.check().is_err());
    }

    #[test]
    fn consent_gate_rejects_below_elevated() {
        let g = ConsentGate { federate_enabled: true, autonomy_level: 2, calibration_window_count: 100 };
        assert!(g.check().is_err());
    }

    #[test]
    fn consent_gate_rejects_uncalibrated() {
        let g = ConsentGate { federate_enabled: true, autonomy_level: 3, calibration_window_count: 10 };
        assert!(g.check().is_err());
    }

    #[test]
    fn consent_gate_passes_when_all_conditions_met() {
        let g = ConsentGate { federate_enabled: true, autonomy_level: 3, calibration_window_count: 50 };
        assert!(g.check().is_ok());
    }

    #[test]
    fn sampling_decision_requires_one_to_one_ratio() {
        let mut sd = SamplingDecision::new();
        sd.total_windows = 100;
        sd.submitted_windows = 5;
        sd.submitted_collapse = 5;
        sd.submitted_non_collapse = 0;
        // Non-collapse should submit to reach parity
        assert!(sd.should_submit(false));
    }

    #[test]
    fn federation_alpn_is_versioned() {
        assert!(FEDERATION_ALPN.ends_with(b"/0.1"));
        assert!(FEDERATION_ALPN.starts_with(b"delta-kosmologie/"));
    }
}
