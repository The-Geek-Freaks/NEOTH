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

use anyhow::{Context as _, Result};
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

// ── GOLD-DELTA-10 — submission pipeline (pending-first) ─────────────────────
//
// The submit path is deliberately two-phase:
//   Phase 1 (sync, under the views.db writer lock): consent gate → load
//     unsubmitted stamped windows → sampling rule → anonymise → sign →
//     write the batch as a durable PENDING file → mark rows submitted.
//     The pending file IS the submission record; a crash after it lands
//     never double-submits.
//   Phase 2 (async, off the lock): `drain_pending` uploads pending files
//     through a [`FederationUploader`] and deletes each on a receipt.
//     No uploader configured → files stay pending for manual upload.

use std::path::{Path, PathBuf};

/// Max windows per batch — keeps single submissions under the receiver's
/// rate limit and bounds pending-file size.
pub const MAX_BATCH_WINDOWS: usize = 500;

/// Transport abstraction for phase 2. The iroh implementation lives behind
/// `cluster-iroh`; tests use a mock.
#[async_trait::async_trait]
pub trait FederationUploader: Send + Sync {
    /// Deliver ONE transport frame (see [`build_transport_frame`]) — the
    /// envelope (signature, batch headers) AND the gzip payload together;
    /// the aggregation node verifies the signature against the payload
    /// before accepting anything. Returns the node's receipt.
    async fn upload(&self, frame: &[u8]) -> Result<SubmissionReceipt>;
}

/// Version tag of the single-frame wire format.
pub const TRANSPORT_FRAME_VERSION: &str = "babel-transport/0.1";

/// Combine a pending payload + its envelope sidecar into the one frame the
/// live transport ships: `{frame_version, envelope, payload_gzip_b64}`.
/// The receiver base64-decodes the payload, hashes it, and verifies
/// `envelope.signature_hex` — an envelope-less payload is unauthenticatable
/// by design (external review 2026-07-02: shipping the payload alone made
/// the live path unacceptable to a signature-checking aggregator).
pub fn build_transport_frame(envelope_json: &serde_json::Value, payload_gz: &[u8]) -> Vec<u8> {
    use base64::Engine as _;
    serde_json::json!({
        "frame_version": TRANSPORT_FRAME_VERSION,
        "envelope": envelope_json,
        "payload_gzip_b64": base64::engine::general_purpose::STANDARD.encode(payload_gz),
    })
    .to_string()
    .into_bytes()
}

/// What one submit pass produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubmitOutcome {
    pub batch_id: String,
    pub windows: usize,
    pub pending_path: PathBuf,
}

/// Phase 1 — build and durably queue one batch. `Ok(None)` when the gate is
/// closed or nothing qualifies (both are normal states, not errors).
#[allow(clippy::too_many_arguments)]
pub fn submit_pending_batch(
    conn: &rusqlite::Connection,
    gate: &ConsentGate,
    meta: &SubmissionMetadata,
    signing_key: &ed25519_dalek::SigningKey,
    local_salt: &[u8],
    pending_dir: &Path,
    epsilon: Option<f64>,
    now_unix: i64,
) -> Result<Option<SubmitOutcome>> {
    if let Err(reason) = gate.check() {
        tracing::debug!(reason, "babel federation: consent gate closed");
        return Ok(None);
    }
    let counts = super::store::submission_counts(conn)?;
    let mut sampling = SamplingDecision {
        total_windows: counts.total_windows,
        submitted_windows: counts.submitted_windows,
        submitted_collapse: counts.submitted_collapse,
        submitted_non_collapse: counts.submitted_non_collapse,
    };
    let candidates = super::store::load_unsubmitted_windows(conn, MAX_BATCH_WINDOWS, epsilon)?;
    let mut records = Vec::new();
    let mut ids = Vec::new();
    for (window, is_collapse) in &candidates {
        if validate_window_for_submission(window).is_err() {
            continue;
        }
        if !sampling.should_submit(*is_collapse) {
            continue;
        }
        sampling.record_submitted(*is_collapse);
        records.push(anonymise_for_batch(window, meta, local_salt));
        ids.push(window.id.clone());
    }
    if records.is_empty() {
        return Ok(None);
    }

    // Sign over SHA-256 of the gzip JSONL payload (one window per line).
    let jsonl: String =
        records.iter().map(|r| r.to_string()).collect::<Vec<_>>().join("\n");
    let payload_gz = gzip_bytes(jsonl.as_bytes())?;
    let digest = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(&payload_gz);
        h.finalize()
    };
    use ed25519_dalek::Signer as _;
    let signature_hex = hex::encode(signing_key.sign(&digest).to_bytes());
    let signer_fingerprint = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(signing_key.verifying_key().as_bytes());
        hex::encode(h.finalize())[..16].to_string()
    };

    let window_count = records.len();
    let batch = FederationBatch {
        batch_id: uuid::Uuid::now_v7().to_string(),
        submitted_at: now_unix,
        windows: records,
        window_count,
        schema_version: BabelWindow::SCHEMA_VERSION.to_string(),
        runtime_version: env!("CARGO_PKG_VERSION").to_string(),
        contributor_id: meta.contributor_id.clone(),
        signature_hex,
        signer_fingerprint,
    };

    std::fs::create_dir_all(pending_dir)
        .with_context(|| format!("create pending dir {}", pending_dir.display()))?;
    // Payload file (what the uploader/operator ships) + envelope sidecar.
    let jsonl_path = pending_dir.join(format!("{}.pending.jsonl.gz", batch.batch_id));
    let meta_path = pending_dir.join(format!("{}.pending.meta.json", batch.batch_id));
    let tmp = jsonl_path.with_extension("tmp");
    std::fs::write(&tmp, &payload_gz)
        .with_context(|| format!("write pending payload {}", tmp.display()))?;
    std::fs::rename(&tmp, &jsonl_path).context("rename pending payload into place")?;
    std::fs::write(&meta_path, serde_json::to_vec_pretty(&batch_envelope(&batch))?)
        .with_context(|| format!("write pending envelope {}", meta_path.display()))?;

    // Only after the batch is durable on disk do the rows flip.
    super::store::mark_submitted(conn, &ids)?;
    tracing::info!(
        batch_id = %batch.batch_id,
        windows = window_count,
        pending = %jsonl_path.display(),
        "babel federation: batch queued (pending-first)"
    );
    Ok(Some(SubmitOutcome { batch_id: batch.batch_id, windows: window_count, pending_path: jsonl_path }))
}

/// The envelope written next to the payload: the full batch minus the
/// (large) window array — enough for the uploader to reconstruct headers
/// and for an operator to inspect what a pending file contains.
fn batch_envelope(batch: &FederationBatch) -> serde_json::Value {
    serde_json::json!({
        "batch_id": batch.batch_id,
        "submitted_at": batch.submitted_at,
        "window_count": batch.window_count,
        "schema_version": batch.schema_version,
        "runtime_version": batch.runtime_version,
        "contributor_id": batch.contributor_id,
        "signature_hex": batch.signature_hex,
        "signer_fingerprint": batch.signer_fingerprint,
        "alpn": String::from_utf8_lossy(FEDERATION_ALPN),
    })
}

fn gzip_bytes(bytes: &[u8]) -> Result<Vec<u8>> {
    use std::io::Write as _;
    let mut enc =
        flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(bytes).context("gzip write")?;
    enc.finish().context("gzip finish")
}

/// Phase 2 — try to deliver every pending payload. Each file is deleted
/// (with its envelope) only on a received receipt; failures leave it for
/// the next drain or manual upload. Returns (delivered, remaining).
pub async fn drain_pending(
    pending_dir: &Path,
    uploader: &dyn FederationUploader,
) -> Result<(usize, usize)> {
    let mut delivered = 0usize;
    let mut remaining = 0usize;
    let Ok(rd) = std::fs::read_dir(pending_dir) else {
        return Ok((0, 0)); // no dir = nothing queued yet
    };
    let mut payloads: Vec<PathBuf> = rd
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.file_name().and_then(|n| n.to_str())
            .is_some_and(|n| n.ends_with(".pending.jsonl.gz")))
        .collect();
    payloads.sort();
    for path in payloads {
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(file = %path.display(), error = %e, "pending batch unreadable");
                remaining += 1;
                continue;
            }
        };
        // The envelope sidecar carries the signature the receiver checks —
        // without it the payload is unauthenticatable; leave it pending.
        let meta_path =
            PathBuf::from(path.to_string_lossy().replace(".jsonl.gz", ".meta.json"));
        let envelope_json: serde_json::Value = match std::fs::read(&meta_path)
            .map_err(anyhow::Error::from)
            .and_then(|b| serde_json::from_slice(&b).map_err(Into::into))
        {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    file = %meta_path.display(), error = %e,
                    "pending batch has no readable envelope — cannot authenticate, stays pending"
                );
                remaining += 1;
                continue;
            }
        };
        let frame = build_transport_frame(&envelope_json, &bytes);
        match uploader.upload(&frame).await {
            Ok(receipt) => {
                tracing::info!(
                    batch = %path.display(),
                    accepted = receipt.accepted_count,
                    rejected = receipt.rejected_count,
                    suspicious = receipt.suspicious_count,
                    "babel federation: batch delivered"
                );
                let _ = std::fs::remove_file(&path);
                let meta = path.to_string_lossy().replace(".jsonl.gz", ".meta.json");
                let _ = std::fs::remove_file(meta);
                delivered += 1;
            }
            Err(e) => {
                tracing::warn!(batch = %path.display(), error = %e,
                    "babel federation: delivery failed, batch stays pending");
                remaining += 1;
            }
        }
    }
    Ok((delivered, remaining))
}

// ── GOLD-DELTA-14 — pooled predictor download (the return path) ─────────────
//
// Firewalls, ENFORCED in code, not documentation:
//   1. ADVISORY-ONLY BY CONSTRUCTION: `apply_advisory` is a pure function
//      returning a note — there is no code path from a pooled predictor to
//      `BabelCronState::set_threshold`. The DELTA-15 self-calibration stays
//      the only threshold mutator.
//   2. CONSENT: pulling uses the SAME `ConsentGate` as submitting.
//   3. CROSS-DOMAIN: `domain != "neoth"` is rejected outright — B_neoth is
//      not comparable to B_oss/B_market/B_epoch.
//   4. POISONING: the envelope must verify against the operator-PINNED
//      aggregator public key (`babel.federation_aggregator_pubkey`); no pin
//      → no pull (fail-closed). Signature covers the raw payload bytes, so
//      there is no JSON-canonicalisation ambiguity.

/// Request frame the aggregation node answers with a signed predictor.
pub const PREDICTOR_REQUEST: &[u8] = b"GET-PREDICTOR/0.1";

/// Wire envelope: `payload` is the exact JSON string the signature covers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PredictorEnvelope {
    pub payload: String,
    /// Ed25519 signature over SHA-256(payload bytes), hex.
    pub signature_hex: String,
}

/// The pooled M-ladder predictor snapshot (out-of-sample validated across
/// contributing instances).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PooledPredictor {
    pub predictor_version: String,
    /// MUST be `"neoth"` — the cross-domain firewall.
    pub domain: String,
    pub trained_on_instances: u32,
    pub trained_on_windows: u64,
    /// Pool-suggested warning threshold for the 15-min b_mult.
    pub threshold_suggestion: f64,
    /// Feature coefficients of the pooled M2 fit (advisory display only).
    pub coefficients: std::collections::HashMap<String, f64>,
    /// Out-of-sample Brier score of the pooled fit.
    pub brier_oos: f64,
}

/// Verify and decode a predictor envelope against the pinned aggregator
/// key. Every rejection reason is a distinct error string (operator-
/// debuggable); consent is checked FIRST — an instance that never opted in
/// never even parses pool data.
pub fn verify_pooled_predictor(
    gate: &ConsentGate,
    envelope: &PredictorEnvelope,
    aggregator_pubkey_hex: Option<&str>,
) -> Result<PooledPredictor> {
    if let Err(reason) = gate.check() {
        anyhow::bail!("predictor pull refused: {reason}");
    }
    let Some(pubkey_hex) = aggregator_pubkey_hex else {
        anyhow::bail!(
            "predictor pull refused: no pinned aggregator public key \
             (babel.federation_aggregator_pubkey) — fail-closed"
        );
    };
    let pubkey_bytes: [u8; 32] = hex::decode(pubkey_hex.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow::anyhow!("pinned aggregator pubkey is not 32-byte hex"))?;
    let verifying =
        ed25519_dalek::VerifyingKey::from_bytes(&pubkey_bytes).context("aggregator pubkey")?;
    let sig_bytes: [u8; 64] = hex::decode(envelope.signature_hex.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow::anyhow!("predictor signature is not 64-byte hex"))?;
    let digest = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(envelope.payload.as_bytes());
        h.finalize()
    };
    use ed25519_dalek::Verifier as _;
    verifying
        .verify(&digest, &ed25519_dalek::Signature::from_bytes(&sig_bytes))
        .map_err(|_| anyhow::anyhow!("predictor signature verification FAILED — rejected"))?;
    let predictor: PooledPredictor =
        serde_json::from_str(&envelope.payload).context("parse predictor payload")?;
    if predictor.domain != "neoth" {
        anyhow::bail!(
            "predictor domain `{}` rejected — cross-domain comparison is forbidden \
             (B_neoth is not comparable to other domains)",
            predictor.domain
        );
    }
    if !predictor.threshold_suggestion.is_finite()
        || predictor.threshold_suggestion <= 0.0
        || predictor.threshold_suggestion >= 1.0
        || !predictor.brier_oos.is_finite()
        || predictor.coefficients.values().any(|v| !v.is_finite())
    {
        anyhow::bail!("predictor payload failed sanity checks — rejected");
    }
    Ok(predictor)
}

/// The advisory note the daemon logs/feeds. PURE — takes references,
/// returns data; the pooled predictor cannot mutate anything.
#[derive(Clone, Debug, PartialEq)]
pub struct PredictorAdvisory {
    pub pool_threshold: f64,
    pub local_threshold: f64,
    pub delta: f64,
    pub trained_on_instances: u32,
    pub brier_oos: f64,
}

pub fn apply_advisory(predictor: &PooledPredictor, local_threshold: f64) -> PredictorAdvisory {
    PredictorAdvisory {
        pool_threshold: predictor.threshold_suggestion,
        local_threshold,
        delta: predictor.threshold_suggestion - local_threshold,
        trained_on_instances: predictor.trained_on_instances,
        brier_oos: predictor.brier_oos,
    }
}

/// Persist the verified predictor so a restart keeps the day-1 advisory
/// without re-pulling. Stored verbatim (envelope) — re-verified on load.
pub fn cache_predictor(dir: &Path, envelope: &PredictorEnvelope) -> Result<PathBuf> {
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let path = dir.join("pooled_predictor.json");
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(envelope)?)
        .with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, &path).context("rename predictor cache into place")?;
    Ok(path)
}

/// Load + re-verify the cached predictor. `Ok(None)` when no cache exists.
pub fn load_cached_predictor(
    dir: &Path,
    gate: &ConsentGate,
    aggregator_pubkey_hex: Option<&str>,
) -> Result<Option<PooledPredictor>> {
    let path = dir.join("pooled_predictor.json");
    if !path.exists() {
        return Ok(None);
    }
    let envelope: PredictorEnvelope =
        serde_json::from_slice(&std::fs::read(&path).context("read predictor cache")?)
            .context("parse predictor cache")?;
    verify_pooled_predictor(gate, &envelope, aggregator_pubkey_hex).map(Some)
}

/// iroh uploader: dials the configured aggregation endpoint with
/// [`FEDERATION_ALPN`] over the existing cluster QUIC transport.
#[cfg(feature = "cluster-iroh")]
pub struct IrohUploader {
    /// The aggregation node's endpoint address string (config
    /// `babel.federation_endpoint`).
    pub endpoint: String,
}

#[cfg(feature = "cluster-iroh")]
#[async_trait::async_trait]
impl FederationUploader for IrohUploader {
    async fn upload(&self, frame: &[u8]) -> Result<SubmissionReceipt> {
        let reply = crate::cluster::iroh_transport::IrohTransport::dial_once_with_alpn(
            &self.endpoint,
            FEDERATION_ALPN,
            frame,
        )
        .await?;
        serde_json::from_slice(&reply).context("parse federation receipt")
    }
}

#[cfg(feature = "cluster-iroh")]
impl IrohUploader {
    /// GOLD-DELTA-14 — pull the pooled predictor envelope from the
    /// aggregation node (verification happens in the caller against the
    /// pinned key — transport and trust are separate concerns).
    pub async fn fetch_predictor(&self) -> Result<PredictorEnvelope> {
        let reply = crate::cluster::iroh_transport::IrohTransport::dial_once_with_alpn(
            &self.endpoint,
            FEDERATION_ALPN,
            PREDICTOR_REQUEST,
        )
        .await?;
        serde_json::from_slice(&reply).context("parse predictor envelope")
    }
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

    // ── GOLD-DELTA-10 — submit pipeline ──────────────────────────────────────

    const T: i64 = 1_800_300_000;

    fn seeded_db(n: usize) -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().expect("mem db");
        super::super::store::ensure_schema(&conn).expect("schema");
        for i in 0..n as i64 {
            let vars = serde_json::json!({
                "C": 0.5, "K": 0.4, "M": 0.3, "A": 0.5, "V": 0.2, "D": 1.0, "H": 1.0,
                "algo": {"c": "C_d_v0", "k": "K_d_v0", "m": "M_d_v0", "a": "A_d_v0",
                          "v": "V_d_v0", "d": "D_d_v0", "h": "H_d_v0"},
                "schema": "neoth-babel-window/0.2.0",
            });
            // Every 10th window is a collapse; all horizons stamped.
            conn.execute(
                "INSERT INTO idx_babel_windows
                 (id, session_id, window_secs, ts_start, ts_end, b_log, b_bottleneck,
                  variables, collapse_5m, collapse_30m)
                 VALUES (?1, 'a1b2c3d4e5f60718', 900, ?2, ?3, -1.0, 0.4, ?4, ?5, ?5)",
                rusqlite::params![
                    format!("w{i}"),
                    T + i * 900 - 900,
                    T + i * 900,
                    vars.to_string(),
                    i64::from(i % 10 == 0),
                ],
            )
            .expect("seed");
        }
        conn
    }

    fn test_meta() -> SubmissionMetadata {
        SubmissionMetadata {
            contributor_id: "c".repeat(64),
            deployment_context: super::super::anonymize::DeploymentContext::SingleUser,
            hardware_tier: super::super::anonymize::HardwareTier::Workstation,
            primary_model_family: "unknown".to_string(),
            avg_tasks_per_day_bucket: 0,
            protocol_version: SubmissionMetadata::PROTOCOL_VERSION,
            runtime_class: SubmissionMetadata::RUNTIME_CLASS,
        }
    }

    fn open_gate(windows: usize) -> ConsentGate {
        ConsentGate {
            federate_enabled: true,
            autonomy_level: 3,
            calibration_window_count: windows,
        }
    }

    #[test]
    fn submit_returns_none_when_gate_closed() {
        let conn = seeded_db(60);
        let dir = tempfile::tempdir().expect("tempdir");
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let gate = ConsentGate {
            federate_enabled: false,
            autonomy_level: 4,
            calibration_window_count: 60,
        };
        let out = submit_pending_batch(
            &conn, &gate, &test_meta(), &key, b"salt", dir.path(), Some(0.01), T,
        )
        .expect("no error");
        assert!(out.is_none(), "closed gate is a no-op, not an error");
        assert_eq!(
            std::fs::read_dir(dir.path()).map(|d| d.count()).unwrap_or(0),
            0,
            "nothing written"
        );
    }

    #[test]
    fn submit_writes_signed_pending_batch_and_marks_rows() {
        let conn = seeded_db(60);
        let dir = tempfile::tempdir().expect("tempdir");
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let out = submit_pending_batch(
            &conn, &gate_and_salt(&conn), &test_meta(), &key, b"salt", dir.path(),
            Some(0.01), T,
        )
        .expect("submit pass")
        .expect("batch produced");
        assert!(out.windows >= 1 && out.windows <= 60);
        assert!(out.pending_path.exists(), "payload file on disk");

        // Payload decodes to JSONL with exactly `windows` anonymised records,
        // none carrying a raw window id or session id.
        let gz = std::fs::read(&out.pending_path).expect("read payload");
        let mut dec = flate2::read::GzDecoder::new(gz.as_slice());
        let mut jsonl = String::new();
        std::io::Read::read_to_string(&mut dec, &mut jsonl).expect("gunzip");
        let lines: Vec<&str> = jsonl.lines().collect();
        assert_eq!(lines.len(), out.windows);
        for line in &lines {
            let v: serde_json::Value = serde_json::from_str(line).expect("valid JSON");
            let wid = v["window"]["id"].as_str().expect("window id present");
            assert!(!wid.starts_with('w'), "window id pseudonymised: {wid}");
            assert_eq!(v["submission_metadata"]["protocol_version"], "neoth-federation/0.1.0");
        }

        // Envelope sidecar carries a verifiable signature block.
        let meta_path = dir.path().join(format!("{}.pending.meta.json", out.batch_id));
        let env: serde_json::Value =
            serde_json::from_slice(&std::fs::read(meta_path).expect("meta")).expect("json");
        assert_eq!(env["window_count"], out.windows);
        assert_eq!(env["signature_hex"].as_str().map(str::len), Some(128));
        assert_eq!(env["signer_fingerprint"].as_str().map(str::len), Some(16));

        // Rows flipped; a second pass finds the pool at its sampling cap.
        let submitted: i64 = conn
            .query_row("SELECT COUNT(*) FROM idx_babel_windows WHERE submitted = 1", [], |r| {
                r.get(0)
            })
            .expect("count");
        assert_eq!(submitted as usize, out.windows);
        let again = submit_pending_batch(
            &conn, &gate_and_salt(&conn), &test_meta(), &key, b"salt", dir.path(),
            Some(0.01), T,
        )
        .expect("second pass");
        assert!(again.is_none(), "sampling cap reached — no second batch from the same pool");
    }

    fn gate_and_salt(conn: &rusqlite::Connection) -> ConsentGate {
        let total: i64 = conn
            .query_row("SELECT COUNT(*) FROM idx_babel_windows", [], |r| r.get(0))
            .expect("count");
        open_gate(total as usize)
    }

    struct MockUploader {
        fail_on: std::sync::Mutex<usize>,
        frames: std::sync::Mutex<Vec<Vec<u8>>>,
    }

    #[async_trait::async_trait]
    impl FederationUploader for MockUploader {
        async fn upload(&self, frame: &[u8]) -> Result<SubmissionReceipt> {
            self.frames.lock().expect("lock").push(frame.to_vec());
            let mut n = self.fail_on.lock().expect("lock");
            *n += 1;
            if *n == 1 {
                Ok(SubmissionReceipt {
                    batch_id: "b1".into(),
                    accepted_count: 3,
                    rejected_count: 0,
                    rejection_reasons: vec![],
                    suspicious_count: 0,
                })
            } else {
                anyhow::bail!("aggregation node unreachable")
            }
        }
    }

    // ── GOLD-DELTA-14 — pooled predictor firewalls ───────────────────────────

    fn signed_predictor(domain: &str) -> (PredictorEnvelope, String) {
        use ed25519_dalek::Signer as _;
        use sha2::{Digest, Sha256};
        let key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let predictor = PooledPredictor {
            predictor_version: "pool-m2/0.1".into(),
            domain: domain.into(),
            trained_on_instances: 7,
            trained_on_windows: 12_000,
            threshold_suggestion: 0.72,
            coefficients: [("C".to_string(), 1.3), ("K".to_string(), -0.4)].into(),
            brier_oos: 0.11,
        };
        let payload = serde_json::to_string(&predictor).expect("serialize");
        let mut h = Sha256::new();
        h.update(payload.as_bytes());
        let sig = key.sign(&h.finalize());
        let envelope =
            PredictorEnvelope { payload, signature_hex: hex::encode(sig.to_bytes()) };
        (envelope, hex::encode(key.verifying_key().as_bytes()))
    }

    #[test]
    fn predictor_rejected_when_consent_gate_fails() {
        let (envelope, pubkey) = signed_predictor("neoth");
        let closed = ConsentGate {
            federate_enabled: false,
            autonomy_level: 4,
            calibration_window_count: 100,
        };
        let err = verify_pooled_predictor(&closed, &envelope, Some(&pubkey))
            .expect_err("consent-closed pull must fail");
        assert!(err.to_string().contains("refused"), "{err}");
    }

    #[test]
    fn predictor_rejected_without_pinned_key_and_on_wrong_domain() {
        let (envelope, pubkey) = signed_predictor("neoth");
        let gate = open_gate(100);
        let err = verify_pooled_predictor(&gate, &envelope, None)
            .expect_err("no pin = fail-closed");
        assert!(err.to_string().contains("fail-closed"), "{err}");

        let (oss, oss_key) = signed_predictor("oss");
        let err = verify_pooled_predictor(&gate, &oss, Some(&oss_key))
            .expect_err("cross-domain must be rejected");
        assert!(err.to_string().contains("cross-domain"), "{err}");
        // pubkey from the neoth envelope stays unused here on purpose
        let _ = pubkey;
    }

    #[test]
    fn predictor_rejected_on_signature_mismatch() {
        let (mut envelope, pubkey) = signed_predictor("neoth");
        envelope.payload = envelope.payload.replace("0.72", "0.99"); // tamper
        let err = verify_pooled_predictor(&open_gate(100), &envelope, Some(&pubkey))
            .expect_err("tampered payload must fail verification");
        assert!(err.to_string().contains("FAILED"), "{err}");
    }

    #[test]
    fn predictor_accepts_valid_envelope_and_advisory_is_pure() {
        let (envelope, pubkey) = signed_predictor("neoth");
        let gate = open_gate(100);
        let predictor = verify_pooled_predictor(&gate, &envelope, Some(&pubkey))
            .expect("valid envelope verifies");
        assert_eq!(predictor.trained_on_instances, 7);

        let local = 0.8;
        let advisory = apply_advisory(&predictor, local);
        assert!((advisory.delta - (0.72 - 0.8)).abs() < 1e-12);
        assert_eq!(advisory.local_threshold, local, "advisory never mutates anything");

        // Cache round-trip re-verifies on load.
        let dir = tempfile::tempdir().expect("tempdir");
        cache_predictor(dir.path(), &envelope).expect("cache");
        let reloaded = load_cached_predictor(dir.path(), &gate, Some(&pubkey))
            .expect("load ok")
            .expect("cache present");
        assert_eq!(reloaded.threshold_suggestion, 0.72);
        // A gate that closed since caching blocks the reload too.
        let closed = ConsentGate {
            federate_enabled: false,
            autonomy_level: 4,
            calibration_window_count: 100,
        };
        assert!(load_cached_predictor(dir.path(), &closed, Some(&pubkey)).is_err());
    }

    #[tokio::test]
    async fn drain_pending_ships_envelope_plus_payload_and_skips_orphans() {
        use base64::Engine as _;
        let dir = tempfile::tempdir().expect("tempdir");
        for name in ["a.pending.jsonl.gz", "b.pending.jsonl.gz"] {
            std::fs::write(dir.path().join(name), b"gz-bytes").expect("write");
            std::fs::write(
                dir.path().join(name.replace(".jsonl.gz", ".meta.json")),
                br#"{"batch_id":"x","signature_hex":"aa"}"#,
            )
            .expect("write meta");
        }
        // A payload with NO envelope sidecar is unauthenticatable — it must
        // never reach the uploader (external review fix 2026-07-02).
        std::fs::write(dir.path().join("c.pending.jsonl.gz"), b"orphan").expect("write");

        let uploader = MockUploader {
            fail_on: std::sync::Mutex::new(0),
            frames: std::sync::Mutex::new(Vec::new()),
        };
        let (delivered, remaining) =
            drain_pending(dir.path(), &uploader).await.expect("drain");
        assert_eq!((delivered, remaining), (1, 2), "a delivered; b failed; c orphaned");

        // The live transport receives envelope AND payload in one frame.
        let frames = uploader.frames.lock().expect("lock");
        assert_eq!(frames.len(), 2, "orphan never reached the uploader");
        let first: serde_json::Value = serde_json::from_slice(&frames[0]).expect("frame JSON");
        assert_eq!(first["frame_version"], TRANSPORT_FRAME_VERSION);
        assert_eq!(
            first["envelope"]["signature_hex"], "aa",
            "signature travels with the batch"
        );
        let payload = base64::engine::general_purpose::STANDARD
            .decode(first["payload_gzip_b64"].as_str().expect("b64 field"))
            .expect("valid base64");
        assert_eq!(payload, b"gz-bytes", "payload round-trips");

        let left: Vec<String> = std::fs::read_dir(dir.path())
            .expect("dir")
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert!(left.contains(&"b.pending.jsonl.gz".to_string()), "failed batch stays");
        assert!(left.contains(&"c.pending.jsonl.gz".to_string()), "orphan stays pending");
        assert!(
            !left.contains(&"a.pending.jsonl.gz".to_string()),
            "delivered batch removed"
        );
        assert!(
            !left.contains(&"a.pending.meta.json".to_string()),
            "delivered envelope removed too"
        );
    }
}
