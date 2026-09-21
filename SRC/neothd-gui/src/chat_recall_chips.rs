//! Request-owned W163 recall-chip control reducer.
//!
//! This module accepts the reduced, authenticated `recall_chip_batch` v3
//! payload only. It keeps no recall text, source identity, hash, session value,
//! prompt, provider value, WAL value, history, or click target. A later GUI
//! owner may render its returned informational rows for the current response.

use serde::Deserialize;
use zeroize::Zeroizing;

/// A bounded no-text v3 chip control. Five closed rows and the existing
/// request/token fields fit well below this limit; larger payloads are rejected
/// before JSON decoding.
pub const MAX_RECALL_CHIP_CONTROL_BYTES: usize = 2_048;
/// W163's producer and consumer both admit no more than five reduced rows.
pub const MAX_RECALL_CHIP_ROWS: usize = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecallChipStatus {
    Ready,
    NoRecall,
    Missing,
    Stale,
    Failed,
    Incognito,
}

impl RecallChipStatus {
    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "ready" => Self::Ready,
            "no_recall" => Self::NoRecall,
            "missing" => Self::Missing,
            "stale" => Self::Stale,
            "failed" => Self::Failed,
            "incognito" => Self::Incognito,
            _ => return None,
        })
    }

    pub const fn is_ready(self) -> bool {
        matches!(self, Self::Ready)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecallChipTier {
    Canonical,
    Hot,
    Warm,
    Cold,
    Unknown,
}

impl RecallChipTier {
    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "canonical" => Self::Canonical,
            "hot" => Self::Hot,
            "warm" => Self::Warm,
            "cold" => Self::Cold,
            "unknown" => Self::Unknown,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecallChipSourceState {
    Available,
    Missing,
    Revoked,
    Untrusted,
}

impl RecallChipSourceState {
    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "available" => Self::Available,
            "missing" => Self::Missing,
            "revoked" => Self::Revoked,
            "untrusted" => Self::Untrusted,
            _ => return None,
        })
    }
}

/// A content-free informational chip. `score` is present only for an available
/// warm row with a finite, existing Stage-3 score in the closed 0..=1 range.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RecallChip {
    pub tier: RecallChipTier,
    pub score: Option<f64>,
    pub source_state: RecallChipSourceState,
}

/// The complete, transient projection for one request. It contains no string
/// values and can be kept readable after a successful provider boundary.
#[derive(Clone, Debug, PartialEq)]
pub struct RecallChipSnapshot {
    pub status: RecallChipStatus,
    pub rows: Vec<RecallChip>,
}

#[derive(Deserialize)]
struct NullableScore(Option<f64>);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecallChipRowFrame {
    tier: String,
    score: NullableScore,
    source_state: String,
}

impl Drop for RecallChipRowFrame {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;

        self.tier.zeroize();
        self.source_state.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecallChipBatchFrame {
    neoth_stream: String,
    protocol_version: u64,
    request_id: String,
    control_token: String,
    sequence: u64,
    status: String,
    rows: Vec<RecallChipRowFrame>,
}

impl Drop for RecallChipBatchFrame {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;

        self.neoth_stream.zeroize();
        self.request_id.zeroize();
        self.control_token.zeroize();
        self.status.zeroize();
    }
}

/// A request-bound W163 lease. Successful provider completion and the final
/// sentinel freeze an already accepted snapshot so it remains readable with
/// the completed current response. Cancellation, error, detach, history, and
/// replacement clear it instead.
pub struct Projection {
    request_id: Zeroizing<String>,
    next_sequence: u64,
    frozen: bool,
    snapshot: Option<RecallChipSnapshot>,
}

impl std::fmt::Debug for Projection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Projection")
            .field("request_id", &"<redacted>")
            .field("next_sequence", &self.next_sequence)
            .field("frozen", &self.frozen)
            .field("snapshot", &self.snapshot)
            .finish()
    }
}
impl Projection {
    /// `request_id` must be the existing authenticated v3 request derivation.
    pub fn new(request_id: String) -> Self {
        Self {
            request_id: Zeroizing::new(request_id),
            next_sequence: 1,
            frozen: false,
            snapshot: None,
        }
    }

    /// The returned value is content-free and safe only for the matching
    /// transient response surface.
    pub fn snapshot(&self) -> Option<RecallChipSnapshot> {
        self.snapshot.clone()
    }

    pub const fn is_frozen(&self) -> bool {
        self.frozen
    }

    /// Replacement is the only operation that reopens sequence 1.
    pub fn replace_request(&mut self, request_id: String) {
        self.request_id = Zeroizing::new(request_id);
        self.next_sequence = 1;
        self.frozen = false;
        self.snapshot = None;
    }

    /// Preserve an accepted batch for the completed current response, while
    /// rejecting any late batch frame.
    pub fn provider_done(&mut self) {
        self.frozen = true;
    }

    /// A clean authenticated final sentinel has the same successful-readback
    /// semantics as `provider_done`.
    pub fn final_sentinel(&mut self) {
        self.frozen = true;
    }

    /// Cancellation, stream error, detach, history/session replacement, and
    /// an invalid open-stream batch must remove the transient projection.
    pub fn clear_and_fence(&mut self) {
        self.snapshot = None;
        self.frozen = true;
    }

    pub fn apply_json(
        &mut self,
        line: &str,
        expected_control_token: &str,
        protocol_version: u64,
    ) -> Result<RecallChipSnapshot, &'static str> {
        // A post-success frame is rejected but must not erase chips already
        // retained for the completed current response.
        if self.frozen {
            return Err("recall chip batch after terminal boundary");
        }
        let result = self.apply_json_inner(line, expected_control_token, protocol_version);
        if result.is_err() {
            self.clear_and_fence();
        }
        result
    }

    fn apply_json_inner(
        &mut self,
        line: &str,
        expected_control_token: &str,
        protocol_version: u64,
    ) -> Result<RecallChipSnapshot, &'static str> {
        if line.len() > MAX_RECALL_CHIP_CONTROL_BYTES {
            return Err("recall chip control exceeds its bounded schema");
        }
        let frame = serde_json::from_str::<RecallChipBatchFrame>(line)
            .map_err(|_| "invalid recall chip control schema")?;
        if frame.neoth_stream != "recall_chip_batch"
            || frame.protocol_version != protocol_version
            || frame.request_id != self.request_id.as_str()
            || frame.control_token != expected_control_token
        {
            return Err("forged or stale recall chip control");
        }
        if frame.sequence == 0 || frame.sequence != self.next_sequence {
            return Err("gapped or duplicate recall chip control");
        }
        let status = RecallChipStatus::parse(frame.status.as_str())
            .ok_or("unknown recall chip batch status")?;
        if frame.rows.len() > MAX_RECALL_CHIP_ROWS {
            return Err("recall chip batch exceeds five rows");
        }

        if !status.is_ready() && !frame.rows.is_empty() {
            return Err("unavailable recall chip batch must be empty");
        }

        let mut rows = Vec::with_capacity(frame.rows.len());
        for row in &frame.rows {
            let tier = RecallChipTier::parse(row.tier.as_str()).ok_or("unknown recall chip tier")?;
            let source_state = RecallChipSourceState::parse(row.source_state.as_str())
                .ok_or("unknown recall chip source state")?;
            if tier == RecallChipTier::Unknown && source_state != RecallChipSourceState::Untrusted {
                return Err("unknown recall chip tier must be untrusted");
            }
            let score = match row.score.0 {
                Some(score)
                    if tier == RecallChipTier::Warm
                        && source_state == RecallChipSourceState::Available
                        && score.is_finite()
                        && (0.0..=1.0).contains(&score) =>
                {
                    Some(score)
                }
                Some(_) => return Err("invalid recall chip score"),
                None => None,
            };
            rows.push(RecallChip {
                tier,
                score,
                source_state,
            });
        }
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or("recall chip sequence exhausted")?;
        let snapshot = RecallChipSnapshot { status, rows };
        self.snapshot = Some(snapshot.clone());
        Ok(snapshot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(tier: &str, score: serde_json::Value, source_state: &str) -> serde_json::Value {
        serde_json::json!({
            "tier": tier,
            "score": score,
            "source_state": source_state,
        })
    }

    fn batch(sequence: u64, status: &str, rows: Vec<serde_json::Value>) -> String {
        serde_json::json!({
            "neoth_stream": "recall_chip_batch",
            "protocol_version": 3,
            "request_id": "request-a",
            "control_token": "token-a",
            "sequence": sequence,
            "status": status,
            "rows": rows,
        })
        .to_string()
    }

    #[test]
    fn accepts_only_reduced_ready_rows_without_any_text_or_identity() {
        let mut projection = Projection::new("request-a".into());
        let snapshot = projection
            .apply_json(
                &batch(
                    1,
                    "ready",
                    vec![
                        row("warm", serde_json::json!(0.75), "available"),
                        row("canonical", serde_json::Value::Null, "available"),
                    ],
                ),
                "token-a",
                3,
            )
            .expect("accept reduced content-free rows");
        assert_eq!(snapshot.status, RecallChipStatus::Ready);
        assert_eq!(snapshot.rows.len(), 2);
        assert_eq!(snapshot.rows[0].score, Some(0.75));
        assert_eq!(snapshot.rows[1].score, None);
        assert_eq!(projection.snapshot(), Some(snapshot));
    }

    #[test]
    fn unknown_fields_and_non_warm_scores_fail_closed() {
        let mut projection = Projection::new("request-a".into());
        let unexpected = r#"{"neoth_stream":"recall_chip_batch","protocol_version":3,"request_id":"request-a","control_token":"token-a","sequence":1,"status":"ready","rows":[{"tier":"warm","score":0.4,"source_state":"available"}],"output_text":"private"}"#;
        assert!(projection.apply_json(unexpected, "token-a", 3).is_err());
        assert!(projection.snapshot().is_none());
        assert!(projection.is_frozen());

        projection.replace_request("request-a".into());
        assert!(
            projection
                .apply_json(
                    &batch(1, "ready", vec![row("hot", serde_json::json!(0.4), "available")]),
                    "token-a",
                    3,
                )
                .is_err()
        );
        assert!(projection.snapshot().is_none());
    }

    #[test]
    fn wrong_binding_gap_and_over_cap_cannot_publish_rows() {
        let mut projection = Projection::new("request-a".into());
        let forged = serde_json::json!({
            "neoth_stream": "recall_chip_batch", "protocol_version": 3,
            "request_id": "request-b", "control_token": "token-a", "sequence": 1,
            "status": "ready", "rows": [row("warm", serde_json::json!(0.5), "available")],
        })
        .to_string();
        assert!(projection.apply_json(&forged, "token-a", 3).is_err());
        assert!(projection.snapshot().is_none());

        projection.replace_request("request-a".into());
        assert!(
            projection
                .apply_json(
                    &batch(2, "ready", vec![row("warm", serde_json::json!(0.5), "available")]),
                    "token-a",
                    3,
                )
                .is_err()
        );
        assert!(projection.snapshot().is_none());

        projection.replace_request("request-a".into());
        let rows = (0..MAX_RECALL_CHIP_ROWS + 1)
            .map(|_| row("warm", serde_json::json!(0.5), "available"))
            .collect();
        assert!(projection.apply_json(&batch(1, "ready", rows), "token-a", 3).is_err());
        assert!(projection.snapshot().is_none());
    }

    #[test]
    fn successful_boundaries_freeze_accepted_rows_but_late_frames_do_not_erase_them() {
        let mut projection = Projection::new("request-a".into());
        let accepted = projection
            .apply_json(
                &batch(1, "ready", vec![row("warm", serde_json::json!(0.5), "available")]),
                "token-a",
                3,
            )
            .expect("accept first request frame");
        projection.provider_done();
        assert!(projection.is_frozen());
        assert_eq!(projection.snapshot(), Some(accepted.clone()));
        assert!(
            projection
                .apply_json(
                    &batch(2, "ready", vec![row("warm", serde_json::json!(0.6), "available")]),
                    "token-a",
                    3,
                )
                .is_err()
        );
        assert_eq!(projection.snapshot(), Some(accepted));

        projection.clear_and_fence();
        assert!(projection.snapshot().is_none());
    }

    #[test]
    fn final_sentinel_replacement_and_clear_remove_only_the_owned_snapshot() {
        let mut projection = Projection::new("request-a".into());
        projection
            .apply_json(
                &batch(1, "ready", vec![row("warm", serde_json::json!(0.5), "available")]),
                "token-a",
                3,
            )
            .expect("accept request-a row");
        projection.final_sentinel();
        assert!(projection.snapshot().is_some());
        assert!(projection.is_frozen());

        projection.replace_request("request-b".into());
        assert!(projection.snapshot().is_none());
        assert!(!projection.is_frozen());
        let request_b = batch(1, "ready", vec![row("warm", serde_json::json!(0.25), "available")])
            .replacen("\"request_id\":\"request-a\"", "\"request_id\":\"request-b\"", 1);
        assert!(projection.apply_json(&request_b, "token-a", 3).is_ok());
        projection.clear_and_fence();
        assert!(projection.snapshot().is_none());
        assert!(projection.is_frozen());
    }
    #[test]
    fn no_recall_and_missing_are_explicit_empty_batches() {
        for status in ["no_recall", "missing", "stale", "failed", "incognito"] {
            let mut projection = Projection::new("request-a".into());
            let snapshot = projection
                .apply_json(&batch(1, status, Vec::new()), "token-a", 3)
                .expect("accept explicit empty status");
            assert!(!snapshot.status.is_ready());
            assert!(snapshot.rows.is_empty());
        }
    }
}
