//! Request-owned W163 recall-chip control reducer.
//!
//! This module accepts the reduced, authenticated `recall_chip_batch` v3
//! payload only. It keeps no recall text, hash, session value, prompt, provider
//! value, WAL value, history, or click target. W246 additionally retains only
//! a closed, typed source identifier for a passive current-response label.

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

/// A closed, content-free identity for a real recall source. It is display-only:
/// the GUI never turns it into a lookup, navigation target, or history row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecallChipWarmKind {
    Retained,
    Summary,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecallChipCitation {
    Event {
        event_id: i64,
        event_type: u8,
    },
    WarmSnapshot {
        consolidated_id: i64,
        warm_kind: RecallChipWarmKind,
        original_event_id: Option<i64>,
    },
    GroundTruth {
        fact_id: i64,
    },
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
    pub citation: Option<RecallChipCitation>,
}

/// The complete, transient projection for one request. It contains no text
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
    #[serde(default)]
    citation: Option<RecallChipCitationFrame>,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum RecallChipCitationFrame {
    Event { event_id: i64, event_type: u8 },
    WarmSnapshot {
        consolidated_id: i64,
        warm_kind: RecallChipWarmKindFrame,
        original_event_id: Option<i64>,
    },
    GroundTruth { fact_id: i64 },
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum RecallChipWarmKindFrame {
    Retained,
    Summary,
}

impl RecallChipCitationFrame {
    fn into_citation(self) -> RecallChipCitation {
        match self {
            Self::Event {
                event_id,
                event_type,
            } => RecallChipCitation::Event {
                event_id,
                event_type,
            },
            Self::WarmSnapshot {
                consolidated_id,
                warm_kind,
                original_event_id,
            } => RecallChipCitation::WarmSnapshot {
                consolidated_id,
                warm_kind: match warm_kind {
                    RecallChipWarmKindFrame::Retained => RecallChipWarmKind::Retained,
                    RecallChipWarmKindFrame::Summary => RecallChipWarmKind::Summary,
                },
                original_event_id,
            },
            Self::GroundTruth { fact_id } => RecallChipCitation::GroundTruth { fact_id },
        }
    }
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

    /// Accept the daemon bridge's already-authenticated, content-free W163
    /// projection. Frame ordering is authenticated by the enclosing daemon
    /// subscription reducer; this method repeats only the closed row/status
    /// invariants before allowing the snapshot to reach Slint.
    pub fn accept_issued_batch(
        &mut self,
        status: RecallChipStatus,
        rows: Vec<RecallChip>,
    ) -> Result<RecallChipSnapshot, &'static str> {
        if self.frozen {
            return Err("recall chip batch after terminal boundary");
        }
        let result = (|| {
            if rows.len() > MAX_RECALL_CHIP_ROWS {
                return Err("recall chip batch exceeds five rows");
            }
            if !status.is_ready() && !rows.is_empty() {
                return Err("unavailable recall chip batch must be empty");
            }
            for row in &rows {
                if row.tier == RecallChipTier::Unknown
                    && row.source_state != RecallChipSourceState::Untrusted
                {
                    return Err("unknown recall chip tier must be untrusted");
                }
                if let Some(score) = row.score
                    && (row.tier != RecallChipTier::Warm
                        || row.source_state != RecallChipSourceState::Available
                        || !score.is_finite()
                        || !(0.0..=1.0).contains(&score))
                {
                    return Err("invalid recall chip score");
                }
                if !recall_chip_citation_is_valid(row) {
                    return Err("invalid recall chip citation");
                }
            }
            let snapshot = RecallChipSnapshot { status, rows };
            self.snapshot = Some(snapshot.clone());
            Ok(snapshot)
        })();
        if result.is_err() {
            self.clear_and_fence();
        }
        result
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
        let mut frame = serde_json::from_str::<RecallChipBatchFrame>(line)
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
        for row in &mut frame.rows {
            let tier =
                RecallChipTier::parse(row.tier.as_str()).ok_or("unknown recall chip tier")?;
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
            let citation = row
                .citation
                .take()
                .map(RecallChipCitationFrame::into_citation);
            let row = RecallChip {
                tier,
                score,
                source_state,
                citation,
            };
            if !recall_chip_citation_is_valid(&row) {
                return Err("invalid recall chip citation");
            }
            rows.push(row);
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

fn recall_chip_citation_is_valid(row: &RecallChip) -> bool {
    match (row.citation, row.tier, row.source_state) {
        (None, _, _) => true,
        (
            Some(RecallChipCitation::Event { event_id, .. }),
            RecallChipTier::Hot | RecallChipTier::Warm | RecallChipTier::Cold,
            RecallChipSourceState::Available,
        ) => event_id > 0,
        (
            Some(RecallChipCitation::WarmSnapshot {
                consolidated_id,
                warm_kind: RecallChipWarmKind::Retained,
                original_event_id,
            }),
            RecallChipTier::Warm,
            RecallChipSourceState::Available,
        ) => {
            consolidated_id > 0
                && match original_event_id {
                    None => true,
                    Some(event_id) => event_id > 0,
                }
        }
        (
            Some(RecallChipCitation::WarmSnapshot {
                consolidated_id,
                warm_kind: RecallChipWarmKind::Summary,
                original_event_id: None,
            }),
            RecallChipTier::Warm,
            RecallChipSourceState::Available,
        ) => consolidated_id > 0,
        (
            Some(RecallChipCitation::GroundTruth { fact_id }),
            RecallChipTier::Canonical,
            RecallChipSourceState::Available,
        ) => fact_id > 0,
        _ => false,
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
                    &batch(
                        1,
                        "ready",
                        vec![row("hot", serde_json::json!(0.4), "available")]
                    ),
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
                    &batch(
                        2,
                        "ready",
                        vec![row("warm", serde_json::json!(0.5), "available")]
                    ),
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
        assert!(
            projection
                .apply_json(&batch(1, "ready", rows), "token-a", 3)
                .is_err()
        );
        assert!(projection.snapshot().is_none());
    }

    #[test]
    fn successful_boundaries_freeze_accepted_rows_but_late_frames_do_not_erase_them() {
        let mut projection = Projection::new("request-a".into());
        let accepted = projection
            .apply_json(
                &batch(
                    1,
                    "ready",
                    vec![row("warm", serde_json::json!(0.5), "available")],
                ),
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
                    &batch(
                        2,
                        "ready",
                        vec![row("warm", serde_json::json!(0.6), "available")]
                    ),
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
                &batch(
                    1,
                    "ready",
                    vec![row("warm", serde_json::json!(0.5), "available")],
                ),
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
        let request_b = batch(
            1,
            "ready",
            vec![row("warm", serde_json::json!(0.25), "available")],
        )
        .replacen(
            "\"request_id\":\"request-a\"",
            "\"request_id\":\"request-b\"",
            1,
        );
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

    #[test]
    fn citations_are_closed_available_source_labels_with_positive_matching_ids() {
        let cited = |tier, citation| {
            serde_json::json!({
                "tier": tier,
                "score": null,
                "source_state": "available",
                "citation": citation,
            })
        };
        let mut projection = Projection::new("request-a".into());
        let snapshot = projection
            .apply_json(
                &batch(
                    1,
                    "ready",
                    vec![
                        cited("hot", serde_json::json!({"kind":"event","event_id":11,"event_type":4})),
                        cited("warm", serde_json::json!({"kind":"warm_snapshot","consolidated_id":12,"warm_kind":"retained","original_event_id":11})),
                        cited("warm", serde_json::json!({"kind":"warm_snapshot","consolidated_id":13,"warm_kind":"retained","original_event_id":null})),
                        cited("warm", serde_json::json!({"kind":"warm_snapshot","consolidated_id":13,"warm_kind":"summary","original_event_id":null})),
                        cited("canonical", serde_json::json!({"kind":"ground_truth","fact_id":14})),
                    ],
                ),
                "token-a",
                3,
            )
            .expect("accept closed W246 citations");
        assert!(matches!(
            snapshot.rows[0].citation,
            Some(RecallChipCitation::Event { event_id: 11, event_type: 4 })
        ));
        assert!(matches!(
            snapshot.rows[3].citation,
            Some(RecallChipCitation::WarmSnapshot {
                consolidated_id: 13,
                warm_kind: RecallChipWarmKind::Summary,
                original_event_id: None,
            })
        ));

        for invalid in [
            cited("canonical", serde_json::json!({"kind":"event","event_id":11,"event_type":4})),
            serde_json::json!({"tier":"warm","score":null,"source_state":"missing","citation":{"kind":"warm_snapshot","consolidated_id":12,"warm_kind":"retained","original_event_id":11}}),
            cited("warm", serde_json::json!({"kind":"warm_snapshot","consolidated_id":-12,"warm_kind":"summary","original_event_id":null})),
            cited("warm", serde_json::json!({"kind":"warm_snapshot","consolidated_id":12,"warm_kind":"summary","original_event_id":11})),
            cited("canonical", serde_json::json!({"kind":"ground_truth","fact_id":0})),
            cited("canonical", serde_json::json!({"kind":"ground_truth","fact_id":14,"extra":"denied"})),
        ] {
            let mut denied = Projection::new("request-a".into());
            assert!(denied
                .apply_json(&batch(1, "ready", vec![invalid]), "token-a", 3)
                .is_err());
            assert!(denied.snapshot().is_none());
            assert!(denied.is_frozen());
        }

        let mut legacy = Projection::new("request-a".into());
        assert!(legacy
            .apply_json(
                &batch(1, "ready", vec![row("warm", serde_json::Value::Null, "available")]),
                "token-a",
                3,
            )
            .is_ok());
    }

    #[test]
    fn typed_daemon_batch_reuses_closed_validation_and_provider_done_freeze() {
        let mut projection = Projection::new("daemon-operation-9".into());
        let accepted = projection
            .accept_issued_batch(
                RecallChipStatus::Ready,
                vec![RecallChip {
                    tier: RecallChipTier::Warm,
                    score: Some(0.42),
                    source_state: RecallChipSourceState::Available,
                    citation: None,
                }],
            )
            .expect("accept daemon-reduced W163 batch");
        projection.provider_done();
        assert_eq!(projection.snapshot(), Some(accepted));
        assert!(
            projection
                .accept_issued_batch(RecallChipStatus::Ready, Vec::new())
                .is_err()
        );

        projection.replace_request("daemon-operation-10".into());
        assert!(
            projection
                .accept_issued_batch(
                    RecallChipStatus::Ready,
                    vec![RecallChip {
                        tier: RecallChipTier::Unknown,
                        score: None,
                        source_state: RecallChipSourceState::Available,
                        citation: None,
                    }],
                )
                .is_err()
        );
        assert!(projection.snapshot().is_none());
        assert!(projection.is_frozen());
    }
}
