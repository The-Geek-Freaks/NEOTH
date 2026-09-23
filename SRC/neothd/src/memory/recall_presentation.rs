//! GOLD-LF-P2-27 — bounded, request-local recall-chip presentation data.
//!
//! This module has no transport, UI, persistence, or text rendering.  It keeps
//! the exact final Stage-3 score and snapshot-local source identity long enough
//! for a later authenticated chat producer to derive a content-free batch.

#[cfg(test)]
use crate::memory::recall_lanes::ScoredHit;
use crate::memory::views::EpisodeHit;

/// Maximum chip rows that a future request-bound presenter may expose.
pub(crate) const MAX_RECALL_CHIP_ROWS: usize = 5;
const MAX_PRESENTABLE_SCORE: f64 = 1.0;

/// Identity of the snapshot row that supplied a recall result.
///
/// It is deliberately local-only until `source_state_for` accepts the exact
/// hit/source binding. Only then may W246 reduce it to a positive, passive,
/// content-free [`RecallChipCitation`] in a chip row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RecallSourceRef {
    Event {
        event_id: i64,
        event_type: u8,
    },
    WarmSnapshot {
        consolidated_id: i64,
        kind: RecallWarmKind,
        /// The exact nullable `idx_consolidated.event_id` value. It is not an
        /// event authority because the warm snapshot stores no event type.
        original_event_id: Option<i64>,
    },
    GroundTruth {
        fact_id: i64,
    },
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecallWarmKind {
    Retained,
    Summary,
}

/// Content-free, typed provenance for a chip whose source was already
/// accepted by [`source_state_for`]. It is never inferred from row ordering,
/// rendered recall text, or the warm-summary negative event sentinel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RecallChipCitation {
    Event {
        event_id: i64,
        event_type: u8,
    },
    WarmSnapshot {
        consolidated_id: i64,
        kind: RecallWarmKind,
        original_event_id: Option<i64>,
    },
    GroundTruth {
        fact_id: i64,
    },
}

/// Public-safe tier vocabulary for the later reduced control frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecallChipTier {
    Canonical,
    Hot,
    Warm,
    Cold,
    Unknown,
}

/// Explicit source state; it never grants navigation or source disclosure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecallChipSourceState {
    Available,
    Missing,
    Untrusted,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum RecallChipScore {
    WarmHit(f32),
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecallChipBatchStatus {
    Ready,
    NoRecall,
    Missing,
    Stale,
    Failed,
    Incognito,
}

/// Reduced row suitable for the Recall-chip UI wire format. It contains no
/// response text, session value, prompt, or database identifier; its optional
/// typed citation is only source provenance already validated for this hit.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct RecallChipRow {
    pub(crate) tier: RecallChipTier,
    pub(crate) score: RecallChipScore,
    pub(crate) source_state: RecallChipSourceState,
    pub(crate) citation: Option<RecallChipCitation>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct RecallChipBatch {
    pub(crate) status: RecallChipBatchStatus,
    pub(crate) rows: Vec<RecallChipRow>,
}

impl RecallChipBatch {
    #[must_use]
    pub(crate) fn unavailable(status: RecallChipBatchStatus) -> Self {
        debug_assert!(status != RecallChipBatchStatus::Ready);
        Self {
            status,
            rows: Vec::new(),
        }
    }

    #[must_use]
    pub(crate) fn from_final_hits(hits: impl IntoIterator<Item = RecallPresentationHit>) -> Self {
        let rows = hits
            .into_iter()
            .take(MAX_RECALL_CHIP_ROWS)
            .map(|hit| hit.chip_row())
            .collect();
        Self {
            status: RecallChipBatchStatus::Ready,
            rows,
        }
    }
}

/// A typed final ranking value plus its source snapshot reference. It stays
/// local until reduced into [`RecallChipRow`].
#[derive(Debug)]
pub(crate) struct RecallPresentationHit {
    hit: EpisodeHit,
    source: RecallSourceRef,
    final_score: f64,
    source_state: RecallChipSourceState,
}

impl RecallPresentationHit {
    /// Preserve a score that Stage-3 already computed. Invalid source identity
    /// is retained only as an explicit untrusted state; it cannot become a
    /// fabricated event reference or a visible score.
    #[must_use]
    #[cfg(test)]
    pub(crate) fn from_final_scored(scored: ScoredHit, source: RecallSourceRef) -> Self {
        let (hit, final_score) = scored.into_presentation_parts();
        Self::from_final_parts(hit, final_score, source)
    }

    #[must_use]
    pub(crate) fn from_final_parts(
        hit: EpisodeHit,
        final_score: f64,
        source: RecallSourceRef,
    ) -> Self {
        let source_state = source_state_for(&hit, &source);
        Self {
            hit,
            source,
            final_score,
            source_state,
        }
    }

    #[must_use]
    pub(crate) fn chip_row(&self) -> RecallChipRow {
        let tier = tier_for(&self.hit);
        let source_state = if tier == RecallChipTier::Unknown {
            RecallChipSourceState::Untrusted
        } else {
            self.source_state
        };
        let score = if tier == RecallChipTier::Warm
            && source_state == RecallChipSourceState::Available
            && self.source.is_warm_provenance()
            && self.final_score.is_finite()
            && (0.0..=MAX_PRESENTABLE_SCORE).contains(&self.final_score)
        {
            RecallChipScore::WarmHit(self.final_score as f32)
        } else {
            RecallChipScore::Unavailable
        };
        let citation = (source_state == RecallChipSourceState::Available)
            .then(|| citation_for(tier, &self.source))
            .flatten();
        RecallChipRow {
            tier,
            score,
            source_state,
            citation,
        }
    }
}

fn citation_for(tier: RecallChipTier, source: &RecallSourceRef) -> Option<RecallChipCitation> {
    match (tier, source) {
        (RecallChipTier::Canonical, RecallSourceRef::GroundTruth { fact_id }) if *fact_id > 0 => {
            Some(RecallChipCitation::GroundTruth { fact_id: *fact_id })
        }
        (
            RecallChipTier::Hot | RecallChipTier::Warm | RecallChipTier::Cold,
            RecallSourceRef::Event {
                event_id,
                event_type,
            },
        ) if *event_id > 0 => Some(RecallChipCitation::Event {
            event_id: *event_id,
            event_type: *event_type,
        }),
        (
            RecallChipTier::Warm,
            RecallSourceRef::WarmSnapshot {
                consolidated_id,
                kind: RecallWarmKind::Retained,
                original_event_id,
            },
        ) if *consolidated_id > 0 && original_event_id.is_none_or(|event_id| event_id > 0) => {
            Some(RecallChipCitation::WarmSnapshot {
                consolidated_id: *consolidated_id,
                kind: RecallWarmKind::Retained,
                original_event_id: *original_event_id,
            })
        }
        (
            RecallChipTier::Warm,
            RecallSourceRef::WarmSnapshot {
                consolidated_id,
                kind: RecallWarmKind::Summary,
                original_event_id: None,
            },
        ) if *consolidated_id > 0 => Some(RecallChipCitation::WarmSnapshot {
            consolidated_id: *consolidated_id,
            kind: RecallWarmKind::Summary,
            original_event_id: None,
        }),
        _ => None,
    }
}

impl RecallSourceRef {
    fn is_warm_provenance(&self) -> bool {
        matches!(self, Self::WarmSnapshot { .. })
    }
}

fn source_state_for(hit: &EpisodeHit, source: &RecallSourceRef) -> RecallChipSourceState {
    match source {
        RecallSourceRef::Event {
            event_id,
            event_type,
        } if *event_id > 0 && hit.event_id == *event_id && hit.event_type == *event_type => {
            RecallChipSourceState::Available
        }
        RecallSourceRef::WarmSnapshot {
            consolidated_id,
            kind: RecallWarmKind::Summary,
            original_event_id: None,
        } if *consolidated_id > 0
            && hit.tier == "warm"
            && consolidated_id.checked_neg() == Some(hit.event_id) =>
        {
            RecallChipSourceState::Available
        }
        RecallSourceRef::WarmSnapshot {
            consolidated_id,
            kind: RecallWarmKind::Retained,
            original_event_id: Some(event_id),
        } if *consolidated_id > 0
            && *event_id > 0
            && hit.tier == "warm"
            && hit.event_id == *event_id =>
        {
            RecallChipSourceState::Available
        }
        RecallSourceRef::WarmSnapshot {
            consolidated_id,
            kind: RecallWarmKind::Retained,
            original_event_id: None,
        } if *consolidated_id > 0
            && hit.tier == "warm"
            && consolidated_id.checked_neg() == Some(hit.event_id) =>
        {
            RecallChipSourceState::Available
        }
        RecallSourceRef::GroundTruth { fact_id }
            if *fact_id > 0 && hit.event_id == *fact_id && hit.tier == "groundtruth" =>
        {
            RecallChipSourceState::Available
        }
        RecallSourceRef::Unavailable => RecallChipSourceState::Missing,
        _ => RecallChipSourceState::Untrusted,
    }
}

fn tier_for(hit: &EpisodeHit) -> RecallChipTier {
    match hit.tier.as_str() {
        "hot" => RecallChipTier::Hot,
        "warm" => RecallChipTier::Warm,
        "cold" => RecallChipTier::Cold,
        "groundtruth" => RecallChipTier::Canonical,
        _ => RecallChipTier::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit(tier: &str, event_id: i64) -> EpisodeHit {
        EpisodeHit {
            event_id,
            event_type: 7,
            ts_ns: 0,
            text: "must not enter a chip".to_owned(),
            text_hash: "private-source-hash".to_owned(),
            channel: Some("private-channel".to_owned()),
            sender_id: Some("private-sender".to_owned()),
            operator_id: Some("private-operator".to_owned()),
            tier: tier.to_owned(),
            importance: Some(0.99),
            access_count: 4,
            trust: 2,
        }
    }

    #[test]
    fn warm_retained_snapshot_preserves_the_existing_final_score_without_using_importance() {
        let scored = crate::memory::recall_lanes::score_ranked_hits(vec![hit("warm", 41)])
            .pop()
            .unwrap();
        let row = RecallPresentationHit::from_final_scored(
            scored,
            RecallSourceRef::WarmSnapshot {
                consolidated_id: 12,
                kind: RecallWarmKind::Retained,
                original_event_id: Some(41),
            },
        )
        .chip_row();
        assert_eq!(row.tier, RecallChipTier::Warm);
        assert_eq!(row.score, RecallChipScore::WarmHit((1.0 / 61.0) as f32));
        assert_eq!(
            row.citation,
            Some(RecallChipCitation::WarmSnapshot {
                consolidated_id: 12,
                kind: RecallWarmKind::Retained,
                original_event_id: Some(41),
            })
        );
    }

    #[test]
    fn warm_summary_uses_a_snapshot_identity_not_the_negative_event_sentinel() {
        let scored = crate::memory::recall_lanes::score_ranked_hits(vec![hit("warm", -12)])
            .pop()
            .unwrap();
        let row = RecallPresentationHit::from_final_scored(
            scored,
            RecallSourceRef::WarmSnapshot {
                consolidated_id: 12,
                kind: RecallWarmKind::Summary,
                original_event_id: None,
            },
        )
        .chip_row();
        assert_eq!(row.source_state, RecallChipSourceState::Available);
        assert!(matches!(row.score, RecallChipScore::WarmHit(_)));
        assert_eq!(
            row.citation,
            Some(RecallChipCitation::WarmSnapshot {
                consolidated_id: 12,
                kind: RecallWarmKind::Summary,
                original_event_id: None,
            })
        );
    }

    #[test]
    fn a_different_positive_snapshot_id_is_untrusted() {
        let scored = crate::memory::recall_lanes::score_ranked_hits(vec![hit("warm", -12)])
            .pop()
            .unwrap();
        let row = RecallPresentationHit::from_final_scored(
            scored,
            RecallSourceRef::WarmSnapshot {
                consolidated_id: 13,
                kind: RecallWarmKind::Summary,
                original_event_id: None,
            },
        )
        .chip_row();
        assert_eq!(row.source_state, RecallChipSourceState::Untrusted);
        assert_eq!(row.score, RecallChipScore::Unavailable);
        assert_eq!(row.citation, None);
    }

    #[test]
    fn retained_snapshot_rejects_a_forged_positive_event_binding() {
        let scored = crate::memory::recall_lanes::score_ranked_hits(vec![hit("warm", 42)])
            .pop()
            .unwrap();
        let row = RecallPresentationHit::from_final_scored(
            scored,
            RecallSourceRef::WarmSnapshot {
                consolidated_id: 12,
                kind: RecallWarmKind::Retained,
                original_event_id: Some(41),
            },
        )
        .chip_row();
        assert_eq!(row.source_state, RecallChipSourceState::Untrusted);
        assert_eq!(row.score, RecallChipScore::Unavailable);
        assert_eq!(row.citation, None);
    }

    #[test]
    fn unknown_tier_is_never_relabelled_as_canonical() {
        let scored = crate::memory::recall_lanes::score_ranked_hits(vec![hit("future-tier", 41)])
            .pop()
            .unwrap();
        let row = RecallPresentationHit::from_final_scored(
            scored,
            RecallSourceRef::Event {
                event_id: 41,
                event_type: 7,
            },
        )
        .chip_row();
        assert_eq!(row.tier, RecallChipTier::Unknown);
        assert_eq!(row.source_state, RecallChipSourceState::Untrusted);
        assert_eq!(row.score, RecallChipScore::Unavailable);
        assert_eq!(row.citation, None);
    }

    #[test]
    fn negative_warm_sentinel_cannot_be_reinterpreted_as_an_event() {
        let scored = crate::memory::recall_lanes::score_ranked_hits(vec![hit("warm", -12)])
            .pop()
            .unwrap();
        let row = RecallPresentationHit::from_final_scored(
            scored,
            RecallSourceRef::Event {
                event_id: -12,
                event_type: 7,
            },
        )
        .chip_row();
        assert_eq!(row.source_state, RecallChipSourceState::Untrusted);
        assert_eq!(row.score, RecallChipScore::Unavailable);
        assert_eq!(row.citation, None);
    }

    #[test]
    fn exact_positive_event_and_ground_truth_bindings_project_typed_citations() {
        let event = RecallPresentationHit::from_final_parts(
            hit("hot", 41),
            0.42,
            RecallSourceRef::Event {
                event_id: 41,
                event_type: 7,
            },
        )
        .chip_row();
        assert_eq!(
            event.citation,
            Some(RecallChipCitation::Event {
                event_id: 41,
                event_type: 7,
            })
        );

        let fact = RecallPresentationHit::from_final_parts(
            hit("groundtruth", 9),
            0.42,
            RecallSourceRef::GroundTruth { fact_id: 9 },
        )
        .chip_row();
        assert_eq!(
            fact.citation,
            Some(RecallChipCitation::GroundTruth { fact_id: 9 })
        );
    }

    #[test]
    fn batch_is_capped_and_never_carries_hit_content() {
        let hits = (1..=MAX_RECALL_CHIP_ROWS + 1).map(|id| {
            let scored =
                crate::memory::recall_lanes::score_ranked_hits(vec![hit("warm", id as i64)])
                    .pop()
                    .unwrap();
            RecallPresentationHit::from_final_scored(
                scored,
                RecallSourceRef::Event {
                    event_id: id as i64,
                    event_type: 7,
                },
            )
        });
        let batch = RecallChipBatch::from_final_hits(hits);
        assert_eq!(batch.status, RecallChipBatchStatus::Ready);
        assert_eq!(batch.rows.len(), MAX_RECALL_CHIP_ROWS);
    }

    #[test]
    fn missing_stale_and_incognito_are_explicit_zero_row_batches() {
        for status in [
            RecallChipBatchStatus::Missing,
            RecallChipBatchStatus::Stale,
            RecallChipBatchStatus::Incognito,
        ] {
            let batch = RecallChipBatch::unavailable(status);
            assert_eq!(batch.status, status);
            assert!(batch.rows.is_empty());
        }
    }
}
