//! QM-6 sub-agent QA verdict types — [`QaVerdict`] + [`FailureItem`].
//!
//! Split out of [`crate::council::quality_score`] (GOLD-ARCH-15) so the
//! verifier-verdict surface lives in its own focused module. Per
//! `PLAN/QUELLEN_ADOPT_agency_2026-05-21.md` finding §5 pick #1 — the
//! dispatcher loop's old `bool success` return was too thin: a real verifier
//! reports WHY it failed (failed test names, missing invariants, blocked-by-
//! permission), and that diagnosis feeds the retry path's reframing/replanning.
//! Production sub-agent fan-out emits this shape through the existing `0x84`
//! sub-agent review frame and persists it in the private run record. The
//! scoring logic stays in [`crate::council::quality_score`].

use serde::{Deserialize, Serialize};

/// One failure item from a verifier sub-agent. Carries enough context
/// for the retry path to decide between "fix this one thing" vs "scrap
/// the patch and replan". Operator-readable strings are rendered by
/// `neoth agents run/history`, persisted in the private run record, and
/// summarized (content-free) in the `0x84 SUBAGENT_REVIEW_STAGE` WAL frame.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailureItem {
    /// Short stable id: `test_failure` / `lint_violation` / `invariant`
    /// / `coverage_gap` / `permission_denied`. Operators grep on these
    /// in the WAL when they want a histogram of failure modes.
    pub kind: String,
    /// Operator-readable description of what failed. Free-form prose
    /// the verifier sub-agent generates.
    pub message: String,
    /// Optional pointer to the evidence — typically `path:line` for
    /// test failures, a regex for lint violations, etc. Empty when
    /// the verifier had no specific anchor to cite.
    #[serde(default)]
    pub citation: Option<String>,
}

/// Outcome of a sub-agent QA pass. Three-state because the binary
/// pass/fail collapses two distinct cases that the retry path should
/// handle differently:
///
/// - `Pass` → patch merges, dispatcher moves on
/// - `Fail` → diagnosable problem with the patch itself; retry with
///   `failures` fed to the reframer
/// - `Blocked` → an external constraint stopped the verifier from
///   reaching a verdict at all (e.g. permission denied, infrastructure
///   missing, upstream API down). Retry doesn't help — the operator
///   needs to know.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum QaVerdict {
    /// Sub-agent confirmed the change is good. Optional `evidence`
    /// list carries the citation chain the verifier walked
    /// (test_passed / invariant_held / etc).
    Pass {
        #[serde(default)]
        evidence: Vec<String>,
    },
    /// Sub-agent found concrete reasons the patch is wrong. `failures`
    /// is non-empty (a `Fail` with zero items is a `Pass` with no
    /// evidence — the constructor enforces this invariant).
    Fail { failures: Vec<FailureItem> },
    /// Sub-agent couldn't verify due to an external constraint.
    /// `reason` surfaces to the operator; the retry path should NOT
    /// loop on this — replanning won't help.
    Blocked { reason: String },
}

impl QaVerdict {
    /// Construct a `Pass` with a clean evidence list.
    pub fn pass() -> Self {
        Self::Pass {
            evidence: Vec::new(),
        }
    }

    /// Construct a `Pass` carrying explicit evidence citations.
    pub fn pass_with_evidence(items: impl IntoIterator<Item = String>) -> Self {
        Self::Pass {
            evidence: items.into_iter().collect(),
        }
    }

    /// Construct a `Fail` from a non-empty failure list. Returns
    /// `QaVerdict::pass()` when the list is empty so callers can't
    /// accidentally produce a `Fail { failures: [] }` (which would
    /// represent "fail but I have no reasons" — semantically a Pass).
    pub fn fail(items: Vec<FailureItem>) -> Self {
        if items.is_empty() {
            Self::pass()
        } else {
            Self::Fail { failures: items }
        }
    }

    /// Construct a `Blocked` verdict.
    pub fn blocked(reason: impl Into<String>) -> Self {
        Self::Blocked {
            reason: reason.into(),
        }
    }

    /// True when the dispatcher should treat this as a green light to
    /// merge the patch and move on.
    pub fn is_pass(&self) -> bool {
        matches!(self, Self::Pass { .. })
    }

    /// True when the dispatcher should feed the failure list back to
    /// the retry path's reframer.
    pub fn is_retriable(&self) -> bool {
        matches!(self, Self::Fail { .. })
    }

    /// True when the dispatcher should surface to the operator and
    /// stop the auto-retry loop.
    pub fn is_blocked(&self) -> bool {
        matches!(self, Self::Blocked { .. })
    }

    /// Validate model-produced verdicts at the trust boundary. Constructors
    /// keep in-process callers honest; deserialization can otherwise create an
    /// empty `Fail`, unbounded evidence, or opaque failure kinds directly.
    pub fn validate(&self) -> Result<(), String> {
        const MAX_ITEMS: usize = 16;
        const MAX_KIND_BYTES: usize = 64;
        const MAX_EVIDENCE_BYTES: usize = 512;
        const MAX_MESSAGE_BYTES: usize = 4096;

        let valid_text = |value: &str, max: usize| {
            !value.trim().is_empty() && value.len() <= max && !value.contains('\0')
        };
        match self {
            Self::Pass { evidence } => {
                if evidence.len() > MAX_ITEMS {
                    return Err(format!("pass evidence exceeds {MAX_ITEMS} items"));
                }
                if evidence
                    .iter()
                    .any(|item| !valid_text(item, MAX_EVIDENCE_BYTES))
                {
                    return Err("pass evidence contains an empty or oversized item".into());
                }
            }
            Self::Fail { failures } => {
                if failures.is_empty() || failures.len() > MAX_ITEMS {
                    return Err(format!(
                        "fail verdict must contain 1..={MAX_ITEMS} failure items"
                    ));
                }
                for failure in failures {
                    if !valid_text(&failure.kind, MAX_KIND_BYTES)
                        || !failure
                            .kind
                            .bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                    {
                        return Err(
                            "failure kind must be a lowercase ASCII slug up to 64 bytes".into()
                        );
                    }
                    if !valid_text(&failure.message, MAX_MESSAGE_BYTES) {
                        return Err("failure message is empty or oversized".into());
                    }
                    if failure
                        .citation
                        .as_deref()
                        .is_some_and(|citation| !valid_text(citation, MAX_EVIDENCE_BYTES))
                    {
                        return Err("failure citation is empty or oversized".into());
                    }
                }
            }
            Self::Blocked { reason } => {
                if !valid_text(reason, MAX_MESSAGE_BYTES) {
                    return Err("blocked reason is empty or oversized".into());
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qa_verdict_pass_round_trips_through_json() {
        let v = QaVerdict::pass_with_evidence(vec![
            "test::ascii_roundtrip passed".to_string(),
            "no clippy warnings on diff".to_string(),
        ]);
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains("\"kind\":\"pass\""));
        assert!(json.contains("test::ascii_roundtrip passed"));
        let back: QaVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
        assert!(back.is_pass());
        assert!(!back.is_retriable());
        assert!(!back.is_blocked());
    }

    #[test]
    fn qa_verdict_fail_carries_failure_items_with_citations() {
        let v = QaVerdict::fail(vec![
            FailureItem {
                kind: "test_failure".into(),
                message: "expected 2 but got 3".into(),
                citation: Some("src/math.rs:42".into()),
            },
            FailureItem {
                kind: "lint_violation".into(),
                message: "unused import: `Context`".into(),
                citation: None,
            },
        ]);
        assert!(v.is_retriable());
        assert!(!v.is_pass());
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains("\"kind\":\"fail\""));
        assert!(json.contains("src/math.rs:42"));
        let back: QaVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn qa_verdict_fail_with_empty_list_collapses_to_pass() {
        // Invariant: a Fail with zero items is semantically a Pass
        // (verifier had no objections). The constructor enforces
        // this so dispatcher code never sees the degenerate shape.
        let v = QaVerdict::fail(Vec::new());
        assert!(v.is_pass(), "empty failure list must collapse to Pass");
    }

    #[test]
    fn qa_verdict_blocked_round_trips_with_reason() {
        let v = QaVerdict::blocked("CI runner unavailable — token expired");
        assert!(v.is_blocked());
        assert!(!v.is_pass());
        assert!(!v.is_retriable());
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains("\"kind\":\"blocked\""));
        let back: QaVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn qa_verdict_serde_wire_form_is_kind_tagged_snake_case() {
        // Pin the on-wire shape so a future refactor (rename Pass →
        // Approved, etc) surfaces as a test failure before it breaks
        // the WAL audit consumers grep'ing for "pass" / "fail" /
        // "blocked" in 0x72 QA_VERDICT_EMITTED frames.
        assert!(
            serde_json::to_string(&QaVerdict::pass())
                .unwrap()
                .starts_with("{\"kind\":\"pass\"")
        );
        assert!(
            serde_json::to_string(&QaVerdict::fail(vec![FailureItem {
                kind: "x".into(),
                message: "y".into(),
                citation: None,
            }]))
            .unwrap()
            .starts_with("{\"kind\":\"fail\"")
        );
        assert!(
            serde_json::to_string(&QaVerdict::blocked("r"))
                .unwrap()
                .starts_with("{\"kind\":\"blocked\"")
        );
    }

    #[test]
    fn qa_verdict_helpers_are_mutually_exclusive() {
        // is_pass / is_retriable / is_blocked must each fire on
        // exactly one variant. Future audit tooling relies on this
        // invariant when bucketing verdicts.
        for v in [
            QaVerdict::pass(),
            QaVerdict::fail(vec![FailureItem {
                kind: "x".into(),
                message: "y".into(),
                citation: None,
            }]),
            QaVerdict::blocked("r"),
        ] {
            let bits = [v.is_pass(), v.is_retriable(), v.is_blocked()];
            let true_count = bits.iter().filter(|b| **b).count();
            assert_eq!(
                true_count, 1,
                "exactly one of is_pass/is_retriable/is_blocked must fire for {v:?}"
            );
        }
    }

    #[test]
    fn model_verdict_validation_rejects_empty_fail_and_opaque_kinds() {
        let empty: QaVerdict = serde_json::from_str(r#"{"kind":"fail","failures":[]}"#).unwrap();
        assert!(empty.validate().is_err());

        let opaque: QaVerdict = serde_json::from_str(
            r#"{"kind":"fail","failures":[{"kind":"Test Failure!","message":"x"}]}"#,
        )
        .unwrap();
        assert!(opaque.validate().is_err());
    }

    #[test]
    fn model_verdict_rejects_unknown_fields() {
        let err = serde_json::from_str::<QaVerdict>(
            r#"{"kind":"pass","evidence":[],"ignore_previous":true}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }
}
