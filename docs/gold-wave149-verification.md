# Gold Wave 149 verification record

## Evidence boundary

This record describes the current source seams and the required focused checks
for the passive Buddy Self-improve-quality surface. It is not a release,
completion, or runtime acceptance statement. No compiler, parser, formatter,
test, GUI runtime, screenshot, accessibility inspection, Git, or network
operation was run while preparing this record.

## Product result represented in source

Buddy status exposes a read-only, all-or-unavailable Self-improve quality
snapshot. When a bounded observation sees recovery clear before and after its
raw proposal read and quality projection, the Buddy card may show proposal
identity, status, canonical W142 quality state/reason, metric/delta/regression
summary, verifier short ID, corpus short SHA-256, and full evidence SHA-256.
When that observation cannot establish a complete snapshot, it reports an
explicit unavailable reason and no proposal rows.

The only intended operator action is a navigation handoff labelled **Review in
Self-improve**. It has no accept, execute, recovery, evaluator, corpus, or CLI
argument construction authority.

## Current source-only observation

### Passive Core and Buddy CLI

- `SRC/neothd/src/self_improve.rs` declares `pub(crate) mod passive`.
- `SRC/neothd/src/self_improve/passive.rs::quality_snapshot` reads recovery
  state before and after `load_proposals_raw`, calls the existing
  `proposal_quality_readback` for every proposal, and returns only
  `PassiveQualitySnapshot::Available` or `::Unavailable`.
- That module documents that it must not call `with_state_lock`; the normal
  locked path creates the state lock and runs recovery. The passive reader is
  a clear-before/after observation, not an atomic lifecycle grant.
- `SRC/neothd/src/cli/buddy.rs::status` obtains the snapshot through
  `passive::quality_snapshot` and serializes it as the top-level
  `self_improve_quality` member for JSON output. The table path only renders
  the serialized readback; it does not invoke Self-improve lifecycle work.

### Strict GUI consumption

- `SRC/neothd-gui/src/panel_logic.rs::parse_buddy_status` decodes a strict
  `BuddyStatusWire`, then sends available proposals through the shared W142
  `project_selfimprove_proposal_wires` projection. `BuddyStatusSnap` is a
  presentation type rather than a direct serde target.
- The projection requires the complete canonical eleven-field quality object:
  `state`, `reason`, `metric`, `score_before`, `score_after`, `score_delta`,
  `evaluator_source_short_id`, `corpus_manifest_sha256`,
  `regression_total`, `regression_passed`, and `evidence_sha256`.
  Missing, unknown, malformed, non-finite, or partial current evidence rejects
  the complete Buddy refresh.
- `refresh_buddyconfig` in `SRC/neothd-gui/src/main.rs` maps a complete
  available snapshot as rows and maps unavailable as zero rows plus its explicit
  reason. On fetch/decode error, the existing last-known-good visible values
  are retained and the Buddy status error is set.
- `SRC/neothd-gui/ui/buddyconfig.slint` contains a passive evidence card. Its
  new layout uses `Theme.space-*`; it distinguishes initial no-refresh,
  explicit unavailable, unexpected non-current top-level state, and row-level
  `stale`, `incomplete`, or `failed` quality. It never gives these states the
  review-ready accent.

### Exact proposal handoff

The generated MainWindow callback invokes the registered passive controller,
which stores the exact proposal ID and opens `evolve`. `ui/main.slint` passes
that ID into SelfImproveView; the exact matching card receives an audit-colored
highlight. Selection context stays visible even if the current review no longer
contains that proposal, without claiming a mutation or refreshed evidence.
The native callback fixture covers exact target identity, unchanged proposal
and toast models, and a missing target. Runtime and render acceptance remain
pending on GitHub.

## Required focused test identities

The following identities name the relevant source tests and native GUI fixture
to run in the appropriate platform gate. They are listed as required evidence,
not as results from this record.

| Area | Test identity | Required observation |
| --- | --- | --- |
| Passive recovery | `self_improve::passive::tests::pending_or_malformed_stage_journal_is_unavailable_without_recovery_or_lock_creation` | Pending or malformed journal yields unavailable, retains bytes, and creates no state lock. |
| Passive race boundary | `self_improve::passive::tests::final_recovery_probe_rejects_a_transition_observed_after_quality_projection` | A journal observed after projection withholds the complete snapshot and is not recovered. |
| Passive identity/quality | `self_improve::passive::tests::strict_raw_proposals_preserve_exact_identity_and_shared_quality_readback` | Strict raw proposal identity survives unchanged and quality comes from the shared reader. |
| Passive invalid identity | `self_improve::passive::tests::altered_or_control_identity_makes_the_entire_snapshot_unavailable` | No clipped, normalized, or control-bearing identity is published. |
| Buddy wire | `cli::buddy::tests::status_json_shape_has_all_seven_keys` | Status JSON includes `self_improve_quality` with the other canonical status members. |
| GUI W142 parser | `panel_logic::tests::w142_selfimprove_review_rejects_missing_or_unknown_quality_fields` | The common parser rejects incomplete and unknown canonical quality fields. |
| Buddy parser | `panel_logic::tests::w149_buddy_quality_rejects_partial_evidence_and_keeps_unavailable_explicit` | Unavailable remains non-success; missing snapshot, unknown state, null/missing evidence, and unknown nested fields reject. |
| Buddy target handoff | `w58_gui_callback_runtime_tests::w149_buddy_quality_handoff_selects_the_exact_selfimprove_proposal` | The real generated callback opens Self-improve with the exact target, preserves evidence and mutation state, and retains truthful missing-target context. |

## GUI source/text evidence and missing evidence

Source and text evidence supports the absence of lifecycle callback text and
the presence of semantic status copy, `Theme` color/font/spacing references,
and a single `bc-self-improve-review` callback. It does not establish rendered
layout, screen-reader labels, focus order, contrast in both themes, keyboard
operation, responsive overflow, or runtime command behavior. Those require
rendered screenshot review, accessibility inspection, and the relevant native
GUI/runtime gate.

The passive source inspection also does not prove that a real filesystem,
transaction transition, CLI process, or operator session behaved as described.
