# W163 - recall provenance chips

Status: published source7091979c passed Hosted CLI build/reference and Code Quality; native/GUI acceptance remains pending.
GOLD-LF-P2-27 remains open.
All executable validation runs on GitHub-hosted runners during the workstation
BSOD hold. Static review, a source test declaration, or an uploaded artifact
alone does not establish native, rendered or accessibility acceptance.

## Same-query evidence

The session-start preload carries one RecallEnrichedOutput: the sanitized
recall output plus paired canonical and episode evidence. The data-version,
prompt and binding checks apply to the complete result. Source capping removes
evidence with its removed row, and final canonical-first text deduplication
retains only the evidence for the context actually injected into the turn.
No later recall query reconstructs the displayed provenance.

Scores come from the final Stage-3 ScoredHit value of the selected recall
path. They are not computed from importance, standalone CLI ranking, text,
provider output or response timing. Warm snapshot identity must originate in
the actual idx_consolidated row; a negative compatibility event sentinel is
not event authority. The enriched router preserves the actual warm snapshot
ID, kind and optional original event ID. It admits warm summaries only in the
Hippocampus default path or the thresholded Amygdala overlay; other structural
regions remain hot-only. Retained warm rows never invent an original event
type; their authority is the selected consolidated snapshot. The public legacy
hot router remains unchanged.

## Reduced authenticated control

The existing v3 RS control transport carries exactly seven top-level fields:
neoth_stream, protocol_version, request_id, control_token, sequence, status,
and rows. Its marker is recall_chip_batch. The chip stream has its own
contiguous sequence beginning at one, request/token binding and a 2,048-byte
consumer limit. At most five rows contain only tier, score and source_state.
No recalled text, source IDs, hashes, session values or click targets cross
this presentation boundary.

Statuses distinguish ready, no_recall, missing, stale, failed and incognito.
Unavailable batches have no rows. Scores are null except for available warm
rows with a finite existing value in the inclusive range 0..1. Unknown tiers
are explicitly untrusted. Incognito performs no recall read and can emit only
its content-free unavailable status to the authenticated GUI stream.

## Current-response lifecycle

Successful provider completion and final settlement freeze already accepted
chips so they remain readable with the current completed response. Later
frames cannot overwrite or erase that accepted snapshot. New requests,
errors, cancellation, detach and session/history switches clear it. Recall
chips are transient: they are not persisted in chat history, Buddy recents,
previews, clipboard text or live WAL records.

The Chat/Buddy integration uses the existing request and surface guards. Chips
are informational, use the established design tokens, and need readable labels
for provenance, missing/stale states and unavailable scores. Keyboard and
screen-reader behavior, actual callbacks and rendered layout remain separate
acceptance requirements.

## Required verification

Focused hosted regressions must cover exact final score and source identity,
warm-summary identity through routing, paired source caps and final dedup,
explicit empty outcomes, strict closed schema, binding/sequence/row limits,
post-success freezing, stale callbacks and all clearing boundaries. The generated-Slint projection and shared-lifecycle fixture is registered in
the macOS native harness and its discovery contract. It does not dispatch the
actual Main/Buddy activation callback; direct callback admission and rendered
accessibility acceptance remain outstanding. Integrated source hashes and qualified test identities belong in the
canonical Gold manifest/matrix before publication.

Working designs, reviews and inventories are retained under
work/gold-20260906/wave163-recall-chips. No W163 native/runtime result is claimed.

## Source admission

358 source inputs; 350 universal native plus 3 Windows-only and 2 Unix-only
requirements; 67 universal GUI tests plus 14 Linux/macOS component fixtures;
seven optional adapter cases. W163 contributes 32 source regression entries.
The macOS custom catalog contains 19 fixture names. Reviews resolved actual
warm provenance and replacement-clearing defects; a conflicting debug assertion
was removed while preserving the six-input/five-output wire-cap regression.
Two pure CRLF-to-LF normalizations are separately recorded. No local validation
was executed and no Road checkbox closes from this admission.

## Hosted format correction

Source7091979c passed Code Quality35638612862 and CLI build/reference35638614813.
The reference has SHA-256 9BE613783FC2C1E8DBD2A203BF75A65F9644889E260F29526B859E498119419C, identical to the committed file.
Preflight35638613969 reported 32 exact hunks across six sources. Those Hosted formatter results were imported without local execution. FORMAT-HOSTED.json and the separate POST-FORMAT inventories bind that delta; original semantic reviews are preserved as historical scoped evidence. Fresh Hosted Preflight and native/GUI gates are still required.
