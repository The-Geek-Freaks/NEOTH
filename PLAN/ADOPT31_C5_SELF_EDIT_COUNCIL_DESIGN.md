# ADOPT31-C5: risk-based Self-Edit Council integration

Operator decision, 2026-11-05: budgeted Council review for configured risky
Self-Edits; valid dissent escalates to the operator, and an override is audited.
This document records the selected behavior and concrete implementation seam;
it is not evidence that the runtime integration is complete.

Source inspection base: 5fa7db6c996d2f519358676a32c9946c8c3fcd79.

## Owners and ordering

Initial complete slice: central `coding/self_source_gate.rs::run_gate_stack`.
The existing five layers, cooldown, source-root ownership, HEAD/index check,
proposal-bound no-follow preimages, authenticated permission decision and live
apply remain authoritative. `cli/bg_session.rs` now delegates real effects to
canonical gates; the historical roadmap line is not a current implementation
location. General `coding/dispatcher.rs` PatchApplyToRepo admission is a separate
subsequent integration, not implicitly covered by the self-source slice.

Perform cheap denial and existing worktree/green checks before paid review.
Classify risk using canonical admitted paths and bounded diff metadata, under
an explicit versioned policy. Bind policy, exact diff hash, actual path set,
source/base identity and expiry. After the bounded review and any operator
interaction, repeat drift/preimage checks before the existing final
permission gate and effect. The existing cross-process self-edit exclusion
must remain effective; do not release it merely to avoid holding it during a
bounded await. Do not introduce an unrelated global mutex around network I/O.

## Reuse rather than a second Council

Use a thin protected coding/self_source_council.rs review adapter over the existing provider factory and model resolver,
configured Left/Right/Cerebellum roles, ProviderCallAuthorizer, per-leaf consent,
model binding, input/output limits, one shared operation budget and the existing
Council daily cap. Recursive review is disabled for this slice. Review input is
the exact bounded patch in a canonical untrusted-data envelope; no tool execution
or persistent memory is required for reviewer roles.

The ordinary debate orchestrator can stop after two matching responses and
uses textual agreement. That is not an action authorization contract. Collect
all three concrete role responses and validate strict bounded `QaVerdict`
representations. All three valid Pass responses permit the review stage.
Valid Fail/Blocked responses are visible dissent. Missing roles, malformed
JSON, duplicate roles, provider refusals/errors, cancellation, budget exhaustion
or receipt failure are infrastructure/contract failures and cannot be treated
as an overrideable successful review.

## Override and receipts

The existing `--yes` acknowledges the original self-edit only. It must never
silently override a later Council objection. A separate real operator response
must see the bounded dissent summary and exact action binding. Noninteractive
or unavailable confirmation refuses with a recoverable explanation; no forged
CLI-origin flag or caller-supplied bool grants approval.

The central gate creates and consumes a private review capability. It is not
publicly constructible or deserializable. Persist a content-poor, action-bound
review/override receipt through the existing WAL owner before the live effect.
Record role outcomes, policy and patch/base hashes, expiry, decision and explicit
override source. Keep raw diffs and provider prose out of WAL receipts. Bind the
final permission decision to the same review identity. Audit failure stops the
effect; post-apply failures keep their existing inconsistent-state semantics.

## Required implementation checks

- Disabled/unconfigured migration behavior is explicit and does not invent
  evidence; configured risky edits cannot silently skip review.
- Risk policy validation and component-aware canonical paths resist bypass;
  cheap permission/hard-deny failures make zero provider calls.
- Three role calls share cost/token/time limits and exact input binding;
  semantic similarity and two-role quorum cannot grant approval.
- Malformed/missing/failed responses block; structured dissent requires a fresh
  operator answer; `--yes`, EOF and unattended entry are insufficient.
- Changed diff, source identity, HEAD/index, preimages, policy or expiry after
  review rejects before mutation. Review infrastructure cannot self-modify.
- Required receipt failure reaches zero live effects. Valid unanimous review or
  bound operator override reaches the existing permission gate, not a bypass.
- Hosted fixtures exercise the actual central live-apply seam and retained WAL
  before claiming runtime acceptance. No local runtime under the BSOD hold.

Implementation and hosted acceptance are outstanding. No raw roadmap checkbox
is changed by this design/decision record.


## W2691 implementation boundary

The central gate now implements the first SelfSourceEdit slice, with five
registered regression identities pending hosted execution. The immutable loaded
FreedomConfig is the authority for one CLI invocation. Its review-policy digest
is bound to the receipt; changes to freedom.yaml affect the next invocation.
This does not claim immediate revocation of an in-flight operation.

The adapter collects three strict validated QaVerdict responses without ordinary
debate quorum, recursion, tools or memory. It uses fail-closed paid-call consent,
the shared operation token/cost budget, three-attempt Council budget and the
existing daily cap. Provider/terminal errors cannot be overridden. Current
review requires an explicit successful provider finish reason; legacy adapters
without it fail closed. A canonical untrusted envelope carries the complete
patch (64 KiB maximum).

The immutable review and separate optional operator confirmation digest form
the resolution receipt (EXTENDED 0x3F). The same resolution digest binds final
permission. No deserialized receipt grants authority. WAL flush_pending is the
existing FIFO sync_data barrier. HEAD/index and available proposal preimages
are checked again after required writes and before consuming the capability.

Existing installations remain disabled until coding.self_edit.council_review
is configured. No local config was enabled. Native provider execution and a
positive interactive TTY ceremony remain separate acceptance requirements.
The shared provider infrastructure is an existing trusted dependency; the new
module, verdict validator and call-budget implementation are hard-denied as
self-edit targets. This is not a claim that every transitive source dependency
is protected against arbitrary code changes.