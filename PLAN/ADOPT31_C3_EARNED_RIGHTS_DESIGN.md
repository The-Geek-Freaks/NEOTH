# ADOPT31-C3: operator-bounded earned peer rights

Status: separate design, requested by the operator on 2026-11-05. No earned
rights are activated by this document. Current pairing and permission behavior
remains unchanged. Source inspection base: 5fa7db6c996d2f519358676a32c9946c8c3fcd79.

## Scope and existing owners

The existing cluster receiver uses `cluster_task_gate` in
`SRC/neothd/src/cluster/hyperswarm.rs` and pairing from
`SRC/neothd/src/cluster/registry.rs::is_paired`. Preserve those boundaries.
The operator chose a separate design for earned rights rather than silently
turning the old 0-1000 score proposal into automatic peer admission.

A paired peer may earn a named capability tier only inside an envelope the
operator explicitly grants. That envelope preauthorizes the maximum actions,
quotas, validity and evidence sources. The score is explanatory input, never an
independent permission. No score can pair a peer, override a deny, renew a
lease, increase a budget, change policy or grant the peer administrative rights.

| Model | Effect | Decision |
| --- | --- | --- |
| Observational ranking | Reorders already eligible tasks/peers; grants nothing | Simpler alternative, not the selected design goal |
| Earned tiers inside an explicit envelope | Unlocks only preauthorized, bounded capabilities after verified evidence | Proposed model |
| Score overrides pairing or policy | Lets behavior expand ungranted authority | Excluded from this proposal |

## State and effect order

States: disabled (migration default), eligible (paired plus envelope), earned
(valid named tier), probation (adverse evidence or inactivity), revoked.
Pairing removal revokes earned state. Re-pairing creates a new epoch; historical
scores do not silently transfer. Existing operator-granted rights are tracked
separately from earned additions, so decay cannot remove an unrelated grant.

At every real action boundary: authenticate the current peer and pairing epoch;
check explicit deny/revocation and the existing permission/lease gate; intersect
the requested action with the current envelope and earned tier; reserve existing
budget/quota; persist the exact decision in the existing authenticated WAL;
recheck epoch/policy/lease immediately before the effect. Grant only the
intersection of those constraints. Failure releases reservations by the existing
owner and produces no effect. A tier transition alone never executes a task.

The envelope contains a schema/version, peer full identity plus pairing epoch,
action allowlist, per-tier maximum scope/quota, promotion conditions, evidence
source allowlist, expiry/decay and revocation policy. Use exact action identities
and resource scopes, not free-form labels or a numeric score as an action gate.

## Evidence, replay and operator controls

Use the existing WAL and its derived materialization; do not introduce a second
trust ledger. Observations bind stable event ID, peer and pairing epoch,
authenticated verifier identity, task/result receipt, outcome category and
local time. Never reward a peer from its own claimed success. Approved local
verifiers or explicitly authorized independent verifiers establish outcomes.
Deduplicate event and task identities; cap correlated observations from retries,
reciprocal reviewers and related identities. A score does not prove Sybil
resistance; operator pairing remains the admission boundary.

Replay deterministically reconstructs envelope versions, evidence decisions,
tiers, revocations and appeals. Stale epochs and unknown verifier identities
cannot promote. Expiry and inactivity affect the effective tier without deleting
history; clock rollback cannot extend a grant. Concurrent actions share existing
lease and budget owners, rather than each reading a stale score and spending
the same remaining allowance.

Receipts expose the decision, envelope version, tier, evidence IDs, expiry and
reason code, with no task body or secret. Operators can inspect evidence,
invalidate an observation, narrow an envelope, revoke earned rights or resolve
an appeal with a recorded reason. Disabling the feature restores the prior
operator-granted authority model without making the historical WAL unreadable.
Already-running work follows the existing cancellation and lease contracts;
non-cancellable completed effects are reported honestly, never called undone.

## Implementation boundaries and acceptance

Implementation starts only after a concrete envelope policy is chosen. Reuse
registry pairing, cluster task admission, canonical permission/lease/budget
owners, WAL events and materialized views. A dedicated evaluator may calculate
an earned tier; it must not become a competing effect or authorization owner.
Migration is disabled for every existing peer and grants no new capability.
A read-only preview compares old and proposed decisions before activation.

Required acceptance scenarios:

1. No envelopes: identical pre-upgrade decisions and no new rights.
2. High score cannot overcome unpaired/revoked/denied state; new pairing epoch
   cannot reuse the previous epoch's tier.
3. Independent evidence unlocks only a named action/scope/quota until expiry;
   every ceiling is enforced at the actual effect boundary.
4. Expired leases, exhausted budgets and simultaneous requests cannot bypass
   existing admission or double-spend a quota.
5. Self-reward, duplicate receipts, retries, forged verifier identity and
   correlated observations cannot inflate independent evidence; replay agrees.
6. Revocation, decay, clock rollback and evidence appeals survive restart and
   produce inspectable decisions without claiming reversal of completed effects.

Before activation the operator must select earnable actions, per-tier ceilings,
approved verifiers, promotion/decay periods and adverse-event consequences.
Those are future policy choices. This design does not request that decision
prematurely or mark ADOPT31-C3 implemented/accepted.
