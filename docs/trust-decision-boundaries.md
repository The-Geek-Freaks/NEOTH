# Required trust decisions at effect boundaries

NEOTH distinguishes policy inspection, permission admission and the outcome of
an operation. A displayed `Allow` is a policy preview. A typed `TrustDecision`
records the resolved permission admission. A later patch, HTTP, MCP or config
receipt records what the admitted operation actually did.

Inspect the retained, authenticated decisions for one exact subject with:

```text
neoth permissions audit --subject local
```

`local` is the operator/process subject for decisions without delegated
authority. The ledger can keep pre-authenticated peer and channel subjects
separate when their authenticated call paths supply them. Wave 4's implemented
boundaries record `local`; the upstream channel-reply boundary records the
platform-verified inbound sender supplied by its channel adapter. Cluster task
admission uses the authenticated Noise remote key and rejects a membership
grant bound to a different transport or peer. A free
display label or a command's source-channel string cannot create a trusted
subject or consume a local confirmation.

The coding GUI and Buddy explicitly select the interactive GUI route. At an
earlier checkpoint, a user-editable source label of `cli` could select the CLI
origin and omit the final policy check. The private CLI confirmation marker
closes that bypass. The separate native GUI flow now requires an exact one-use
patch approval, described below; every dispatcher apply still receives the
policy. An unattended request or a GUI route without its live run broker cannot
satisfy `Confirm`.

## Admission and persistence

Required callers await the canonical Gate's compatibility permission frame
and its typed `TrustDecision`. The latter is acknowledged only after a keyed
WAL authentication marker covers the decision. An unavailable writer, failed
append or failed authentication acknowledgement prevents the effect.

One-shot CLI commands use the authenticated RPC for the exact NEOTH home when
a live daemon owns that home. They do not open a fallback writer beside an
unavailable live daemon. Otherwise the command owns a standalone home-bound
writer through admission, operation and finalization. Finalization has a
deadline; abandoned operations retain cancellation ownership of the writer.

An authenticated admission does not assert that an effect succeeded. For
example, cancellation after admission but before worktree creation retains the
real `Allowed` history while restoring the task to `Backlog` and reporting no
applied task ID. An effect already underway is joined and its actual outcome
is reported.

## Implemented request boundaries

| Boundary | Admission binding and ordering |
|---|---|
| Coding patch application | The explicit CLI apply action supplies local confirmation. Admission binds physical repository identity, task, accepted patch and origin. A private consumed capability is revalidated before the sole worktree creation path. No patch means no apply decision. |
| Self-source edit | A live terminal permission refusal is recorded before preparation. A permitted request records its final allow after Git path, HEAD/index and proposal-image checks, immediately before live apply. The two routes do not create duplicate final decisions. |
| External HTTP | Permission evidence uses the same writer/RPC owner as the required HTTP intent and result. It precedes intent, permit creation and transport. A scheduling denial hint is a pure preview. |
| Explicitly released research | Policy and confirmation see the real request. Persisted permission action and denial labels are fixed and provider-neutral. The typed reason digest hashes the neutral label; the audit binding derives from random request correlation, never the private topic-bearing permit binding. |
| Todo and calendar writes | Required admission precedes the provider mutation and binds the effective immutable request, including the calendar collection destination. The same audited operation owns its finalization. Read-only list and dry-run paths do not create production write admissions. |
| Skill and cron self-activation | Existing kill-switch, allowlist, sovereign/Custom and confirmation rules remain authoritative. Config writes revalidate under the coherent config lock; cron holds config authority through dependent jobs publication in config-to-jobs lock order. Lock-taking mutations run off the async runtime thread. |
| One-shot MCP call | The audit owner spans preflight, authorization, child spawn, invocation and outcome. Canonical server/tool/argument binding is carried by the opaque proof and checked again before transport. Rejection and invocation compatibility records do not independently emit another final TrustDecision. |
| Upstream channel reply | The required decision retains the verified inbound sender as lease and ledger subject. It precedes live provider-stream opening or the ordinary reply release tail. A missing audit prevents returned outbound/egress. This is distinct from final durable outbox authority, whose recipient/body binding exists later. |
| Obsidian template preload | Disabled or incomplete configuration skips without a decision. A configured preload requires one local decision before spawning the task and before its lifecycle intent, vault/state writes or DB ingestion. Both primary and knowledge templates ingest into the authoritative instance home's `views.db`. Shared containment checks reject existing linked ancestors before creating target parents. A denial or unavailable writer starts no preload task. |
| Cluster task queue admission | Validated, paired tasks reserve bounded executor capacity before the final required decision. The authenticated Noise key is the ledger/lease subject; a domain-separated digest binds peer, task ID and exact prompt. Membership is revalidated after admission. A final fallible enqueue detects executor closure or newly exhausted capacity; the accepted cluster event follows only a successful enqueue. |

## Authentication and completeness

Ledger inspection returns either a complete authenticated history or an
explicit authenticated prefix. A live writer may have an ordinary HTTP intent
or outcome after its last authentication marker. The earlier sealed
TrustDecision remains inspectable, but the later tail is not silently presented
as complete authenticated history. Tests of ordering must distinguish those
two facts.

Request digests are commitments, not permission to substitute an action. The
production effect must consume the same immutable target/arguments that were
admitted. Raw request bodies, patches and task contents are not fields of a
typed TrustDecision.

## Durable outbound admission

Proactive claims v3 and webhook outboxes v2 persist an immutable local-subject
descriptor before submission. It binds the operation, action, effective target
and body, policy fingerprint and decision provenance. A local receipt cache
is not authority: recovery validates the descriptor against the actual effect
and reconciles it through the authenticated primary WAL.

The closed writer transaction owns home-scoped process and OS authority while
it checks the ledger and, if absent, appends one schema-2 TrustDecision with a
forced HMAC marker. It seals only the writer's own open HMAC window before
lookup. A foreign or malformed tail cannot become an absence proof. An exact
receipt returns ExistingExact; duplicate, conflict and indeterminate outcomes
remain distinct. Generic append routes reject schema 2. The mandatory local
RPC preserves the same typed results and home identity without automatic retry.

Live egress captures one accepted ReloadController snapshot. An authenticated
receipt precedes the accepted snapshot's effect lease and actual transport.
Reload retires old admission and drains already leased effects before it
publishes a replacement. A suppressed proactive operation still records its
authenticated Intent/Result history, but never Arms or invokes a provider.
The dispatcher reads a coherent config/credential pair from the exact serve
configuration path and requires it to match the accepted snapshot before use.

Normal proactive ownership retains the generation lease through terminal
Result acknowledgement. Its provider task also owns a clone through actual
I/O teardown, so cancellation cannot release a live effect or retain a reload
lease until a later recovery tick. The Armed claim and queued JoinHandle retain
truthful unknown-outcome reconciliation independently. A webhook owned task
holds its record and generation leases through HTTP, result audit and durable
outbox settlement even when the outer caller is cancelled.

Webhook retries reuse the same authenticated descriptor when the current
accepted policy fingerprint matches. Process-local reload epochs are not
persisted authority. Legacy retry migration marks historical attempts as
future-only continuation; it never claims retrospective authorization.
DeliveredPendingAudit remains audit-only. Legacy proactive Armed uncertainty
remains CrashUnknown without resend. Exactly once describes the TrustDecision,
not physical provider delivery.

## Native GUI accepted-patch approval

Settings and Buddy select the public GUI apply route, which supplies no
authority by itself. Only the live Coding run attaches its private approval
broker to the dispatcher. One bounded pending slot binds the canonical
repository identity, task, exact accepted patch digest, request binding and
expiry. Events and snapshots expose metadata only. A separate local read
returns the complete accepted patch while that exact approval remains pending;
neither a preview read nor an audit artifact file authorizes an effect.

The controller fences every observation, preview and response by UI revision,
run ID and opaque approval ID. It reserves one local response and rejects
delayed completions from an older approval. Cancellation synchronously closes
this admission on the UI callback thread before asynchronous Core delivery.
Shutdown, cancellation and terminal settlement clear pending preview state.

The broker consumes its slot before replying and invalidates snapshot metadata
in the same ordered transition. Reject, expiry, cancellation and replay cannot
yield another grant. The private non-cloneable accepted grant remains bound to
the exact request. After the approval wait, the dispatcher re-discovers the
physical repository and recomputes the binding before the required final Gate.
Only this matching grant supplies `native_gui_patch_approval`; a GUI route or
source label alone cannot do so. The authenticated TrustDecision precedes the
sole worktree effect, and the existing post-admission identity and cancellation
checks still apply. Cancellation after writer ownership retains a truthful
decision while preventing the later worktree effect.

The local CLI confirmation capability remains private and distinct. GUI
approval never makes an editable `LocalCliFlag` or source string authoritative.

## Remaining GOLD scope

This document describes implemented boundaries; runtime evidence belongs to
the corresponding source-bound batch verification report. The Wave 7 inventory
and verified local runtime gates close `GOLD-LF-P1-05`; the final report is
`gold-wave7-verification.md`. Full workspace, live-provider and platform/release
acceptance remain separate Gold requirements. Pure policy displays and
scheduling probes must not be
turned into duplicate final decisions to inflate apparent coverage.

The upstream authenticated channel-turn decision is distinct from the final
local-subject durable reply decision, whose exact recipient and body exist
only after the pipeline returns. Neither a boolean nor an unrelated upstream
receipt authorizes that final outbox operation.

Cluster parsing, static-denial and membership/lease prefilters, plus absent,
full or closed executor queues, reject before final queue admission. They do
not manufacture typed decisions for work that cannot enter the queue. A lease
that expires before the final Gate is denied there. Membership revocation
after an authenticated Allow retains that truthful decision but prevents the
queue effect and accepted event. The same distinction applies if the executor
closes or another producer takes the capacity before the final enqueue.
This boundary does not deduplicate repeated
peer task IDs or claim exactly-once remote task execution.
