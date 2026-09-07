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
separate when their authenticated call paths supply them. This Wave 4 scope
records `local` and does not establish peer or channel principals. A free
display label or a command's source-channel string cannot create a trusted
subject or consume a local confirmation.

The coding GUI and Buddy use the public unattended request constructor. At
the prior checkpoint, a user-editable GUI source label of `cli` could select
the CLI origin and omit the final policy check. The private confirmation
marker closes that bypass: only the actual local CLI apply flags can create
it, and every dispatcher apply receives the policy. Default GUI and Buddy
apply requests still refuse `Confirm`, as they did before this change. They
do not yet have a separately bound GUI approval flow.

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

## Remaining GOLD scope

This document describes implemented boundaries; runtime evidence belongs to
the corresponding source-bound batch verification report. It does not close
the all-boundary `GOLD-LF-P1-05` task. Durable proactive/webhook admission and
unknown-append reconciliation, authenticated cluster-task admission, required
upstream channel-reply audit and Obsidian preload admission remain separate
implementation work. Pure policy displays and scheduling probes must not be
turned into duplicate final decisions to inflate apparent coverage.

The upstream authenticated channel-turn decision is distinct from the final
local-subject durable reply decision, whose exact recipient and body exist
only after the pipeline returns. Neither a boolean nor an unrelated upstream
receipt authorizes that final outbox operation.
