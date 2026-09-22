# Wave 207 request-local chat silence watchdog

**Hosted compile correction:** Grouped141 on d630708d stopped on E0382 before
any behavior test ran. Save the stream boolean before moving ChatArgs into
post-reply work; fresh hosted compilation and behavior remain required.

W207 gives an admitted chat turn one 120-second meaningful-progress deadline.
The same watchdog covers the actual provider dispatch and response-producing
post-reply work. Non-empty visible/reasoning deltas and successful provider
completion count as progress; empty deltas, metadata and read polling do not.
A sticky expired signal prevents late events from reviving an expired turn.
Cancellation and expiry share one atomic terminal claim. The watchdog owns no
background task and drops with the turn.

Expiry produces a typed TurnSilenceTimeout, not a successful StreamDone or
terminal completion. Plain daemon RPC returns a typed 503; a written request
cannot fall back to standalone dispatch. Plain connect/write remain bounded;
there is no competing total response deadline that interrupts legitimate
provider progress. GUI attach bounds its header and allows the core silence
window plus five seconds for terminal delivery between subsequent reads.
The GUI maps timeout to Failed and retains retry guidance in the exact active
subscription through the failed terminal, keeping the canonical reply separate.
Reattachment and generation changes clear the transient timeout projection.

Seventeen new core test identities cover timer races, coalesced/late signals,
real prepared streaming turns, metadata-only silence, explicit cancellation,
a real post-reply agent-review stall, typed protocol contracts and a delayed
actual attach transport. One GUI reducer test covers partial Delta -> Timeout
-> Failed and stale-turn/generation rejection. These are source regressions;
execution is pending on GitHub. Independent static review passed after repairing
the shorter attach timeout, unguarded post-reply future, unreachable old retry
fixture and transient GUI error text. Successful direct completion also resets
the carried deadline before post-reply processing.

This batch also carries the W206 transport-versus-billing budget repair,
minimal mirror leaf requests with 128 output tokens, the incomplete-home Unix
0700 fixture, and safe missing-role diagnostics in the original delegated-channel
integration. That integration remains unresolved until a fresh hosted result.
No assertion was waived and no Road checkbox is closed by this publication.

GUI evidence: only Rust protocol/state/copy paths changed, no Slint/token/layout
or interactive control changed. Source review confirms subscription-bound error
copy and no completed preview on failure. Screenshot, accessibility and native
runtime acceptance remain unrun; the design-system audit checklist is not claimed
complete. Exact-source core/GUI hosted gates remain required.

Host constraint: no local compiler, Cargo, formatter, code/model parser, tests,
fixtures, product, GUI or audio execution. Text, JSON, hash and Git work only.
The older Windows preview run 35731976627 passed on a68442cb. Its 12 lifecycle
and 10 diff-impact receipts include the expected corrupt/stale rejection cases
and share one binary hash; they do not accept this newer batch.
