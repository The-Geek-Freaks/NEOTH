# Wave 207 request-local chat silence watchdog

**Hosted stack-repair result:** Grouped171 35753809069 on 76769a27 has no
stack-overflow or SIGABRT failures. Its W207 timing, cancellation, silent-stream
and post-reply paths now execute. The surviving normal output assertion assumed
a raw provider chunk boundary at the Markdown-buffered output sink. It now joins
all visible deltas and requires the exact text `first second done`, preserving
the 119-second progress and real-turn completion assertions. Fresh Hosted proof
of this final output assertion remains required.
**Hosted behavior checkpoint:** df9d9d22 passed Core test-target checking and
CLI build/export (35751196645). Grouped141 (35751191741) had 132 passes,
three assertion failures and six stack-overflow aborts. All four new actual
Prepared-Turn fixtures aborted; the isolated watchdog units passed. The repair
pins dispatch/post-reply on the heap and type-erases the watchdog input as a
boxed Send future, retaining the existing spawned regression tests. Stack
limits and behavioral assertions are unchanged; the repair needs Hosted proof.
The channel unavailable-context receipt now retains its admitted WAL session;
the mirror fixture declares sampling/output controls and a truthful finite cap.
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
