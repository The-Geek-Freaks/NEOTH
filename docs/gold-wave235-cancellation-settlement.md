# W235 — Acknowledged provider cancellation settlement

Two actual macOS failures in Full CI 35782661515 exposed the chat cancellation
teardown boundary. The 250 ms fixture includes dispatch and WAL-writer shutdown;
the prior timeout alone did not identify which part stalled.

Cancellation now belongs to the authorized provider operation. Opening an event
stream, consuming its next event, and the optional history-compaction utility
completion explicitly await the provider terminal audit acknowledgement before
returning the cancellation error. ProviderCallAuditGuard::Drop remains a fallback
for an abandoned consumer, not the normal cancellation settlement mechanism.
A scheduler yield followed by a WAL flush was rejected because it cannot prove
that a detached Drop task submitted its terminal append before the flush.

Token-cap, fallback, compactor and its ArcAdapter forward the cancellation-aware
entries to the concrete leaf. Ordinary completion and stream entries preserve
their existing behavior. Role, consent, budget and effect-start checks remain in
the authorized path. During utility cancellation, compaction can still enter its
existing generic summary-error handling before a later cancellation fence wins;
it cannot dispatch the main provider or abandon the utility terminal audit.

## Focused acceptance

Four cases are selected in the Hosted grouped workflow:

- cli::chat::tests::dispatch_pending_stream_open_cancellation_closes_unobserved_once
- cli::chat::tests::dispatch_pending_stream_next_cancellation_keeps_bound_leaf_and_closes_once
- providers::compactor::tests::cancellable_compaction_settles_pending_utility_before_main_dispatch
- providers::fallback::tests::cancellable_authorized_completion_forwards_to_primary_leaf

The two chat cases retain the 250 ms cancellation contract and now require exactly
one PROVIDER_REQUEST followed by one PROVIDER_ERROR with stream_cancelled. The
new compactor case reaches a genuinely pending utility completion and proves that
the main provider is untouched. The new fallback case reaches the primary leaf
through the actual cancellation-aware forwarder. Both assert the same acknowledged
WAL lifecycle. Their teardown drops the authorizer's retained sender before the
writer and bounds writer_join to 250 ms, preventing an unbounded fixture hang.

Independent focused source review passed. Root caught and repaired a retained
fixture sender before publication. Dynamic validation is pending GitHub execution;
source review and a clean whitespace diff are not acceptance of the behavior.
The actual grouped union is now 402 cases; universal native identities rise from
843 to 845. The source manifest remains 535 paths; GUI inventory is unchanged.

Preflight 35795288640 passed on 3e99cfa5. GUI116 35795046176 and Group398
35795048502 remain separate runs on 480ff458 and cannot validate this W235 delta.
The next gates are Hosted core typecheck/slim Clippy, Group402 and preflight,
followed by full Windows/macOS CI after the focused production gates pass.

Road remains 1016 checked / 306 open / 2 partial. No checkbox is closed by this
source repair. No local compiler, formatter, parser, test or product runtime ran.

Preflight35796229434 supplied exact formatting for three provider files. The source
head, artifact digests, Git/local preimages and resulting postimages were verified
before import. No local formatter ran. Behavioral gates remain on5661e7d2.
