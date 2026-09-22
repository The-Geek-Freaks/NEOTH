# Wave 217 durable provider retry visibility

The existing Claude tmux classifier and authorization flow now publish a stable
operator receipt at their actual provider lifecycle terminal. This is a
vertical slice of GOLD-LF-P2-14, with a read-only cross-process Buddy projection.
It adds neither a second retry policy nor a sidecar persistence store.

## Producer and retained authority

`neoth.retry-receipt.v1` contains only retry chain, class, 1-based attempt,
concrete provider, canonical authorized wire model and confirmed disposition:
`retry_intent_closed`, `exhausted` or `auth_non_retryable`. A retry closes its
existing attempt before backoff; a final classified stop closes it exactly
once, including outer provider cleanup. A fresh attempt still requires the
existing request/model/cost/permission/role admission and actual-start fences.
Its existing request lifecycle carries the explicit chain and next attempt.

There is no raw prompt or error-string field. No extra WAL event family or
status sidecar is introduced. A permission denial between a closed attempt
and the next authorized request cannot invent a provider terminal receipt.

## Buddy projection

`neoth buddy status` adds `provider_retry`. It reads the selected default
instance home, using the existing authenticated WAL-prefix scanner. A later
request counts as an observed successor only for the same opaque WAL session,
exact chain and immediate next attempt after `retry_intent_closed`. Auth and
exhausted receipts cannot be reinterpreted as retries. Reused chain identifiers
remain separate across sessions.

The projection is explicitly bounded to 64 directory entries, 32 segments,
4 MiB physical / 8 MiB logical scan, 16 recent rows, 128-byte dynamic fields and
16 KiB output. Invalid schemas, zero attempts and malformed/oversized receipts
are not projected. Incomplete authenticated history is marked as incomplete;
no bytes from a torn tail appear. `follow_up_lifecycle: observed` proves a
later admitted lifecycle intent, never that a raw provider send occurred.
The query creates no history files and survives process boundaries through WAL.

## Verification boundary

Independent bounded source review passed after correcting session/attempt
correlation and preserving two sessions sharing a chain. Four selected tests:

- `providers::claude_retry::tests::retry_receipt_wire_is_versioned_and_content_free`
- `providers::claude_retry::tests::authenticated_retry_history_requires_same_session_next_attempt_and_valid_receipt`
- `providers::cost_authorization::tests::empty_stdout_retry_gets_a_second_authorized_lifecycle`
- `providers::cost_authorization::tests::final_retry_receipts_close_once_and_buddy_never_marks_them_followed_up`

The reader regression writes and drains an authenticated Home WAL, then checks
valid succession, cross-session and reused-chain isolation, wrong ordering,
wrong attempt, invalid receipt, exhaustion and torn-tail exclusion. Producer
regressions exercise actual permit/authorizer transitions and require exact
request/terminal pairing; final Auth and exhausted outcomes remain un-followed
in Buddy readback. These tests are source changes awaiting Hosted execution.

Current inventory: 531 sources / 813 universal native / 92 GUI plus unchanged
platform extras. Grouped270 covers the four cases. This does not close P2-14:
GUI retry presentation, broader backend coverage and an explicit between-attempt
authorization-denial receipt remain follow-ups. No Road checkbox or release gate
closes here. No local compiler, formatter, parser, tests or runtime were invoked.

W216 exact formatting is published in `4273f118`, Preflight `35777121108` passed.
Its Grouped266/Core on `558163ad` remain under evaluation. Old full CI
`35765595152` ended with macOS compile timeout after 100 minutes of paging,
without a Rust diagnostic. Its discoverable 1.31 GiB partial cache is retained
for the next unchanged single-job native compile; Windows14 were repaired W216.

Published33566416757ea69da6e84e4e39233b00955aec09. Exact Hosted formatter
receipt35778052636 is imported after source SHA, patch SHA and both Git
pre/postimages were verified. No formatter ran locally. Grouped27035778050758
and Core35778054554 are running on that source; behavior remains pending.
