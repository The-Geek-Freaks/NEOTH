# W221 — Durable receipt for a pre-send retry consent denial

An admitted retry can lose live provider consent after its durable request
intent but before raw transport. The existing error terminal now carries
`authorization_denied`, bound to the same chain, provider, wire model and
1-based retry attempt. This receipt is only valid from attempt 2. The change
is limited to the live-consent fence; role-dispatch and effect-start denial
projections remain separate work and are not claimed by this batch.

The permit retains an immutable retry-origin class for this final denial.
Every `retry_intent_closed` terminal still records the actual class of that
specific failed attempt. The origin mutex is released before asynchronous
terminal writing. The existing audit state enforces active-only production,
rejects BetweenAttempts/TransportOnly receipt creation and preserves Closed
idempotence. Authorization failures before a new durable intent still do not
invent a request or terminal receipt.

Core history and the strict Buddy GUI accept the new closed disposition only
for non-Auth classes, attempt >=2 and no observed follow-up. Auth remains paired
only with `auth_non_retryable`. Receipt projection contains no prompt/raw error,
chain/session remain absent from GUI rows, and the passive card makes no send
or delivery claim.

## Focused regression scope

- `providers::cost_authorization::tests::consent_revoked_between_attempts_blocks_before_the_retry_wire`
  checks two paired lifecycles, one simulated raw send and the exact final denial.
- `providers::cost_authorization::tests::mixed_retry_chain_retains_origin_only_for_final_authorization_denial`
  exercises Transient attempt 1, SessionCollision attempt 2, then admitted
  attempt 3 denied for revoked consent. It requires six alternating lifecycle
  frames, two simulated raw attempts, correct per-attempt classes, stable chain/
  provider/model and an actual authenticated Buddy readback of the final denial.
  It uses the canonical home WAL/key, waits readiness and drains the writer.
- Existing versioned-wire/history and W219 GUI-parser cases additionally reject
  Auth mismatches, attempt-1 denial, unknown dispositions and observed denial.

Independent static review passed after correcting class retention, mutex scope
and the authenticated fixture path. No local executable validation ran. Hosted
Grouped281 must execute the new and extended native cases; GUI parsing and
rendering require the native GUI lane. No P2-14 checkbox closes on this slice.
Inventory: 532 sources, 819 universal native cases, 94 GUI names, 22 Linux and
22 macOS GUI extras, 26 custom macOS cases.

Prior source-bound Grouped27435783436951 on e8772e77 passed all274 exact cases,
including both W220 persisted-registry/config-drift regressions. All57 source
paths, matrix, lock and individual result terminals match Git objects. That
receipt does not validate later W221 or W222 source.

Published778637e05d611cba84504adecfcfa325715348b1. Hosted formatter receipt
35785415822 imported with source/SHA256 and exact Git pre/postimage checks.
Grouped28135785415701 is running on that published source; no local formatter ran.

## Hosted result 2026-09-22

Both named W221 regressions passed in source-bound Grouped281 `35785415701`
on `778637e05d611cba84504adecfcfa325715348b1`: 281/281 total, all 58 source
hashes/matrix/lock/individual pass terminals verified. This accepts the core
consent-denial regression scope. Current native GUI acceptance remains separate.