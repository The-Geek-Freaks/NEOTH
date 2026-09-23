# Gold W315: bounded direct-provider retry

## Admission status

Source-only W315 admission. The workstation is under the local BSOD hold, so
this change has not run Cargo, a compiler, Rust parser, formatter, tests, a
runtime, or a model. It is not an acceptance claim. Exact-head hosted CI must
run the intended native gates before this behavior is considered verified.

## Scope

W315 adds one explicit retry entrypoint for the normal, non-stream direct-chat
provider route in `cli/chat.rs`. The existing `CostAuthorizingProvider`
boundary selects it only after direct-route selection. Ordinary
`Provider::complete_authorized` and `CostAuthorizingProvider::complete` retain
their one-attempt behavior.

The change excludes streaming, MCP, council, fallback, channel, Cron, coding,
sub-agent, clarification, pinned recovery, Claude CLI's already permit-owned
tmux retry adapter, and every other provider route.

## Lifecycle contract

Each failed retryable attempt first writes its existing provider terminal with
a `retry_intent_closed` receipt. Only then does the runner wait. Before every
next raw call it invokes the existing `ProviderDispatchPermit` retry path,
which reauthorizes the exact leaf, cost/budget, provider subject, role policy,
consent, effect fence, WAL lifecycle, retry-chain, and retry attempt.

Authentication-class failures are terminal. Retryable failures use the shared
bounded retry decision: transient failures permit three retries after the
original send; session-collision and empty-output classes permit one. A final
failure emits one existing terminal with `exhausted`; a newly admitted retry
that is denied by authorization or role policy emits the existing
`authorization_denied` receipt before another raw send.

A typed `QuotaError` is different from a generic transient: it receives one
in-turn retry only when it includes an explicit `Retry-After` of at most 30
seconds. Missing or longer values stop immediately, so the existing quota
recorder can retain its durable cooldown rather than the chat runner sending
before it expires.

Direct-provider classification never receives `error.to_string()`, HTTP
bodies, prompts, or response text. It retries only typed quota errors and
typed reqwest connect, timeout, 408, 429, and 5xx transport outcomes; typed
401/403 outcomes are terminal authentication failures. An untyped error is
terminal without a retry receipt because it may be a permanent rejection or
an ambiguous after-effect outcome. Receipts and Buddy's read-only retry
history therefore contain only the stable class, provider, bound wire model,
retry chain, attempt, and disposition.

## Intended verification

The focused tests in `providers/cost_authorization.rs` cover a raw transient
failure followed by success, typed HTTP-auth and untyped terminal behavior,
bounded transient exhaustion, fresh retry lifecycle provenance, raw-error
exclusion from lifecycle frames, and consent revocation between attempts with
zero second raw call. Adapter Wiremock 401 fixtures prove that real upstream
authentication responses produce the same typed status. Existing permit tests
cover authorization denial between attempts. The direct quota fixture confirms
that a one-hour `Retry-After` has exactly one raw call. Intended admission
gates are the exact-head hosted Rust format, targeted provider authorization
tests, and the repository's native build/test workflow. No local gate was
executed under the BSOD hold.
