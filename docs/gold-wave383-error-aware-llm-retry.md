# W383 — error-aware LLM retry

## Scope

W383 addresses the concrete P2-14 implementation gap identified by W375 for the existing normal non-stream direct-chat provider consumer. It does not close P2-14 acceptance: hosted current-head validation remains required. It does not add a retry framework or expand retry ownership to other callers.

## Behaviour

`Provider::complete_authorized_direct_retry` now derives a bounded correction context only from typed retryable facts:

- quota retry delay;
- typed provider HTTP status;
- typed `reqwest` HTTP status, timeout, or connection failure.

The retry request carries a fixed system instruction asking the model to re-evaluate the original request, plus the actual typed fact, for example `kind=http_status status=500`. The first request is unchanged. Each retry is rebuilt from that original request so correction text does not accumulate across the existing bounded retry limit.

No arbitrary `anyhow` display text, provider response body, or quota body enters the correction request. Unknown or ambiguous errors remain terminal. Authentication failures remain terminal, and existing quota cooldown, retry bound, consent, role, authorization, Council budget, cost, and durable lifecycle gates stay in front of every later raw send.

## Binding and operator privacy

`ProviderDispatchPermit::begin_retry_attempt_for_request` authorizes the exact correction request immediately before its transport call. This renews the request/cost/permission binding instead of using the first request's authorization. The retry receipt continues to contain only its stable class, attempt, provider, model, chain, and disposition fields. The correction context is not written into receipts, Buddy history, or WAL lifecycle payloads.

## Regression coverage added

`providers::cost_authorization::tests::direct_retry_reauthorizes_a_bounded_typed_error_correction_request` records the real request received by the direct-provider transport fixture. It proves that a typed HTTP 500 reaches one reauthorized second request carrying the bounded context; its raw fixture body is absent; Council budget is charged twice; and WAL payloads contain no correction context.

`direct_retry_context_over_input_cap_is_denied_before_a_second_raw_send` additionally proves that an initial request at its exact input cap is admitted, while the augmented retry request is denied before a second raw call. Its first retry terminal stays durable and truthful; no fictional second lifecycle is written. The shared-bound test captures all four requests and proves the correction context is rebuilt from the original request instead of accumulating.

Existing direct-retry regressions retain the deterministic stop, consent-revocation, and Council budget/cap boundaries:

- `direct_retry_untyped_failure_is_terminal_without_a_second_raw_call`;
- `direct_retry_typed_http_auth_is_terminal_without_a_second_raw_call`;
- `direct_retry_stops_at_the_shared_transient_bound`;
- `direct_retry_consent_revocation_blocks_the_second_raw_call`;
- `direct_retry_does_not_send_early_during_a_durable_quota_cooldown`; and
- `direct_retry_honours_one_short_quota_retry_and_stops`.

## Validation boundary

No Cargo, compiler, parser, rustfmt, test, runtime, or local executable validation was run under the absolute BSOD hold. The change received text and Git inspection only; hosted checks remain required.
