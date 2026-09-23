# W278 — retry role-revocation receipt at the immediate send fence

The warm Claude tmux retry path rebinds a retry through the existing request,
wire-model, cost, permission, and role-dispatch authorization before its next
send. A second role-policy check occurs after session preparation and directly
before the pane effect is reserved. Previously that specific check closed an
admitted retry with a generic provider terminal, losing the typed retry receipt
that binds the attempted retry to its chain, class, attempt, provider, and
wire model.

`ensure_role_dispatch_before_send_or_retry_terminal` now routes that rejection
through `ProviderDispatchPermit::finish_retry_authorization_denied` with
`role_dispatch_policy_changed`. For an initial attempt without retry context,
the existing permit behavior remains a normal terminal. For an admitted retry,
the terminal is `authorization_denied`; it is written before any raw pane send.

`providers::cost_authorization::role_dispatch_tests::w278_immediate_before_send_role_rejection_closes_admitted_retry_with_denial_receipt`
uses the real immediate-before-send helper after a real retry reauthorization
and an accepted role-policy reload. It requires exactly request/error,
request/error lifecycle pairs, no response frame, no duplicate terminal, and
the second receipt's exact transient class, attempt 2, stable retry chain,
provider, and wire model.

The test seam is `cfg(test)` only. It exposes the production helper to the
sibling role-dispatch test module and adds no product command or public API.
No local compiler, formatter, parser, test, or runtime was run under the
current BSOD hold.
