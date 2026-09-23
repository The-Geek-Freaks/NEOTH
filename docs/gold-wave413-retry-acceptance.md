# W413 — P2-14 Ralph retry acceptance

P2-14 is accepted at committed head 8f6ef116. This is a narrow parent acceptance for typed error classification, bounded LLM correction retry, fresh request/model/cost/permission authorization, deterministic stops, durable receipts, and CLI/GUI/Buddy presentation.

## Evidence ladder

The committed build-and-release cadence says Road-to-Gold evidence must not be weakened. Its accepted P2-24 precedent uses exact source-bound PASS terminals, a source-delta carry review, and retains unrelated grouped failures. This review applies the same rule: no generic all-green, all-OS, GUI-release, model-download, or local-execution gate is inferred.

## Required terminal set

Nineteen exact identities cover P2-14:

1. providers::claude_retry::tests::retry_receipt_wire_is_versioned_and_content_free
2. providers::claude_retry::tests::authenticated_retry_history_requires_same_session_next_attempt_and_valid_receipt
3. providers::cost_authorization::tests::empty_stdout_retry_gets_a_second_authorized_lifecycle
4. providers::cost_authorization::tests::final_retry_receipts_close_once_and_buddy_never_marks_them_followed_up
5. providers::cost_authorization::tests::consent_revoked_between_attempts_blocks_before_the_retry_wire
6. providers::cost_authorization::tests::mixed_retry_chain_retains_origin_only_for_final_authorization_denial
7. providers::cost_authorization::tests::direct_retry_closes_first_terminal_then_reauthorizes_before_success
8. providers::cost_authorization::tests::direct_retry_untyped_failure_is_terminal_without_a_second_raw_call
9. providers::cost_authorization::tests::direct_retry_typed_http_auth_is_terminal_without_a_second_raw_call
10. providers::cost_authorization::tests::direct_retry_stops_at_the_shared_transient_bound
11. providers::cost_authorization::tests::direct_retry_consent_revocation_blocks_the_second_raw_call
12. providers::cost_authorization::tests::direct_retry_does_not_send_early_during_a_durable_quota_cooldown
13. providers::cost_authorization::tests::direct_retry_honours_one_short_quota_retry_and_stops
14. providers::cost_authorization::role_dispatch_tests::w225_effect_start_role_rejection_closes_admitted_retry_with_denial_receipt
15. providers::cost_authorization::role_dispatch_tests::w278_immediate_before_send_role_rejection_closes_admitted_retry_with_denial_receipt
16. providers::cost_authorization::tests::direct_retry_reauthorizes_a_bounded_typed_error_correction_request
17. providers::cost_authorization::tests::direct_retry_context_over_input_cap_is_denied_before_a_second_raw_send
18. panel_logic::tests::w219_provider_retry_is_strict_bounded_redacted_and_absence_compatible
19. w58_gui_callback_runtime_tests::w219_provider_retry_status_callback_projects_only_safe_rows_and_retains_last_known_good

Group810bdb run 35866133454 provides source-bound actual PASS terminals for identities 1 through 17. It selected and executed 810 identities, passed 807, retained three unrelated failures, and admits all 163 source hashes, matrix/lock bindings, and actual terminal ordering.

GUI135216 run 35856964423 provides source-bound PASS terminals for identities 18 and 19. Its receipt records each as selected, started, completed, executed, and passed, with direct execution receipts test-094-execution.txt and test-127-execution.txt.

## W375 gap closure

W375 correctly left P2-14 open because its then-current evidence showed deterministic typed retry conditions but not a documented error-aware LLM correction request carrying extracted context.

The current provider path now derives a bounded typed error context, places it only in a fixed-format correction system request, and reauthorizes the exact changed request before a second raw send. It refuses unavailable context and rejects an over-cap correction before transport. It does not place the correction context into receipts, WAL payloads, or Buddy history.

Identity 16 proves a typed HTTP 500 causes exactly one reauthorized correction request, contains bounded status context, excludes the untrusted upstream body, and leaves no correction context in WAL. Identity 17 proves an over-cap correction is denied before a second raw send or second Council charge. These are the smallest additional terminals that close W375's documented error-aware correction gap.

## Current-head carry

From Group810 source bdb50ac2 to current head 8f6ef116, the Git blobs are identical for claude_retry.rs, cost_authorization.rs, providers/mod.rs, cli/chat.rs, cli/buddy.rs, panel_logic.rs, and main.rs.

GUI135 was admitted on 21612331. panel_logic.rs is byte-identical through 8f6ef116. The only main.rs delta is confined to W164 response-feedback and citation fixture shell syntax; it does not touch the W219 retry panel contract or callback wiring. GUI135 therefore carries for identities 18 and 19.

The three Group810 failures concern CLI parity inventory and physical WAL-redaction fixtures. They are retained in the group admission but neither overlaps this identity set nor changes the relevant source paths.

## Decision

The P2-14 parent Road box is closable. No P2-14 production or evidence gap remains under the literal Road criterion.

No local compiler, parser, formatter, test, product runtime, model archive, or download ran under the BSOD hold.
