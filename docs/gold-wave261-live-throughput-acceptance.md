# W261 acceptance — GOLD-LF-P2-29

## Recommendation

**Accepted: `GOLD-LF-P2-29` only (2026-09-23).** The exact Road literal is satisfied by source-bound, individually selected and actually passing evidence for its native, CLI, GUI, Main and Buddy requirements at `d99d5c6c2cb69eab0648364bf1ac158679a3ac21`.

This is a leaf-specific recommendation. It is **not** a claim that the entire GUI124 run passed: GUI124d99 executed all 124 fixtures but failed W153 and W164. `GOLD-LF-P2-28` remains open because W164 is a P2-28 feedback callback fixture and failed.

## Road literal and required semantics

`PLAN/ROAD_TO_1_0_GOLD.md:8155` defines P2-29 as:

> compute a stable one-second rolling throughput from real streamed tokens/events, reset correctly across messages/providers and expose unavailable/paused/error states without invented values.

The candidate mapping narrows the source semantics correctly: current providers expose **visible stream events/s**, while final token totals do not become a live token rate. The selected tests cover the one-second denominator, exact expiry/high-rate preservation, explicit-incremental token-basis rejection, time-regression rejection, terminal/reset lifetime, content-free CLI wire and ordered producer lifecycle, plus typed daemon protocol/runtime/bridge state. The Road literal permits `tokens/events`; the evidence is specifically for real visible streamed **events**, and rejects invented token values.

## Native/CLI/daemon evidence — Group432d99

- Run: `35806200712` (`Group432d99`), terminal admission: `SOURCE-BOUND RESULTS; FAILURES RETAINED`.
- Source head: `d99d5c6c2cb69eab0648364bf1ac158679a3ac21`; receipt ref: `refs/heads/main`.
- Exact selection/execution: 432 required, 432 executed, 430 passed, 2 failed; the two failures are unrelated to throughput:
  - `connectors::control_plane::rpc::tests::unix_client_endpoint_identity_detects_a_replaced_socket_leaf`
  - `cli::context::unix_tests::unix_context_cli_client_status_plan_apply_pause_resume_reopen_and_shutdown_are_bound_to_live_daemon`
- All twelve P2-29 native identities are present in the selected fixture list and are not among those two failures, hence individually admitted passing terminals:
  1. `daemon::live_throughput::tests::visible_events_use_a_stable_one_second_denominator`
  2. `daemon::live_throughput::tests::discrete_window_expires_a_bucket_at_exactly_one_thousand_milliseconds`
  3. `daemon::live_throughput::tests::fixed_buckets_preserve_high_event_rate_within_one_millisecond`
  4. `daemon::live_throughput::tests::token_basis_requires_positive_explicit_incremental_deltas`
  5. `daemon::live_throughput::tests::time_regression_is_rejected_without_reusing_old_buckets`
  6. `daemon::live_throughput::tests::terminal_clears_state_and_reset_starts_a_distinct_lifetime`
  7. `cli::chat::tests::live_throughput_wire_is_exact_private_and_content_free`
  8. `cli::chat::tests::live_throughput_producer_sequences_transitions_before_provider_done`
  9. `cli::chat::tests::live_throughput_idle_interval_is_not_starved_by_ready_nonvisible_events`
  10. `daemon::gui_chat_protocol::tests::throughput_state_is_typed_bounded_and_content_free`
  11. `daemon::gui_chat_runtime::lifecycle_tests::throughput_mapping_preserves_the_producer_state_without_rederivation`
  12. `daemon::gui_chat_bridge::tests::throughput_bridge_event_preserves_inner_and_outer_sequences`

This covers the requested CLI requirement (items 7–9), typed daemon transport/runtime/bridge requirements (items 10–12), and the actual rolling-event lifecycle (items 1–6).

## GUI/Main/Buddy evidence — GUI124d99

- Run: `35806202796` (`GUI124d99`), terminal `failure`; source head is the same exact `d99d5c6c2cb69eab0648364bf1ac158679a3ac21`.
- Both hosted builds succeeded: `buildNeothCliExit=0`, `buildGuiTestHarnessExit=0`.
- Receipt accounting is complete: 124 expected/started/completed/executed; 122 passed; 2 failed; 0 unstarted; `coverageComplete=true`, `complete=false`, proof invariant `proof-incomplete`.
- Each selected P2-29 GUI terminal passed:
  1. `chat_throughput::tests::visible_event_rate_preserves_its_actual_unit`
  2. `chat_throughput::tests::paused_state_requires_null_rate_but_keeps_the_explicit_basis`
  3. `chat_throughput::tests::invalid_unit_and_final_usage_field_fail_closed`
  4. `chat_throughput::tests::stale_gap_and_provider_done_cannot_repaint_a_request`
  5. `chat_throughput::tests::cancellation_is_terminal_until_the_request_is_replaced`
  6. `w58_gui_callback_runtime_tests::w162_throughput_controls_are_transient_and_provider_done_fenced`
  7. `w58_gui_callback_runtime_tests::w168_daemon_throughput_state_projects_main_and_buddy_then_fences_boundaries`

Items 1–5 establish the reducer’s actual-unit, paused/unavailable/error, stale-terminal and cancellation boundaries. Item 6 is the Main callback. Item 7 is the daemon/Main/**Buddy** projection callback. Thus the specified GUI and Buddy requirements have passing terminals.

## Required retained failures and P2-28 boundary

GUI124d99 did **not** pass as a whole. Its two retained failures are:

- `w58_gui_callback_runtime_tests::w153_legacy_child_callbacks_project_only_transient_reasoning`: manager-owned GUI chat service reported `load=loaded, active=failed, sub=failed` before provider launch; the request unit exited `125/n/a`.
- `w58_gui_callback_runtime_tests::w164_response_feedback_callback_requires_post_done_target_and_verified_readback`: `NEOTH_GUI_CONTAINMENT_SYSTEMD_USER_MANAGER_UNAVAILABLE`; the per-user manager did not create and verify the request-owned transient service; the request unit exited `125/n/a`.

The targeted retained diagnostics show `neoth-w252-bin` AppArmor `ALLOWED` records and no matching `DENIED` record. They prove the observed service/manager failure boundary, not an AppArmor root cause.

W164 belongs to the P2-28 response-feedback callback evidence, so its failure keeps **P2-28 open**. Neither W153 nor W164 is one of the twelve native or seven GUI P2-29 identities above; neither invalidates the direct P2-29 behavior terminals. They remain material GUI admission failures and must remain visible in any Road decision record.

## Source, matrix, lock, and receipt binding

Both lanes bind the same admitted source and relevant selection artifacts:

| Binding | Value |
|---|---|
| Head | `d99d5c6c2cb69eab0648364bf1ac158679a3ac21` |
| Matrix | `docs/verification/gold-wave95-96-test-matrix.json` SHA-256 `43E7575B7305F4470906A291AB481091D4E29E1570720B57773765778F0486F8` |
| Source manifest | `docs/verification/gold-wave95-96-source-manifest.json`, 92839 bytes, SHA-256 `A5E8DE233378582934DDF049CEA3189A0F2EFCFA5902531816359696FA4A3EA8` |
| Cargo lock | `SRC/Cargo.lock`, 383179 bytes, SHA-256 `1FBCB15C89E2A3BDF7B0EDEC9AC0252C782BC7453EBCF83224463472D513A35D` |
| GUI workflow | `.github/workflows/gui-linux-fixtures.yml`, 36390 bytes, SHA-256 `287503AA29B386CE2AE4A05A8AE814191508149CE7093A4D01D87BF755555C53` |
| Group admission | `grouped432-d99/ADMISSION.json`, SHA-256 `BCEC71943BB906447E86D691D0A3A2424A79C2506001FC8517B33D3A3FC2E914` |
| GUI admission | `gui124-d99/ADMISSION.json`, SHA-256 `270469309F1A0D598CB27C7BA44C3A7BB0FEEBDF6103A6B5E53EE1ED7B654DBB` |

## Conclusion

P2-29 has complete leaf-specific behavior evidence at the admitted source: exact 12 native/CLI/daemon terminals and exact 7 GUI/Main/Buddy terminals passed; all are selected against the bound admitted matrix, manifest and lock. Recommend that the Road owner close `GOLD-LF-P2-29` with this evidence boundary.

Do not use this recommendation to mark GUI124 healthy or P2-28 closed. The retained W153/W164 failures, `GUI124d99` terminal failure and `proof-incomplete` status remain explicit facts.
Root verified that all 22 relevant native/GUI source paths remain unchanged from
`d99d5c6c` through `c43e5d0e`. W260 subsequently changes only failure diagnostics in
test-only supervisor code; it does not change throughput behavior. This source
comparison does not relabel the historical run as a current whole-workspace pass.
