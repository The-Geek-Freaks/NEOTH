# W410 - P2-23 Dream opt-in functional acceptance

GOLD-LF-P2-23 is accepted for its functional Dream opt-in contract. The
acceptance is deliberately source-bound and limited to the 22 named
terminals: 12 native Dream/configuration/scheduler cases and ten GUI
wizard/Settings receipt-and-readback cases. It does not claim full CI,
platform-package, release, or clean-machine acceptance.

## Admitted terminal evidence

Group810bdb35866133454 ran on source
bdb50ac2acc4583345b61eb620ae7d08ecac5307. Its grouped receipt records
810 selected, 810 executed, 807 passed and three retained failures. All 163
source bindings matched, the matrix and lock matched, and ordered selection
with actual terminals was verified. None of its three failures is a P2-23
identity. The native run log contains a successful discovery and run terminal
for every twelve cases below, including the current
cli::serve_tasks::zf06_fleet_tests::desired_dream_cron_uses_explicit_fail_closed_autonomy_rail
identity.

GUI135216 run35856964423 ran on source
21612331dbc4e1fc8929e6990775f165c86fb3f1. Its source-bound fixture receipt
is complete: 135 selected, started, completed, executed and passed; no failure
or unstarted name remains. All ten named Dream GUI identities below are in its
passed-name receipt. The admission has 23 source/input bindings, all matching
Git, with ordered selection and actual terminals verified.

## Accepted native terminals (12 of 12)

- `cli::dream::tests::status_without_config_reports_manual_only_defaults` — default off/readback.
- `cli::dream::tests::cron_enable_is_atomic_lossless_and_canonicalizes_legacy_spelling` — authoritative enable and legacy normalization.
- `cli::dream::tests::cron_disable_is_idempotent_but_still_requests_reconciliation` — explicit disable and reconciliation.
- `cli::dream::tests::cron_mutation_requires_initialized_config` — no mutation without initialized config.
- `cli::dream::tests::invalid_config_is_unchanged_and_never_requests_reload` — malformed config fails closed.
- `cli::dream::tests::status_exposes_enabled_but_fail_closed_autonomy_contracts` — status/readback exposes autonomy denial.
- `config::reload::tests::reload_retires_old_dream_gate_and_waits_for_active_commit` — reload retires and drains old Dream gate.
- `config::reload::tests::reload_closes_dream_updater_and_egress_admission_before_every_drain_or_publication` — reload closes irreversible Dream leaves before drain/publication.
- `config::reload::tests::strict_and_custom_snapshots_never_open_a_dream_commit_gate` — Strict and Custom fail closed.
- `config::reload::tests::policy_reenable_publishes_a_fresh_active_dream_gate` — reenable has fresh generation gate.
- `cli::serve_tasks::tests::spawn_cron_scheduler_blocks_strict_and_fail_closed_custom` — scheduler suppresses Strict/Custom.
- `cli::serve_tasks::zf06_fleet_tests::desired_dream_cron_uses_explicit_fail_closed_autonomy_rail` — fleet desired state consumes explicit Dream/autonomy rail.

## Accepted GUI terminals (10 of 10)

- `dream_cron_gui_tests::wizard_completion_is_daemon_acknowledged_and_fails_closed_on_loss` — wizard completion and daemon-loss fail closure.
- `dream_cron_gui_tests::daemon_completion_failure_retains_existing_dream_readback_and_revision_order` — failure preserves verified readback ordering.
- `dream_cron_gui_tests::observer_uses_a_separate_read_only_handle_without_holding_mutation_lock` — nonblocking read-only observer.
- `dream_cron_gui_tests::finish_navigation_is_owned_by_verified_rust_completion` — no Slint-side optimistic Finish navigation.
- `dream_cron_gui_tests::mutation_requires_reload_receipt_then_matching_readback` — Settings mutation receipt then matching readback.
- `dream_cron_gui_tests::mutation_rejects_acknowledged_but_mismatched_readback` — mismatched readback is rejected.
- `dream_cron_gui_tests::settings_dream_control_is_command_only_and_never_flips_verified_state` — Settings control is command-only.
- `dream_cron_gui_tests::only_verified_readback_publishes_visible_dream_state` — only verified readback may publish state.
- `dream_cron_gui_tests::refresh_mutation_error_and_concurrency_keep_readback_authoritative` — error/race preserves readback authority.
- `dream_cron_gui_tests::late_status_refresh_cannot_overwrite_the_onboarding_draft` — late refresh cannot overwrite onboarding choice.

## Focused source carry

The native evidence remains carried from Group810bdb. Between its source and
the current committed source, the only changed selected-native path is
SRC/neothd/src/cli/serve_tasks.rs: a cluster-only
outbound_task_delegate parameter is threaded into spawn_audit_rpc. The
W359 scheduler and ZF-06 Dream test bodies are outside that hunk. The Dream
CLI and reload files have no committed delta in this focused comparison.

GUI135216 is carried after a focused rather than whole-HEAD source review.
From GUI135216 to Group810bdb, SRC/neothd-gui/src/main.rs changes only the
W164 macOS response-feedback containment assertion and a citation test shell
fixture from grep to POSIX case; no Dream opt-in, receipt/readback, wizard,
or Slint behavior is changed. None of the reviewed GUI paths changes from
Group810bdb to the current committed source. Unrelated dirty worktree source is
excluded from this comparison.

The machine BSOD hold prohibited local executable validation. The exact
identity-to-source-to-receipt record is
docs/verification/gold-wave410-p223-acceptance.json.
