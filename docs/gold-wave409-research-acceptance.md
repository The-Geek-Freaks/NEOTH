# W409 — P2-09 autonomous research acceptance

P2-09 is accepted at committed head 8f6ef116. Group810bdb run 35866133454 supplies all required P2-09 terminals as source-bound hosted PASS evidence. This decision does not require a broad all-green Group810 result, an all-OS matrix, GUI acceptance, release packaging, a local model archive, or local executable validation.

## Road criterion and evidence ladder

The canonical Road row requires an operator-governed research-goal lifecycle with bounded planning/execution, budgets, pause/resume/cancel, evidence capture, proposal-first mutation, and audit/rollback surfaces.

The evidence ladder states that the Road-to-Gold cadence must not weaken public-tag evidence. Its accepted P2-24 precedent also requires exact source-bound PASS terminals plus a source-delta review, while retaining unrelated grouped failures. This review applies that same narrow rule to P2-09: admitted source, selection, individual actual terminals, and a relevant committed-head carry check.

## Admitted evidence

Group810bdb admission records:

| Property | Value |
|---|---|
| Hosted run | 35866133454 |
| Source head | bdb50ac2acc4583345b61eb620ae7d08ecac5307 |
| Selected / executed | 810 / 810 |
| Passed / failed | 807 / 3 |
| Source bindings | 163, all matching |
| Matrix and lock | matching |
| Actual terminal ordering | admitted |

The three failed identities are cli::parity_drift::operation_inventory_tracks_live_nested_cli_leaves, cli::memory::tests::physical_redaction_refuses_journal_target_that_is_not_the_bound_leaf, and wal::redact::tests::staged_authenticated_leaf_refuses_matched_structural_frame_byte_identically. None is in the P2-09 required set and none implements the research-goal lifecycle.

## Required actual PASS terminals

The machine-readable receipt lists all 18 identities, their source binding, and their individual terminal proof. Group810's research lifecycle log contains a separate test <identity> ... ok terminal for each:

1. daemon::research_runs::tests::approval_is_revision_bound_and_budget_is_immutable
2. daemon::research_runs::tests::cancel_before_effect_is_terminal
3. daemon::research_runs::tests::checkpoint_survives_pause_and_claimed_resume_without_round_rewind
4. daemon::research_runs::tests::malformed_unknown_future_or_filename_mismatched_store_refuses_without_overwrite
5. daemon::research_runs::tests::missing_home_reads_create_nothing_and_held_lock_refuses_rewrite
6. daemon::research_runs::tests::stale_attempt_cannot_mutate_resumed_run_and_late_control_still_completes
7. daemon::research_runs::tests::provider_call_reservations_persist_across_pause_reopen_and_resume
8. daemon::research_runs::tests::wall_time_accumulates_active_attempts_without_pause_dwell
9. daemon::research_runs::tests::wall_time_settlement_caps_timeout_overshoot_for_terminal_persistence
10. daemon::research_runs::tests::missing_budget_consumption_fields_refuse_without_overwrite
11. tools::deep_research::tests::resumed_checkpoint_skips_planning_search_and_fetch_for_completed_round
12. cli::research::tests::provider_call_cap_rejects_next_call_without_inner_invocation
13. cli::research::tests::research_parser_requires_revision_for_mutations_and_keeps_read_commands
14. cli::research::tests::paused_or_cancelled_terminal_wal_failure_is_reported_without_mutation
15. cli::research::tests::pre_effect_config_setup_failure_persists_failed_without_provider_or_http_effect
16. cli::research::tests::operator_lifecycle_dispatches_create_approve_run_pause_resume_cancel_show_and_list_with_exact_revisions
17. cli::research::tests::successful_lifecycle_dispatches_real_authorized_producer_and_decodes_wal_terminals_without_replay
18. cli::research::tests::interrupted_lifecycle_decodes_started_wal_and_refuses_replay_after_terminal_failure

Together these prove the concrete parent behavior: a revision-gated Draft to Approved to Running lifecycle, immutable round/call/wall-time budgets, durable pause/checkpoint/resume/cancel fencing, proposal-first no-effect setup failure, bounded evidence continuation, and authenticated successful/interrupted WAL terminal custody with no replay.

## Source carry to current head

The admitted source bdb50ac2 and current head 8f6ef116 have identical Git blobs for:

- SRC/neothd/src/cli/research.rs
- SRC/neothd/src/daemon/research_runs.rs
- SRC/neothd/src/tools/deep_research.rs
- SRC/neothd/src/config/mod.rs
- SRC/neothd/src/config/automation.rs
- SRC/neothd/src/wal/writer.rs
- SRC/neothd/src/wal/events.rs

The bdb50ac2..8f6ef116 changes are scoped to cluster outbound delegation, its tests, workflow/roadmap metadata, and source manifests. They do not change the P2-09 lifecycle, budget, control, evidence, proposal-first, audit, rollback, configuration, or WAL terminal code. The admitted evidence therefore carries to the current committed head.

## Decision

The P2-09 parent Road box is closable. There is no remaining P2-09 production gap or missing required terminal. The three retained Group810 failures remain explicit group-level work and do not block this scoped parent decision.

No local compiler, parser, formatter, test, product runtime, model archive, or download ran under the BSOD hold.
