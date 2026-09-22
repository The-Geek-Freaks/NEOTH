# W190 research lifecycle verification

W190 adds the operator-owned `neoth research` lifecycle: `create`, `show`,
`list`, `approve`, `run`, `pause`, `resume`, and `cancel`. Mutating actions
require the record revision; `create`, `show`, and `list` remain ordinary CLI
read/create surfaces.

The run record snapshots its execution limits before approval: deep-research
round/result/page limits, the configured per-provider-call token setting (zero retains its explicit
unlimited meaning), a finite provider-call count, and
wall-time. The executor restores its private query/evidence checkpoint on
resume and skips every completed round.

Pause is cooperative. A request during a round lets that bounded round finish,
stores the checkpoint, and then enters `Paused`; resume starts with the next
query. Cancel is observed before the next provider/search/fetch/synthesis
effect. If a request arrives after synthesis, the known report is persisted as
`Completed` with a `control_observed_after_final_effect` audit row, avoiding a
replayed synthesis call.

The source tests added for this batch are:

- `provider_call_cap_rejects_next_call_without_inner_invocation`
- `research_parser_requires_revision_for_mutations_and_keeps_read_commands`
- `pre_effect_config_setup_failure_persists_failed_without_provider_or_http_effect`
- `resumed_checkpoint_skips_planning_search_and_fetch_for_completed_round`
- `daemon::research_runs::tests::approval_is_revision_bound_and_budget_is_immutable`
- `daemon::research_runs::tests::cancel_before_effect_is_terminal`
- `daemon::research_runs::tests::checkpoint_survives_pause_and_claimed_resume_without_round_rewind`
- `daemon::research_runs::tests::malformed_unknown_future_or_filename_mismatched_store_refuses_without_overwrite`
- `daemon::research_runs::tests::missing_home_reads_create_nothing_and_held_lock_refuses_rewrite`
- `daemon::research_runs::tests::stale_attempt_cannot_mutate_resumed_run_and_late_control_still_completes`

No local Cargo, rustfmt, parser, or test command was run because the active
BSOD hold permits only source edits and static text checks. Hosted execution is
the remaining verification boundary.
