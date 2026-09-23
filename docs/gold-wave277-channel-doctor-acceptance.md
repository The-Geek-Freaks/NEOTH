# W277 — channel Doctor focused acceptance selection

This is the minimum existing-test selection for literal `GOLD-LF-P1-17` closure. It is additive to the already selected actual egress and Doctor-caller tests:

- W262 Discord generated authenticated-WAL egress coverage.
- W268 Signal generated authenticated-WAL egress coverage.
- W271 `cli::doctor::checks::providers::tests::channel_transport_flapping_reads_authenticated_live_wal_and_warns_only_failed_channel`.

Nine cases are newly selected by W277; the equal-account-name case is already selected by W262 and runs only once in the combined lane. W277 adds the missing account-isolation and fail-closed reader cases. It does not add a provider-usage attribution claim: historical usage rows do not carry an authenticated `ChannelRef`.

## Exact tests to add

### Authenticated home-WAL reader isolation and refusal

All five are `#[cfg(test)]` `#[tokio::test]` cases in `SRC/neothd/src/daemon/channel_transport_evidence.rs`; they have no target-OS or feature gate.

1. `daemon::channel_transport_evidence::tests::authenticated_home_wal_reader_isolates_historical_live_a_and_b_without_current_config`
   - Real authenticated home WAL; distinct mapped historical account A/B counters without current `freedom.yaml`.
2. `daemon::channel_transport_evidence::tests::authenticated_home_wal_keeps_marked_slack_and_mapped_telegram_counters_isolated`
   - Current mapped Telegram evidence remains separate from marked legacy-default Slack evidence.
3. `daemon::channel_transport_evidence::tests::authenticated_home_wal_keeps_equal_account_names_isolated_by_channel`
   - Proves the key is full `ChannelRef`, not the shared `default` account-id string, across Telegram, Slack, Discord, and Signal.
4. `daemon::channel_transport_evidence::tests::authenticated_home_wal_reader_rejects_incomplete_later_tail_without_legacy_prefix_counters`
   - Torn later WAL tail fails closed; valid-prefix counters are not returned.
5. `daemon::channel_transport_evidence::tests::authenticated_home_wal_reader_rejects_tampered_later_frame_without_prefix_counters`
   - Tampered later authenticated frame fails closed; valid-prefix counters are not returned.

### Doctor classification boundaries

All five are `#[cfg(test)]` synchronous unit tests in `SRC/neothd/src/cli/doctor/checks/providers.rs`; they have no target-OS or feature gate.

1. `cli::doctor::checks::providers::tests::account_transport_flapping_isolated_per_account_at_threshold`
   - Exactly five completed attempts and the 20% threshold produce an account-specific warning without naming the healthy account.
2. `cli::doctor::checks::providers::tests::account_transport_flapping_passes_when_no_bound_attempts_exist`
   - No evidence is an explicit Pass, not a fabricated failure rate.
3. `cli::doctor::checks::providers::tests::account_transport_flapping_unknown_evidence_is_inconclusive_without_rate`
   - Armed-but-unknown evidence is Warn/inconclusive and never converted into a percentage.
4. `cli::doctor::checks::providers::tests::account_transport_flapping_renders_unsettled_evidence_without_rate_when_uncompleted`
   - Unsettled live intent is Warn/inconclusive and never treated as a completed attempt.
5. `cli::doctor::checks::providers::tests::account_transport_flapping_reader_error_is_fixed_unavailable_failure`
   - Reader failure is a fixed unavailable failure without leaking the underlying error.

## Production/dependency binding to retain in the lane

The selected tests exercise the existing production chain; no test-only replacement is needed:

- `SRC/neothd/src/daemon/channel_transport_evidence.rs` — authenticated WAL scan, closed grammar, `ChannelRef` aggregation and counter refusal.
- `SRC/neothd/src/channels/send_gate.rs` — sealed live intent/result emission used by W262, W268 and W271.
- `SRC/neothd/src/channels/discord.rs` and `SRC/neothd/src/channels/signal.rs` — real default-account egress paths covered by W262/W268.
- `SRC/neothd/src/cli/doctor/checks/providers.rs` — transport classifier, threshold, registered check and runbook.
- `SRC/neothd/src/cli/doctor.rs` — providers check domain included by `run_all_checks`.
- `SRC/neothd/src/cli/serve_tasks.rs` — legacy-default provenance and mapped account binding source.
- `SRC/neothd/src/wal/writer.rs` and the authenticated WAL reader dependencies — writer completion must be awaited by the async WAL tests before inspection.

Acceptance must record the exact commit, each individual terminal, and the W262/W268/W271 evidence. This selection proves adapter-transport health only: an accepted terminal is neither recipient delivery nor a read receipt.
