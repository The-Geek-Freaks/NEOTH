# W265 — Per-turn silence watchdog accepted

GOLD-LF-P1-21 is accepted on 2026-09-23 from 13 source-bound native terminals
in Group44185c (run35808222289) and the individually passing GUI presentation
terminal in GUI124d99 (run35806202796). Those whole runs retain their unrelated
failures; this is a leaf-specific behavior acceptance, not release qualification.

## Actual pipeline and operator behavior

`run_prepared_chat_turn` constructs one 120-second `TurnSilenceWatchdog`, passes
its progress handle into provider dispatch, and races dispatch plus subsequent
post-reply work against the same deadline. Only nonempty visible/done payload,
`done=true`, or nonempty reasoning delta is a meaningful signal. Polling,
short reads, identity/metadata-only frames and reasoning terminal markers do
not rearm the watchdog. Late signals cannot revive an expired turn.

Cancellation takes priority over expiry; completion/drop disarm the watchdog.
Expiry emits a retry diagnostic and returns typed `TurnSilenceTimeout`. The
daemon GUI runtime maps that error to retryable timeout guidance followed by
Failed, preserving the generation fence and never reporting completion.
An independent review checked these actual production callers and consumers.

## Individually passing native identities

- `cli::chat_turn_watchdog::tests::expires_after_a_full_silence_window_and_closes_the_shared_gate`
- `cli::chat_turn_watchdog::tests::repeated_real_signals_keep_one_inflight_operation_alive_past_120_seconds`
- `cli::chat_turn_watchdog::tests::coalesced_timely_signals_rearm_even_when_the_receiver_has_not_polled_yet`
- `cli::chat_turn_watchdog::tests::late_signal_after_a_full_silence_window_cannot_revive_the_turn`
- `cli::chat_turn_watchdog::tests::user_cancellation_wins_an_expiry_race`
- `cli::chat_turn_watchdog::tests::read_polling_without_a_progress_signal_still_expires`
- `cli::chat_turn_watchdog::tests::already_expired_deadline_beats_a_simultaneously_ready_completion`
- `cli::chat_turn_watchdog::tests::completed_operation_disarms_without_later_cancellation`
- `cli::chat_turn_watchdog::tests::nonterminal_completion_carries_the_same_deadline_into_post_reply_work`
- `cli::chat_turn_watchdog::tests::dropped_unpolled_watchdog_cannot_close_its_turn_later`
- `daemon::audit_rpc::daemon_plain_chat_contract_tests::silence_timeout_error_is_typed_retry_guidance_not_a_success_response`
- `daemon::gui_chat_protocol::tests::silence_timeout_frame_is_typed_and_cannot_be_misreported_as_completion`
- `daemon::audit_rpc::tests::gui_attach_accepts_late_progress_then_typed_silence_timeout`

The GUI terminal is
`chat_stream_phase::daemon_chat_presentation_tests::timeout_guidance_survives_failed_terminal_and_cannot_cross_generation`.

## Source binding and retained limits

`docs/verification/gold-wave265-watchdog-acceptance.json` records all seven
native dependency Git blobs and SHA-256 hashes plus the GUI presentation source.
Root compared their admitted source blobs against `0fb6c307` and verified exact
equality. Native evidence ran on `85c87f57`; GUI evidence ran on `d99d5c6c`.
The evidence is carried forward only for these unchanged behavior boundaries.
The original receipts remain in `work/gold-20260906/wave256-258-native-search-socket/grouped441-85c/ADMISSION.json`
and `work/gold-20260906/wave253-255-import-preview-guardian/gui124-d99/ADMISSION.json`.

The Group441 Unix paused-import failure and GUI124 W153/W164 failures are still
retained and are not reclassified as passing. P1-20 remains open because it has
its own explicit exact-head Linux/macOS/Windows and release-matrix condition.
No local compiler, parser, formatter, test or runtime ran under the BSOD hold.
