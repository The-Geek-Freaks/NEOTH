# W426 - P1-20 Sidebar last-message preview acceptance

GOLD-LF-P1-20 is scoped accepted on the exact sidebar-preview evidence ladder: four canonical transcript-store terminals and eight GUI behavior terminals. This covers the Road requirement to show each session's canonical latest visible message and to update it on send, stream completion and reload, including redaction, empty rows, truncation, Unicode and session-switch safety. It is not a whole-HEAD, all-OS, release, or package acceptance claim.

## Source-bound terminals

Group841bc9 run35871794576 ran on bc9db76c4ff72bfff9fa3674f20d904ead12fc76. It selected and executed 841 native fixtures: 834 passed and seven unrelated cluster fixtures failed. Its admission records 169 matching source bindings, a matching matrix and lock, and ordered actual terminals. The four P1-20 native cases below each have successful exact discovery and run terminals in the group log.

- memory::transcript_store::tests::lf_p1_20_readonly_session_egress_is_ordered_and_resanitizes_legacy_agent_rows — PASS in Group841bc9 run35871794576.
- memory::transcript_store::tests::lf_p1_20_latest_turns_keep_sessions_isolated_and_omit_legacy_missing_cards — PASS in Group841bc9 run35871794576.
- memory::transcript_store::tests::lf_p1_20_latest_turns_skip_empty_and_control_only_tail_rows — PASS in Group841bc9 run35871794576.
- memory::transcript_store::tests::lf_p1_20_readonly_legacy_database_without_raw_turns_is_empty — PASS in Group841bc9 run35871794576.

GUI1438f6 run35867782202 ran on 8f6ef1166440037ceedc6a13c8a0f78596a8218b and is complete: 143 selected, executed and passed, with no failed identity. Its 23 source/input bindings all match Git and ordered selection plus actual terminals was verified. The eight P1-20 GUI cases are successful individual fixture receipts:

- panel_logic::tests::lf_p1_20_preview_redacts_normalizes_and_truncates_graphemes_once — PASS in GUI1438f6 run35867782202 (test-106-execution.txt).
- panel_logic::tests::lf_p1_20_send_completion_delete_recomputes_to_previous_visible_message — PASS in GUI1438f6 run35867782202 (test-107-execution.txt).
- panel_logic::tests::lf_p1_20_reload_and_session_switch_keep_a_b_isolated — PASS in GUI1438f6 run35867782202 (test-108-execution.txt).
- panel_logic::tests::lf_p1_20_session_label_sanitizes_legacy_titles_and_controls — PASS in GUI1438f6 run35867782202 (test-109-execution.txt).
- panel_logic::tests::lf_p1_20_session_history_propagates_corrupt_database_errors — PASS in GUI1438f6 run35867782202 (test-110-execution.txt).
- chat_subprocess_tests::lf_p1_20_send_before_channel_probe_hydrates_live_preview — PASS in GUI1438f6 run35867782202 (test-111-execution.txt).
- chat_subprocess_tests::lf_p1_20_session_load_generation_rejects_a_after_b_and_return_to_live — PASS in GUI1438f6 run35867782202 (test-112-execution.txt).
- chat_subprocess_tests::lf_p1_20_chat_sidebar_session_selection_is_readonly_and_fully_wired — PASS in GUI1438f6 run35867782202 (test-113-execution.txt).

## Behavior admitted

The native cases prove read-only transcript access, ordered and re-sanitized legacy-agent rows, session isolation, omission of legacy cards without visible turns, empty/control-only tail suppression, and legacy databases without raw_turns. GUI cases prove redaction and control removal, whitespace normalization, a 64-grapheme Unicode bound, completion/delete recomputation, legacy-label sanitization, corrupt-store error propagation, reload isolation, A-to-B/A-to-live generation fencing, early-send live preview hydration, and the read-only Sidebar/Slint selection contract.

## Focused source carry to 010d535c

The relevant evidence paths are transcript_store.rs, panel_logic.rs, main.rs, ui/main.slint, and ui/chat.slint. Git comparison from both Group841bc9 and GUI1438f6 source heads through 010d535c84b3966270877ae9bb808b51c8ea35e5 reports no committed delta for any of those paths. Unrelated worktree changes are excluded. The exact identity-to-source-to-receipt record is docs/verification/gold-wave426-p120-acceptance.json.

No local executable validation ran under the BSOD hold.
