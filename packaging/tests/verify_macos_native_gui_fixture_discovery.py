from __future__ import annotations

import json
from pathlib import Path
import sys


CUSTOM_BINARY_ID = "neothd-gui::neothd-gui-macos-native"
CUSTOM_TESTS = frozenset(
    {
        "w58_gui_callback_runtime_tests::w58_buddy_status_callback_publishes_selected_root_readiness",
        "w58_gui_callback_runtime_tests::w80_buddy_impact_callback_renders_selected_git_receipt",
        "w58_gui_callback_runtime_tests::w73_buddy_start_reaches_real_provider_worker_and_commits_terminal_provenance",
        "w58_gui_callback_runtime_tests::w73_buddy_cancel_joins_real_blocked_provider_without_success_repaint",
        "w58_gui_callback_runtime_tests::w73_queued_late_terminal_bridge_callback_executes_and_revision_gate_rejects_it",
        "w58_gui_callback_runtime_tests::w116_channel_account_retirement_callback_preserves_projection_until_exact_receipt",
        "w58_gui_callback_runtime_tests::w121_channel_pairing_request_callbacks_require_exact_receipts_before_relisting",
        "w58_gui_callback_runtime_tests::w122_channel_account_dm_pairing_callback_preserves_projection_until_exact_receipt",
        "w58_gui_callback_runtime_tests::w126_channel_pairing_approval_callback_keeps_private_input_and_relists_only_after_exact_receipt",
        "w58_gui_callback_runtime_tests::w130_channel_legacy_migration_callback_preserves_legacy_projection_until_exact_receipt",
        "w58_gui_callback_runtime_tests::w138_skill_autonomy_callbacks_require_exact_receipt_and_fresh_readback",
        "w58_gui_callback_runtime_tests::w142_selfimprove_accept_requires_exact_bound_receipt_and_fresh_readback",
        "w58_gui_callback_runtime_tests::w149_buddy_quality_handoff_selects_the_exact_selfimprove_proposal",
        "w58_gui_callback_runtime_tests::w151_ouro_q8_callback_requires_typed_receipt_and_keeps_singleflight",
        "w58_gui_callback_runtime_tests::w153_legacy_child_callbacks_project_only_transient_reasoning",
        "w58_gui_callback_runtime_tests::w153_reasoning_child_controls_are_transient_and_history_excluded",
        "w58_gui_callback_runtime_tests::w155_citation_callbacks_bind_cache_and_live_consent_receipts",
        "w58_gui_callback_runtime_tests::w162_throughput_controls_are_transient_and_provider_done_fenced",
        "w58_gui_callback_runtime_tests::w163_recall_chip_controls_freeze_current_response_and_clear_on_turn_change",
        "w58_gui_callback_runtime_tests::w167_daemon_recall_chip_batch_projects_current_surface_and_fences_terminals",
        "w58_gui_callback_runtime_tests::w168_daemon_throughput_state_projects_main_and_buddy_then_fences_boundaries",
        "w58_gui_callback_runtime_tests::w164_response_feedback_callback_requires_post_done_target_and_verified_readback",
        "w58_gui_callback_runtime_tests::w184_vault_mirror_repair_callback_requires_typed_ack_and_fresh_readback",
        "w58_gui_callback_runtime_tests::w185_local_model_callbacks_require_typed_ack_and_fresh_readback",
        "w58_gui_callback_runtime_tests::w218_buddy_embedding_callbacks_require_exact_config_singleflight_and_fresh_probe",
        "w58_gui_callback_runtime_tests::w219_provider_retry_status_callback_projects_only_safe_rows_and_retains_last_known_good",
    }
)
CONTROLLER_TEST = (
    "coding_controller::tests::gui_reserved_start_reaches_real_provider_worker_"
    "with_prepared_code_map_context"
)
CONTROLLER_OWNERS = frozenset(
    {"neothd-gui::bin/neothd-gui", "neoth::gui_coding_controller"}
)


def verify_fixture_discovery(listing: object) -> None:
    if not isinstance(listing, dict):
        raise ValueError("nextest JSON root is not an object")
    suites = listing.get("rust-suites")
    if not isinstance(suites, dict):
        raise ValueError("nextest JSON does not contain rust-suites")

    custom_suite = suites.get(CUSTOM_BINARY_ID)
    if (
        not isinstance(custom_suite, dict)
        or custom_suite.get("binary-id") != CUSTOM_BINARY_ID
        or set(custom_suite.get("testcases", {})) != CUSTOM_TESTS
    ):
        raise ValueError("custom macOS GUI suite does not contain exactly the required callback fixtures")

    def is_runnable(suite: object, test_name: str) -> bool:
        if not isinstance(suite, dict):
            return False
        testcases = suite.get("testcases")
        if not isinstance(testcases, dict):
            return False
        testcase = testcases.get(test_name)
        return (
            isinstance(testcase, dict)
            and testcase.get("ignored") is False
            and testcase.get("filter-match") == {"status": "matches"}
        )

    for test_name in CUSTOM_TESTS:
        if not is_runnable(custom_suite, test_name):
            raise ValueError(f"custom W58 fixture is not runnable: {test_name}")

    def owners(test_name: str) -> set[str]:
        return {
            binary_id
            for binary_id, suite in suites.items()
            if isinstance(suite, dict) and test_name in suite.get("testcases", {})
        }

    for test_name in CUSTOM_TESTS:
        if owners(test_name) != {CUSTOM_BINARY_ID}:
            raise ValueError(f"unexpected W58 fixture ownership: {test_name}")

    if owners(CONTROLLER_TEST) != CONTROLLER_OWNERS or any(
        not is_runnable(suites.get(binary_id), CONTROLLER_TEST)
        for binary_id in CONTROLLER_OWNERS
    ):
        raise ValueError("ordinary GUI controller fixture ownership changed")


def main(arguments: list[str]) -> int:
    if len(arguments) != 1:
        print("usage: verify_macos_native_gui_fixture_discovery.py <nextest-list.json>", file=sys.stderr)
        return 2
    try:
        with Path(arguments[0]).open(encoding="utf-8") as fixture_list:
            verify_fixture_discovery(json.load(fixture_list))
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"macOS native GUI fixture discovery failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
