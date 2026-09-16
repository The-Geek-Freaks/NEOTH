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
        raise ValueError("custom macOS GUI suite does not contain exactly the five W58 fixtures")

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
