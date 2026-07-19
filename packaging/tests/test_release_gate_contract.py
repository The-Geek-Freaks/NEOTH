from __future__ import annotations

from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import re
import unittest


SCRIPT = Path(__file__).parents[1] / "release_gate_contract.py"
CI_WORKFLOW = Path(__file__).parents[2] / ".github" / "workflows" / "ci.yml"
CI_TEXT = CI_WORKFLOW.read_text(encoding="utf-8")
SPEC = importlib.util.spec_from_file_location("release_gate_contract", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)

HEAD = "a" * 40
NOW = datetime(2026, 7, 15, 12, 0, tzinfo=timezone.utc)


def workflow_run(
    run_id: int,
    started_at: str,
    *,
    status: str = "completed",
    conclusion: str | None = "success",
    event: str = "push",
    head_sha: str = HEAD,
    run_attempt: int = 1,
) -> dict[str, object]:
    return {
        "id": run_id,
        "head_sha": head_sha,
        "event": event,
        "status": status,
        "conclusion": conclusion,
        "created_at": started_at,
        "run_started_at": started_at,
        "updated_at": started_at,
        "run_attempt": run_attempt,
    }


def select(payload: object) -> dict[str, object]:
    return gate.select_latest_successful_run(
        payload,
        head_sha=HEAD,
        workflow_name="Security",
        max_age=timedelta(hours=24),
        now=NOW,
    )


class ReleaseGateContractTests(unittest.TestCase):
    def test_gold_ci_keeps_lost_feature_integrity_gate_wired(self) -> None:
        jobs_text = CI_TEXT.split("\njobs:\n", maxsplit=1)
        self.assertEqual(len(jobs_text), 2, "ci.yml must contain one jobs mapping")
        jobs = dict(
            re.findall(
                r"(?ms)^  ([A-Za-z0-9_-]+):\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
                jobs_text[1],
            )
        )
        self.assertIn("license-notices", jobs)
        self.assertIn("gold-ci", jobs)
        self.assertEqual(
            jobs["license-notices"].count(
                "python3 scripts/test_lost_feature_integrity.py"
            ),
            1,
            "required license-notices job must run the lost-feature integrity contract exactly once",
        )
        self.assertRegex(
            jobs["gold-ci"],
            r"(?m)^\s{6}- license-notices\s*$",
            "Gold CI must depend on the job that runs lost-feature integrity",
        )

    def test_newest_run_is_selected_across_events_and_pages(self) -> None:
        payload = [
            {
                "workflow_runs": [
                    workflow_run(10, "2026-07-15T08:00:00Z", event="push"),
                    workflow_run(
                        99,
                        "2026-07-15T11:30:00Z",
                        head_sha="b" * 40,
                        event="workflow_dispatch",
                    ),
                ]
            },
            {
                "workflow_runs": [
                    workflow_run(11, "2026-07-15T10:00:00Z", event="schedule")
                ]
            },
        ]

        selected = select(payload)

        self.assertEqual(selected["id"], 11)
        self.assertEqual(selected["event"], "schedule")

    def test_newer_failed_run_blocks_older_success(self) -> None:
        payload = {
            "workflow_runs": [
                workflow_run(20, "2026-07-15T09:00:00Z"),
                workflow_run(
                    21,
                    "2026-07-15T11:00:00Z",
                    event="schedule",
                    conclusion="failure",
                ),
            ]
        }

        with self.assertRaisesRegex(
            gate.ReleaseGateError,
            "run 21 .*concluded 'failure'.*Older green runs are ignored",
        ):
            select(payload)

    def test_newer_active_run_blocks_older_success(self) -> None:
        payload = {
            "workflow_runs": [
                workflow_run(30, "2026-07-15T09:00:00Z"),
                workflow_run(
                    31,
                    "2026-07-15T11:30:00Z",
                    event="workflow_dispatch",
                    status="in_progress",
                    conclusion=None,
                ),
            ]
        }

        with self.assertRaisesRegex(
            gate.ReleaseGateError,
            "run 31 .*not completed.*Older green runs are ignored",
        ):
            select(payload)

    def test_success_older_than_24_hours_is_rejected_with_remediation(self) -> None:
        payload = {
            "workflow_runs": [workflow_run(40, "2026-07-14T11:59:59Z")]
        }

        with self.assertRaisesRegex(
            gate.ReleaseGateError,
            "older than 24 hours.*Run or re-run Security on main",
        ):
            select(payload)

    def test_latest_attempt_breaks_same_start_time_tie(self) -> None:
        payload = {
            "workflow_runs": [
                workflow_run(50, "2026-07-15T11:00:00Z", run_attempt=1),
                workflow_run(50, "2026-07-15T11:00:00Z", run_attempt=2),
            ]
        }

        selected = select(payload)

        self.assertEqual(selected["run_attempt"], 2)

    def test_old_high_attempt_does_not_outrank_new_run(self) -> None:
        payload = {
            "workflow_runs": [
                workflow_run(
                    70,
                    "2026-07-15T09:00:00Z",
                    run_attempt=99,
                    conclusion="failure",
                ),
                workflow_run(71, "2026-07-15T11:00:00Z", run_attempt=1),
            ]
        }

        selected = select(payload)

        self.assertEqual(selected["id"], 71)

    def test_no_exact_head_run_fails_closed(self) -> None:
        payload = {
            "workflow_runs": [
                workflow_run(60, "2026-07-15T11:00:00Z", head_sha="b" * 40)
            ]
        }

        with self.assertRaisesRegex(
            gate.ReleaseGateError,
            "no Security run exists for exact SHA",
        ):
            select(payload)


if __name__ == "__main__":
    unittest.main()
