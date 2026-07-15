#!/usr/bin/env python3
"""Fail-closed selection of the freshest exact-head workflow verdict."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
from typing import Iterable


class ReleaseGateError(ValueError):
    pass


def _parse_time(value: object, *, field: str, run_id: object) -> datetime:
    if not isinstance(value, str) or not value:
        raise ReleaseGateError(f"workflow run {run_id!r} has no valid {field}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ReleaseGateError(
            f"workflow run {run_id!r} has invalid {field}: {value!r}"
        ) from error
    if parsed.tzinfo is None:
        raise ReleaseGateError(
            f"workflow run {run_id!r} has timezone-free {field}: {value!r}"
        )
    return parsed.astimezone(timezone.utc)


def _workflow_runs(payload: object) -> list[dict[str, object]]:
    pages = payload if isinstance(payload, list) else [payload]
    if not pages:
        return []
    runs: list[dict[str, object]] = []
    for page in pages:
        if not isinstance(page, dict) or not isinstance(page.get("workflow_runs"), list):
            raise ReleaseGateError(
                "workflow-runs API response is not an object with workflow_runs"
            )
        for run in page["workflow_runs"]:
            if not isinstance(run, dict):
                raise ReleaseGateError("workflow-runs API returned a non-object run")
            runs.append(run)
    return runs


def _chronology_key(run: dict[str, object]) -> tuple[datetime, datetime, int, int]:
    run_id = run.get("id")
    started = _parse_time(
        run.get("run_started_at") or run.get("created_at"),
        field="run_started_at/created_at",
        run_id=run_id,
    )
    updated = _parse_time(
        run.get("updated_at") or run.get("run_started_at") or run.get("created_at"),
        field="updated_at/run_started_at/created_at",
        run_id=run_id,
    )
    attempt = run.get("run_attempt", 0)
    if not isinstance(attempt, int) or attempt < 0:
        raise ReleaseGateError(f"workflow run {run_id!r} has invalid run_attempt")
    if not isinstance(run_id, int) or run_id <= 0:
        raise ReleaseGateError(f"workflow run has invalid id: {run_id!r}")
    return started, updated, attempt, run_id


def _remediation(workflow_name: str, head_sha: str) -> str:
    return (
        f"Run or re-run {workflow_name} on main for exact SHA {head_sha}, wait "
        "for the newest run to complete successfully, then re-run the release "
        "workflow (or recreate the release tag)."
    )


def select_latest_successful_run(
    payload: object,
    *,
    head_sha: str,
    workflow_name: str,
    max_age: timedelta,
    now: datetime | None = None,
) -> dict[str, object]:
    if max_age <= timedelta(0):
        raise ReleaseGateError("maximum workflow-run age must be positive")
    normalized_head = head_sha.lower()
    matching = [
        run
        for run in _workflow_runs(payload)
        if isinstance(run.get("head_sha"), str)
        and str(run["head_sha"]).lower() == normalized_head
    ]
    if not matching:
        raise ReleaseGateError(
            f"no {workflow_name} run exists for exact SHA {head_sha}. "
            + _remediation(workflow_name, head_sha)
        )

    # Select chronology first. Filtering by status or conclusion before this
    # point would let an older green run hide a newer pending or failed run.
    latest = max(matching, key=_chronology_key)
    run_id = latest["id"]
    event = latest.get("event", "unknown")
    status = latest.get("status")
    conclusion = latest.get("conclusion")
    if status != "completed":
        raise ReleaseGateError(
            f"newest {workflow_name} run {run_id} ({event}) for exact SHA "
            f"{head_sha} is {status!r}, not completed. Older green runs are "
            f"ignored. {_remediation(workflow_name, head_sha)}"
        )
    if conclusion != "success":
        raise ReleaseGateError(
            f"newest {workflow_name} run {run_id} ({event}) for exact SHA "
            f"{head_sha} concluded {conclusion!r}. Older green runs are ignored. "
            + _remediation(workflow_name, head_sha)
        )

    completed = _parse_time(
        latest.get("updated_at")
        or latest.get("run_started_at")
        or latest.get("created_at"),
        field="updated_at/run_started_at/created_at",
        run_id=run_id,
    )
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ReleaseGateError("current time must include a timezone")
    age = current.astimezone(timezone.utc) - completed
    if age < timedelta(minutes=-5):
        raise ReleaseGateError(
            f"newest {workflow_name} run {run_id} has a completion time in the "
            "future; refusing an unverifiable freshness result. "
            + _remediation(workflow_name, head_sha)
        )
    if age > max_age:
        hours = max_age.total_seconds() / 3600
        raise ReleaseGateError(
            f"newest successful {workflow_name} run {run_id} for exact SHA "
            f"{head_sha} is older than {hours:g} hours. "
            + _remediation(workflow_name, head_sha)
        )
    return latest


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    subcommands = result.add_subparsers(dest="command", required=True)
    select = subcommands.add_parser("select-latest")
    select.add_argument("--input", required=True, type=Path)
    select.add_argument("--head-sha", required=True)
    select.add_argument("--workflow-name", required=True)
    select.add_argument("--max-age-hours", required=True, type=float)
    return result


def main(argv: Iterable[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command != "select-latest":  # pragma: no cover - argparse owns it
            raise ReleaseGateError(f"unsupported command: {args.command}")
        payload = json.loads(args.input.read_text(encoding="utf-8"))
        selected = select_latest_successful_run(
            payload,
            head_sha=args.head_sha,
            workflow_name=args.workflow_name,
            max_age=timedelta(hours=args.max_age_hours),
        )
        print(selected["id"])
    except (ReleaseGateError, OSError, json.JSONDecodeError) as error:
        print(f"::error::release gate failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
