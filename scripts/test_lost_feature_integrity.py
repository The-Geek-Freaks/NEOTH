#!/usr/bin/env python3
"""Fail closed when the v1.0 lost-feature inventory and trackers drift."""

from __future__ import annotations

from collections import Counter
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
from typing import Any
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
INVENTORY_PATH = REPO_ROOT / "PLAN" / "lost_features_1_0_inventory.json"
SOURCE_PATH = REPO_ROOT / "PLAN" / "LOST_FEATURES_1_0_RECOVERY.md"
ROAD_PATH = REPO_ROOT / "PLAN" / "ROAD_TO_1_0_GOLD.md"
GUI_PLAN_PATH = REPO_ROOT / "PLAN" / "GUI_TOP_TIER_PLAN.md"
PROGRESS_PATH = REPO_ROOT / "PLAN" / "PROGRESS_v1_0.md"

EXPECTED_DISPOSITIONS = {
    "CONFIRMED_LOST": 52,
    "ALREADY_BUILT": 8,
    "ALREADY_TRACKED": 11,
    "REJECTED_STANDS": 3,
    "DUPLICATE": 5,
}
EXPECTED_PRIORITIES = {"P1": 23, "P2": 29}
EXPECTED_PROVENANCE = {
    "kind": "claude_workflow_journal",
    "workflow_id": "wf_bfbcf7a3-158",
    "journal": "subagents/workflows/wf_bfbcf7a3-158/journal.jsonl",
    "source_commit": "69234ed3",
    "candidate_order": "journal result encounter order",
}
EXPECTED_IDENTITY_SHA256 = "f9871f4eb906868257e5cfae1b3d15a0bc3fffb8b5cfaf42dddd755a107b2915"
EXPECTED_ROAD_MAPPING_SHA256 = "431f8114e8799aa328e176eb664f157f7495a06f38df01bb8ad7333ced9e80d6"
COMMON_CANDIDATE_FIELDS = {"id", "name", "source", "disposition"}
DISPOSITION_FIELDS = {
    "CONFIRMED_LOST": {"priority", "road_id"},
    "ALREADY_BUILT": {"resolution_ref"},
    "ALREADY_TRACKED": {"resolution_ref", "release_gate"},
    "REJECTED_STANDS": {"resolution_ref"},
    "DUPLICATE": {"duplicate_of", "duplicate_kind", "preserved_scope"},
}
TRACKED_RELEASE_GATES = {
    "LF-CAND-032": "GOLD-R4-13",
    "LF-CAND-048": "GOLD-R4-05",
    "LF-CAND-049": "GOLD-R4-05",
    "LF-CAND-069": "GOLD-R4-05",
    "LF-CAND-070": "GOLD-R4-05",
    "LF-CAND-071": "GOLD-R4-05",
    "LF-CAND-072": "GOLD-R4-05",
    "LF-CAND-075": "GOLD-R4-05",
    "LF-CAND-077": "GOLD-R4-05",
    "LF-CAND-078": "GOLD-R4-05",
    "LF-CAND-079": "GOLD-ADAPT-HR-06",
}
GUI_TRACKED_ANCHORS = {
    "LF-CAND-048": ("H22", "H22"),
    "LF-CAND-049": ("D1-residual", "D1"),
    "LF-CAND-069": ("H17", "H17"),
    "LF-CAND-070": ("H20", "H20"),
    "LF-CAND-071": ("H22", "H22"),
    "LF-CAND-072": ("I15", "I15"),
    "LF-CAND-075": ("H15", "H15"),
    "LF-CAND-077": ("H6", "H6"),
    "LF-CAND-078": ("H11", "H11"),
}
EVIDENCE_PATH_RE = re.compile(
    r"\b(?:PLAN/[A-Za-z0-9_./-]+\.md|SRC/[A-Za-z0-9_./-]+\.(?:rs|yaml))"
    r"(?![A-Za-z0-9_.-])"
)


class ContractError(ValueError):
    """The inventory cannot prove its release-tracker contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def expected_candidate_ids() -> list[str]:
    return [f"LF-CAND-{number:03d}" for number in range(1, 80)]


def expected_road_ids(priority: str) -> list[str]:
    return [
        f"GOLD-LF-{priority}-{number:02d}"
        for number in range(1, EXPECTED_PRIORITIES[priority] + 1)
    ]


def normalized(text: str) -> str:
    return " ".join(text.split())


def canonical_json_sha256(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def blockquote_field(document: str, label: str) -> str:
    lines = document.splitlines()
    marker = f"> **{label}:**"
    for index, line in enumerate(lines):
        if not line.startswith(marker):
            continue
        collected = [line.removeprefix("> ")]
        for continuation in lines[index + 1 :]:
            if continuation.strip() == ">" or not continuation.startswith(">"):
                break
            if re.match(r"^>\s+\*\*[^*]+:\*\*", continuation):
                break
            collected.append(continuation.removeprefix("> "))
        return normalized("\n".join(collected))
    raise ContractError(f"source is missing the {label!r} blockquote field")


def recovery_section(document: str, priority: str) -> tuple[str, str]:
    match = re.search(
        rf"(?m)^## {re.escape(priority)}\b(?P<heading>[^\r\n]*)(?:\r?\n)(?P<body>.*?)(?=^##\s|\Z)",
        document,
        flags=re.DOTALL,
    )
    if match is None:
        raise ContractError(f"source is missing the {priority} recovery section")
    return f"## {priority}{match.group('heading')}", match.group("body")


def source_recovery_ids(document: str, priority: str) -> list[str]:
    _, body = recovery_section(document, priority)
    bullets = re.findall(r"(?ms)^-\s+(.*?)(?=^-\s+|\Z)", body)
    ids: list[str] = []
    for position, bullet in enumerate(bullets, start=1):
        found = re.findall(r"\bGOLD-LF-P[12]-\d{2}\b", bullet)
        require(
            len(found) == 1,
            f"source {priority} row {position} must expose exactly one GOLD-LF ID; "
            f"found {found!r}",
        )
        ids.append(found[0])
    return ids


def source_archive_dispositions(document: str) -> dict[str, str]:
    section = re.search(
        r"(?ms)^## Vom Verify gekillt\b.*?(?=^##\s|\Z)",
        document,
    )
    if section is None:
        raise ContractError("source is missing the 'Vom Verify gekillt' archive")
    rows = re.findall(
        r"(?m)^-\s+\*\*(LF-CAND-\d{3})\s+—\s+.*?\*\*\s+—\s+([A-Z_]+)\b",
        section.group(0),
    )
    require(
        len(rows) == 27,
        f"source killed archive must contain exactly 27 top-level candidate rows; got {len(rows)}",
    )
    archive = dict(rows)
    require(
        len(archive) == len(rows),
        "source killed archive candidate IDs must be unique",
    )
    return archive


def road_checkbox_ids(document: str) -> tuple[dict[str, list[str]], list[str]]:
    matches = re.findall(
        r"(?m)^\s*-\s+\[([ xX])\]\s+\*\*(GOLD-LF-P([12])-\d{2})\b",
        document,
    )
    by_priority = {"P1": [], "P2": []}
    marks: list[str] = []
    for mark, road_id, tier in matches:
        by_priority[f"P{tier}"].append(road_id)
        marks.append(mark)
    return by_priority, marks


def ws_lf_section(document: str) -> str:
    match = re.search(r"(?ms)^## WS-LF\b.*?(?=^##\s|\Z)", document)
    if match is None:
        raise ContractError("ROAD is missing the WS-LF workstream section")
    return match.group(0)


def ws_lf_task_counts(document: str) -> tuple[int, int, int]:
    tasks = re.findall(
        r"(?m)^\s*-\s+\[([^\]])\]\s+\*\*(GOLD-LF-[A-Z0-9-]+)\b",
        ws_lf_section(document),
    )
    require(len(tasks) == 118, f"WS-LF must contain exactly 118 task checkboxes; got {len(tasks)}")
    task_ids = [task_id for _, task_id in tasks]
    require(
        len(set(task_ids)) == 118,
        "WS-LF task checkbox IDs must be unique across all 118 children",
    )
    invalid_marks = sorted({mark for mark, _ in tasks if mark not in {" ", "x", "X"}})
    require(
        not invalid_marks,
        f"WS-LF tasks may only be open or done, not partial/unknown: {invalid_marks!r}",
    )
    done = sum(mark.lower() == "x" for mark, _ in tasks)
    return len(tasks), len(tasks) - done, done


def validate_inventory(inventory: dict[str, Any]) -> dict[str, dict[str, Any]]:
    require(inventory.get("schema_version") == 1, "inventory schema_version must be 1")
    require(
        inventory.get("inventory_id") == "lost-features-1.0-recovery",
        "inventory_id must bind the lost-features-1.0-recovery ledger",
    )
    require(
        inventory.get("provenance") == EXPECTED_PROVENANCE,
        "inventory provenance must remain pinned to workflow wf_bfbcf7a3-158, "
        "source commit 69234ed3, and journal encounter order",
    )
    expected_counts = inventory.get("expected_counts")
    require(isinstance(expected_counts, dict), "inventory expected_counts must be an object")
    require(expected_counts.get("total") == 79, "expected_counts.total must be exactly 79")
    require(
        expected_counts.get("by_disposition") == EXPECTED_DISPOSITIONS,
        "expected_counts.by_disposition must be exactly 52/8/11/3/5",
    )
    require(
        expected_counts.get("confirmed_lost_by_priority") == EXPECTED_PRIORITIES,
        "expected_counts.confirmed_lost_by_priority must be exactly P1=23/P2=29",
    )

    candidates = inventory.get("candidates")
    require(isinstance(candidates, list), "inventory candidates must be an array")
    observed_ids = [candidate.get("id") for candidate in candidates if isinstance(candidate, dict)]
    require(
        len(observed_ids) == len(candidates),
        "every inventory candidate must be an object with an id",
    )
    require(
        observed_ids == expected_candidate_ids(),
        "candidate IDs must be unique, ordered, and sequential LF-CAND-001..LF-CAND-079",
    )

    by_id: dict[str, dict[str, Any]] = {}
    for candidate in candidates:
        candidate_id = candidate["id"]
        disposition = candidate.get("disposition")
        require(
            disposition in EXPECTED_DISPOSITIONS,
            f"{candidate_id} has unknown disposition {disposition!r}",
        )
        required_fields = COMMON_CANDIDATE_FIELDS | DISPOSITION_FIELDS[disposition]
        missing = required_fields - candidate.keys()
        unexpected = candidate.keys() - required_fields
        require(not missing, f"{candidate_id} is missing fields {sorted(missing)!r}")
        require(not unexpected, f"{candidate_id} has unexpected fields {sorted(unexpected)!r}")
        for field in required_fields:
            require(
                isinstance(candidate[field], str) and candidate[field].strip(),
                f"{candidate_id}.{field} must be a non-empty string",
            )
        if disposition != "CONFIRMED_LOST":
            require(
                "road_id" not in candidate,
                f"{candidate_id} is {disposition} and must not carry road_id",
            )
            require(
                "priority" not in candidate,
                f"{candidate_id} is {disposition} and must not carry priority",
            )
        if disposition == "DUPLICATE":
            require(
                candidate["duplicate_kind"] == "semantic_merge",
                f"{candidate_id}.duplicate_kind must explicitly be semantic_merge",
            )
        if disposition in {"ALREADY_BUILT", "REJECTED_STANDS"}:
            evidence_paths = EVIDENCE_PATH_RE.findall(candidate["resolution_ref"])
            require(
                bool(evidence_paths),
                f"{candidate_id}.resolution_ref must contain a PLAN .md or SRC .rs/.yaml path",
            )
            for relative in evidence_paths:
                relative_path = Path(relative)
                require(
                    ".." not in relative_path.parts,
                    f"{candidate_id} evidence path must not traverse outside the repo: {relative}",
                )
                require(
                    (REPO_ROOT / relative_path).is_file(),
                    f"{candidate_id} evidence path does not exist: {relative}",
                )
        by_id[candidate_id] = candidate

    identity = [
        (candidate["id"], candidate["name"], candidate["source"])
        for candidate in candidates
    ]
    require(
        canonical_json_sha256(identity) == EXPECTED_IDENTITY_SHA256,
        "ordered candidate id/name/source identity drifted from the pinned journal",
    )

    actual_dispositions = Counter(candidate["disposition"] for candidate in candidates)
    require(
        dict(actual_dispositions) == EXPECTED_DISPOSITIONS,
        f"disposition counts must be 52/8/11/3/5; got {dict(actual_dispositions)!r}",
    )
    actual_priorities = Counter(
        candidate["priority"]
        for candidate in candidates
        if candidate["disposition"] == "CONFIRMED_LOST"
    )
    require(
        dict(actual_priorities) == EXPECTED_PRIORITIES,
        f"confirmed lost priority counts must be P1=23/P2=29; got {dict(actual_priorities)!r}",
    )

    for priority in EXPECTED_PRIORITIES:
        observed_road_ids = [
            candidate["road_id"]
            for candidate in candidates
            if candidate["disposition"] == "CONFIRMED_LOST"
            and candidate["priority"] == priority
        ]
        expected = expected_road_ids(priority)
        require(
            len(observed_road_ids) == len(set(observed_road_ids)),
            f"inventory {priority} road_id values must be unique",
        )
        require(
            set(observed_road_ids) == set(expected),
            f"inventory {priority} road_id range must be complete: expected {expected!r}, "
            f"got {sorted(observed_road_ids)!r}",
        )
        for candidate in candidates:
            if candidate.get("disposition") != "CONFIRMED_LOST":
                continue
            if candidate.get("priority") == priority:
                require(
                    candidate["road_id"].startswith(f"GOLD-LF-{priority}-"),
                    f"{candidate['id']} crosses tiers: {priority} cannot map to "
                    f"{candidate['road_id']}",
                )

    road_mapping = sorted(
        (candidate["id"], candidate["road_id"])
        for candidate in candidates
        if candidate["disposition"] == "CONFIRMED_LOST"
    )
    require(
        canonical_json_sha256(road_mapping) == EXPECTED_ROAD_MAPPING_SHA256,
        "candidate-to-ROAD mapping drifted from the reviewed recovery mapping",
    )

    duplicate_ids = {
        candidate["id"]
        for candidate in candidates
        if candidate["disposition"] == "DUPLICATE"
    }
    for duplicate_id in duplicate_ids:
        target_id = by_id[duplicate_id]["duplicate_of"]
        require(target_id in by_id, f"{duplicate_id} targets missing candidate {target_id}")
        require(target_id != duplicate_id, f"{duplicate_id} must not duplicate itself")
        seen = {duplicate_id}
        cursor = target_id
        while by_id[cursor]["disposition"] == "DUPLICATE":
            if cursor in seen:
                raise ContractError(
                    f"duplicate cycle detected from {duplicate_id} through {cursor}"
                )
            seen.add(cursor)
            cursor = by_id[cursor]["duplicate_of"]
            require(
                cursor in by_id,
                f"duplicate chain from {duplicate_id} targets missing {cursor}",
            )
        require(
            target_id not in duplicate_ids,
            f"{duplicate_id} forms a duplicate chain via {target_id}; target canonical directly",
        )
        require(
            by_id[target_id]["disposition"] == "CONFIRMED_LOST",
            f"{duplicate_id} must target a canonical CONFIRMED_LOST candidate, got "
            f"{by_id[target_id]['disposition']}",
        )

    return by_id


def validate_source(source: str) -> dict[str, list[str]]:
    counter = blockquote_field(source, "Zähler")
    require(
        not re.search(
            r"(?:~|\bca\.?\b|\bcirca\b|\bungefähr\b|\babout\b|\bapproximately\b)",
            counter,
            re.IGNORECASE,
        ),
        "source Zähler must use exact counts, never approximate counts",
    )
    require(
        re.search(
            r"79\s+Kandidaten\s*=\s*52\s+CONFIRMED_LOST\s*\+\s*8\s+ALREADY_BUILT\s*\+\s*"
            r"11\s+ALREADY_TRACKED\s*\+\s*3\s+REJECTED_STANDS\s*\+\s*5\s+DUPLICATE",
            counter,
            re.IGNORECASE,
        )
        is not None,
        "source Zähler must state exact arithmetic: 79 = 52 + 8 + 11 + 3 + 5",
    )
    require(
        re.search(r"23\s+P1\s*\+\s*29\s+P2", counter, re.IGNORECASE) is not None,
        "source Zähler must state the exact 23 P1 + 29 P2 split",
    )

    tracking = blockquote_field(source, "Tracking-Regel")
    require(
        "ROAD_TO_1_0_GOLD.md" in tracking,
        "source Tracking-Regel must name ROAD_TO_1_0_GOLD.md",
    )
    require(
        re.search(r"(?:alle\s+52|all\s+52)", tracking, re.IGNORECASE) is not None,
        "source Tracking-Regel must bind all 52 confirmed losses to ROAD",
    )
    require(
        re.search(r"(?:autoritative|authoritative|kanonisch|canonical)", tracking, re.IGNORECASE)
        is not None,
        "source Tracking-Regel must declare ROAD the canonical live tracker",
    )
    if "GUI_TOP_TIER_PLAN.md" in tracking:
        require(
            re.search(
                r"(?:unterstützende|supporting|sekundär|secondary|"
                r"ersetzt\s+aber\s+keine|does\s+not\s+replace)",
                tracking,
                re.IGNORECASE,
            )
            is not None,
            "GUI_TOP_TIER_PLAN may only be supporting evidence, not a split tracker",
        )

    source_ids: dict[str, list[str]] = {}
    for priority in EXPECTED_PRIORITIES:
        heading, _ = recovery_section(source, priority)
        require(
            "1.0" in heading
            and re.search(
                r"(?:verpflichtend|verbindlich|mandatory|pflicht)",
                heading,
                re.IGNORECASE,
            )
            is not None,
            f"source {priority} heading must make every recovered row mandatory v1.0 scope",
        )
        if priority == "P2":
            require(
                re.search(
                    r"wenn\s+Kapazität|sonst[^\r\n]*1\.1|otherwise[^\r\n]*1\.1",
                    heading,
                    re.IGNORECASE,
                )
                is None,
                "source P2 heading must not defer work by capacity or to v1.1",
            )
        observed = source_recovery_ids(source, priority)
        expected = expected_road_ids(priority)
        require(
            observed == expected,
            f"source {priority} top-level rows must expose {len(expected)} ordered IDs "
            f"{expected!r}; got {observed!r}",
        )
        source_ids[priority] = observed
    return source_ids


def validate_road(road: str) -> dict[str, list[str]]:
    by_priority, _ = road_checkbox_ids(road)
    for priority in EXPECTED_PRIORITIES:
        expected = expected_road_ids(priority)
        observed = by_priority[priority]
        require(
            observed == expected,
            f"ROAD {priority} checkbox IDs must appear exactly once and in order: "
            f"expected {expected!r}, got {observed!r}",
        )

    integrity = re.findall(
        r"(?m)^\s*-\s+\[([ xX])\]\s+\*\*GOLD-LF-INTEGRITY-01\b",
        road,
    )
    require(
        len(integrity) == 1,
        "ROAD must define GOLD-LF-INTEGRITY-01 exactly once as a checkbox",
    )
    require(
        integrity[0].lower() == "x",
        "ROAD GOLD-LF-INTEGRITY-01 must remain open until this contract is wired, then be checked",
    )
    require(
        re.search(r"53-versus-52|30-versus-29|claims\s+53", road, re.IGNORECASE) is None,
        "ROAD must not retain the superseded 53-versus-52 count discrepancy",
    )

    actual_total, actual_open, actual_done = ws_lf_task_counts(road)
    dashboard_rows = re.findall(
        r"(?m)^\|\s*WS-LF\s+Confirmed lost-feature recovery[^|]*\|"
        r"\s*(\d+)\s+materialized[^|]*\|\s*\*\*(\d+)\*\*\s*\|"
        r"\s*\*\*(\d+)\*\*\s*\|\s*$",
        road,
        flags=re.IGNORECASE,
    )
    require(
        len(dashboard_rows) == 1,
        "ROAD dashboard must contain exactly one parseable WS-LF total/open/done row",
    )
    dashboard_total, dashboard_open, dashboard_done = map(int, dashboard_rows[0])
    require(
        (dashboard_total, dashboard_open, dashboard_done)
        == (actual_total, actual_open, actual_done),
        "WS-LF dashboard drift: expected actual "
        f"{actual_total} total / {actual_open} open / {actual_done} done, got "
        f"{dashboard_total}/{dashboard_open}/{dashboard_done}",
    )

    rollups = re.findall(
        r"(?m)^\s*-\s+\[([ xX])\]\s+WS-LF:\s+all\s+(\d+)\s+`GOLD-LF-\*`",
        road,
    )
    require(
        len(rollups) == 1,
        "Definition of GOLD must contain exactly one parseable WS-LF rollup",
    )
    rollup_mark, rollup_total_text = rollups[0]
    require(
        int(rollup_total_text) == actual_total,
        f"Definition-of-GOLD WS-LF rollup must name all {actual_total} child tasks",
    )
    if actual_open:
        require(
            rollup_mark == " ",
            "Definition-of-GOLD WS-LF rollup is premature while child tasks remain open",
        )
    else:
        require(
            rollup_mark.lower() == "x",
            "Definition-of-GOLD WS-LF rollup must close when every child task is done",
        )
    return by_priority


def validate_progress(progress: str, road: str) -> None:
    sections = re.findall(
        r"(?ms)^> \*\*Current WS-LF inventory integrity\b.*?(?=^>\s*$|\Z)",
        progress,
    )
    require(
        len(sections) == 1,
        "PROGRESS must contain exactly one Current WS-LF inventory integrity section",
    )
    section_text = normalized(
        " ".join(line.removeprefix("> ") for line in sections[0].splitlines())
    )
    counts = re.findall(
        r"\*\*(\d+)\s+done\s*/\s*(\d+)[^*]*\bopen\*\*",
        section_text,
        flags=re.IGNORECASE,
    )
    require(
        len(counts) == 1,
        "PROGRESS Current WS-LF section must state exactly one done/open count pair",
    )
    progress_done, progress_open = map(int, counts[0])
    total, actual_open, actual_done = ws_lf_task_counts(road)
    require(
        progress_done + progress_open == total,
        f"PROGRESS WS-LF counts must sum to {total}, got {progress_done + progress_open}",
    )
    require(
        (progress_open, progress_done) == (actual_open, actual_done),
        "PROGRESS WS-LF drift: ROAD has "
        f"{actual_done} done / {actual_open} open, PROGRESS has "
        f"{progress_done} done / {progress_open} open",
    )


def checkbox_marks(document: str, checkbox_id: str, *, bold: bool) -> list[str]:
    label = rf"\*\*{re.escape(checkbox_id)}\b" if bold else rf"{re.escape(checkbox_id)}\b"
    return re.findall(
        rf"(?m)^\s*-\s+\[([ xX~])\]\s+{label}",
        document,
    )


def validate_tracked_evidence(
    by_id: dict[str, dict[str, Any]],
    road: str,
    gui_plan: str,
) -> None:
    tracked_ids = {
        candidate_id
        for candidate_id, candidate in by_id.items()
        if candidate["disposition"] == "ALREADY_TRACKED"
    }
    require(
        tracked_ids == set(TRACKED_RELEASE_GATES),
        "ALREADY_TRACKED candidates must remain bound to the 11 reviewed live gates",
    )
    gate_marks: dict[str, str] = {}
    for candidate_id, expected_gate in TRACKED_RELEASE_GATES.items():
        release_gate = by_id[candidate_id]["release_gate"]
        parsed = re.fullmatch(
            r"PLAN/ROAD_TO_1_0_GOLD\.md#(GOLD-[A-Z0-9-]+)",
            release_gate,
        )
        require(
            parsed is not None,
            f"{candidate_id}.release_gate must be PLAN/ROAD_TO_1_0_GOLD.md#<ID>",
        )
        gate_id = parsed.group(1)
        require(
            gate_id == expected_gate,
            f"{candidate_id} release_gate contract requires {expected_gate}, got {gate_id}",
        )
        marks = checkbox_marks(road, gate_id, bold=True)
        require(
            len(marks) == 1,
            f"{candidate_id} release gate {gate_id} must resolve to exactly one ROAD checkbox",
        )
        require(
            marks[0] in {" ", "x", "X"},
            f"{candidate_id} release gate {gate_id} must be open or done, not partial",
        )
        gate_marks[gate_id] = marks[0].lower()

    require(
        set(GUI_TRACKED_ANCHORS).issubset(tracked_ids),
        "all nine GUI tracked candidates must remain ALREADY_TRACKED",
    )
    gui_marks: dict[str, str] = {}
    for candidate_id, (expected_anchor, checkbox_id) in GUI_TRACKED_ANCHORS.items():
        resolution_ref = by_id[candidate_id]["resolution_ref"]
        parsed = re.fullmatch(
            r"PLAN/GUI_TOP_TIER_PLAN\.md#([A-Za-z0-9-]+)",
            resolution_ref,
        )
        require(
            parsed is not None,
            f"{candidate_id}.resolution_ref must be a GUI_TOP_TIER_PLAN anchor",
        )
        require(
            parsed.group(1) == expected_anchor,
            f"{candidate_id} GUI resolution anchor must be {expected_anchor}, got "
            f"{parsed.group(1)}",
        )
        marks = checkbox_marks(gui_plan, checkbox_id, bold=False)
        require(
            len(marks) == 1,
            f"{candidate_id} GUI anchor {expected_anchor} must resolve to exactly one checkbox",
        )
        require(
            marks[0] in {" ", "~", "x", "X"},
            f"{candidate_id} GUI anchor {expected_anchor} has an invalid checkbox state",
        )
        gui_marks[candidate_id] = marks[0].lower()

    if gate_marks["GOLD-R4-05"] == "x":
        unfinished = sorted(
            candidate_id
            for candidate_id, mark in gui_marks.items()
            if mark != "x"
        )
        require(
            not unfinished,
            "GOLD-R4-05 cannot be done while linked GUI candidates remain unfinished: "
            f"{unfinished!r}",
        )


def validate_contract(
    inventory: dict[str, Any],
    source: str,
    road: str,
    gui_plan: str,
    progress: str,
) -> None:
    by_id = validate_inventory(inventory)
    source_ids = validate_source(source)
    archive = source_archive_dispositions(source)
    road_ids = validate_road(road)
    validate_progress(progress, road)
    validate_tracked_evidence(by_id, road, gui_plan)
    for priority in EXPECTED_PRIORITIES:
        inventory_ids = {
            candidate["road_id"]
            for candidate in by_id.values()
            if candidate["disposition"] == "CONFIRMED_LOST"
            and candidate["priority"] == priority
        }
        require(
            inventory_ids == set(source_ids[priority]) == set(road_ids[priority]),
            f"{priority} mapping drift: source, inventory, and ROAD must name the same IDs",
        )

    expected_archive = {
        candidate_id: candidate["disposition"]
        for candidate_id, candidate in by_id.items()
        if candidate["disposition"] != "CONFIRMED_LOST"
    }
    require(
        set(archive) == set(expected_archive),
        "source killed archive IDs must equal all 27 non-CONFIRMED_LOST ledger IDs; "
        f"missing {sorted(set(expected_archive) - set(archive))!r}, "
        f"unexpected {sorted(set(archive) - set(expected_archive))!r}",
    )
    for candidate_id, disposition in expected_archive.items():
        allowed_statuses = (
            {"DUPLICATE", "DUPLICATE_OF"}
            if disposition == "DUPLICATE"
            else {disposition}
        )
        require(
            archive[candidate_id] in allowed_statuses,
            f"source killed archive status drift for {candidate_id}: ledger says "
            f"{disposition}, source says {archive[candidate_id]}",
        )


def load_repository_contract() -> tuple[dict[str, Any], str, str, str, str]:
    try:
        inventory = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ContractError(f"cannot read valid inventory JSON: {error}") from error
    return (
        inventory,
        SOURCE_PATH.read_text(encoding="utf-8"),
        ROAD_PATH.read_text(encoding="utf-8"),
        GUI_PLAN_PATH.read_text(encoding="utf-8"),
        PROGRESS_PATH.read_text(encoding="utf-8"),
    )


class LostFeatureIntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        (
            cls.inventory,
            cls.source,
            cls.road,
            cls.gui_plan,
            cls.progress,
        ) = load_repository_contract()

    def set_checkbox_mark(
        self,
        document: str,
        checkbox_id: str,
        mark: str,
        *,
        bold: bool,
    ) -> str:
        label = (
            rf"\*\*{re.escape(checkbox_id)}\b"
            if bold
            else rf"{re.escape(checkbox_id)}\b"
        )
        mutated, replacements = re.subn(
            rf"(?m)^(\s*-\s+\[)[^\]](\]\s+{label})",
            rf"\g<1>{mark}\g<2>",
            document,
            count=1,
        )
        self.assertEqual(
            replacements,
            1,
            f"checkbox mutation fixture did not find {checkbox_id}",
        )
        return mutated

    def assert_contract_fails(
        self,
        inventory: dict[str, Any],
        source: str,
        road: str,
        pattern: str,
        *,
        gui_plan: str | None = None,
        progress: str | None = None,
    ) -> None:
        with self.assertRaisesRegex(ContractError, pattern):
            validate_contract(
                inventory,
                source,
                road,
                gui_plan if gui_plan is not None else self.gui_plan,
                progress if progress is not None else self.progress,
            )

    def test_repository_contract(self) -> None:
        validate_contract(
            self.inventory,
            self.source,
            self.road,
            self.gui_plan,
            self.progress,
        )

    def test_missing_candidate_fails_closed(self) -> None:
        mutated = deepcopy(self.inventory)
        mutated["candidates"].pop(20)
        self.assert_contract_fails(mutated, self.source, self.road, "candidate IDs")

    def test_duplicate_candidate_id_fails_closed(self) -> None:
        mutated = deepcopy(self.inventory)
        mutated["candidates"][1]["id"] = mutated["candidates"][0]["id"]
        self.assert_contract_fails(mutated, self.source, self.road, "candidate IDs")

    def test_cross_tier_mapping_fails_closed(self) -> None:
        mutated = deepcopy(self.inventory)
        candidate = next(
            item
            for item in mutated["candidates"]
            if item.get("disposition") == "CONFIRMED_LOST"
            and item.get("priority") == "P1"
        )
        candidate["priority"] = "P2"
        self.assert_contract_fails(mutated, self.source, self.road, "priority counts")

    def test_road_checkbox_drift_fails_closed(self) -> None:
        mutated_road = self.road.replace(
            "**GOLD-LF-P1-01 —",
            "**GOLD-LF-P1-99 —",
            1,
        )
        self.assert_contract_fails(
            self.inventory,
            self.source,
            mutated_road,
            "ROAD P1 checkbox IDs",
        )

    def test_duplicate_cycle_fails_closed(self) -> None:
        mutated = deepcopy(self.inventory)
        duplicates = [
            item for item in mutated["candidates"] if item["disposition"] == "DUPLICATE"
        ]
        duplicates[0]["duplicate_of"] = duplicates[1]["id"]
        duplicates[1]["duplicate_of"] = duplicates[0]["id"]
        self.assert_contract_fails(mutated, self.source, self.road, "duplicate cycle")

    def test_provenance_drift_fails_closed(self) -> None:
        mutated = deepcopy(self.inventory)
        mutated["provenance"]["source_commit"] = "0" * 8
        self.assert_contract_fails(mutated, self.source, self.road, "provenance")

    def test_candidate_identity_drift_fails_closed(self) -> None:
        mutated = deepcopy(self.inventory)
        mutated["candidates"][0]["name"] += " rewritten"
        self.assert_contract_fails(mutated, self.source, self.road, "identity drifted")

    def test_missing_resolution_evidence_path_fails_closed(self) -> None:
        mutated = deepcopy(self.inventory)
        candidate = next(
            item for item in mutated["candidates"] if item["id"] == "LF-CAND-053"
        )
        candidate["resolution_ref"] = (
            "SRC/neothd/src/cli/init/missing_steps_autonomy.rs bulk-enable step"
        )
        self.assert_contract_fails(
            mutated,
            self.source,
            self.road,
            "evidence path does not exist",
        )

    def test_candidate_road_mapping_permutation_fails_closed(self) -> None:
        mutated = deepcopy(self.inventory)
        candidates = [
            item
            for item in mutated["candidates"]
            if item.get("disposition") == "CONFIRMED_LOST"
            and item.get("priority") == "P1"
        ][:2]
        candidates[0]["road_id"], candidates[1]["road_id"] = (
            candidates[1]["road_id"],
            candidates[0]["road_id"],
        )
        self.assert_contract_fails(
            mutated,
            self.source,
            self.road,
            "candidate-to-ROAD mapping drifted",
        )

    def test_p1_mandatory_scope_drift_fails_closed(self) -> None:
        mutated_source, replacements = re.subn(
            r"(?m)^## P1 — VERPFLICHTEND in 1\.0",
            "## P1 — optional",
            self.source,
            count=1,
        )
        self.assertEqual(replacements, 1, "P1 heading mutation fixture did not match")
        self.assert_contract_fails(
            self.inventory,
            mutated_source,
            self.road,
            "source P1 heading",
        )

    def test_dashboard_drift_fails_closed(self) -> None:
        mutated_road, replacements = re.subn(
            r"(?m)^(\|\s*WS-LF\s+Confirmed lost-feature recovery[^|]*\|"
            r"[^|]*\|\s*\*\*)\d+(\*\*\s*\|\s*\*\*\d+\*\*\s*\|\s*)$",
            r"\g<1>999\g<2>",
            self.road,
        )
        self.assertEqual(replacements, 1, "dashboard mutation fixture did not match")
        self.assert_contract_fails(
            self.inventory,
            self.source,
            mutated_road,
            "WS-LF dashboard drift",
        )

    def test_progress_drift_fails_closed(self) -> None:
        def drift(match: re.Match[str]) -> str:
            done, open_tasks = map(int, match.groups())
            if open_tasks:
                done += 1
                open_tasks -= 1
            else:
                done -= 1
                open_tasks += 1
            return f"**{done} done / {open_tasks}"

        section_match = re.search(
            r"(?ms)^> \*\*Current WS-LF inventory integrity\b.*?(?=^>\s*$|\Z)",
            self.progress,
        )
        self.assertIsNotNone(
            section_match,
            "PROGRESS mutation fixture did not find the WS-LF section",
        )
        assert section_match is not None
        mutated_section, replacements = re.subn(
            r"\*\*(\d+)\s+done\s*/\s*(\d+)(?=\s+[^*]*\bopen\*\*)",
            drift,
            section_match.group(0),
            count=1,
        )
        self.assertEqual(replacements, 1, "PROGRESS mutation fixture did not match")
        mutated_progress = (
            self.progress[: section_match.start()]
            + mutated_section
            + self.progress[section_match.end() :]
        )
        self.assert_contract_fails(
            self.inventory,
            self.source,
            self.road,
            "PROGRESS WS-LF drift",
            progress=mutated_progress,
        )

    def test_premature_definition_of_gold_rollup_fails_closed(self) -> None:
        mutated_road, replacements = re.subn(
            r"(?m)^- \[ \] WS-LF:",
            "- [x] WS-LF:",
            self.road,
            count=1,
        )
        self.assertEqual(replacements, 1, "WS-LF rollup mutation fixture did not match")
        self.assert_contract_fails(
            self.inventory,
            self.source,
            mutated_road,
            "WS-LF rollup is premature",
        )

    def test_missing_source_archive_candidate_fails_closed(self) -> None:
        mutated_source, replacements = re.subn(
            r"(?ms)^- \*\*LF-CAND-011\b.*?(?=^- \*\*LF-CAND-|\Z)",
            "",
            self.source,
            count=1,
        )
        self.assertEqual(replacements, 1, "source archive mutation fixture did not match")
        self.assert_contract_fails(
            self.inventory,
            mutated_source,
            self.road,
            "killed archive must contain exactly 27",
        )

    def test_invented_release_gate_fails_closed(self) -> None:
        mutated = deepcopy(self.inventory)
        candidate = next(
            item for item in mutated["candidates"] if item["id"] == "LF-CAND-032"
        )
        candidate["release_gate"] = "PLAN/ROAD_TO_1_0_GOLD.md#GOLD-R4-99"
        self.assert_contract_fails(
            mutated,
            self.source,
            self.road,
            "release_gate contract requires GOLD-R4-13",
        )

    def test_release_gate_may_legitimately_complete(self) -> None:
        mutated_road = self.set_checkbox_mark(
            self.road,
            "GOLD-R4-13",
            "x",
            bold=True,
        )
        validate_contract(
            self.inventory,
            self.source,
            mutated_road,
            self.gui_plan,
            self.progress,
        )

    def test_gui_parent_cannot_close_before_linked_children(self) -> None:
        mutated_road = self.set_checkbox_mark(
            self.road,
            "GOLD-R4-05",
            "x",
            bold=True,
        )
        mutated_gui = self.set_checkbox_mark(
            self.gui_plan,
            "H6",
            " ",
            bold=False,
        )
        self.assert_contract_fails(
            self.inventory,
            self.source,
            mutated_road,
            "GOLD-R4-05 cannot be done",
            gui_plan=mutated_gui,
        )

    def test_gui_parent_and_all_linked_children_may_complete(self) -> None:
        mutated_road = self.set_checkbox_mark(
            self.road,
            "GOLD-R4-05",
            "x",
            bold=True,
        )
        mutated_gui = self.gui_plan
        for checkbox_id in ("H22", "D1", "H17", "H20", "I15", "H15", "H6", "H11"):
            mutated_gui = self.set_checkbox_mark(
                mutated_gui,
                checkbox_id,
                "x",
                bold=False,
            )
        validate_contract(
            self.inventory,
            self.source,
            mutated_road,
            mutated_gui,
            self.progress,
        )


if __name__ == "__main__":
    unittest.main()
