#!/usr/bin/env python3
"""Block release tags while mandatory Road-to-Gold work remains open."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import re
import sys
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ROADMAP = ROOT / "PLAN" / "ROAD_TO_1_0_GOLD.md"
RELEASE_GENERATED_ID = "GOLD-RELEASE-ARTIFACTS"

_TASK_BOX = re.compile(
    r"^(?:[ \t]*>[ \t]*)*[ \t]*"
    r"(?:(?:[-+*]|\d+[.)])[ \t]+)+"
    r"\[(?P<state>[^\]\r\n]*)\](?:[ \t]+(?P<body>.*?))?\s*$"
)
_GOLD_ID = re.compile(
    r"^\*\*(?P<identifier>GOLD-[A-Z0-9-]+)\*\*(?:\s|$)"
)
_FENCE_OPEN = re.compile(
    r"^(?P<indent> {0,3})(?P<marker>`{3,}|~{3,})(?P<info>.*)$"
)
_PUBLISHED_SUMMARY = re.compile(
    r"<!-- ROADMAP-RELEASE-GATE-SUMMARY "
    r"total=(?P<total>\d+) "
    r"complete=(?P<complete>\d+) "
    r"open=(?P<open>\d+) "
    r"partial=(?P<partial>\d+) "
    r"raw_blockers=(?P<raw_blockers>\d+) "
    r"release_tag_blockers=(?P<release_tag_blockers>\d+) "
    r"release_generated_items=(?P<release_generated_items>\d+) -->"
)


class RoadmapReleaseGateError(ValueError):
    """The roadmap cannot authorize a public release tag."""


@dataclass(frozen=True)
class RoadmapItem:
    line: int
    state: str
    identifier: str | None
    body: str

    @property
    def label(self) -> str:
        return self.identifier or self.body[:96]


@dataclass(frozen=True)
class RoadmapSummary:
    total: int
    complete: int
    open: int
    partial: int
    raw_blockers: int
    release_tag_blockers: int
    release_generated_items: int


def roadmap_items(text: str) -> list[RoadmapItem]:
    """Return every Markdown task outside fenced code."""

    result: list[RoadmapItem] = []
    fence: tuple[str, int, int] | None = None
    for line_number, line in enumerate(text.splitlines(), start=1):
        if fence is not None:
            marker_char, marker_length, _ = fence
            if re.fullmatch(
                rf" {{0,3}}{re.escape(marker_char)}{{{marker_length},}}[ \t]*",
                line,
            ):
                fence = None
            continue
        fence_match = _FENCE_OPEN.match(line)
        if fence_match is not None:
            marker = fence_match.group("marker")
            info = fence_match.group("info")
            if marker.startswith("`") and "`" in info:
                # CommonMark does not recognize a backtick fence whose info
                # string contains a backtick. Treat it as ordinary text.
                pass
            else:
                fence = (marker[0], len(marker), line_number)
                continue
        match = _TASK_BOX.match(line)
        if match is None:
            continue
        state = match.group("state")
        if state not in {" ", "x", "X", "~"}:
            raise RoadmapReleaseGateError(
                f"roadmap line {line_number} has unknown task state "
                f"[{state}]; only [ ], [x], [X], and [~] are valid"
            )
        body = match.group("body") or ""
        identifier_match = _GOLD_ID.search(body)
        result.append(
            RoadmapItem(
                line=line_number,
                state=state,
                identifier=(
                    identifier_match.group("identifier")
                    if identifier_match is not None
                    else None
                ),
                body=body,
            )
        )
    if fence is not None:
        marker_char, marker_length, opening_line = fence
        raise RoadmapReleaseGateError(
            "roadmap contains an unterminated fenced code block opened at "
            f"line {opening_line} with {marker_length} {marker_char!r} markers"
        )
    return result


def open_items(text: str) -> list[RoadmapItem]:
    """Return every unchecked or partial Markdown task outside fenced code."""

    return [item for item in roadmap_items(text) if item.state in {" ", "~"}]


def roadmap_summary(text: str) -> RoadmapSummary:
    """Return the exact release-gate counts used by CI and roadmap reporting."""

    items = roadmap_items(text)
    raw_blockers = [
        item for item in items if item.state in {" ", "~"}
    ]
    release_generated = [
        item for item in items if item.identifier == RELEASE_GENERATED_ID
    ]
    return RoadmapSummary(
        total=len(items),
        complete=sum(item.state in {"x", "X"} for item in items),
        open=sum(item.state == " " for item in items),
        partial=sum(item.state == "~" for item in items),
        raw_blockers=len(raw_blockers),
        release_tag_blockers=sum(
            item.identifier != RELEASE_GENERATED_ID for item in raw_blockers
        ),
        release_generated_items=len(release_generated),
    )


def published_summary(text: str) -> RoadmapSummary:
    """Read the single dashboard count marker maintained by the roadmap."""

    matches = list(_PUBLISHED_SUMMARY.finditer(text))
    if len(matches) != 1:
        raise RoadmapReleaseGateError(
            "roadmap must contain exactly one "
            "ROADMAP-RELEASE-GATE-SUMMARY marker; "
            f"found {len(matches)}"
        )
    values = {key: int(value) for key, value in matches[0].groupdict().items()}
    return RoadmapSummary(**values)


def require_release_ready(
    text: str,
    *,
    allow_release_generated_artifacts: bool,
) -> None:
    """Require all work complete except the artifact created by this workflow."""

    all_items = roadmap_items(text)
    items = [item for item in all_items if item.state in {" ", "~"}]
    release_generated = [
        item for item in all_items if item.identifier == RELEASE_GENERATED_ID
    ]
    if allow_release_generated_artifacts:
        if len(release_generated) != 1:
            raise RoadmapReleaseGateError(
                "roadmap must contain exactly one "
                f"{RELEASE_GENERATED_ID} item; found {len(release_generated)}"
            )
        if release_generated[0].state == "~":
            raise RoadmapReleaseGateError(
                f"{RELEASE_GENERATED_ID} cannot be partial"
            )
        items = [
            item
            for item in items
            if item.identifier != RELEASE_GENERATED_ID
        ]

    if not items:
        return

    preview = "\n".join(
        f"  line {item.line}: [{item.state}] {item.label}"
        for item in items[:20]
    )
    remainder = len(items) - 20
    if remainder > 0:
        preview += f"\n  ... and {remainder} more"
    raise RoadmapReleaseGateError(
        f"{len(items)} mandatory Road-to-Gold item(s) remain open or partial:\n"
        f"{preview}"
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--roadmap", type=Path, default=DEFAULT_ROADMAP)
    result.add_argument(
        "--release-tag",
        action="store_true",
        help=(
            "allow only the single GOLD-RELEASE-ARTIFACTS task whose evidence "
            "is created by the release workflow itself"
        ),
    )
    result.add_argument(
        "--summary-json",
        action="store_true",
        help=(
            "print machine-readable checkbox and release-blocker counts without "
            "requiring the roadmap to be complete"
        ),
    )
    return result


def main(argv: Iterable[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        text = args.roadmap.read_text(encoding="utf-8")
        if args.summary_json:
            print(json.dumps(roadmap_summary(text).__dict__, sort_keys=True))
            return 0
        require_release_ready(
            text,
            allow_release_generated_artifacts=args.release_tag,
        )
    except (OSError, UnicodeError, RoadmapReleaseGateError) as error:
        print(f"::error::Road-to-Gold release gate failed: {error}", file=sys.stderr)
        return 1
    print("Road-to-Gold release gate: all mandatory pre-tag work is complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
