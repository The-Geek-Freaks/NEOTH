#!/usr/bin/env python3
"""Block release tags while mandatory Road-to-Gold work remains open."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
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
    return result


def main(argv: Iterable[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        text = args.roadmap.read_text(encoding="utf-8")
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
