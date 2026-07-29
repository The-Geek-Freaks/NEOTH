from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).parents[2]

import sys

sys.path.insert(0, str(ROOT / "packaging"))

from roadmap_release_gate import (  # noqa: E402
    RELEASE_GENERATED_ID,
    RoadmapReleaseGateError,
    open_items,
    require_release_ready,
)


RELEASE_ITEM = (
    f"- [ ] **{RELEASE_GENERATED_ID}** Signed release artifacts exist "
    "(created by release.yml).\n"
)


class RoadmapReleaseGateTests(unittest.TestCase):
    def test_complete_roadmap_passes_without_release_exception(self) -> None:
        require_release_ready(
            "- [x] **GOLD-DONE-01** complete\n",
            allow_release_generated_artifacts=False,
        )

    def test_release_tag_allows_only_the_single_release_generated_item(self) -> None:
        require_release_ready(
            RELEASE_ITEM + "- [x] **GOLD-DONE-01** complete\n",
            allow_release_generated_artifacts=True,
        )
        require_release_ready(
            RELEASE_ITEM.replace("[ ]", "[x]"),
            allow_release_generated_artifacts=True,
        )

    def test_unknown_open_and_partial_items_both_block(self) -> None:
        for state in (" ", "~"):
            with self.subTest(state=state):
                with self.assertRaisesRegex(
                    RoadmapReleaseGateError,
                    "1 mandatory Road-to-Gold item",
                ):
                    require_release_ready(
                        RELEASE_ITEM + f"- [{state}] **GOLD-OPEN-01** pending\n",
                        allow_release_generated_artifacts=True,
                    )

    def test_release_exception_must_exist_exactly_once_and_cannot_be_partial(
        self,
    ) -> None:
        invalid_fixtures = (
            "",
            RELEASE_ITEM + RELEASE_ITEM,
            RELEASE_ITEM.replace("[ ]", "[~]"),
        )
        for fixture in invalid_fixtures:
            with self.subTest(fixture=fixture):
                with self.assertRaises(RoadmapReleaseGateError):
                    require_release_ready(
                        fixture,
                        allow_release_generated_artifacts=True,
                    )

    def test_fenced_examples_do_not_create_release_work(self) -> None:
        items = open_items(
            "```md\n- [ ] **GOLD-EXAMPLE-01** example only\n```\n"
            + RELEASE_ITEM
        )
        self.assertEqual([item.identifier for item in items], [RELEASE_GENERATED_ID])

    def test_every_commonmark_task_marker_and_blockquote_blocks(self) -> None:
        fixtures = (
            "* [ ] **GOLD-OPEN-01** pending\n",
            "+ [ ] **GOLD-OPEN-01** pending\n",
            "1. [ ] **GOLD-OPEN-01** pending\n",
            "2) [~] **GOLD-OPEN-01** partial\n",
            "> - [ ] **GOLD-OPEN-01** quoted\n",
            "\t> - [ ] **GOLD-OPEN-01** tab-quoted\n",
            "    - [ ] **GOLD-OPEN-01** nested\n",
            "- - [ ] **GOLD-OPEN-01** compact nested\n",
            "- [ ]\n",
        )
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                with self.assertRaisesRegex(
                    RoadmapReleaseGateError,
                    "mandatory Road-to-Gold item",
                ):
                    require_release_ready(
                        RELEASE_ITEM + fixture,
                        allow_release_generated_artifacts=True,
                    )

    def test_malformed_or_unterminated_fences_fail_closed(self) -> None:
        fixtures = (
            RELEASE_ITEM + "```\n- [ ] **GOLD-HIDDEN-01** pending\n",
            RELEASE_ITEM + "````\n- [ ] **GOLD-HIDDEN-01** pending\n```\n",
            RELEASE_ITEM
            + "    ```\n"
            + "    - [ ] **GOLD-HIDDEN-01** pending\n"
            + "    ```\n",
        )
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                with self.assertRaises(RoadmapReleaseGateError):
                    require_release_ready(
                        fixture,
                        allow_release_generated_artifacts=True,
                    )

    def test_release_exception_id_must_start_the_task_body(self) -> None:
        fixtures = (
            "- [ ] **GOLD-OPEN-01** mentions "
            + RELEASE_GENERATED_ID
            + " later\n",
            f"- [ ] **{RELEASE_GENERATED_ID}-** near match\n",
            f"- [ ] **{RELEASE_GENERATED_ID}/** near match\n",
            f"- [ ] **{RELEASE_GENERATED_ID} extra** near match\n",
        )
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                with self.assertRaises(RoadmapReleaseGateError):
                    require_release_ready(
                        RELEASE_ITEM + fixture,
                        allow_release_generated_artifacts=True,
                    )

    def test_unknown_checkbox_like_states_fail_closed(self) -> None:
        for state in ("?", "!", "TODO", "\t"):
            with self.subTest(state=state):
                with self.assertRaisesRegex(
                    RoadmapReleaseGateError,
                    "unknown task state",
                ):
                    require_release_ready(
                        RELEASE_ITEM + f"- [{state}] **GOLD-OPEN-01** pending\n",
                        allow_release_generated_artifacts=True,
                    )

    def test_current_roadmap_is_intentionally_blocked_until_gold_is_complete(
        self,
    ) -> None:
        text = (ROOT / "PLAN" / "ROAD_TO_1_0_GOLD.md").read_text(encoding="utf-8")
        items = open_items(text)
        release_items = [
            item for item in items if item.identifier == RELEASE_GENERATED_ID
        ]
        self.assertEqual(len(release_items), 1)
        with self.assertRaisesRegex(
            RoadmapReleaseGateError,
            "mandatory Road-to-Gold item",
        ):
            require_release_ready(
                text,
                allow_release_generated_artifacts=True,
            )


if __name__ == "__main__":
    unittest.main()
