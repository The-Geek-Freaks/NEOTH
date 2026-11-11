from __future__ import annotations

from copy import deepcopy
from datetime import date
from pathlib import Path
import re
import sys
from typing import Any
import unittest


ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT / "packaging"))

import advisory_exception_gate as gate  # noqa: E402


AUDIT_CONFIG: dict[str, Any] = {
    "advisories": {"ignore": list(gate.TEMPORARY_ADVISORIES)},
}
DENY_CONFIG: dict[str, Any] = {
    "advisories": {
        "ignore": [
            {"id": identifier, "reason": "fixture"}
            for identifier in gate.TEMPORARY_ADVISORIES
        ],
    },
}


def package(
    identifier: str,
    name: str,
    version: str,
    source: str | None = gate.CRATES_IO_REGISTRY_SOURCE,
) -> dict[str, str]:
    result = {"id": identifier, "name": name, "version": version}
    if source is not None:
        result["source"] = source
    return result


def metadata_fixture() -> dict[str, Any]:
    """The minimal reviewed bitmaps -> imbl -> eyeball-im -> Matrix path."""

    packages = [
        package("bitmaps", "bitmaps", "3.2.1"),
        package("imbl", "imbl", "6.1.0"),
        package("eyeball-im", "eyeball-im", "0.8.0"),
        package("matrix-sdk", "matrix-sdk", "0.18.0"),
        package("neoth", "neoth", "1.0.0"),
    ]
    return {
        "packages": packages,
        "workspace_members": ["neoth"],
        "resolve": {
            "nodes": [
                {"id": "bitmaps", "dependencies": []},
                {"id": "imbl", "dependencies": ["bitmaps"]},
                {"id": "eyeball-im", "dependencies": ["imbl"]},
                {"id": "matrix-sdk", "dependencies": ["eyeball-im"]},
                {"id": "neoth", "dependencies": ["matrix-sdk"]},
            ],
        },
    }


def closed_metadata_fixture() -> dict[str, Any]:
    """A structurally valid graph after the path-patched imbl removes bitmaps."""

    active = metadata_fixture()
    packages = [item for item in active["packages"] if item["id"] != "bitmaps"]
    nodes = []
    for node in active["resolve"]["nodes"]:
        if node["id"] == "bitmaps":
            continue
        nodes.append(
            {
                "id": node["id"],
                "dependencies": [dependency for dependency in node["dependencies"] if dependency != "bitmaps"],
            }
        )
    return {
        "packages": packages,
        "workspace_members": active["workspace_members"],
        "resolve": {"nodes": nodes},
    }


def matrix_stack_configs() -> tuple[dict[str, Any], dict[str, Any]]:
    expiry = gate.MATRIX_STACK_EXPIRY_DATE.isoformat()
    audit: dict[str, Any] = {"advisories": {"ignore": list(gate.MATRIX_STACK_ADVISORIES)}}
    deny: dict[str, Any] = {
        "advisories": {
            "ignore": [
                {"id": identifier, "reason": f"fixture; expires {expiry}"}
                for identifier in gate.MATRIX_STACK_ADVISORIES
            ],
        },
    }
    return audit, deny


def matrix_stack_metadata(
    vodozemac: str | None = "0.10.0", sqlite: str | None = "0.35.0"
) -> dict[str, Any]:
    metadata = closed_metadata_fixture()
    for name, version in (("vodozemac", vodozemac), ("libsqlite3-sys", sqlite)):
        if version is not None:
            metadata["packages"].append(package(name, name, version))
            metadata["resolve"]["nodes"].append({"id": name, "dependencies": []})
    return metadata


class MatrixStackExceptionTests(unittest.TestCase):
    TODAY = date(2026, 11, 12)

    def check(
        self,
        audit: dict[str, Any],
        deny: dict[str, Any],
        metadata: dict[str, Any] | None = None,
        *,
        today: date | None = None,
    ) -> str:
        return gate.require_matrix_stack_exceptions(
            audit,
            deny,
            matrix_stack_metadata() if metadata is None else metadata,
            today=self.TODAY if today is None else today,
        )

    def test_synchronized_exception_is_active_and_keeps_the_bitmaps_state(self) -> None:
        audit, deny = matrix_stack_configs()
        self.assertEqual(self.check(audit, deny), "active")
        self.assertEqual(
            gate.validate(
                audit_config=audit,
                deny_config=deny,
                metadata=matrix_stack_metadata(),
                today=self.TODAY,
            ),
            "closed",
        )

    def test_absent_exception_is_closed_without_reading_the_graph(self) -> None:
        empty: dict[str, Any] = {"advisories": {"ignore": []}}
        self.assertEqual(
            self.check(empty, deepcopy(empty), today=gate.MATRIX_STACK_EXPIRY_DATE),
            "closed",
        )

    def test_expiry_is_exclusive_and_fails_closed(self) -> None:
        audit, deny = matrix_stack_configs()
        with self.assertRaisesRegex(gate.AdvisoryExceptionGateError, "expired on 2026-12-01"):
            self.check(audit, deny, today=gate.MATRIX_STACK_EXPIRY_DATE)
        with self.assertRaisesRegex(gate.AdvisoryExceptionGateError, "expired on 2026-12-01"):
            gate.validate(
                audit_config=audit,
                deny_config=deny,
                metadata=matrix_stack_metadata(),
                today=gate.MATRIX_STACK_EXPIRY_DATE,
            )

    def test_one_sided_or_duplicate_exception_fails_closed(self) -> None:
        audit, deny = matrix_stack_configs()
        one_sided = deepcopy(audit)
        one_sided["advisories"]["ignore"].pop()
        with self.assertRaisesRegex(gate.AdvisoryExceptionGateError, "exactly once"):
            self.check(one_sided, deny)
        duplicate = deepcopy(deny)
        duplicate["advisories"]["ignore"].append(deepcopy(deny["advisories"]["ignore"][0]))
        with self.assertRaisesRegex(gate.AdvisoryExceptionGateError, "exactly once"):
            self.check(audit, duplicate)
        deny_only: dict[str, Any] = {"advisories": {"ignore": []}}
        with self.assertRaisesRegex(gate.AdvisoryExceptionGateError, "exactly once"):
            self.check(deny_only, deny)

    def test_reason_must_state_the_expiry(self) -> None:
        audit, deny = matrix_stack_configs()
        deny["advisories"]["ignore"][0]["reason"] = "no date"
        with self.assertRaisesRegex(gate.AdvisoryExceptionGateError, "must state the 2026-12-01"):
            self.check(audit, deny)

    def test_stale_exception_fails_once_the_graph_no_longer_needs_it(self) -> None:
        audit, deny = matrix_stack_configs()
        with self.assertRaisesRegex(gate.AdvisoryExceptionGateError, "vodozemac is no longer"):
            self.check(audit, deny, matrix_stack_metadata(vodozemac=None))
        with self.assertRaisesRegex(
            gate.AdvisoryExceptionGateError, "every resolved vodozemac is patched"
        ):
            self.check(audit, deny, matrix_stack_metadata(vodozemac="0.11.2"))
        with self.assertRaisesRegex(
            gate.AdvisoryExceptionGateError, "every resolved libsqlite3-sys is patched"
        ):
            self.check(audit, deny, matrix_stack_metadata(sqlite="0.39.1"))
        with self.assertRaisesRegex(gate.AdvisoryExceptionGateError, "unparseable"):
            self.check(audit, deny, matrix_stack_metadata(sqlite="next"))

    def test_checked_in_configuration_is_synchronized_or_removed(self) -> None:
        # Present entries must be mirrored, dated and reasoned; removing both
        # with the Matrix stack bump is the other valid state.
        self.assertIn(
            self.check(
                gate._load_toml(gate.DEFAULT_AUDIT_CONFIG),
                gate._load_toml(gate.DEFAULT_DENY_CONFIG),
            ),
            {"active", "closed"},
        )


class AdvisoryExceptionGateTests(unittest.TestCase):
    def validate(
        self, metadata: object | None = None, *, today: date = date(2026, 11, 12)
    ) -> None:
        gate.validate(
            audit_config=deepcopy(AUDIT_CONFIG),
            deny_config=deepcopy(DENY_CONFIG),
            metadata=metadata_fixture() if metadata is None else metadata,
            today=today,
        )

    def test_reviewed_matrix_chain_passes(self) -> None:
        self.validate()

    def test_closed_state_requires_absent_graph_and_absent_exceptions(self) -> None:
        closed_audit: dict[str, Any] = {"advisories": {"ignore": []}}
        closed_deny: dict[str, Any] = {"advisories": {"ignore": []}}
        self.assertEqual(
            gate.validate(
                audit_config=closed_audit,
                deny_config=closed_deny,
                metadata=closed_metadata_fixture(),
                today=gate.EXPIRY_DATE,
            ),
            "closed",
        )

    def test_closed_state_rejects_leftover_package_or_one_sided_ignore(self) -> None:
        closed_audit: dict[str, Any] = {"advisories": {"ignore": []}}
        closed_deny: dict[str, Any] = {"advisories": {"ignore": []}}
        with self.assertRaisesRegex(gate.AdvisoryExceptionGateError, "no resolved bitmaps"):
            gate.validate(
                audit_config=closed_audit,
                deny_config=closed_deny,
                metadata=metadata_fixture(),
                today=gate.EXPIRY_DATE,
            )
        one_sided_audit: dict[str, Any] = {
            "advisories": {"ignore": ["RUSTSEC-2026-0247"]}
        }
        with self.assertRaisesRegex(gate.AdvisoryExceptionGateError, "exactly once"):
            gate.validate(
                audit_config=one_sided_audit,
                deny_config=closed_deny,
                metadata=closed_metadata_fixture(),
                today=date(2026, 11, 12),
            )

    def test_expiration_is_exclusive_and_fails_closed_on_the_review_date(self) -> None:
        with self.assertRaisesRegex(gate.AdvisoryExceptionGateError, "expired"):
            self.validate(today=gate.EXPIRY_DATE)

    def test_unsynchronized_audit_and_deny_exceptions_fail_closed(self) -> None:
        audit = deepcopy(AUDIT_CONFIG)
        audit["advisories"]["ignore"].remove("RUSTSEC-2025-0167")
        with self.assertRaisesRegex(gate.AdvisoryExceptionGateError, "exactly once"):
            gate.validate(
                audit_config=audit,
                deny_config=deepcopy(DENY_CONFIG),
                metadata=metadata_fixture(),
                today=date(2026, 11, 12),
            )

    def test_duplicate_exception_fails_closed(self) -> None:
        deny = deepcopy(DENY_CONFIG)
        deny["advisories"]["ignore"].append(
            {"id": "RUSTSEC-2026-0247", "reason": "duplicate"}
        )
        with self.assertRaisesRegex(gate.AdvisoryExceptionGateError, "exactly once"):
            gate.validate(
                audit_config=deepcopy(AUDIT_CONFIG),
                deny_config=deny,
                metadata=metadata_fixture(),
                today=date(2026, 11, 12),
            )

    def test_new_or_multiple_bitmaps_versions_fail_closed(self) -> None:
        changed = metadata_fixture()
        changed["packages"][0]["version"] = "3.2.2"
        with self.assertRaisesRegex(
            gate.AdvisoryExceptionGateError, "canonical crates.io source and version"
        ):
            self.validate(changed)

        multiple = metadata_fixture()
        multiple["packages"].append(package("bitmaps-old", "bitmaps", "3.1.0"))
        multiple["resolve"]["nodes"].append({"id": "bitmaps-old", "dependencies": []})
        with self.assertRaisesRegex(
            gate.AdvisoryExceptionGateError, "at most one canonical reviewed package"
        ):
            self.validate(multiple)

    def test_unreviewed_immutable_collections_or_matrix_version_fails_closed(
        self,
    ) -> None:
        changed = metadata_fixture()
        changed["packages"][1]["version"] = "6.2.0"
        with self.assertRaisesRegex(
            gate.AdvisoryExceptionGateError, "canonical crates.io source and version"
        ):
            self.validate(changed)

    def test_workspace_path_git_and_duplicate_source_variants_fail_closed(self) -> None:
        workspace_patch = metadata_fixture()
        workspace_patch["packages"][0].pop("source")
        with self.assertRaisesRegex(
            gate.AdvisoryExceptionGateError, "canonical crates.io source"
        ):
            self.validate(workspace_patch)

        path_patch = metadata_fixture()
        path_patch["packages"][1]["source"] = "path+file:///tmp/imbl"
        with self.assertRaisesRegex(
            gate.AdvisoryExceptionGateError, "canonical crates.io source"
        ):
            self.validate(path_patch)

        git_override = metadata_fixture()
        git_override["packages"][2]["source"] = "git+https://example.invalid/eyeball-im"
        with self.assertRaisesRegex(
            gate.AdvisoryExceptionGateError, "canonical crates.io source"
        ):
            self.validate(git_override)

        duplicate_source = metadata_fixture()
        duplicate_source["packages"].append(
            package(
                "matrix-sdk-git",
                "matrix-sdk",
                "0.18.0",
                "git+https://example.invalid/matrix-sdk",
            )
        )
        duplicate_source["resolve"]["nodes"].append(
            {"id": "matrix-sdk-git", "dependencies": ["eyeball-im"]}
        )
        with self.assertRaisesRegex(
            gate.AdvisoryExceptionGateError, "at most one canonical reviewed package"
        ):
            self.validate(duplicate_source)

    def test_direct_or_non_matrix_reverse_path_fails_closed(self) -> None:
        direct = metadata_fixture()
        direct["resolve"]["nodes"][-1]["dependencies"].append("bitmaps")
        with self.assertRaisesRegex(
            gate.AdvisoryExceptionGateError, "expected 'imbl' or 'imbl-sized-chunks'"
        ):
            self.validate(direct)

        direct_eyeball = metadata_fixture()
        direct_eyeball["resolve"]["nodes"][-1]["dependencies"].append("eyeball-im")
        with self.assertRaisesRegex(
            gate.AdvisoryExceptionGateError,
            "before a reviewed Matrix SDK package",
        ):
            self.validate(direct_eyeball)

        non_matrix = metadata_fixture()
        non_matrix["packages"].append(package("not-matrix", "unreviewed-sdk", "1.0.0"))
        non_matrix["resolve"]["nodes"].append(
            {"id": "not-matrix", "dependencies": ["eyeball-im"]}
        )
        with self.assertRaisesRegex(
            gate.AdvisoryExceptionGateError, "Matrix SDK chain"
        ):
            self.validate(non_matrix)

    def test_missing_or_ambiguous_metadata_fails_closed(self) -> None:
        with self.assertRaisesRegex(
            gate.AdvisoryExceptionGateError, "root must be an object"
        ):
            self.validate([])
        broken = metadata_fixture()
        broken["resolve"]["nodes"][1]["dependencies"] = ["missing"]
        with self.assertRaisesRegex(
            gate.AdvisoryExceptionGateError, "invalid dependencies"
        ):
            self.validate(broken)

    def test_security_workflow_generates_one_locked_all_features_metadata_snapshot(
        self,
    ) -> None:
        workflow = (ROOT / ".github" / "workflows" / "security.yml").read_text(
            encoding="utf-8"
        )
        metadata_command = (
            "cargo metadata --manifest-path SRC/Cargo.toml --locked --all-features "
            "--format-version 1"
        )
        validator_command = "python3 packaging/advisory_exception_gate.py --metadata"
        self.assertEqual(workflow.count(metadata_command), 1)
        self.assertEqual(workflow.count(validator_command), 1)

        for consumer in ("audit", "deny"):
            job = re.search(
                rf"(?ms)^  {consumer}:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
                workflow,
            )
            self.assertIsNotNone(job, f"Security workflow has no {consumer} job")
            assert job is not None
            self.assertIn(
                "needs: [trusted-main, advisory-exception-gate]",
                job.group("body"),
                f"{consumer} must not consume the global advisory ignores before "
                "the dedicated exception gate succeeds",
            )


if __name__ == "__main__":
    unittest.main()
