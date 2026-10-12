from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import subprocess
import sys
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).parents[1] / "workflow_compare_gate.py"
SPEC = importlib.util.spec_from_file_location("workflow_compare_gate", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
compare = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(compare)

HEAD = "a" * 40
SKILL_A = "b" * 64
SKILL_B = "c" * 64
PUBLIC_CONFIG = "d" * 64


class WorkflowComparisonTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.paths = {
            name: self.root / f"{name}.json"
            for name in ("protocol", "corpus", "baseline", "candidate", "out")
        }
        self.corpus = {
            "schema_version": 1, "kind": "workflow-replay-corpus-v1",
            "provenance": {
                "label": "operator-curated+inputhash", "input_sha256": "e" * 64,
            },
            "episodes": [
                {"episode_id": name, "prompt": "PRIVATE_PROMPT_CANARY",
                 "expected_contains": "expected", "skill": "brief"}
                for name in ("consent", "format", "recovery")
            ],
        }
        self.write("corpus", self.corpus)
        self.config = {
            "provider": "test-provider", "model": "fixed-model",
            "max_per_request": 512,
            "fingerprint_sha256": compare.replay._config_fingerprint(
                "test-provider", "fixed-model", 512
            ),
            "effective_public_config_sha256": PUBLIC_CONFIG,
        }
        self.protocol = {
            "schema_version": 1,
            "kind": "workflow-replay-comparison-protocol-v1",
            "source_revision": HEAD,
            "corpus_sha256": self.digest("corpus"),
            "episode_ids": ["consent", "format", "recovery"],
            "scorer": "contains-v1", "config": self.config,
            "baseline": {
                "id": "before", "skill_id": "brief", "skill_content_sha256": SKILL_A,
            },
            "candidate": {
                "id": "after", "skill_id": "brief", "skill_content_sha256": SKILL_B,
            },
            "hard_case_ids": ["consent", "recovery"],
        }
        self.write("protocol", self.protocol)
        self.protocol_hash = self.digest("protocol")
        self.before = self.report(SKILL_A, ("pass", "fail", "error"))
        self.after = self.report(SKILL_B, ("fail", "pass", "error"))
        self.write("baseline", self.before)
        self.write("candidate", self.after)

    def write(self, name: str, data: object) -> None:
        self.paths[name].write_text(json.dumps(data), encoding="utf-8")

    def digest(self, name: str) -> str:
        return hashlib.sha256(self.paths[name].read_bytes()).hexdigest()

    def report(self, skill_hash: str, outcomes: tuple[str, ...]) -> dict[str, object]:
        rows = []
        for name, outcome in zip(self.protocol["episode_ids"], outcomes):
            early_error = outcome == "error"
            rows.append({
                "episode_id": name, "outcome": outcome,
                "reason": None if outcome == "pass" else "PRIVATE_REASON_CANARY",
                "provider": self.config["provider"], "model": self.config["model"],
                "selected_skill": None if early_error else "brief",
                "selected_skill_content_sha256": None if early_error else skill_hash,
                "response_sha256": None if early_error else "f" * 64,
            })
        return {
            "schema_version": 1, "kind": "workflow-replay-report-v1",
            "corpus_sha256": self.protocol["corpus_sha256"], "source_revision": HEAD,
            "scorer": "contains-v1", "config": copy.deepcopy(self.config),
            "containment": copy.deepcopy(compare.CONTAINMENT),
            "episodes": rows, "passed": all(outcome == "pass" for outcome in outcomes),
        }

    def invoke(self) -> int:
        arguments = []
        for name, path in self.paths.items():
            arguments.extend((f"--{name}", str(path)))
        arguments.extend((
            "--expected-protocol-sha256", self.protocol_hash,
            "--expected-source-revision", HEAD,
        ))
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return compare.main(arguments)

    def assert_rejected(self) -> None:
        self.assertEqual(self.invoke(), 1)
        self.assertFalse(self.paths["out"].exists())

    def test_cli_preserves_errors_regressions_and_unknown_measurements(self) -> None:
        self.assertEqual(self.invoke(), 0)
        raw = self.paths["out"].read_text(encoding="utf-8")
        witness = json.loads(raw)
        self.assertEqual(witness["baseline"], {"pass": 1, "fail": 1, "error": 1})
        self.assertEqual(witness["candidate"], {"pass": 1, "fail": 1, "error": 1})
        self.assertEqual(witness["regression_indices"], [0])
        self.assertEqual(witness["hard_case_regression_indices"], [0])
        self.assertEqual(witness["candidate_hard_case_failure_indices"], [0, 2])
        self.assertEqual(
            witness["unobserved_variant_indices"], {"baseline": [2], "candidate": [2]}
        )
        self.assertEqual(witness["candidate_report_sha256"], self.digest("candidate"))
        self.assertEqual(witness["protocol_sha256"], self.protocol_hash)
        self.assertEqual(witness["result"], "measurement_only")
        self.assertIs(witness["comparison_complete"], False)
        self.assertIs(witness["inconclusive"], True)
        self.assertIs(witness["reported_containment_matches_contract"], True)
        self.assertIs(witness["historical_preregistration_verified"], False)
        self.assertIs(witness["automatic_promotion"], False)
        self.assertEqual(witness["cost_status"], "unknown")
        self.assertEqual(witness["token_usage_status"], "unknown")
        self.assertEqual(witness["provider_attempt_count_status"], "unknown")
        self.assertNotIn("PRIVATE_", raw)
        self.assertNotIn('"consent"', raw)
        # The unchanged release gate still refuses this failed report.
        with self.assertRaises(compare.Error):
            compare.replay.validate(self.paths["corpus"], self.paths["candidate"], HEAD)

    def test_observed_gain_never_authorizes_promotion(self) -> None:
        self.write("baseline", self.report(SKILL_A, ("pass", "fail", "fail")))
        self.write("candidate", self.report(SKILL_B, ("pass", "pass", "pass")))
        self.assertEqual(self.invoke(), 0)
        witness = json.loads(self.paths["out"].read_text(encoding="utf-8"))
        self.assertEqual(witness["candidate_minus_baseline_passes"], 2)
        self.assertIs(witness["comparison_complete"], True)
        self.assertIs(witness["inconclusive"], False)
        self.assertEqual(witness["candidate_hard_case_failure_indices"], [])
        self.assertEqual(witness["result"], "measurement_only")
        self.assertIs(witness["automatic_promotion"], False)

    def test_early_and_observed_errors_remain_in_the_denominator(self) -> None:
        self.after["episodes"][2]["selected_skill"] = "brief"
        self.after["episodes"][2]["selected_skill_content_sha256"] = SKILL_B
        self.after["episodes"][2]["response_sha256"] = "f" * 64
        self.write("candidate", self.after)
        self.assertEqual(self.invoke(), 0)
        witness = json.loads(self.paths["out"].read_text(encoding="utf-8"))
        self.assertEqual(witness["candidate"]["error"], 1)
        self.assertEqual(witness["unobserved_variant_indices"]["candidate"], [])
        self.assertEqual(witness["unobserved_variant_indices"]["baseline"], [2])

    def test_provider_default_is_not_fixed_model_evidence(self) -> None:
        self.protocol["config"]["model"] = "provider_default"
        self.protocol["config"]["fingerprint_sha256"] = compare.replay._config_fingerprint(
            "test-provider", "provider_default", 512
        )
        self.write("protocol", self.protocol)
        self.protocol_hash = self.digest("protocol")
        self.assert_rejected()

    def test_changed_protocol_bytes_or_posthoc_hard_cases_are_rejected(self) -> None:
        self.protocol["hard_case_ids"] = ["format"]
        self.write("protocol", self.protocol)
        self.assert_rejected()

    def test_source_corpus_and_case_order_must_match(self) -> None:
        for field, value in (
            ("source_revision", "9" * 40),
            ("corpus_sha256", "9" * 64),
            ("episodes", list(reversed(self.after["episodes"]))),
            ("episodes", self.after["episodes"][:-1]),
            ("episodes", [self.after["episodes"][0]] * 3),
        ):
            with self.subTest(field=field, value=value):
                changed = copy.deepcopy(self.after)
                changed[field] = value
                self.write("candidate", changed)
                self.assert_rejected()

    def test_model_cap_config_and_actual_episode_model_are_bound(self) -> None:
        for field, value in (
            ("provider", "other"), ("model", "other"),
            ("max_per_request", 1024), ("max_per_request", True),
            ("effective_public_config_sha256", "9" * 64),
            ("fingerprint_sha256", "9" * 64),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.after)
                changed["config"][field] = value
                self.write("candidate", changed)
                self.assert_rejected()
        changed = copy.deepcopy(self.after)
        changed["episodes"][0]["model"] = "fallback-model"
        self.write("candidate", changed)
        self.assert_rejected()

    def test_skill_observation_cannot_be_fabricated_or_dropped(self) -> None:
        for field, value in (
            ("selected_skill", "foreign"),
            ("selected_skill_content_sha256", SKILL_A),
            ("selected_skill_content_sha256", None),
            ("response_sha256", None),
            ("response_sha256", "not-a-digest"),
        ):
            with self.subTest(field=field, value=value):
                changed = copy.deepcopy(self.after)
                changed["episodes"][1][field] = value
                self.write("candidate", changed)
                self.assert_rejected()
        changed = copy.deepcopy(self.after)
        changed["episodes"][2]["selected_skill"] = "brief"
        self.write("candidate", changed)
        self.assert_rejected()

    def test_equal_variants_and_unplanned_corpus_skill_are_rejected(self) -> None:
        self.protocol["candidate"]["skill_content_sha256"] = SKILL_A
        self.write("protocol", self.protocol)
        self.protocol_hash = self.digest("protocol")
        self.assert_rejected()
        self.protocol["candidate"]["skill_content_sha256"] = SKILL_B
        self.corpus["episodes"][0]["skill"] = None
        self.write("corpus", self.corpus)
        self.protocol["corpus_sha256"] = self.digest("corpus")
        self.write("protocol", self.protocol)
        self.protocol_hash = self.digest("protocol")
        self.assert_rejected()

    def test_report_shape_and_containment_fail_closed(self) -> None:
        for field, value in (
            ("schema_version", True), ("passed", 1), ("passed", True),
            ("episodes", None), ("extra", "unreviewed"),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.after)
                changed[field] = value
                self.write("candidate", changed)
                self.assert_rejected()
        for field, value in (("external_tools", "allow"), ("transient_home", 1)):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.after)
                changed["containment"][field] = value
                self.write("candidate", changed)
                self.assert_rejected()

    def test_duplicate_json_keys_and_size_limit_are_enforced(self) -> None:
        self.paths["candidate"].write_text(
            '{"schema_version":1,"schema_version":1}', encoding="utf-8"
        )
        self.assert_rejected()
        self.paths["candidate"].write_bytes(b" " * (compare.replay.MAX_ARTIFACT_BYTES + 1))
        self.assert_rejected()

    def test_fresh_cli_process_loads_helpers_and_writes_only_measurement(self) -> None:
        arguments = [sys.executable, str(SCRIPT)]
        for name, path in self.paths.items():
            arguments.extend((f"--{name}", str(path)))
        arguments.extend((
            "--expected-protocol-sha256", self.protocol_hash,
            "--expected-source-revision", HEAD,
        ))
        result = subprocess.run(
            arguments, check=False, capture_output=True, text=True, timeout=15,
            cwd=self.root,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        witness = json.loads(self.paths["out"].read_text(encoding="utf-8"))
        self.assertIs(witness["automatic_promotion"], False)
        self.assertNotIn("PRIVATE_", result.stdout + result.stderr)

    def test_output_is_exclusive_and_inputs_are_never_replaced(self) -> None:
        self.paths["out"].write_text("keep me", encoding="utf-8")
        self.assertEqual(self.invoke(), 1)
        self.assertEqual(self.paths["out"].read_text(encoding="utf-8"), "keep me")
        self.paths["out"] = self.paths["candidate"]
        before = self.paths["candidate"].read_bytes()
        self.assertEqual(self.invoke(), 1)
        self.assertEqual(self.paths["candidate"].read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
