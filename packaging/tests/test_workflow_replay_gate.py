from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).parents[1] / "workflow_replay_gate.py"
SPEC = importlib.util.spec_from_file_location("workflow_replay_gate", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)

HEAD = "a" * 40
DIGEST = "b" * 64


def fingerprint() -> str:
    return hashlib.sha256(
        b"\x00".join(
            [
                b"workflow-replay-config-v1", b"provider", b"model", b"1",
                b"contains-v1", b"deny_all",
            ]
        )
    ).hexdigest()


def corpus() -> dict[str, object]:
    return {
        "schema_version": 1,
        "kind": "workflow-replay-corpus-v1",
        "provenance": {"label": "operator-curated+inputhash", "input_sha256": DIGEST},
        "episodes": [
            {"episode_id": "one", "prompt": "say hello", "expected_contains": "hello", "skill": None},
            {"episode_id": "two", "prompt": "use the skill", "expected_contains": "done", "skill": "brief"},
        ],
    }


def report(corpus_bytes: bytes) -> dict[str, object]:
    return {
        "schema_version": 1,
        "kind": "workflow-replay-report-v1",
        "corpus_sha256": hashlib.sha256(corpus_bytes).hexdigest(),
        "source_revision": HEAD,
        "scorer": "contains-v1",
        "config": {"provider": "provider", "model": "model", "max_per_request": 1, "fingerprint_sha256": fingerprint(), "effective_public_config_sha256": DIGEST},
        "containment": {
            "transient_home": True,
            "transient_workspace": True,
            "actual_home_effects": ["provider_consent_and_cost_usage_audit"],
            "external_tools": "deny_all",
        },
        "episodes": [
            {"episode_id": "one", "outcome": "pass", "reason": None, "provider": "provider", "model": "model", "selected_skill": None, "selected_skill_content_sha256": None, "response_sha256": DIGEST},
            {"episode_id": "two", "outcome": "pass", "reason": None, "provider": "provider", "model": "model", "selected_skill": "brief", "selected_skill_content_sha256": DIGEST, "response_sha256": DIGEST},
        ],
        "passed": True,
    }


class WorkflowReplayGateTests(unittest.TestCase):
    def write_witness(self) -> tuple[tempfile.TemporaryDirectory[str], Path, Path]:
        directory = tempfile.TemporaryDirectory()
        corpus_path = Path(directory.name) / "corpus.json"
        corpus_path.write_text(json.dumps(corpus()), encoding="utf-8")
        report_path = Path(directory.name) / "workflow-replay-report-v1.json"
        report_path.write_text(json.dumps(report(corpus_path.read_bytes())), encoding="utf-8")
        return directory, corpus_path, report_path

    def test_accepts_exact_complete_contained_manual_witness(self) -> None:
        directory, corpus_path, report_path = self.write_witness()
        with directory:
            gate.validate(corpus_path, report_path, HEAD)

    def test_rejects_wrong_bytes_source_or_nonpass_result(self) -> None:
        directory, corpus_path, report_path = self.write_witness()
        with directory:
            data = json.loads(report_path.read_text(encoding="utf-8"))
            data["corpus_sha256"] = DIGEST
            report_path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(gate.WorkflowReplayGateError, "exact supplied corpus bytes"):
                gate.validate(corpus_path, report_path, HEAD)
            data["corpus_sha256"] = hashlib.sha256(corpus_path.read_bytes()).hexdigest()
            data["source_revision"] = "c" * 40
            report_path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(gate.WorkflowReplayGateError, "exact release candidate"):
                gate.validate(corpus_path, report_path, HEAD)
            data["source_revision"] = HEAD
            data["episodes"][1]["outcome"] = "fail"
            report_path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(gate.WorkflowReplayGateError, "did not pass"):
                gate.validate(corpus_path, report_path, HEAD)

    def test_rejects_episode_set_and_containment_drift(self) -> None:
        directory, corpus_path, report_path = self.write_witness()
        with directory:
            data = json.loads(report_path.read_text(encoding="utf-8"))
            data["episodes"][1]["episode_id"] = "one"
            report_path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(gate.WorkflowReplayGateError, "duplicate episode_id"):
                gate.validate(corpus_path, report_path, HEAD)
            data = report(corpus_path.read_bytes())
            data["containment"]["external_tools"] = "allowed"
            report_path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(gate.WorkflowReplayGateError, "deny_all"):
                gate.validate(corpus_path, report_path, HEAD)

    def test_rejects_incoherent_or_unhashed_skills_and_reply(self) -> None:
        directory, corpus_path, report_path = self.write_witness()
        with directory:
            data = json.loads(report_path.read_text(encoding="utf-8"))
            data["episodes"][0]["selected_skill"] = "brief"
            report_path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(gate.WorkflowReplayGateError, "incoherent auto-routed skill pair"):
                gate.validate(corpus_path, report_path, HEAD)
            data = report(corpus_path.read_bytes())
            data["episodes"][0]["selected_skill"] = "brief"
            data["episodes"][0]["selected_skill_content_sha256"] = DIGEST
            report_path.write_text(json.dumps(data), encoding="utf-8")
            gate.validate(corpus_path, report_path, HEAD)
            data = report(corpus_path.read_bytes())
            data["episodes"][1]["selected_skill_content_sha256"] = None
            report_path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(gate.WorkflowReplayGateError, "selected_skill_content_sha256"):
                gate.validate(corpus_path, report_path, HEAD)

    def test_rejects_duplicate_json_key_bool_schema_and_config_fingerprint_drift(self) -> None:
        directory, corpus_path, report_path = self.write_witness()
        with directory:
            corpus_path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
            with self.assertRaisesRegex(gate.WorkflowReplayGateError, "duplicate key"):
                gate.validate(corpus_path, report_path, HEAD)
            corpus_path.write_text(json.dumps(corpus()), encoding="utf-8")
            data = report(corpus_path.read_bytes())
            data["schema_version"] = True
            report_path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(gate.WorkflowReplayGateError, "report must be"):
                gate.validate(corpus_path, report_path, HEAD)
            data["schema_version"] = 1
            data["config"]["fingerprint_sha256"] = DIGEST
            report_path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(gate.WorkflowReplayGateError, "config projection"):
                gate.validate(corpus_path, report_path, HEAD)
            data = report(corpus_path.read_bytes())
            data["config"]["effective_public_config_sha256"] = "not-a-digest"
            report_path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(gate.WorkflowReplayGateError, "effective_public_config_sha256"):
                gate.validate(corpus_path, report_path, HEAD)

    def test_rejects_float_schema_and_accepts_rust_optional_skill_field(self) -> None:
        directory, corpus_path, report_path = self.write_witness()
        with directory:
            raw_corpus = corpus()
            raw_corpus["episodes"][0].pop("skill")
            corpus_path.write_text(json.dumps(raw_corpus), encoding="utf-8")
            report_path.write_text(json.dumps(report(corpus_path.read_bytes())), encoding="utf-8")
            gate.validate(corpus_path, report_path, HEAD)
            data = json.loads(report_path.read_text(encoding="utf-8"))
            data["schema_version"] = 1.0
            report_path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(gate.WorkflowReplayGateError, "report must be"):
                gate.validate(corpus_path, report_path, HEAD)

    def test_emitted_content_free_manifest_is_accepted_without_raw_replay_data(self) -> None:
        directory, corpus_path, report_path = self.write_witness()
        with directory:
            manifest_path = Path(directory.name) / "witness.json"
            original = gate.validate(corpus_path, report_path, HEAD)
            manifest_path.write_text(json.dumps(original), encoding="utf-8")
            gate.validate_manifest(manifest_path, HEAD)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertNotIn("prompt", json.dumps(manifest))
            self.assertNotIn("expected_contains", json.dumps(manifest))
            self.assertNotIn("response_sha256", manifest)
            self.assertEqual(manifest["effective_public_config_sha256"], DIGEST)

    def test_manifest_rejects_raw_fields_and_all_core_claim_drift(self) -> None:
        directory, corpus_path, report_path = self.write_witness()
        with directory:
            manifest_path = Path(directory.name) / "witness.json"
            manifest = gate.validate(corpus_path, report_path, HEAD)
            manifest["prompt"] = "must never leave the operator machine"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(gate.WorkflowReplayGateError, "unsupported or missing fields"):
                gate.validate_manifest(manifest_path, HEAD)
            manifest.pop("prompt")
            for field, value, message in (
                ("source_revision", "c" * 40, "exact release candidate"),
                ("episode_count", 0, "episode_count"),
                ("passed", False, "passed contains-v1"),
            ):
                altered = dict(manifest)
                altered[field] = value
                manifest_path.write_text(json.dumps(altered), encoding="utf-8")
                with self.assertRaisesRegex(gate.WorkflowReplayGateError, message):
                    gate.validate_manifest(manifest_path, HEAD)
            altered = dict(manifest)
            altered["containment"] = dict(manifest["containment"])
            altered["containment"]["transient_home"] = False
            manifest_path.write_text(json.dumps(altered), encoding="utf-8")
            with self.assertRaisesRegex(gate.WorkflowReplayGateError, "transient home"):
                gate.validate_manifest(manifest_path, HEAD)
            altered = dict(manifest)
            altered["effective_public_config_sha256"] = "not-a-digest"
            manifest_path.write_text(json.dumps(altered), encoding="utf-8")
            with self.assertRaisesRegex(gate.WorkflowReplayGateError, "effective_public_config_sha256"):
                gate.validate_manifest(manifest_path, HEAD)

    def test_episode_id_digest_is_collision_free_for_embedded_nul(self) -> None:
        self.assertNotEqual(
            gate._episode_ids_sha256(["a\0b", "c"]),
            gate._episode_ids_sha256(["a", "b\0c"]),
        )

    def test_direct_cli_exit_codes_cover_valid_manifest_and_missing_inputs(self) -> None:
        directory, corpus_path, report_path = self.write_witness()
        with directory:
            manifest_path = Path(directory.name) / "witness.json"
            self.assertEqual(
                gate.main([
                    "--corpus", str(corpus_path), "--report", str(report_path),
                    "--expected-source-revision", HEAD, "--emit-manifest", str(manifest_path),
                ]),
                0,
            )
            self.assertEqual(
                gate.main(["--manifest", str(manifest_path), "--expected-source-revision", HEAD]),
                0,
            )
            self.assertEqual(gate.main(["--expected-source-revision", HEAD]), 1)


if __name__ == "__main__":
    unittest.main()
