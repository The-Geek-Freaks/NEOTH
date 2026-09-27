import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

MODULE_PATH = Path(__file__).parents[1] / "n8n_update_target_preflight_canary.py"
SPEC = importlib.util.spec_from_file_location("update_target_canary", MODULE_PATH)
canary = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = canary
SPEC.loader.exec_module(canary)

def result(code=0, stdout=b"", stderr=b"", timed_out=False, overflow=False):
    return canary.Result(code, stdout, stderr, timed_out, overflow)

def target(config_digest):
    return json.dumps({"selector": "n8n-2.40.7", "version": canary.VERSION, "platform": canary.PLATFORM, "runtime_image": canary.RUNTIME_IMAGE, "index_digest": canary.INDEX_DIGEST, "child_manifest_digest": canary.CHILD_MANIFEST_DIGEST, "config_digest": config_digest, "catalog_evidence_sha256": canary.CATALOG_EVIDENCE_SHA256}).encode()

class UpdateTargetCanaryTests(unittest.TestCase):
    def test_valid_cli_projection_requires_genuine_selector(self):
        config = "sha256:" + "a" * 64
        self.assertEqual(canary.validate_target(canary.parse_json(target(config), "target"))["selector"], "n8n-2.40.7")
        wrong = json.loads(target(config)); wrong["selector"] = "n8n"
        with self.assertRaises(canary.Failure): canary.validate_target(wrong)

    def test_docker_verification_is_inspect_only_and_rejects_identity_mismatch(self):
        config = "sha256:" + "b" * 64
        good = json.dumps([{"Id": config, "Os": "linux", "Architecture": "amd64", "RepoDigests": ["index.docker.io/" + canary.RUNTIME_IMAGE.removeprefix("docker.io/")]}]).encode()
        with patch.object(canary, "run", return_value=result(stdout=good)) as mocked:
            self.assertEqual(canary.verify_docker_image(canary.RUNTIME_IMAGE, config)["id"], config)
        self.assertEqual(mocked.call_args.args[0], ("docker", "image", "inspect", canary.RUNTIME_IMAGE))
        wrong = json.dumps([{"Id": config, "Os": "linux", "Architecture": "amd64", "RepoDigests": ["n8nio/n8n@sha256:" + "d" * 64]}]).encode()
        with patch.object(canary, "run", return_value=result(stdout=wrong)):
            with self.assertRaises(canary.Failure): canary.verify_docker_image(canary.RUNTIME_IMAGE, config)

    def test_negative_controls_require_expected_errors_and_no_docker_shim_invocation(self):
        with tempfile.TemporaryDirectory() as temporary:
            calls = []
            def fake_run(argv, timeout, env):
                calls.append((tuple(argv), env))
                marker = b"n8n_update_target_selector_not_admitted" if "n8n-0.0.0" in argv else b"invalid value"
                return result(code=2, stderr=marker)
            with patch.object(canary, "run", side_effect=fake_run):
                evidence = canary.verify_negative_controls(Path("/tmp/neoth"), Path(temporary))
        self.assertEqual(set(evidence), {"unknown_selector", "unsupported_platform"})
        self.assertTrue(all(call[1]["PATH"].startswith(str(temporary)) for call in calls))

    def test_negative_controls_fail_if_docker_shim_records_an_invocation(self):
        with tempfile.TemporaryDirectory() as temporary:
            def fake_run(argv, timeout, env):
                Path(env["W1592_DOCKER_SHIM_LOG"]).write_text("x", encoding="utf-8")
                return result(code=2, stderr=b"n8n_update_target_selector_not_admitted")
            with patch.object(canary, "run", side_effect=fake_run):
                with self.assertRaises(canary.Failure): canary.verify_negative_controls(Path("/tmp/neoth"), Path(temporary))

    def test_negative_controls_reject_timeout_and_overflow(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(canary, "run", return_value=result(code=2, stderr=b"n8n_update_target_selector_not_admitted", timed_out=True)):
                with self.assertRaises(canary.Failure): canary.verify_negative_controls(Path("/tmp/neoth"), Path(temporary))
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(canary, "run", return_value=result(code=2, stderr=b"n8n_update_target_selector_not_admitted", overflow=True)):
                with self.assertRaises(canary.Failure): canary.verify_negative_controls(Path("/tmp/neoth"), Path(temporary))

    def test_home_must_remain_empty_and_rejects_symlink_or_content(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            self.assertEqual(canary.require_empty_home(home)["count"], 0)
            (home / "drift").write_text("x", encoding="utf-8")
            with self.assertRaises(canary.Failure): canary.require_empty_home(home)
            (home / "drift").unlink()
            (home / "linked-drift").symlink_to(home / "missing")
            with self.assertRaises(canary.Failure): canary.require_empty_home(home)

    def test_failure_projection_redacts_raw_and_marks_timeout_or_overflow(self):
        diagnostic = canary.safe_failure(result(1, b"TOKEN=leak", b"password=leak", True, True))
        rendered = json.dumps(diagnostic)
        self.assertNotIn("TOKEN=leak", rendered); self.assertNotIn("password=leak", rendered)
        self.assertTrue(diagnostic["timed_out"]); self.assertTrue(diagnostic["overflow"])

if __name__ == "__main__": unittest.main()
