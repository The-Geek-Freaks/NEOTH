"""Pure helper checks for the hosted compiled-product bootstrap canary."""
from __future__ import annotations

import sys
import json
import http.server
import os
import tempfile
import threading
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import n8n_product_bootstrap_canary as canary


class ProductReceiptTests(unittest.TestCase):
    def test_product_output_requires_ready_and_nonempty_job(self) -> None:
        job = "12345678-1234-7234-8234-123456789abc"
        self.assertEqual(canary.validate_product({"job_id": job, "state": "ready", "failure_code": None}), job)
        for row in ({"job_id": "", "state": "ready", "failure_code": None}, {"job_id": job, "state": "failed", "failure_code": None}, {"job_id": job, "state": "ready", "failure_code": "x"}):
            with self.subTest(row=row):
                with self.assertRaises(canary.Failure): canary.validate_product(row)

    def test_status_rejects_wrong_endpoint_or_incomplete_progress(self) -> None:
        job = "12345678-1234-7234-8234-123456789abc"
        status = {"job": {"id": job, "state": "ready", "completed_steps": 4, "total_steps": 4, "failure_code": None}, "configured_endpoint": "http://127.0.0.1:5681", "api_key_present": True}
        canary.validate_status(status, job, 5681)
        status["job"]["completed_steps"] = 3
        with self.assertRaisesRegex(canary.Failure, "status_progress_invalid"): canary.validate_status(status, job, 5681)

    def test_custody_rejects_foreign_runtime_or_noncanonical_volume(self) -> None:
        job, digest, identifier, volume = "12345678-1234-7234-8234-123456789abc", "a" * 64, "b" * 64, "neoth_n8n_" + "c" * 32
        boot = {"schema_version": 2, "phase": "Ready", "job_id": job, "manifest_sha256": digest, "volume_name": volume, "bootstrap_container_id": identifier, "runtime_container_id": identifier, "host_port": 5681, "pinned_image": canary.IMAGE}
        runtime = {"schema_version": 2, "phase": "Ready", "job_id": job, "manifest_sha256": digest, "container_id": identifier, "container_name": "neoth-n8n", "host_port": 5681, "volume": volume, "image": canary.IMAGE}
        self.assertEqual(canary.validate_custody(boot, runtime, job, 5681), (volume, identifier, identifier))
        runtime["manifest_sha256"] = "f" * 64
        with self.assertRaisesRegex(canary.Failure, "custody_manifest_mismatch"):
            canary.validate_custody(boot, runtime, job, 5681)
        runtime["manifest_sha256"] = digest
        runtime["container_name"] = "foreign"
        with self.assertRaises(canary.Failure): canary.validate_custody(boot, runtime, job, 5681)


class ProductUninstallReceiptTests(unittest.TestCase):
    source_job = "12345678-1234-7234-8234-123456789abc"
    uninstall_job = "abcdef12-1234-7234-8234-123456789abc"
    manifest = "a" * 64
    volume = "neoth_n8n_" + "b" * 32

    def uninstall_output(self) -> dict:
        return {"job_id": self.uninstall_job, "operation": "uninstall", "state": "ready", "failure_code": None, "disposition": "container_removed_data_volume_retained", "config_cleanup": "preserved_unproven", "data_volume_policy": "retain"}

    def test_uninstall_output_requires_distinct_ready_retained_disposition(self) -> None:
        output = self.uninstall_output()
        self.assertEqual(canary.validate_uninstall_product(output, self.source_job), self.uninstall_job)
        for key, value in (("job_id", self.source_job), ("state", "failed"), ("disposition", "container_removed"), ("config_cleanup", "cleared"), ("data_volume_policy", "purge")):
            with self.subTest(key=key):
                changed = dict(output)
                changed[key] = value
                with self.assertRaisesRegex(canary.Failure, "uninstall_not_ready"):
                    canary.validate_uninstall_product(changed, self.source_job)

    def test_uninstall_status_rejects_wrong_job_or_incomplete_state(self) -> None:
        row = {"id": self.uninstall_job, "operation": "uninstall", "state": "ready", "disposition": "container_removed_data_volume_retained", "config_cleanup": "preserved_unproven", "failure_code": None, "completed_steps": 4, "total_steps": 4}
        canary.validate_uninstall_status({"job": row}, self.uninstall_job)
        for key, value in (("id", self.source_job), ("operation", "install"), ("completed_steps", 3), ("config_cleanup", "cleared")):
            with self.subTest(key=key):
                changed = dict(row)
                changed[key] = value
                with self.assertRaisesRegex(canary.Failure, "uninstall_status_invalid"):
                    canary.validate_uninstall_status({"job": changed}, self.uninstall_job)

    def test_completion_receipt_binds_exact_source_and_uninstall_jobs(self) -> None:
        runtime = "c" * 64
        receipt = {"schema_version": 1, "uninstall_job_id": self.uninstall_job, "uninstall_manifest_sha256": self.manifest, "source_install_job_id": self.source_job, "source_install_manifest_sha256": self.manifest, "cleanup_disposition": "preserved_unproven", "source_container_id": runtime, "source_image": canary.IMAGE, "source_host_port": 5681, "source_volume": self.volume, "source_bootstrap_volume": True, "source_volume_owner_install_job_id": self.source_job, "source_retained_reinstall": None}
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            path = home / f"n8n-uninstall-{self.uninstall_job}.receipt.json"
            path.write_text(json.dumps(receipt))
            observed = canary.read_uninstall_completion_receipt(home, self.uninstall_job, self.manifest, self.source_job, self.manifest, runtime, self.volume, 5681)
            self.assertEqual(observed["bytes"], path.stat().st_size)
            receipt["source_install_job_id"] = "wrong"
            path.write_text(json.dumps(receipt))
            with self.assertRaisesRegex(canary.Failure, "uninstall_completion_receipt_invalid"):
                canary.read_uninstall_completion_receipt(home, self.uninstall_job, self.manifest, self.source_job, self.manifest, runtime, self.volume, 5681)

    def test_reinstall_requires_new_ready_job_and_exact_new_runtime_custody(self) -> None:
        reinstall = "fedcba98-1234-7234-8234-123456789abc"
        output = {"job_id": reinstall, "state": "ready", "probe_binding": "authenticated_n8n_workflows", "failure_code": None}
        self.assertEqual(canary.validate_reinstall_product(output, self.source_job, self.uninstall_job), reinstall)
        runtime = {"schema_version": 2, "phase": "Ready", "job_id": reinstall, "manifest_sha256": self.manifest, "container_id": "c" * 64, "container_name": "neoth-n8n", "host_port": 5681, "volume": self.volume, "image": canary.IMAGE}
        self.assertEqual(canary.validate_reinstalled_custody(runtime, reinstall, self.manifest, self.volume, "d" * 64, 5681), "c" * 64)
        for key, value in (("job_id", self.uninstall_job), ("container_id", "d" * 64), ("volume", "foreign")):
            with self.subTest(key=key):
                changed = dict(runtime)
                changed[key] = value
                with self.assertRaises(canary.Failure):
                    canary.validate_reinstalled_custody(changed, reinstall, self.manifest, self.volume, "d" * 64, 5681)

    def test_reinstall_completion_receipt_requires_original_chain(self) -> None:
        reinstall = "fedcba98-1234-7234-8234-123456789abc"
        final_uninstall = "deafbeef-1234-7234-8234-123456789abc"
        runtime = "c" * 64
        chain = {"uninstall_job_id": self.uninstall_job, "uninstall_manifest_sha256": self.manifest, "source_install_job_id": self.source_job, "source_install_manifest_sha256": self.manifest, "bootstrap_volume": True, "volume_owner_install_job_id": self.source_job}
        receipt = {"schema_version": 1, "uninstall_job_id": final_uninstall, "uninstall_manifest_sha256": self.manifest, "source_install_job_id": reinstall, "source_install_manifest_sha256": self.manifest, "cleanup_disposition": "preserved_unproven", "source_container_id": runtime, "source_image": canary.IMAGE, "source_host_port": 5681, "source_volume": self.volume, "source_bootstrap_volume": True, "source_volume_owner_install_job_id": self.source_job, "source_retained_reinstall": chain}
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            path = home / f"n8n-uninstall-{final_uninstall}.receipt.json"
            path.write_text(json.dumps(receipt))
            canary.read_reinstall_uninstall_completion_receipt(home, final_uninstall, self.manifest, reinstall, self.manifest, runtime, self.volume, 5681, self.uninstall_job, self.manifest, self.source_job, self.manifest)
            receipt["source_retained_reinstall"]["source_install_job_id"] = "wrong"
            path.write_text(json.dumps(receipt))
            with self.assertRaisesRegex(canary.Failure, "reinstall_uninstall_completion_receipt_invalid"):
                canary.read_reinstall_uninstall_completion_receipt(home, final_uninstall, self.manifest, reinstall, self.manifest, runtime, self.volume, 5681, self.uninstall_job, self.manifest, self.source_job, self.manifest)

    def test_reinstall_repeat_requires_documented_pre_effect_rejection(self) -> None:
        binary = Path("neoth")
        result = canary.bounded.Result(1, b"", b"n8n_retained_reinstall_already_active", False, False)
        with patch.object(canary.bounded, "run", return_value=result) as command:
            self.assertEqual(canary.assert_reinstall_repeat_rejected(binary, self.uninstall_job, b"private-key\n"), {"exit_code": 1, "reason": "active_runtime_pre_effect_rejection"})
        argv = command.call_args.args[0]
        self.assertNotIn("private-key", json.dumps(argv))
        self.assertEqual(command.call_args.kwargs["payload"], b"private-key\n")

    def test_retained_volume_rejects_wrong_id_volume_or_job(self) -> None:
        row = {"Name": self.volume, "Labels": {"io.neoth.managed": "n8n", "io.neoth.n8n-job": self.source_job, "io.neoth.n8n-bootstrap": "v2"}}
        canary.validate_retained_volume(row, self.source_job, self.volume)
        cases = (("Name", "foreign"), ("io.neoth.n8n-job", "wrong-job"), ("io.neoth.managed", "other"))
        for key, value in cases:
            with self.subTest(key=key):
                changed = {"Name": row["Name"], "Labels": dict(row["Labels"])}
                if key == "Name":
                    changed[key] = value
                else:
                    changed["Labels"][key] = value
                with self.assertRaisesRegex(canary.Failure, "retained_volume_identity_invalid"):
                    canary.validate_retained_volume(changed, self.source_job, self.volume)

    def test_cleanup_accepts_product_absent_runtime_but_removes_only_exact_volume(self) -> None:
        volume_row = {"Name": self.volume, "Labels": {"io.neoth.managed": "n8n", "io.neoth.n8n-job": self.source_job, "io.neoth.n8n-bootstrap": "v2"}}
        with patch.object(canary, "exact_absent", side_effect=[True, True]) as absent, patch.object(canary, "docker_inspect", return_value=volume_row) as inspect, patch.object(canary, "run") as command:
            self.assertTrue(canary.cleanup_owned_runtime_and_volume("c" * 64, self.volume, self.source_job, 5681, True))
        inspect.assert_called_once_with(self.volume)
        command.assert_called_once_with(["docker", "volume", "rm", self.volume])
        self.assertEqual(absent.call_args_list[0].args, ("container", "c" * 64))
        self.assertEqual(absent.call_args_list[1].args, ("volume", self.volume))

    def test_canonical_keychain_key_requires_a_bounded_non_control_value(self) -> None:
        with patch.object(canary, "run", return_value=b"canonical-key\n") as lookup:
            self.assertEqual(canary.canonical_n8n_api_key(), b"canonical-key")
        lookup.assert_called_once_with(["secret-tool", "lookup", "neoth-key", "n8n_api_key"], timeout=10)
        for value in (b"short", b"contains\x00control"):
            with self.subTest(value=value):
                with patch.object(canary, "run", return_value=value):
                    with self.assertRaisesRegex(canary.Failure, "canonical_n8n_key_unavailable"):
                        canary.canonical_n8n_api_key()
    def test_active_runtime_or_uninstall_sidecar_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            for name in ("n8n-managed-runtime.v2.json", "n8n-managed-uninstall.v1.json"):
                with self.subTest(name=name):
                    (home / name).write_text("{}")
                    with self.assertRaisesRegex(canary.Failure, "active_sidecar_retained"):
                        canary.sidecar_absent(home, name)
                    (home / name).unlink()

    def test_exact_job_snapshot_detects_changes_outside_progress_fields(self) -> None:
        row = {"job_id": self.source_job, "operation": "install", "state": "ready", "state_revision": 4, "completed_steps": 4, "total_steps": 4, "manifest_sha256": self.manifest, "ready_evidence_json": "original"}
        with patch.object(canary, "run", return_value=json.dumps([row]).encode()):
            before = canary.observe_exact_job(Path("fixture"), self.source_job, "install")
        row["ready_evidence_json"] = "changed"
        with patch.object(canary, "run", return_value=json.dumps([row]).encode()):
            after = canary.observe_exact_job(Path("fixture"), self.source_job, "install")
        self.assertNotEqual(before["row_sha256"], after["row_sha256"])

    def test_full_job_observer_uses_persisted_import_operation(self) -> None:
        row = {"job_id": self.source_job, "operation": "import"}
        with patch.object(canary, "run", return_value=json.dumps(row).encode()):
            self.assertIsInstance(canary.observe_full_job_row(Path("fixture"), self.source_job, "import"), str)
            with self.assertRaisesRegex(canary.Failure, "full_job_row_invalid"):
                canary.observe_full_job_row(Path("fixture"), self.source_job, "import_inactive_workflows")

    def test_failed_uninstall_cleanup_reconciles_absence_before_any_container_remove(self) -> None:
        volume_row = {"Name": self.volume, "Labels": {"io.neoth.managed": "n8n", "io.neoth.n8n-job": self.source_job, "io.neoth.n8n-bootstrap": "v2"}}
        with patch.object(canary, "exact_absent", side_effect=[True, True, True]), patch.object(canary, "docker_inspect", return_value=volume_row), patch.object(canary, "run") as command:
            self.assertTrue(canary.cleanup_owned_runtime_and_volume("c" * 64, self.volume, self.source_job, 5681, False))
        command.assert_called_once_with(["docker", "volume", "rm", self.volume])
class CustodyBoundaryTests(unittest.TestCase):
    def test_purge_plan_requires_exact_uninstall_volume_and_phrase(self) -> None:
        job = "12345678-1234-7234-8234-123456789abc"; volume = "neoth_n8n_" + "a" * 32
        phrase = canary.purge_phrase(job, volume)
        self.assertEqual(canary.validate_purge_plan({"operation":"purge","state":"confirmation_required","uninstall_job_id":job,"volume":volume,"confirmation":phrase}, job, volume), phrase)
        with self.assertRaises(canary.Failure): canary.validate_purge_plan({"operation":"purge","state":"confirmation_required","uninstall_job_id":job,"volume":volume,"confirmation":phrase + "x"}, job, volume)

    def test_purge_ready_response_requires_exact_source_and_disposition(self) -> None:
        uninstall = "12345678-1234-7234-8234-123456789abc"; purge = "22345678-1234-7234-8234-123456789abc"
        value = {"job_id":purge,"operation":"purge","state":"ready","disposition":"volume_removed","uninstall_job_id":uninstall,"failure_code":None}
        self.assertEqual(canary.validate_purge_product(value, uninstall), purge)
        value["uninstall_job_id"] = "32345678-1234-7234-8234-123456789abc"
        with self.assertRaises(canary.Failure): canary.validate_purge_product(value, uninstall)

    def test_cleanup_after_confirmed_purge_does_not_remove_absent_volume(self) -> None:
        with patch.object(canary, "exact_absent", return_value=True), patch.object(canary, "docker_inspect") as inspect, patch.object(canary, "run") as command:
            self.assertTrue(canary.cleanup_owned_runtime_and_volume("a" * 64, "neoth_n8n_" + "b" * 32, "job", 5681, True, True))
        inspect.assert_not_called(); command.assert_not_called()

    def test_wrong_confirmation_witness_requires_no_purge_custody_or_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            self.assertEqual(canary.purge_artifacts_absent(home), ())
            (home / "n8n-managed-purge.v1.json").write_text("{}")
            with self.assertRaisesRegex(canary.Failure, "purge_custody_present"):
                canary.purge_artifacts_absent(home)
            (home / "n8n-managed-purge.v1.json").unlink()
            (home / "n8n-purge-12345678-1234-7234-8234-123456789abc.receipt.json").write_text("{}")
            with self.assertRaisesRegex(canary.Failure, "purge_receipt_present"):
                canary.purge_artifacts_absent(home)
    def test_fresh_product_initialization_precedes_install_and_requires_keychain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            config = home / "freedom.yaml"
            calls = []
            def initialized(argv: list[str], timeout: int = 180) -> bytes:
                calls.append((argv, timeout))
                config.write_text("operator_id: w1127canary\nsecrets_backend: file\n")
                return b""
            with patch.object(canary, "run", side_effect=initialized):
                canary.initialize_product_home(Path("neoth"), home)
            self.assertEqual(calls, [(["neoth", "init", "--non-interactive", "--cli", "--accept-license", "--operator-id", "w1127canary", "--provider", "skip"], 180)])
            self.assertEqual(canary.read_product_config(config)["secrets_backend"], "keychain")
        with patch.object(canary, "initialize_product_home", side_effect=canary.Failure("product_init_config_missing")), patch.object(canary, "read_json_from_command") as install:
            with self.assertRaisesRegex(canary.Failure, "product_init_config_missing"):
                canary.first_product_install(Path("neoth"), Path("unused"), 5681)
        install.assert_not_called()

    def test_workflow_observer_rejects_redirect_without_following_it(self) -> None:
        hits = {"redirect": 0, "target": 0, "source_key": None}
        class RedirectHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                if self.path == "/redirect":
                    hits["redirect"] += 1
                    hits["source_key"] = self.headers.get("X-N8N-API-KEY")
                    self.send_response(302)
                    self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/redirect-target")
                    self.end_headers()
                elif self.path == "/redirect-target":
                    hits["target"] += 1
                    self.send_response(200)
                    self.end_headers()
            def log_message(self, format: str, *args) -> None:
                pass
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with self.assertRaisesRegex(canary.Failure, "workflow_observer_redirect"):
                canary.workflow_api_json(server.server_port, b"test-key", "/redirect")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        self.assertEqual(hits, {"redirect": 1, "target": 0, "source_key": "test-key"})

    def test_workflow_custody_binds_ordered_readbacks_and_manifest(self) -> None:
        job = "12345678-1234-7234-8234-123456789abc"
        manifest = "a" * 64
        observed = tuple((f"workflow_{index}", f"id-{index:02}", f"{index:064x}") for index in range(13))
        entries = "\n".join(
            "  - slug: {slug}\n    source_sha256: {source}\n    create_dto_sha256: {dto}\n    state: !read_back\n      workflow_id: {identifier}\n      normalized_readback_sha256: {graph}".format(
                slug=slug, source=json.dumps("b" * 64), dto=json.dumps("c" * 64), identifier=identifier, graph=json.dumps(graph)
            )
            for slug, identifier, graph in observed
        )
        document = "job_id: {job}\nendpoint_binding_sha256: {binding}\ncredential_binding_sha256: {binding}\nmanifest_sha256: {manifest}\nentries:\n{entries}\n".format(job=job, binding=json.dumps("d" * 64), manifest=json.dumps(manifest), entries=entries)
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            path = home / f".n8n-workflow-import-{job}.custody.yaml"
            path.write_text(document)
            custody = canary.observe_workflow_custody(home, job, observed)
            self.assertEqual(custody["manifest_sha256"], manifest)
            canary.validate_workflow_import_provenance(custody, {"manifest_sha256": manifest})
            path.write_text(document.replace("workflow_id: id-00", "workflow_id: swapped-id", 1))
            with self.assertRaisesRegex(canary.Failure, "workflow_import_custody_invalid"):
                canary.observe_workflow_custody(home, job, observed)
        with self.assertRaisesRegex(canary.Failure, "workflow_import_provenance_mismatch"):
            canary.validate_workflow_import_provenance(custody, {"manifest_sha256": "e" * 64})

    def test_workflow_import_job_rejects_wrong_capability(self) -> None:
        job = "12345678-1234-7234-8234-123456789abc"
        row = f"wrong-capability|import|ready|7|13|13|{'a' * 64}\n".encode()
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(canary, "run", return_value=row):
                with self.assertRaisesRegex(canary.Failure, "workflow_import_job_row_invalid"):
                    canary.observe_import_job(Path(directory), job)

    def test_workflow_template_admission_requires_exact_unique_bundle(self) -> None:
        rows = [{"slug": f"workflow_{index}", "name": f"Workflow {index}"} for index in range(13)]
        self.assertEqual(len(canary.workflow_templates({"workflows": rows})), 13)
        with self.assertRaisesRegex(canary.Failure, "workflow_template_count_invalid"):
            canary.workflow_templates({"workflows": rows[:-1]})
        rows[-1]["slug"] = rows[0]["slug"]
        with self.assertRaisesRegex(canary.Failure, "workflow_template_duplicate"):
            canary.workflow_templates({"workflows": rows})

    def test_workflow_observer_rejects_active_readback(self) -> None:
        templates = tuple((f"workflow_{index}", f"Workflow {index}") for index in range(13))
        listing = {"data": [{"id": str(index), "name": name, "active": False} for index, (_, name) in enumerate(templates)]}
        def observed(_: int, __: bytes, path: str) -> dict:
            if path.endswith("?limit=100"):
                return listing
            identifier = path.rsplit("/", 1)[-1]
            return {"data": {"id": identifier, "name": f"Workflow {identifier}", "active": True, "nodes": [], "connections": {}, "settings": {}}}
        with patch.object(canary, "workflow_api_json", side_effect=observed):
            with self.assertRaisesRegex(canary.Failure, "workflow_observer_readback_invalid"):
                canary.observe_imported_workflows(5681, b"test-key", templates)

    def test_failed_install_job_observer_reports_only_allowlisted_error_code(self) -> None:
        job = "12345678-1234-7234-8234-123456789abc"
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            (home / "n8n-managed-bootstrap.v2.json").write_text(json.dumps({"schema_version": 2, "phase": "BootstrapRemoved", "job_id": job}))
            with patch.object(canary, "run", return_value=b"failed|n8n_loopback_health_timeout\n"):
                observation = canary.observe_failed_install_job(home)
        self.assertEqual(observation, {"state": "failed", "error_code": "n8n_loopback_health_timeout"})
        self.assertNotIn("private", json.dumps(observation))

    def test_probe_failure_categories_are_exact_and_do_not_leak_server_text(self) -> None:
        codes = (
            "n8n_negative_control_unexpected_success", "n8n_negative_control_not_found",
            "n8n_negative_control_server_error", "n8n_negative_control_unexpected_status",
            "n8n_authenticated_not_found", "n8n_authenticated_server_error",
            "n8n_authenticated_unexpected_status", "n8n_response_json_invalid",
            "n8n_response_envelope_invalid", "n8n_response_cursor_invalid",
        )
        job = "12345678-1234-1234-1234-123456789abc"
        secret = "private-response-key-value"
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            (home / "n8n-managed-bootstrap.v2.json").write_text(json.dumps({
                "schema_version": 2, "phase": "BootstrapRemoved", "job_id": job,
            }))
            for code in codes:
                with self.subTest(code=code):
                    result = canary.bounded.Result(1, b"", f"{code}: {secret}".encode(), False, False)
                    failure = canary.CommandFailure(["neoth", "--output", "json", "n8n", "install"], result)
                    self.assertEqual(failure.diagnostic["known_error_categories"], [code])
                    self.assertNotIn(secret, json.dumps(failure.diagnostic))
                    with patch.object(canary, "run", return_value=f"failed|{code}\n".encode()):
                        self.assertEqual(canary.observe_failed_install_job(home), {"state": "failed", "error_code": code})
                    with patch.object(canary, "run", return_value=f"failed|{code}-{secret}\n".encode()):
                        self.assertEqual(canary.observe_failed_install_job(home), {"state": "failed", "error_code": "unclassified"})

    def test_command_diagnosis_reveals_only_fixed_categories(self) -> None:
        secret = "must-never-appear-in-receipt"
        result = canary.bounded.Result(1, secret.encode(), b"Error: n8n_bootstrap_docker_failed " + secret.encode(), False, False)
        failure = canary.CommandFailure(["SRC/target/debug/neoth", "--output", "json", "n8n", "install", secret], result)
        encoded = json.dumps(failure.diagnostic)
        self.assertNotIn(secret, encoded)
        self.assertEqual(failure.diagnostic["command"], "product_install")
        self.assertEqual(failure.diagnostic["exit_code"], 1)
        self.assertEqual(failure.diagnostic["known_error_categories"], ["n8n_bootstrap_docker_failed"])

    def test_inner_transport_category_is_distinct_from_outer_helper_timeout(self) -> None:
        secret = "private-transport-output"
        for suffix in ("empty_command", "spawn_failed", "stdin_failed", "capture_failed",
                       "wait_failed", "timeout", "cancelled", "output_limit"):
            code = "n8n_bootstrap_docker_" + suffix
            with self.subTest(code=code):
                result = canary.bounded.Result(1, secret.encode(), f"{code}: {secret}".encode(), False, False)
                failure = canary.CommandFailure(["neoth", "--output", "json", "n8n", "install", secret], result)
                self.assertEqual(failure.diagnostic["known_error_categories"], [code])
                self.assertFalse(failure.diagnostic["timed_out"])
                self.assertFalse(failure.diagnostic["overflow"])
                self.assertNotIn(secret, json.dumps(failure.diagnostic))

    def test_runtime_diagnosis_reports_source_markers_without_secret_suffix(self) -> None:
        secret = "must-never-appear-in-runtime-diagnosis"
        stderr = (
            b"n8n_container_inspect_unknown "
            b"n8n_managed_container_identity_ambiguous "
            b"stale integration job revision (expected 7, current 8) "
            + secret.encode()
        )
        result = canary.bounded.Result(1, b"", stderr, False, False)
        failure = canary.CommandFailure(
            ["SRC/target/debug/neoth", "--output", "json", "n8n", "install"], result
        )
        encoded = json.dumps(failure.diagnostic)
        self.assertNotIn(secret, encoded)
        self.assertNotIn("expected 7", encoded)
        self.assertEqual(
            failure.diagnostic["known_error_categories"],
            [
                "n8n_container_inspect_unknown",
                "n8n_managed_container_identity_ambiguous",
                "stale integration job revision",
            ],
        )

    def test_command_diagnosis_preserves_timeout_and_overflow_separately(self) -> None:
        result = canary.bounded.Result(-1, b"", b"private unknown failure", True, True)
        failure = canary.CommandFailure(["secret-tool", "lookup", "private-key"], result)
        self.assertEqual(failure.diagnostic["command"], "secret-tool")
        self.assertTrue(failure.diagnostic["timed_out"])
        self.assertTrue(failure.diagnostic["overflow"])
        self.assertEqual(failure.diagnostic["known_error_categories"], [])
        self.assertNotIn("private", json.dumps(failure.diagnostic))

    def test_absence_rejects_identifier_prefix_collision(self) -> None:
        result = canary.bounded.Result(1, b"", b"Error response from daemon: No such container: expected-extra", False, False)
        with patch.object(canary.bounded, "daemon_healthy", return_value=True), patch.object(canary.bounded, "run", return_value=result):
            self.assertFalse(canary.exact_absent("container", "expected"))

    def test_bounded_command_does_not_accept_truncated_success(self) -> None:
        result = canary.bounded.Result(0, b"partial", b"", False, True)
        with patch.object(canary.bounded, "run", return_value=result):
            with self.assertRaisesRegex(canary.Failure, "command_failed"):
                canary.run(["fixture"])

    def test_event_command_suffix_cannot_hide_rebootstrap(self) -> None:
        event = {"Action": "exec_create: node -e fixture", "Actor": {"Attributes": {"io.neoth.n8n-job": "fixture"}}}
        with self.assertRaisesRegex(canary.Failure, "second_call_rebootstrap_event"):
            canary.assert_no_rebootstrap_events(json.dumps(event), "fixture")
        event["Action"] = "die"
        with self.assertRaisesRegex(canary.Failure, "event_owner_mismatch"):
            canary.assert_no_rebootstrap_events(json.dumps(event), "different")

    def test_invalid_hosted_guard_cannot_write_receipt_or_delete_home(self) -> None:
        with patch.object(sys, "argv", ["canary", "--binary", "unused", "--home", "/outside", "--port", "5681", "--receipt", "/outside.json"]), patch.dict(os.environ, {"GITHUB_ACTIONS": "false"}), patch.object(Path, "write_text") as write, patch.object(canary.shutil, "rmtree") as remove, patch.object(canary, "read_json_from_command") as command:
            self.assertEqual(canary.main(), 2)
        write.assert_not_called()
        remove.assert_not_called()
        command.assert_not_called()

    def test_hosted_home_requires_exact_empty_owned_destination(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            home = root / "w1018-n8n-123-1" / "neoth-home"
            home.mkdir(parents=True)
            receipt = home.parent / "receipt" / "receipt.json"
            env = {"GITHUB_ACTIONS": "true", "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": "a" * 40, "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1", "RUNNER_TEMP": str(root), "NEOTH_HOME": str(home)}
            with patch.dict(os.environ, env):
                self.assertEqual(canary.hosted_paths(home, receipt), home.parent)
                (home / "existing-custody").write_text("preserve")
                with self.assertRaisesRegex(canary.Failure, "isolated_path_invalid"):
                    canary.hosted_paths(home, receipt)

    def test_secret_cleanup_rejects_still_present_value(self) -> None:
        result = canary.bounded.Result(0, b"still-present", b"", False, False)
        with patch.object(canary, "run"), patch.object(canary.bounded, "run", return_value=result):
            with self.assertRaisesRegex(canary.Failure, "secret_removal_unproven"):
                canary.clear_bootstrap_secrets("fixture")


if __name__ == "__main__": unittest.main()
