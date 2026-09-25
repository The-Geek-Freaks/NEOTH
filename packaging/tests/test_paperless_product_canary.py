"""Pure boundary checks for the hosted Paperless product canary."""
from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import paperless_product_canary as canary


def container(service: str = "webserver") -> dict:
    project = "neoth-paperless-abcdef123456"
    mounts = [{"Type": "volume", "Name": f"{project}_paperless_consume", "Destination": "/usr/src/paperless/consume"}, {"Type": "volume", "Name": f"{project}_paperless_data", "Destination": "/usr/src/paperless/data"}, {"Type": "volume", "Name": f"{project}_paperless_media", "Destination": "/usr/src/paperless/media"}, {"Type": "volume", "Name": f"{project}_paperless_export", "Destination": "/usr/src/paperless/export"}] if service == "webserver" else [{"Type": "volume", "Name": f"{project}_paperless_valkey", "Destination": "/data"}]
    return {"Id": "a" * 64, "Image": "b" * 64, "State": {"Running": True}, "Config": {"Labels": {"com.docker.compose.project": project, "com.docker.compose.service": service}}, "NetworkSettings": {"Ports": {"8000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "18001"}]} if service == "webserver" else {}}, "Mounts": mounts}


def install_receipt(schema_version: int = 1, volume_set_id: str | None = None) -> dict:
    project = "neoth-paperless-abcdef123456"
    configs = {service: f"sha256:{index:064x}" for index, service in enumerate(canary.IMAGES, start=1)}
    receipt = {
        "schema_version": schema_version, "operation": "install", "project": project,
        "loopback_port": 18001, "authenticated_api_ready": True,
        "images": [{"service": service, "reference": reference, "config_id": configs[service]} for service, reference in canary.IMAGES.items()],
        "containers": [{"service": service, "id": f"{index:064x}", "image_id": configs[service]} for index, service in enumerate(canary.IMAGES, start=10)],
        "volumes": [{"logical_name": logical, "name": f"{project}_{logical}", "project": project, "volume_set_id": volume_set_id} for logical, _, _ in canary.VOLUMES],
    }
    if schema_version == 2:
        receipt["volume_set_id"] = volume_set_id
    return receipt


def install_receipt_bytes() -> bytes:
    return json.dumps(install_receipt(), sort_keys=True).encode("utf-8")


def uninstall_receipt() -> dict:
    installed = install_receipt()
    ids = [row["id"] for row in installed["containers"]]
    return {
        "schema_version": 1, "operation": "paperless.safe_uninstall", "project": installed["project"],
        "phase": "complete", "network_retained": True, "original_container_ids": ids,
        "install_receipt_sha256": hashlib.sha256(install_receipt_bytes()).hexdigest(),
        "retained_volumes": [row["name"] for row in installed["volumes"]],
        "containers": [{"service": service, "id": identifier, "removed": True} for service, identifier in zip(canary.IMAGES, ids, strict=True)],
    }


class CustodyTests(unittest.TestCase):
    def test_docker_inspect_uses_bounded_validator_projection_without_env(self) -> None:
        expected = container()
        with patch.object(canary, "run", return_value=json.dumps(expected).encode("utf-8")) as command:
            observed = canary.docker_json("a" * 64)
        canary.validate_container(observed, "neoth-paperless-abcdef123456", "webserver", "b" * 64, 18001)
        argv = command.call_args.args[0]
        self.assertEqual(argv[:4], ["docker", "container", "inspect", "--format"])
        self.assertNotIn("Env", argv[4])
        self.assertIn("Mounts", argv[4])
        self.assertIn("NetworkSettings", argv[4])

    def test_container_rejects_foreign_label_mount_and_port(self) -> None:
        row = container()
        self.assertEqual(canary.validate_container(row, "neoth-paperless-abcdef123456", "webserver", "b" * 64, 18001), "a" * 64)
        self.assertEqual(len(row["Mounts"]), 4)
        for mutate in (lambda x: x["Config"]["Labels"].update({"com.docker.compose.project": "foreign"}), lambda x: x["Mounts"].__setitem__(0, {"Type": "volume", "Name": "foreign", "Destination": "/usr/src/paperless/consume"}), lambda x: x["Mounts"].append({"Type": "volume", "Name": "anonymous-image-volume", "Destination": "/tmp/foreign"}), lambda x: x["NetworkSettings"]["Ports"]["8000/tcp"][0].update({"HostIp": "0.0.0.0"})):
            bad = container(); mutate(bad)
            with self.subTest(mutate=mutate), self.assertRaises(canary.Failure):
                canary.validate_container(bad, "neoth-paperless-abcdef123456", "webserver", "b" * 64, 18001)

    def test_volume_rejects_foreign_project_or_logical_name(self) -> None:
        row = {"Name": "neoth-paperless-abcdef123456_paperless_data", "Labels": {"com.docker.compose.project": "neoth-paperless-abcdef123456", "com.docker.compose.volume": "paperless_data"}}
        self.assertEqual(canary.validate_volume(row, "neoth-paperless-abcdef123456", "paperless_data"), row["Name"])
        row["Labels"]["com.docker.compose.project"] = "foreign"
        with self.assertRaises(canary.Failure): canary.validate_volume(row, "neoth-paperless-abcdef123456", "paperless_data")

    def test_generated_volume_requires_matching_generation_label(self) -> None:
        generation = "12345678-1234-4234-8234-123456789abc"
        row = {"Name": "neoth-paperless-abcdef123456_paperless_data", "Labels": {"com.docker.compose.project": "neoth-paperless-abcdef123456", "com.docker.compose.volume": "paperless_data", "io.neoth.paperless.volume-set-id": generation}}
        self.assertEqual(canary.validate_volume(row, "neoth-paperless-abcdef123456", "paperless_data", generation), row["Name"])
        row["Labels"]["io.neoth.paperless.volume-set-id"] = "abcdef12-1234-4234-8234-123456789abc"
        with self.assertRaises(canary.Failure):
            canary.validate_volume(row, "neoth-paperless-abcdef123456", "paperless_data", generation)

    def test_install_receipt_accepts_exact_six_volumes_and_rejects_duplicate_or_missing(self) -> None:
        receipt = install_receipt()
        project, _, identities, volume_set_id = canary.validate_install(receipt, 18001)
        self.assertEqual(project, "neoth-paperless-abcdef123456")
        self.assertIsNone(volume_set_id)
        self.assertEqual(len(identities), len(canary.IMAGES) + len(canary.VOLUMES))
        duplicate = install_receipt()
        duplicate["volumes"][-1] = duplicate["volumes"][0].copy()
        with self.assertRaises(canary.Failure): canary.validate_install(duplicate, 18001)
        missing = install_receipt()
        missing["volumes"] = missing["volumes"][:-1]
        with self.assertRaises(canary.Failure): canary.validate_install(missing, 18001)

    def test_schema_two_install_requires_one_canonical_volume_generation_per_volume(self) -> None:
        generation = "12345678-1234-4234-8234-123456789abc"
        receipt = install_receipt(2, generation)
        self.assertEqual(canary.validate_install(receipt, 18001)[3], generation)
        for mutate in (
            lambda value: value.__setitem__("volume_set_id", "not-a-uuid"),
            lambda value: value["volumes"][0].__setitem__("volume_set_id", "abcdef12-1234-4234-8234-123456789abc"),
            lambda value: value["volumes"][0].pop("volume_set_id"),
        ):
            invalid = install_receipt(2, generation); mutate(invalid)
            with self.subTest(mutate=mutate), self.assertRaises(canary.Failure):
                canary.validate_install(invalid, 18001)

    def test_command_failure_is_redacted(self) -> None:
        secret = "must-never-appear-in-a-receipt"
        result = canary.bounded.Result(1, secret.encode(), ("paperless_command_failed " + secret).encode(), False, False)
        failure = canary.CommandFailure(["neoth", "--output", "json", "paperless", "install", secret], result)
        encoded = json.dumps(failure.diagnostic)
        self.assertNotIn(secret, encoded)
        self.assertEqual(failure.diagnostic["command"], "product_install")
        self.assertEqual(failure.diagnostic["known_error_categories"], ["paperless_command_failed"])

    def test_command_failure_discloses_only_exact_lifecycle_markers(self) -> None:
        secret = "private-volume-detail"
        result = canary.bounded.Result(1, b"", ("paperless_volume_ownership_mismatch paperless_legacy_state_migration_required " + secret).encode(), False, False)
        encoded = json.dumps(canary.CommandFailure(["neoth", "--output", "json", "paperless", "install"], result).diagnostic)
        self.assertNotIn(secret, encoded)
        self.assertIn("paperless_volume_ownership_mismatch", encoded)
        self.assertIn("paperless_legacy_state_migration_required", encoded)

    def test_command_failure_allowlists_repair_and_generation_auth_markers_without_output(self) -> None:
        secret = "untrusted-command-output"
        result = canary.bounded.Result(1, secret.encode(), ("paperless_repair_start_outcome_ambiguous paperless_generation_auth_token_conflict " + secret).encode(), False, False)
        encoded = json.dumps(canary.CommandFailure(["neoth", "--output", "json", "paperless", "repair"], result).diagnostic)
        self.assertNotIn(secret, encoded)
        self.assertIn("paperless_repair_start_outcome_ambiguous", encoded)
        self.assertIn("paperless_generation_auth_token_conflict", encoded)

    def test_independent_image_admission_rejects_wrong_digest_or_config(self) -> None:
        reference, config = canary.admitted_images()["webserver"]
        image = {"Id": config, "RepoDigests": [reference], "Os": "linux", "Architecture": "amd64"}
        canary.validate_image(image, reference, config)
        image["RepoDigests"] = ["ghcr.io/paperless-ngx/paperless-ngx@sha256:" + "f" * 64]
        with self.assertRaises(canary.Failure): canary.validate_image(image, reference, config)
        image["RepoDigests"] = [reference]; image["Id"] = "sha256:" + "f" * 64
        with self.assertRaises(canary.Failure): canary.validate_image(image, reference, config)

    def test_hosted_paths_match_real_workflow_and_reject_sibling_missing_or_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory); run_id, attempt = "123", "2"
            root = parent / f"w1146-paperless-{run_id}-{attempt}"; home = root / "neoth-home"; receipt = root / "receipt" / "receipt.json"
            home.mkdir(parents=True); receipt.parent.mkdir()
            env = {"GITHUB_ACTIONS": "true", "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": "a" * 40, "GITHUB_RUN_ID": run_id, "GITHUB_RUN_ATTEMPT": attempt, "RUNNER_TEMP": str(parent), "W1146_ROOT": str(parent), "NEOTH_HOME": str(home.resolve())}
            with patch.dict(os.environ, env, clear=True):
                self.assertEqual(canary.hosted_paths(home, receipt), root)
                sibling = parent / "sibling"; sibling.mkdir()
                with self.assertRaises(canary.Failure): canary.hosted_paths(sibling, receipt)
                with patch.dict(os.environ, {"W1146_ROOT": ""}):
                    with self.assertRaises(canary.Failure): canary.hosted_paths(home, receipt)
                with patch.object(Path, "is_symlink", autospec=True, side_effect=lambda path: path == root):
                    with self.assertRaises(canary.Failure): canary.hosted_paths(home, receipt)

    def test_cleanup_reports_fixed_failure_category(self) -> None:
        with patch.object(canary, "docker_json", side_effect=canary.Failure("container_identity_invalid")):
            self.assertEqual(canary.cleanup("project", {"webserver": "a", "broker": "b", "db": "c"}, ("a" * 64, "b" * 64, "c" * 64, "one", "two", "three", "four", "five", "six"), 18001), (False, "cleanup_ownership_unproven"))

    def test_uninstall_receipt_requires_exact_original_ids_and_all_six_retained_volumes(self) -> None:
        receipt = uninstall_receipt()
        installed = install_receipt()
        ids = tuple(row["id"] for row in installed["containers"])
        volumes = tuple(row["name"] for row in installed["volumes"])
        canary.validate_uninstall(receipt, installed["project"], ids, volumes, install_receipt_bytes())
        bad_ids = uninstall_receipt(); bad_ids["original_container_ids"][0] = "f" * 64
        with self.assertRaises(canary.Failure): canary.validate_uninstall(bad_ids, installed["project"], ids, volumes, install_receipt_bytes())
        missing_volume = uninstall_receipt(); missing_volume["retained_volumes"].pop()
        with self.assertRaises(canary.Failure): canary.validate_uninstall(missing_volume, installed["project"], ids, volumes, install_receipt_bytes())
        wrong_phase = uninstall_receipt(); wrong_phase["phase"] = "containers_removed"
        with self.assertRaises(canary.Failure): canary.validate_uninstall(wrong_phase, installed["project"], ids, volumes, install_receipt_bytes())
        duplicate = uninstall_receipt(); duplicate["containers"][1]["id"] = duplicate["containers"][0]["id"]
        with self.assertRaises(canary.Failure): canary.validate_uninstall(duplicate, installed["project"], ids, volumes, install_receipt_bytes())
        omitted = uninstall_receipt(); omitted["containers"].pop()
        with self.assertRaises(canary.Failure): canary.validate_uninstall(omitted, installed["project"], ids, volumes, install_receipt_bytes())
        hash_mismatch = uninstall_receipt(); hash_mismatch["install_receipt_sha256"] = "0" * 64
        with self.assertRaises(canary.Failure): canary.validate_uninstall(hash_mismatch, installed["project"], ids, volumes, install_receipt_bytes())

    def test_generated_uninstall_requires_ordered_generation_bound_snapshot(self) -> None:
        generation = "12345678-1234-4234-8234-123456789abc"
        installed = install_receipt(2, generation)
        ids = tuple(row["id"] for row in installed["containers"])
        volumes = tuple(row["name"] for row in installed["volumes"])
        receipt = uninstall_receipt()
        receipt["schema_version"] = 2
        receipt["install_receipt_sha256"] = hashlib.sha256(json.dumps(installed, sort_keys=True).encode("utf-8")).hexdigest()
        receipt["retained_volume_snapshot"] = [{"logical_name": logical, "name": name, "project": installed["project"], "volume_set_id": generation} for (logical, _, _), name in zip(canary.VOLUMES, volumes, strict=True)]
        install_raw = json.dumps(installed, sort_keys=True).encode("utf-8")
        canary.validate_uninstall(receipt, installed["project"], ids, volumes, install_raw, generation)
        receipt["retained_volume_snapshot"][0]["volume_set_id"] = "abcdef12-1234-4234-8234-123456789abc"
        with self.assertRaises(canary.Failure):
            canary.validate_uninstall(receipt, installed["project"], ids, volumes, install_raw, generation)

    def test_purge_preview_and_completion_bind_both_receipts_generation_and_six_volumes(self) -> None:
        project, generation = "neoth-paperless-abcdef123456", "12345678-1234-4234-8234-123456789abc"
        install_raw, uninstall_raw = b"install-custody", b"final-uninstall-custody"
        names = tuple(f"{project}_{logical}" for logical, _, _ in canary.VOLUMES)
        phrase = f"PURGE PAPERLESS VOLUME SET {hashlib.sha256(install_raw).hexdigest()} {generation}"
        preview = {"schema_version": 1, "operation": "paperless.confirmed_purge", "state": "confirmation_required", "project": project, "install_receipt_sha256": hashlib.sha256(install_raw).hexdigest(), "uninstall_receipt_sha256": hashlib.sha256(uninstall_raw).hexdigest(), "volume_set_id": generation, "volumes": [{"logical_name": logical, "name": name, "state": "prepared"} for (logical, _, _), name in zip(canary.VOLUMES, names, strict=True)], "confirmation": phrase}
        self.assertEqual(canary.validate_purge_preview(preview, project, install_raw, uninstall_raw, generation, names), phrase)
        completed = dict(preview); completed.pop("confirmation"); completed["state"] = "volumes_removed"; completed["volumes"] = [{"logical_name": logical, "name": name, "state": "absent_verified"} for (logical, _, _), name in zip(canary.VOLUMES, names, strict=True)]
        canary.validate_purge_complete(completed, project, install_raw, uninstall_raw, generation, names)
        completed["volumes"][0]["state"] = "prepared"
        with self.assertRaises(canary.Failure):
            canary.validate_purge_complete(completed, project, install_raw, uninstall_raw, generation, names)

    def test_wrong_confirmation_witness_requires_no_purge_custody_or_terminal_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory); state = home / "paperless" / "state"; state.mkdir(parents=True)
            self.assertEqual(canary.purge_artifacts_absent(home), ())
            for name in (".neoth-paperless-purge-custody.v1.json", ".neoth-paperless-purge-receipt.v1.json"):
                path = state / name; path.write_text("{}")
                with self.subTest(name=name), self.assertRaises(canary.Failure):
                    canary.purge_artifacts_absent(home)
                path.unlink()

    def test_cleanup_after_confirmed_purge_proves_absence_without_volume_remove(self) -> None:
        project, generation = "neoth-paperless-abcdef123456", "12345678-1234-4234-8234-123456789abc"
        identities = ("a" * 64, "b" * 64, "c" * 64) + tuple(f"{project}_{logical}" for logical, _, _ in canary.VOLUMES)
        with patch.object(canary.bounded, "prove_absent"), patch.object(canary, "docker_json") as inspect, patch.object(canary, "run") as command:
            self.assertEqual(canary.cleanup(project, {"webserver": "d", "broker": "e", "db": "f"}, identities, 18001, identities[:3], generation, True), (True, None))
        inspect.assert_not_called(); command.assert_not_called()

    def test_persisted_install_receipt_requires_exact_expected_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory); state = home / "paperless" / "state"; state.mkdir(parents=True)
            path = state / ".neoth-paperless-lifecycle-receipt.v1.json"; path.write_bytes(install_receipt_bytes())
            expected = canary.validate_install(install_receipt(), 18001)
            self.assertEqual(canary.persisted_install_receipt(home, expected, 18001), install_receipt_bytes())
            mutated = install_receipt(); mutated["project"] = "foreign"
            path.write_bytes(json.dumps(mutated, sort_keys=True).encode("utf-8"))
            with self.assertRaises(canary.Failure): canary.persisted_install_receipt(home, expected, 18001)

    def test_persisted_volume_set_snapshot_requires_exact_project_generation_and_six_names(self) -> None:
        project, generation = "neoth-paperless-abcdef123456", "12345678-1234-4234-8234-123456789abc"
        snapshot = {"schema_version": 1, "project": project, "volume_set_id": generation, "logical_volumes": [logical for logical, _, _ in canary.VOLUMES]}
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory); state = home / "paperless" / "state"; state.mkdir(parents=True)
            path = state / ".neoth-paperless-volume-set.v1.json"; path.write_text(json.dumps(snapshot))
            self.assertEqual(canary.persisted_volume_set_snapshot(home, project, generation), path.read_bytes())
            snapshot["logical_volumes"].reverse(); path.write_text(json.dumps(snapshot))
            with self.assertRaises(canary.Failure):
                canary.persisted_volume_set_snapshot(home, project, generation)

    def test_persisted_complete_custody_bytes_must_remain_identical_on_repeat(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory); state = home / "paperless" / "state"; state.mkdir(parents=True)
            receipt = uninstall_receipt(); raw = json.dumps(receipt, sort_keys=True).encode("utf-8")
            path = state / ".neoth-paperless-uninstall-custody.v1.json"; path.write_bytes(raw)
            first = canary.persisted_uninstall_receipt(home, receipt)
            second = canary.persisted_uninstall_receipt(home, receipt)
            self.assertEqual(first, second)
            path.write_bytes(raw + b"\n")
            self.assertNotEqual(path.read_bytes(), first)

    def test_retired_generation_archives_require_canonical_names_and_exact_old_authority(self) -> None:
        generation = "12345678-1234-4234-8234-123456789abc"
        authority = tuple((role, f"{role}-authority".encode()) for role in canary.RETIRED_AUTHORITY_ROLES)
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory); state = home / "paperless" / "state"; state.mkdir(parents=True)
            for role, raw in authority:
                (state / canary.retired_authority_archive_name(generation, role, raw)).write_bytes(raw)
            canary.retained_retired_authority(home, generation, authority)
            role, raw = authority[0]
            (state / canary.retired_authority_archive_name(generation, role, raw)).write_bytes(b"substituted")
            with self.assertRaises(canary.Failure):
                canary.retained_retired_authority(home, generation, authority)
        with self.assertRaises(canary.Failure):
            canary.retired_authority_archive_name("not-a-generation", "install", b"receipt")

    def test_rotation_journal_must_be_retired_after_fresh_generation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory); state = home / "paperless" / "state"; state.mkdir(parents=True)
            canary.rotation_journal_absent(home)
            (state / ".neoth-paperless-generation-rotation.v1.json").write_text("{}")
            with self.assertRaises(canary.Failure):
                canary.rotation_journal_absent(home)

    def test_repair_receipt_requires_exact_services_actions_ids_and_generation(self) -> None:
        project, generation = "neoth-paperless-abcdef123456", "12345678-1234-4234-8234-123456789abc"
        ids = tuple(f"{index:064x}" for index in range(1, 4))
        expected = tuple((service, "healthy", identifier, identifier) for service, identifier in zip(canary.IMAGES, ids, strict=True))
        receipt = {"schema_version": 1, "operation": "paperless.repair", "project": project, "volume_set_id": generation, "services": [{"service": service, "action": action, "prior_id": prior, "current_id": current} for service, action, prior, current in expected]}
        canary.validate_repair(receipt, project, generation, expected)
        for mutate in (lambda value: value["services"].pop(), lambda value: value["services"][0].update({"action": "recreated"}), lambda value: value["services"][0].update({"current_id": "f" * 64}), lambda value: value.__setitem__("volume_set_id", "abcdef12-1234-4234-8234-123456789abc")):
            invalid = json.loads(json.dumps(receipt)); mutate(invalid)
            with self.subTest(mutate=mutate), self.assertRaises(canary.Failure):
                canary.validate_repair(invalid, project, generation, expected)

    def test_fresh_credentials_allow_only_a_token_value_change_and_auth_marker_must_retire(self) -> None:
        before = b"unknown: retained\npaperless_token: old-token\npaperless_url: http://127.0.0.1:18001\n"
        after = b"unknown: retained\npaperless_token: new-token\npaperless_url: http://127.0.0.1:18001\n"
        self.assertEqual(canary.credentials_token_only_replaced(before, after), ("old-token", "new-token"))
        with self.assertRaises(canary.Failure):
            canary.credentials_token_only_replaced(before, after.replace(b"unknown: retained", b"unknown: changed"))
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory); state = home / "paperless" / "state"; state.mkdir(parents=True)
            canary.generation_auth_marker_absent(home)
            (state / ".neoth-paperless-generation-auth.v1.json").write_text("{}")
            with self.assertRaises(canary.Failure):
                canary.generation_auth_marker_absent(home)

    def test_marker_task_requires_one_matching_success_document(self) -> None:
        task_id = "12345678-1234-1234-1234-123456789abc"
        success = {"results": [{"task_id": task_id, "status": "success", "related_document_ids": [42]}]}
        with patch.object(canary, "paperless_api_json", return_value=success):
            self.assertEqual(canary.task_document_id(18001, "token", task_id), (42, 1))
        for response in (
            {"results": [{"task_id": task_id, "status": "success", "related_document_ids": []}]},
            {"results": [{"task_id": task_id, "status": "success", "related_document_ids": [1, 2]}]},
            {"results": [{"task_id": task_id, "status": "failure", "related_document_ids": []}]},
            {"results": [{"task_id": task_id, "status": "revoked", "related_document_ids": []}]},
            {"results": [{"task_id": task_id, "status": "SUCCESS", "related_document_ids": [42]}]},
            {"results": [{"task_id": task_id, "status": "unknown", "related_document_ids": []}]},
            {"results": [{"task_id": task_id, "status": "pending"}, {"task_id": task_id, "status": "pending"}]},
        ):
            with self.subTest(response=response), patch.object(canary, "paperless_api_json", return_value=response):
                with self.assertRaises(canary.Failure): canary.task_document_id(18001, "token", task_id)

    def test_marker_metadata_uses_detail_title_and_original_byte_hash(self) -> None:
        document_id = 42
        detail = {"id": document_id, "title": canary.MARKER_TITLE}
        with patch.object(canary, "paperless_api_json", return_value=detail), patch.object(canary, "paperless_api_bytes", return_value=(200, canary.MARKER_PDF)):
            self.assertEqual(canary.marker_metadata(18001, "token", document_id), (document_id, canary.MARKER_TITLE, __import__("hashlib").sha256(canary.MARKER_PDF).hexdigest()))
        with patch.object(canary, "paperless_api_json", return_value={"id": document_id, "title": "other"}):
            with self.assertRaises(canary.Failure): canary.marker_metadata(18001, "token", document_id)

    def test_marker_pdf_has_visible_text_and_exact_xref_offsets(self) -> None:
        canary.validate_marker_pdf(canary.MARKER_PDF)
        self.assertIn(b"/BaseFont /Helvetica", canary.MARKER_PDF)
        self.assertIn(b"(NEOTH retained-data canary) Tj", canary.MARKER_PDF)
        self.assertEqual(tuple(canary.MARKER_PDF.find(f"{index} 0 obj\n".encode("ascii")) for index in range(1, 6)), canary.MARKER_PDF_OFFSETS)
        altered = canary.MARKER_PDF.replace(b"startxref\n418", b"startxref\n417")
        with self.assertRaises(canary.Failure): canary.validate_marker_pdf(altered)

    def test_json_api_pins_upstream_v10_media_type(self) -> None:
        with patch.object(canary, "paperless_api_bytes", return_value=(200, b"{}")) as request:
            self.assertEqual(canary.paperless_api_json(18001, "token", "/api/tasks/?task_id=x", {200}), {})
        self.assertEqual(request.call_args.kwargs["extra_headers"], {"Accept": "application/json; version=10"})

    def test_cleanup_accepts_only_prevalidated_new_ids_and_absent_old_ids(self) -> None:
        project = "neoth-paperless-abcdef123456"
        current_ids = ("a" * 64, "b" * 64, "c" * 64)
        configs = {"webserver": "d" * 64, "broker": "e" * 64, "db": "f" * 64}
        volume_names = tuple(f"{project}_{logical}" for logical, _, _ in canary.VOLUMES)
        old_ids = ("d" * 64, "e" * 64, "f" * 64)
        def inspected(identifier: str, volume: bool = False) -> dict:
            if volume:
                logical = identifier.removeprefix(project + "_")
                return {"Name": identifier, "Labels": {"com.docker.compose.project": project, "com.docker.compose.volume": logical}}
            service = next(name for name, current in zip(canary.IMAGES, current_ids, strict=True) if current == identifier)
            mounts = [{"Type": "volume", "Name": f"{project}_{logical}", "Destination": destination} for logical, owner, destination in canary.VOLUMES if owner == service]
            return {"Id": identifier, "Image": configs[service], "State": {"Running": True}, "Config": {"Labels": {"com.docker.compose.project": project, "com.docker.compose.service": service}}, "NetworkSettings": {"Ports": {"8000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "18001"}]} if service == "webserver" else {}}, "Mounts": mounts}
        with patch.object(canary, "docker_json", side_effect=inspected), patch.object(canary, "run", return_value=b""), patch.object(canary.bounded, "prove_absent") as absent:
            self.assertEqual(canary.cleanup(project, configs, current_ids + volume_names, 18001, old_ids), (True, None))
        self.assertEqual(absent.call_count, len(old_ids) + len(current_ids) + len(volume_names))

    def test_cleanup_after_uninstall_only_removes_the_six_prevalidated_fixture_volumes(self) -> None:
        project = "neoth-paperless-abcdef123456"
        old_ids = ("a" * 64, "b" * 64, "c" * 64)
        volume_names = tuple(f"{project}_{logical}" for logical, _, _ in canary.VOLUMES)
        def inspected(identifier: str, volume: bool = False) -> dict:
            self.assertTrue(volume)
            logical = identifier.removeprefix(project + "_")
            return {"Name": identifier, "Labels": {"com.docker.compose.project": project, "com.docker.compose.volume": logical}}
        with patch.object(canary, "docker_json", side_effect=inspected), patch.object(canary, "run", return_value=b"") as command, patch.object(canary.bounded, "prove_absent"):
            self.assertEqual(canary.cleanup(project, {"webserver": "d", "broker": "e", "db": "f"}, old_ids + volume_names, 18001, old_ids), (True, None))
        self.assertEqual(command.call_count, len(volume_names))
        self.assertTrue(all(call.args[0][:3] == ["docker", "volume", "rm"] for call in command.call_args_list))
