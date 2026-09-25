"""Pure boundary checks for the hosted Paperless product canary."""
from __future__ import annotations

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


def install_receipt() -> dict:
    project = "neoth-paperless-abcdef123456"
    configs = {service: f"sha256:{index:064x}" for index, service in enumerate(canary.IMAGES, start=1)}
    return {
        "schema_version": 1, "operation": "install", "project": project,
        "loopback_port": 18001, "authenticated_api_ready": True,
        "images": [{"service": service, "reference": reference, "config_id": configs[service]} for service, reference in canary.IMAGES.items()],
        "containers": [{"service": service, "id": f"{index:064x}", "image_id": configs[service]} for index, service in enumerate(canary.IMAGES, start=10)],
        "volumes": [{"logical_name": logical, "name": f"{project}_{logical}", "project": project} for logical, _, _ in canary.VOLUMES],
    }


class CustodyTests(unittest.TestCase):
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

    def test_install_receipt_accepts_exact_six_volumes_and_rejects_duplicate_or_missing(self) -> None:
        receipt = install_receipt()
        project, _, identities = canary.validate_install(receipt, 18001)
        self.assertEqual(project, "neoth-paperless-abcdef123456")
        self.assertEqual(len(identities), len(canary.IMAGES) + len(canary.VOLUMES))
        duplicate = install_receipt()
        duplicate["volumes"][-1] = duplicate["volumes"][0].copy()
        with self.assertRaises(canary.Failure): canary.validate_install(duplicate, 18001)
        missing = install_receipt()
        missing["volumes"] = missing["volumes"][:-1]
        with self.assertRaises(canary.Failure): canary.validate_install(missing, 18001)

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
