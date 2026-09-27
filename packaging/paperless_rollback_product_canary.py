#!/usr/bin/env python3
"""Hosted-only real Paperless Restore rollback lifecycle canary."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path

import paperless_product_canary as base

ROLLBACK_JOURNAL = ".neoth-paperless-rollback-journal.v1.json"


class Failure(RuntimeError):
    pass


def read_json(raw: bytes, code: str) -> dict:
    try:
        value = json.loads(raw)
    except Exception as error:
        raise Failure(code) from error
    if not isinstance(value, dict):
        raise Failure(code)
    return value


def state_bytes(home: Path, name: str, code: str) -> bytes:
    return base.persisted_receipt_bytes(home, name, code)


def require_sha(value: object, code: str) -> str:
    if not isinstance(value, str) or not base.SHA256.fullmatch(value):
        raise Failure(code)
    return value


def rollback_preview(value: dict, restore_job: str, current_project: str, rollback_project: str, current_install: bytes) -> str:
    required = {"operation", "restore_job_id", "current_project", "rollback_project", "current_install_receipt_sha256", "confirmation"}
    if set(value) != required or value.get("operation") != "paperless.rollback" or value.get("restore_job_id") != restore_job or value.get("current_project") != current_project or value.get("rollback_project") != rollback_project or value.get("current_install_receipt_sha256") != hashlib.sha256(current_install).hexdigest() or not isinstance(value.get("confirmation"), str) or not value["confirmation"]:
        raise Failure("rollback_preview_invalid")
    return value["confirmation"]


def rollback_receipt(value: dict, restore_job: str, current_project: str, rollback_project: str) -> tuple[str, str]:
    required = {"operation", "restore_job_id", "current_project", "rollback_project", "old_source_was_running", "authenticated_api_ready", "rollback_custody_ref", "rollback_custody_sha256"}
    if set(value) != required or value.get("operation") != "paperless.rollback" or value.get("restore_job_id") != restore_job or value.get("current_project") != current_project or value.get("rollback_project") != rollback_project or value.get("old_source_was_running") is not True or value.get("authenticated_api_ready") is not True or not isinstance(value.get("rollback_custody_ref"), str) or value["rollback_custody_ref"] != f".neoth-paperless-rollback-{restore_job}.v1.json":
        raise Failure("rollback_receipt_invalid")
    return value["rollback_custody_ref"], require_sha(value.get("rollback_custody_sha256"), "rollback_receipt_invalid")


def expected_containers(identities: tuple[str, ...], configs: dict[str, str], running: bool) -> list[dict]:
    return [{"service": service, "id": identifier, "image_id": configs[service], "running": running} for service, identifier in zip(base.IMAGES, identities[:3], strict=True)]


def validate_terminal_custody(home: Path, name: str, terminal_digest: str, restore_digest: str, restore_job: str, current_install: bytes, current_snapshot: bytes, current_pointer: bytes, current_project: str, rollback_project: str, current: list[dict], old: list[dict]) -> dict:
    raw = state_bytes(home, name, "rollback_custody_invalid")
    value = read_json(raw, "rollback_custody_invalid")
    required = {"schema_version", "operation", "phase", "restore_job_id", "restore_custody_sha256", "current_install_receipt_bytes", "current_snapshot_bytes", "current_active_pointer", "current_project", "rollback_project", "current", "old", "current_stop_attempted", "old_start_attempted", "readiness_attempted", "authenticated_api_ready", "pending_command"}
    pointer = {"state": "present", "bytes": list(current_pointer), "sha256": hashlib.sha256(current_pointer).hexdigest()}
    if hashlib.sha256(raw).hexdigest() != terminal_digest or set(value) != required or value.get("schema_version") != 1 or value.get("operation") != "paperless.rollback" or value.get("phase") != "committed" or value.get("restore_job_id") != restore_job or require_sha(value.get("restore_custody_sha256"), "rollback_custody_invalid") != restore_digest or value.get("current_install_receipt_bytes") != list(current_install) or value.get("current_snapshot_bytes") != list(current_snapshot) or value.get("current_active_pointer") != pointer or value.get("current_project") != current_project or value.get("rollback_project") != rollback_project or value.get("current") != current or value.get("old") != old or value.get("current_stop_attempted") is not True or value.get("old_start_attempted") is not True or value.get("readiness_attempted") is not True or value.get("authenticated_api_ready") is not True or value.get("pending_command") is not None:
        raise Failure("rollback_custody_invalid")
    return value


def hosted_paths(home: Path, receipt: Path) -> None:
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("GITHUB_REF") != "refs/heads/main" or not base.re.fullmatch(r"[0-9a-f]{40}", os.environ.get("GITHUB_SHA", "")):
        raise Failure("hosted_guard_failed")
    if home.is_symlink() or not home.is_dir() or any(home.iterdir()) or receipt.parent.is_symlink():
        raise Failure("isolated_path_invalid")


def active_pointer_absent(home: Path) -> None:
    path = home / "paperless" / "state" / ".neoth-paperless-restore-active.v1.json"
    if path.exists() or path.is_symlink():
        raise Failure("rollback_pointer_not_absent")


def observe_retained_stopped(project: str, configs: dict[str, str], identities: tuple[str, ...], port: int, generation: str) -> None:
    for service, identifier in zip(base.IMAGES, identities[:3], strict=True):
        if base.validate_stopped_container(base.docker_json(identifier), identifier, project, service, configs[service], port) != identifier:
            raise Failure("rollback_retained_identity_invalid")
    for (logical, _, _), name in zip(base.VOLUMES, identities[3:], strict=True):
        if base.validate_volume(base.docker_json(name, volume=True), project, logical, generation) != name:
            raise Failure("rollback_retained_identity_invalid")


def captured_install_group(home: Path, port: int) -> tuple[str, dict[str, str], tuple[str, ...], str] | None:
    """Best-effort exact recovery custody after an effect whose CLI JSON is unusable."""
    try:
        raw = state_bytes(home, ".neoth-paperless-lifecycle-receipt.v1.json", "rollback_recovery_receipt_invalid")
        project, configs, identities, generation = base.validate_install(read_json(raw, "rollback_recovery_receipt_invalid"), port)
        if generation is None:
            return None
        return project, configs, identities, generation
    except Exception:
        return None


def trusted_restore_recovery(base_project: str, backup_job: str, observed: tuple[str, dict[str, str], tuple[str, ...], str] | None) -> bool:
    return observed is not None and base.restore_project_name(base_project, backup_job, observed[3]) == observed[0]


def trusted_rollback_recovery(base_project: str, base_generation: str, observed: tuple[str, dict[str, str], tuple[str, ...], str] | None) -> bool:
    return observed is not None and observed[0] == base_project and observed[3] == base_generation


def cleanup_observed_group(project: str, configs: dict[str, str], identities: tuple[str, ...], port: int, generation: str) -> tuple[bool, str | None]:
    try:
        states = [base.docker_json(identifier).get("State", {}).get("Running") for identifier in identities[:3]]
    except Exception:
        return False, "rollback_cleanup_state_unproven"
    if all(state is True for state in states):
        return base.cleanup(project, configs, identities, port, volume_set_id=generation)
    if all(state is False for state in states):
        return base.cleanup_retained_stopped_generation(project, configs, identities, port, generation)
    return False, "rollback_cleanup_state_unproven"


def provenance(binary: Path) -> dict[str, str]:
    root = Path(__file__).resolve().parents[1]
    names = (
        "packaging/paperless_rollback_product_canary.py", "packaging/tests/test_paperless_rollback_product_canary.py",
        ".github/workflows/paperless-rollback-product.yml", "SRC/neothd/src/cli/paperless.rs",
        "SRC/neothd/src/installers/paperless_restore.rs", "SRC/neothd/src/installers/paperless_rollback.rs",
        "SRC/neothd/src/installers/paperless_backup.rs", "SRC/neothd/src/installers/paperless_lifecycle.rs",
    )
    values = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in names}
    values["binary"] = hashlib.sha256(binary.read_bytes()).hexdigest()
    return values


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--home", required=True, type=Path)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args()
    receipt: dict[str, object] = {"schema": 1, "outcome": "failed", "cleanup_proven": False}
    home, binary = args.home.resolve(), args.binary.resolve()
    cleanup_groups: list[tuple[str, dict[str, str], tuple[str, ...], str, str]] = []
    try:
        hosted_paths(home, args.receipt)
        receipt["source_sha"] = os.environ["GITHUB_SHA"]
        receipt["provenance"] = provenance(binary)
        base.initialize_home(binary, home)
        prepared = read_json(base.run([str(binary), "--output", "json", "paperless", "prepare"], 900), "prepare_invalid"); base.validate_prepare(prepared)
        base.write_env_fixture(home / "paperless", args.port)
        installed = read_json(base.run([str(binary), "--output", "json", "paperless", "install"], 900), "install_invalid")
        project, configs, identities, generation = base.validate_install(installed, args.port)
        cleanup_groups = [("initial", configs, identities, generation, project)]
        install = base.persisted_install_receipt(home, (project, configs, identities, generation), args.port)
        snapshot = base.persisted_volume_set_snapshot(home, project, generation)
        token = base.configured_token(home)
        document_id, _ = base.task_document_id(args.port, token, base.upload_marker(args.port, token))
        marker = base.marker_metadata(args.port, token, document_id)
        backup = read_json(base.run([str(binary), "--output", "json", "paperless", "backup"], 900), "backup_invalid")
        backup_job, _ = base.validate_backup(backup, home, project, configs, identities, generation, install, snapshot, True)
        active_pointer_absent(home)
        restore_raw = base.run([str(binary), "--output", "json", "paperless", "restore", backup_job], 900)
        recovered_restore = captured_install_group(home, args.port)
        if trusted_restore_recovery(project, backup_job, recovered_restore):
            cleanup_groups = [("restore-recovery-active", recovered_restore[1], recovered_restore[2], recovered_restore[3], recovered_restore[0]), ("restore-recovery-source", configs, identities, generation, project)]
        restored = read_json(restore_raw, "restore_invalid")
        restore_job, restore_project, restore_generation = base.validate_restore(restored, backup, project, generation, install)
        restored_install = state_bytes(home, ".neoth-paperless-lifecycle-receipt.v1.json", "restore_install_invalid")
        now_project, now_configs, now_ids, now_generation = base.validate_install(read_json(restored_install, "restore_install_invalid"), args.port)
        source_binding = base.validate_backup_source(home, backup_job, install, snapshot)
        base.validate_restore_authority(home, restored, install, snapshot, restored_install, identities, now_ids, configs, args.port, source_binding, {"state": "absent", "absence": "not_found"})
        pointer = state_bytes(home, ".neoth-paperless-restore-active.v1.json", "restore_pointer_invalid")
        restore_custody = state_bytes(home, restored["rollback_custody_ref"], "restore_custody_invalid")
        current_snapshot = base.persisted_volume_set_snapshot(home, now_project, now_generation)
        cleanup_groups = [("restore-active", now_configs, now_ids, now_generation, now_project), ("rollback-source", configs, identities, generation, project)]
        preview = read_json(base.run([str(binary), "--output", "json", "paperless", "rollback", restore_job], 900), "rollback_preview_invalid")
        phrase = rollback_preview(preview, restore_job, now_project, project, restored_install)
        if state_bytes(home, ".neoth-paperless-lifecycle-receipt.v1.json", "rollback_preview_mutated") != restored_install or state_bytes(home, ".neoth-paperless-restore-active.v1.json", "rollback_preview_mutated") != pointer:
            raise Failure("rollback_preview_mutated")
        rollback_raw = base.run([str(binary), "--output", "json", "paperless", "rollback", restore_job, "--confirm", phrase], 900)
        recovered_rollback = captured_install_group(home, args.port)
        if trusted_rollback_recovery(project, generation, recovered_rollback):
            cleanup_groups = [("rollback-recovery-active", recovered_rollback[1], recovered_rollback[2], recovered_rollback[3], recovered_rollback[0]), ("rollback-recovery-retained", now_configs, now_ids, now_generation, now_project)]
        rolled = read_json(rollback_raw, "rollback_invalid")
        custody_name, custody_digest = rollback_receipt(rolled, restore_job, now_project, project)
        terminal = validate_terminal_custody(home, custody_name, custody_digest, hashlib.sha256(restore_custody).hexdigest(), restore_job, restored_install, current_snapshot, pointer, now_project, project, expected_containers(now_ids, now_configs, True), expected_containers(identities, configs, True))
        repeated = read_json(base.run([str(binary), "--output", "json", "paperless", "rollback", restore_job, "--confirm", phrase], 900), "rollback_repeat_invalid")
        if repeated != rolled:
            raise Failure("rollback_repeat_mutation")
        restored_original = state_bytes(home, ".neoth-paperless-lifecycle-receipt.v1.json", "rollback_original_invalid")
        if restored_original != install or state_bytes(home, ".neoth-paperless-volume-set.v1.json", "rollback_snapshot_invalid") != snapshot:
            raise Failure("rollback_prior_generation_not_restored")
        active_pointer_absent(home)
        project, configs, identities, generation = base.validate_install(read_json(restored_original, "rollback_original_invalid"), args.port)
        base.verify_api(args.port, base.configured_token(home)); base.marker_metadata_matches(args.port, base.configured_token(home), document_id, marker)
        cleanup_groups = [("rollback-active", configs, identities, generation, project), ("rollback-retained", now_configs, now_ids, now_generation, now_project)]
        observe_retained_stopped(now_project, now_configs, now_ids, args.port, now_generation)
        post_backup = read_json(base.run([str(binary), "--output", "json", "paperless", "backup"], 900), "rollback_backup_invalid")
        base.validate_backup(post_backup, home, project, configs, identities, generation, install, snapshot, True)
        repair = read_json(base.run([str(binary), "--output", "json", "paperless", "repair"], 900), "rollback_repair_invalid")
        base.validate_repair(repair, project, generation, tuple((service, "healthy", identifier, identifier) for service, identifier in zip(base.IMAGES, identities[:3], strict=True)))
        uninstall = read_json(base.run([str(binary), "--output", "json", "paperless", "uninstall"], 900), "rollback_uninstall_invalid")
        base.validate_uninstall(uninstall, project, identities[:3], identities[3:], install, generation)
        reinstall = read_json(base.run([str(binary), "--output", "json", "paperless", "install"], 900), "rollback_reinstall_invalid")
        reproject, reconfigs, reids, regeneration = base.validate_install(reinstall, args.port)
        if (reproject, reconfigs, regeneration) != (project, configs, generation):
            raise Failure("rollback_reinstall_generation_invalid")
        base.verify_api(args.port, base.configured_token(home)); base.marker_metadata_matches(args.port, base.configured_token(home), document_id, marker)
        cleanup_groups = [("post-reinstall-active", reconfigs, reids, regeneration, reproject), ("rollback-retained", now_configs, now_ids, now_generation, now_project)]
        receipt.update({"outcome": "passed", "restore_job_sha256": hashlib.sha256(restore_job.encode()).hexdigest(), "restore_custody_sha256": hashlib.sha256(restore_custody).hexdigest(), "rollback_custody_sha256": custody_digest, "terminal_custody_phase": terminal["phase"], "marker_preserved": True, "marker_preserved_after_reinstall": True, "retained_restore_generation_stopped": True, "prior_pointer_absent": True, "repeat_idempotent": True, "terminal_journal_allows_uninstall_reinstall": True})
    except Exception as error:
        receipt["failure_stage"] = str(error) if isinstance(error, Failure) else "unexpected"
    finally:
        cleanup_results = {}
        for role, configs, identities, generation, project in cleanup_groups:
            result, failure = cleanup_observed_group(project, configs, identities, args.port, generation)
            cleanup_results[role] = {"proven": result, "failure": failure}
        cleaned = bool(cleanup_results) and all(item["proven"] for item in cleanup_results.values())
        receipt["cleanup"] = cleanup_results
        receipt["cleanup_proven"] = cleaned
        if receipt.get("outcome") == "passed" and cleaned:
            shutil.rmtree(home); receipt["isolated_home_removed"] = not home.exists()
        else:
            receipt["outcome"] = "failed"; receipt["isolated_home_removed"] = False
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        args.receipt.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return 0 if receipt.get("outcome") == "passed" and receipt.get("cleanup_proven") else 1


if __name__ == "__main__":
    sys.exit(main())
