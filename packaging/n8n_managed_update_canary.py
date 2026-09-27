#!/usr/bin/env python3
"""Hosted acceptance proof for the compiled managed n8n Update path."""
from __future__ import annotations
import argparse, hashlib, json, os, re, shutil, subprocess, sys, tempfile, threading
from pathlib import Path
import n8n_product_bootstrap_canary as product
import n8n_update_migration_canary as migration

TARGET, PLATFORM, COUNT = "n8n-2.40.7", "linux/amd64", 13
ID = re.compile(r"[0-9a-f]{64}")
class Failure(RuntimeError): pass

FIELDS = {"schema_version", "update_job_id", "update_manifest_sha256", "selector", "version", "platform", "runtime_image", "repo_digest", "catalog_evidence_sha256", "index_digest", "child_manifest_digest", "config_digest", "source_job_id", "source_manifest_sha256", "source_container_id", "source_image", "source_volume", "host_port", "source_archive_sha256", "source_archive_bytes", "update_volume", "new_container_id", "retained_source_container_id", "retained_source_name", "baseline_workflow_count", "baseline_credential_count", "baseline_content_sha256", "migrated_workflow_count", "migrated_credential_count", "migrated_content_sha256", "evidence_sha256"}
SHA_FIELDS = {"update_manifest_sha256", "repo_digest", "catalog_evidence_sha256", "index_digest", "child_manifest_digest", "config_digest", "source_manifest_sha256", "source_archive_sha256", "baseline_content_sha256", "migrated_content_sha256", "evidence_sha256"}
def canon(x): return json.dumps(x, sort_keys=True, separators=(",", ":")).encode()
def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def digest(value):
    if not isinstance(value, str): return False
    for prefix in ("n8nio/n8n@sha256:", "sha256:"):
        if value.startswith(prefix): value = value[len(prefix):]; break
    return ID.fullmatch(value) is not None
def api_key_stdin(key):
    if not isinstance(key, bytes) or not key or b"\n" in key: raise Failure("api_key_payload_invalid")
    return key + b"\n"
def raw(argv, payload=None, timeout=600): return migration.raw(argv, payload=payload, timeout=timeout)
def docker(*args, timeout=180): return migration.docker(*args, timeout=timeout)
def receipt(path, value): path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(canon(value)+b"\n")

def guard(home, output):
    run, attempt, root = os.environ.get("GITHUB_RUN_ID", ""), os.environ.get("GITHUB_RUN_ATTEMPT", ""), os.environ.get("RUNNER_TEMP", "")
    task = Path(root).resolve() / f"w1623-n8n-{run}-{attempt}"
    if (os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("GITHUB_REF") != "refs/heads/main" or not re.fullmatch(r"[0-9a-f]{40}", os.environ.get("GITHUB_SHA", "")) or sys.platform != "linux" or os.environ.get("DOCKER_HOST") != "unix:///var/run/docker.sock" or os.environ.get("DOCKER_CONTEXT") or home.is_symlink() or not home.is_dir() or any(home.iterdir()) or home.resolve() != task / "neoth-home" or output.resolve() != task / "receipt" / "receipt.json" or os.environ.get("NEOTH_HOME") != str(home.resolve())): raise Failure("hosted_guard_failed")
    for variable, leaf in (("XDG_CONFIG_HOME", "xdg-config"), ("XDG_DATA_HOME", "xdg-data"), ("XDG_RUNTIME_DIR", "xdg-runtime")):
        directory = Path(os.environ.get(variable, ""))
        if directory.is_symlink() or not directory.is_dir() or directory.resolve() != task / leaf: raise Failure("private_xdg_guard_failed")
    if not docker("version", "--format", "{{.Server.Version}}", timeout=20).strip(): raise Failure("docker_engine_unavailable")

def validate_update(value):
    envelope = {"job_id", "state", "operation", "target", "platform", "receipt", "failure_code"}
    if set(value) != envelope or value.get("state") != "ready" or value.get("operation") != "update" or value.get("target") != TARGET or value.get("platform") != PLATFORM or value.get("failure_code") is not None or not isinstance(value.get("job_id"), str) or not isinstance(value.get("receipt"), dict): raise Failure("update_envelope_invalid")
    envelope_job = value["job_id"]
    value = value["receipt"]
    numeric = {"schema_version", "host_port", "source_archive_bytes", "baseline_workflow_count", "baseline_credential_count", "migrated_workflow_count", "migrated_credential_count"}
    if set(value) != FIELDS or any(type(value.get(k)) is not int for k in numeric) or value["schema_version"] != 1 or value["selector"] != TARGET or value["platform"] != PLATFORM or value["version"] != "2.40.7" or value["update_job_id"] != envelope_job: raise Failure("update_receipt_projection_invalid")
    if any(not isinstance(value[k], str) or not value[k] for k in FIELDS - numeric): raise Failure("update_receipt_projection_invalid")
    if any(not digest(value[key]) for key in SHA_FIELDS) or value["host_port"] != 5681 or value["source_archive_bytes"] <= 0: raise Failure("update_receipt_projection_invalid")
    if not all(ID.fullmatch(value[k]) for k in ("source_container_id", "new_container_id", "retained_source_container_id")): raise Failure("update_receipt_identity_invalid")
    if value["source_container_id"] != value["retained_source_container_id"] or value["retained_source_name"] == "neoth-n8n" or not value["retained_source_name"].startswith("neoth-n8n-retired-") or value["update_volume"] == value["source_volume"]: raise Failure("update_receipt_custody_invalid")
    if (value["baseline_workflow_count"] != COUNT or value["migrated_workflow_count"] != COUNT
            or value["baseline_credential_count"] != 1 or value["migrated_credential_count"] != 1
            or value["baseline_workflow_count"] != value["migrated_workflow_count"]
            or value["baseline_credential_count"] != value["migrated_credential_count"]
            or value["baseline_content_sha256"] != value["migrated_content_sha256"]):
        raise Failure("update_receipt_content_mismatch")
    return value

def archive_manifest(container, directory):
    # The source is stopped; this opaque private stream never reaches logs or a receipt.
    data = migration.capture(["docker", "cp", f"{container}:/home/node/.n8n/.", "-"], timeout=180, limit=migration.MAX_ARCHIVE_BYTES)
    path = directory / "source.tar"; path.write_bytes(data); path.chmod(0o600)
    return migration.safe_archive_manifest(path), sha(path), path.stat().st_size

def validate_source_archive_receipt(update, archive_sha256, archive_bytes):
    if update.get("source_archive_sha256") != archive_sha256 or update.get("source_archive_bytes") != archive_bytes:
        raise Failure("update_source_archive_receipt_mismatch")

def volume_inspect(name):
    rows = json.loads(docker("volume", "inspect", name))
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict): raise Failure("update_volume_inspect_invalid")
    return rows[0]

def ready_operation(raw_bytes, operation):
    value = product.read_json_bytes(raw_bytes)
    if not isinstance(value, dict) or value.get("state") != "ready" or value.get("operation") != operation or value.get("failure_code") is not None or not isinstance(value.get("job_id"), str): raise Failure("downstream_operation_not_ready")
    return value["job_id"]

def job_manifest(home, job, operation):
    # The observer validates the complete Ready row and returns its hashed
    # projection, not the original database row.
    observation = product.observe_exact_job(home, job, operation)
    manifest = observation.get("manifest_sha256")
    if not isinstance(manifest, str) or not re.fullmatch(r"[0-9a-f]{64}", manifest):
        raise Failure("downstream_job_manifest_invalid")
    return manifest

def validate_update_backup(home, backup, backup_manifest, update):
    path = home / f"n8n-backup-{backup}.receipt.json"
    if not path.is_file() or path.is_symlink(): raise Failure("update_backup_receipt_missing")
    value = product.read_json(path)
    fields = {"schema_version", "backup_job_id", "backup_manifest_sha256", "source_install_job_id", "source_job_id", "source_manifest_sha256", "source_operation", "source_pinned_image", "source_container_id", "volume_name", "generation", "archive_sha256", "archive_bytes", "original_running_state", "restored_running_state"}
    if (set(value) != fields or value.get("schema_version") != 3 or value.get("backup_job_id") != backup
            or value.get("backup_manifest_sha256") != backup_manifest
            or value.get("source_install_job_id") != update["update_job_id"]
            or value.get("source_job_id") != update["update_job_id"]
            or value.get("source_manifest_sha256") != update["update_manifest_sha256"]
            or value.get("source_operation") != "update"
            or value.get("source_pinned_image") != update["runtime_image"]
            or value.get("source_container_id") != update["new_container_id"]
            or value.get("volume_name") != update["update_volume"]
            or type(value.get("generation")) is not int or value["generation"] < 1
            or value.get("original_running_state") is not True or value.get("restored_running_state") is not True
            or not digest(value.get("archive_sha256")) or type(value.get("archive_bytes")) is not int or value["archive_bytes"] <= 0):
        raise Failure("update_backup_receipt_invalid")
    archive = home / "n8n-backups" / f"{backup}.tar"
    if archive.is_symlink() or not archive.is_file() or archive.stat().st_size != value["archive_bytes"] or sha(archive) != value["archive_sha256"]:
        raise Failure("update_backup_archive_invalid")
    return {"archive_sha256": value["archive_sha256"], "archive_bytes": value["archive_bytes"], "generation": value["generation"]}

def validate_reinstall_rejection(returncode, timed_out, writer_alive, stderr):
    if returncode == 0 or timed_out or writer_alive or b"n8n_retained_reinstall_already_active" not in stderr:
        raise Failure("reinstall_repeat_rejection_unproven")

def bounded_reinstall_rejection(binary, uninstall, payload, timeout=180):
    """Deadline includes an uncooperative child's stdin read as well as exit."""
    child = subprocess.Popen([str(binary), "--output", "json", "n8n", "install", "--reuse-uninstall", uninstall, "--api-key-stdin"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr, writer_failed = bytearray(), bytearray(), []
    def drain(stream, target, cap):
        try:
            while chunk := stream.read(4096):
                if len(target) + len(chunk) > cap: return writer_failed.append(True)
                target.extend(chunk)
        except OSError: writer_failed.append(True)
    def feed():
        try: child.stdin.write(payload); child.stdin.close()
        except OSError: writer_failed.append(True)
    threads = [threading.Thread(target=drain, args=(child.stdout, stdout, 16 * 1024), daemon=True), threading.Thread(target=drain, args=(child.stderr, stderr, 16 * 1024), daemon=True), threading.Thread(target=feed, daemon=True)]
    for thread in threads: thread.start()
    timed_out = False
    try: child.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True; child.kill(); child.wait(timeout=5)
    for thread in threads: thread.join(2)
    validate_reinstall_rejection(child.returncode, timed_out, any(thread.is_alive() for thread in threads) or bool(writer_failed), bytes(stderr))

def update_runtime(home, update, prior_id=None, job=None, manifest=None):
    """Read the current Update generation without borrowing Install's image contract."""
    runtime = product.read_json(home / "n8n-managed-runtime.v2.json")
    identifier = runtime.get("container_id") if isinstance(runtime, dict) else None
    if (not isinstance(identifier, str) or not ID.fullmatch(identifier)
            or identifier == prior_id or runtime.get("phase") != "Ready"
            or runtime.get("container_name") != "neoth-n8n"
            or runtime.get("job_id") != (job or update["update_job_id"])
            or runtime.get("manifest_sha256") != (manifest or update["update_manifest_sha256"])
            or runtime.get("volume") != update["update_volume"]
            or runtime.get("image") != update["runtime_image"]):
        raise Failure("update_runtime_binding_invalid")
    row = product.docker_inspect(identifier)
    mounts = row.get("Mounts")
    if (row.get("Id") != identifier or row.get("Name") != "/neoth-n8n"
            or row.get("State", {}).get("Running") is not True
            or row.get("Config", {}).get("Image") != update["runtime_image"]
            or row.get("Config", {}).get("Labels", {}).get("io.neoth.managed") != "n8n"
            or row.get("Config", {}).get("Labels", {}).get("io.neoth.n8n-job") != (job or update["update_job_id"])
            or not isinstance(mounts, list)
            or not any(m.get("Type") == "volume" and m.get("Name") == update["update_volume"]
                       and m.get("Destination") == "/home/node/.n8n" and m.get("RW") is True for m in mounts)):
        raise Failure("update_runtime_identity_invalid")
    return identifier

def assert_update_content(identifier, workflow_key, credential_key, templates, credential, proof, expected_graphs):
    if (migration.candidate_workflows(identifier, workflow_key, templates) != expected_graphs
            or migration.candidate_credential_listing(identifier, credential_key) != credential
            or migration.credential_proof(identifier, *credential) != proof):
        raise Failure("update_lifecycle_content_invalid")

def assert_no_update_candidates(job):
    """Candidates have an exact per-job label; any survivor is an unsafe shared-volume owner."""
    rows = docker("ps", "--all", "--quiet", "--filter", f"label=io.neoth.n8n-update={job}", timeout=30).decode("ascii", "strict").split()
    for identifier in rows:
        if not ID.fullmatch(identifier):
            raise Failure("update_candidate_identity_invalid")
        row = product.docker_inspect(identifier)
        if row.get("Id") != identifier or row.get("Config", {}).get("Labels", {}).get("io.neoth.n8n-update") != job:
            raise Failure("update_candidate_identity_invalid")
    if rows:
        raise Failure("update_candidate_survived")

def update_binding(value, update, identifier):
    lineage = value.get("lineage") if isinstance(value, dict) else None
    expected_lineage = {"update_job_id": update["update_job_id"], "update_manifest_sha256": update["update_manifest_sha256"], "admitted_selector": update["selector"], "admitted_version": update["version"], "admitted_platform": update["platform"], "admitted_runtime_image": update["runtime_image"], "admitted_repo_digest": update["repo_digest"], "catalog_evidence_sha256": update["catalog_evidence_sha256"], "index_digest": update["index_digest"], "child_manifest_digest": update["child_manifest_digest"], "config_digest": update["config_digest"], "source_job_id": update["source_job_id"], "source_manifest_sha256": update["source_manifest_sha256"], "source_archive_sha256": update["source_archive_sha256"], "source_archive_bytes": update["source_archive_bytes"], "update_volume_owner_job_id": update["update_job_id"], "source_container_id": update["source_container_id"], "source_image": update["source_image"], "source_volume": update["source_volume"], "baseline_workflow_count": update["baseline_workflow_count"], "baseline_credential_count": update["baseline_credential_count"], "baseline_content_sha256": update["baseline_content_sha256"], "migrated_workflow_count": update["migrated_workflow_count"], "migrated_credential_count": update["migrated_credential_count"], "migrated_content_sha256": update["migrated_content_sha256"], "retained_source_container_id": update["retained_source_container_id"], "retained_source_name": update["retained_source_name"]}
    if (set(value) != {"schema_version", "phase", "job_id", "manifest_sha256", "container_name", "container_id", "image", "host_port", "volume", "retained_reinstall", "bootstrap_volume_owner_job_id", "lineage"}
            or value.get("schema_version") != 4 or value.get("phase") != "Ready"
            or value.get("job_id") != update["update_job_id"] or value.get("manifest_sha256") != update["update_manifest_sha256"]
            or value.get("container_name") != "neoth-n8n" or value.get("container_id") != identifier
            or value.get("image") != update["runtime_image"] or value.get("host_port") != 5681
            or value.get("volume") != update["update_volume"] or value.get("retained_reinstall") is not None
            or value.get("bootstrap_volume_owner_job_id") is not None or lineage != {"update": expected_lineage}):
        raise Failure("update_repair_binding_invalid")
    return value

def repair_bytes(value, field):
    raw = value.get(field)
    if not isinstance(raw, list) or not raw or any(type(item) is not int or not 0 <= item <= 255 for item in raw):
        raise Failure("update_repair_binding_bytes_invalid")
    try: return json.loads(bytes(raw))
    except Exception as error: raise Failure("update_repair_binding_bytes_invalid") from error

def validate_update_repair(view, repair_job, repair_manifest, update, action, prior, current):
    fields = {"schema_version", "phase", "repair_job_id", "repair_manifest_sha256", "generation", "source_install_job_id", "source_install_manifest_sha256", "action", "old_container_id", "new_container_id", "old_binding", "new_binding", "old_binding_bytes", "new_binding_bytes"}
    if (set(view) != fields or view.get("schema_version") != 1 or view.get("phase") != "completed"
            or view.get("repair_job_id") != repair_job or view.get("repair_manifest_sha256") != repair_manifest
            or type(view.get("generation")) is not int or view["generation"] < 1
            or view.get("source_install_job_id") != update["update_job_id"]
            or view.get("source_install_manifest_sha256") != update["update_manifest_sha256"]
            or view.get("action") != action or view.get("old_container_id") != prior):
        raise Failure("update_repair_state_invalid")
    old = update_binding(view.get("old_binding"), update, prior)
    if repair_bytes(view, "old_binding_bytes") != old: raise Failure("update_repair_binding_bytes_invalid")
    if action in ("healthy", "started"):
        if current != prior or view.get("new_container_id") is not None or view.get("new_binding") is not None or view.get("new_binding_bytes") is not None:
            raise Failure("update_repair_same_id_invalid")
    elif action == "recreated":
        if current == prior or view.get("new_container_id") != current:
            raise Failure("update_repair_replacement_invalid")
        new = update_binding(view.get("new_binding"), update, current)
        if repair_bytes(view, "new_binding_bytes") != new:
            raise Failure("update_repair_binding_bytes_invalid")
        expected = dict(old); expected["container_id"] = current
        if new != expected: raise Failure("update_repair_replacement_invalid")
    else:
        raise Failure("update_repair_action_invalid")

def update_downstream(binary, home, update, workflow_key, credential_key):
    """Exercise each public lifecycle transition with receipt-owned identifiers."""
    templates = product.workflow_templates(product.read_json_from_command([str(binary), "--output", "json", "n8n", "workflows"]))
    credential = migration.candidate_credential_listing(update["new_container_id"], credential_key)
    proof = migration.credential_proof(update["new_container_id"], *credential)
    graphs = migration.candidate_workflows(update["new_container_id"], workflow_key, templates)
    assert_update_content(update["new_container_id"], workflow_key, credential_key, templates, credential, proof, graphs)
    backup = ready_operation(raw([str(binary), "--output", "json", "n8n", "backup"]), "backup")
    backup_manifest = job_manifest(home, backup, "backup")
    backup_receipt = validate_update_backup(home, backup, backup_manifest, update)
    current = update_runtime(home, update)
    assert_update_content(current, workflow_key, credential_key, templates, credential, proof, graphs)
    repair_state = home / "n8n-managed-repair.v1.json"
    repairs = []
    def repair(expected_action, prior):
        repair_job = ready_operation(raw([str(binary), "--output", "json", "n8n", "repair"]), "repair")
        repair_manifest = job_manifest(home, repair_job, "repair")
        if not repair_state.is_file() or repair_state.is_symlink(): raise Failure("update_repair_state_missing")
        current_id = update_runtime(home, update, prior if expected_action == "recreated" else None)
        view = product.read_json(repair_state)
        validate_update_repair(view, repair_job, repair_manifest, update, expected_action, prior, current_id)
        if expected_action == "recreated":
            immutable = home / f"n8n-repair-container-{current_id}.receipt.json"
            if not immutable.is_file() or immutable.is_symlink(): raise Failure("update_repair_replacement_receipt_missing")
            immutable_view = product.read_json(immutable)
            validate_update_repair(immutable_view, repair_job, repair_manifest, update, expected_action, prior, current_id)
        assert_update_content(current_id, workflow_key, credential_key, templates, credential, proof, graphs)
        repairs.append({"job_id": repair_job, "manifest_sha256": repair_manifest, "action": expected_action,
                        "prior_container_id": prior, "container_id": current_id})
        return current_id
    current = repair("healthy", current)
    docker("container", "stop", current)
    if product.docker_inspect(current).get("State", {}).get("Running") is not False: raise Failure("update_repair_stop_unproven")
    current = repair("started", current)
    prior_id, volume = current, update["update_volume"]
    docker("container", "rm", "-f", prior_id)
    if not product.exact_absent("container", prior_id): raise Failure("update_repair_remove_unproven")
    current = repair("recreated", prior_id)
    assert_no_update_candidates(update["update_job_id"])
    chain = []
    for ordinal in (1, 2):
        uninstall = ready_operation(raw([str(binary), "--output", "json", "n8n", "uninstall"]), "uninstall")
        uninstall_manifest = job_manifest(home, uninstall, "uninstall")
        product.validate_uninstall_status(product.read_json_from_command([str(binary), "--output", "json", "n8n", "status", "--job", uninstall]), uninstall)
        if not product.exact_absent("container", current): raise Failure("update_uninstall_runtime_present")
        reinstall = ready_operation(raw([str(binary), "--output", "json", "n8n", "install", "--reuse-uninstall", uninstall, "--api-key-stdin"], payload=api_key_stdin(workflow_key)), "install")
        reinstall_manifest = job_manifest(home, reinstall, "install")
        new_id = update_runtime(home, update, current, reinstall, reinstall_manifest)
        bounded_reinstall_rejection(binary, uninstall, api_key_stdin(workflow_key))
        assert_update_content(new_id, workflow_key, credential_key, templates, credential, proof, graphs)
        chain.append({"ordinal": ordinal, "uninstall_job_id": uninstall, "uninstall_manifest_sha256": uninstall_manifest, "reinstall_job_id": reinstall, "reinstall_manifest_sha256": reinstall_manifest})
        current = new_id
    uninstall = ready_operation(raw([str(binary), "--output", "json", "n8n", "uninstall"]), "uninstall")
    uninstall_manifest = job_manifest(home, uninstall, "uninstall")
    plan = product.read_json_bytes(raw([str(binary), "--output", "json", "n8n", "purge", "--uninstall", uninstall]))
    phrase = product.validate_purge_plan(plan, uninstall, volume)
    purge = ready_operation(raw([str(binary), "--output", "json", "n8n", "purge", "--uninstall", uninstall, "--confirm", phrase]), "purge")
    purge_manifest = job_manifest(home, purge, "purge")
    if not product.exact_absent("container", current) or not product.exact_absent("volume", volume): raise Failure("update_purge_effect_unproven")
    assert_no_update_candidates(update["update_job_id"])
    return {"backup_job_id": backup, "backup_manifest_sha256": backup_manifest, "backup_archive": backup_receipt, "repairs": repairs, "reinstall_chain": chain, "final_uninstall_job_id": uninstall, "final_uninstall_manifest_sha256": uninstall_manifest, "purge_job_id": purge, "purge_manifest_sha256": purge_manifest, "update_volume_absent": True}

def cleanup_update_fixture(home, source, update, update_attempted):
    if source is None: return False
    source_job, _, source_volume, source_id = source
    try:
        # Before an Update receipt exists this is still the ordinary isolated
        # install fixture; do not infer any Update identity from partial state.
        pending = home / "n8n-managed-update.v1.json"
        if update is None and (update_attempted or pending.exists() or pending.is_symlink()):
            return False
        if update is None:
            return product.cleanup_owned_runtime_and_volume(source_id, source_volume, source_job, 5681, runtime_already_absent=False) and migration.clear_fixture_secrets(source_job)
        # A completed Update receipt is the only authority to clean its target
        # volume. Every per-job candidate must already be absent: deleting one
        # after an ambiguous create/remove would hide the unsafe state.
        assert_no_update_candidates(update["update_job_id"])
        if not product.exact_absent("container", update["new_container_id"]): return False
        if not product.exact_absent("volume", update["update_volume"]): return False
        old = product.docker_inspect(source_id)
        mounts = old.get("Mounts")
        if (old.get("Id") != source_id or old.get("Name") != "/" + update["retained_source_name"]
                or old.get("State", {}).get("Running") is not False
                or old.get("Config", {}).get("Image") != update["source_image"]
                or old.get("Config", {}).get("Labels", {}).get("io.neoth.managed") != "n8n"
                or old.get("Config", {}).get("Labels", {}).get("io.neoth.n8n-job") != source_job
                or old.get("HostConfig", {}).get("PortBindings") != {"5678/tcp":[{"HostIp":"127.0.0.1","HostPort":"5681"}]}
                or not isinstance(mounts, list) or len(mounts) != 1
                or mounts[0].get("Type") != "volume" or mounts[0].get("Name") != source_volume
                or mounts[0].get("Destination") != "/home/node/.n8n" or mounts[0].get("RW") is not True):
            return False
        source_row = volume_inspect(source_volume)
        product.validate_retained_volume(source_row, source_job, source_volume)
        docker("container", "rm", source_id)
        if not product.exact_absent("container", source_id): return False
        docker("volume", "rm", source_volume)
        return product.exact_absent("volume", source_volume) and migration.clear_fixture_secrets(source_job)
    except Exception: return False

def provenance():
    names = ("packaging/n8n_managed_update_canary.py", "packaging/tests/test_n8n_managed_update_canary.py", "packaging/tests/test_n8n_update_content.py", "packaging/tests/test_n8n_update_migration_canary.py", "packaging/tests/test_n8n_product_bootstrap_canary.py", ".github/workflows/n8n-managed-update.yml", "packaging/n8n_update_migration_canary.py", "packaging/n8n_product_bootstrap_canary.py", "packaging/n8n_update_target_preflight_canary.py", "SRC/Cargo.lock", "SRC/neothd/Cargo.toml", "SRC/neothd/src/cli/n8n.rs", "SRC/neothd/src/integrations/n8n.rs", "SRC/neothd/src/integrations/n8n/managed_update.rs", "SRC/neothd/src/integrations/n8n/managed_update_tests.rs", "SRC/neothd/src/integrations/n8n/managed_update_candidate.rs", "SRC/neothd/src/integrations/n8n/managed_update_content.rs", "SRC/neothd/src/integrations/n8n/managed_update_verify.js", "SRC/neothd/src/integrations/n8n/managed_update_target.rs", "SRC/neothd/src/integrations/n8n/managed_runtime.rs", "SRC/neothd/src/integrations/n8n/managed_runtime_tests.rs", "SRC/neothd/src/integrations/n8n/managed_backup.rs", "SRC/neothd/src/integrations/n8n/managed_backup_tests.rs", "SRC/neothd/src/integrations/n8n/managed_repair.rs", "SRC/neothd/src/integrations/n8n/managed_repair_tests.rs", "SRC/neothd/src/integrations/n8n/managed_uninstall.rs", "SRC/neothd/src/integrations/n8n/managed_purge.rs", "SRC/neothd/src/integrations/n8n/managed_rollback.rs", "SRC/neothd/src/integrations/jobs.rs", "SRC/neothd/src/integrations/state.rs")
    return {name: sha(name) for name in names}

def main(argv):
    p=argparse.ArgumentParser(); p.add_argument("--binary",required=True,type=Path); p.add_argument("--home",required=True,type=Path); p.add_argument("--receipt",required=True,type=Path); p.add_argument("--port",type=int,default=5681); a=p.parse_args(argv)
    try: guard(a.home,a.receipt)
    except Exception: return 2
    out={"schema":1,"scenario":"n8n_managed_update","source_sha":os.environ.get("GITHUB_SHA"),"outcome":"failed","cleanup_proven":False}; source=update=None; update_attempted=False
    try:
        if not a.binary.is_file() or a.binary.is_symlink(): raise Failure("binary_invalid")
        out["input_sha256"],out["binary_sha256"]=provenance(),sha(a.binary)
        job=product.validate_product(product.first_product_install(a.binary,a.home,a.port)); source=migration.source_record(a.home,a.port)
        source_job, boot, source_volume, source_id=source
        if source_job != job: raise Failure("source_job_mismatch")
        source_image = product.docker_inspect(source_id).get("Config", {}).get("Image")
        templates=product.workflow_templates(product.read_json_from_command([str(a.binary),"--output","json","n8n","workflows"])); key=product.canonical_n8n_api_key()
        product.validate_import_job(product.read_json_bytes(raw([str(a.binary),"--output","json","n8n","import-workflows"])))
        graphs=migration.source_workflows(a.port,key,templates); scoped=product.mint_restore_credential_key(job,source_id); product.create_restore_fixture_credential(a.port,scoped); credential=migration.credential_listing(a.port,scoped); proof=migration.credential_proof(source_id,*credential)
        docker("container","stop",source_id)
        with tempfile.TemporaryDirectory(prefix="w1623-archive-",dir=a.receipt.parent) as temp:
            before_manifest,before_sha,before_bytes=archive_manifest(source_id,Path(temp))
            update_attempted=True
            update=validate_update(product.read_json_bytes(migration.capture([str(a.binary),"--output","json","n8n","update","--target",TARGET,"--platform",PLATFORM,"--api-key-stdin"], payload=api_key_stdin(key),timeout=900,limit=64*1024)))
            if update["source_job_id"] != source_job or update["source_container_id"] != source_id or update["source_volume"] != source_volume or update["source_image"] != source_image: raise Failure("update_source_custody_mismatch")
            validate_source_archive_receipt(update, before_sha, before_bytes)
            after_manifest,after_sha,after_bytes=archive_manifest(source_id,Path(temp))
        if before_manifest != after_manifest: raise Failure("retired_source_archive_changed")
        live=product.docker_inspect(update["new_container_id"])
        if live.get("Name") != "/neoth-n8n" or live.get("State",{}).get("Running") is not True or live.get("Config",{}).get("Labels",{}).get("io.neoth.managed") != "n8n": raise Failure("updated_runtime_invalid")
        old=product.docker_inspect(source_id)
        if old.get("Name") != "/"+update["retained_source_name"] or old.get("State",{}).get("Running") is not False: raise Failure("retained_source_invalid")
        labels=volume_inspect(update["update_volume"]).get("Labels",{})
        if labels.get("io.neoth.n8n-update") != update["update_job_id"] or labels.get("io.neoth.n8n-update-schema") != "1" or labels.get("io.neoth.managed") != "n8n": raise Failure("update_volume_invalid")
        if migration.candidate_workflows(update["new_container_id"], key, templates) != graphs or migration.candidate_credential_listing(update["new_container_id"], scoped) != credential or migration.credential_proof(update["new_container_id"],*credential) != proof: raise Failure("updated_content_invalid")
        again=validate_update(product.read_json_bytes(migration.capture([str(a.binary),"--output","json","n8n","update","--target",TARGET,"--platform",PLATFORM,"--api-key-stdin"],payload=api_key_stdin(key),timeout=900,limit=64*1024)))
        if again["update_job_id"] != update["update_job_id"] or again["new_container_id"] != update["new_container_id"] or again["update_volume"] != update["update_volume"]: raise Failure("update_repeat_not_idempotent")
        downstream = update_downstream(a.binary, a.home, update, key, scoped)
        out.update({"update":{k:update[k] for k in ("update_job_id","selector","version","platform","runtime_image","update_volume","new_container_id","retained_source_name")},"source_archive":{"member_manifest_sha256":before_manifest,"archive_sha256":before_sha,"archive_bytes":before_bytes,"after_member_manifest_sha256":after_manifest,"after_archive_sha256":after_sha,"after_archive_bytes":after_bytes},"content":{"workflows":COUNT,"node_groups":True,"credential_decryption":True,"anonymous_401":True,"historical_key":True},"downstream":downstream,"outcome":"passed"})
    except Exception as e: out["failure_stage"]=str(e) if isinstance(e,Failure) else "unexpected"
    finally:
        # Only the product helper's exact owned-custody cleanup is allowed.
        cleaned=cleanup_update_fixture(a.home, source, update, update_attempted)
        home_removed=False
        if cleaned:
            try: shutil.rmtree(a.home); home_removed=not a.home.exists()
            except Exception: home_removed=False
        try:
            update_absent = bool(update) and product.exact_absent("container", update["new_container_id"]) and product.exact_absent("volume", update["update_volume"])
        except Exception:
            update_absent = False
        out["cleanup"]={"update_runtime_and_volume_absent": update_absent, "retained_source_and_volume_removed": cleaned, "secrets_removed": cleaned, "isolated_home_removed": home_removed}
        out["cleanup_proven"]=cleaned and home_removed and (not update_attempted or update_absent)
        if not out["cleanup_proven"]: out["outcome"]="failed"
        receipt(a.receipt,out)
    return 0 if out["outcome"]=="passed" and out["cleanup_proven"] else 1
if __name__=="__main__": raise SystemExit(main(sys.argv[1:]))
