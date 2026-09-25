#!/usr/bin/env python3
"""Hosted-only proof for the compiled NEOTH owner-bootstrap command."""
from __future__ import annotations

import argparse, hashlib, json, os, re, shutil, sys, time, urllib.error, urllib.parse, urllib.request
from pathlib import Path

import n8n_bootstrap_canary as bounded
import yaml

IMAGE = "docker.io/n8nio/n8n@sha256:9f693fd5565539efd5e75ad168526c8041a6af516d9e50bc4d9cb1c9c5031523"
ID = re.compile(r"[0-9a-f]{64}")
VOLUME = re.compile(r"neoth_n8n_[0-9a-f]{32}")
JOB = re.compile(r"[0-9a-f-]{36}")
WORKFLOW_COUNT = 13
WORKFLOW_RESPONSE_MAX = 256 * 1024
PRODUCT_CONFIG_MAX = 256 * 1024
INSTALL_FAILURE_CODES = (
    "n8n_bootstrap_runtime_finalize_unproven", "n8n_loopback_health_timeout",
    "n8n_adoption_cancelled", "n8n_postcommit_probe_failed", "n8n_probe_timeout",
    "n8n_probe_transport", "n8n_unauthorized", "n8n_redirect_rejected",
    "n8n_response_too_large", "n8n_invalid_response", "adoption_prepare_failed",
    "n8n_negative_control_unexpected_success", "n8n_negative_control_not_found",
    "n8n_negative_control_server_error", "n8n_negative_control_unexpected_status",
    "n8n_authenticated_not_found", "n8n_authenticated_server_error",
    "n8n_authenticated_unexpected_status", "n8n_response_json_invalid",
    "n8n_response_envelope_invalid", "n8n_response_cursor_invalid",
    "adoption_validation_failed", "adoption_progress_failed", "adoption_publish_failed",
    "adoption_cleanup_failed", "adoption_cancel_request_failed", "adoption_job_missing",
    "adoption_job_read_failed", "adoption_contract_missing",
)

class Failure(RuntimeError): pass

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

class WorkflowCustodyLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        if not isinstance(node, yaml.nodes.MappingNode):
            raise yaml.constructor.ConstructorError(None, None, "expected mapping", node.start_mark)
        mapping = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in mapping:
                raise yaml.constructor.ConstructorError(None, None, "duplicate or invalid mapping key", key_node.start_mark)
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping

def read_back_state(loader: WorkflowCustodyLoader, node: yaml.nodes.Node) -> tuple[str, dict]:
    if not isinstance(node, yaml.nodes.MappingNode):
        raise yaml.constructor.ConstructorError(None, None, "read_back state must be a mapping", node.start_mark)
    return ("read_back", loader.construct_mapping(node, deep=True))

WorkflowCustodyLoader.add_constructor("!read_back", read_back_state)

def workflow_opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

class CommandFailure(Failure):
    def __init__(self, argv: list[str], result: bounded.Result):
        super().__init__("command_failed")
        program = Path(argv[0]).name
        command = "other"
        if program == "neoth" and argv[1:4] == ["--output", "json", "n8n"]:
            command = {"install": "product_install", "status": "product_status", "repair": "product_repair"}.get(argv[4], "other") if len(argv) > 4 else "other"
        elif program in {"docker", "sqlite3", "secret-tool"}:
            command = program
        self.diagnostic = {
            "command": command, "exit_code": result.code,
            "timed_out": result.timed_out, "overflow": result.overflow,
            "stdout_bytes": len(result.stdout), "stderr_bytes": len(result.stderr),
        }
        # Only literal source-defined categories are disclosed. Never emit
        # arbitrary stderr, JSON error text, arguments or credential values.
        known = (
            "n8n_bootstrap_docker_unavailable", "n8n_bootstrap_docker_failed",
            "n8n_bootstrap_docker_empty_command", "n8n_bootstrap_docker_spawn_failed",
            "n8n_bootstrap_docker_stdin_failed", "n8n_bootstrap_docker_capture_failed",
            "n8n_bootstrap_docker_wait_failed", "n8n_bootstrap_docker_timeout",
            "n8n_bootstrap_docker_cancelled", "n8n_bootstrap_docker_output_limit",
            "n8n_bootstrap_volume_mismatch", "n8n_bootstrap_http_unknown",
            "n8n_bootstrap_http_rejected", "n8n_managed_instance_already_owned",
            "n8n_runtime_binding_write_failed", "n8n_managed_prepared_job_not_active",
            "n8n_container_inspect_unknown", "n8n_managed_container_create_failed",
            "n8n_managed_container_identity_ambiguous",
            "n8n_preexisting_container_unowned_or_mismatch",
            "n8n_managed_custody_mismatch", "n8n_retained_reinstall_already_active", "n8n_docker_wait_failed",
            "n8n_repair_binding_compare_and_set_failed", "n8n_repair_binding_missing",
            "n8n_repair_config_custody_mismatch", "n8n_repair_conflicting_custody",
            "n8n_repair_create_id_unwitnessed", "n8n_repair_create_outcome_uncertain",
            "n8n_repair_custody_create_failed", "n8n_repair_custody_invalid",
            "n8n_repair_custody_mismatch", "n8n_repair_custody_read_failed",
            "n8n_repair_custody_write_failed", "n8n_repair_loopback_health_timeout",
            "n8n_repair_named_container_present", "n8n_repair_receipt_mismatch",
            "n8n_repair_receipt_stale", "n8n_repair_reconciliation_required",
            "n8n_repair_recreated_not_running", "n8n_repair_recreated_outcome_uncertain",
            "n8n_repair_runtime_state_unknown", "n8n_repair_source_missing",
            "n8n_repair_source_read_failed", "n8n_repair_start_outcome_uncertain",
            "n8n_docker_output_limit", "n8n_docker_non_utf8",
            "stale integration job revision", "stale integration job state",
            "illegal integration job transition",
            *INSTALL_FAILURE_CODES,
            "n8n bootstrap requires the private OS secret store",
            "open a Linux Secret Service collection",
            "Cannot start a runtime from within a runtime",
            "Cannot drop a runtime in a context where blocking is not allowed",
        )
        self.diagnostic["known_error_categories"] = [
            marker for marker in known if marker.encode() in result.stderr
        ]

def read_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_bytes())
    except Exception as error: raise Failure("json_invalid") from error
    if not isinstance(value, dict): raise Failure("json_shape_invalid")
    return value

def required(value: dict, key: str, kind: type):
    item = value.get(key)
    if type(item) is not kind: raise Failure(f"missing_{key}")
    return item

def validate_product(value: dict) -> str:
    job = required(value, "job_id", str)
    if not JOB.fullmatch(job) or value.get("state") != "ready" or value.get("failure_code") is not None: raise Failure("product_not_ready")
    return job

def validate_status(value: dict, job: str, port: int) -> None:
    row = value.get("job")
    if not isinstance(row, dict) or row.get("id") != job or row.get("state") != "ready": raise Failure("status_job_mismatch")
    if type(row.get("completed_steps")) is not int or row["completed_steps"] != row.get("total_steps") or row.get("failure_code") is not None: raise Failure("status_progress_invalid")
    if value.get("configured_endpoint") != f"http://127.0.0.1:{port}" or value.get("api_key_present") is not True: raise Failure("status_binding_invalid")

def validate_import_job(value: dict) -> str:
    job = required(value, "job_id", str)
    if not JOB.fullmatch(job) or value.get("state") != "ready" or value.get("operation") != "import_inactive_workflows" or value.get("failure_code") is not None:
        raise Failure("workflow_import_not_ready")
    return job

def validate_uninstall_product(value: dict, source_job: str) -> str:
    job = required(value, "job_id", str)
    if (not JOB.fullmatch(job) or job == source_job or value.get("operation") != "uninstall"
            or value.get("state") != "ready" or value.get("failure_code") is not None
            or value.get("disposition") != "container_removed_data_volume_retained"
            or value.get("config_cleanup") != "preserved_unproven"
            or value.get("data_volume_policy") != "retain"):
        raise Failure("uninstall_not_ready")
    return job

def validate_reinstall_product(value: dict, source_job: str, uninstall_job: str) -> str:
    job = validate_product(value)
    if job in {source_job, uninstall_job} or value.get("probe_binding") != "authenticated_n8n_workflows":
        raise Failure("reinstall_not_ready")
    return job

def validate_reinstalled_custody(runtime: dict, reinstall_job: str, reinstall_manifest: str, volume: str, old_runtime_id: str, port: int) -> str:
    runtime_id = required(runtime, "container_id", str)
    if (runtime.get("schema_version") != 2 or runtime.get("phase") != "Ready"
            or runtime.get("job_id") != reinstall_job or runtime.get("manifest_sha256") != reinstall_manifest
            or not ID.fullmatch(runtime_id) or runtime_id == old_runtime_id
            or runtime.get("container_name") != "neoth-n8n" or runtime.get("host_port") != port
            or runtime.get("volume") != volume or runtime.get("image") != IMAGE):
        raise Failure("reinstall_custody_invalid")
    return runtime_id
def validate_uninstall_status(value: dict, uninstall_job: str) -> None:
    row = value.get("job")
    if (not isinstance(row, dict) or row.get("id") != uninstall_job
            or row.get("operation") != "uninstall" or row.get("state") != "ready"
            or row.get("disposition") != "container_removed_data_volume_retained"
            or row.get("config_cleanup") != "preserved_unproven"
            or row.get("failure_code") is not None
            or type(row.get("completed_steps")) is not int
            or row["completed_steps"] != row.get("total_steps")):
        raise Failure("uninstall_status_invalid")

def read_uninstall_completion_receipt(home: Path, uninstall_job: str, uninstall_manifest: str, source_job: str, source_manifest: str, source_runtime_id: str, volume: str, port: int) -> dict:
    path = home / f"n8n-uninstall-{uninstall_job}.receipt.json"
    value = read_json(path)
    expected = {
        "schema_version": 1,
        "uninstall_job_id": uninstall_job,
        "uninstall_manifest_sha256": uninstall_manifest,
        "source_install_job_id": source_job,
        "source_install_manifest_sha256": source_manifest,
        "cleanup_disposition": "preserved_unproven",
        "source_container_id": source_runtime_id,
        "source_image": IMAGE,
        "source_host_port": port,
        "source_volume": volume,
        "source_bootstrap_volume": True,
        "source_retained_reinstall": None,
        "source_volume_owner_install_job_id": source_job,
    }
    if value != expected:
        raise Failure("uninstall_completion_receipt_invalid")
    return {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "bytes": path.stat().st_size}

def read_reinstall_uninstall_completion_receipt(home: Path, uninstall_job: str, uninstall_manifest: str, reinstall_job: str, reinstall_manifest: str, runtime_id: str, volume: str, port: int, original_uninstall_job: str, original_uninstall_manifest: str, original_install_job: str, original_install_manifest: str) -> dict:
    path = home / f"n8n-uninstall-{uninstall_job}.receipt.json"
    value = read_json(path)
    expected = {
        "schema_version": 1,
        "uninstall_job_id": uninstall_job,
        "uninstall_manifest_sha256": uninstall_manifest,
        "source_install_job_id": reinstall_job,
        "source_install_manifest_sha256": reinstall_manifest,
        "cleanup_disposition": "preserved_unproven",
        "source_container_id": runtime_id,
        "source_image": IMAGE,
        "source_host_port": port,
        "source_volume": volume,
        "source_bootstrap_volume": True,
        "source_retained_reinstall": {
            "uninstall_job_id": original_uninstall_job,
            "uninstall_manifest_sha256": original_uninstall_manifest,
            "source_install_job_id": original_install_job,
            "source_install_manifest_sha256": original_install_manifest,
            "bootstrap_volume": True,
            "volume_owner_install_job_id": original_install_job,
        },
        "source_volume_owner_install_job_id": original_install_job,
    }
    if value != expected:
        raise Failure("reinstall_uninstall_completion_receipt_invalid")
    return {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "bytes": path.stat().st_size}
def observe_exact_job(home: Path, job: str, operation: str) -> dict:
    if not JOB.fullmatch(job):
        raise Failure("exact_job_row_invalid")
    output = run(["sqlite3", "-readonly", "-json", str(home / "setup.db"), "SELECT * FROM integration_jobs WHERE job_id='" + job + "';"])
    rows = json.loads(output)
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise Failure("exact_job_row_invalid")
    row = rows[0]
    if (row.get("job_id") != job or row.get("operation") != operation or row.get("state") != "ready"
            or type(row.get("state_revision")) is not int or row["state_revision"] < 0
            or type(row.get("completed_steps")) is not int
            or type(row.get("total_steps")) is not int or row["total_steps"] < 1
            or row["completed_steps"] != row["total_steps"]
            or not isinstance(row.get("manifest_sha256"), str) or not ID.fullmatch(row["manifest_sha256"])):
        raise Failure("exact_job_row_invalid")
    return {"row_sha256": json_sha256(row), "manifest_sha256": row["manifest_sha256"], "revision": row["state_revision"]}

def observe_full_job_row(home: Path, job: str, operation: str) -> str:
    columns = ("job_id", "capability_id", "operation", "release_version", "manifest_sha256", "state", "state_revision", "current_step", "completed_steps", "total_steps", "bytes_done", "bytes_total", "created_at", "started_at", "updated_at", "terminal_at", "error_code", "redacted_error", "ready_evidence_json", "retry_of", "requested_by", "cancel_requested", "evidence_contract_json", "progress_evidence_json")
    pairs = ",".join(f"'{column}',{column}" for column in columns)
    output = run(["sqlite3", "-readonly", str(home / "setup.db"), "SELECT json_object(" + pairs + ") FROM integration_jobs WHERE job_id='" + job + "';"])
    rows = output.splitlines()
    if len(rows) != 1:
        raise Failure("full_job_row_invalid")
    value = read_json_bytes(rows[0])
    if value.get("job_id") != job or value.get("operation") != operation:
        raise Failure("full_job_row_invalid")
    return hashlib.sha256(rows[0]).hexdigest()
def observe_all_job_rows(home: Path) -> str:
    output = run(["sqlite3", "-readonly", "-json", str(home / "setup.db"), "SELECT * FROM integration_jobs ORDER BY job_id;"])
    try: value = json.loads(output)
    except Exception as error: raise Failure("all_job_rows_invalid") from error
    if not isinstance(value, list) or any(not isinstance(row, dict) or not isinstance(row.get("job_id"), str) for row in value): raise Failure("all_job_rows_invalid")
    return hashlib.sha256(output).hexdigest()
def purge_artifacts_absent(home: Path) -> tuple[str, ...]:
    custody = home / "n8n-managed-purge.v1.json"
    if custody.exists() or custody.is_symlink(): raise Failure("purge_custody_present")
    receipts = tuple(sorted(path.name for path in home.iterdir() if path.is_file() and not path.is_symlink() and re.fullmatch(r"n8n-purge-[0-9a-f-]{36}\.receipt\.json", path.name)))
    if receipts: raise Failure("purge_receipt_present")
    return receipts
def validate_retained_volume(row: dict, source_job: str, volume: str) -> None:
    labels = row.get("Labels")
    if (row.get("Name") != volume or not isinstance(labels, dict)
            or labels.get("io.neoth.managed") != "n8n"
            or labels.get("io.neoth.n8n-job") != source_job
            or labels.get("io.neoth.n8n-bootstrap") != "v2"):
        raise Failure("retained_volume_identity_invalid")

def sidecar_absent(home: Path, name: str) -> None:
    path = home / name
    if path.exists() or path.is_symlink():
        raise Failure("active_sidecar_retained")

def json_sha256(value: dict) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()

def purge_phrase(uninstall_job: str, volume: str) -> str:
    if not JOB.fullmatch(uninstall_job) or not VOLUME.fullmatch(volume): raise Failure("purge_target_invalid")
    return f"PURGE N8N VOLUME {uninstall_job} {volume}"
def validate_purge_plan(value: dict, uninstall_job: str, volume: str) -> str:
    phrase = purge_phrase(uninstall_job, volume)
    if value != {"operation": "purge", "state": "confirmation_required", "uninstall_job_id": uninstall_job, "volume": volume, "confirmation": phrase}: raise Failure("purge_plan_invalid")
    return phrase
def validate_purge_product(value: dict, uninstall_job: str) -> str:
    job = required(value, "job_id", str)
    if not JOB.fullmatch(job) or value != {"job_id": job, "operation": "purge", "state": "ready", "disposition": "volume_removed", "uninstall_job_id": uninstall_job, "failure_code": None}: raise Failure("purge_product_invalid")
    return job

def validate_repair_product(value: dict, source_job: str, action: str) -> str:
    """Accept only the redacted, completed same-generation repair receipt."""
    job = required(value, "job_id", str)
    if (set(value) != {"job_id", "state", "operation", "action", "failure_code"}
            or not JOB.fullmatch(job) or job == source_job or value.get("operation") != "repair"
            or value.get("state") != "ready" or value.get("action") != action
            or value.get("failure_code") is not None):
        raise Failure("repair_not_ready")
    return job

def validate_repair_custody(value: dict, repair_job: str, repair_manifest: str,
                            source_job: str, source_manifest: str, action: str,
                            old_runtime_id: str, runtime_id: str, volume: str,
                            port: int, expected_old_binding: dict) -> int:
    """Bind a repair result to its source Ready witness and exact runtime ids."""
    custody_manifest = required(value, "repair_manifest_sha256", str)
    old_binding = required(value, "old_binding", dict)
    binding = value.get("new_binding") if action == "recreated" else old_binding
    generation = value.get("generation")
    expected_new_binding = dict(expected_old_binding)
    expected_new_binding.update({"container_id": runtime_id, "phase": "Ready"})
    if (not re.fullmatch(r"[0-9a-f]{64}", custody_manifest)
            or value.get("schema_version") != 1 or value.get("phase") != "completed"
            or type(generation) is not int or generation < 1
            or value.get("repair_job_id") != repair_job or custody_manifest != repair_manifest
            or value.get("source_install_job_id") != source_job
            or value.get("source_install_manifest_sha256") != source_manifest
            or value.get("action") != action or value.get("old_container_id") != old_runtime_id
            or old_binding != expected_old_binding
            or not isinstance(binding, dict) or binding != expected_new_binding
            or binding.get("container_id") != runtime_id or binding.get("job_id") != source_job
            or binding.get("manifest_sha256") != source_manifest
            or binding.get("phase") != "Ready" or binding.get("container_name") != "neoth-n8n"
            or binding.get("host_port") != port or binding.get("volume") != volume
            or binding.get("image") != IMAGE):
        raise Failure("repair_custody_invalid")
    if action == "recreated":
        if value.get("new_container_id") != runtime_id or runtime_id == old_runtime_id:
            raise Failure("repair_custody_invalid")
    elif value.get("new_container_id") is not None or value.get("new_binding") is not None:
        raise Failure("repair_custody_invalid")
    return generation

def validate_repair_generation(home: Path, expected_generation: int) -> None:
    value = read_json(home / "n8n-managed-repair-generation.v1.json")
    if value != {"schema_version": 1, "generation": expected_generation}:
        raise Failure("repair_generation_invalid")

def assert_runtime_running(identifier: str, expected: bool) -> None:
    row = docker_inspect(identifier)
    if row.get("Id") != identifier or row.get("State", {}).get("Running") is not expected:
        raise Failure("runtime_running_state_invalid")
def read_purge_receipt(home: Path, purge_job: str, purge_manifest: str, uninstall_job: str, volume: str) -> dict:
    path = home / f"n8n-purge-{purge_job}.receipt.json"; value = read_json(path)
    if value != {"schema_version": 1, "purge_job_id": purge_job, "purge_manifest_sha256": purge_manifest, "uninstall_job_id": uninstall_job, "volume": volume, "disposition": "volume_removed"}: raise Failure("purge_receipt_invalid")
    return {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "bytes": path.stat().st_size}

def cleanup_owned_runtime_and_volume(runtime_id: str, volume: str, job: str, port: int, runtime_already_absent: bool, volume_already_absent: bool = False) -> bool:
    try:
        if runtime_already_absent or exact_absent("container", runtime_id):
            if not exact_absent("container", runtime_id):
                return False
        else:
            validate_runtime(docker_inspect(runtime_id), job, volume, runtime_id, port)
            run(["docker", "rm", "-f", runtime_id])
            if not exact_absent("container", runtime_id):
                return False
        if volume_already_absent:
            return exact_absent("volume", volume)
        row = docker_inspect(volume)
        validate_retained_volume(row, job, volume)
        run(["docker", "volume", "rm", volume])
        return exact_absent("volume", volume)
    except Exception:
        return False
def workflow_templates(value: dict) -> tuple[tuple[str, str], ...]:
    rows = required(value, "workflows", list)
    if len(rows) != WORKFLOW_COUNT:
        raise Failure("workflow_template_count_invalid")
    templates = []
    for row in rows:
        if not isinstance(row, dict):
            raise Failure("workflow_template_shape_invalid")
        slug, name = row.get("slug"), row.get("name")
        if not isinstance(slug, str) or not slug or len(slug) > 128 or not isinstance(name, str) or not name or len(name) > 512:
            raise Failure("workflow_template_shape_invalid")
        templates.append((slug, name))
    if len(set(templates)) != WORKFLOW_COUNT or len({slug for slug, _ in templates}) != WORKFLOW_COUNT or len({name for _, name in templates}) != WORKFLOW_COUNT:
        raise Failure("workflow_template_duplicate")
    return tuple(templates)

def workflow_api_json(port: int, key: bytes, path: str) -> dict:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", headers={"X-N8N-API-KEY": key.decode("utf-8", "strict")}
    )
    try:
        with workflow_opener().open(request, timeout=20) as response:
            if 300 <= response.status < 400:
                raise Failure("workflow_observer_redirect")
            raw = response.read(WORKFLOW_RESPONSE_MAX + 1)
    except urllib.error.HTTPError as error:
        if 300 <= error.code < 400:
            raise Failure("workflow_observer_redirect") from error
        raise Failure("workflow_observer_request_failed") from error
    except Exception as error:
        raise Failure("workflow_observer_request_failed") from error
    if len(raw) > WORKFLOW_RESPONSE_MAX:
        raise Failure("workflow_observer_response_too_large")
    return read_json_bytes(raw)

def workflow_data(value: dict) -> dict:
    data = value.get("data", value)
    if not isinstance(data, dict):
        raise Failure("workflow_observer_shape_invalid")
    return data

def observe_imported_workflows(port: int, key: bytes, templates: tuple[tuple[str, str], ...]) -> dict:
    listing = workflow_api_json(port, key, "/api/v1/workflows?limit=100")
    rows = listing.get("data")
    if not isinstance(rows, list) or len(rows) != WORKFLOW_COUNT:
        raise Failure("workflow_observer_count_invalid")
    expected_names = {name for _, name in templates}
    found: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str) or not row["id"] or len(row["id"]) > 256 or any(ord(character) < 32 or ord(character) == 127 for character in row["id"]) or not isinstance(row.get("name"), str) or row.get("active") is not False:
            raise Failure("workflow_observer_list_invalid")
        name = row["name"]
        if name not in expected_names or name in found:
            raise Failure("workflow_observer_list_invalid")
        found[name] = row["id"]
    if set(found) != expected_names or len(set(found.values())) != WORKFLOW_COUNT:
        raise Failure("workflow_observer_list_invalid")
    exact = []
    for slug, name in templates:
        identifier = found[name]
        read = workflow_data(workflow_api_json(port, key, f"/api/v1/workflows/{urllib.parse.quote(identifier, safe='')}"))
        if read.get("id") != identifier or read.get("name") != name or read.get("active") is not False:
            raise Failure("workflow_observer_readback_invalid")
        graph = {field: read.get(field) for field in ("name", "nodes", "connections", "settings")}
        if any(value is None for value in graph.values()):
            raise Failure("workflow_observer_graph_invalid")
        exact.append((slug, identifier, hashlib.sha256(json.dumps(graph, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()))
    encoded = json.dumps(exact, separators=(",", ":")).encode("utf-8")
    return {"count": WORKFLOW_COUNT, "workflow_set_sha256": hashlib.sha256(encoded).hexdigest(), "entries": tuple(exact)}

def observe_workflow_custody(home: Path, job: str, observed: tuple[tuple[str, str, str], ...]) -> dict:
    path = home / f".n8n-workflow-import-{job}.custody.yaml"
    if path.is_symlink() or not path.is_file():
        raise Failure("workflow_import_custody_missing")
    with path.open("rb") as custody_file:
        raw = custody_file.read(64 * 1024 + 1)
    if len(raw) > 64 * 1024:
        raise Failure("workflow_import_custody_too_large")
    try:
        custody = yaml.load(raw, Loader=WorkflowCustodyLoader)
    except yaml.YAMLError as error:
        raise Failure("workflow_import_custody_invalid") from error
    if not isinstance(custody, dict) or set(custody) != {"job_id", "endpoint_binding_sha256", "credential_binding_sha256", "manifest_sha256", "entries"} or custody.get("job_id") != job or not all(isinstance(custody.get(name), str) and ID.fullmatch(custody[name]) for name in ("endpoint_binding_sha256", "credential_binding_sha256", "manifest_sha256")):
        raise Failure("workflow_import_custody_invalid")
    entries = custody.get("entries")
    if not isinstance(entries, list) or len(entries) != WORKFLOW_COUNT or len(observed) != WORKFLOW_COUNT:
        raise Failure("workflow_import_custody_invalid")
    for entry, (slug, identifier, graph_sha256) in zip(entries, observed, strict=True):
        if not isinstance(entry, dict) or set(entry) != {"slug", "source_sha256", "create_dto_sha256", "state"} or entry.get("slug") != slug or not all(isinstance(entry.get(name), str) and ID.fullmatch(entry[name]) for name in ("source_sha256", "create_dto_sha256")):
            raise Failure("workflow_import_custody_invalid")
        state = entry.get("state")
        if not isinstance(state, tuple) or len(state) != 2 or state[0] != "read_back" or not isinstance(state[1], dict) or set(state[1]) != {"workflow_id", "normalized_readback_sha256"} or state[1].get("workflow_id") != identifier or state[1].get("normalized_readback_sha256") != graph_sha256:
            raise Failure("workflow_import_custody_invalid")
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "manifest_sha256": custody["manifest_sha256"]}

def observe_import_job(home: Path, job: str) -> dict:
    output = run(["sqlite3", "-readonly", str(home / "setup.db"), "SELECT capability_id || '|' || operation || '|' || state || '|' || state_revision || '|' || completed_steps || '|' || total_steps || '|' || manifest_sha256 FROM integration_jobs WHERE job_id='" + job + "';"])
    rows = output.decode("utf-8", "strict").splitlines()
    if len(rows) != 1:
        raise Failure("workflow_import_job_row_invalid")
    parts = rows[0].split("|")
    if len(parts) != 7 or parts[0] != "n8n-instance" or parts[1] != "import" or parts[2] != "ready" or parts[4] != str(WORKFLOW_COUNT) or parts[5] != str(WORKFLOW_COUNT) or not parts[3].isdigit() or not ID.fullmatch(parts[6]):
        raise Failure("workflow_import_job_row_invalid")
    return {"sha256": hashlib.sha256(rows[0].encode("utf-8")).hexdigest(), "revision": int(parts[3]), "manifest_sha256": parts[6]}

def validate_workflow_import_provenance(custody: dict, import_job: dict) -> None:
    if custody.get("manifest_sha256") != import_job.get("manifest_sha256"):
        raise Failure("workflow_import_provenance_mismatch")

def validate_custody(boot: dict, runtime: dict, job: str, port: int) -> tuple[str, str, str]:
    for row, schema in ((boot, 2), (runtime, 2)):
        if row.get("schema_version") != schema or row.get("phase") != "Ready" or row.get("job_id") != job or type(row.get("manifest_sha256")) is not str: raise Failure("custody_invalid")
    if not ID.fullmatch(boot["manifest_sha256"]) or runtime["manifest_sha256"] != boot["manifest_sha256"]:
        raise Failure("custody_manifest_mismatch")
    volume = required(boot, "volume_name", str); bootstrap_id = required(boot, "bootstrap_container_id", str); runtime_id = required(boot, "runtime_container_id", str)
    if not VOLUME.fullmatch(volume) or not ID.fullmatch(bootstrap_id) or not ID.fullmatch(runtime_id): raise Failure("custody_identity_invalid")
    if boot.get("host_port") != port or boot.get("pinned_image") != IMAGE or runtime.get("container_id") != runtime_id or runtime.get("container_name") != "neoth-n8n" or runtime.get("host_port") != port or runtime.get("volume") != volume or runtime.get("image") != IMAGE: raise Failure("custody_binding_mismatch")
    return volume, bootstrap_id, runtime_id

def read_product_config(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise Failure("product_init_config_missing")
    with path.open("rb") as config_file:
        raw = config_file.read(PRODUCT_CONFIG_MAX + 1)
    if len(raw) > PRODUCT_CONFIG_MAX:
        raise Failure("product_init_config_too_large")
    try:
        config = yaml.safe_load(raw)
    except yaml.YAMLError as error:
        raise Failure("product_init_config_invalid") from error
    if not isinstance(config, dict):
        raise Failure("product_init_config_invalid")
    return config

def initialize_product_home(binary: Path, home: Path) -> None:
    config_path = home / "freedom.yaml"
    if config_path.exists() or config_path.is_symlink():
        raise Failure("product_init_config_preexisting")
    run([str(binary), "init", "--non-interactive", "--cli", "--accept-license", "--operator-id", "w1127canary", "--provider", "skip"])
    config = read_product_config(config_path)
    config["secrets_backend"] = "keychain"
    rendered = yaml.safe_dump(config, allow_unicode=True, sort_keys=True).encode("utf-8")
    if len(rendered) > PRODUCT_CONFIG_MAX:
        raise Failure("product_init_config_too_large")
    config_path.write_bytes(rendered)
    if read_product_config(config_path).get("secrets_backend") != "keychain":
        raise Failure("product_init_keychain_unproven")

def first_product_install(binary: Path, home: Path, port: int) -> dict:
    initialize_product_home(binary, home)
    return read_json_from_command([str(binary), "--output", "json", "n8n", "install", "--bootstrap-owner", "--port", str(port)])

def run(argv: list[str], timeout: int = 180) -> bytes:
    result = bounded.run(argv, timeout=timeout)
    if result.code != 0 or result.timed_out or result.overflow:
        raise CommandFailure(argv, result)
    return result.stdout

def run_with_payload(argv: list[str], payload: bytes, timeout: int = 180) -> bytes:
    result = bounded.run(argv, payload=payload, timeout=timeout)
    if result.code != 0 or result.timed_out or result.overflow:
        raise CommandFailure(argv, result)
    return result.stdout

def read_json_from_payload_command(argv: list[str], payload: bytes) -> dict:
    return read_json_bytes(run_with_payload(argv, payload))
def assert_reinstall_repeat_rejected(binary: Path, uninstall_job: str, payload: bytes) -> dict:
    result = bounded.run([str(binary), "--output", "json", "n8n", "install", "--reuse-uninstall", uninstall_job, "--api-key-stdin"], payload=payload, timeout=180)
    if result.code == 0 or result.timed_out or result.overflow or b"n8n_retained_reinstall_already_active" not in result.stderr:
        raise Failure("reinstall_repeat_rejection_unproven")
    return {"exit_code": result.code, "reason": "active_runtime_pre_effect_rejection"}
def docker_inspect(identifier: str) -> dict:
    raw = run(["docker", "inspect", identifier])
    value = json.loads(raw)
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict): raise Failure("docker_inspect_invalid")
    return value[0]

def validate_runtime(row: dict, job: str, volume: str, runtime_id: str, port: int) -> None:
    labels = row.get("Config", {}).get("Labels", {}); mounts = row.get("Mounts", []); ports = row.get("NetworkSettings", {}).get("Ports", {}).get("5678/tcp")
    if row.get("Id") != runtime_id or row.get("Config", {}).get("Image") != IMAGE or labels.get("io.neoth.managed") != "n8n" or labels.get("io.neoth.n8n-job") != job: raise Failure("runtime_identity_invalid")
    if not isinstance(mounts, list) or len(mounts) != 1 or mounts[0].get("Type") != "volume" or mounts[0].get("Name") != volume or mounts[0].get("Destination") != "/home/node/.n8n": raise Failure("runtime_mount_invalid")
    if not isinstance(ports, list) or len(ports) != 1 or ports[0].get("HostIp") != "127.0.0.1" or ports[0].get("HostPort") != str(port): raise Failure("runtime_port_invalid")

def exact_absent(kind: str, identifier: str) -> bool:
    try:
        bounded.prove_absent(kind, identifier)
        return True
    except bounded.CanaryFailure:
        return False

def hosted_paths(home: Path, receipt: Path) -> Path:
    root_text = os.environ.get("RUNNER_TEMP", "")
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("GITHUB_REF") != "refs/heads/main" or not re.fullmatch(r"[0-9a-f]{40}", os.environ.get("GITHUB_SHA", "")) or not re.fullmatch(r"[1-9][0-9]*", os.environ.get("GITHUB_RUN_ID", "")) or not re.fullmatch(r"[1-9][0-9]*", os.environ.get("GITHUB_RUN_ATTEMPT", "")) or not root_text: raise Failure("hosted_guard_failed")
    root = Path(root_text).resolve()
    task_root = root / f"w1018-n8n-{os.environ['GITHUB_RUN_ID']}-{os.environ['GITHUB_RUN_ATTEMPT']}"
    if home.is_symlink() or not home.is_dir() or home.resolve() != task_root / "neoth-home" or receipt.resolve() != task_root / "receipt" / "receipt.json" or any(home.iterdir()):
        raise Failure("isolated_path_invalid")
    if os.environ.get("NEOTH_HOME") != str(home.resolve()):
        raise Failure("product_home_environment_mismatch")
    return task_root

def validate_single_job(home: Path, job: str, manifest: str) -> None:
    output = run(["sqlite3", "-readonly", str(home / "setup.db"), "SELECT job_id || '|' || manifest_sha256 || '|' || state FROM integration_jobs WHERE capability_id='n8n-instance';"])
    rows = output.decode("utf-8", "strict").splitlines()
    if rows != [f"{job}|{manifest}|ready"]: raise Failure("durable_job_row_invalid")

def observe_failed_install_job(home: Path) -> dict:
    bootstrap = read_json(home / "n8n-managed-bootstrap.v2.json")
    job = bootstrap.get("job_id")
    if bootstrap.get("schema_version") != 2 or bootstrap.get("phase") not in {"VolumeIntent", "VolumeBound", "BootstrapContainerBound", "OwnerSetupInFlight", "OwnerEstablished", "KeyMintInFlight", "KeyMintUnknown", "KeyCaptured", "BootstrapStopped", "BootstrapRemoved", "RuntimeContainerBound", "Ready"} or not isinstance(job, str) or not JOB.fullmatch(job):
        raise Failure("bootstrap_job_custody_invalid")
    output = run(["sqlite3", "-readonly", str(home / "setup.db"), "SELECT state || '|' || COALESCE(error_code, '') FROM integration_jobs WHERE job_id='" + job + "';"])
    rows = output.decode("utf-8", "strict").splitlines()
    if len(rows) != 1:
        raise Failure("bootstrap_job_row_invalid")
    state, separator, error_code = rows[0].partition("|")
    if not separator or state not in {"queued", "running", "validating", "configuring", "ready", "failed", "cancelled"}:
        raise Failure("bootstrap_job_row_invalid")
    return {"state": state, "error_code": error_code if error_code in INSTALL_FAILURE_CODES else "unclassified"}

def authenticated_probe(job: str, port: int) -> dict:
    key = run(["secret-tool", "lookup", "neoth-key", f"n8n-bootstrap.captured-api-key.{job}"], timeout=10).rstrip(b"\n")
    if not 8 <= len(key) <= 8192 or any(byte < 32 or byte == 127 for byte in key):
        raise Failure("captured_key_unavailable")
    try:
        return bounded.final_host_probe(port, key.decode("utf-8", "strict"))
    except Exception as error:
        raise Failure("authenticated_probe_invalid") from error

def canonical_n8n_api_key() -> bytes:
    key = run(["secret-tool", "lookup", "neoth-key", "n8n_api_key"], timeout=10).rstrip(b"\n")
    if not 8 <= len(key) <= 8192 or any(byte < 32 or byte == 127 for byte in key):
        raise Failure("canonical_n8n_key_unavailable")
    return key
def clear_bootstrap_secrets(job: str) -> None:
    for kind in ("owner-password", "browser-id", "api-key-label", "captured-api-key"):
        key = f"n8n-bootstrap.{kind}.{job}"
        run(["secret-tool", "clear", "neoth-key", key], timeout=10)
        result = bounded.run(["secret-tool", "lookup", "neoth-key", key], timeout=10)
        if result.timed_out or result.overflow or result.code != 1 or result.stdout or result.stderr:
            raise Failure("secret_removal_unproven")

def assert_no_rebootstrap_events(output: str, job: str) -> None:
    for line in output.splitlines():
        if not line:
            continue
        event = json.loads(line)
        actor = event.get("Actor", {})
        if not isinstance(actor, dict) or actor.get("Attributes", {}).get("io.neoth.n8n-job") != job:
            raise Failure("event_owner_mismatch")
        action = event.get("Action")
        if not isinstance(action, str):
            raise Failure("event_shape_invalid")
        if action.split(":", 1)[0] in {"create", "start", "exec_create", "exec_start"}:
            raise Failure("second_call_rebootstrap_event")

def assert_no_repair_runtime_effect_events(output: str, job: str) -> None:
    """A healthy repair must not touch the owned container at all."""
    blocked = {"create", "start", "exec_create", "exec_start", "stop", "die", "kill", "destroy", "remove"}
    for line in output.splitlines():
        if not line:
            continue
        event = json.loads(line)
        actor = event.get("Actor", {})
        if not isinstance(actor, dict) or actor.get("Attributes", {}).get("io.neoth.n8n-job") != job:
            raise Failure("event_owner_mismatch")
        action = event.get("Action")
        if not isinstance(action, str):
            raise Failure("event_shape_invalid")
        if action.split(":", 1)[0] in blocked:
            raise Failure("healthy_repair_runtime_effect_event")

def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--binary", required=True); parser.add_argument("--home", required=True); parser.add_argument("--port", required=True, type=int); parser.add_argument("--receipt", required=True)
    args = parser.parse_args(); binary, home, receipt_path = Path(args.binary), Path(args.home), Path(args.receipt)
    # Reject untrusted destinations before entering any receipt/cleanup path.
    try:
        hosted_paths(home, receipt_path)
        if not 1 <= args.port <= 65535:
            return 2
    except Exception:
        return 2
    receipt = {"schema": 1, "source_sha": os.environ.get("GITHUB_SHA"), "port": args.port, "outcome": "failed"}; runtime_id = volume = job = None; uninstall_runtime_absent = False; volume_purged = False
    try:
        receipt.update({"helper_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "bounded_helper_sha256": hashlib.sha256(Path(bounded.__file__).read_bytes()).hexdigest(), "workflow_sha256": hashlib.sha256((Path.cwd() / ".github/workflows/n8n-product-bootstrap.yml").read_bytes()).hexdigest(), "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(), "cargo_lock_sha256": hashlib.sha256((Path.cwd() / "SRC/Cargo.lock").read_bytes()).hexdigest()})
        input_names = (
            "packaging/tests/test_n8n_product_bootstrap_canary.py",
            "SRC/neothd/src/cli/n8n.rs", "SRC/neothd/src/integrations/n8n.rs",
            "SRC/neothd/src/integrations/n8n/managed_bootstrap.rs",
            "SRC/neothd/src/integrations/n8n/managed_runtime.rs", "SRC/neothd/src/integrations/n8n/managed_repair.rs", "SRC/neothd/src/integrations/n8n/managed_repair_tests.rs", "SRC/neothd/src/integrations/n8n/managed_uninstall.rs", "SRC/neothd/src/integrations/n8n/managed_purge.rs",
            "SRC/neothd/src/integrations/n8n/bootstrap_transport.rs",
            "SRC/neothd/src/integrations/n8n/workflow_import.rs",
            "SRC/neothd/src/integrations/jobs.rs", "SRC/neothd/src/integrations/state.rs",
            "SRC/neothd/src/installers/n8n_workflows.rs",
            "SRC/neothd/src/installers/n8n_starter_workflows.rs",
            "SRC/neothd/src/cli/init.rs", "SRC/neothd/src/cli/init/io.rs",
            "SRC/neothd/src/cli/init/steps_provider.rs", "SRC/neothd/src/cli/init/types.rs",
            "SRC/neothd/src/cli/credential.rs", "SRC/neothd/src/config/mod.rs",
            "SRC/neothd/src/config/credentials.rs", "SRC/neothd/src/config/keychain.rs",
        )
        assets = sorted((Path.cwd() / "SRC/neothd/assets/n8n_workflows").glob("*.json"))
        if len(assets) != 3:
            raise Failure("workflow_asset_set_invalid")
        receipt["input_sha256"] = {
            name: hashlib.sha256((Path.cwd() / name).read_bytes()).hexdigest()
            for name in input_names + tuple(str(asset.relative_to(Path.cwd())).replace("\\", "/") for asset in assets)
        }
        receipt["stage"] = "first_product_install"
        first = first_product_install(binary, home, args.port)
        job = validate_product(first); receipt["job_id"] = job; receipt["first_state"] = first["state"]
        status = read_json_from_command([str(binary), "--output", "json", "n8n", "status", "--job", job]); validate_status(status, job, args.port)
        boot = read_json(home / "n8n-managed-bootstrap.v2.json"); runtime = read_json(home / "n8n-managed-runtime.v2.json")
        volume, bootstrap_id, runtime_id = validate_custody(boot, runtime, job, args.port); validate_runtime(docker_inspect(runtime_id), job, volume, runtime_id, args.port)
        validate_single_job(home, job, boot["manifest_sha256"])
        source_install = observe_exact_job(home, job, "install")
        source_install_full = observe_full_job_row(home, job, "install")
        if source_install["manifest_sha256"] != boot["manifest_sha256"]:
            raise Failure("source_install_manifest_mismatch")
        if not exact_absent("container", bootstrap_id): raise Failure("bootstrap_absence_unproven")
        receipt["http_probe"] = authenticated_probe(job, args.port)
        before_ns = time.time_ns()
        before = f"{before_ns // 1_000_000_000}.{before_ns % 1_000_000_000:09d}"
        try:
            second = read_json_from_command([str(binary), "--output", "json", "n8n", "install", "--bootstrap-owner", "--port", str(args.port)])
        finally:
            after_ns = time.time_ns()
            after = f"{after_ns // 1_000_000_000}.{after_ns % 1_000_000_000:09d}"
            output = run(["docker", "events", "--since", before, "--until", after, "--format", "{{json .}}", "--filter", f"label=io.neoth.n8n-job={job}"], timeout=20).decode("utf-8", "strict")
        if validate_product(second) != job: raise Failure("second_job_not_reused")
        second_boot = read_json(home / "n8n-managed-bootstrap.v2.json")
        second_runtime = read_json(home / "n8n-managed-runtime.v2.json")
        validate_custody(second_boot, second_runtime, job, args.port)
        if second_boot != boot or second_runtime != runtime:
            raise Failure("second_custody_changed")
        validate_status(read_json_from_command([str(binary), "--output", "json", "n8n", "status", "--job", job]), job, args.port)
        validate_runtime(docker_inspect(runtime_id), job, volume, runtime_id, args.port)
        receipt["second_http_probe"] = authenticated_probe(job, args.port)
        validate_single_job(home, job, boot["manifest_sha256"])
        assert_no_rebootstrap_events(output, job)
        templates = workflow_templates(read_json_from_command([str(binary), "--output", "json", "n8n", "workflows"]))
        receipt["stage"] = "first_workflow_import"
        first_import_raw = run([str(binary), "--output", "json", "n8n", "import-workflows"])
        import_job = validate_import_job(read_json_bytes(first_import_raw))
        key = run(["secret-tool", "lookup", "neoth-key", f"n8n-bootstrap.captured-api-key.{job}"], timeout=10).rstrip(b"\n")
        canonical_key = canonical_n8n_api_key()
        if canonical_key != key:
            raise Failure("canonical_n8n_key_mismatch")
        first_workflows = observe_imported_workflows(args.port, key, templates)
        first_custody = observe_workflow_custody(home, import_job, first_workflows["entries"])
        first_import_job = observe_import_job(home, import_job)
        validate_workflow_import_provenance(first_custody, first_import_job)
        receipt["stage"] = "second_workflow_import"
        second_import_raw = run([str(binary), "--output", "json", "n8n", "import-workflows"])
        if second_import_raw != first_import_raw or validate_import_job(read_json_bytes(second_import_raw)) != import_job:
            raise Failure("workflow_import_repeat_changed")
        second_workflows = observe_imported_workflows(args.port, key, templates)
        second_custody = observe_workflow_custody(home, import_job, second_workflows["entries"])
        second_import_job = observe_import_job(home, import_job)
        validate_workflow_import_provenance(second_custody, second_import_job)
        if second_workflows != first_workflows or second_custody != first_custody or second_import_job != first_import_job:
            raise Failure("workflow_import_repeat_not_read_only")
        receipt["workflow_import"] = {"workflow_count": WORKFLOW_COUNT, "first_cli_sha256": hashlib.sha256(first_import_raw).hexdigest(), "workflow_set_sha256": first_workflows["workflow_set_sha256"], "custody_sha256": first_custody["sha256"], "custody_bytes": first_custody["bytes"], "job_row_sha256": first_import_job["sha256"], "job_revision": first_import_job["revision"], "repeat_read_only": True}
        receipt["stage"] = "healthy_n8n_repair"
        before_ns = time.time_ns()
        before = f"{before_ns // 1_000_000_000}.{before_ns % 1_000_000_000:09d}"
        try:
            healthy_repair_raw = run([str(binary), "--output", "json", "n8n", "repair"])
        finally:
            after_ns = time.time_ns()
            after = f"{after_ns // 1_000_000_000}.{after_ns % 1_000_000_000:09d}"
            healthy_events = run(["docker", "events", "--since", before, "--until", after, "--format", "{{json .}}", "--filter", f"label=io.neoth.n8n-job={job}"], timeout=20).decode("utf-8", "strict")
        if canonical_key in healthy_repair_raw:
            raise Failure("repair_output_key_leak")
        healthy_repair_job = validate_repair_product(read_json_bytes(healthy_repair_raw), job, "healthy")
        healthy_repair_record = observe_exact_job(home, healthy_repair_job, "repair")
        validate_status(read_json_from_command([str(binary), "--output", "json", "n8n", "status", "--job", healthy_repair_job]), healthy_repair_job, args.port)
        healthy_runtime = read_json(home / "n8n-managed-runtime.v2.json")
        if healthy_runtime != runtime:
            raise Failure("healthy_repair_runtime_mutation")
        healthy_generation = validate_repair_custody(read_json(home / "n8n-managed-repair.v1.json"), healthy_repair_job, healthy_repair_record["manifest_sha256"], job, source_install["manifest_sha256"], "healthy", runtime_id, runtime_id, volume, args.port, runtime)
        validate_repair_generation(home, healthy_generation)
        validate_runtime(docker_inspect(runtime_id), job, volume, runtime_id, args.port)
        assert_runtime_running(runtime_id, True)
        assert_no_repair_runtime_effect_events(healthy_events, job)
        if (authenticated_probe(job, args.port) != receipt["http_probe"]
                or observe_imported_workflows(args.port, canonical_key, templates) != first_workflows
                or observe_exact_job(home, job, "install") != source_install
                or observe_full_job_row(home, job, "install") != source_install_full
                or canonical_n8n_api_key() != canonical_key):
            raise Failure("healthy_repair_authority_or_data_mutation")
        receipt["repair_healthy"] = {"job_id": healthy_repair_job, "job_row_sha256": healthy_repair_record["row_sha256"], "manifest_sha256": healthy_repair_record["manifest_sha256"], "generation": healthy_generation, "runtime_id": runtime_id, "volume": volume, "no_docker_effect": True, "authenticated": True, "workflows_persisted": True}
        receipt["stage"] = "stopped_exact_id_n8n_repair"
        run(["docker", "container", "stop", runtime_id])
        assert_runtime_running(runtime_id, False)
        started_repair_raw = run([str(binary), "--output", "json", "n8n", "repair"])
        if canonical_key in started_repair_raw:
            raise Failure("repair_output_key_leak")
        started_repair_job = validate_repair_product(read_json_bytes(started_repair_raw), job, "started")
        if started_repair_job == healthy_repair_job:
            raise Failure("stopped_repair_job_reused")
        started_repair_record = observe_exact_job(home, started_repair_job, "repair")
        validate_status(read_json_from_command([str(binary), "--output", "json", "n8n", "status", "--job", started_repair_job]), started_repair_job, args.port)
        started_generation = validate_repair_custody(read_json(home / "n8n-managed-repair.v1.json"), started_repair_job, started_repair_record["manifest_sha256"], job, source_install["manifest_sha256"], "started", runtime_id, runtime_id, volume, args.port, runtime)
        if started_generation <= healthy_generation:
            raise Failure("repair_generation_not_advanced")
        validate_repair_generation(home, started_generation)
        validate_runtime(docker_inspect(runtime_id), job, volume, runtime_id, args.port)
        assert_runtime_running(runtime_id, True)
        if (authenticated_probe(job, args.port) != receipt["http_probe"]
                or observe_imported_workflows(args.port, canonical_key, templates) != first_workflows
                or observe_exact_job(home, job, "install") != source_install
                or observe_full_job_row(home, job, "install") != source_install_full
                or canonical_n8n_api_key() != canonical_key):
            raise Failure("stopped_repair_authority_or_data_mutation")
        receipt["repair_started"] = {"job_id": started_repair_job, "job_row_sha256": started_repair_record["row_sha256"], "manifest_sha256": started_repair_record["manifest_sha256"], "generation": started_generation, "runtime_id": runtime_id, "volume": volume, "exact_stopped_id_restarted": True, "authenticated": True, "workflows_persisted": True}
        receipt["stage"] = "missing_exact_id_n8n_repair"
        old_runtime_id = runtime_id
        run(["docker", "rm", "-f", old_runtime_id])
        if not exact_absent("container", old_runtime_id):
            raise Failure("recreate_source_runtime_absence_unproven")
        recreated_repair_raw = run([str(binary), "--output", "json", "n8n", "repair"])
        if canonical_key in recreated_repair_raw:
            raise Failure("repair_output_key_leak")
        recreated_repair_job = validate_repair_product(read_json_bytes(recreated_repair_raw), job, "recreated")
        if recreated_repair_job in {healthy_repair_job, started_repair_job}:
            raise Failure("recreated_repair_job_reused")
        recreated_repair_record = observe_exact_job(home, recreated_repair_job, "repair")
        validate_status(read_json_from_command([str(binary), "--output", "json", "n8n", "status", "--job", recreated_repair_job]), recreated_repair_job, args.port)
        repaired_runtime = read_json(home / "n8n-managed-runtime.v2.json")
        runtime_id = required(repaired_runtime, "container_id", str)
        recreated_generation = validate_repair_custody(read_json(home / "n8n-managed-repair.v1.json"), recreated_repair_job, recreated_repair_record["manifest_sha256"], job, source_install["manifest_sha256"], "recreated", old_runtime_id, runtime_id, volume, args.port, runtime)
        if recreated_generation <= started_generation:
            raise Failure("repair_generation_not_advanced")
        validate_repair_generation(home, recreated_generation)
        validate_runtime(docker_inspect(runtime_id), job, volume, runtime_id, args.port)
        assert_runtime_running(runtime_id, True)
        if (authenticated_probe(job, args.port) != receipt["http_probe"]
                or observe_imported_workflows(args.port, canonical_key, templates) != first_workflows
                or observe_exact_job(home, job, "install") != source_install
                or observe_full_job_row(home, job, "install") != source_install_full
                or canonical_n8n_api_key() != canonical_key):
            raise Failure("recreated_repair_authority_or_data_mutation")
        receipt["repair_recreated"] = {"job_id": recreated_repair_job, "job_row_sha256": recreated_repair_record["row_sha256"], "manifest_sha256": recreated_repair_record["manifest_sha256"], "generation": recreated_generation, "old_runtime_id": old_runtime_id, "runtime_id": runtime_id, "reused_volume": volume, "authenticated": True, "workflows_persisted": True, "source_api_key_authority_preserved": True}
        receipt["stage"] = "first_product_uninstall"
        first_uninstall_raw = run([str(binary), "--output", "json", "n8n", "uninstall"])
        if canonical_key in first_uninstall_raw:
            raise Failure("uninstall_output_key_leak")
        uninstall_job = validate_uninstall_product(read_json_bytes(first_uninstall_raw), job)
        uninstall_record = observe_exact_job(home, uninstall_job, "uninstall")
        uninstall_record_full = observe_full_job_row(home, uninstall_job, "uninstall")
        validate_uninstall_status(read_json_from_command([str(binary), "--output", "json", "n8n", "status", "--job", uninstall_job]), uninstall_job)
        if not exact_absent("container", runtime_id):
            raise Failure("uninstall_runtime_absence_unproven")
        uninstall_runtime_absent = True
        retained_volume = docker_inspect(volume)
        validate_retained_volume(retained_volume, job, volume)
        if canonical_n8n_api_key() != canonical_key:
            raise Failure("canonical_n8n_key_changed")
        sidecar_absent(home, "n8n-managed-runtime.v2.json")
        sidecar_absent(home, "n8n-managed-uninstall.v1.json")
        completion = read_uninstall_completion_receipt(home, uninstall_job, uninstall_record["manifest_sha256"], job, source_install["manifest_sha256"], runtime_id, volume, args.port)
        receipt["stage"] = "repeat_product_uninstall"
        repeat_uninstall_raw = run([str(binary), "--output", "json", "n8n", "uninstall"])
        if canonical_key in repeat_uninstall_raw:
            raise Failure("uninstall_output_key_leak")
        if repeat_uninstall_raw != first_uninstall_raw or validate_uninstall_product(read_json_bytes(repeat_uninstall_raw), job) != uninstall_job:
            raise Failure("uninstall_repeat_changed")
        repeat_uninstall_record = observe_exact_job(home, uninstall_job, "uninstall")
        validate_uninstall_status(read_json_from_command([str(binary), "--output", "json", "n8n", "status", "--job", uninstall_job]), uninstall_job)
        if repeat_uninstall_record != uninstall_record or observe_exact_job(home, job, "install") != source_install or observe_full_job_row(home, job, "install") != source_install_full or observe_full_job_row(home, uninstall_job, "uninstall") != uninstall_record_full:
            raise Failure("uninstall_repeat_job_mutation")
        if read_uninstall_completion_receipt(home, uninstall_job, uninstall_record["manifest_sha256"], job, source_install["manifest_sha256"], runtime_id, volume, args.port) != completion:
            raise Failure("uninstall_repeat_receipt_mutation")
        if not exact_absent("container", runtime_id):
            raise Failure("uninstall_repeat_runtime_absence_unproven")
        retained_volume_repeat = docker_inspect(volume)
        validate_retained_volume(retained_volume_repeat, job, volume)
        if canonical_n8n_api_key() != canonical_key:
            raise Failure("canonical_n8n_key_changed")
        if json_sha256(retained_volume_repeat) != json_sha256(retained_volume):
            raise Failure("uninstall_repeat_volume_mutation")
        sidecar_absent(home, "n8n-managed-runtime.v2.json")
        sidecar_absent(home, "n8n-managed-uninstall.v1.json")
        uninstall_runtime_absent = True
        receipt["uninstall"] = {"job_id": uninstall_job, "job_row_sha256": uninstall_record["row_sha256"], "full_job_row_sha256": uninstall_record_full, "job_manifest_sha256": uninstall_record["manifest_sha256"], "completion_receipt_sha256": completion["sha256"], "completion_receipt_bytes": completion["bytes"], "disposition": "container_removed_data_volume_retained", "config_cleanup": "preserved_unproven", "data_volume_policy": "retain", "runtime_absent": True, "volume_retained": True, "canonical_api_key_preserved": True, "repeat_read_only": True, "active_sidecars_removed": True}
        receipt["stage"] = "retained_volume_reinstall"
        reinstall_payload = canonical_key + b"\n"
        reinstall_raw = run_with_payload([str(binary), "--output", "json", "n8n", "install", "--reuse-uninstall", uninstall_job, "--api-key-stdin"], reinstall_payload)
        if canonical_key in reinstall_raw:
            raise Failure("reinstall_output_key_leak")
        reinstall_job = validate_reinstall_product(read_json_bytes(reinstall_raw), job, uninstall_job)
        reinstall_record = observe_exact_job(home, reinstall_job, "install")
        reinstall_record_full = observe_full_job_row(home, reinstall_job, "install")
        validate_status(read_json_from_command([str(binary), "--output", "json", "n8n", "status", "--job", reinstall_job]), reinstall_job, args.port)
        reinstall_runtime = read_json(home / "n8n-managed-runtime.v2.json")
        reinstall_runtime_id = validate_reinstalled_custody(reinstall_runtime, reinstall_job, reinstall_record["manifest_sha256"], volume, runtime_id, args.port)
        validate_runtime(docker_inspect(reinstall_runtime_id), reinstall_job, volume, reinstall_runtime_id, args.port)
        if read_json(home / "n8n-managed-bootstrap.v2.json") != boot:
            raise Failure("reinstall_bootstrap_custody_changed")
        if canonical_n8n_api_key() != canonical_key:
            raise Failure("reinstall_canonical_n8n_key_changed")
        reinstall_workflows = observe_imported_workflows(args.port, canonical_key, templates)
        if reinstall_workflows != first_workflows:
            raise Failure("reinstall_workflow_persistence_unproven")
        if observe_exact_job(home, job, "install") != source_install or observe_exact_job(home, uninstall_job, "uninstall") != uninstall_record or observe_full_job_row(home, job, "install") != source_install_full or observe_full_job_row(home, uninstall_job, "uninstall") != uninstall_record_full:
            raise Failure("reinstall_history_mutation")
        if read_uninstall_completion_receipt(home, uninstall_job, uninstall_record["manifest_sha256"], job, source_install["manifest_sha256"], runtime_id, volume, args.port) != completion:
            raise Failure("reinstall_original_receipt_mutation")
        receipt["stage"] = "repeat_retained_volume_reinstall"
        reinstall_repeat = assert_reinstall_repeat_rejected(binary, uninstall_job, reinstall_payload)
        if observe_exact_job(home, reinstall_job, "install") != reinstall_record or observe_full_job_row(home, reinstall_job, "install") != reinstall_record_full or read_json(home / "n8n-managed-runtime.v2.json") != reinstall_runtime:
            raise Failure("reinstall_repeat_mutation")
        validate_runtime(docker_inspect(reinstall_runtime_id), reinstall_job, volume, reinstall_runtime_id, args.port)
        if observe_exact_job(home, job, "install") != source_install or observe_exact_job(home, uninstall_job, "uninstall") != uninstall_record or observe_full_job_row(home, job, "install") != source_install_full or observe_full_job_row(home, uninstall_job, "uninstall") != uninstall_record_full:
            raise Failure("reinstall_repeat_history_mutation")
        receipt["stage"] = "reinstall_product_uninstall"
        reinstall_uninstall_raw = run([str(binary), "--output", "json", "n8n", "uninstall"])
        if canonical_key in reinstall_uninstall_raw:
            raise Failure("reinstall_uninstall_output_key_leak")
        reinstall_uninstall_job = validate_uninstall_product(read_json_bytes(reinstall_uninstall_raw), reinstall_job)
        reinstall_uninstall_record = observe_exact_job(home, reinstall_uninstall_job, "uninstall")
        reinstall_uninstall_record_full = observe_full_job_row(home, reinstall_uninstall_job, "uninstall")
        validate_uninstall_status(read_json_from_command([str(binary), "--output", "json", "n8n", "status", "--job", reinstall_uninstall_job]), reinstall_uninstall_job)
        if not exact_absent("container", reinstall_runtime_id):
            raise Failure("reinstall_uninstall_runtime_absence_unproven")
        validate_retained_volume(docker_inspect(volume), job, volume)
        if canonical_n8n_api_key() != canonical_key:
            raise Failure("reinstall_uninstall_canonical_n8n_key_changed")
        sidecar_absent(home, "n8n-managed-runtime.v2.json")
        sidecar_absent(home, "n8n-managed-uninstall.v1.json")
        reinstall_completion = read_reinstall_uninstall_completion_receipt(home, reinstall_uninstall_job, reinstall_uninstall_record["manifest_sha256"], reinstall_job, reinstall_record["manifest_sha256"], reinstall_runtime_id, volume, args.port, uninstall_job, uninstall_record["manifest_sha256"], job, source_install["manifest_sha256"])
        if read_json(home / "n8n-managed-bootstrap.v2.json") != boot or observe_exact_job(home, job, "install") != source_install or observe_exact_job(home, uninstall_job, "uninstall") != uninstall_record:
            raise Failure("reinstall_final_history_mutation")
        receipt["reinstall"] = {"job_id": reinstall_job, "job_row_sha256": reinstall_record["row_sha256"], "full_job_row_sha256": reinstall_record_full, "runtime_id": reinstall_runtime_id, "reused_volume": volume, "workflows_persisted": True, "canonical_api_key_preserved": True, "repeat": reinstall_repeat, "final_uninstall_job_id": reinstall_uninstall_job, "final_uninstall_row_sha256": reinstall_uninstall_record["row_sha256"], "final_uninstall_full_row_sha256": reinstall_uninstall_record_full, "final_completion_receipt_sha256": reinstall_completion["sha256"], "final_completion_receipt_bytes": reinstall_completion["bytes"], "final_runtime_absent": True, "volume_retained": True}
        receipt["stage"] = "confirmed_retained_volume_purge"
        plan_raw = run([str(binary), "--output", "json", "n8n", "purge", "--uninstall", reinstall_uninstall_job])
        phrase = validate_purge_plan(read_json_bytes(plan_raw), reinstall_uninstall_job, volume)
        validate_retained_volume(docker_inspect(volume), job, volume)
        source_before = observe_full_job_row(home, job, "install"); uninstall_before = observe_full_job_row(home, uninstall_job, "uninstall"); import_before = observe_full_job_row(home, import_job, "import"); final_before = observe_full_job_row(home, reinstall_uninstall_job, "uninstall"); all_jobs_before = observe_all_job_rows(home); original_receipts_before = (completion, reinstall_completion, first_custody); purge_receipts_before = purge_artifacts_absent(home)
        wrong = bounded.run([str(binary), "--output", "json", "n8n", "purge", "--uninstall", reinstall_uninstall_job, "--confirm", phrase + " wrong"], timeout=180)
        if wrong.code == 0 or wrong.timed_out or wrong.overflow or b"n8n_purge_confirmation_mismatch" not in wrong.stderr: raise Failure("purge_wrong_confirmation_unproven")
        validate_retained_volume(docker_inspect(volume), job, volume)
        if purge_artifacts_absent(home) != purge_receipts_before or observe_all_job_rows(home) != all_jobs_before or (read_uninstall_completion_receipt(home, uninstall_job, uninstall_record["manifest_sha256"], job, source_install["manifest_sha256"], runtime_id, volume, args.port), read_reinstall_uninstall_completion_receipt(home, reinstall_uninstall_job, reinstall_uninstall_record["manifest_sha256"], reinstall_job, reinstall_record["manifest_sha256"], reinstall_runtime_id, volume, args.port, uninstall_job, uninstall_record["manifest_sha256"], job, source_install["manifest_sha256"]), observe_workflow_custody(home, import_job, first_workflows["entries"])) != original_receipts_before: raise Failure("purge_wrong_confirmation_mutated_history")
        purge_raw = run([str(binary), "--output", "json", "n8n", "purge", "--uninstall", reinstall_uninstall_job, "--confirm", phrase])
        purge_job = validate_purge_product(read_json_bytes(purge_raw), reinstall_uninstall_job); purge_record = observe_exact_job(home, purge_job, "purge"); purge_full = observe_full_job_row(home, purge_job, "purge")
        if not exact_absent("volume", volume) or canonical_n8n_api_key() != canonical_key: raise Failure("purge_effect_unproven")
        purge_completion = read_purge_receipt(home, purge_job, purge_record["manifest_sha256"], reinstall_uninstall_job, volume)
        repeat_purge_raw = run([str(binary), "--output", "json", "n8n", "purge", "--uninstall", reinstall_uninstall_job, "--confirm", phrase])
        if repeat_purge_raw != purge_raw or validate_purge_product(read_json_bytes(repeat_purge_raw), reinstall_uninstall_job) != purge_job or observe_exact_job(home, purge_job, "purge") != purge_record or observe_full_job_row(home, purge_job, "purge") != purge_full or read_purge_receipt(home, purge_job, purge_record["manifest_sha256"], reinstall_uninstall_job, volume) != purge_completion: raise Failure("purge_repeat_mutation")
        if (observe_full_job_row(home, job, "install"), observe_full_job_row(home, uninstall_job, "uninstall"), observe_full_job_row(home, import_job, "import"), observe_full_job_row(home, reinstall_uninstall_job, "uninstall")) != (source_before, uninstall_before, import_before, final_before): raise Failure("purge_history_mutation")
        volume_purged = True; receipt["purge"] = {"source_uninstall_job_sha256": hashlib.sha256(reinstall_uninstall_job.encode()).hexdigest(), "purge_job_sha256": hashlib.sha256(purge_job.encode()).hexdigest(), "target_sha256": hashlib.sha256(phrase.encode()).hexdigest(), "job_row_sha256": purge_record["row_sha256"], "receipt_sha256": purge_completion["sha256"], "receipt_bytes": purge_completion["bytes"], "volume_absent": True, "canonical_api_key_preserved": True, "repeat_read_only": True}
        receipt.update({"manifest_sha256": boot["manifest_sha256"], "volume": volume, "bootstrap_id": bootstrap_id, "runtime_id": runtime_id, "status_ready": True, "reused_same_job": True, "no_rebootstrap_events": True})
        receipt["outcome"] = "passed"
    except Exception as error:
        receipt["failure_stage"] = str(error) if isinstance(error, Failure) else "unexpected"
        if isinstance(error, CommandFailure):
            receipt["command_failure"] = error.diagnostic
        try:
            receipt["install_job"] = observe_failed_install_job(home)
        except Failure:
            pass
        # Capture only closed-vocabulary local custody state, even when the
        # first product call failed before returning a job. No guessed cleanup.
        for name, allowed in (
            ("n8n-managed-bootstrap.v2.json", {"VolumeIntent", "VolumeBound", "BootstrapContainerBound", "OwnerSetupInFlight", "OwnerEstablished", "KeyMintInFlight", "KeyMintUnknown", "KeyCaptured", "BootstrapStopped", "BootstrapRemoved", "RuntimeContainerBound", "Ready"}),
            ("n8n-managed-runtime.v2.json", {"CreateIntent", "Bound", "Ready", "AbsentVerified"}),
        ):
            path = home / name
            if path.is_file() and not path.is_symlink():
                try:
                    phase = read_json(path).get("phase")
                    receipt[name] = {"exists": True, "phase": phase if isinstance(phase, str) and phase in allowed else "unclassified"}
                except Exception:
                    receipt[name] = {"exists": True, "phase": "unreadable"}
    finally:
        # A failed product command can leave partial custody. Preserve it and
        # report it unproven if the complete exact identities were not read.
        cleanup = False
        if runtime_id and volume and job:
            cleanup = cleanup_owned_runtime_and_volume(runtime_id, volume, job, args.port, uninstall_runtime_absent, volume_purged)
        receipt["docker_cleanup_proven"] = cleanup
        if not cleanup: receipt["outcome"] = "failed"
        if receipt["outcome"] == "passed" and cleanup:
            try:
                clear_bootstrap_secrets(job)
                receipt["bootstrap_secrets_cleared"] = True
            except Exception:
                receipt["outcome"] = "failed"
                receipt["failure_stage"] = "secret_cleanup_unproven"
        if receipt["outcome"] == "passed" and cleanup:
            try:
                shutil.rmtree(home)
                receipt["isolated_home_removed"] = not home.exists()
                if home.exists():
                    raise Failure("home_removal_unproven")
            except Exception:
                receipt["outcome"] = "failed"
                receipt["failure_stage"] = "home_cleanup_unproven"
        receipt["cleanup_proven"] = cleanup and receipt.get("bootstrap_secrets_cleared") is True and receipt.get("isolated_home_removed") is True
        receipt_path.parent.mkdir(parents=True, exist_ok=True); receipt_path.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    return 0 if receipt["outcome"] == "passed" else 1

def read_json_from_command(argv: list[str]) -> dict:
    return read_json_bytes(run(argv))

def read_json_bytes(raw: bytes) -> dict:
    try: value = json.loads(raw)
    except Exception as error: raise Failure("product_json_invalid") from error
    if not isinstance(value, dict): raise Failure("product_json_shape_invalid")
    return value

if __name__ == "__main__": sys.exit(main())
