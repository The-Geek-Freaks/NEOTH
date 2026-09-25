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
INSTALL_FAILURE_CODES = (
    "n8n_bootstrap_runtime_finalize_unproven", "n8n_loopback_health_timeout",
    "n8n_adoption_cancelled", "n8n_postcommit_probe_failed", "n8n_probe_timeout",
    "n8n_probe_transport", "n8n_unauthorized", "n8n_redirect_rejected",
    "n8n_response_too_large", "n8n_invalid_response", "adoption_prepare_failed",
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
            command = {"install": "product_install", "status": "product_status"}.get(argv[4], "other") if len(argv) > 4 else "other"
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
            "n8n_bootstrap_volume_mismatch", "n8n_bootstrap_http_unknown",
            "n8n_bootstrap_http_rejected", "n8n_managed_instance_already_owned",
            "n8n_runtime_binding_write_failed", "n8n_managed_prepared_job_not_active",
            "n8n_container_inspect_unknown", "n8n_managed_container_create_failed",
            "n8n_managed_container_identity_ambiguous",
            "n8n_preexisting_container_unowned_or_mismatch",
            "n8n_managed_custody_mismatch", "n8n_docker_wait_failed",
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

def run(argv: list[str], timeout: int = 180) -> bytes:
    result = bounded.run(argv, timeout=timeout)
    if result.code != 0 or result.timed_out or result.overflow:
        raise CommandFailure(argv, result)
    return result.stdout

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
    receipt = {"schema": 1, "source_sha": os.environ.get("GITHUB_SHA"), "port": args.port, "outcome": "failed"}; runtime_id = volume = job = None
    try:
        receipt.update({"helper_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "bounded_helper_sha256": hashlib.sha256(Path(bounded.__file__).read_bytes()).hexdigest(), "workflow_sha256": hashlib.sha256((Path.cwd() / ".github/workflows/n8n-product-bootstrap.yml").read_bytes()).hexdigest(), "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(), "cargo_lock_sha256": hashlib.sha256((Path.cwd() / "SRC/Cargo.lock").read_bytes()).hexdigest()})
        input_names = (
            "packaging/tests/test_n8n_product_bootstrap_canary.py",
            "SRC/neothd/src/cli/n8n.rs", "SRC/neothd/src/integrations/n8n.rs",
            "SRC/neothd/src/integrations/n8n/managed_bootstrap.rs",
            "SRC/neothd/src/integrations/n8n/managed_runtime.rs",
            "SRC/neothd/src/integrations/n8n/bootstrap_transport.rs",
            "SRC/neothd/src/integrations/n8n/workflow_import.rs",
            "SRC/neothd/src/integrations/jobs.rs", "SRC/neothd/src/integrations/state.rs",
            "SRC/neothd/src/installers/n8n_workflows.rs",
            "SRC/neothd/src/installers/n8n_starter_workflows.rs",
            "SRC/neothd/src/config/keychain.rs",
        )
        assets = sorted((Path.cwd() / "SRC/neothd/assets/n8n_workflows").glob("*.json"))
        if len(assets) != 3:
            raise Failure("workflow_asset_set_invalid")
        receipt["input_sha256"] = {
            name: hashlib.sha256((Path.cwd() / name).read_bytes()).hexdigest()
            for name in input_names + tuple(str(asset.relative_to(Path.cwd())).replace("\\", "/") for asset in assets)
        }
        receipt["stage"] = "first_product_install"
        first = read_json_from_command([str(binary), "--output", "json", "n8n", "install", "--bootstrap-owner", "--port", str(args.port)])
        job = validate_product(first); receipt["job_id"] = job; receipt["first_state"] = first["state"]
        status = read_json_from_command([str(binary), "--output", "json", "n8n", "status", "--job", job]); validate_status(status, job, args.port)
        boot = read_json(home / "n8n-managed-bootstrap.v2.json"); runtime = read_json(home / "n8n-managed-runtime.v2.json")
        volume, bootstrap_id, runtime_id = validate_custody(boot, runtime, job, args.port); validate_runtime(docker_inspect(runtime_id), job, volume, runtime_id, args.port)
        validate_single_job(home, job, boot["manifest_sha256"])
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
            try:
                validate_runtime(docker_inspect(runtime_id), job, volume, runtime_id, args.port); run(["docker", "rm", "-f", runtime_id]); cleanup = exact_absent("container", runtime_id)
            except Exception: cleanup = False
            try:
                row = docker_inspect(volume)
                if row.get("Labels", {}).get("io.neoth.managed") != "n8n" or row.get("Labels", {}).get("io.neoth.n8n-job") != job or row.get("Labels", {}).get("io.neoth.n8n-bootstrap") != "v2": raise Failure("volume_identity_invalid")
                run(["docker", "volume", "rm", volume]); cleanup = exact_absent("volume", volume) and cleanup
            except Exception: cleanup = False
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
