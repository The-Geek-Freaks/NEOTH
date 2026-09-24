#!/usr/bin/env python3
"""Hosted-only proof for the compiled NEOTH owner-bootstrap command."""
from __future__ import annotations

import argparse, hashlib, json, os, re, shutil, sys, time
from pathlib import Path

import n8n_bootstrap_canary as bounded

IMAGE = "docker.io/n8nio/n8n@sha256:9f693fd5565539efd5e75ad168526c8041a6af516d9e50bc4d9cb1c9c5031523"
ID = re.compile(r"[0-9a-f]{64}")
VOLUME = re.compile(r"neoth_n8n_[0-9a-f]{32}")
JOB = re.compile(r"[0-9a-f-]{36}")

class Failure(RuntimeError): pass

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
        raise Failure("command_failed")
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
        receipt["input_sha256"] = {
            name: hashlib.sha256((Path.cwd() / name).read_bytes()).hexdigest()
            for name in (
                "packaging/tests/test_n8n_product_bootstrap_canary.py",
                "SRC/neothd/src/cli/n8n.rs",
                "SRC/neothd/src/integrations/n8n.rs",
                "SRC/neothd/src/integrations/n8n/managed_bootstrap.rs",
                "SRC/neothd/src/integrations/n8n/managed_runtime.rs",
                "SRC/neothd/src/integrations/n8n/bootstrap_transport.rs",
                "SRC/neothd/src/config/keychain.rs",
            )
        }
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
        receipt.update({"manifest_sha256": boot["manifest_sha256"], "volume": volume, "bootstrap_id": bootstrap_id, "runtime_id": runtime_id, "status_ready": True, "reused_same_job": True, "no_rebootstrap_events": True})
        receipt["outcome"] = "passed"
    except Exception as error:
        receipt["failure_stage"] = str(error) if isinstance(error, Failure) else "unexpected"
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
