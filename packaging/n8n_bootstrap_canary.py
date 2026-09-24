#!/usr/bin/env python3
"""Disposable, pinned-image n8n bootstrap feasibility canary.

This is a hosted smoke test, not the NEOTH product bootstrap.  It deliberately
keeps every secret in process memory or Docker-exec stdin and writes a compact,
redacted receipt only.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
from urllib.parse import quote
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

IMAGE = "docker.io/n8nio/n8n@sha256:9f693fd5565539efd5e75ad168526c8041a6af516d9e50bc4d9cb1c9c5031523"
IMAGE_DIGEST = "sha256:9f693fd5565539efd5e75ad168526c8041a6af516d9e50bc4d9cb1c9c5031523"
UPSTREAM_COMMIT = "a331d3858797b161e4acba288396be3835425d8e"
MAX_OUTPUT = 16 * 1024
COMMAND_TIMEOUT = 45
STARTUP_TIMEOUT = 75
WORKFLOW_ASSETS = ("morning_brief.json", "daily_summary.json", "weekly_stats.json")
WORKFLOW_FIELDS = frozenset(("name", "description", "active", "nodes", "connections", "settings", "tags"))

# This program is constant. Its operation and all secret values are read from
# stdin JSON, never from argv or an environment variable.
BOOTSTRAP_NODE = r"""
const read = async () => { let b=''; for await (const c of process.stdin) b += c; return JSON.parse(b); };
const fail = (stage, status = 0, unknown = false) => { process.stdout.write(JSON.stringify({ok:false,stage,status,unknown})+'\n'); process.exit(2); };
const main = async () => {
  const p = await read(); const base = 'http://127.0.0.1:5678';
  const headers = {'content-type':'application/json', 'browser-id':p.browserId};
  const until = Date.now() + 60000; let r; let settings;
  do { r = await fetch(base + '/rest/settings', {headers:{'browser-id':p.browserId}}).catch(() => null); settings = r && await r.json().catch(() => null); if (r?.ok && settings?.data?.userManagement) break; await new Promise(resolve => setTimeout(resolve, 500)); } while (Date.now() < until);
  if (!r || !r.ok || !settings?.data?.userManagement || settings.data.userManagement.showSetupOnFirstLoad !== true) fail('settings', r?.status ?? 0);
  try { r = await fetch(base + '/rest/owner/setup', {method:'POST', headers, body:JSON.stringify({email:p.email,firstName:'NEOTH',lastName:'Canary',password:p.password})}); } catch (_) { fail('owner_setup', 0, true); }
  const setup = await r.json().catch(() => null); const setupCookie = r.headers.get('set-cookie');
  if (!r.ok) fail('owner_setup', r.status); if (!setup?.data || !setupCookie) fail('owner_setup', r.status, true);
  try { r = await fetch(base + '/rest/login', {method:'POST', headers, body:JSON.stringify({emailOrLdapLoginId:p.email,password:p.password})}); } catch (_) { fail('owner_login', 0, true); }
  const login = await r.json().catch(() => null); const cookie = r.headers.get('set-cookie');
  if (!r.ok) fail('owner_login', r.status); if (!login?.data || !cookie) fail('owner_login', r.status, true);
  const scopes=['workflow:list','workflow:create','workflow:read']; if(p.executeTemplates===true) scopes.push('credential:create');
  try { r = await fetch(base + '/rest/api-keys', {method:'POST', headers:{...headers, cookie}, body:JSON.stringify({label:p.label,scopes,expiresAt:null})}); } catch (_) { fail('key_mint', 0, true); }
  const key = await r.json().catch(() => null);
  if (!r.ok) fail('key_mint', r.status); if (typeof key?.data?.rawApiKey !== 'string' || key.data.rawApiKey.length < 8) fail('key_mint', r.status, true);
  process.stdout.write(JSON.stringify({ok:true,rawApiKey:key.data.rawApiKey,keyId:typeof key.data.id==='string'?key.data.id:null,mintStatus:r.status})+'\n');
}; main().catch(() => fail('transport'));
""".strip()

CONFIG_KEY_NODE = r"""
const fs = require('fs'); const crypto = require('crypto');
try { const c = JSON.parse(fs.readFileSync('/home/node/.n8n/config', 'utf8')); if (typeof c.encryptionKey !== 'string' || c.encryptionKey.length < 8) process.exit(2); process.stdout.write(JSON.stringify({ok:true,encryptionKeySha256:crypto.createHash('sha256').update(c.encryptionKey).digest('hex')})+'\n'); } catch (_) { process.exit(2); }
""".strip()

IN_CONTAINER_NEGATIVE_PROBE_NODE = r"""
fetch('http://127.0.0.1:5678/api/v1/workflows?limit=1').then(r => process.stdout.write(JSON.stringify({status:r.status})+'\n')).catch(() => process.stdout.write(JSON.stringify({error:'transport'})+'\n'));
""".strip()


class CanaryFailure(RuntimeError):
    pass


class UnknownEffect(CanaryFailure):
    pass


class ProbeFailure(CanaryFailure):
    def __init__(self, stage: str, diagnosis: dict[str, object]):
        super().__init__(stage)
        self.diagnosis = diagnosis


@dataclass
class Result:
    code: int
    stdout: bytes
    stderr: bytes
    timed_out: bool
    overflow: bool


def drain(stream, target: bytearray, overflow: list[bool]) -> None:
    while chunk := stream.read(4096):
        remaining = MAX_OUTPUT + 1 - len(target)
        if remaining > 0:
            target.extend(chunk[:remaining])
        if len(chunk) > remaining:
            overflow[0] = True


def run(argv: Sequence[str], payload: bytes | None = None, timeout: int = COMMAND_TIMEOUT) -> Result:
    child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err, overflow = bytearray(), bytearray(), [False]
    out_thread = threading.Thread(target=drain, args=(child.stdout, out, overflow), daemon=True)
    err_thread = threading.Thread(target=drain, args=(child.stderr, err, overflow), daemon=True)
    out_thread.start(); err_thread.start()
    try:
        if payload is not None:
            assert child.stdin is not None
            child.stdin.write(payload); child.stdin.flush()
        assert child.stdin is not None
        child.stdin.close()
        child.wait(timeout=timeout)
        timed_out = False
    except subprocess.TimeoutExpired:
        child.kill(); child.wait(); timed_out = True
    out_thread.join(3); err_thread.join(3)
    return Result(child.returncode, bytes(out), bytes(err), timed_out, overflow[0])


def checked(argv: Sequence[str], payload: bytes | None = None, timeout: int = COMMAND_TIMEOUT) -> bytes:
    result = run(argv, payload, timeout)
    if result.timed_out or result.overflow or result.code != 0:
        raise CanaryFailure("bounded_docker_command_failed")
    return result.stdout


def docker(*args: str, payload: bytes | None = None, timeout: int = COMMAND_TIMEOUT) -> bytes:
    return checked(("docker", *args), payload, timeout)


def inspect(target: str) -> dict:
    raw = docker("inspect", target)
    try:
        value = json.loads(raw)
        if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
            raise ValueError
        return value[0]
    except (ValueError, json.JSONDecodeError) as error:
        raise CanaryFailure("inspect_shape_invalid") from error


def expect_labels(row: dict, job: str, kind: str) -> None:
    labels = row.get("Config", {}).get("Labels", {})
    if labels.get("io.neoth.managed") != "n8n" or labels.get("io.neoth.n8n-job") != job or labels.get("io.neoth.canary-kind") != kind:
        raise CanaryFailure("owned_label_mismatch")


def expect_mount(row: dict, volume: str) -> None:
    mounts = row.get("Mounts", [])
    if len(mounts) != 1 or mounts[0].get("Type") != "volume" or mounts[0].get("Name") != volume or mounts[0].get("Destination") != "/home/node/.n8n":
        raise CanaryFailure("owned_mount_mismatch")


def owned_container(row: dict, job: str, kind: str, volume: str) -> str:
    identifier = row.get("Id")
    if not isinstance(identifier, str) or len(identifier) != 64:
        raise CanaryFailure("container_id_invalid")
    expect_labels(row, job, kind); expect_mount(row, volume)
    image = row.get("Config", {}).get("Image")
    if image != IMAGE:
        raise CanaryFailure("image_reference_mismatch")
    environment = row.get("Config", {}).get("Env", [])
    if not isinstance(environment, list) or any(
        not isinstance(value, str) or value == "N8N_ENCRYPTION_KEY" or value.startswith("N8N_ENCRYPTION_KEY=")
        for value in environment
    ):
        raise CanaryFailure("injected_encryption_key_environment")
    return identifier


def daemon_healthy() -> bool:
    result = run(("docker", "info"))
    return result.code == 0 and not result.timed_out and not result.overflow


def prove_absent(kind: str, identifier: str) -> None:
    if not daemon_healthy():
        raise CanaryFailure("docker_daemon_health_unproven")
    result = run(("docker", kind, "inspect", identifier))
    if kind == "container":
        expected = {f"no such container: {identifier}"}
    elif kind == "volume":
        expected = {f"get {identifier}: no such volume", f"no such volume: {identifier}"}
    elif kind == "network":
        expected = {f"network {identifier} not found", f"no such network: {identifier}"}
    else:
        raise CanaryFailure("absence_kind_invalid")
    valid_lines = expected | {f"error response from daemon: {line}" for line in expected}
    diagnostic_lines = {
        line.strip().lower()
        for line in (result.stdout + result.stderr).decode("utf-8", "replace").splitlines()
        if line.strip()
    }
    if result.timed_out or result.overflow or result.code == 0 or not diagnostic_lines.intersection(valid_lines):
        raise CanaryFailure(f"{kind}_absence_unproven")


def sanitize_json(raw: bytes) -> dict:
    if len(raw) > MAX_OUTPUT:
        raise CanaryFailure("node_response_too_large")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as error:
        raise CanaryFailure("node_response_invalid") from error


def bootstrap_node_response(identifier: str, payload: bytes) -> dict:
    try:
        result = run(("docker", "exec", "-i", "-u", "node", identifier, "node", "-e", BOOTSTRAP_NODE), payload, STARTUP_TIMEOUT)
    except (BrokenPipeError, OSError) as error:
        raise UnknownEffect("owner_setup_or_key_mint") from error
    if result.timed_out or result.overflow or result.code not in (0, 2):
        raise UnknownEffect("owner_setup_or_key_mint")
    try:
        value = sanitize_json(result.stdout)
    except CanaryFailure as error:
        raise UnknownEffect("owner_setup_or_key_mint") from error
    if not isinstance(value, dict) or type(value.get("ok")) is not bool:
        raise UnknownEffect("owner_setup_or_key_mint")
    if value["ok"] is True:
        if not isinstance(value.get("rawApiKey"), str) or len(value["rawApiKey"]) < 8 or type(value.get("mintStatus")) is not int or not 200 <= value["mintStatus"] < 300:
            raise UnknownEffect("owner_setup_or_key_mint")
    elif not isinstance(value.get("stage"), str) or type(value.get("status")) is not int or type(value.get("unknown")) is not bool:
        raise UnknownEffect("owner_setup_or_key_mint")
    return value


def http_response(connection: http.client.HTTPConnection) -> tuple[int, bytes]:
    response = connection.getresponse()
    body = response.read(MAX_OUTPUT + 1)
    if len(body) > MAX_OUTPUT:
        raise CanaryFailure("host_probe_response_too_large")
    return response.status, body


def final_host_probe(port: int, raw_key: str) -> dict:
    deadline = time.monotonic() + 60
    ready = False
    readiness_status: int | None = None
    readiness_error: str | None = None
    while time.monotonic() < deadline:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            connection.request("GET", "/healthz/readiness", headers={"Connection": "close"})
            readiness_status, readiness_body = http_response(connection)
            try:
                readiness = json.loads(readiness_body)
            except json.JSONDecodeError:
                readiness = None
            if readiness_status == 200 and isinstance(readiness, dict) and readiness.get("status") == "ok":
                ready = True
                break
            readiness_error = "not_ready" if readiness_status == 503 else "unexpected_response"
        except OSError:
            readiness_error = "transport"
        except http.client.HTTPException:
            readiness_error = "http"
        finally:
            connection.close()
        time.sleep(0.5)
    if not ready:
        raise ProbeFailure("final_readiness_probe_failed", {"readiness_status": readiness_status, "readiness_error": readiness_error or "readiness_deadline"})
    path = "/api/v1/workflows?limit=1"
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request("GET", path, headers={"Connection": "close"})
        negative_status, _ = http_response(connection)
    except OSError as error:
        raise ProbeFailure("final_unauthenticated_probe_failed", {"negative_status": None, "negative_error": "transport"}) from error
    except http.client.HTTPException as error:
        raise ProbeFailure("final_unauthenticated_probe_failed", {"negative_status": None, "negative_error": "http"}) from error
    finally:
        connection.close()
    if negative_status not in (401, 403):
        raise ProbeFailure("final_unauthenticated_probe_failed", {"negative_status": negative_status, "negative_error": None})
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request("GET", path, headers={"Connection": "close", "X-N8N-API-KEY": raw_key})
        positive_status, raw_body = http_response(connection)
    except OSError as error:
        raise ProbeFailure("final_authenticated_probe_failed", {"positive_status": None, "positive_error": "transport"}) from error
    except http.client.HTTPException as error:
        raise ProbeFailure("final_authenticated_probe_failed", {"positive_status": None, "positive_error": "http"}) from error
    finally:
        connection.close()
    try:
        body = json.loads(raw_body)
    except json.JSONDecodeError as error:
        raise ProbeFailure("final_authenticated_probe_invalid_json", {"positive_status": positive_status, "positive_error": "invalid_json"}) from error
    if positive_status != 200 or not isinstance(body, dict) or not isinstance(body.get("data"), list):
        raise ProbeFailure("final_authenticated_probe_failed", {"positive_status": positive_status, "positive_error": "protocol"})
    return {"negativeStatus": negative_status, "positiveStatus": positive_status}


def runtime_observation(identifier: str) -> dict[str, object]:
    try:
        row = inspect(identifier)
        state = row.get("State", {})
        ports = row.get("NetworkSettings", {}).get("Ports", {}).get("5678/tcp")
        observed = ports[0] if isinstance(ports, list) and len(ports) == 1 and isinstance(ports[0], dict) else {}
        return {"running": state.get("Running") if isinstance(state.get("Running"), bool) else None, "exit_code": state.get("ExitCode") if type(state.get("ExitCode")) is int else None, "oom_killed": state.get("OOMKilled") if isinstance(state.get("OOMKilled"), bool) else None, "host_ip": observed.get("HostIp") if isinstance(observed.get("HostIp"), str) else None, "host_port": observed.get("HostPort") if isinstance(observed.get("HostPort"), str) else None}
    except CanaryFailure:
        return {"observation_error": "inspect_unavailable"}


def workflow_payload_from_value(value: object) -> dict:
    if not isinstance(value, dict) or set(value).difference(WORKFLOW_FIELDS):
        raise CanaryFailure("workflow_payload_invalid")
    payload = {key: value[key] for key in WORKFLOW_FIELDS if key in value}
    if payload.get("active") is not False or not isinstance(payload.get("name"), str) or not isinstance(payload.get("nodes"), list) or not payload["nodes"] or not isinstance(payload.get("connections"), dict) or not isinstance(payload.get("settings"), dict):
        raise CanaryFailure("workflow_payload_invalid")
    # The pinned public create DTO accepts description only on update.
    return {key: value for key, value in payload.items() if key not in {"active", "tags", "description"}}


def workflow_payload(path: Path) -> dict:
    return workflow_payload_from_value(json.loads(path.read_bytes()))


def workflow_request(port: int, raw_key: str, method: str, path: str, payload: dict | None = None) -> tuple[int, dict | None]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        body = json.dumps(payload, separators=(",", ":")).encode() if payload is not None else None
        headers = {"Connection": "close", "X-N8N-API-KEY": raw_key}
        if body is not None:
            headers["Content-Type"] = "application/json"
        connection.request(method, path, body=body, headers=headers)
        status, raw = http_response(connection)
        try:
            return status, json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return status, None
    finally:
        connection.close()


def preserves_submitted_fields(expected: object, observed: object) -> bool:
    """Permit server-added defaults, but require every submitted graph field."""
    if isinstance(expected, dict):
        return isinstance(observed, dict) and all(
            key in observed and preserves_submitted_fields(value, observed[key])
            for key, value in expected.items()
        )
    if isinstance(expected, list):
        return isinstance(observed, list) and len(expected) == len(observed) and all(
            preserves_submitted_fields(left, right) for left, right in zip(expected, observed)
        )
    return type(expected) is type(observed) and expected == observed


def workflow_matches_payload(payload: dict, observed: dict) -> bool:
    for field in ("nodes", "connections"):
        if json.dumps(payload[field], sort_keys=True) != json.dumps(observed.get(field), sort_keys=True):
            return False
    return preserves_submitted_fields(payload, observed)


def import_workflows(repository: Path, port: int, raw_key: str, receipt: dict) -> None:
    assets = repository / "SRC" / "neothd" / "assets" / "n8n_workflows"
    receipt["workflow_asset_sha256"] = {name: sha256_file(assets / name) for name in WORKFLOW_ASSETS}
    status, listed = workflow_request(port, raw_key, "GET", "/api/v1/workflows?limit=1")
    if status != 200 or not isinstance(listed, dict) or not isinstance(listed.get("data"), list):
        raise CanaryFailure("workflow_list_failed")
    receipt["workflow_import_stages"] = ["workflow_list_passed"]
    for name in WORKFLOW_ASSETS:
        payload = workflow_payload(assets / name)
        try:
            status, created = workflow_request(port, raw_key, "POST", "/api/v1/workflows", payload)
        except (OSError, http.client.HTTPException, CanaryFailure) as error:
            receipt["workflow_create_observation"] = "transport_or_bounded_response_failure"
            receipt["unknown_effect_stage"] = f"workflow_create_{name}"
            raise UnknownEffect("workflow_create_unknown") from error
        receipt["workflow_create_status"] = status
        created_value = created.get("data", created) if isinstance(created, dict) else None
        if status not in (200, 201) or not isinstance(created_value, dict) or not isinstance(created_value.get("id"), str) or not created_value["id"]:
            receipt["workflow_create_observation"] = (
                "non_success_status" if status not in (200, 201) else "missing_exact_id"
            )
            receipt["unknown_effect_stage"] = f"workflow_create_{name}"
            raise UnknownEffect("workflow_create_unknown")
        workflow_id = created_value["id"]
        status, read = workflow_request(port, raw_key, "GET", f"/api/v1/workflows/{quote(workflow_id, safe='')}")
        read_value = read.get("data", read) if isinstance(read, dict) else None
        if status != 200 or not isinstance(read_value, dict) or read_value.get("id") != workflow_id or read_value.get("active") is not False or not workflow_matches_payload(payload, read_value):
            raise CanaryFailure("workflow_read_verification_failed")
        receipt["workflow_import_stages"].append(f"workflow_{name}_created_inactive_verified")


def in_container_negative_probe(identifier: str) -> dict[str, object]:
    try:
        result = run(("docker", "exec", "-u", "node", identifier, "node", "-e", IN_CONTAINER_NEGATIVE_PROBE_NODE), timeout=COMMAND_TIMEOUT)
    except OSError:
        return {"error": "exec_transport"}
    if result.timed_out:
        return {"error": "timeout"}
    if result.overflow:
        return {"error": "overflow"}
    if result.code != 0:
        return {"error": "exec_exit"}
    try:
        value = sanitize_json(result.stdout)
    except CanaryFailure:
        return {"error": "invalid_response"}
    if isinstance(value, dict) and type(value.get("status")) is int:
        return {"status": value["status"]}
    if isinstance(value, dict) and value.get("error") == "transport":
        return {"error": "transport"}
    return {"error": "invalid_response"}


def write_receipt(path: Path, receipt: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def bootstrap_ports_are_unpublished(row: dict) -> bool:
    host = row.get("HostConfig", {}).get("PortBindings")
    network = row.get("NetworkSettings", {}).get("Ports")
    return host in ({}, None) and network in ({}, None, {"5678/tcp": None})


def assigned_loopback_port(row: dict) -> int:
    host_config = row.get("HostConfig", {})
    network_settings = row.get("NetworkSettings", {})
    if not isinstance(host_config, dict) or not isinstance(network_settings, dict):
        raise CanaryFailure("final_loopback_mapping_mismatch")
    host_bindings = host_config.get("PortBindings", {})
    network_ports = network_settings.get("Ports", {})
    if not isinstance(host_bindings, dict) or not isinstance(network_ports, dict):
        raise CanaryFailure("final_loopback_mapping_mismatch")
    if set(host_bindings) != {"5678/tcp"} or set(network_ports) != {"5678/tcp"}:
        raise CanaryFailure("final_loopback_mapping_mismatch")
    host = host_bindings.get("5678/tcp")
    network = network_ports.get("5678/tcp")
    if not isinstance(host, list) or len(host) != 1 or not isinstance(network, list) or len(network) != 1:
        raise CanaryFailure("final_loopback_mapping_mismatch")
    configured, observed = host[0], network[0]
    if configured.get("HostIp") != "127.0.0.1" or observed.get("HostIp") != "127.0.0.1":
        raise CanaryFailure("final_loopback_mapping_mismatch")
    try:
        port = int(observed.get("HostPort", ""))
    except (TypeError, ValueError) as error:
        raise CanaryFailure("final_loopback_mapping_mismatch") from error
    if not 1 <= port <= 65535:
        raise CanaryFailure("final_loopback_mapping_mismatch")
    configured_port = str(configured.get("HostPort", ""))
    if configured_port not in ("", str(port)):
        raise CanaryFailure("final_loopback_mapping_mismatch")
    return port


def main() -> int:
    github_sha = os.environ.get("GITHUB_SHA", "")
    github_run_id = os.environ.get("GITHUB_RUN_ID", "")
    github_run_attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
    execute_templates = os.environ.get("NEOTH_EXECUTE_TEMPLATES", "false")
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("GITHUB_REF") != "refs/heads/main"
        or re.fullmatch(r"[0-9a-fA-F]{40}", github_sha) is None
        or re.fullmatch(r"[1-9][0-9]*", github_run_id) is None
        or re.fullmatch(r"[1-9][0-9]*", github_run_attempt) is None
        or execute_templates not in ("true", "false")
    ):
        return 1
    repository = Path(__file__).resolve().parents[1]
    workflow = repository / ".github" / "workflows" / "n8n-bootstrap-canary.yml"
    receipt: dict[str, object] = {
        "schema": 3,
        "github_sha": github_sha,
        "image_digest": IMAGE_DIGEST,
        "upstream_commit": UPSTREAM_COMMIT,
        "script_sha256": sha256_file(Path(__file__).resolve()),
        "workflow_sha256": sha256_file(workflow),
        "stages": [],
        "execute_templates": execute_templates == "true",
        "outcome": "failed",
    }
    runner_temp = os.environ.get("RUNNER_TEMP")
    if not runner_temp:
        return 1
    root = Path(runner_temp) / "n8n-bootstrap-canary"
    receipt_path = root / "receipt.json"
    job = f"gh-{github_run_id}-{github_run_attempt}"
    suffix = secrets.token_hex(8)
    volume = f"neoth_n8n_canary_{suffix}"
    bootstrap_name = f"neoth-n8n-bootstrap-{suffix}"
    runtime_name = f"neoth-n8n-runtime-{suffix}"
    bootstrap_id = runtime_id = None
    raw_key: str | None = None
    exit_code = 1
    cleanup_failed = False
    try:
        docker("pull", IMAGE, timeout=STARTUP_TIMEOUT); receipt["stages"].append("image_pulled")
        image_row = inspect(IMAGE); repo_digests = image_row.get("RepoDigests", [])
        accepted_repo_digests = {IMAGE, f"n8nio/n8n@{IMAGE_DIGEST}"}
        if not isinstance(repo_digests, list) or not any(value in accepted_repo_digests for value in repo_digests):
            raise CanaryFailure("image_digest_provenance_mismatch")
        image_id = image_row.get("Id")
        if not isinstance(image_id, str) or not image_id.startswith("sha256:"):
            raise CanaryFailure("image_id_provenance_missing")
        receipt["image_id"] = image_id
        docker("volume", "create", "--label", "io.neoth.managed=n8n", "--label", f"io.neoth.n8n-job={job}", "--label", "io.neoth.canary-kind=volume", volume)
        volume_row = inspect(volume); labels = volume_row.get("Labels", {})
        if labels.get("io.neoth.managed") != "n8n" or labels.get("io.neoth.n8n-job") != job or labels.get("io.neoth.canary-kind") != "volume":
            raise CanaryFailure("volume_label_mismatch")
        receipt["stages"].append("volume_bound")
        docker("run", "-d", "--name", bootstrap_name, "--network", "none", "--label", "io.neoth.managed=n8n", "--label", f"io.neoth.n8n-job={job}", "--label", "io.neoth.canary-kind=bootstrap", "-e", "N8N_LISTEN_ADDRESS=127.0.0.1", "-v", f"{volume}:/home/node/.n8n", IMAGE)
        bootstrap = inspect(bootstrap_name); bootstrap_id = owned_container(bootstrap, job, "bootstrap", volume)
        if bootstrap.get("HostConfig", {}).get("NetworkMode") != "none" or not bootstrap_ports_are_unpublished(bootstrap):
            raise CanaryFailure("bootstrap_isolation_mismatch")
        receipt["stages"].append("isolated_bootstrap_bound")
        receipt["node_version"] = docker("exec", "-u", "node", bootstrap_id, "node", "--version").decode("utf-8", "replace").strip()[:64]
        browser_id = secrets.token_urlsafe(24); password = "N9" + secrets.token_urlsafe(30); email = f"canary-{suffix}@invalid.test"; label = f"neoth-bootstrap-{suffix}-{secrets.token_hex(8)}"
        payload = json.dumps({"browserId": browser_id, "password": password, "email": email, "label": label, "executeTemplates": execute_templates == "true"}, separators=(",", ":")).encode()
        node = bootstrap_node_response(bootstrap_id, payload)
        if node.get("ok") is not True or not isinstance(node.get("rawApiKey"), str):
            stage = node.get("stage") if isinstance(node.get("stage"), str) else "bootstrap_protocol"
            if node.get("unknown") is True:
                receipt["unknown_effect_stage"] = stage
            else:
                receipt["failure_stage"] = stage
            raise CanaryFailure("bootstrap_owner_or_mint_failed")
        raw_key = node.pop("rawApiKey")
        receipt["mint_status"] = node.get("mintStatus"); receipt["raw_key_sha256"] = hashlib.sha256(raw_key.encode()).hexdigest(); receipt["stages"].append("owner_and_key_captured")
        key_before = sanitize_json(docker("exec", "-u", "node", bootstrap_id, "node", "-e", CONFIG_KEY_NODE))
        if key_before.get("ok") is not True or not isinstance(key_before.get("encryptionKeySha256"), str):
            raise CanaryFailure("bootstrap_encryption_key_unproven")
        receipt["encryption_key_sha256"] = key_before["encryptionKeySha256"]
        docker("stop", "--time", "15", bootstrap_id, timeout=STARTUP_TIMEOUT)
        stopped = inspect(bootstrap_id)
        if stopped.get("State", {}).get("Running") is not False:
            raise CanaryFailure("bootstrap_not_stopped")
        docker("rm", bootstrap_id)
        prove_absent("container", bootstrap_id)
        receipt["stages"].append("bootstrap_stopped_and_absent")
        docker("run", "-d", "--name", runtime_name, "--label", "io.neoth.managed=n8n", "--label", f"io.neoth.n8n-job={job}", "--label", "io.neoth.canary-kind=runtime", "-p", "127.0.0.1::5678", "-v", f"{volume}:/home/node/.n8n", IMAGE)
        runtime = inspect(runtime_name); runtime_id = owned_container(runtime, job, "runtime", volume)
        assigned_port = assigned_loopback_port(runtime)
        receipt["stages"].append("replacement_runtime_bound")
        key_after = sanitize_json(docker("exec", "-u", "node", runtime_id, "node", "-e", CONFIG_KEY_NODE))
        if key_after.get("ok") is not True or key_after.get("encryptionKeySha256") != key_before["encryptionKeySha256"]:
            raise CanaryFailure("volume_encryption_key_handoff_unproven")
        try:
            probe = final_host_probe(assigned_port, raw_key)
        except ProbeFailure as error:
            receipt["final_probe"] = error.diagnosis
            receipt["final_runtime"] = runtime_observation(runtime_id)
            if str(error) == "final_unauthenticated_probe_failed":
                receipt["in_container_negative_probe"] = in_container_negative_probe(runtime_id)
            raise
        receipt["negative_status"] = probe.get("negativeStatus"); receipt["positive_status"] = probe.get("positiveStatus"); receipt["stages"].append("negative_and_authenticated_probe_passed")
        import_workflows(repository, assigned_port, raw_key, receipt)
        if execute_templates == "true":
            import n8n_template_execution_canary as execution_canary
            assert runtime_id is not None
            receipt["execution_script_sha256"] = sha256_file(Path(execution_canary.__file__).resolve())
            execution_canary.execute_templates(sys.modules[__name__], repository, job, volume, runtime_id, assigned_port, raw_key, receipt)
            runtime_id = None
        receipt["outcome"] = "passed"
        exit_code = 0
    except UnknownEffect as error:
        receipt.setdefault("unknown_effect_stage", str(error))
    except CanaryFailure as error:
        receipt["failure_stage"] = str(error)
    except Exception:
        receipt["failure_stage"] = "unexpected_canary_failure"
    finally:
        raw_key = None
        for identifier in (runtime_id, bootstrap_id):
            if identifier is not None:
                try:
                    row = inspect(identifier)
                    if owned_container(row, job, "runtime" if identifier == runtime_id else "bootstrap", volume) == identifier:
                        result = run(("docker", "rm", "-f", identifier))
                        if result.code != 0 or result.timed_out or result.overflow:
                            raise CanaryFailure("container_cleanup_failed")
                        prove_absent("container", identifier)
                except CanaryFailure:
                    # A transition may already have removed the exact bootstrap
                    # ID.  Only Docker-health plus the canonical absence reply
                    # can distinguish that from a generic inspect failure.
                    try:
                        prove_absent("container", identifier)
                    except CanaryFailure:
                        receipt.setdefault("cleanup", []).append("container_retained_identity_unproven")
                        cleanup_failed = True
        try:
            row = inspect(volume)
            labels = row.get("Labels", {})
            if labels.get("io.neoth.managed") == "n8n" and labels.get("io.neoth.n8n-job") == job and labels.get("io.neoth.canary-kind") == "volume":
                result = run(("docker", "volume", "rm", volume))
                if result.code != 0 or result.timed_out or result.overflow:
                    raise CanaryFailure("volume_cleanup_failed")
                prove_absent("volume", volume)
            else:
                receipt.setdefault("cleanup", []).append("volume_retained_identity_unproven")
                cleanup_failed = True
        except CanaryFailure:
            receipt.setdefault("cleanup", []).append("volume_inspect_unavailable")
            cleanup_failed = True
        if cleanup_failed:
            receipt["outcome"] = "failed"
            receipt["cleanup_failure_stage"] = "cleanup_unproven"
            if exit_code == 0:
                receipt["failure_stage"] = "cleanup_unproven"
            exit_code = 1
        write_receipt(receipt_path, receipt)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
