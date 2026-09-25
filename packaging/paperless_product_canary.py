#!/usr/bin/env python3
"""Hosted-only end-to-end canary for the public NEOTH Paperless lifecycle.

The receipt deliberately contains hashes and counts only.  Docker identifiers,
volume names, fixture secrets, command output, and API bodies remain local to
this disposable runner process.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import n8n_bootstrap_canary as bounded

IMAGES = {
    "webserver": "ghcr.io/paperless-ngx/paperless-ngx@sha256:5fa76604a81df6945086e0837b14b56543d137e8ce4f311cc5d9ebe907e74e79",
    "broker": "registry-1.docker.io/valkey/valkey@sha256:48332870af354a799964c0012ae1194a0bf2bf894eb508f945810596dc2d8d11",
    "db": "registry-1.docker.io/library/postgres@sha256:86c951e05bf56c93d95d397747fb8820ac76cc3bedb78f43abd83eedbe3666ae",
}
VOLUMES = (
    ("paperless_consume", "webserver", "/usr/src/paperless/consume"),
    ("paperless_data", "webserver", "/usr/src/paperless/data"),
    ("paperless_media", "webserver", "/usr/src/paperless/media"),
    ("paperless_export", "webserver", "/usr/src/paperless/export"),
    ("paperless_valkey", "broker", "/data"),
    ("paperless_postgres", "db", "/var/lib/postgresql"),
)
SHA256 = re.compile(r"[0-9a-f]{64}")
IDENTIFIER = re.compile(r"[0-9a-f]{64}")
VOLUME_SET_ID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}")
API_LIMIT = 32 * 1024
CONFIG_LIMIT = 256 * 1024
DOWNLOAD_LIMIT = 2 * 1024 * 1024
TASK_ID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
MARKER_TITLE = "NEOTH Paperless retained-data canary"
# A deterministic, minimal, one-page PDF. PDF is handled by the pinned
# Paperless image without relying on a separately configured text parser.
MARKER_PDF = (
    b"%PDF-1.4\n"
    b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
    b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>\nendobj\n"
    b"4 0 obj\n<< /Length 58 >>\nstream\nBT\n/F1 12 Tf\n72 720 Td\n(NEOTH retained-data canary) Tj\nET\nendstream\nendobj\n"
    b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n"
    b"xref\n0 6\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n0000000241 00000 n \n0000000348 00000 n \n"
    b"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n418\n%%EOF\n"
)
MARKER_PDF_OFFSETS = (9, 58, 115, 241, 348)


class Failure(RuntimeError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def api_opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())


class CommandFailure(Failure):
    def __init__(self, argv: list[str], result: bounded.Result):
        super().__init__("command_failed")
        program = Path(argv[0]).name
        command = "docker" if program == "docker" else "other"
        if program == "neoth" and argv[1:4] == ["--output", "json", "paperless"]:
            command = {"prepare": "product_prepare", "install": "product_install", "status": "product_status"}.get(argv[4], "other")
        elif program == "neoth" and argv[1:2] == ["init"]:
            command = "product_init"
        markers = (
            "paperless_not_prepared", "paperless_unowned_or_mismatch",
            "paperless_legacy_state_migration_required",
            "paperless_loopback_credentials_required", "paperless_provenance_receipt_invalid",
            "paperless_compose_external_launch_unavailable", "paperless_authenticated_readiness_failed",
            "paperless_lifecycle_io_error", "paperless_command_spawn_failed",
            "paperless_command_capture_failed", "paperless_command_wait_failed",
            "paperless_command_failed", "paperless_command_non_utf8",
            "paperless_command_timeout", "paperless_command_output_limit",
            "paperless_empty_command", "paperless_container_id_missing", "paperless_container_id_changed",
            "paperless_container_service_missing", "paperless_volume_changed_after_readiness",
            "paperless_volume_inspect_invalid", "paperless_volume_ownership_mismatch",
            "paperless_image_inspect_invalid", "paperless_image_repo_digest_mismatch",
            "paperless_image_engine_platform_mismatch", "paperless_image_platform_unadmitted",
            "paperless_image_config_id_mismatch", "paperless_container_inspect_invalid",
            "paperless_container_image_mismatch", "paperless_container_compose_labels_mismatch",
            "paperless_loopback_port_mismatch", "paperless_container_volume_mount_mismatch",
            "paperless_docker_engine_platform_rejected", "paperless_docker_engine_invalid",
            "paperless_docker_context_invalid", "paperless_docker_context_endpoint_invalid",
            "paperless_remote_docker_context_rejected", "paperless_docker_host_override_rejected",
            "paperless_bootstrap_config_invalid", "paperless_bootstrap_transport", "paperless_bootstrap_timeout",
        )
        self.diagnostic = {
            "command": command, "exit_code": result.code, "timed_out": result.timed_out,
            "overflow": result.overflow, "stdout_bytes": len(result.stdout),
            "stderr_bytes": len(result.stderr),
            "known_error_categories": [m for m in markers if m.encode() in result.stderr],
        }


def run(argv: list[str], timeout: int = 180) -> bytes:
    result = bounded.run(argv, timeout=timeout)
    if result.timed_out or result.overflow or result.code != 0:
        raise CommandFailure(argv, result)
    return result.stdout


def read_json_bytes(raw: bytes, code: str) -> dict:
    try:
        value = json.loads(raw)
    except Exception as error:
        raise Failure(code) from error
    if not isinstance(value, dict):
        raise Failure(code)
    return value


def require(value: dict, key: str, kind: type):
    item = value.get(key)
    if type(item) is not kind:
        raise Failure("product_json_shape_invalid")
    return item


def project_name(root: Path) -> str:
    return "neoth-paperless-" + hashlib.sha256(str(root).encode()).hexdigest()[:12]


def hosted_paths(home: Path, receipt: Path) -> Path:
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("GITHUB_REF") != "refs/heads/main":
        raise Failure("hosted_guard_failed")
    if not re.fullmatch(r"[0-9a-f]{40}", os.environ.get("GITHUB_SHA", "")) or not re.fullmatch(r"[1-9][0-9]*", os.environ.get("GITHUB_RUN_ID", "")) or not re.fullmatch(r"[1-9][0-9]*", os.environ.get("GITHUB_RUN_ATTEMPT", "")):
        raise Failure("hosted_guard_failed")
    parent_text, root_text = os.environ.get("RUNNER_TEMP", ""), os.environ.get("W1146_ROOT", "")
    if not parent_text or not root_text:
        raise Failure("hosted_guard_failed")
    parent, claimed_parent = Path(parent_text).resolve(), Path(root_text).resolve()
    expected = parent / f"w1146-paperless-{os.environ['GITHUB_RUN_ID']}-{os.environ['GITHUB_RUN_ATTEMPT']}"
    if claimed_parent != parent or not expected.is_dir() or expected.is_symlink() or home.is_symlink() or not home.is_dir() or home.resolve() != expected / "neoth-home" or receipt.resolve() != expected / "receipt" / "receipt.json" or any(home.iterdir()) or os.environ.get("NEOTH_HOME") != str(home.resolve()):
        raise Failure("isolated_path_invalid")
    return expected


def initialize_home(binary: Path, home: Path) -> None:
    run([str(binary), "init", "--non-interactive", "--cli", "--accept-license", "--operator-id", "w1146canary", "--provider", "skip"])
    config = home / "freedom.yaml"
    if config.is_symlink() or not config.is_file() or config.stat().st_size > CONFIG_LIMIT:
        raise Failure("product_init_config_invalid")
    raw = config.read_bytes()
    if b"secrets_backend: file" not in raw or b"operator_id: w1146canary" not in raw:
        raise Failure("product_init_config_invalid")


def validate_prepare(value: dict) -> None:
    if value.get("status") not in {"prepared_pinned", "already_prepared"} or value.get("prepared") is not True:
        raise Failure("prepare_not_ready")
    if not all(isinstance(value.get(k), str) and value[k] for k in ("receipt_id", "contract_id", "provenance_coverage")):
        raise Failure("prepare_json_shape_invalid")


def write_env_fixture(root: Path, port: int) -> None:
    required = {"ownership.json", "compose.yaml", "paperless.env.example"}
    if root.is_symlink() or not root.is_dir() or {p.name for p in root.iterdir()} != required:
        raise Failure("prepared_root_invalid")
    path = root / "paperless.env"
    if path.exists() or path.is_symlink():
        raise Failure("fixture_path_invalid")
    values = {
        "PAPERLESS_SECRET_KEY": secrets.token_urlsafe(48), "PAPERLESS_DB_NAME": "paperless",
        "PAPERLESS_DB_USER": "paperless", "PAPERLESS_DB_PASSWORD": secrets.token_urlsafe(32),
        "PAPERLESS_ADMIN_USER": "w1146canary", "PAPERLESS_ADMIN_PASSWORD": secrets.token_urlsafe(32),
        "PAPERLESS_BIND_PORT": str(port),
    }
    path.write_text("".join(f"{key}={value}\n" for key, value in values.items()), encoding="utf-8")
    os.chmod(path, 0o600)


def docker_json(identifier: str, volume: bool = False) -> dict:
    if volume:
        projection = r'{"Name":{{json .Name}},"Labels":{"com.docker.compose.project":{{json (index .Labels "com.docker.compose.project")}},"com.docker.compose.volume":{{json (index .Labels "com.docker.compose.volume")}},"io.neoth.paperless.volume-set-id":{{json (index .Labels "io.neoth.paperless.volume-set-id")}}}}'
        argv = ["docker", "volume", "inspect", "--format", projection, identifier]
    else:
        projection = r'{"Id":{{json .Id}},"Image":{{json .Image}},"State":{"Running":{{json .State.Running}}},"Config":{"Labels":{"com.docker.compose.project":{{json (index .Config.Labels "com.docker.compose.project")}},"com.docker.compose.service":{{json (index .Config.Labels "com.docker.compose.service")}}}},"NetworkSettings":{"Ports":{{json .NetworkSettings.Ports}}},"Mounts":{{json .Mounts}}}'
        argv = ["docker", "container", "inspect", "--format", projection, identifier]
    raw = run(argv, timeout=45)
    try:
        value = json.loads(raw)
    except Exception as error:
        raise Failure("docker_inspect_invalid") from error
    if not isinstance(value, dict):
        raise Failure("docker_inspect_invalid")
    return value


def validate_container(row: dict, project: str, service: str, image_id: str, port: int) -> str:
    identifier = row.get("Id")
    labels = row.get("Config", {}).get("Labels", {})
    if not isinstance(identifier, str) or not IDENTIFIER.fullmatch(identifier) or row.get("Image") != image_id or row.get("State", {}).get("Running") is not True or labels.get("com.docker.compose.project") != project or labels.get("com.docker.compose.service") != service:
        raise Failure("container_identity_invalid")
    expected = [(name, destination) for name, owner, destination in VOLUMES if owner == service]
    mounts = row.get("Mounts")
    if not isinstance(mounts, list) or len(mounts) != len(expected) or any(not any(m.get("Type") == "volume" and m.get("Name") == f"{project}_{name}" and m.get("Destination") == destination for m in mounts if isinstance(m, dict)) for name, destination in expected):
        raise Failure("container_mount_invalid")
    ports = row.get("NetworkSettings", {}).get("Ports", {})
    bindings = ports.get("8000/tcp") if isinstance(ports, dict) else None
    if service == "webserver":
        if not isinstance(bindings, list) or len(bindings) != 1 or bindings[0].get("HostIp") != "127.0.0.1" or bindings[0].get("HostPort") != str(port):
            raise Failure("container_port_invalid")
    elif bindings not in (None, []):
        raise Failure("container_port_invalid")
    return identifier


def validate_volume(row: dict, project: str, logical: str, volume_set_id: str | None = None) -> str:
    name = row.get("Name")
    labels = row.get("Labels", {})
    if not isinstance(name, str) or name != f"{project}_{logical}" or labels.get("com.docker.compose.project") != project or labels.get("com.docker.compose.volume") != logical or (volume_set_id is not None and labels.get("io.neoth.paperless.volume-set-id") != volume_set_id):
        raise Failure("volume_identity_invalid")
    return name


def validate_install(value: dict, port: int) -> tuple[str, dict[str, str], tuple[str, ...], str | None]:
    project = require(value, "project", str)
    schema_version = value.get("schema_version")
    volume_set_id = value.get("volume_set_id")
    if schema_version not in {1, 2} or value.get("operation") != "install" or value.get("loopback_port") != port or value.get("authenticated_api_ready") is not True:
        raise Failure("install_json_invalid")
    if schema_version == 1 and volume_set_id is not None:
        raise Failure("install_json_invalid")
    if schema_version == 2 and (not isinstance(volume_set_id, str) or not VOLUME_SET_ID.fullmatch(volume_set_id)):
        raise Failure("install_json_invalid")
    images, containers, volumes = require(value, "images", list), require(value, "containers", list), require(value, "volumes", list)
    if len(images) != len(IMAGES) or len(containers) != len(IMAGES) or len(volumes) != len(VOLUMES):
        raise Failure("install_json_shape_invalid")
    config_ids: dict[str, str] = {}
    for item in images:
        if not isinstance(item, dict) or item.get("service") not in IMAGES or item.get("reference") != IMAGES[item["service"]] or not isinstance(item.get("config_id"), str) or not item["config_id"]:
            raise Failure("image_receipt_invalid")
        config_ids[item["service"]] = item["config_id"]
    ids: list[str] = []
    container_services: set[str] = set()
    for item in containers:
        if not isinstance(item, dict) or item.get("service") not in config_ids or not isinstance(item.get("id"), str) or not IDENTIFIER.fullmatch(item["id"]) or item.get("image_id") != config_ids[item["service"]]:
            raise Failure("container_receipt_invalid")
        ids.append(item["id"])
        container_services.add(item["service"])
    expected_logical_names = {logical for logical, _, _ in VOLUMES}
    names: dict[str, str] = {}
    for item in volumes:
        logical_name = item.get("logical_name") if isinstance(item, dict) else None
        name = item.get("name") if isinstance(item, dict) else None
        if not isinstance(item, dict) or not isinstance(logical_name, str) or logical_name not in expected_logical_names or logical_name in names or item.get("project") != project or not isinstance(name, str) or name != f"{project}_{logical_name}" or item.get("volume_set_id") != volume_set_id:
            raise Failure("volume_receipt_invalid")
        names[logical_name] = name
    if len(set(ids)) != len(IMAGES) or len(config_ids) != len(IMAGES) or container_services != set(IMAGES) or set(names) != expected_logical_names:
        raise Failure("lifecycle_identity_duplicate")
    return project, config_ids, tuple(ids + [names[logical] for logical, _, _ in VOLUMES]), volume_set_id


def admitted_images() -> dict[str, tuple[str, str]]:
    path = Path.cwd() / "docs/verification/paperless-oci-v3.2.1/recursive-blob-receipt.json"
    try:
        receipt = json.loads(path.read_bytes())
    except Exception as error:
        raise Failure("admission_receipt_invalid") from error
    if not isinstance(receipt, dict) or receipt.get("schema_version") != 2 or receipt.get("artifact_blob_bytes_verified") is not True or not isinstance(receipt.get("selectors"), list):
        raise Failure("admission_receipt_invalid")
    names = {"paperless": "webserver", "valkey": "broker", "postgres": "db"}
    admitted: dict[str, tuple[str, str]] = {}
    for selector in receipt["selectors"]:
        if not isinstance(selector, dict) or selector.get("name") not in names or not isinstance(selector.get("index"), dict) or not isinstance(selector["index"].get("digest"), str) or not isinstance(selector.get("platforms"), dict):
            raise Failure("admission_receipt_invalid")
        service, digest = names[selector["name"]], selector["index"]["digest"]
        platform = selector["platforms"].get("linux/amd64")
        if not isinstance(platform, dict) or not isinstance(platform.get("config"), dict) or not isinstance(platform["config"].get("digest"), str) or IMAGES[service].rsplit("@", 1)[-1] != digest:
            raise Failure("admission_receipt_invalid")
        admitted[service] = (IMAGES[service], platform["config"]["digest"])
    if set(admitted) != set(IMAGES):
        raise Failure("admission_receipt_invalid")
    return admitted


def validate_image(row: dict, reference: str, config_id: str) -> None:
    digests = row.get("RepoDigests")
    if row.get("Id") != config_id or row.get("Os") != "linux" or row.get("Architecture") != "amd64" or not isinstance(digests, list) or reference not in digests:
        raise Failure("independent_image_admission_invalid")


def docker_image(reference: str) -> dict:
    raw = run(["docker", "image", "inspect", reference], timeout=45)
    try:
        value = json.loads(raw)
    except Exception as error:
        raise Failure("docker_image_inspect_invalid") from error
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise Failure("docker_image_inspect_invalid")
    return value[0]


def configured_token(home: Path) -> str:
    path = home / "credentials.yaml"
    if path.is_symlink() or not path.is_file() or path.stat().st_size > CONFIG_LIMIT:
        raise Failure("file_credential_token_missing")
    match = re.search(rb"(?m)^paperless_token:\s*(?:\"([^\"]+)\"|'([^']+)'|([^\s#]+))\s*$", path.read_bytes())
    if not match:
        raise Failure("file_credential_token_missing")
    token = next(part for part in match.groups() if part is not None)
    if not 1 <= len(token) <= 4096:
        raise Failure("file_credential_token_invalid")
    return token.decode("utf-8", "strict")


def paperless_api_bytes(port: int, token: str | None, path: str, expected: set[int], *, method: str = "GET", data: bytes | None = None, extra_headers: dict[str, str] | None = None, limit: int = API_LIMIT) -> tuple[int, bytes]:
    headers = {"Authorization": f"Token {token}"} if token is not None else {}
    if extra_headers:
        headers.update(extra_headers)
    request = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, headers=headers, method=method)
    try:
        with api_opener().open(request, timeout=20) as response:
            status = response.status
            raw = response.read(limit + 1)
    except urllib.error.HTTPError as error:
        status, raw = error.code, error.read(limit + 1)
    except Exception as error:
        raise Failure("paperless_api_transport") from error
    if status in range(300, 400):
        raise Failure("paperless_api_redirect")
    if status not in expected:
        raise Failure("paperless_api_status_invalid")
    if len(raw) > limit:
        raise Failure("paperless_api_response_too_large")
    return status, raw


def paperless_api_json(port: int, token: str | None, path: str, expected: set[int]) -> dict:
    status, raw = paperless_api_bytes(port, token, path, expected, extra_headers={"Accept": "application/json; version=10"})
    if status in {401, 403}:
        return {}
    try:
        value = json.loads(raw)
    except Exception as error:
        raise Failure("paperless_api_json_invalid") from error
    if not isinstance(value, dict):
        raise Failure("paperless_api_json_invalid")
    return value


def verify_api(port: int, token: str) -> dict:
    paperless_api_json(port, None, "/api/profile/", {401, 403})
    profile = paperless_api_json(port, token, "/api/profile/", {200})
    status = paperless_api_json(port, token, "/api/status/", {200, 403})
    if not isinstance(profile.get("has_usable_password"), bool) or not isinstance(profile.get("is_mfa_enabled"), bool) or not isinstance(profile.get("social_accounts"), list):
        raise Failure("paperless_api_profile_invalid")
    version = status.get("pngx_version") if status else None
    if status and (not isinstance(version, str) or not re.fullmatch(r"[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}", version)):
        raise Failure("paperless_api_status_shape_invalid")
    return {"profile_authenticated": True, "negative_control_rejected": True, "status_permission_required": not bool(status), "version_sha256": hashlib.sha256((version or "permission_required").encode()).hexdigest()}


def validate_marker_pdf(document: bytes) -> None:
    objects = tuple(f"{index} 0 obj\n".encode("ascii") for index in range(1, 6))
    if not document.startswith(b"%PDF-1.4\n") or not document.endswith(b"%%EOF\n") or b"(NEOTH retained-data canary) Tj\n" not in document or b"/Length 58 >>\nstream\n" not in document:
        raise Failure("marker_pdf_invalid")
    if tuple(document.find(item) for item in objects) != MARKER_PDF_OFFSETS:
        raise Failure("marker_pdf_invalid")
    xref = b"xref\n0 6\n0000000000 65535 f \n" + b"".join(f"{offset:010d} 00000 n \n".encode("ascii") for offset in MARKER_PDF_OFFSETS)
    if xref not in document or document.find(b"xref\n") != 418 or b"startxref\n418\n" not in document:
        raise Failure("marker_pdf_invalid")


def multipart_marker(title: str, document: bytes) -> tuple[bytes, str]:
    if not title or "\r" in title or "\n" in title or len(document) > DOWNLOAD_LIMIT:
        raise Failure("marker_fixture_invalid")
    validate_marker_pdf(document)
    boundary = "----neoth-" + secrets.token_hex(16)
    body = (
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\n{title}\r\n"
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"document\"; filename=\"retained-canary.pdf\"\r\nContent-Type: application/pdf\r\n\r\n"
    ).encode("ascii") + document + f"\r\n--{boundary}--\r\n".encode("ascii")
    return body, f"multipart/form-data; boundary={boundary}"


def upload_marker(port: int, token: str) -> str:
    body, content_type = multipart_marker(MARKER_TITLE, MARKER_PDF)
    _, raw = paperless_api_bytes(port, token, "/api/documents/post_document/", {200}, method="POST", data=body, extra_headers={"Content-Type": content_type, "Accept": "application/json; version=10"}, limit=API_LIMIT)
    try:
        task_id = json.loads(raw)
    except Exception as error:
        raise Failure("marker_upload_response_invalid") from error
    if not isinstance(task_id, str) or not TASK_ID.fullmatch(task_id):
        raise Failure("marker_upload_response_invalid")
    return task_id


def task_document_id(port: int, token: str, task_id: str) -> tuple[int, int]:
    if not TASK_ID.fullmatch(task_id):
        raise Failure("marker_task_id_invalid")
    polls = 0
    deadline = time.monotonic() + 120
    path = "/api/tasks/?task_id=" + urllib.parse.quote(task_id, safe="")
    while time.monotonic() < deadline:
        polls += 1
        response = paperless_api_json(port, token, path, {200})
        results = response.get("results")
        if not isinstance(results, list):
            raise Failure("marker_task_response_invalid")
        if len(results) > 1:
            raise Failure("marker_task_ambiguous")
        if not results:
            time.sleep(2)
            continue
        task = results[0]
        if not isinstance(task, dict) or task.get("task_id") != task_id or not isinstance(task.get("status"), str):
            raise Failure("marker_task_response_invalid")
        status = task["status"]
        if status == "success":
            document_ids = task.get("related_document_ids")
            if not isinstance(document_ids, list) or len(document_ids) != 1 or type(document_ids[0]) is not int or document_ids[0] <= 0:
                raise Failure("marker_task_document_invalid")
            return document_ids[0], polls
        if status in {"failure", "revoked"}:
            raise Failure("marker_task_failed")
        if status not in {"pending", "started"}:
            raise Failure("marker_task_status_invalid")
        time.sleep(2)
    raise Failure("marker_task_timeout")


def marker_metadata(port: int, token: str, document_id: int) -> tuple[int, str, str]:
    if type(document_id) is not int or document_id <= 0:
        raise Failure("marker_document_id_invalid")
    detail = paperless_api_json(port, token, f"/api/documents/{document_id}/", {200})
    if detail.get("id") != document_id or detail.get("title") != MARKER_TITLE:
        raise Failure("marker_metadata_invalid")
    _, original = paperless_api_bytes(port, token, f"/api/documents/{document_id}/download/?original=true", {200}, limit=DOWNLOAD_LIMIT)
    digest = hashlib.sha256(original).hexdigest()
    if digest != hashlib.sha256(MARKER_PDF).hexdigest():
        raise Failure("marker_original_bytes_mismatch")
    return document_id, MARKER_TITLE, digest


def persisted_receipt_bytes(home: Path, name: str, code: str) -> bytes:
    path = home / "paperless" / "state" / name
    if path.is_symlink() or not path.is_file() or path.stat().st_size > CONFIG_LIMIT:
        raise Failure(code)
    return path.read_bytes()


def persisted_install_receipt(home: Path, expected: tuple[str, dict[str, str], tuple[str, ...], str | None], port: int) -> bytes:
    raw = persisted_receipt_bytes(home, ".neoth-paperless-lifecycle-receipt.v1.json", "install_receipt_bytes_invalid")
    if validate_install(read_json_bytes(raw, "install_receipt_bytes_invalid"), port) != expected:
        raise Failure("install_receipt_bytes_invalid")
    return raw


def persisted_uninstall_receipt(home: Path, expected: dict) -> bytes:
    raw = persisted_receipt_bytes(home, ".neoth-paperless-uninstall-custody.v1.json", "uninstall_receipt_bytes_invalid")
    if read_json_bytes(raw, "uninstall_receipt_bytes_invalid") != expected:
        raise Failure("uninstall_receipt_bytes_invalid")
    return raw


def persisted_purge_receipt(home: Path, expected: dict) -> bytes:
    raw = persisted_receipt_bytes(home, ".neoth-paperless-purge-receipt.v1.json", "purge_receipt_bytes_invalid")
    if read_json_bytes(raw, "purge_receipt_bytes_invalid") != expected:
        raise Failure("purge_receipt_bytes_invalid")
    return raw


def purge_artifacts_absent(home: Path) -> tuple[object, ...]:
    for name in (".neoth-paperless-purge-custody.v1.json", ".neoth-paperless-purge-receipt.v1.json"):
        path = home / "paperless" / "state" / name
        if path.exists() or path.is_symlink():
            raise Failure("purge_artifact_present")
    return ()


def validate_uninstall(value: dict, project: str, original_ids: tuple[str, ...], volume_names: tuple[str, ...], install_receipt_bytes: bytes, volume_set_id: str | None = None) -> None:
    schema_version = value.get("schema_version")
    if schema_version not in {1, 2} or value.get("operation") != "paperless.safe_uninstall" or value.get("project") != project or value.get("phase") != "complete" or value.get("network_retained") is not True:
        raise Failure("uninstall_receipt_invalid")
    if (volume_set_id is None and schema_version != 1) or (volume_set_id is not None and schema_version != 2):
        raise Failure("uninstall_receipt_invalid")
    ids = value.get("original_container_ids")
    retained = value.get("retained_volumes")
    containers = value.get("containers")
    if not isinstance(ids, list) or tuple(ids) != original_ids or not isinstance(retained, list) or tuple(retained) != volume_names or not isinstance(containers, list) or len(containers) != len(original_ids) or value.get("install_receipt_sha256") != hashlib.sha256(install_receipt_bytes).hexdigest():
        raise Failure("uninstall_receipt_invalid")
    expected_services = set(IMAGES)
    seen_ids: set[str] = set()
    seen_services: set[str] = set()
    for item in containers:
        if not isinstance(item, dict) or item.get("id") not in original_ids or item.get("removed") is not True or item.get("service") not in expected_services or item["id"] in seen_ids or item["service"] in seen_services:
            raise Failure("uninstall_receipt_invalid")
        seen_ids.add(item["id"]); seen_services.add(item["service"])
    if seen_ids != set(original_ids) or seen_services != expected_services:
        raise Failure("uninstall_receipt_invalid")

    snapshot = value.get("retained_volume_snapshot")
    if volume_set_id is None:
        if snapshot not in (None, []):
            raise Failure("uninstall_receipt_invalid")
        return
    expected_snapshot = [
        {"logical_name": logical, "name": name, "project": project, "volume_set_id": volume_set_id}
        for (logical, _, _), name in zip(VOLUMES, volume_names, strict=True)
    ]
    if snapshot != expected_snapshot:
        raise Failure("uninstall_receipt_invalid")


def retained_volumes(project: str, volume_names: tuple[str, ...], volume_set_id: str | None = None) -> None:
    if len(volume_names) != len(VOLUMES):
        raise Failure("retained_volume_count_invalid")
    for (logical, _, _), name in zip(VOLUMES, volume_names, strict=True):
        if validate_volume(docker_json(name, volume=True), project, logical, volume_set_id) != name:
            raise Failure("retained_volume_identity_invalid")


def persisted_volume_set_snapshot(home: Path, project: str, volume_set_id: str) -> bytes:
    raw = persisted_receipt_bytes(home, ".neoth-paperless-volume-set.v1.json", "volume_set_snapshot_invalid")
    value = read_json_bytes(raw, "volume_set_snapshot_invalid")
    if value != {"schema_version": 1, "project": project, "volume_set_id": volume_set_id, "logical_volumes": [logical for logical, _, _ in VOLUMES]}:
        raise Failure("volume_set_snapshot_invalid")
    return raw


def json_sha256(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def validate_purge_preview(value: dict, project: str, install_receipt_bytes: bytes, uninstall_receipt_bytes: bytes, volume_set_id: str, volume_names: tuple[str, ...]) -> str:
    expected_volumes = [{"logical_name": logical, "name": name, "state": "prepared"} for (logical, _, _), name in zip(VOLUMES, volume_names, strict=True)]
    phrase = f"PURGE PAPERLESS VOLUME SET {hashlib.sha256(install_receipt_bytes).hexdigest()} {volume_set_id}"
    if set(value) != {"schema_version", "operation", "state", "project", "install_receipt_sha256", "uninstall_receipt_sha256", "volume_set_id", "volumes", "confirmation"} or value.get("schema_version") != 1 or value.get("operation") != "paperless.confirmed_purge" or value.get("state") != "confirmation_required" or value.get("project") != project or value.get("install_receipt_sha256") != hashlib.sha256(install_receipt_bytes).hexdigest() or value.get("uninstall_receipt_sha256") != hashlib.sha256(uninstall_receipt_bytes).hexdigest() or value.get("volume_set_id") != volume_set_id or value.get("volumes") != expected_volumes or value.get("confirmation") != phrase:
        raise Failure("purge_preview_invalid")
    return phrase


def validate_purge_complete(value: dict, project: str, install_receipt_bytes: bytes, uninstall_receipt_bytes: bytes, volume_set_id: str, volume_names: tuple[str, ...]) -> None:
    expected_volumes = [{"logical_name": logical, "name": name, "state": "absent_verified"} for (logical, _, _), name in zip(VOLUMES, volume_names, strict=True)]
    if set(value) != {"schema_version", "operation", "state", "project", "install_receipt_sha256", "uninstall_receipt_sha256", "volume_set_id", "volumes"} or value.get("schema_version") != 1 or value.get("operation") != "paperless.confirmed_purge" or value.get("state") != "volumes_removed" or value.get("project") != project or value.get("install_receipt_sha256") != hashlib.sha256(install_receipt_bytes).hexdigest() or value.get("uninstall_receipt_sha256") != hashlib.sha256(uninstall_receipt_bytes).hexdigest() or value.get("volume_set_id") != volume_set_id or value.get("volumes") != expected_volumes:
        raise Failure("purge_receipt_invalid")


def cleanup(project: str, config_ids: dict[str, str], identities: tuple[str, ...], port: int, retired_container_ids: tuple[str, ...] = (), volume_set_id: str | None = None, volumes_already_absent: bool = False) -> tuple[bool, str | None]:
    container_ids, volume_names = identities[:3], identities[3:]
    try:
        for service, identifier in zip(IMAGES, container_ids, strict=True):
            if identifier in retired_container_ids:
                bounded.prove_absent("container", identifier)
            else:
                validate_container(docker_json(identifier), project, service, config_ids[service], port)
        for identifier in retired_container_ids:
            if not IDENTIFIER.fullmatch(identifier):
                raise Failure("retired_container_identity_invalid")
            if identifier not in container_ids:
                bounded.prove_absent("container", identifier)
        for (logical, _, _), name in zip(VOLUMES, volume_names, strict=True):
            if volumes_already_absent:
                bounded.prove_absent("volume", name)
                continue
            if validate_volume(docker_json(name, volume=True), project, logical, volume_set_id) != name:
                raise Failure("volume_identity_invalid")
        for identifier in container_ids:
            if identifier in retired_container_ids:
                continue
            run(["docker", "rm", "-f", identifier], timeout=45)
            bounded.prove_absent("container", identifier)
        for name in volume_names:
            if volumes_already_absent:
                continue
            run(["docker", "volume", "rm", name], timeout=45)
            bounded.prove_absent("volume", name)
        return True, None
    except CommandFailure:
        return False, "cleanup_command_failed"
    except Failure:
        return False, "cleanup_ownership_unproven"
    except Exception:
        return False, "cleanup_unexpected"


def source_hashes() -> dict[str, str]:
    names = (
        "packaging/tests/test_paperless_product_canary.py", "SRC/neothd/src/cli/paperless.rs",
        "SRC/neothd/src/installers/paperless_staging.rs", "SRC/neothd/src/installers/paperless_lifecycle.rs",
        "SRC/neothd/src/installers/paperless_purge.rs", "SRC/neothd/src/installers/paperless_purge_tests.rs",
        "SRC/neothd/src/installers/paperless_operation_lock.rs", "SRC/neothd/src/installers/paperless_uninstall_tests.rs",
        "SRC/neothd/src/installers/paperless_readiness.rs", "SRC/neothd/src/installers/paperless_bootstrap.rs",
        "SRC/neothd/src/cli/init.rs", "SRC/neothd/src/config/credentials.rs", "SRC/Cargo.lock",
        "SRC/neothd/src/config/mod.rs", "SRC/neothd/src/updater/process_containment.rs",
        "docs/verification/paperless-oci-v3.2.1/recursive-blob-receipt.json",
    )
    return {name: hashlib.sha256((Path.cwd() / name).read_bytes()).hexdigest() for name in names}


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--binary", required=True); parser.add_argument("--home", required=True); parser.add_argument("--port", required=True, type=int); parser.add_argument("--receipt", required=True)
    args = parser.parse_args(); binary, home, receipt_path = Path(args.binary), Path(args.home), Path(args.receipt)
    receipt = {"schema": 1, "source_sha": os.environ.get("GITHUB_SHA"), "port": args.port, "credential_backend": "file", "outcome": "failed", "cleanup_proven": False}
    project = None; config_ids: dict[str, str] | None = None; identities: tuple[str, ...] | None = None; retired_ids: tuple[str, ...] = (); volume_set_id: str | None = None; volumes_purged = False
    try:
        hosted_paths(home, receipt_path)
        if not 1 <= args.port <= 65535 or not binary.is_file():
            raise Failure("arguments_invalid")
        receipt.update({"helper_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "bounded_helper_sha256": hashlib.sha256(Path(bounded.__file__).read_bytes()).hexdigest(), "workflow_sha256": hashlib.sha256((Path.cwd() / ".github/workflows/paperless-product.yml").read_bytes()).hexdigest(), "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(), "input_sha256": source_hashes()})
        initialize_home(binary, home)
        prepared = read_json_bytes(run([str(binary), "--output", "json", "paperless", "prepare"]), "prepare_json_invalid"); validate_prepare(prepared)
        write_env_fixture(home / "paperless", args.port)
        first = read_json_bytes(run([str(binary), "--output", "json", "paperless", "install"], timeout=900), "install_json_invalid")
        project, reported_configs, identities, volume_set_id = validate_install(first, args.port)
        if volume_set_id is None:
            raise Failure("fresh_volume_set_required")
        volume_set_snapshot_bytes = persisted_volume_set_snapshot(home, project, volume_set_id)
        admitted = admitted_images()
        config_ids = {}
        for service, (reference, config_id) in admitted.items():
            validate_image(docker_image(reference), reference, config_id)
            if reported_configs.get(service) != config_id:
                raise Failure("product_image_receipt_mismatch")
            config_ids[service] = config_id
        if project != project_name(home / "paperless"):
            raise Failure("project_name_invalid")
        for service, identifier in zip(IMAGES, identities[:3], strict=True):
            validate_container(docker_json(identifier), project, service, config_ids[service], args.port)
        for (logical, _, _), name in zip(VOLUMES, identities[3:], strict=True):
            validate_volume(docker_json(name, volume=True), project, logical, volume_set_id)
        status = read_json_bytes(run([str(binary), "--output", "json", "paperless", "status"]), "status_json_invalid")
        if status.get("status") != "authenticated_api_ready" or status.get("authenticated_api_ready") is not True or status.get("staging") not in {"prepared_pinned", "already_prepared"}:
            raise Failure("product_status_invalid")
        receipt["api"] = verify_api(args.port, configured_token(home))
        repeated = read_json_bytes(run([str(binary), "--output", "json", "paperless", "install"], timeout=900), "install_json_invalid")
        repeated_project, repeated_configs, repeated_ids, repeated_volume_set_id = validate_install(repeated, args.port)
        if (repeated_project, repeated_configs, repeated_ids, repeated_volume_set_id) != (project, config_ids, identities, volume_set_id) or persisted_volume_set_snapshot(home, project, volume_set_id) != volume_set_snapshot_bytes:
            raise Failure("repeat_install_changed_identities")
        retained_volumes(project, identities[3:], volume_set_id)
        install_receipt_bytes = persisted_install_receipt(home, (project, config_ids, identities, volume_set_id), args.port)
        receipt["repeat_api"] = verify_api(args.port, configured_token(home))
        token = configured_token(home)
        document_id, task_polls = task_document_id(args.port, token, upload_marker(args.port, token))
        baseline_id, baseline_title, baseline_sha256 = marker_metadata(args.port, token, document_id)
        removed = read_json_bytes(run([str(binary), "--output", "json", "paperless", "uninstall"], timeout=900), "uninstall_json_invalid")
        retired_ids = identities[:3]
        volume_names = identities[3:]
        validate_uninstall(removed, project, retired_ids, volume_names, install_receipt_bytes, volume_set_id)
        uninstall_receipt_bytes = persisted_uninstall_receipt(home, removed)
        retained_volumes(project, volume_names, volume_set_id)
        for identifier in retired_ids:
            bounded.prove_absent("container", identifier)
        repeated_uninstall = read_json_bytes(run([str(binary), "--output", "json", "paperless", "uninstall"], timeout=900), "uninstall_json_invalid")
        validate_uninstall(repeated_uninstall, project, retired_ids, volume_names, install_receipt_bytes, volume_set_id)
        if persisted_uninstall_receipt(home, repeated_uninstall) != uninstall_receipt_bytes or persisted_install_receipt(home, (project, config_ids, identities, volume_set_id), args.port) != install_receipt_bytes or persisted_volume_set_snapshot(home, project, volume_set_id) != volume_set_snapshot_bytes:
            raise Failure("repeat_uninstall_mutated_custody")
        retained_volumes(project, volume_names, volume_set_id)
        for identifier in retired_ids:
            bounded.prove_absent("container", identifier)
        reinstalled = read_json_bytes(run([str(binary), "--output", "json", "paperless", "install"], timeout=900), "install_json_invalid")
        reinstall_project, reinstall_configs, reinstall_ids, reinstall_volume_set_id = validate_install(reinstalled, args.port)
        if reinstall_project != project or reinstall_configs != config_ids or reinstall_ids[3:] != volume_names or reinstall_volume_set_id != volume_set_id or set(reinstall_ids[:3]) & set(retired_ids) or persisted_volume_set_snapshot(home, project, volume_set_id) != volume_set_snapshot_bytes:
            raise Failure("reinstall_retained_data_identity_invalid")
        for service, identifier in zip(IMAGES, reinstall_ids[:3], strict=True):
            validate_container(docker_json(identifier), project, service, config_ids[service], args.port)
        retained_volumes(project, volume_names, volume_set_id)
        identities = reinstall_ids
        receipt["reinstall_api"] = verify_api(args.port, configured_token(home))
        survived_id, survived_title, survived_sha256 = marker_metadata(args.port, configured_token(home), document_id)
        receipt["retained_document"] = {
            "document_id_sha256": hashlib.sha256(str(document_id).encode()).hexdigest(),
            "title_sha256": hashlib.sha256(baseline_title.encode()).hexdigest(),
            "baseline_sha256": baseline_sha256,
            "metadata_id_stable": survived_id == baseline_id,
            "metadata_title_stable": survived_title == baseline_title,
            "download_sha256_matches": survived_sha256 == baseline_sha256,
            "task_polls": task_polls,
        }
        if survived_id != baseline_id or survived_title != baseline_title or survived_sha256 != baseline_sha256:
            raise Failure("retained_document_mismatch")
        final_removed = read_json_bytes(run([str(binary), "--output", "json", "paperless", "uninstall"], timeout=900), "uninstall_json_invalid")
        final_ids = identities[:3]
        retired_ids = final_ids
        validate_uninstall(final_removed, project, final_ids, volume_names, install_receipt_bytes, volume_set_id)
        final_uninstall_receipt_bytes = persisted_uninstall_receipt(home, final_removed)
        retained_volumes(project, volume_names, volume_set_id)
        for identifier in final_ids:
            bounded.prove_absent("container", identifier)
        history_before_purge = (
            install_receipt_bytes, final_uninstall_receipt_bytes, volume_set_snapshot_bytes,
            (home / "freedom.yaml").read_bytes(), (home / "credentials.yaml").read_bytes(),
            tuple(json_sha256(docker_json(name, volume=True)) for name in volume_names), purge_artifacts_absent(home),
        )
        preview_raw = run([str(binary), "--output", "json", "paperless", "purge"])
        phrase = validate_purge_preview(read_json_bytes(preview_raw, "purge_preview_invalid"), project, install_receipt_bytes, final_uninstall_receipt_bytes, volume_set_id, volume_names)
        wrong = bounded.run([str(binary), "--output", "json", "paperless", "purge", "--confirm", phrase + " wrong"], timeout=180)
        if wrong.code == 0 or wrong.timed_out or wrong.overflow or b"paperless_purge_confirmation_mismatch" not in wrong.stderr:
            raise Failure("purge_wrong_confirmation_unproven")
        retained_volumes(project, volume_names, volume_set_id)
        if history_before_purge != (
            persisted_install_receipt(home, (project, config_ids, identities, volume_set_id), args.port), persisted_uninstall_receipt(home, final_removed), persisted_volume_set_snapshot(home, project, volume_set_id),
            (home / "freedom.yaml").read_bytes(), (home / "credentials.yaml").read_bytes(),
            tuple(json_sha256(docker_json(name, volume=True)) for name in volume_names), purge_artifacts_absent(home),
        ):
            raise Failure("purge_wrong_confirmation_mutated_history")
        purge_raw = run([str(binary), "--output", "json", "paperless", "purge", "--confirm", phrase], timeout=900)
        purge = read_json_bytes(purge_raw, "purge_receipt_invalid")
        validate_purge_complete(purge, project, install_receipt_bytes, final_uninstall_receipt_bytes, volume_set_id, volume_names)
        purge_custody_bytes = persisted_receipt_bytes(home, ".neoth-paperless-purge-custody.v1.json", "purge_custody_bytes_invalid")
        purge_receipt_bytes = persisted_purge_receipt(home, purge)
        for name in volume_names:
            bounded.prove_absent("volume", name)
        if (persisted_install_receipt(home, (project, config_ids, identities, volume_set_id), args.port), persisted_uninstall_receipt(home, final_removed), persisted_volume_set_snapshot(home, project, volume_set_id), (home / "freedom.yaml").read_bytes(), (home / "credentials.yaml").read_bytes()) != history_before_purge[:5]:
            raise Failure("purge_mutated_persisted_history")
        history_after_purge = history_before_purge[:5] + (purge_custody_bytes, purge_receipt_bytes)
        repeat_purge_raw = run([str(binary), "--output", "json", "paperless", "purge", "--confirm", phrase], timeout=900)
        if repeat_purge_raw != purge_raw:
            raise Failure("purge_repeat_mutation")
        repeat_purge = read_json_bytes(repeat_purge_raw, "purge_receipt_invalid")
        validate_purge_complete(repeat_purge, project, install_receipt_bytes, final_uninstall_receipt_bytes, volume_set_id, volume_names)
        if persisted_purge_receipt(home, repeat_purge) != purge_receipt_bytes:
            raise Failure("purge_repeat_mutation")
        if history_after_purge != (
            persisted_install_receipt(home, (project, config_ids, identities, volume_set_id), args.port), persisted_uninstall_receipt(home, final_removed), persisted_volume_set_snapshot(home, project, volume_set_id),
            (home / "freedom.yaml").read_bytes(), (home / "credentials.yaml").read_bytes(),
            persisted_receipt_bytes(home, ".neoth-paperless-purge-custody.v1.json", "purge_custody_bytes_invalid"), persisted_purge_receipt(home, repeat_purge),
        ):
            raise Failure("purge_repeat_mutation")
        for name in volume_names:
            bounded.prove_absent("volume", name)
        volumes_purged = True
        receipt["purge"] = {"install_receipt_sha256": hashlib.sha256(install_receipt_bytes).hexdigest(), "final_uninstall_receipt_sha256": hashlib.sha256(final_uninstall_receipt_bytes).hexdigest(), "volume_set_id_sha256": hashlib.sha256(volume_set_id.encode()).hexdigest(), "volumes_absent": True, "repeat_read_only": True}
        receipt.update({"project_sha256": hashlib.sha256(project.encode()).hexdigest(), "volume_set_id_sha256": hashlib.sha256(volume_set_id.encode()).hexdigest(), "volume_set_snapshot_sha256": hashlib.sha256(volume_set_snapshot_bytes).hexdigest(), "images": len(config_ids), "containers": 3, "volumes": 6, "repeat_install_preserved_identities": True, "uninstall_repeat_read_only": True, "status_ready": True})
        receipt["outcome"] = "passed"
    except Exception as error:
        receipt["failure_stage"] = str(error) if isinstance(error, Failure) else "unexpected"
        if isinstance(error, CommandFailure):
            receipt["command_failure"] = error.diagnostic
    finally:
        cleaned, cleanup_failure = (False, None)
        if project and config_ids and identities:
            cleaned, cleanup_failure = cleanup(project, config_ids, identities, args.port, retired_ids, volume_set_id, volumes_purged)
        receipt["docker_cleanup_proven"] = cleaned
        if cleanup_failure is not None:
            receipt["cleanup_failure_stage"] = cleanup_failure
        if receipt["outcome"] == "passed" and cleaned:
            try:
                shutil.rmtree(home)
                receipt["isolated_home_removed"] = not home.exists()
            except Exception:
                receipt["isolated_home_removed"] = False
        else:
            receipt["isolated_home_removed"] = False
        receipt["cleanup_proven"] = cleaned and receipt["isolated_home_removed"]
        if not receipt["cleanup_proven"]:
            receipt["outcome"] = "failed"
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        receipt_path.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return 0 if receipt["outcome"] == "passed" else 1


if __name__ == "__main__": sys.exit(main())
