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
import urllib.error
import urllib.request
from pathlib import Path

import n8n_bootstrap_canary as bounded

IMAGES = {
    "webserver": "ghcr.io/paperless-ngx/paperless-ngx@sha256:5fa76604a81df6945086e0837b14b56543d137e8ce4f311cc5d9ebe907e74e79",
    "broker": "registry-1.docker.io/valkey/valkey@sha256:48332870af354a799964c0012ae1194a0bf2bf894eb508f945810596dc2d8d11",
    "db": "registry-1.docker.io/library/postgres@sha256:86c951e05bf56c93d95d397747fb8820ac76cc3bedb78f43abd83eedbe3666ae",
}
VOLUMES = (
    ("paperless_data", "webserver", "/usr/src/paperless/data"),
    ("paperless_media", "webserver", "/usr/src/paperless/media"),
    ("paperless_valkey", "broker", "/data"),
    ("paperless_postgres", "db", "/var/lib/postgresql"),
)
SHA256 = re.compile(r"[0-9a-f]{64}")
IDENTIFIER = re.compile(r"[0-9a-f]{64}")
API_LIMIT = 32 * 1024
CONFIG_LIMIT = 256 * 1024


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
    argv = ["docker", "volume", "inspect", identifier] if volume else ["docker", "container", "inspect", identifier]
    raw = run(argv, timeout=45)
    try:
        value = json.loads(raw)
    except Exception as error:
        raise Failure("docker_inspect_invalid") from error
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise Failure("docker_inspect_invalid")
    return value[0]


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


def validate_volume(row: dict, project: str, logical: str) -> str:
    name = row.get("Name")
    labels = row.get("Labels", {})
    if not isinstance(name, str) or name != f"{project}_{logical}" or labels.get("com.docker.compose.project") != project or labels.get("com.docker.compose.volume") != logical:
        raise Failure("volume_identity_invalid")
    return name


def validate_install(value: dict, port: int) -> tuple[str, dict[str, str], tuple[str, ...]]:
    project = require(value, "project", str)
    if value.get("schema_version") != 1 or value.get("operation") != "install" or value.get("loopback_port") != port or value.get("authenticated_api_ready") is not True:
        raise Failure("install_json_invalid")
    images, containers, volumes = require(value, "images", list), require(value, "containers", list), require(value, "volumes", list)
    if len(images) != 3 or len(containers) != 3 or len(volumes) != 4:
        raise Failure("install_json_shape_invalid")
    config_ids: dict[str, str] = {}
    for item in images:
        if not isinstance(item, dict) or item.get("service") not in IMAGES or item.get("reference") != IMAGES[item["service"]] or not isinstance(item.get("config_id"), str) or not item["config_id"]:
            raise Failure("image_receipt_invalid")
        config_ids[item["service"]] = item["config_id"]
    ids: list[str] = []
    for item in containers:
        if not isinstance(item, dict) or item.get("service") not in config_ids or not isinstance(item.get("id"), str) or not IDENTIFIER.fullmatch(item["id"]) or item.get("image_id") != config_ids[item["service"]]:
            raise Failure("container_receipt_invalid")
        ids.append(item["id"])
    names = []
    for item in volumes:
        if not isinstance(item, dict) or item.get("logical_name") not in {x[0] for x in VOLUMES} or item.get("project") != project or not isinstance(item.get("name"), str):
            raise Failure("volume_receipt_invalid")
        names.append(item["name"])
    if len(set(ids)) != 3 or len(set(names)) != 4 or len(config_ids) != 3:
        raise Failure("lifecycle_identity_duplicate")
    return project, config_ids, tuple(ids + names)


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


def paperless_api_json(port: int, token: str | None, path: str, expected: set[int]) -> dict:
    headers = {"Authorization": f"Token {token}"} if token is not None else {}
    request = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=headers)
    try:
        with api_opener().open(request, timeout=20) as response:
            status = response.status
            raw = response.read(API_LIMIT + 1)
    except urllib.error.HTTPError as error:
        status, raw = error.code, error.read(API_LIMIT + 1)
    except Exception as error:
        raise Failure("paperless_api_transport") from error
    if status in range(300, 400):
        raise Failure("paperless_api_redirect")
    if status not in expected:
        raise Failure("paperless_api_status_invalid")
    if len(raw) > API_LIMIT:
        raise Failure("paperless_api_response_too_large")
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


def cleanup(project: str, config_ids: dict[str, str], identities: tuple[str, ...], port: int) -> tuple[bool, str | None]:
    container_ids, volume_names = identities[:3], identities[3:]
    try:
        for service, identifier in zip(IMAGES, container_ids, strict=True):
            validate_container(docker_json(identifier), project, service, config_ids[service], port)
        for (logical, _, _), name in zip(VOLUMES, volume_names, strict=True):
            if validate_volume(docker_json(name, volume=True), project, logical) != name:
                raise Failure("volume_identity_invalid")
        for identifier in container_ids:
            run(["docker", "rm", "-f", identifier], timeout=45)
            bounded.prove_absent("container", identifier)
        for name in volume_names:
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
    project = None; config_ids: dict[str, str] | None = None; identities: tuple[str, ...] | None = None
    try:
        hosted_paths(home, receipt_path)
        if not 1 <= args.port <= 65535 or not binary.is_file():
            raise Failure("arguments_invalid")
        receipt.update({"helper_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "bounded_helper_sha256": hashlib.sha256(Path(bounded.__file__).read_bytes()).hexdigest(), "workflow_sha256": hashlib.sha256((Path.cwd() / ".github/workflows/paperless-product.yml").read_bytes()).hexdigest(), "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(), "input_sha256": source_hashes()})
        initialize_home(binary, home)
        prepared = read_json_bytes(run([str(binary), "--output", "json", "paperless", "prepare"]), "prepare_json_invalid"); validate_prepare(prepared)
        write_env_fixture(home / "paperless", args.port)
        first = read_json_bytes(run([str(binary), "--output", "json", "paperless", "install"], timeout=900), "install_json_invalid")
        project, reported_configs, identities = validate_install(first, args.port)
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
            validate_volume(docker_json(name, volume=True), project, logical)
        status = read_json_bytes(run([str(binary), "--output", "json", "paperless", "status"]), "status_json_invalid")
        if status.get("status") != "authenticated_api_ready" or status.get("authenticated_api_ready") is not True or status.get("staging") not in {"prepared_pinned", "already_prepared"}:
            raise Failure("product_status_invalid")
        receipt["api"] = verify_api(args.port, configured_token(home))
        second = read_json_bytes(run([str(binary), "--output", "json", "paperless", "install"], timeout=900), "install_json_invalid")
        second_project, second_configs, second_ids = validate_install(second, args.port)
        if (second_project, second_configs, second_ids) != (project, config_ids, identities):
            raise Failure("repeat_install_changed_identities")
        receipt["repeat_api"] = verify_api(args.port, configured_token(home))
        receipt.update({"project_sha256": hashlib.sha256(project.encode()).hexdigest(), "images": len(config_ids), "containers": 3, "volumes": 4, "repeat_install_preserved_identities": True, "status_ready": True})
        receipt["outcome"] = "passed"
    except Exception as error:
        receipt["failure_stage"] = str(error) if isinstance(error, Failure) else "unexpected"
        if isinstance(error, CommandFailure):
            receipt["command_failure"] = error.diagnostic
    finally:
        cleaned, cleanup_failure = (False, None)
        if project and config_ids and identities:
            cleaned, cleanup_failure = cleanup(project, config_ids, identities, args.port)
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
