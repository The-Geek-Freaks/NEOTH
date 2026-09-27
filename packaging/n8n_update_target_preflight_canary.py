#!/usr/bin/env python3
"""Hosted-only compiled CLI proof for the fixed n8n update target."""
from __future__ import annotations
import argparse, hashlib, json, os, signal, subprocess, sys, tempfile, threading
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

VERSION = "2.40.7"
SELECTOR = "n8n-2.40.7"
PLATFORM = "linux/amd64"
INDEX_DIGEST = "sha256:ffeb52485f78b1b06c9a832205853cf75da72a07a514c9a27724df85979d6c34"
CHILD_MANIFEST_DIGEST = "sha256:599d68c7b6fb18b5ac1e7cd013a2e72c886ec1c807b9d436d56e90da32c664ac"
CATALOG_EVIDENCE_SHA256 = "a3c804dbdb2cc45cb0fdaa6a40be49522dc7811123c46eec51883032ad60fb02"
RUNTIME_IMAGE = f"docker.io/n8nio/n8n@{INDEX_DIGEST}"
MAX_OUTPUT, CLI_TIMEOUT, DOCKER_TIMEOUT, DRAIN_TIMEOUT = 32 * 1024, 400, 120, 5

class Failure(RuntimeError): pass
@dataclass
class Result:
    code: int; stdout: bytes; stderr: bytes; timed_out: bool; overflow: bool

def drain(stream, target: bytearray, overflow: list[bool]) -> None:
    while chunk := stream.read(4096):
        remaining = MAX_OUTPUT - len(target)
        if remaining > 0: target.extend(chunk[:remaining])
        if len(chunk) > remaining: overflow[0] = True

def run(argv: Sequence[str], timeout: int, env: Mapping[str, str] | None = None) -> Result:
    try:
        child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, start_new_session=os.name != "nt")
    except OSError:
        return Result(127, b"", b"", False, False)
    out, err, overflow = bytearray(), bytearray(), [False]
    threads = [threading.Thread(target=drain, args=(stream, target, overflow), daemon=True) for stream, target in ((child.stdout, out), (child.stderr, err))]
    for thread in threads: thread.start()
    timed_out = False
    try: code = child.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        if os.name != "nt":
            try: os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError: pass
        else: child.kill()
        code = child.wait()
    for thread in threads:
        thread.join(DRAIN_TIMEOUT)
        if thread.is_alive(): overflow[0] = True
    return Result(code, bytes(out), bytes(err), timed_out, overflow[0])

def safe_failure(result: Result) -> dict:
    return {"exit_code": result.code, "timed_out": result.timed_out, "overflow": result.overflow, "stdout_bytes": len(result.stdout), "stderr_bytes": len(result.stderr)}

def require_success(argv: Sequence[str], timeout: int) -> bytes:
    result = run(argv, timeout)
    if result.code != 0 or result.timed_out or result.overflow: raise Failure("command_failed")
    return result.stdout

def parse_json(raw: bytes, label: str) -> dict:
    try: value = json.loads(raw)
    except Exception as error: raise Failure(label + "_json_invalid") from error
    if not isinstance(value, dict): raise Failure(label + "_shape_invalid")
    return value

def require_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or len(value) != 71 or not value.startswith("sha256:"): raise Failure(label)
    try: int(value[7:], 16)
    except ValueError as error: raise Failure(label) from error
    return value

def validate_target(value: dict) -> dict:
    expected = {"selector", "version", "platform", "runtime_image", "index_digest", "child_manifest_digest", "config_digest", "catalog_evidence_sha256"}
    if set(value) != expected or value.get("selector") != SELECTOR or value.get("version") != VERSION or value.get("platform") != PLATFORM: raise Failure("target_projection_invalid")
    if value.get("runtime_image") != RUNTIME_IMAGE or value.get("index_digest") != INDEX_DIGEST or value.get("child_manifest_digest") != CHILD_MANIFEST_DIGEST or value.get("catalog_evidence_sha256") != CATALOG_EVIDENCE_SHA256: raise Failure("target_catalog_chain_invalid")
    require_digest(value.get("config_digest"), "target_config_digest_invalid")
    return value

def inventory(kind: str) -> dict:
    argv = ("docker", "container", "ls", "-aq", "--no-trunc") if kind == "containers" else ("docker", "volume", "ls", "-q")
    raw = require_success(argv, DOCKER_TIMEOUT)
    rows = tuple(sorted(row for row in raw.decode("utf-8", "strict").splitlines() if row))
    return {"count": len(rows), "sha256": hashlib.sha256(("\n".join(rows) + "\n").encode()).hexdigest()}

def require_empty_home(home: Path) -> dict:
    if not home.is_dir() or home.is_symlink(): raise Failure("isolated_home_invalid")
    if tuple(home.iterdir()): raise Failure("isolated_home_not_empty")
    return {"count": 0, "sha256": hashlib.sha256(b"").hexdigest()}

def write_docker_deny_shim(directory: Path) -> Path:
    log, shim = directory / "docker-invocations", directory / "docker"
    shim.write_text("#!/bin/sh\nprintf x >> \"$W1592_DOCKER_SHIM_LOG\"\nexit 97\n", encoding="utf-8")
    shim.chmod(0o700)
    return log

def verify_negative_controls(binary: Path, directory: Path) -> dict:
    log = write_docker_deny_shim(directory)
    environment = dict(os.environ); environment["PATH"] = str(directory) + os.pathsep + environment.get("PATH", ""); environment["W1592_DOCKER_SHIM_LOG"] = str(log)
    base = [str(binary), "--output", "json", "n8n", "update-target", "verify"]
    controls = (("unknown_selector", [*base, "--target", "n8n-0.0.0", "--platform", PLATFORM], b"n8n_update_target_selector_not_admitted"), ("unsupported_platform", [*base, "--target", SELECTOR, "--platform", "windows/amd64"], b"invalid value"))
    evidence = {}
    for name, argv, marker in controls:
        result = run(argv, CLI_TIMEOUT, environment)
        if result.code == 0 or result.timed_out or result.overflow or marker not in result.stderr or log.exists(): raise Failure("negative_control_unproven")
        evidence[name] = {**safe_failure(result), "expected_error": name, "docker_invocations": 0}
    return evidence

def verify_docker_image(runtime_image: str, config_digest: str) -> dict:
    raw = require_success(("docker", "image", "inspect", runtime_image), DOCKER_TIMEOUT)
    try: rows = json.loads(raw)
    except Exception as error: raise Failure("docker_inspect_json_invalid") from error
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict): raise Failure("docker_inspect_shape_invalid")
    row, repo_digests = rows[0], rows[0].get("RepoDigests")
    normalized = runtime_image.removeprefix("docker.io/")
    aliases = {runtime_image, normalized, "index.docker.io/" + normalized}
    if row.get("Id") != config_digest or row.get("Os") != "linux" or row.get("Architecture") != "amd64" or not isinstance(repo_digests, list) or not aliases.intersection(repo_digests): raise Failure("docker_image_chain_invalid")
    return {"id": config_digest, "repo_digest_bound": True, "platform": PLATFORM}

def input_hashes() -> dict:
    names = ("SRC/neothd/src/cli/n8n.rs", "SRC/neothd/src/installers/n8n.rs", "SRC/neothd/src/integrations/n8n.rs", "SRC/neothd/src/integrations/n8n/managed_update_target.rs", "SRC/neothd/src/integrations/n8n/managed_update_target_tests.rs", "docs/verification/gold-wave1587-update-target-metadata-accepted.json", "packaging/n8n_update_target_preflight_canary.py", "packaging/tests/test_n8n_update_target_preflight_canary.py", ".github/workflows/n8n-update-target-preflight.yml")
    return {name: hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in names}

def write_receipt(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True); path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")

def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--binary", required=True, type=Path); parser.add_argument("--home", required=True, type=Path); parser.add_argument("--receipt", required=True, type=Path); args = parser.parse_args(argv)
    receipt = {"schema": 1, "source_sha": os.environ.get("GITHUB_SHA"), "scenario": "n8n_update_target_preflight", "outcome": "failed"}
    try:
        if not args.binary.is_file() or args.binary.is_symlink(): raise Failure("binary_invalid")
        if Path(os.environ.get("NEOTH_HOME", "")).resolve() != args.home.resolve(): raise Failure("isolated_home_environment_mismatch")
        receipt["input_sha256"] = input_hashes(); receipt["binary_sha256"] = hashlib.sha256(args.binary.read_bytes()).hexdigest()
        before = {"containers": inventory("containers"), "volumes": inventory("volumes"), "home": require_empty_home(args.home)}
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="w1592-negative-", dir=args.receipt.parent) as temporary: receipt["negative_controls"] = verify_negative_controls(args.binary, Path(temporary))
        raw = require_success((str(args.binary), "--output", "json", "n8n", "update-target", "verify", "--target", SELECTOR, "--platform", PLATFORM), CLI_TIMEOUT)
        target = validate_target(parse_json(raw, "target")); receipt["docker_image"] = verify_docker_image(target["runtime_image"], target["config_digest"])
        after = {"containers": inventory("containers"), "volumes": inventory("volumes"), "home": require_empty_home(args.home)}
        if after != before: raise Failure("preflight_mutated_fixture")
        receipt.update({"selector": SELECTOR, "version": VERSION, "platform": PLATFORM, "runtime_image": target["runtime_image"], "index_digest": INDEX_DIGEST, "child_manifest_digest": CHILD_MANIFEST_DIGEST, "config_digest": target["config_digest"], "catalog_evidence_sha256": CATALOG_EVIDENCE_SHA256, "inventories": before, "outcome": "passed"})
    except Exception as error: receipt["failure_stage"] = str(error) if isinstance(error, Failure) else "unexpected"
    write_receipt(args.receipt, receipt)
    return 0 if receipt["outcome"] == "passed" else 1

if __name__ == "__main__": raise SystemExit(main(sys.argv[1:]))
