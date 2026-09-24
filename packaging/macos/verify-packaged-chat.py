#!/usr/bin/env python3
"""Run the real macOS app chat probe and verify process exit outside the app."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys


def process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def verify(app: Path, evidence: Path, source: str) -> None:
    if sys.platform != "darwin":
        raise RuntimeError("packaged chat acceptance requires macOS")
    app = app.resolve(strict=True)
    if app.suffix != ".app":
        raise ValueError("expected a native .app bundle")
    evidence.mkdir(parents=True, exist_ok=False)
    receipt_path = evidence / "probe.json"
    binary_root = app / "Contents" / "MacOS"
    binaries = {}
    for name in ("neoth", "neothd", "neothd-gui"):
        path = binary_root / name
        if path.is_symlink() or not path.is_file():
            raise RuntimeError(f"missing regular bundled binary: {name}")
        binaries[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    env = {key: value for key, value in os.environ.items() if not key.startswith("NEOTH_")}
    env["NEOTH_PRODUCT_LAUNCHER"] = "1"
    with (evidence / "stdout.log").open("wb") as stdout, (evidence / "stderr.log").open("wb") as stderr:
        child = subprocess.Popen(
            [str(binary_root / "neothd-gui"), "--packaged-chat-acceptance", str(receipt_path)],
            cwd=app,
            env=env,
            stdout=stdout,
            stderr=stderr,
            start_new_session=True,
        )
        try:
            exit_code = child.wait(timeout=90)
        except subprocess.TimeoutExpired:
            # This process group was created by this invocation; never signal
            # an arbitrary PID from a product-generated receipt.
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=5)
            raise RuntimeError("packaged chat probe exceeded its outer deadline") from None
    if exit_code != 0:
        raise RuntimeError(f"packaged chat probe exited {exit_code}")
    if receipt_path.is_symlink() or not receipt_path.is_file() or receipt_path.stat().st_size > 65536:
        raise RuntimeError("missing or oversized package probe receipt")
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    if receipt.get("schema") != "neoth-packaged-chat-probe/v1" or receipt.get("result") != "passed":
        raise RuntimeError("package probe did not report its verified terminal")
    required_checks = (
        "same_turn_reopen", "cursor_monotonic", "provider_failure_terminal",
        "cancellation_terminal", "main_buddy_parity", "deduplicated_visible_completion",
    )
    checks = receipt.get("checks")
    if not isinstance(checks, dict) or any(checks.get(name) is not True for name in required_checks):
        raise RuntimeError("package probe is missing a required behavioral assertion")
    if type(receipt.get("provider_requests")) is not int or receipt["provider_requests"] != 3:
        raise RuntimeError("expected exactly three distinct provider turns")
    if receipt.get("gui_pid") != child.pid:
        raise RuntimeError("probe receipt is not bound to the launched GUI")
    daemon_pid = receipt.get("daemon_pid")
    if type(daemon_pid) is not int or daemon_pid <= 1 or daemon_pid == child.pid:
        raise RuntimeError("invalid bundled daemon process identity")
    if receipt.get("daemon_exit_success") is not True or receipt.get("home_removed") is not True:
        raise RuntimeError("probe did not cleanly drain its daemon and isolated home")
    if process_exists(child.pid) or process_exists(daemon_pid):
        raise RuntimeError("packaged GUI or daemon remains alive after successful exit")
    processes = subprocess.check_output(["/bin/ps", "-axo", "pid=,comm="], text=True, timeout=5)
    survivors = [line.strip() for line in processes.splitlines() if str(binary_root) in line]
    if survivors:
        raise RuntimeError("a process from the isolated app bundle remains alive")
    result = {
        "schema": "neoth-packaged-chat-external-admission/v1",
        "source": source,
        "result": "passed",
        "gui_pid": child.pid,
        "daemon_pid": daemon_pid,
        "gui_exit_code": exit_code,
        "no_package_process_survived": True,
        "binary_sha256": binaries,
        "probe_sha256": hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
        "developer_id_release_qualification": False,
    }
    (evidence / "external-admission.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print("Packaged chat probe and external no-orphan check passed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--source", required=True)
    args = parser.parse_args()
    try:
        verify(args.app, args.evidence.resolve(), args.source)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"packaged chat acceptance failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
