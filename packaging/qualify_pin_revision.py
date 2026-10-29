#!/usr/bin/env python3
"""Hosted-only behavior evidence for a Root-reviewed exact pin solver candidate."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import subprocess
import time

import candle_zip_migration as gate

ROOT = Path(__file__).resolve().parents[1]
LIMIT = 10 * 1024 * 1024
GROUPS = {"candle": 3, "document": None, "browser": 3, "updater": 1, "ssh": None}
AUTHORITY = (
    "config::credentials::tests::unavailable_keychain_aborts_legacy_ssh_migration_without_writing",
    "config::credentials::tests::keychain_ssh_authority_wins_without_leaking_into_credentials_file",
    "config::credentials::tests::keychain_empty_ssh_authority_disables_legacy_without_file_copy",
    "config::keychain::tests::ssh_tunnel_bundle_round_trips_through_every_keychain_path",
    "config::keychain::tests::file_empty_ssh_authority_wins_over_keychain_bundle",
    "config::keychain::tests::corrupt_keychain_ssh_bundle_fails_closed",
    "config::keychain::tests::ssh_bundle_set_failure_rolls_back_prior_scalar_overwrite",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path: Path) -> dict:
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= LIMIT,
            f"missing, linked or oversized evidence: {path.name}")
    return json.loads(path.read_bytes())


def save(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def context() -> dict:
    return {key: os.environ[env] for key, env in (
        ("producer", "GITHUB_SHA"), ("run", "GITHUB_RUN_ID"), ("attempt", "GITHUB_RUN_ATTEMPT"),
    )}


def verify_admitted(proof: Path) -> dict:
    result = load(proof / "receipt.json")
    require(all(result.get(k) == v for k, v in context().items()), "solver context changed")
    require(result.get("status") == "ROOT_REVIEW_REQUIRED" and result.get("solverExecuted") is True,
            "successful solver receipt missing")
    for env, name in (("ADMITTED_LOCK_SHA256", "candidate-Cargo.lock"),
                      ("ADMITTED_DELTA_SHA256", "solver-delta.json")):
        expected = os.environ.get(env, "")
        require(re.fullmatch(r"[0-9a-f]{64}", expected) is not None, "Root admission hash missing")
        require(sha(proof / name) == expected, f"candidate differs from Root admission: {name}")
    require(sha(ROOT / "SRC/Cargo.lock") == result["lockSha256"]
            == os.environ["ADMITTED_LOCK_SHA256"], "working lock differs")
    gate.verify_source(gate.bindings(), gate.upstream_files(), require_revision=True)
    return result


def tracked_inputs() -> list[str]:
    paths = subprocess.check_output(
        ["git", "ls-files", "-z", "--", "SRC"], cwd=ROOT
    ).decode().split("\0")
    paths = set(filter(None, paths))
    paths.update((
        ".github/workflows/candle-pin-revision.yml",
        "packaging/qualify_pin_revision.py",
        "packaging/candle_zip_migration.py",
        "packaging/candle_pin_revision.py",
        "packaging/generate_rust_notices.py",
        "packaging/rust-license-snapshots.json",
        "packaging/vendor-provenance/candle-core-0.8.4-pin-revision.json",
    ))
    for relative in paths:
        path = ROOT / relative
        require(path.is_file() and not path.is_symlink(), "nonregular qualification input")
    return sorted(paths)


def run_bounded(proof: Path, name: str, command: list[str], *, cwd: Path, timeout: int) -> int:
    """Retain bounded original streams and reap the owned process group on failure."""
    print(f"Running {name}: {' '.join(command)}", flush=True)
    process = subprocess.Popen(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True)
    deadline = time.monotonic() + timeout
    selector = selectors.DefaultSelector()
    streams = []
    completed = False
    try:
        for stream, suffix in ((process.stdout, ".log"), (process.stderr, ".stderr.log")):
            output = (proof / (name + suffix)).open("wb")
            streams.append(output)
            selector.register(stream, selectors.EVENT_READ, [output, 0])
        while selector.get_map():
            require(time.monotonic() < deadline, f"command timed out: {name}")
            for key, _ in selector.select(timeout=1):
                data = os.read(key.fileobj.fileno(), 65536)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                output, size = key.data
                require(size + len(data) <= LIMIT, f"command stream exceeds bound: {name}")
                output.write(data)
                key.data[1] += len(data)
        code = process.wait(timeout=max(1, deadline - time.monotonic()))
        completed = True
        return code
    finally:
        if not completed:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=15)
        selector.close()
        for output in streams:
            output.close()
        for stream in (process.stdout, process.stderr):
            if stream:
                stream.close()


def selection() -> list[dict]:
    groups = [
        ("candle", ["--test", "candle_zip_compat"], 3, None),
        ("document", ["--lib", "media::document::tests::"], None, None),
        ("browser", ["--lib", "tools::managed_browser::tests::controlled_zip_fixture"], 3, None),
        ("updater", ["--lib", "updater::self_update::tests::zip_extractor_rejects_wrong_root_duplicates_and_links"], 1,
         "updater::self_update::tests::zip_extractor_rejects_wrong_root_duplicates_and_links"),
        ("ssh", ["--lib", "--features", "ssh-tunnel", "transport::ssh_"], None, None),
    ]
    groups.extend((f"authority-{i}", ["--lib", "--features", "ssh-tunnel", name], 1, name)
                  for i, name in enumerate(AUTHORITY, 1))
    return [{"name": name, "args": args, "expectedCount": count, "exact": exact}
            for name, args, count, exact in groups]


def exercise(proof: Path) -> None:
    verify_admitted(proof)
    for package in ("zip@9.0.5", "russh@0.64.1"):
        require(run_bounded(proof, package.split("@")[0] + "-features",
                            ["cargo", "+1.91.0", "tree", "-p", "neoth", "--locked",
                             "--features", "ssh-tunnel", "-e", "features", "-i", package],
                            cwd=ROOT / "SRC", timeout=180) == 0, "feature evidence failed")
    for group in selection():
        command = ["cargo", "+1.91.0", "test", "-p", "neoth", "--locked", *group["args"], "--"]
        exact = ["--exact"] if group["exact"] else []
        for suffix, flags, timeout in (
            ("discovery", [*exact, "--list", "--color", "never"], 3600),
            ("tests", [*exact, "--test-threads=1", "--color", "never"], 600),
        ):
            require(run_bounded(proof, f"{group['name']}-{suffix}", command + flags,
                                cwd=ROOT / "SRC", timeout=timeout) == 0,
                    f"test command failed: {group['name']} {suffix}")
        test_cases(proof, group["name"], group["expectedCount"], group["exact"])


def notices(proof: Path) -> None:
    verify_admitted(proof)
    for mode in ("write", "check"):
        require(run_bounded(proof, "notices-" + mode,
                            ["python", "packaging/generate_rust_notices.py", "--" + mode],
                            cwd=ROOT, timeout=900) == 0, f"notices {mode} failed")


def prepare(proof: Path) -> None:
    solver = verify_admitted(proof)
    inputs = {p: sha(ROOT / p) for p in tracked_inputs()}
    save(proof / "behavior-prepared.json", {
        **context(), "schema": "neoth.pin-behavior-inputs.v1",
        "admittedLockSha256": solver["lockSha256"],
        "admittedDeltaSha256": os.environ["ADMITTED_DELTA_SHA256"],
        "solverReceiptSha256": sha(proof / "receipt.json"), "inputs": inputs,
        "target": "x86_64-unknown-linux-gnu", "toolchain": "1.91.0",
        "groups": GROUPS, "authorityCases": list(AUTHORITY), "selection": selection(),
        "sshProfile": "source opt-in ssh-tunnel, dependency ring; not a stock release capability",
        "pinsImported": False, "goldAccepted": False,
    })
    (proof / "authority-cases.txt").write_text("\n".join(AUTHORITY) + "\n")


def audit(proof: Path) -> None:
    verify_admitted(proof)
    exit_code = run_bounded(proof, "audit", ["cargo", "audit", "--json"],
                            cwd=ROOT / "SRC", timeout=600)
    data = load(proof / "audit.log")
    database = data["database"]
    updated = datetime.datetime.fromisoformat(database["last-updated"])
    now = datetime.datetime.now(datetime.timezone.utc)
    require(updated.utcoffset() is not None
            and re.fullmatch(r"[0-9a-f]{40}", database["last-commit"]) is not None,
            "audit database provenance missing")
    require(-300 <= (now - updated).total_seconds() <= 14 * 86400,
            "audit database freshness bound exceeded")
    findings = data["vulnerabilities"]["list"]
    save(proof / "audit-assessment.json", {
        **context(), "exitCode": exit_code, "database": database,
        "vulnerabilities": data["vulnerabilities"], "warnings": data["warnings"],
        "settings": data["settings"], "fullSecurityAccepted": False,
    })
    require(not any(f["package"]["name"] in ("zip", "russh") for f in findings),
            "target package vulnerability remains")
    require(exit_code == 0 and not findings, "existing audit policy is not passing")
    prepared = load(proof / "behavior-prepared.json")
    for path in ("SRC/.cargo/audit.toml", "SRC/deny.toml"):
        require(sha(ROOT / path) == prepared["inputs"][path], "audit policy changed")


def test_cases(proof: Path, name: str, count: int | None, exact: str | None = None) -> dict:
    texts = []
    for suffix in ("discovery", "tests"):
        path = proof / f"{name}-{suffix}.log"
        require(path.is_file() and path.stat().st_size <= LIMIT, f"missing/big {name} log")
        texts.append(path.read_text())
    discovered = re.findall(r"^([A-Za-z0-9_:]+): test$", texts[0], re.M)
    passed = re.findall(r"^test ([A-Za-z0-9_:]+) \.\.\. ok$", texts[1], re.M)
    terminals = re.findall(
        r"^test result: ok\. (\d+) passed; 0 failed; 0 ignored; 0 measured; \d+ filtered out;",
        texts[1], re.M,
    )
    require(discovered and len(set(discovered)) == len(discovered), f"empty/duplicate discovery: {name}")
    require(len(terminals) == 1 and int(terminals[0]) == len(discovered)
            and sorted(passed) == sorted(discovered), f"incomplete executed case set: {name}")
    require(count is None or len(discovered) == count, f"unexpected case count: {name}")
    require(exact is None or discovered == [exact], f"exact authority case changed: {name}")
    return {"count": len(discovered), "cases": sorted(discovered)}


def finish(proof: Path) -> None:
    verify_admitted(proof)
    prepared = load(proof / "behavior-prepared.json")
    require(all(prepared[k] == v for k, v in context().items()), "behavior context changed")
    require(prepared["solverReceiptSha256"] == sha(proof / "receipt.json"),
            "solver receipt changed during qualification")
    require(set(prepared["inputs"]) == set(tracked_inputs()), "qualification source scope changed")
    require(prepared["selection"] == selection(), "test selection changed")
    for path, expected in prepared["inputs"].items():
        require(sha(ROOT / path) == expected, f"qualification source changed: {path}")
    cases = {name: test_cases(proof, name, count) for name, count in GROUPS.items()}
    for number, identity in enumerate(AUTHORITY, 1):
        cases[f"authority-{number}"] = test_cases(proof, f"authority-{number}", 1, identity)
    assessment = load(proof / "audit-assessment.json")
    require(assessment["exitCode"] == 0 and not assessment["vulnerabilities"]["list"],
            "passing fresh audit missing")
    expected = {"SRC/Cargo.lock", "SRC/neothd/Cargo.toml",
                "SRC/vendor/candle-core/Cargo.toml", "SRC/vendor/candle-core/Cargo.toml.orig"}
    changed = set(subprocess.check_output(
        ["git", "diff", "HEAD", "--name-only"], cwd=ROOT
    ).decode().splitlines())
    require(expected <= changed <= expected | {"THIRD_PARTY_LICENSES"}, "qualification source escape")
    untracked = set(filter(None, subprocess.check_output(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"], cwd=ROOT
    ).decode().split("\0")))
    require(untracked == {"packaging/vendor-provenance/candle-core-0.8.4-pin-revision.json"},
            "unexpected untracked qualification source")
    shutil.copyfile(ROOT / "THIRD_PARTY_LICENSES", proof / "THIRD_PARTY_LICENSES")
    save(proof / "behavior-receipt.json", {
        **context(), "schema": "neoth.pin-behavior-qualification.v1",
        "status": "LINUX_BEHAVIOR_ROOT_REVIEW_REQUIRED",
        "inputReceiptSha256": sha(proof / "behavior-prepared.json"),
        "candidateLockSha256": sha(ROOT / "SRC/Cargo.lock"),
        "solverDeltaSha256": sha(proof / "solver-delta.json"), "groups": cases,
        "selection": selection(), "sshProfile": prepared["sshProfile"],
        "passedCases": sum(group["count"] for group in cases.values()),
        "auditDatabase": assessment["database"], "auditPassed": True,
        "noticesSha256": sha(proof / "THIRD_PARTY_LICENSES"),
        "windowsAccepted": False, "macosAccepted": False,
        "pinsImported": False, "goldAccepted": False,
    })


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "audit", "notices", "exercise", "finish"))
    args = parser.parse_args()
    proof = Path(os.environ["PROOF"])
    {"prepare": prepare, "audit": audit, "notices": notices,
     "exercise": exercise, "finish": finish}[args.mode](proof)


if __name__ == "__main__":
    main()
