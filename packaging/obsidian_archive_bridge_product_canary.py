#!/usr/bin/env python3
"""Hosted product acceptance for the bundled Obsidian Archive Bridge.

The Node helper is a narrow host adapter that loads the installed, compiled
``main.js``.  It does not represent an Obsidian desktop/UI acceptance: it
only provides the API calls the plugin uses to enumerate and read a disposable
vault and records the bundle's real same-user IPC responses.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import signal
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

SHA256 = re.compile(r"[0-9a-f]{64}")
LIMIT = 256 * 1024

class Failure(RuntimeError): pass

def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def require_hosted(root: Path, home: Path, vault: Path, receipt: Path) -> None:
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("GITHUB_REF") != "refs/heads/main": raise Failure("hosted_guard_failed")
    if not re.fullmatch(r"[0-9a-f]{40}", os.environ.get("GITHUB_SHA", "")): raise Failure("hosted_guard_failed")
    if not root.is_dir() or root.is_symlink() or root.parent.resolve() != Path(os.environ.get("RUNNER_TEMP", "")).resolve() or any(root.iterdir()): raise Failure("isolated_root_invalid")
    if home.resolve() != root.resolve() / "neoth-home" or vault.resolve() != root.resolve() / "vault" or receipt.resolve().parent != root.resolve() / "receipt" or receipt.name != "receipt.json": raise Failure("isolated_path_invalid")
    # The paired Unix implementation appends exactly this 32-hex UUID suffix
    # and rejects encoded socket paths at 100 bytes.  Check the prospective
    # path before init so a workflow-root change cannot defer this failure to
    # the later paired start.  The hosted product lane runs on Linux.
    prospective_socket = home / ("obsidian-bridge-" + "0" * 32 + ".sock")
    if len(os.fsencode(prospective_socket)) >= 100: raise Failure("bridge_socket_path_too_long")

def run(argv: list[str], env: dict[str, str], timeout: int = 45) -> bytes:
    try:
        completed = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as error: raise Failure("command_unavailable") from error
    if completed.returncode != 0 or len(completed.stdout) > LIMIT or len(completed.stderr) > LIMIT: raise Failure("command_failed")
    return completed.stdout

def json_command(argv: list[str], env: dict[str, str]) -> dict:
    try: value = json.loads(run(argv, env))
    except Exception as error: raise Failure("cli_json_invalid") from error
    if not isinstance(value, dict): raise Failure("cli_json_invalid")
    return value

def write_bridge_config(home: Path, vault: Path) -> None:
    # FreedomConfig derives defaults, so this is the smallest complete daemon
    # configuration.  It admits exactly the accountless local Obsidian source.
    policy = {"revision": 1, "consent": "explicitly_granted", "retention": "encrypted_evidence", "egress": "local_only", "agent_authority": "denied", "side_effects": "forbidden", "limits": {"max_items_per_run": 1000, "max_bytes_per_item": 16777216, "max_total_bytes_per_run": 134217728, "max_runtime_seconds": 300}}
    value = {"operator_id": "archive-bridge-canary", "onboarding_complete": True, "obsidian_vault": str(vault), "obsidian_vault_reader_enabled": True, "obsidian_archive_bridge_enabled": True, "context_connectors": {"schema_version": 1, "enabled": True, "registered_accounts": [{"configuration": {"connector_id": "obsidian", "account_id": None, "subject_id": "archive-bridge-canary", "credential_ref": None, "policy": policy}, "lifecycle": "active", "lifecycle_revision": 1}]}}
    # JSON is valid YAML; avoid a parser dependency in the acceptance helper.
    (home / "freedom.yaml").write_text(json.dumps(value), encoding="utf-8")

def provision_disposable_master_key(binary: Path, home: Path, env: dict[str, str], root: Path, state: dict) -> Path:
    """Install a fresh hosted-fixture key through the public recovery command.

    `serve` intentionally has a load-only bridge-owner path. The product
    fixture therefore creates no `wal/master.key` itself: it supplies a
    disposable raw 32-byte recovery input to the existing `security
    restore-master-key` CLI, which validates and binds that key for this
    isolated runner user. The raw input is never recorded in the receipt and
    is removed by cleanup.
    """
    seed = root / "bridge-canary-master-key.raw"
    if seed.exists() or seed.is_symlink() or seed.parent.resolve() != root.resolve():
        raise Failure("master_key_seed_target_invalid")
    try:
        raw = secrets.token_bytes(32)
        if len(raw) != 32: raise Failure("master_key_seed_invalid")
        descriptor = os.open(seed, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        # Register as soon as the exclusive file exists. This also retains
        # cleanup custody for a partial write failure.
        state["master_key_seed"] = seed
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
    except OSError as error:
        raise Failure("master_key_seed_write_failed") from error
    # It is already registered before the external CLI invocation, so a
    # rejected restore also has explicit seed cleanup custody.
    try:
        run(
            [str(binary), "security", "restore-master-key", "--source", str(seed), "--home", str(home)],
            env,
        )
    except Failure as error:
        raise Failure("master_key_restore_failed") from error
    return seed

def redacted_daemon_diagnostic(reason: str, returncode: int | None, raw: bytes) -> dict:
    if reason not in {"daemon_exited_early", "daemon_not_ready"}: raise Failure("daemon_diagnostic_reason_invalid")
    bounded = raw[:LIMIT]
    # These literals are stable source-owned error contexts.  They turn a
    # failed hosted start into a closed diagnostic category without retaining
    # the surrounding error text, which can contain local paths or secrets.
    signatures = (
        (b"GOLD-ADAPT-OH-03: onboarding incomplete", "onboarding_incomplete"),
        (b"mode 0o700 required", "home_permissions_rejected"),
        (b"missing field", "configuration_missing_field"),
        (b"runtime config pair at", "runtime_config_pair_rejected"),
        (b"operator hooks at", "startup_hooks_rejected"),
        (b"establish instance WAL HMAC authority before recovery scan", "wal_authority_rejected"),
        (b"write BOOT WAL frame", "boot_wal_write_failed"),
        (b"persist instance clock floor", "clock_floor_persist_failed"),
        (b"open daemon membership authority", "membership_authority_open_failed"),
        (b"join membership outbox startup replay", "membership_outbox_join_failed"),
        (b"replay membership outbox before carrier startup", "membership_outbox_replay_failed"),
        (b"start daemon membership/audit RPC", "membership_audit_rpc_start_failed"),
        (b"start mandatory daemon audit RPC", "audit_rpc_start_failed"),
        (b"select active Obsidian connector authority for Archive Bridge", "bridge_authority_rejected"),
        (b"obsidian_vault is required", "bridge_vault_missing"),
        (b"existing WAL master key is absent at", "wal_master_key_missing"),
        (b"read bridge pairing record", "bridge_pairing_record_unreadable"),
        (b"parse bridge pairing record", "bridge_pairing_record_invalid"),
        (b"invalid bridge pairing record", "bridge_pairing_record_invalid"),
        (b"construct private connector-control authority projection", "connector_control_projection_failed"),
        (b"connector-control operator_id is incompatible with SubjectId", "connector_control_subject_invalid"),
        (b"connector-control requires an operator_id compatible with SubjectId", "connector_control_subject_invalid"),
        (b"attach sealed connector-control runtime to Obsidian Archive Bridge", "bridge_runtime_attachment_failed"),
        (b"bind existing private Obsidian Archive Bridge IPC", "bridge_ipc_bind_failed"),
        (b"start private connector-control RPC", "connector_control_rpc_start_failed"),
        (b"recover pending consent mutation before provider startup", "consent_recovery_failed"),
        (b"recover pending counterparty-consent audit before provider startup", "counterparty_consent_recovery_failed"),
        (b"recover pending audited Skill mutation before daemon registry load", "skill_mutation_recovery_failed"),
        (b"join Self-Improve journal recovery before daemon registry load", "self_improve_recovery_join_failed"),
        (b"recover Self-Improve journal after installed-Skill reconciliation", "self_improve_recovery_failed"),
        (b"invalid OMI configuration", "omi_configuration_invalid"),
        (b"consent gate (V03-08 + A-2)", "provider_consent_rejected"),
        (b"daemon startup cannot retain Allow Once consent", "provider_consent_ephemeral_rejected"),
        (b"load skill registry for daemon instance", "skill_registry_load_failed"),
        (b"start skill registry watcher for daemon instance", "skill_registry_watcher_start_failed"),
    )
    # These are success messages already emitted by serve.  They only say how
    # far this start demonstrably got; no synthetic progress is inferred.
    milestones = (
        (b"loaded freedom.yaml", "config_loaded"),
        (b"BOOT event written and fsynced", "boot_wal_persisted"),
        (b"obsidian vault reader cron enabled", "obsidian_reader_started"),
        (b"skill registry primed for daemon", "skill_registry_primed"),
        (b"TRAIL-04: ViewsExecutor ready (writer:1 + readers:4)", "views_executor_ready"),
    )
    # Emit only a fixed diagnostic class; never return matched text or paths.
    classification = next((code for marker, code in signatures if marker in bounded), "unclassified")
    observed = ((bounded.rfind(marker), code) for marker, code in milestones if marker in bounded)
    last_milestone = max(observed, default=(-1, "not_observed"))[1]
    return {"reason": reason, "classification": classification, "last_milestone": last_milestone, "returncode": returncode, "log_sha256": hashlib.sha256(bounded).hexdigest(), "log_bytes": len(bounded), "log_truncated": len(raw) > LIMIT}

def capture_daemon_diagnostic(path: Path, reason: str, returncode: int | None) -> dict:
    try:
        with path.open("rb") as stream: raw = stream.read(LIMIT + 1)
    except OSError: raw = b""
    return redacted_daemon_diagnostic(reason, returncode, raw)

def start_daemon(binary: Path, home: Path, env: dict[str, str], root: Path, state: dict) -> subprocess.Popen[bytes]:
    log = root / f"daemon-{len(state['daemons'])}.log"; state["artifacts"].append(log)
    try:
        sink = log.open("xb")
        try: process = subprocess.Popen([str(binary), "serve", "--config", str(home / "freedom.yaml")], env=env, stdin=subprocess.DEVNULL, stdout=sink, stderr=subprocess.STDOUT)
        finally: sink.close()
    except OSError as error: raise Failure("daemon_spawn_failed") from error
    state["daemons"].append(process)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process.poll() is not None:
            state["daemon_diagnostics"].append(capture_daemon_diagnostic(log, "daemon_exited_early", process.returncode))
            raise Failure("daemon_exited_early")
        try:
            json_command([str(binary), "--output", "json", "obsidian", "bridge", "pairing-status"], env)
            return process
        except Failure: time.sleep(.2)
    process.terminate()
    try: process.wait(timeout=10)
    except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)
    state["daemon_diagnostics"].append(capture_daemon_diagnostic(log, "daemon_not_ready", process.returncode))
    raise Failure("daemon_not_ready")

def stop_daemon(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
        try: process.wait(timeout=20)
        except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5); raise Failure("daemon_stop_timeout")
    if process.returncode not in (0, -signal.SIGTERM): raise Failure("daemon_stop_failed")

def driver(node: str, driver_path: Path, plugin: Path, vault: Path, output: Path, mode: str, env: dict[str, str], artifacts: list[Path], pairing: Path | None = None, replay: Path | None = None) -> dict:
    argv = [node, str(driver_path), "--plugin", str(plugin), "--vault", str(vault), "--mode", mode, "--output", str(output)]
    if pairing: argv += ["--pairing", str(pairing)]
    if replay: argv += ["--replay", str(replay)]
    artifacts.append(output)
    run(argv, env, timeout=30)
    try: value = json.loads(output.read_bytes())
    except Exception as error: raise Failure("driver_output_invalid") from error
    if not isinstance(value, dict) or value.get("mode") != mode or not isinstance(value.get("pending"), int) or not isinstance(value.get("exchanges"), list) or not isinstance(value.get("sync_descriptors"), list): raise Failure("driver_output_invalid")
    return value

def receipt_count(home: Path) -> int:
    try: value = json.loads((home / "obsidian_archive_bridge_pairing.v1.json").read_bytes())
    except Exception as error: raise Failure("pairing_receipt_invalid") from error
    receipts = value.get("receipts") if isinstance(value, dict) else None
    if not isinstance(receipts, list): raise Failure("pairing_receipt_invalid")
    return len(receipts)

def observe_import_effect(home: Path, fixture_body: bytes) -> None:
    db = home / "views.db"; state = home / "obsidian_archive_bridge_state.v1.json"
    if not db.is_file() or db.is_symlink() or not state.is_file() or state.is_symlink(): raise Failure("import_effect_files_missing")
    try:
        connection = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        try:
            dedup = connection.execute("SELECT COUNT(*) FROM obsidian_archive_bridge_dedup_v1").fetchone()
            rows = connection.execute("SELECT statement, source, scope FROM idx_groundtruth WHERE source = ?1 AND scope = ?2 AND revoked_at IS NULL", ("import:obsidian", "obsidian-archive-bridge")).fetchall()
        finally: connection.close()
        state_value = json.loads(state.read_bytes())
    except Exception as error: raise Failure("import_effect_invalid") from error
    expected_hash = hashlib.sha256(fixture_body).hexdigest()
    if dedup != (1,) or len(rows) != 1 or not isinstance(state_value, dict) or len(state_value) != 1 or hashlib.sha256(rows[0][0].encode("utf-8")).hexdigest() != expected_hash or rows[0][1:] != ("import:obsidian", "obsidian-archive-bridge"):
        raise Failure("import_effect_invalid")

def checked_view(value: dict, expected: str) -> None:
    if value.get("status") != expected or value.get("plugin_id") != "neoth-archive-bridge" or value.get("version") != "0.2.0" or not isinstance(value.get("pairing_live"), bool):
        raise Failure("bridge_operation_not_authenticated")

def assert_current_payload(slot: Path, asset: Path) -> None:
    for name in ("main.js", "manifest.json"):
        if not (slot / name).is_file() or (slot / name).read_bytes() != (asset / name).read_bytes():
            raise Failure("installed_payload_mismatch")
    if not (slot / "ownership.json").is_file() or (slot / "ownership.json").read_bytes() != ownership_bytes(asset):
        raise Failure("installed_ownership_mismatch")

def ownership_bytes(asset: Path) -> bytes:
    manifest, main = asset / "manifest.json", asset / "main.js"
    if not manifest.is_file() or not main.is_file(): raise Failure("ownership_source_missing")
    return ("{\"schema\":1,\"plugin_id\":\"neoth-archive-bridge\",\"version\":\"0.2.0\",\"pairing\":\"disabled\",\"artifacts\":{\"manifest.json\":\"" + digest(manifest) + "\",\"main.js\":\"" + digest(main) + "\"}}\n").encode("ascii")

def validate_post_sync_settings(raw: bytes) -> None:
    try: value = json.loads(raw)
    except Exception as error: raise Failure("retained_settings_invalid") from error
    if not isinstance(value, dict) or value.get("operator") is not True or value.get("unknown") != 7 or value.get("enabled") is not True or not isinstance(value.get("pairingSecret"), str) or not isinstance(value.get("pairingGeneration"), int) or not isinstance(value.get("endpoint"), str) or not isinstance(value.get("pending"), list):
        raise Failure("retained_settings_invalid")

def cleanup_owned(root: Path, home: Path, vault: Path, host_home: Path, pairing: Path, artifacts: list[Path], daemons: list[subprocess.Popen[bytes]], master_key_seed: Path | None = None) -> dict[str, bool]:
    flags: dict[str, bool] = {}
    # Reap every process before removing any of its instance files or IPC
    # directories. A stopped process is not assumed merely because a later
    # scenario called stop_daemon.
    reaped = True
    for process in daemons:
        try:
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=10)
                except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)
            reaped = reaped and process.poll() is not None
        except Exception: reaped = False
    flags["daemons_reaped"] = reaped
    for name, target in (("home_removed", home), ("vault_removed", vault), ("host_home_removed", host_home)):
        try:
            if target.parent.resolve() != root.resolve() or target.is_symlink(): raise Failure("cleanup_target_invalid")
            if target.exists(): shutil.rmtree(target)
            flags[name] = not target.exists()
        except Exception: flags[name] = False
    try:
        if pairing.parent.resolve() != root.resolve() or pairing.is_symlink(): raise Failure("pairing_cleanup_target_invalid")
        if pairing.exists(): pairing.unlink()
        flags["pairing_removed"] = not pairing.exists()
    except Exception: flags["pairing_removed"] = False
    if master_key_seed is None:
        flags["master_key_seed_removed"] = True
    else:
        try:
            if master_key_seed.parent.resolve() != root.resolve() or master_key_seed.is_symlink(): raise Failure("master_key_seed_cleanup_target_invalid")
            if master_key_seed.exists(): master_key_seed.unlink()
            flags["master_key_seed_removed"] = not master_key_seed.exists()
        except Exception: flags["master_key_seed_removed"] = False
    artifacts_removed = True
    for artifact in artifacts:
        try:
            if artifact.parent.resolve() != root.resolve() or artifact.is_symlink(): raise Failure("artifact_cleanup_target_invalid")
            if artifact.exists(): artifact.unlink()
            artifacts_removed = artifacts_removed and not artifact.exists()
        except Exception: artifacts_removed = False
    flags["driver_artifacts_removed"] = artifacts_removed
    return flags

def bindings(asset: Path, driver_path: Path, workflow: Path) -> dict[str, str]:
    paths = {
        "bundle_main": asset / "main.js", "bundle_manifest": asset / "manifest.json", "bundle_lock": asset / "package-lock.json",
        "bundle_source": asset / "src/main.ts", "bundle_contract": asset / "test/plugin-contract.mjs",
        "predecessor_main": asset / "releases/0.1.1/main.js", "predecessor_manifest": asset / "releases/0.1.1/manifest.json", "predecessor_ownership": asset / "releases/0.1.1/ownership.json",
        "cli": Path("SRC/neothd/src/cli/obsidian.rs"), "serve": Path("SRC/neothd/src/cli/serve.rs"), "installer": Path("SRC/neothd/src/installers/obsidian_archive_bridge.rs"), "owner": Path("SRC/neothd/src/daemon/obsidian_archive_bridge_owner.rs"), "ipc": Path("SRC/neothd/src/daemon/obsidian_archive_bridge_ipc.rs"), "reader": Path("SRC/neothd/src/daemon/obsidian_vault_reader_cron.rs"), "memory_store": Path("SRC/neothd/src/memory/store.rs"), "groundtruth": Path("SRC/neothd/src/memory/groundtruth.rs"), "connector": Path("SRC/neothd/src/connectors/obsidian.rs"), "config": Path("SRC/neothd/src/config/mod.rs"), "canary": Path(__file__), "driver": driver_path, "workflow": workflow,
    }
    if any(not path.is_file() or path.is_symlink() for path in paths.values()): raise Failure("source_provenance_missing")
    return {name: digest(path) for name, path in paths.items()}

def execute(binary: Path, root: Path, home: Path, vault: Path, workflow: Path, node: str, state: dict) -> dict:
    asset = Path("SRC/neothd/assets/obsidian_archive_bridge").resolve(); driver_path = Path(__file__).with_name("obsidian_archive_bridge_product_driver.cjs").resolve()
    required = [binary, asset / "main.js", asset / "manifest.json", asset / "package-lock.json", driver_path, workflow]
    if any(not path.is_file() or path.is_symlink() for path in required): raise Failure("provenance_input_invalid")
    home.mkdir(); vault.mkdir(); host_home = root / "host-home"; host_home.mkdir(); state["host_home"] = host_home
    env = dict(os.environ); env["NEOTH_HOME"] = str(home); env["HOME"] = str(host_home)
    # Initialize the product's own home/key material, then write the narrow
    # explicit archive-bridge configuration used by serve.
    state["stage"] = "init"; run([str(binary), "init", "--non-interactive", "--cli", "--accept-license", "--operator-id", "archive-bridge-canary", "--provider", "skip"], env)
    state["stage"] = "provision_master_key"; provision_disposable_master_key(binary, home, env, root, state)
    write_bridge_config(home, vault)
    note = vault / "NEOTH-sessions" / "fixture.md"; note.parent.mkdir(); note.write_text("---\nsource: neoth-archive-bridge\n---\nfixture", encoding="utf-8")
    plugin_dir = vault / ".obsidian" / "plugins" / "neoth-archive-bridge"
    sentinel, unknown = b'{"operator":true,"unknown":7}', b"preserve-me"
    state["stage"] = "install"; install = json_command([str(binary), "--output", "json", "obsidian", "bridge", "install", "--vault", str(vault)], env)
    checked_view(install, "installed_disabled"); assert_current_payload(plugin_dir, asset)
    installed_hashes = {f"installed_{name}": digest(plugin_dir / name) for name in ("main.js", "manifest.json", "ownership.json")}
    # The installer must first authenticate and publish an empty owned slot.
    # Only then are operator-owned settings/additions introduced, matching a
    # real installed plugin rather than asking install to accept a foreign slot.
    (plugin_dir / "data.json").write_bytes(sentinel); (plugin_dir / "operator.extra").write_bytes(unknown)
    state["stage"] = "daemon_start_for_pair"; daemon = start_daemon(binary, home, env, root, state)
    try:
        state["stage"] = "pair"
        pairing = json_command([str(binary), "--output", "json", "obsidian", "bridge", "pair", "--vault", str(vault)], env)
        if set(pairing) != {"protocol", "endpoint", "pairingSecret", "pairingGeneration"} or pairing.get("protocol") != 1: raise Failure("pairing_payload_invalid")
        if pairing["pairingSecret"] in json.dumps(json_command([str(binary), "--output", "json", "obsidian", "bridge", "pairing-status"], env)): raise Failure("pairing_status_leaks_secret")
    finally: stop_daemon(daemon)
    pairing_file = root / "pairing.json"; state["pairing"] = pairing_file; pairing_file.write_text(json.dumps(pairing), encoding="utf-8")
    state["stage"] = "offline_queue"; offline = driver(node, driver_path, plugin_dir / "main.js", vault, root / "offline.json", "offline-pair", env, state["artifacts"], pairing_file)
    if offline["pending"] != 1 or offline["exchanges"]: raise Failure("offline_queue_not_retained")
    state["stage"] = "daemon_start_for_accept"; daemon = start_daemon(binary, home, env, root, state)
    try:
        state["stage"] = "daemon_ipc_accept"; accepted = driver(node, driver_path, plugin_dir / "main.js", vault, root / "accepted.json", "sync", env, state["artifacts"])
        if accepted["pending"] or "accepted" not in accepted["exchanges"] or len(accepted["sync_descriptors"]) != 1 or receipt_count(home) != 1: raise Failure("sync_not_accepted")
        observe_import_effect(home, b"fixture")
        replay = root / "accepted-descriptor.json"; state["artifacts"].append(replay); replay.write_text(json.dumps(accepted["sync_descriptors"][0]), encoding="utf-8")
        state["stage"] = "dedup"; duplicate = driver(node, driver_path, plugin_dir / "main.js", vault, root / "duplicate.json", "replay", env, state["artifacts"], replay=replay)
        if duplicate["pending"] or "already_current" not in duplicate["exchanges"] or duplicate["sync_descriptors"] != accepted["sync_descriptors"] or receipt_count(home) != 1: raise Failure("dedup_not_proven")
        observe_import_effect(home, b"fixture")
        # Produce a descriptor while the owner is unavailable, then remove the
        # source before it can be imported.  The daemon must acknowledge it as
        # stale rather than importing a cached note body (the bundle never has
        # one to send).
        stop_daemon(daemon); daemon = None
        note.write_text("---\nsource: neoth-archive-bridge\n---\nstale fixture", encoding="utf-8")
        state["stage"] = "stale"; stale_queued = driver(node, driver_path, plugin_dir / "main.js", vault, root / "stale-queued.json", "sync", env, state["artifacts"])
        if stale_queued["pending"] != 1: raise Failure("stale_queue_not_retained")
        note.unlink()
        state["stage"] = "daemon_start_for_stale"; daemon = start_daemon(binary, home, env, root, state)
        state["stage"] = "stale"; stale = driver(node, driver_path, plugin_dir / "main.js", vault, root / "stale.json", "sync", env, state["artifacts"])
        if stale["pending"] or "stale_revision" not in stale["exchanges"]: raise Failure("stale_not_proven")
        observe_import_effect(home, b"fixture")
        # Queue once while offline, then revoke before the old generation can sync.
        stop_daemon(daemon); daemon = None
        note.write_text("---\nsource: neoth-archive-bridge\n---\nold generation", encoding="utf-8")
        state["stage"] = "unpair"; retained = driver(node, driver_path, plugin_dir / "main.js", vault, root / "retained.json", "sync", env, state["artifacts"])
        if retained["pending"] != 1: raise Failure("unpair_fixture_queue_invalid")
        state["stage"] = "daemon_start_for_unpair"; daemon = start_daemon(binary, home, env, root, state)
        state["stage"] = "unpair"; json_command([str(binary), "--output", "json", "obsidian", "bridge", "unpair", "--vault", str(vault)], env)
        inert = driver(node, driver_path, plugin_dir / "main.js", vault, root / "inert.json", "sync", env, state["artifacts"])
        # Unpair withdraws the private listener, so no synthetic `unpaired`
        # response is expected. The old generation must remain queued and no
        # successful IPC acknowledgement may be observed.
        if inert["pending"] != 1 or inert["exchanges"]: raise Failure("unpair_not_inert")
        observe_import_effect(home, b"fixture")
    finally:
        if daemon is not None: stop_daemon(daemon)
    # Pairing changes managed fields. The preservation contract is that the
    # complete post-sync settings bytes, including unknown operator fields,
    # survive the artifact lifecycle exactly.
    post_sync_settings = (plugin_dir / "data.json").read_bytes(); validate_post_sync_settings(post_sync_settings)
    # Update authentic predecessor coverage is exercised by an exact shipped 0.1.1 artifact.
    state["stage"] = "update"
    shutil.copyfile(asset / "releases" / "0.1.1" / "main.js", plugin_dir / "main.js"); shutil.copyfile(asset / "releases" / "0.1.1" / "manifest.json", plugin_dir / "manifest.json"); shutil.copyfile(asset / "releases" / "0.1.1" / "ownership.json", plugin_dir / "ownership.json")
    update = json_command([str(binary), "--output", "json", "obsidian", "bridge", "update", "--vault", str(vault)], env); checked_view(update, "installed_disabled"); assert_current_payload(plugin_dir, asset)
    state["stage"] = "repair"
    (plugin_dir / "main.js").write_bytes(b"corrupt")
    repair = json_command([str(binary), "--output", "json", "obsidian", "bridge", "repair", "--vault", str(vault)], env); checked_view(repair, "installed_disabled"); assert_current_payload(plugin_dir, asset)
    if (plugin_dir / "data.json").read_bytes() != post_sync_settings or (plugin_dir / "operator.extra").read_bytes() != unknown: raise Failure("retained_plugin_data_changed")
    state["stage"] = "uninstall"; uninstall = json_command([str(binary), "--output", "json", "obsidian", "bridge", "uninstall", "--vault", str(vault)], env)
    if uninstall.get("status") != "residual" or (plugin_dir / "main.js").exists() or (plugin_dir / "manifest.json").exists() or not (plugin_dir / "ownership.json").is_file() or (plugin_dir / "ownership.json").read_bytes() != ownership_bytes(asset) or (plugin_dir / "data.json").read_bytes() != post_sync_settings or (plugin_dir / "operator.extra").read_bytes() != unknown or note.read_text(encoding="utf-8") != "---\nsource: neoth-archive-bridge\n---\nold generation": raise Failure("uninstall_retention_invalid")
    pairing_file.unlink()
    return {"schema_version": 1, "source_head": os.environ["GITHUB_SHA"], "host_adapter": "minimal_node_stub_loads_installed_main_js_no_obsidian_ui", "stages": ["install", "pair", "offline_queue", "daemon_ipc_accept", "dedup", "stale", "unpair", "update", "repair", "uninstall"], "sha256": {"binary": digest(binary), **installed_hashes, **bindings(asset, driver_path, workflow)}}

def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--binary", required=True); parser.add_argument("--root", required=True); parser.add_argument("--home", required=True); parser.add_argument("--vault", required=True); parser.add_argument("--receipt", required=True); parser.add_argument("--node", default="node"); parser.add_argument("--workflow", required=True); args = parser.parse_args()
    binary, root, home, vault, receipt, workflow = Path(args.binary).resolve(), Path(args.root).resolve(), Path(args.home).resolve(), Path(args.vault).resolve(), Path(args.receipt).resolve(), Path(args.workflow).resolve()
    require_hosted(root, home, vault, receipt); receipt.parent.mkdir(parents=True, exist_ok=True)
    state: dict = {"stage": "prepare", "host_home": root / "host-home", "pairing": root / "pairing.json", "master_key_seed": None, "artifacts": [], "daemons": [], "daemon_diagnostics": []}; outcome: dict | None = None; error = None
    try: outcome = execute(binary, root, home, vault, workflow, args.node, state)
    except Failure as caught: error = str(caught)
    except Exception: error = "unexpected_failure"
    cleanup = cleanup_owned(root, home, vault, state["host_home"], state["pairing"], state["artifacts"], state["daemons"], state["master_key_seed"])
    result = {"schema_version": 1, "source_head": os.environ["GITHUB_SHA"], "outcome": "passed" if outcome is not None and all(cleanup.values()) else "failed", "stage": "cleanup" if outcome is not None else state["stage"], "failure": error, "cleanup": cleanup, "daemon_start_diagnostics": state["daemon_diagnostics"], "host_adapter": "minimal_node_stub_loads_installed_main_js_no_obsidian_ui"}
    if outcome is not None: result.update(outcome)
    receipt.write_text(json.dumps(result, sort_keys=True), encoding="utf-8")
    return 0 if result["outcome"] == "passed" else 1

if __name__ == "__main__":
    try: raise SystemExit(main())
    except Failure as error: print(str(error), file=sys.stderr); raise SystemExit(1)
