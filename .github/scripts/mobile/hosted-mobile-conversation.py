#!/usr/bin/env python3
"""Hosted-only real Companion conversation/restart journey; never run locally."""
from __future__ import annotations

import argparse
import ctypes
import http.server
import importlib.util
import json
import os
import pathlib
import subprocess
import tempfile
import threading
import time
import uuid
from typing import Any

_spec = importlib.util.spec_from_file_location("conversation_interop", pathlib.Path(__file__).with_name("hosted-mobile-interop.py"))
assert _spec is not None and _spec.loader is not None
H = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(H)

PROMPTS = ("Remember the ordinary conversation marker cobalt-orbit.", "Which ordinary conversation marker did I give you?")
REPLIES = ("The ordinary conversation marker is cobalt-orbit.", "You gave me cobalt-orbit in this conversation.")
MAX_RESULT = 184 * 1024


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def public_uuid(value: Any) -> str:
    require(isinstance(value, str), "public identity is not text")
    parsed = uuid.UUID(value)
    require(parsed.int != 0 and str(parsed) == value, "public identity is not canonical")
    return value


def validate_history(value: Any, request_id: str, revision: int, conversation_id: str | None,
                     *, committed: bool, rows: list[dict[str, Any]], read: bool) -> None:
    keys = {"conversation_schema_version", "request_id", "revision", "conversation_id", "state",
            "current_turn_committed", "bounded_tail", "turns"}
    if read:
        keys.add("kind")
    require(isinstance(value, dict) and set(value) == keys, "history public fields differ")
    if read:
        require(value["kind"] == "conversation_history" and not committed, "read cannot claim a new commit")
    require(type(value["conversation_schema_version"]) is int and value["conversation_schema_version"] == 1,
            "history schema differs")
    require(value["request_id"] == request_id and type(value["revision"]) is int and value["revision"] == revision,
            "history request/revision differs")
    require(value["conversation_id"] == conversation_id and value["state"] == ("available" if conversation_id else "not_found"),
            "history conversation/state differs")
    require(value["current_turn_committed"] is committed and value["bounded_tail"] is True and value["turns"] == rows,
            "history commit/ordered canonical rows differ")
    require(len(rows) <= 32 and len(json.dumps(rows, separators=(",", ":")).encode()) <= 96 * 1024,
            "history rows exceed wire bounds")


def validate_chat(value: Any, request_id: str, revision: int, expected_id: str | None,
                  *, rows: list[dict[str, Any]], reply: str) -> str:
    require(isinstance(value, dict) and set(value) == {"kind", "schema_version", "request_id", "outcome", "records",
            "provider", "model", "conversation_admission", "conversation_history"}, "chat public fields differ")
    require(value["kind"] == "chat" and type(value["schema_version"]) is int and value["schema_version"] == 3
            and value["request_id"] == request_id and value["outcome"] == "accepted", "chat terminal is not exact acceptance")
    require(value["records"] == [{"kind": "stdout", "text": reply}]
            and isinstance(value["provider"], str) and bool(value["provider"])
            and value["model"] == "w2328-loopback-model", "chat answer/model custody differs")
    admitted = value["conversation_admission"]
    require(isinstance(admitted, dict) and set(admitted) == {"conversation_schema_version", "request_id", "revision", "conversation_id", "incognito"},
            "admission public fields differ")
    require(type(admitted["conversation_schema_version"]) is int and admitted["conversation_schema_version"] == 1
            and admitted["request_id"] == request_id and type(admitted["revision"]) is int
            and admitted["revision"] == revision and admitted["incognito"] is False, "admission binding differs")
    conversation_id = public_uuid(admitted["conversation_id"])
    require(expected_id is None or expected_id == conversation_id, "resumed conversation changed")
    validate_history(value["conversation_history"], request_id, revision, conversation_id, committed=True, rows=rows, read=False)
    return conversation_id


class ConversationFrameError(RuntimeError):
    """Only fixed public classifications cross into diagnostic receipts."""
    def __init__(self, code: int, value: dict[str, Any], request_id: str):
        def selected(field: str, allowed: set[str]) -> str:
            observed = value.get(field)
            return observed if isinstance(observed, str) and observed in allowed else "other"
        self.public_failure = {
            "poll_code": code if type(code) is int and code in (-1, 0, 1, 2, 3, 4, 5, 6, 7) else -1,
            "kind": selected("kind", {"chat", "conversation_history"}),
            "outcome": selected("outcome", {"accepted", "denied", "busy", "unavailable", "timeout", "indeterminate"}),
            "code": selected("code", {"cancelled", "device_denied", "unknown_device", "revoked", "invalid_signature",
                "transport_join_failed", "transport_closed", "chat_connect_timeout", "daemon_key_mismatch",
                "invalid_server_frame", "transport_read_failed", "chat_challenge_timeout", "invalid_chat_challenge",
                "conversation_not_supported", "stale_conversation_revision", "invalid_chat_request"}),
            "request_matches": value.get("request_id") == request_id,
        }
        super().__init__("conversation terminal rejected: " + json.dumps(self.public_failure, sort_keys=True))

class ConversationBridge(H.Bridge):
    def __init__(self, shared: pathlib.Path):
        super().__init__(shared)
        u8, size, ptr = ctypes.c_ubyte, ctypes.c_size_t, ctypes.c_void_p
        self.lib.neoth_companion_conversation_start_v1.argtypes = [ptr, ctypes.POINTER(u8), size, ctypes.POINTER(u8), size, ctypes.POINTER(u8), size]
        self.lib.neoth_companion_conversation_start_v1.restype = ptr
        self.lib.neoth_companion_conversation_poll_v1.argtypes = [ptr, ctypes.POINTER(u8), size, ctypes.POINTER(size)]
        self.lib.neoth_companion_conversation_poll_v1.restype = ctypes.c_int32

    def restart_native_owner(self) -> None:
        # Recreate the actual native runtime with the same in-memory protected
        # identity. No private seed is written to any artifact or receipt.
        require(bool(self.handle), "native owner already closed")
        self.lib.neoth_companion_bridge_free(self.handle)
        self.handle = None
        self.handle = self.lib.neoth_companion_bridge_new(self.seed, 32)
        require(bool(self.handle), "native identity restore failed")

    def conversation(self, descriptor: dict[str, Any], device_id: str, revision: int,
                     request_id: str, action: dict[str, Any], timeout: float) -> dict[str, Any]:
        read = action["operation"] in ("history", "recover")
        command = {"command_schema_version": 1, "request_id": request_id, "revision": revision, "action": action}
        values = (json.dumps(descriptor, separators=(",", ":")), device_id, json.dumps(command, separators=(",", ":")))
        buffers = [(ctypes.c_ubyte * len(value.encode())).from_buffer_copy(value.encode()) for value in values]
        op = self.lib.neoth_companion_conversation_start_v1(self.handle, buffers[0], len(buffers[0]),
                buffers[1], len(buffers[1]), buffers[2], len(buffers[2]))
        require(bool(op), "conversation start returned null")
        until = time.monotonic() + timeout
        preview_revision = 0
        try:
            while time.monotonic() < until:
                code, raw = self._conversation_poll(op, until)
                if code == H.PENDING:
                    time.sleep(min(.125, H.budget(until, .125)))
                    continue
                value = H.cli_json(raw, "conversation frame")
                require(isinstance(value, dict), "conversation frame is not an object")
                if code in (H.STREAM, H.ACTIVITY):
                    require(not read and value.get("request_id") == request_id, "read/foreign progress frame")
                    if code == H.STREAM:
                        require(value.get("kind") == "chat_stream_snapshot" and type(value.get("revision")) is int
                                and preview_revision < value["revision"] <= 2**64 - 1
                                and isinstance(value.get("text"), str) and len(value["text"].encode()) <= 10240,
                                "invalid conversation preview")
                        preview_revision = value["revision"]
                    else:
                        require(value.get("kind") == "chat_activity_snapshot", "invalid activity frame")
                    continue
                if code != H.OK or value.get("request_id") != request_id or (read and value.get("kind") != "conversation_history"):
                    raise ConversationFrameError(code, value, request_id)
                return value
            raise H.WorkDeadline("conversation work deadline exhausted")
        except Exception:
            self.lib.neoth_companion_operation_cancel(op)
            # Native cancellation owns the worker drain; never resend/start.
            drain_until = time.monotonic() + 15
            while time.monotonic() < drain_until:
                code, _ = self._conversation_poll(op, drain_until)
                if code not in (H.PENDING, H.STREAM, H.ACTIVITY):
                    break
            raise
        finally:
            self.lib.neoth_companion_operation_free(op)
            for value in buffers:
                ctypes.memset(ctypes.addressof(value), 0, len(value))

    def _conversation_poll(self, operation: Any, deadline: float) -> tuple[int, bytes]:
        H.budget(deadline)
        required = ctypes.c_size_t()
        code = self.lib.neoth_companion_conversation_poll_v1(operation, None, 0, ctypes.byref(required))
        if code == H.PENDING:
            return code, b""
        require(code == H.BUFFER_TOO_SMALL and 0 < required.value <= MAX_RESULT, "invalid conversation poll probe")
        while True:
            H.budget(deadline)
            capacity = required.value
            output = (ctypes.c_ubyte * capacity)()
            code = self.lib.neoth_companion_conversation_poll_v1(operation, output, capacity, ctypes.byref(required))
            if code == H.BUFFER_TOO_SMALL:
                require(capacity < required.value <= MAX_RESULT, "invalid conversation poll growth")
                continue
            require(0 < required.value <= capacity, "invalid conversation poll length")
            return code, bytes(output[:required.value])


class Provider(http.server.BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        if self.path != "/v1/chat/completions":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        if not 0 < length <= 512 * 1024:
            self.send_error(413)
            return
        request = json.loads(self.rfile.read(length))
        with self.server.state_lock:
            index = self.server.request_count
            self.server.request_count += 1
            messages = request.get("messages")
            valid = index < 2 and request.get("stream") is True and isinstance(messages, list) and bool(messages)
            valid = valid and messages[-1] == {"role": "user", "content": PROMPTS[index]}
            if index == 1 and valid:
                context = json.dumps(messages[:-1], ensure_ascii=False)
                self.server.context_verified = PROMPTS[0] in context and REPLIES[0] in context
                valid = self.server.context_verified
            self.server.provider_valid = self.server.provider_valid and valid
        if not valid:
            self.send_error(400)
            return
        body = {"id": "w2516-conversation", "object": "chat.completion.chunk", "model": "w2328-loopback-model",
                "choices": [{"index": 0, "delta": {"content": REPLIES[index]}, "finish_reason": "stop"}]}
        encoded = b"data: " + json.dumps(body, separators=(",", ":")).encode() + b"\n\ndata: [DONE]\n\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)
        self.wfile.flush()

    def log_message(self, *_: Any) -> None:
        pass


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--staging", type=pathlib.Path, required=True)
    ap.add_argument("--receipt", type=pathlib.Path, required=True)
    ap.add_argument("--allow-external-udp", action="store_true")
    ns = ap.parse_args()
    require(ns.allow_external_udp, "explicit external UDP consent required")
    require(not ns.receipt.exists(), "receipt must be fresh")
    manifest = json.loads((ns.staging / "host-interop-manifest.json").read_text())
    binary, library = ns.staging / "neoth", ns.staging / "libneoth_companion_bridge.so"
    require(manifest.get("profile") == "debug" and manifest.get("required_symbols") == list(H.SYMBOLS)
            and H.sha(binary) == manifest["artifacts"]["neoth_sha256"]
            and H.sha(library) == manifest["artifacts"]["bridge_sha256"], "staged producer custody mismatch")
    work_deadline = time.monotonic() + 480
    cleanup_deadline = work_deadline + 150
    receipt: dict[str, Any] = {"schema": "neoth.mobile-conversation-journey.v1", "source_head": manifest["source_head"],
            "artifacts": manifest["artifacts"], "outcome": "failed", "generations": [], "steps": {},
            "physical_device_accepted": False, "release_accepted": False}
    server = http.server.HTTPServer(("127.0.0.1", 0), Provider)
    server.request_count, server.context_verified, server.provider_valid = 0, False, True
    server.state_lock = threading.Lock()
    provider_thread = threading.Thread(target=server.serve_forever, daemon=True)
    provider_thread.start()
    serve = None
    markers = None
    bridge = None
    previous_diagnostics = os.environ.get("NEOTH_COMPANION_DIAGNOSTICS")

    def stop_generation() -> None:
        nonlocal serve, markers
        if serve is None:
            return
        outcome = H.stop_serve(serve, cleanup_deadline)
        observed = markers.snapshot(cleanup_deadline - time.monotonic()) if markers is not None else {}
        generation = {"shutdown": outcome, "exit_code": serve.returncode, "observed": observed}
        receipt["generations"].append(generation)
        serve = None
        markers = None
        require(outcome == "graceful" and generation["exit_code"] == 0
                and observed.get("reader_closed") is True and observed.get("reader_error") is False
                and observed.get("rust_panic_observed") is False
                and observed.get("markers", {}).get("wal_drained") is True
                and observed.get("markers", {}).get("wal_other_senders_absent") is True,
                "daemon generation did not drain cleanly")

    try:
        with tempfile.TemporaryDirectory(prefix="neoth-conversation-") as temporary:
            home = pathlib.Path(temporary) / "home"
            home.mkdir(mode=0o700)
            health_port, companion_port = H.port(), H.port()
            config = H.write_config(home, f"http://127.0.0.1:{server.server_address[1]}/v1", health_port, companion_port)
            env = {**os.environ, "NEOTH_HOME": str(home), "NEOTH_COMPANION_DIAGNOSTICS": "1"}
            os.environ["NEOTH_COMPANION_DIAGNOSTICS"] = "1"
            H.invoke([str(binary), "--output", "json", "consent", "grant", "openai_compat"], env, H.budget(work_deadline, 20))

            def start_generation() -> None:
                nonlocal serve, markers
                serve = subprocess.Popen([str(binary), "serve", "--config", str(config)], env=env, stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
                require(serve.stdout is not None, "missing daemon output owner")
                markers = H.ShutdownMarkerCollector(serve.stdout)
                until = min(work_deadline, time.monotonic() + 30)
                while time.monotonic() < until and serve.poll() is None:
                    if H.health(health_port, H.budget(until, 2)):
                        return
                    time.sleep(.25)
                raise RuntimeError("daemon readiness failed")

            try:
                receipt["stage"] = "initial_daemon"
                start_generation()
                raw = H.invoke([str(binary), "--output", "json", "companion", "pair-mobile", "--scope", "chat-send"],
                        env, H.budget(work_deadline, 20), pair_mint=True)
                bridge = ConversationBridge(library)
                code, raw = bridge.call("neoth_companion_pair_start", H.pair_url(raw), "w2516-conversation", timeout=H.budget(work_deadline))
                require(code == H.OK, "chat enrollment rejected")
                paired = H.terminal(raw, "paired")
                device_id, revision, descriptor = paired["device_id"], paired["revision"], paired["descriptor"]
                public_uuid(device_id)
                require(type(revision) is int and revision > 0, "enrollment revision invalid")
                request_id = str(uuid.uuid4())
                checkpoint = home / "conversation-public-checkpoint.json"
                checkpoint.write_text(json.dumps({"device_id": device_id, "revision": revision, "created_by_request": request_id}))
                rows = [{"role": "operator", "text": PROMPTS[0], "truncated": False}, {"role": "agent", "text": REPLIES[0], "truncated": False}]
                receipt["stage"] = "first_encrypted_message"
                first = bridge.conversation(descriptor, device_id, revision, request_id,
                        {"operation": "new", "message": PROMPTS[0], "incognito": False}, H.budget(work_deadline))
                validate_chat(first, request_id, revision, None, rows=rows, reply=REPLIES[0])
                require(server.request_count == 1, "first message provider count differs")
                receipt["steps"]["first"] = {"accepted": True, "canonical_rows": 2, "provider_calls": 1}
                del first  # Simulate loss of the local terminal/admission, never replay its prompt.
                receipt["stage"] = "restart_daemon_and_native"
                stop_generation()
                bridge.restart_native_owner()
                start_generation()
                saved = json.loads(checkpoint.read_text())
                require(set(saved) == {"device_id", "revision", "created_by_request"}, "checkpoint contains non-public state")
                recovered_request = str(uuid.uuid4())
                receipt["stage"] = "readonly_creator_recovery"
                recovered = bridge.conversation(descriptor, saved["device_id"], saved["revision"], recovered_request,
                        {"operation": "recover", "created_by_request": saved["created_by_request"]}, H.budget(work_deadline))
                conversation_id = public_uuid(recovered.get("conversation_id"))
                validate_history(recovered, recovered_request, revision, conversation_id, committed=False, rows=rows, read=True)
                require(server.request_count == 1, "recovery called the provider")
                receipt["steps"]["restart_recovery"] = {"daemon_restarted": True, "native_recreated": True,
                        "public_checkpoint_only": True, "canonical_rows": 2, "provider_calls": 1, "new_commit_claimed": False}
                receipt["stage"] = "second_encrypted_message"
                second_request = str(uuid.uuid4())
                rows += [{"role": "operator", "text": PROMPTS[1], "truncated": False}, {"role": "agent", "text": REPLIES[1], "truncated": False}]
                second = bridge.conversation(descriptor, device_id, revision, second_request,
                        {"operation": "resume", "conversation_id": conversation_id, "message": PROMPTS[1]}, H.budget(work_deadline))
                validate_chat(second, second_request, revision, conversation_id, rows=rows, reply=REPLIES[1])
                require(server.request_count == 2 and server.context_verified and server.provider_valid, "resumed provider did not receive exact prior context")
                receipt["steps"]["second"] = {"accepted": True, "same_conversation": True, "canonical_rows": 4,
                        "provider_calls": 2, "prior_context_verified": True}
                receipt["stage"] = "readonly_history_and_missing_creator"
                history_request = str(uuid.uuid4())
                history = bridge.conversation(descriptor, device_id, revision, history_request,
                        {"operation": "history", "conversation_id": conversation_id}, H.budget(work_deadline))
                validate_history(history, history_request, revision, conversation_id, committed=False, rows=rows, read=True)
                missing_request = str(uuid.uuid4())
                missing = bridge.conversation(descriptor, device_id, revision, missing_request,
                        {"operation": "recover", "created_by_request": str(uuid.uuid4())}, H.budget(work_deadline))
                validate_history(missing, missing_request, revision, None, committed=False, rows=[], read=True)
                require(server.request_count == 2, "read-only requests called the provider")
                receipt["steps"]["readonly"] = {"history_rows": 4, "missing_creator": "not_found", "provider_calls": 2, "new_commit_claimed": False}
                receipt["stage"] = "durable_revoke"
                revoke = H.cli_json(H.invoke([str(binary), "--output", "json", "companion", "devices", "revoke", device_id], env, H.budget(work_deadline, 20), companion_rpc=True), "revoke")
                views = H.cli_json(H.invoke([str(binary), "--output", "json", "companion", "devices", "status", device_id], env, H.budget(work_deadline, 20), companion_rpc=True), "status")
                require(revoke == {"revoked": True} and isinstance(views, list) and len(views) == 1
                        and views[0].get("device_id") == device_id and views[0].get("grant_state") == "revoked"
                        and views[0].get("revision") == revision + 1 and server.request_count == 2, "revoke custody differs")
                receipt["steps"]["revoke"] = {"durable": True, "revision_advanced": True, "provider_calls": 2}
            finally:
                if bridge is not None:
                    bridge.close()
                    bridge = None
                stop_generation()
            require(len(receipt["generations"]) == 2, "two daemon generations were not drained")
            receipt["outcome"] = "passed"
            receipt["stage"] = "complete"
    except Exception as error:
        receipt["failure_class"] = "public_terminal" if isinstance(error, ConversationFrameError) else "journey_check"
        if isinstance(error, ConversationFrameError):
            receipt["public_failure"] = error.public_failure
        raise
    finally:
        if bridge is not None:
            bridge.close()
        try:
            stop_generation()
        finally:
            if previous_diagnostics is None:
                os.environ.pop("NEOTH_COMPANION_DIAGNOSTICS", None)
            else:
                os.environ["NEOTH_COMPANION_DIAGNOSTICS"] = previous_diagnostics
            server.shutdown()
            server.server_close()
            provider_thread.join(timeout=5)
            receipt["provider_calls"] = server.request_count
            ns.receipt.parent.mkdir(parents=True, exist_ok=True)
            ns.receipt.write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"Conversation journey failed: {H.brief(str(error))}", file=H.sys.stderr)
        raise SystemExit(1)
