#!/usr/bin/env python3
"""W2328 R8 hosted real-CLI/cdylib interop runner; never run under local hold."""
from __future__ import annotations
import argparse, ctypes, hashlib, http.server, json, os, pathlib, re, secrets
import signal, socket, socketserver, subprocess, sys, tempfile, threading, time
import urllib.request
from typing import Any, Callable

PENDING, OK, FAILED = 0, 1, 3
MAX_PUBLIC, PAIR_JSON_MAX, PAIR_URL_MAX, DEADLINE = 80 * 1024, 8 * 1024, 512, 140.0
HOSTED_STEP_SECONDS, CLEANUP_RESERVE_SECONDS, START_MARGIN_SECONDS = 600.0, 180.0, 30.0
WORK_SECONDS = HOSTED_STEP_SECONDS - CLEANUP_RESERVE_SECONDS - START_MARGIN_SECONDS

class WorkDeadline(RuntimeError): pass
class CliFailure(RuntimeError):
    def __init__(self, returncode: int, category: str, parse_subtype: str = "unknown"):
        super().__init__(f"CLI failed rc={returncode} category={category}")
        self.category = category
        self.parse_subtype = parse_subtype
REPLY = "W2328 deterministic loopback reply"
SYMBOLS = ("neoth_companion_bridge_new","neoth_companion_pair_start",
 "neoth_companion_reconnect_start","neoth_companion_chat_start",
 "neoth_companion_operation_poll","neoth_companion_operation_cancel",
 "neoth_companion_operation_free","neoth_companion_bridge_free")
SHUTDOWN_MARKERS = (
    ("background_entry", b"shutdown checkpoint: background entry"),
    ("generation_effects_retired", b"shutdown checkpoint: generation effects retired"),
    ("channels_dispatch_drained", b"shutdown checkpoint: channels and dispatch drained"),
    ("updater_shutdown_entry", b"shutdown checkpoint: updater shutdown entry"),
    ("cron_fleet_drained", b"shutdown checkpoint: cron fleet drained"),
    ("cluster_drained", b"shutdown checkpoint: cluster drained"),
    ("outboxes_drained", b"shutdown checkpoint: outboxes drained"),
    ("core_authority_drained", b"shutdown checkpoint: core authority drained"),
    ("transports_drained", b"shutdown checkpoint: transports drained"),
    ("final_pre_wal_tasks_drained", b"shutdown checkpoint: final pre-WAL tasks drained"),
    ("wal_other_senders_present", b"shutdown checkpoint: WAL other senders present"),
    ("wal_other_senders_absent", b"shutdown checkpoint: WAL other senders absent"),
    ("wal_join_entry", b"shutdown checkpoint: WAL join entry"),
    ("wal_drained", b"WAL writer task drained cleanly"),
)
RUST_PANIC_MARKERS = (b"[neoth panic]", b"panicked at")
RUST_PANIC_SITE_RE = re.compile(
    rb"(?:^|\n)NEOTH_PANIC_SITE=([A-Za-z0-9_.-]{1,96}:[1-9][0-9]{0,6})\n"
)
PAIR_PHASES = (
    "bootstrap_started", "bootstrap_ready", "topic_joined", "awaiting_connection",
    "connection_received", "psk_verified", "proof_read", "response_written",
    "teardown_started", "teardown_completed",
    "enrollment_begin", "enrollment_authority_pending", "enrollment_audit_finalized",
    "active_listener_ready", "active_listener_unready", "enrollment_rollback_proven",
    "enrollment_rollback_noop", "enrollment_rollback_unproven", "pair_rendezvous_leave_started",
    "pair_rendezvous_left", "enrollment_response_write_started", "teardown_failed",
    "rendezvous_started", "initial_discovery_started",
    "readiness_stop_requested", "readiness_owner_cancelled", "readiness_owner_deadline",
    "readiness_owner_ended", "readiness_owner_refused",
)
PAIR_MARKERS = tuple(
    (phase, f"NEOTH_COMPANION_PAIR_PHASE={phase}\n".encode("ascii"))
    for phase in (*PAIR_PHASES, *(f"failed.{phase}" for phase in PAIR_PHASES))
)
DISCOVERY_PHASES = (
    "announce_success", "announce_failure", "lookup_none", "lookup_peers",
    "lookup_failure", "connect_attempt_started", "connect_attempt_succeeded",
    "connect_attempt_failed", "connect_attempt_timed_out",
    "server_topic_announce_succeeded", "server_topic_announce_failed",
    "server_key_announce_succeeded", "server_key_announce_failed",
    "responder_noise_started", "candidate_rejected",
)
DISCOVERY_MARKERS = tuple(
    (phase, f"NEOTH_COMPANION_DISCOVERY_PHASE={phase}".encode("ascii"))
    for phase in DISCOVERY_PHASES
)
CONNECT_PHASES = (
    "route_lookup_started", "route_lookup_completed", "route_lookup_empty",
    "find_peer_fallback_started", "find_peer_fallback_completed",
    "handshake_request_started", "handshake_reply_received", "noise_completed",
    "udx_establishment_started", "udx_establishment_completed", "path_direct",
    "path_relay", "handshake_dispatch_received", "route_direct_selected",
    "route_forwarded_marker", "relay_through_started", "holepunch_started",
)
CONNECT_MARKERS = tuple(
    (phase, f"NEOTH_COMPANION_CONNECT_PHASE={phase}\n".encode("ascii"))
    for phase in CONNECT_PHASES
)
SCOPED_CONNECT_PHASES = (
    "handshake_dispatch_received", "handshake_routing_local",
    "handshake_routing_relay", "handshake_routing_closer_nodes",
    "handshake_routing_dropped", "handshake_local_admitted",
    "handshake_local_rejected", "handshake_reply_capability_consumed",
    "handshake_reply_capability_dropped", "responder_noise_started",
    "responder_noise_authenticated", "responder_pin_rejected",
    "responder_connection_delivered", "handshake_deferred_reply_observed",
    "handshake_reply_udp_accepted", "handshake_reply_udp_queued",
    "handshake_reply_udp_queue_dropped", "handshake_reply_udp_terminal_error",
    "handshake_reply_prepare_failed", "handshake_reply_expired",
    "handshake_reply_udp_os_send_succeeded",
    "handshake_reply_udp_os_send_failed",
    "handshake_reply_udp_os_send_dropped",
    "client_udx_route_admitted", "client_udx_route_rejected",
    "client_udx_route_unknown_fallback", "server_udx_route_admitted",
    "server_udx_route_rejected", "server_udx_route_unknown_fallback",
)
SCOPED_CONNECT_MARKERS = tuple(
    (f"{scope}_{phase}", f"NEOTH_COMPANION_CONNECT_PHASE={scope}_{phase}\n".encode("ascii"))
    for scope in ("pair", "active") for phase in SCOPED_CONNECT_PHASES
)
SCOPED_CONNECT_COUNT_LIMIT = 65535
def sha(path: pathlib.Path) -> str: return hashlib.sha256(path.read_bytes()).hexdigest().upper()
def brief(value: str) -> str: return value.replace("\n", " ").replace("\r", " ")[:160]
def port() -> int:
    with socket.socket() as sock: sock.bind(("127.0.0.1", 0)); return sock.getsockname()[1]
def budget(deadline: float, cap: float = DEADLINE) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0: raise WorkDeadline("work deadline exhausted")
    return min(cap, remaining)

class ShutdownMarkerCollector:
    """Discard daemon output while retaining fixed booleans and bounded scoped counts."""
    def __init__(self, stream: Any) -> None:
        self.stream, self.lock = stream, threading.Lock()
        self.observed = {name: False for name, _ in SHUTDOWN_MARKERS}
        self.rust_panic_observed = False
        self.rust_panic_site: str | None = None
        self.rust_panic_floor: int | None = None
        self.pair_observed = {name: False for name, _ in PAIR_MARKERS}
        self.discovery_observed = {name: False for name, _ in DISCOVERY_MARKERS}
        self.connect_observed = {name: False for name, _ in CONNECT_MARKERS}
        self.scoped_connect_counts = {name: 0 for name, _ in SCOPED_CONNECT_MARKERS}
        self.scoped_connect_saturated = False
        self.reader_error = False
        self.overlap = max(
            max(
                len(marker)
                for _, marker in (*SHUTDOWN_MARKERS, *PAIR_MARKERS, *DISCOVERY_MARKERS, *CONNECT_MARKERS, *SCOPED_CONNECT_MARKERS)
            ),
            128,
        ) - 1
        self.thread = threading.Thread(target=self._drain, daemon=True)
        self.thread.start()

    def _drain(self) -> None:
        tail = b""
        stream_offset = 0
        try:
            while chunk := self.stream.read(4096):
                window = tail + chunk
                window_start = stream_offset - len(tail)
                with self.lock:
                    for name, marker in SHUTDOWN_MARKERS:
                        if marker in window:
                            self.observed[name] = True
                    if self.rust_panic_floor is None:
                        panic_ends = [
                            offset + len(marker)
                            for marker in RUST_PANIC_MARKERS
                            if (offset := window.find(marker)) >= 0
                        ]
                        if panic_ends:
                            self.rust_panic_observed = True
                            self.rust_panic_floor = window_start + min(panic_ends)
                    if self.rust_panic_floor is not None and self.rust_panic_site is None:
                        for site in RUST_PANIC_SITE_RE.finditer(window):
                            if window_start + site.start() >= self.rust_panic_floor:
                                self.rust_panic_site = site.group(1).decode("ascii")
                                break
                    for name, marker in PAIR_MARKERS:
                        if marker in window:
                            self.pair_observed[name] = True
                    for name, marker in DISCOVERY_MARKERS:
                        if marker in window:
                            self.discovery_observed[name] = True
                    for name, marker in CONNECT_MARKERS:
                        if marker in window:
                            self.connect_observed[name] = True
                    for name, marker in SCOPED_CONNECT_MARKERS:
                        at = window.find(marker)
                        while at >= 0:
                            # Retained overlap may contain a complete shorter marker.
                            # Count it only when this chunk supplies its final byte.
                            if at + len(marker) > len(tail):
                                if self.scoped_connect_counts[name] < SCOPED_CONNECT_COUNT_LIMIT:
                                    self.scoped_connect_counts[name] += 1
                                else:
                                    self.scoped_connect_saturated = True
                            at = window.find(marker, at + len(marker))
                stream_offset += len(chunk)
                tail = window[-self.overlap:]
        except Exception:
            with self.lock:
                self.reader_error = True
        finally:
            tail = b""
            try:
                self.stream.close()
            except OSError:
                pass

    def scoped_connect_cursor(self) -> dict[str, Any]:
        with self.lock:
            return {"counts": dict(self.scoped_connect_counts),
                    "saturated": self.scoped_connect_saturated,
                    "reader_error": self.reader_error}

    def scoped_connect_since(self, cursor: dict[str, Any]) -> dict[str, Any]:
        with self.lock:
            end = dict(self.scoped_connect_counts)
            return {
                "basis": "collector_observation_cursor",
                "emission_time_bound": False,
                "before": dict(cursor["counts"]),
                "after": end,
                "observed_delta": {name: count - cursor["counts"][name] for name, count in end.items()},
                "saturated": cursor["saturated"] or self.scoped_connect_saturated,
                "reader_error": cursor["reader_error"] or self.reader_error,
            }

    def snapshot(self, remaining_cleanup: float) -> dict[str, Any]:
        self.thread.join(timeout=min(1.0, max(0.0, remaining_cleanup)))
        with self.lock:
            return {
                "markers": dict(self.observed),
                "rust_panic_observed": self.rust_panic_observed,
                "rust_panic_site": self.rust_panic_site,
                "pair_markers": dict(self.pair_observed),
                "discovery_markers": dict(self.discovery_observed),
                "connect_markers": dict(self.connect_observed),
                "scoped_connect_counts": dict(self.scoped_connect_counts),
                "scoped_connect_saturated": self.scoped_connect_saturated,
                "reader_closed": not self.thread.is_alive(),
                "reader_error": self.reader_error,
            }

class Provider(http.server.BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        if self.path != "/v1/chat/completions":
            self.send_error(404); return
        length = int(self.headers.get("Content-Length", "0"))
        if length > 65536: self.send_error(413); return
        self.rfile.read(length)
        self.server.request_count += 1
        body = json.dumps({"id":"w2328-loopback","object":"chat.completion",
          "model":"w2328-loopback-model","choices":[{"index":0,
          "message":{"role":"assistant","content":REPLY},
          "finish_reason":"stop"}]}, separators=(",", ":")).encode()
        self.send_response(200); self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *_: Any) -> None: pass

class Loopback:
    def __enter__(self) -> "Loopback":
        self.server = socketserver.TCPServer(("127.0.0.1", 0), Provider)
        self.server.request_count = 0
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/v1"; return self
    def __exit__(self, *_: Any) -> None:
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=5)

def write_config(home: pathlib.Path, provider_url: str, health_port: int, companion_port: int) -> pathlib.Path:
    config = home / "freedom.yaml"
    config.write_text(
      f"operator_id: w2328-hosted\nonboarding_complete: true\nsecrets_backend: file\nprovider_kind: openai_compat\n"
      f"provider_endpoint: {provider_url}\nprovider_model: w2328-loopback-model\n"
      f"observability_listen: 127.0.0.1:{health_port}\ncompanion:\n  enabled: true\n"
      f"  port: {companion_port}\n  p2p_enabled: true\n", encoding="utf-8")
    # Local canary value only. It is never emitted and the provider ignores it.
    (home / "credentials.yaml").write_text("provider_key: w2328-loopback-only\n", encoding="utf-8")
    return config

def pair_cli_failure_category(stderr: bytes) -> str:
    # Keep daemon/client diagnostics private: classify fixed public source
    # strings only, never persist the command stream or an invitation payload.
    text=stderr.decode("utf-8",errors="replace")
    if "companion v3 daemon unavailable: stale audit-RPC sidecar" in text: return "daemon_rpc_stale_sidecar"
    if "companion v3 daemon unavailable: RPC exchange" in text: return "daemon_rpc_exchange_deadline"
    if "companion v3 daemon unavailable: companion pair mint exchange with " in text and "exceeded the 20s deadline" in text: return "pair_mint_exchange_deadline"
    if "companion v3 daemon unavailable: read: " in text: return "daemon_rpc_read_failed"
    if "companion v3 daemon unavailable: malformed RPC response" in text: return "daemon_rpc_malformed_response"
    if "companion v3 daemon unavailable: connect " in text: return "daemon_rpc_transport_unavailable"
    if "companion v3 daemon unavailable:" in text: return "daemon_rpc_unavailable"
    if "companion v3 daemon refused request: HTTP 503" in text: return "companion_runtime_unavailable"
    if "companion v3 daemon refused request: HTTP 422" in text: return "companion_request_refused"
    if "companion v3 daemon refused request: HTTP 401" in text: return "daemon_rpc_authorization_refused"
    if "companion v3 daemon refused request: HTTP 404" in text: return "daemon_rpc_route_unavailable"
    if "companion v3 daemon refused request:" in text: return "daemon_rpc_refused_other"
    if "companion v3 daemon returned malformed response" in text: return "daemon_rpc_malformed_response"
    if "companion v3 requires the cluster feature" in text: return "companion_runtime_unavailable"
    return "unclassified"

PAIR_RPC_PARSE_FAILURES = (
    ("companion v3 daemon unavailable: malformed RPC response", "delimiter"),
    ("companion v3 daemon unavailable: RPC response did not use HTTP/1.1", "http_version"),
    ("companion v3 daemon unavailable: invalid RPC status code", "status"),
    ("companion v3 daemon unavailable: malformed RPC response header", "header"),
    ("companion v3 daemon unavailable: chunked RPC responses are not supported", "transfer_encoding"),
    ("companion v3 daemon unavailable: duplicate RPC Content-Length", "content_length_duplicate"),
    ("companion v3 daemon unavailable: invalid RPC Content-Length", "content_length_invalid"),
    ("companion v3 daemon unavailable: missing RPC Content-Length", "content_length_missing"),
    ("companion v3 daemon unavailable: RPC response body length mismatch", "content_length_mismatch"),
    ("companion v3 daemon returned malformed response", "companion_response_malformed"),
)
PAIR_RPC_PARSE_FAILURE_PREFIXES = (
    ("companion v3 daemon unavailable: invalid RPC headers: ", "headers_invalid"),
    ("companion v3 daemon unavailable: invalid RPC body: ", "body_invalid"),
    ("companion v3 daemon unavailable: invalid RPC JSON: ", "json_invalid"),
)

def pair_cli_failure_parse_subtype(stderr: bytes) -> str:
    # Result<()> may add `Error:`, anyhow context, and numbered cause-chain
    # prefixes. Match fixed source messages only as a complete line suffix;
    # retain just the closed enum, never stderr or formatter detail.
    text = stderr.decode("utf-8", errors="replace")
    for line in text.splitlines():
        line = line.strip()
        for message, subtype in PAIR_RPC_PARSE_FAILURES:
            if line.endswith(message):
                return subtype
        for prefix, subtype in PAIR_RPC_PARSE_FAILURE_PREFIXES:
            # These three source diagnostics append only Rust's formatter
            # detail; Result/anyhow may add a prefix before the source text.
            if prefix in line:
                return subtype
    return "unknown"
def invoke(argv: list[str], env: dict[str,str], timeout: float, pair_mint: bool = False) -> bytes:
    try: item = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
      stderr=subprocess.PIPE, timeout=timeout, check=False)
    except subprocess.TimeoutExpired: raise WorkDeadline("CLI budget exhausted")
    # Pairing stdout is a capability. Never reflect either stream into a CI log.
    if item.returncode:
        category=pair_cli_failure_category(item.stderr) if pair_mint else "cli_nonzero"
        parse_subtype=pair_cli_failure_parse_subtype(item.stderr) if pair_mint else "unknown"
        raise CliFailure(item.returncode,category,parse_subtype)
    return item.stdout

def stop_serve(serve: subprocess.Popen[bytes], cleanup_deadline: float) -> str:
    if serve.poll() is not None: return "already_exited"
    serve.send_signal(signal.SIGTERM)
    try:
        serve.wait(timeout=min(120.0,max(0.0,cleanup_deadline-time.monotonic())))
        return "graceful"
    except subprocess.TimeoutExpired:
        serve.kill()
        remaining=min(5.0,max(0.0,cleanup_deadline-time.monotonic()))
        if remaining:
            try: serve.wait(timeout=remaining)
            except subprocess.TimeoutExpired: return "forced_kill_unreaped"
        return "forced_kill"

def health(port_number: int, timeout: float) -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port_number}/healthz", timeout=timeout) as response:
            return response.status == 200
    except Exception: return False

def pair_url(raw: bytes) -> str:
    # The CLI serializes a complete invitation. Keep its capability fields in
    # memory and hand the URL-only FFI entry point exactly its public input.
    if len(raw) > PAIR_JSON_MAX: raise RuntimeError("pair CLI output over cap")
    try: value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError): raise RuntimeError("pair CLI output invalid")
    if not isinstance(value, dict): raise RuntimeError("pair CLI response invalid")
    value = value.get("pair_url")
    if not isinstance(value, str) or not value.startswith("neoth://companion/pair?"):
        raise RuntimeError("pair CLI response lacks valid pair_url")
    if not 0 < len(value.encode("utf-8")) <= PAIR_URL_MAX:
        raise RuntimeError("pair CLI pair_url over cap")
    return value

def cli_json(raw: bytes, label: str) -> Any:
    if len(raw) > MAX_PUBLIC: raise RuntimeError(f"{label} output over cap")
    try: return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError): raise RuntimeError(f"{label} output invalid")

def terminal(raw: bytes, kind: str) -> dict[str,Any]:
    value = cli_json(raw, "public terminal")
    expectation = {"paired":("state","paired"),"status":("state","status"),
                   "chat":("kind","chat"),"denied":("state","denied"),
                   "failed":("state","failed")}[kind]
    if not isinstance(value,dict) or value.get(expectation[0]) != expectation[1]:
        raise RuntimeError(f"unexpected {kind} terminal")
    return value

class Bridge:
    def __init__(self, shared: pathlib.Path):
        self.lib = ctypes.CDLL(str(shared))
        for name in SYMBOLS: getattr(self.lib,name)
        u8, size, ptr = ctypes.c_ubyte, ctypes.c_size_t, ctypes.c_void_p
        self.lib.neoth_companion_bridge_new.argtypes=[ctypes.POINTER(u8),size]; self.lib.neoth_companion_bridge_new.restype=ptr
        self.lib.neoth_companion_pair_start.argtypes=[ptr,ctypes.POINTER(u8),size,ctypes.POINTER(u8),size]
        self.lib.neoth_companion_reconnect_start.argtypes=[ptr,ctypes.POINTER(u8),size,ctypes.POINTER(u8),size]
        self.lib.neoth_companion_chat_start.argtypes=[ptr,ctypes.POINTER(u8),size,ctypes.POINTER(u8),size,ctypes.POINTER(u8),size]
        for name in ("neoth_companion_pair_start","neoth_companion_reconnect_start","neoth_companion_chat_start"): getattr(self.lib,name).restype=ptr
        self.lib.neoth_companion_operation_poll.argtypes=[ptr,ctypes.POINTER(u8),size,ctypes.POINTER(size)]; self.lib.neoth_companion_operation_poll.restype=ctypes.c_int32
        self.lib.neoth_companion_operation_cancel.argtypes=[ptr]; self.lib.neoth_companion_operation_free.argtypes=[ptr]; self.lib.neoth_companion_bridge_free.argtypes=[ptr]
        self.seed=(u8*32).from_buffer_copy(secrets.token_bytes(32)); self.handle=self.lib.neoth_companion_bridge_new(self.seed,32)
        if not self.handle: raise RuntimeError("bridge_new rejected transient seed")
    def close(self) -> None:
        if self.handle: self.lib.neoth_companion_bridge_free(self.handle); self.handle=None
        ctypes.memset(ctypes.addressof(self.seed),0,32)
    def call(self, name: str, *values: str, timeout: float = DEADLINE) -> tuple[int,bytes]:
        buffers=[(ctypes.c_ubyte*len(v.encode())).from_buffer_copy(v.encode()) for v in values]
        args: list[Any]=[self.handle]
        for value in buffers: args.extend((value,len(value)))
        op=getattr(self.lib,name)(*args)
        if not op: raise RuntimeError(f"{name} returned null")
        try:
            until=time.monotonic()+timeout
            while time.monotonic()<until:
                required=ctypes.c_size_t(); code=self.lib.neoth_companion_operation_poll(op,None,0,ctypes.byref(required))
                if code==PENDING: time.sleep(.125); continue
                if not 0<required.value<=MAX_PUBLIC: return code,b""
                out=(ctypes.c_ubyte*required.value)(); code=self.lib.neoth_companion_operation_poll(op,out,required.value,ctypes.byref(required))
                return code,bytes(out)
            self.lib.neoth_companion_operation_cancel(op)
            # The ABI owns cancellation. Give it a bounded poll window to
            # reach a terminal state before free; do not let Actions kill an
            # in-flight owned operation at the global work boundary.
            drain_until=time.monotonic()+15.0
            while time.monotonic()<drain_until:
                required=ctypes.c_size_t()
                if self.lib.neoth_companion_operation_poll(op,None,0,ctypes.byref(required)) != PENDING: break
                time.sleep(.125)
            raise WorkDeadline(f"{name} work deadline exhausted")
        finally:
            self.lib.neoth_companion_operation_free(op)
            for value in buffers: ctypes.memset(ctypes.addressof(value),0,len(value))

CHAT_FAILURE_TERMINAL_OUTCOMES = frozenset((
    "denied",
    "busy",
    "unavailable",
    "timeout",
    "indeterminate",
))
CHAT_FAILED_CODES = frozenset((
    "bridge_task_panicked",
    "invalid_reconnect_descriptor",
    "key_derivation_failed",
    "transport_start_failed",
    "transport_start_timeout",
    "transport_join_failed",
    "transport_closed",
    "chat_connect_timeout",
    "transport_read_failed",
    "chat_challenge_timeout",
    "invalid_server_frame",
    "invalid_chat_request",
))
CHAT_DENIED_CODES = frozenset((
    "daemon_key_mismatch",
    "invalid_chat_challenge",
    "device_denied",
    "invalid_frame",
    "retry_later",
    "unavailable",
))
CHAT_SCHEMA_VERSION = 3
CHAT_FAILURE_TERMINAL_SENTINEL = "malformed_or_nonterminal"

def chat_failure_terminal_diagnostic(raw: bytes) -> dict[str, Any]:
    malformed = {
        "terminal_kind": CHAT_FAILURE_TERMINAL_SENTINEL,
        "terminal_code": "unknown",
        "terminal_shape_valid": False,
    }
    try:
        value = cli_json(raw, "chat failure terminal")
    except RuntimeError:
        return malformed
    if not isinstance(value, dict):
        return malformed
    if value.get("kind") == "chat" and value.get("schema_version") == CHAT_SCHEMA_VERSION:
        outcome = value.get("outcome")
        if isinstance(outcome, str) and outcome in CHAT_FAILURE_TERMINAL_OUTCOMES:
            return {
                "terminal_kind": "chat",
                "terminal_code": outcome,
                "terminal_shape_valid": True,
            }
        return malformed
    if set(value) == {"state", "code"} and value.get("state") == "failed":
        code = value.get("code")
        if isinstance(code, str) and code in CHAT_FAILED_CODES:
            return {
                "terminal_kind": "failed",
                "terminal_code": code,
                "terminal_shape_valid": True,
            }
        return malformed
    if set(value) == {"state", "code"} and value.get("state") == "denied":
        code = value.get("code")
        if isinstance(code, str) and code in CHAT_DENIED_CODES:
            return {
                "terminal_kind": "denied",
                "terminal_code": code,
                "terminal_shape_valid": True,
            }
        return malformed
    if value == {"state": "cancelled"}:
        return {
            "terminal_kind": "cancelled",
            "terminal_code": "cancelled",
            "terminal_shape_valid": True,
        }
    return malformed

def record_chat_start_failure(receipt: dict[str, Any], code: int, raw: bytes) -> None:
    receipt["chat_start_failure"] = {
        "bridge_poll_code": code,
        **chat_failure_terminal_diagnostic(raw),
    }
def record_chat_start_observation(
    receipt: dict[str, Any],
    daemon_alive_before: bool,
    daemon_alive_after: bool,
    provider_request_delta: int,
    diagnostics: dict[str, Any],
) -> None:
    receipt["chat_start_daemon_alive_before"] = daemon_alive_before
    receipt["chat_start_daemon_alive_after"] = daemon_alive_after
    receipt["chat_start_provider_request_delta"] = provider_request_delta
    receipt["chat_start_diagnostics"] = diagnostics

def run_chat_pair_and_start(
    factory: Callable[[pathlib.Path], Any],
    library: pathlib.Path,
    pair_url_value: str,
    receipt: dict[str,Any],
    timeout: Callable[[], float],
    observe_chat_start: Callable[[str], None] | None = None,
) -> tuple[dict[str,Any],dict[str,Any]]:
    chat_bridge = factory(library)
    try:
        receipt["stage"]="pair_chat_start"
        code,raw=chat_bridge.call("neoth_companion_pair_start",pair_url_value,"w2328-chat",timeout=timeout())
        if code != OK:
            receipt["steps"]["chat_pair"]={"code":code,"validated":False}
            receipt["chat_pair_failure_code"]=code
            raise RuntimeError("chat pair rejected")
        chat_pair=terminal(raw,"paired")
        receipt["steps"]["chat_pair"]={"code":code,"validated":True}
        receipt["stage"]="chat_start"
        if observe_chat_start is not None:
            observe_chat_start("before")
        try:
            code,raw=chat_bridge.call("neoth_companion_chat_start",json.dumps(chat_pair["descriptor"],separators=(",",":")),chat_pair["device_id"],"W2328 interop canary",timeout=timeout())
        finally:
            if observe_chat_start is not None:
                observe_chat_start("after")
        if code != OK:
            record_chat_start_failure(receipt, code, raw)
            raise RuntimeError("chat rejected")
        try:
            chat = terminal(raw, "chat")
        except RuntimeError:
            record_chat_start_failure(receipt, code, raw)
            raise
        return chat_pair,chat
    finally:
        chat_bridge.close()

def main() -> int:
    process_started=time.monotonic()
    work_deadline=process_started+WORK_SECONDS
    cleanup_deadline=work_deadline+CLEANUP_RESERVE_SECONDS
    hosted_deadline=process_started+HOSTED_STEP_SECONDS
    if cleanup_deadline+START_MARGIN_SECONDS != hosted_deadline: raise RuntimeError("invalid work budget")
    ap=argparse.ArgumentParser(); ap.add_argument("--staging",type=pathlib.Path,required=True); ap.add_argument("--receipt",type=pathlib.Path,required=True); ap.add_argument("--allow-external-udp",action="store_true"); ns=ap.parse_args()
    if not ns.allow_external_udp: raise RuntimeError("explicit --allow-external-udp required for Peeroxide public bootstrap/UDP")
    manifest=json.loads((ns.staging/"host-interop-manifest.json").read_text())
    binary, library=ns.staging/"neoth",ns.staging/"libneoth_companion_bridge.so"
    if manifest.get("profile") != "debug" or manifest.get("required_symbols")!=list(SYMBOLS) or sha(binary)!=manifest["artifacts"]["neoth_sha256"] or sha(library)!=manifest["artifacts"]["bridge_sha256"]: raise RuntimeError("staged artifact custody mismatch")
    if ns.receipt.exists(): raise RuntimeError("receipt path must be fresh")
    receipt: dict[str,Any]={"schema":"neoth.wave2328.mobile-interop-r5-receipt.v1","source_head":manifest["source_head"],"artifact_hashes":manifest["artifacts"],"build_profile":manifest["profile"],"external_transport":"peeroxide-public-bootstrap-udp","steps":{}}
    budget(work_deadline)
    with tempfile.TemporaryDirectory(prefix="neoth-w2328-") as base, Loopback() as provider:
        receipt["work_deadline_seconds"]=int(WORK_SECONDS)
        receipt["cleanup_reserve_seconds"]=int(CLEANUP_RESERVE_SECONDS)
        receipt["scheduler_margin_seconds"]=int(START_MARGIN_SECONDS)
        home=pathlib.Path(base)/"home"; home.mkdir(mode=0o700); health_port,companion_port=port(),port()
        config=write_config(home,provider.url,health_port,companion_port)
        receipt["isolated_config_sha256"]=sha(config)
        env={**os.environ,"NEOTH_HOME":str(home),"NEOTH_COMPANION_DIAGNOSTICS":"1"}
        # Bind consent to this isolated loopback route through the public CLI.
        # The running daemon still rechecks that durable grant before dispatch.
        invoke([str(binary),"--output","json","consent","grant","openai_compat"],env,budget(work_deadline,20.0))
        receipt["steps"]["loopback_consent_granted"]={"granted":True}
        # Drain the merged daemon stream continuously; retain only fixed
        # shutdown markers and never raw output.
        serve=subprocess.Popen([str(binary),"serve","--config",str(config)],env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,bufsize=0)
        shutdown_markers=None
        bridge_diagnostics_previous=None
        bridge_diagnostics_set=False
        try:
            assert serve.stdout is not None
            shutdown_markers=ShutdownMarkerCollector(serve.stdout)
            bridge_diagnostics_previous=os.environ.get("NEOTH_COMPANION_DIAGNOSTICS")
            os.environ["NEOTH_COMPANION_DIAGNOSTICS"]="1"
            bridge_diagnostics_set=True
            readiness_deadline=min(time.monotonic()+30,work_deadline)
            while time.monotonic()<readiness_deadline and serve.poll() is None:
                if health(health_port,budget(work_deadline,2.0)): break
                time.sleep(min(.25,budget(work_deadline,.25)))
            else:
                if time.monotonic() >= work_deadline: raise WorkDeadline("serve readiness budget exhausted")
                receipt["serve_startup_state"] = "exited_before_ready" if serve.poll() is not None else "readiness_timeout"
                raise RuntimeError(f"serve readiness failed rc={serve.poll()}")
            bridge=Bridge(library)
            try:
                def mint_pair(scope: str, stage: str) -> bytes:
                    receipt["stage"]=stage
                    try: return invoke([str(binary),"--output","json","companion","pair-mobile","--scope",scope],env,budget(work_deadline,20.0),pair_mint=True)
                    except CliFailure as error:
                        receipt["pair_cli_failure_stage"]=stage
                        receipt["pair_cli_failure_category"]=error.category
                        receipt["pair_cli_failure_parse_subtype"]=error.parse_subtype
                        raise
                status_pair_url=pair_url(mint_pair("status-read","pair_status_read_mint"))
                receipt["stage"]="pair_status_start"
                code,raw=bridge.call("neoth_companion_pair_start",status_pair_url,"w2328-status",timeout=budget(work_deadline))
                status_pair=terminal(raw,"paired") if code==OK else (_ for _ in ()).throw(RuntimeError("status pair rejected"))
                receipt["steps"]["status_pair"]={"code":code,"validated":True}
                receipt["stage"]="status_reconnect_start"
                reconnect_cursor=shutdown_markers.scoped_connect_cursor()
                print("NEOTH_COMPANION_HOSTED_STAGE=status_reconnect_start",file=sys.stderr,flush=True)
                try:
                    code,raw=bridge.call("neoth_companion_reconnect_start",json.dumps(status_pair["descriptor"],separators=(",",":")),status_pair["device_id"],timeout=budget(work_deadline))
                finally:
                    # Observe before daemon-wide shutdown. The pipe reader can lag
                    # emission, so the receipt names an observation cursor only.
                    receipt["status_reconnect_diagnostics"]=shutdown_markers.scoped_connect_since(reconnect_cursor)
                    print("NEOTH_COMPANION_HOSTED_STAGE=status_reconnect_finished",file=sys.stderr,flush=True)
                status=terminal(raw,"status") if code==OK else (_ for _ in ()).throw(RuntimeError("status reconnect rejected"))
                receipt["steps"]["status"]={"code":code,"readiness":status.get("readiness"),"active_turns_known":status.get("active_turns") is not None}
                # Source-bound scope rejection: a status grant reaches the
                # status listener, which emits StatusChallenge. chat_start
                # accepts only ChatChallenge, so Bridge R2 returns this exact
                # FAILED terminal before a provider request is possible.
                receipt["stage"]="status_scope_chat_start"
                code,raw=bridge.call("neoth_companion_chat_start",json.dumps(status_pair["descriptor"],separators=(",",":")),status_pair["device_id"],"W2328 status-scope negative",timeout=budget(work_deadline))
                scope_rejection=terminal(raw,"failed") if code==FAILED else (_ for _ in ()).throw(RuntimeError("status-scope chat did not fail at frame boundary"))
                if scope_rejection.get("code") != "invalid_server_frame" or provider.server.request_count != 0:
                    raise RuntimeError("status-scope rejection/provider boundary missing")
                receipt["steps"]["status_scope_chat_rejected"]={"code":code,"failure_code":"invalid_server_frame","loopback_request_count":0}
                chat_pair_url=pair_url(mint_pair("chat-send","pair_chat_send_mint"))
                chat_provider_before = 0
                chat_cursor: dict[str, Any] | None = None
                def observe_chat_start(boundary: str) -> None:
                    nonlocal chat_provider_before, chat_cursor
                    if boundary == "before":
                        chat_provider_before = provider.server.request_count
                        chat_cursor = shutdown_markers.scoped_connect_cursor()
                        receipt["chat_start_daemon_alive_before"] = serve.poll() is None
                        return
                    if boundary != "after" or chat_cursor is None:
                        raise RuntimeError("invalid chat-start observation boundary")
                    record_chat_start_observation(
                        receipt,
                        receipt["chat_start_daemon_alive_before"],
                        serve.poll() is None,
                        provider.server.request_count - chat_provider_before,
                        shutdown_markers.scoped_connect_since(chat_cursor),
                    )
                chat_pair,chat=run_chat_pair_and_start(
                    Bridge,
                    library,
                    chat_pair_url,
                    receipt,
                    lambda: budget(work_deadline),
                    observe_chat_start,
                )
                records=chat.get("records",[])
                if provider.server.request_count != 1 or chat.get("outcome") != "accepted" or not any(isinstance(record,dict) and record.get("text") == REPLY for record in records):
                    raise RuntimeError("owned loopback provider/chat terminal proof missing")
                receipt["steps"]["chat"]={"code":OK,"outcome":chat.get("outcome"),"record_count":len(records),"provider":chat.get("provider"),"model":chat.get("model"),"loopback_request_count":provider.server.request_count,"reply_sha256":hashlib.sha256(REPLY.encode()).hexdigest().upper()}
                receipt["stage"]="device_revoke"
                revoke=cli_json(invoke([str(binary),"--output","json","companion","devices","revoke",chat_pair["device_id"]],env,budget(work_deadline,20.0)),"revoke")
                if revoke != {"revoked": True}: raise RuntimeError("revoke result was not exact success")
                receipt["stage"]="device_status_readback"
                views=cli_json(invoke([str(binary),"--output","json","companion","devices","status",chat_pair["device_id"]],env,budget(work_deadline,20.0)),"device status")
                if not isinstance(views,list) or len(views) != 1 or not isinstance(views[0],dict):
                    raise RuntimeError("device status was not one public view")
                view=views[0]
                expected_revision=chat_pair.get("revision")
                if view.get("device_id") != chat_pair["device_id"] or view.get("grant_state") != "revoked" or not isinstance(expected_revision,int) or view.get("revision") != expected_revision + 1:
                    raise RuntimeError("durable revoke state/revision proof missing")
                if provider.server.request_count != 1: raise RuntimeError("provider count changed after revoke")
                receipt["steps"]["revoke"]={"revoked":True,"grant_state":"revoked","revision_advanced":True,"loopback_request_count":1}
            finally: bridge.close()
            receipt["outcome"]="passed"
        except WorkDeadline:
            receipt["outcome"]="failed"; receipt["failure_category"]="work_deadline"
            raise
        except Exception:
            receipt["outcome"]="failed"; receipt["failure_category"]="bounded_failure"
            raise
        finally:
            active_exception=sys.exc_info()[0] is not None
            try: shutdown=stop_serve(serve,cleanup_deadline)
            except Exception: shutdown="shutdown_error"
            if bridge_diagnostics_set:
                if bridge_diagnostics_previous is None:
                    os.environ.pop("NEOTH_COMPANION_DIAGNOSTICS",None)
                else:
                    os.environ["NEOTH_COMPANION_DIAGNOSTICS"]=bridge_diagnostics_previous
            receipt["serve_exit_code"]=serve.returncode
            receipt["serve_shutdown"]=shutdown
            if shutdown_markers is not None:
                receipt["serve_shutdown_markers"]=shutdown_markers.snapshot(cleanup_deadline-time.monotonic())
            else:
                if serve.stdout is not None: serve.stdout.close()
                receipt["serve_shutdown_markers"]={"markers":{name:False for name,_ in SHUTDOWN_MARKERS},"rust_panic_observed":False,"rust_panic_site":None,"pair_markers":{name:False for name,_ in PAIR_MARKERS},"discovery_markers":{name:False for name,_ in DISCOVERY_MARKERS},"connect_markers":{name:False for name,_ in CONNECT_MARKERS},"scoped_connect_counts":{name:0 for name,_ in SCOPED_CONNECT_MARKERS},"scoped_connect_saturated":False,"reader_closed":True,"reader_error":True}
            cleanup_failure = (
                "forced_kill" if shutdown.startswith("forced_kill") else
                "shutdown_error" if shutdown == "shutdown_error" else
                "nonzero_exit" if serve.returncode not in (0,None) else None
            )
            if cleanup_failure:
                receipt["cleanup_failure_category"]=cleanup_failure
                receipt["outcome"]="failed"
                if not active_exception: receipt["failure_category"]="serve_cleanup_failure"
            ns.receipt.parent.mkdir(parents=True,exist_ok=True); ns.receipt.write_text(json.dumps(receipt,sort_keys=True,separators=(",",":"))+"\n")
            if cleanup_failure and not active_exception:
                raise RuntimeError(f"serve cleanup failed category={cleanup_failure}")
    return 0
if __name__=="__main__":
    try: raise SystemExit(main())
    except Exception as exc: print(f"W2328 R8 failed: {brief(str(exc))}",file=sys.stderr); raise SystemExit(1)
