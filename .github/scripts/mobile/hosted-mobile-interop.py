#!/usr/bin/env python3
"""W2328 R8 hosted real-CLI/cdylib interop runner; never run under local hold."""
from __future__ import annotations
import argparse, ctypes, hashlib, http.server, json, os, pathlib, secrets
import signal, socket, socketserver, subprocess, sys, tempfile, threading, time
import urllib.request
from typing import Any

PENDING, OK, FAILED = 0, 1, 3
MAX_PUBLIC, PAIR_JSON_MAX, PAIR_URL_MAX, DEADLINE = 80 * 1024, 8 * 1024, 512, 140.0
HOSTED_STEP_SECONDS, CLEANUP_RESERVE_SECONDS, START_MARGIN_SECONDS = 600.0, 180.0, 30.0
WORK_SECONDS = HOSTED_STEP_SECONDS - CLEANUP_RESERVE_SECONDS - START_MARGIN_SECONDS

class WorkDeadline(RuntimeError): pass
REPLY = "W2328 deterministic loopback reply"
SYMBOLS = ("neoth_companion_bridge_new","neoth_companion_pair_start",
 "neoth_companion_reconnect_start","neoth_companion_chat_start",
 "neoth_companion_operation_poll","neoth_companion_operation_cancel",
 "neoth_companion_operation_free","neoth_companion_bridge_free")

def sha(path: pathlib.Path) -> str: return hashlib.sha256(path.read_bytes()).hexdigest().upper()
def brief(value: str) -> str: return value.replace("\n", " ").replace("\r", " ")[:160]
def port() -> int:
    with socket.socket() as sock: sock.bind(("127.0.0.1", 0)); return sock.getsockname()[1]
def budget(deadline: float, cap: float = DEADLINE) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0: raise WorkDeadline("work deadline exhausted")
    return min(cap, remaining)

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
      f"operator_id: w2328-hosted\nsecrets_backend: file\nprovider_kind: openai_compat\n"
      f"provider_endpoint: {provider_url}\nprovider_model: w2328-loopback-model\n"
      f"observability_listen: 127.0.0.1:{health_port}\ncompanion:\n  enabled: true\n"
      f"  port: {companion_port}\n  p2p_enabled: true\n", encoding="utf-8")
    # Local canary value only. It is never emitted and the provider ignores it.
    (home / "credentials.yaml").write_text("provider_key: w2328-loopback-only\n", encoding="utf-8")
    return config

def invoke(argv: list[str], env: dict[str,str], timeout: float) -> bytes:
    try: item = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
      stderr=subprocess.PIPE, timeout=timeout, check=False)
    except subprocess.TimeoutExpired: raise WorkDeadline("CLI budget exhausted")
    # Pairing stdout is a capability. Never reflect either stream into a CI log.
    if item.returncode: raise RuntimeError(f"CLI failed rc={item.returncode}")
    return item.stdout

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

def main() -> int:
    process_started=time.monotonic()
    work_deadline=process_started+WORK_SECONDS
    cleanup_deadline=work_deadline+CLEANUP_RESERVE_SECONDS
    if cleanup_deadline+START_MARGIN_SECONDS != process_started+HOSTED_STEP_SECONDS: raise RuntimeError("invalid work budget")
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
        env={**os.environ,"NEOTH_HOME":str(home)}
        # Do not PIPE an unconsumed daemon stream: it can deadlock, and daemon
        # output may contain configuration diagnostics. Receipt carries only rc.
        serve=subprocess.Popen([str(binary),"serve","--config",str(config)],env=env,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            readiness_deadline=min(time.monotonic()+30,work_deadline)
            while time.monotonic()<readiness_deadline and serve.poll() is None:
                if health(health_port,budget(work_deadline,2.0)): break
                time.sleep(min(.25,budget(work_deadline,.25)))
            else:
                if time.monotonic() >= work_deadline: raise WorkDeadline("serve readiness budget exhausted")
                raise RuntimeError(f"serve readiness failed rc={serve.poll()}")
            bridge=Bridge(library)
            try:
                pair=lambda scope: invoke([str(binary),"--output","json","companion","pair-mobile","--scope",scope],env,budget(work_deadline,20.0))
                code,raw=bridge.call("neoth_companion_pair_start",pair_url(pair("status-read")),"w2328-status",timeout=budget(work_deadline))
                status_pair=terminal(raw,"paired") if code==OK else (_ for _ in ()).throw(RuntimeError("status pair rejected"))
                code,raw=bridge.call("neoth_companion_reconnect_start",json.dumps(status_pair["descriptor"],separators=(",",":")),status_pair["device_id"],timeout=budget(work_deadline))
                status=terminal(raw,"status") if code==OK else (_ for _ in ()).throw(RuntimeError("status reconnect rejected"))
                receipt["steps"]["status"]={"code":code,"readiness":status.get("readiness"),"active_turns_known":status.get("active_turns") is not None}
                # Source-bound scope rejection: a status grant reaches the
                # status listener, which emits StatusChallenge. chat_start
                # accepts only ChatChallenge, so Bridge R2 returns this exact
                # FAILED terminal before a provider request is possible.
                code,raw=bridge.call("neoth_companion_chat_start",json.dumps(status_pair["descriptor"],separators=(",",":")),status_pair["device_id"],"W2328 status-scope negative",timeout=budget(work_deadline))
                scope_rejection=terminal(raw,"failed") if code==FAILED else (_ for _ in ()).throw(RuntimeError("status-scope chat did not fail at frame boundary"))
                if scope_rejection.get("code") != "invalid_server_frame" or provider.server.request_count != 0:
                    raise RuntimeError("status-scope rejection/provider boundary missing")
                receipt["steps"]["status_scope_chat_rejected"]={"code":code,"failure_code":"invalid_server_frame","loopback_request_count":0}
                code,raw=bridge.call("neoth_companion_pair_start",pair_url(pair("chat-send")),"w2328-chat",timeout=budget(work_deadline))
                chat_pair=terminal(raw,"paired") if code==OK else (_ for _ in ()).throw(RuntimeError("chat pair rejected"))
                code,raw=bridge.call("neoth_companion_chat_start",json.dumps(chat_pair["descriptor"],separators=(",",":")),chat_pair["device_id"],"W2328 interop canary",timeout=budget(work_deadline))
                chat=terminal(raw,"chat") if code==OK else (_ for _ in ()).throw(RuntimeError("chat rejected"))
                records=chat.get("records",[])
                if provider.server.request_count != 1 or chat.get("outcome") != "accepted" or not any(isinstance(record,dict) and record.get("text") == REPLY for record in records):
                    raise RuntimeError("owned loopback provider/chat terminal proof missing")
                receipt["steps"]["chat"]={"code":code,"outcome":chat.get("outcome"),"record_count":len(records),"provider":chat.get("provider"),"model":chat.get("model"),"loopback_request_count":provider.server.request_count,"reply_sha256":hashlib.sha256(REPLY.encode()).hexdigest().upper()}
                revoke=cli_json(invoke([str(binary),"--output","json","companion","devices","revoke",chat_pair["device_id"]],env,budget(work_deadline,20.0)),"revoke")
                if revoke != {"revoked": True}: raise RuntimeError("revoke result was not exact success")
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
            if serve.poll() is None:
                serve.send_signal(signal.SIGTERM)
                try: serve.wait(timeout=15)
                except subprocess.TimeoutExpired: serve.kill(); serve.wait(timeout=5)
            receipt["serve_exit_code"]=serve.returncode
            ns.receipt.parent.mkdir(parents=True,exist_ok=True); ns.receipt.write_text(json.dumps(receipt,sort_keys=True,separators=(",",":"))+"\n")
    return 0
if __name__=="__main__":
    try: raise SystemExit(main())
    except Exception as exc: print(f"W2328 R8 failed: {brief(str(exc))}",file=sys.stderr); raise SystemExit(1)
