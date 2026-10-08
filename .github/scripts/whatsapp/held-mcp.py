#!/usr/bin/env python3
"""Hosted-only held MCP child. Each actual process identity is retained for reap checks."""
import json
import os
import pathlib
import sys
import time

if os.environ.get("GITHUB_ACTIONS") != "true":
    raise SystemExit("hosted runner required")
root = pathlib.Path(sys.argv[1])
mode = sys.argv[2]
if not root.is_absolute() or mode not in ("success", "tool_error", "disabled", "cancel"):
    raise SystemExit("invalid fixture")
# Linux identity includes birth tick, preventing cleanup of a reused PID.
birth = pathlib.Path("/proc/self/stat").read_text().rsplit(")", 1)[1].split()[19]
with (root / "children.jsonl").open("a") as stream:
    stream.write(json.dumps({"pid": os.getpid(), "birth": birth}) + "\n")

def reply(identity, value):
    print(json.dumps({"jsonrpc": "2.0", "id": identity, "result": value}), flush=True)

for raw in sys.stdin:
    request = json.loads(raw)
    method, identity = request.get("method"), request.get("id")
    if method == "initialize":
        reply(identity, {"protocolVersion": "2025-11-25", "capabilities": {},
                         "serverInfo": {"name": "w2511-held", "version": "1"}})
    elif method == "tools/list":
        reply(identity, {"tools": [{"name": "read", "annotations": {"readOnlyHint": True}}]})
    elif method == "tools/call":
        if request.get("params", {}).get("name") != "read":
            raise SystemExit("unexpected tool")
        with (root / "calls").open("a") as stream:
            stream.write("read\n")
        (root / "entered").write_text("entered\n")
        deadline = time.monotonic() + 90
        while not (root / "release").is_file():
            if time.monotonic() > deadline:
                raise SystemExit("release deadline")
            time.sleep(0.05)
        is_error = mode == "tool_error"
        reply(identity, {"content": [{"type": "text", "text": "W2511_FIXTURE_ERROR" if is_error
                                     else "W2511_FIXTURE_OK"}], "isError": is_error})
