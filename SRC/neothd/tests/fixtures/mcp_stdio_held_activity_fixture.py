#!/usr/bin/env python3
"""Test-only held MCP read fixture for hosted mobile activity acceptance."""
import json
import pathlib
import sys
import time

HOLD_SECONDS = 90.0

def reply(request_id, result):
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result}) + "\n")
    sys.stdout.flush()

def increment(counter):
    count = int(counter.read_text()) if counter.exists() else 0
    counter.write_text(str(count + 1))

def wait_for_release(release):
    deadline = time.monotonic() + HOLD_SECONDS
    while time.monotonic() < deadline:
        if release.is_file():
            return
        time.sleep(0.05)
    raise RuntimeError("held activity fixture release deadline exhausted")

def main():
    if len(sys.argv) != 4:
        raise RuntimeError("expected absolute counter, entered, and release paths")
    counter, entered, release = (pathlib.Path(value) for value in sys.argv[1:])
    if not all(path.is_absolute() for path in (counter, entered, release)):
        raise RuntimeError("fixture paths must be absolute")
    for raw in sys.stdin:
        value = json.loads(raw)
        method, request_id = value.get("method"), value.get("id")
        if method == "initialize":
            reply(request_id, {"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"held-activity-fixture","version":"1"}})
        elif method == "tools/list":
            reply(request_id, {"tools":[{"name":"read","annotations":{"readOnlyHint":True}}]})
        elif method == "tools/call":
            increment(counter)
            entered.write_text("entered\n")
            wait_for_release(release)
            reply(request_id, {"content":[{"type":"text","text":"held fixture activity result"}],"isError":False})

if __name__ == "__main__":
    main()
