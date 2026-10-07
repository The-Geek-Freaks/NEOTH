#!/usr/bin/env python3
"""Test-only MCP fixture: `arguments.activity_is_error` selects isError."""
import json
import pathlib
import sys

def reply(request_id, result):
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result}) + "\n")
    sys.stdout.flush()

def main():
    counter = pathlib.Path(sys.argv[1])
    for raw in sys.stdin:
        value = json.loads(raw)
        method, request_id = value.get("method"), value.get("id")
        if method == "initialize":
            reply(request_id, {"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"activity-fixture","version":"1"}})
        elif method == "tools/call":
            args = value.get("params", {}).get("arguments", {})
            count = int(counter.read_text()) if counter.exists() else 0
            counter.write_text(str(count + 1))
            reply(request_id, {"content":[{"type":"text","text":"fixture activity result"}], "isError": bool(args.get("activity_is_error"))})
        elif method == "tools/list":
            reply(request_id, {"tools":[{"name":"read","annotations":{"readOnlyHint":True}}]})

if __name__ == "__main__":
    main()
