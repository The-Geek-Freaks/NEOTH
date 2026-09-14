#!/usr/bin/env python3
"""Strict NDJSON MCP fixture used only by Rust integration-style unit tests."""
import json
import pathlib
import sys


def reply(request_id, result):
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result}) + "\n")
    sys.stdout.flush()


def count(counter):
    prior = int(counter.read_text(encoding="utf-8")) if counter.exists() else 0
    counter.write_text(str(prior + 1), encoding="utf-8")


def main():
    if len(sys.argv) != 2:
        raise SystemExit("expected one absolute counter path")
    counter = pathlib.Path(sys.argv[1])
    if not counter.is_absolute():
        raise SystemExit("counter path must be absolute")
    for raw in sys.stdin:
        if not raw.endswith("\n"):
            raise SystemExit("strict NDJSON requires newline")
        value = json.loads(raw)
        method = value.get("method")
        request_id = value.get("id")
        if method == "notifications/initialized":
            continue
        if method == "initialize":
            reply(request_id, {"protocolVersion": "2025-11-25", "capabilities": {}, "serverInfo": {"name": "fixture", "version": "1"}})
        elif method == "tools/list":
            reply(request_id, {"tools": [{"name": "read", "annotations": {"readOnlyHint": True}}]})
        elif method == "tools/call":
            count(counter)
            args = value.get("params", {}).get("arguments", {})
            reply(request_id, {"content": [{"type": "text", "text": "fixture-result:" + json.dumps(args, sort_keys=True)}], "isError": False})
        else:
            reply(request_id, {})


if __name__ == "__main__":
    main()
