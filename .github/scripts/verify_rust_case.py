"""Verify one discovered Rust libtest case despite interleaved diagnostics."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

SUMMARY = re.compile(
    r"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; "
    r"\d+ filtered out; finished in \d+(?:\.\d+)?s"
)


def verify_case(identity: str, text: str, exit_code: int) -> dict[str, object]:
    lines = text.splitlines()
    prefix = f"test {identity} ... "
    named = [line for line in lines if line.startswith("test ") and not line.startswith("test result:")]
    terminals = [line for line in lines if line.startswith("test result:")]
    exact_start = len(named) == 1 and named[0].startswith(prefix)
    inline_ok = exact_start and named[0] == prefix + "ok"
    split_ok = exact_start and named[0] != prefix + "ok" and lines.count("ok") == 1
    checks = {
        "identity_valid": bool(identity) and not any(char.isspace() for char in identity),
        "exit_zero": exit_code == 0,
        "discovered_once": lines.count(identity + ": test") == 1,
        "one_case_started": lines.count("running 1 test") == 1 and exact_start,
        "successful_case_terminal": inline_ok or split_ok,
        "one_successful_summary": len(terminals) == 1 and SUMMARY.fullmatch(terminals[0]) is not None,
    }
    return {
        "schema": "neoth.exact-rust-case.v1",
        "identity": identity,
        "exit_code": exit_code,
        "accepted": all(checks.values()),
        "checks": checks,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--identity", required=True)
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--exit-code", required=True, type=int)
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args()
    result = verify_case(args.identity, args.log.read_text(encoding="utf-8"), args.exit_code)
    args.receipt.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return 0 if result["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
