# Wave 357 fixture scope repair

The hosted core test-target check in run `35848398917` at commit `3978`
reported two `E0425` errors after the production slim-core Clippy job passed.

- The affected `chat.rs` test already used `open`, `RepoMap`, and `ScanReport`
  from the code-map persistence fixture. Its second `persist_map` call lacked
  the matching test-local import, which is now included.
- `reflection/retention_v2_tests.rs` cannot access the similarly named helper
  private to `reflection::periodic::tests`. It now has its own test-local,
  byte-equivalent Daily JSONL archive fixture. This preserves the test's direct
  historical-archive setup without widening test-module visibility.

No production code path or local executable command changed. GitHub must rerun
the exact test-target check to prove the repaired head.
