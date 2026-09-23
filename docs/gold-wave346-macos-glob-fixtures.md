# W346 — macOS-safe W279 glob fixtures

Four W279 tests create a `TempDir` and exercise the production no-follow
filesystem gate. macOS commonly exposes that directory through `/var/...`,
where `/var` aliases `/private/var`; the gate correctly rejects the alias
before any fixture assertion runs.

Each affected test now retains its `TempDir`, creates all fixture files through
that handle, and derives one canonical `root_path` for both the gate and the
pre-tool-use context. This preserves the exact tested capability root while
removing the macOS display-path alias from the test setup.

The production `open_absolute_directory_no_follow` implementation and its
parent traversal are unchanged. The symlink-entry fixture still creates an
actual untrusted child symlink and asserts that glob discovery neither returns
nor follows it.

No local compiler, formatter, test, parser, or runtime command was run under
the BSOD hold. Hosted macOS validation must run the four W279 fixtures and the
normal selected formatting/compile gate.
