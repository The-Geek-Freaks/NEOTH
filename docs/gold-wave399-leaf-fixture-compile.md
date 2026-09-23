# W399 authenticated-leaf fixture compile repair

Hosted Core118 passed the production slim-Clippy step and failed only while
type-checking test targets. The eight diagnostics were confined to newly added
authenticated-leaf fixtures in `wal/redact.rs`:

- three unresolved `HeaderBuilder` references;
- four `super::events` paths that became invalid inside the nested test module;
- one borrowed `Cow` from `logical_segment_bytes` whose temporary file-byte
  buffer ended before the later frame assertions.

The fixtures now import `crate::wal::{events, HeaderBuilder}`, use that module
for the four event constants, and retain the rewritten file bytes in a local
binding for the full lifetime of the logical-frame assertions.

No fixture assertion, authenticated marker verification, production behavior,
or WAL format changed. Hosted test-target type-check and the normal follow-up
gates remain required to validate this exact source revision.
