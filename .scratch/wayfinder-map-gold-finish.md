# Map: NEOTH v1.0 Gold — the way to a taggable release

`wayfinder:map` · local-markdown tracker · created 2026-07-31

## Destination

A `v1.0.0` tag that is *earned*: `PLAN/ROAD_TO_1_0_GOLD.md` has no pre-tag
blocker left, the exact release head passes full CI, security and CodeQL on
Windows/macOS/Linux, and every advertised feature is wired end to end. Reaching
it means the remaining 233 blockers are each either closed or consciously
ruled out of v1.0 — not that they were quietly reclassified.

## Notes

- Domain: Rust daemon + CLI + Slint GUI, WAL-backed audit, multi-provider inference.
- Source of truth for scope: `PLAN/ROAD_TO_1_0_GOLD.md`. Progress narrative: `PLAN/PROGRESS_v1_0.md`. Both updated in the same commit as the work.
- Skills every session should consult: `system-design-101` for any architectural choice, `impeccable` for GUI/design work, `graphify` before grep for structure questions, `research` subagents for anything outside this working directory.
- Verification standard: a claim is worth what its test output is worth. Run the command, read the output, then say it. Never a source-string assertion where process behaviour is the thing under test — that class of gate already rubber-stamped one broken bound here.
- A parallel Codex line edits this working tree. Stage exact paths, never `git add -A`.
- Local build reality: MSVC gates under `SRC/_*.bat`, `CARGO_BUILD_JOBS=2`, `--test-threads=1`. Full-workspace runs are expensive; scope them.

## Decisions so far

- [Bound every provider response envelope](../PLAN/ROAD_TO_1_0_GOLD.md) — every external byte stream (8 HTTP transports, Claude CLI, tmux, PTY, sidecar) reads under a hard cap with digest-only diagnostics; `tests/provider_response_bounds_source_gate.rs` is the no-bypass ratchet.
- [Bound the transport, not just the buffer](../PLAN/PROGRESS_v1_0.md) — a capped `Vec` is not a bounded process. Every local reader now also bounds lifetime: drain-to-EOF, absolute deadline, kill-and-reap on truncation, sidecar reset on framing failure.
- [WAL fixtures follow production, not the reverse](../PLAN/PROGRESS_v1_0.md) — 8 of 10 red tests were fixtures asserting on internal segment layout that the R3-18A hardening legitimately changed. Production was right every time; the invariant was never weakened for a test.

## Tickets

### T1 — Must a redaction's own audit segment verify like any other? · open · `wayfinder:grilling` · unblocked · claimed
`SRC/neothd/src/cli/verify.rs:1299`.

**Narrowed by investigation.** The exemption is not broken: the final
`run_verify` reports `authorised_redaction_count: 1` and
`operator_authorised_redactions: 1`, and the failure for the redacted segment
`000001.wal` is gone. The signed 0xF3 does reclassify the window it covers.

What remains failing are two *other* segments, both written by the test's own
run: `attacker-audit.wal` and `redact-audit.wal`. Each reports an HMAC
mismatch over its whole window. So `run_verify` now walks every segment in the
home, including the audit trails that the redaction path itself produces, and
those trails do not carry markers it accepts.

The decision, not yet made:
- **(a)** Redaction-audit segments are ordinary WAL segments and must publish
  markers `run_verify` accepts — then the writing path has a real gap, and this
  is a production fix, not a fixture fix.
- **(b)** They are a distinct artifact class, deliberately outside the marker
  contract — then `run_verify` needs to say so explicitly rather than reporting
  them as tampered, and the fixture's expectation is right but its assertion
  is aimed at the wrong scope.

Resolving means picking (a) or (b) with a reason, not making the assert pass.
T2 (`verify.rs:1431`) very likely resolves with whichever is chosen.

### T2 — Does `scan_and_redact` hold its contract on a compressed sealed segment? · open · `wayfinder:grilling` · unblocked
`SRC/neothd/src/cli/verify.rs:1431`. Same family as T1; may resolve with it.

### T3 — What does an exact-head release-candidate run actually have to cover? · open · `wayfinder:task` · blocked by T1, T2
Full CI, security, CodeQL, feature combinations, three platforms. Cannot start
while any test is knowingly red. Resolution records the exact workflow set and
the observed result per platform.

### T4 — Which of the 233 pre-tag blockers are genuinely v1.0, and which are v1.1? · open · `wayfinder:grilling` · unblocked
The roadmap counts 1,222 boxes with 233 pre-tag blockers. Some are hard release
contracts (artifacts, installers, parity); others are refinements that a tagged
v1.0 can live without. This ticket produces the split — and it is HITL, because
scope is the operator's call, not the agent's.

### T5 — What is the smallest honest release artifact matrix? · open · `wayfinder:research` · blocked by T4
`GOLD-R4-01a..f` enumerate Alpine, glibc floor, RPM, Windows, macOS
qualification. Determine which are release-blocking for a first tag versus
documented-unsupported.

## Not yet specified

- The GUI lane: `GOLD-R4-05` capability parity and `GOLD-R4-09` accessibility are large and unscoped here; they need their own charting pass once T4 fixes what counts as v1.0.
- `R3-18A` key-epoch frontier and redaction-stable commitments — sharp enough to describe, not yet sharp enough to ticket without deciding how much of it v1.0 needs (depends on T4).
- Cluster completion (`GOLD-R4-13a..l`), Mobile Companion (`R4-12`), channel parity (`R4-07`) — same dependency.

## Out of scope

- Anything that redraws the destination itself (a v2 feature set, a different
  distribution model). Those return as a fresh effort, not a resumption.
