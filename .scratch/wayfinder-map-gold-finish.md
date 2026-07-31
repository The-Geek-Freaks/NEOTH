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
- **Unix paths are unverifiable locally.** This is a Windows workstation, so every `#[cfg(unix)]` block is never compiled here — not by `cargo check`, not by clippy, not with `--no-default-features`. Three separate defects reached `main` through that blind spot in one session (a `cap_std` trait mismatch, a `needless_borrow`, a `needless_return`). When a change touches a `cfg(unix)` block, the CI run is not confirmation of a local green — it is the only verification that exists. Trigger it and read the job log via `gh api repos/.../actions/jobs/<id>/logs`, which works while the overall run is still in progress.

## Decisions so far

- [Bound every provider response envelope](../PLAN/ROAD_TO_1_0_GOLD.md) — every external byte stream (8 HTTP transports, Claude CLI, tmux, PTY, sidecar) reads under a hard cap with digest-only diagnostics; `tests/provider_response_bounds_source_gate.rs` is the no-bypass ratchet.
- [Bound the transport, not just the buffer](../PLAN/PROGRESS_v1_0.md) — a capped `Vec` is not a bounded process. Every local reader now also bounds lifetime: drain-to-EOF, absolute deadline, kill-and-reap on truncation, sidecar reset on framing failure.
- [WAL fixtures follow production, not the reverse](../PLAN/PROGRESS_v1_0.md) — 8 of 10 red tests were fixtures asserting on internal segment layout that the R3-18A hardening legitimately changed. Production was right every time; the invariant was never weakened for a test.

## Tickets

### T1 — Must a redaction's own audit segment verify like any other? · **resolved (a)** · `wayfinder:grilling`
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

**Resolution:** **(a) — test fixture gap, not a production gap. No change to
`run_verify`; the writer side needs a home-bound spawn in the test.**

**Evidence per question:**

1. **Writer identity** — Production: `run_physical_redaction`
   (`cli/memory.rs:1301`) calls
   `crate::wal::writer::spawn_for_home_with_completion(audit_segment, home)`.
   That function (`writer.rs:997`) uses
   `hmac_key_path = home.join("wal").join("hmac.key")` and passes
   `skip_compaction_markers: false` — the full authenticated writer contract,
   identical to any data segment. Tests: both `redact-audit.wal`
   (`verify.rs:1283`, `1446`) and `attacker-audit.wal` (`verify.rs:1102`)
   are created via the test-only `pub fn spawn()` (`writer.rs:926`), which
   calls `spawn_with_policy_and_compression` (`writer.rs:1322-1339`) and
   hard-codes `crate::wal::compaction::default_key_path()` — the process-global
   `~/.neoth/wal/hmac.key`, not the per-test tempdir key.

2. **HMAC identity** — The writer emits COMPACTION_MARKERs (`skip_compaction_markers: false`).
   In production the markers are signed with `home/wal/hmac.key`. In the test
   the same markers are signed with the global `~/.neoth/wal/hmac.key`. The test
   loads `wal_dir.join("hmac.key")` (`verify.rs:1181`) — a freshly generated
   per-test key that does not match the global one. HMAC mismatch is therefore
   certain in the test; impossible in production.

3. **`run_verify` segment classification** — `list_segments` (`verify.rs:395-411`)
   collects every `*.wal` file in the directory with no name filter.
   `extract_markers_with_offsets_from` (`verify.rs:556-585`) looks only for
   `EVENT_TYPE_COMPACTION_MARKER` (0xF0). A segment carrying only 0xF3
   REDACTION_MARKER frames would produce zero markers and zero failures — it
   would verify clean. The problem is specifically that the audit segments in the
   test DO carry COMPACTION_MARKERs (from `spawn()`) signed with the wrong key.
   No name-based class distinction exists today or is needed.

4. **Other consumers** — `for_each_frame_at_home` (`wal/scan.rs:364`) enforces
   `canonical_segment_name` (`scan.rs:282`): a name must match
   `(<namespace>-)?NNNNNN.wal` with exactly six decimal digits.
   `attacker-audit.wal` and `redact-audit.wal` fail this check (sequence part
   "audit" is not digits) and would cause the scanner to bail with an error —
   they can only exist in test tempdirs. The production audit segment is
   named via `unique_standalone_segment_path(wal_dir, "memory-redact")`
   (`memory.rs:1262`) which generates `memory-redact-<uuid7>-000001.wal` — a
   canonical name that recall, compaction, and doctor all process normally. No
   consumer applies a special-class exemption to audit segments.

5. **Security** — Option (b) would require `run_verify` to skip or soften HMAC
   checking for files matching a name pattern such as `*-audit.wal`. An attacker
   with WAL write access (the same prerequisite as segment tampering) could name
   a forged or tampered segment to match that pattern and have it bypass integrity
   verification entirely. Option (a) closes this: every `*.wal` file is checked
   uniformly; the name grants no exemption.

**Changes required:**

- **Production (`cli/memory.rs`, `wal/writer.rs`):** None. The production writer
  path already uses `spawn_for_home_with_completion` with the correct home-bound
  HMAC key. `run_verify` would accept those markers.

- **Test fixture — `redact-audit.wal` (`verify.rs:1283`, `verify.rs:1446`):**
  The test calls `crate::wal::writer::spawn(wal_dir.join("redact-audit.wal"))`.
  This must be replaced by a writer that derives its HMAC key from the test's
  own key path (`wal_dir.join("hmac.key")`). Cleanest path: add a
  `#[cfg(test)]` function in `writer.rs` —
  `pub fn spawn_with_hmac_key_path(segment: PathBuf, hmac_key_path: PathBuf)`
  — that calls `spawn_with_policy_and_compression_at_home` with the explicit
  key path and `skip_compaction_markers: false`. Alternatively, restructure the
  test tempdir to a proper `home/wal/` layout so `spawn_for_home` can be used
  directly (requires adjusting `wal_dir`, `key_path`, and `VerifyArgs`).

- **Test fixture — `attacker-audit.wal` (`verify.rs:1074`
  `write_signed_redaction_frame`, called at `verify.rs:1102`, `1265`):**
  The attacker helper also uses `spawn()` (global key). Since the assertion at
  `verify.rs:1276` is `is_err()`, the test accidentally passes — but for a
  wrong reason (HMAC mismatch in the attacker's own compaction marker, not
  because the attacker's 0xF3 was rejected). The semantically correct model: a
  realistic attacker writing a raw 0xF3 frame would not own a
  properly-HMAC-keyed writer at all. Fix: spawn with `skip_compaction_markers:
  true` (needs a test-only `spawn_no_markers` variant), or write the frame
  bytes manually without a compaction writer, so the segment contains only the
  0xF3 frame and no compaction markers.

- **T2 (`verify.rs:1431`):** Identical root cause — line `1446` repeats the
  same `spawn(wal_dir.join("redact-audit.wal"))` call. Resolves with the same
  `redact-audit.wal` fixture fix above.

### T2 — Does `scan_and_redact` hold its contract on a compressed sealed segment? · **resolved** · `wayfinder:grilling`
`SRC/neothd/src/cli/verify.rs:1431`.

**Resolution:** the test is ahead of the implementation, and correctly so.
`scan_and_redact` deliberately refuses physical redaction of any segment
carrying authenticated chain-structural frames (COMPACTION_MARKER,
SEGMENT_ROLLOVER/cross-link, REDACTION_MARKER) until the authenticated rewrite
transaction exists — the R3-18A contract, with logical forget covering the
operator need meanwhile. Any segment a real writer produces carries such
frames, so the test cannot reach its assertion.

Marked `#[ignore]` against GOLD-R3-18A rather than weakened or deleted: it is
the load-bearing proof that compressed-redaction offsets live in the same
logical coordinate space `verify` walks, and it turns green the moment the
rewrite transaction lands. **This makes R3-18A the gate for the last red
test, and T3 can proceed without it.**

### T6 — Refresh the licence snapshots so the wasmtime advisory can land · **resolved** · `wayfinder:task`
`cargo audit` reports **RUSTSEC-2026-0222** in `wasmtime` (stores can mix up
type indices between engines) — a real vulnerability in the WASM plugin host,
not a maintenance notice. `cargo update -p wasmtime` clears it and the host
compiles clean afterwards.

The blocker is downstream: the bump moves `cranelift-assembler-x64` and
`-meta` from 0.123.9 to 0.123.13, and `packaging/rust-license-snapshots.json`
is version-keyed. Each entry carries `repository`, `path_in_vcs`, `revision`
(the exact upstream git commit) and per-file SHA-256 of the licence texts.
That `revision` is provenance which cannot be derived from the crates.io
tarball — it has to be resolved against the bytecodealliance/wasmtime
repository for the matching release.

**Resolution path, now fully diagnosed (2026-07-31):**

1. The `revision` is *not* a research problem. Every crates.io tarball ships
   `.cargo_vcs_info.json`, and the existing 0.123.9 snapshot's revision
   `c59270b1…` is exactly that file's `git.sha1`. For 0.123.13 the value is
   `f65ae51bc2527490a5cd8fde805ea9754b81be1f`, and `path_in_vcs` comes from the
   same file. Both are already on disk under
   `~/.cargo/registry/src/index.crates.io-*/cranelift-assembler-x64-0.123.13/`
   after a `cargo update -p wasmtime`.
2. The `files[].text` is the part that needs the network. Verified by
   inspection: neither 0.123.9 nor 0.123.13 ships a `LICENSE` file in the
   tarball, yet the snapshot carries its full text — so the generator reads it
   from `bytecodealliance/wasmtime` at that revision, not from the package.
   Fetch `LICENSE` (and any sibling the 0.123.9 entry lists) from the repo at
   `f65ae51b…`, hash the exact bytes, write both entries, then re-run
   `packaging/generate_rust_notices.py --write` and land lock + snapshots +
   notices in one commit.

3. **The obvious fetch is wrong — verified, not assumed.** Fetching
   `LICENSE` from the repository root at the recorded 0.123.9 revision and
   hashing it does **not** reproduce that entry's `sha256`. The recorded text
   is 12,208 bytes and starts `Apache License
` with leading spaces on the
   version line; the repo-root file is 12,243 bytes and starts with a blank
   line before a centred `Apache License`. So the generator either reads a
   different path (likely `cranelift/assembler-x64/LICENSE` per `path_in_vcs`,
   or a licence carried elsewhere in the tree) or normalises before hashing.
   Whoever picks this up should read `packaging/generate_rust_notices.py`'s
   own fetch-and-hash path and reuse it verbatim rather than reimplementing it.

Fabricating the text — even with correct-looking Apache-2.0 boilerplate —
would falsify a licence record for a revision nobody checked. The check above
is exactly why: the plausible approach produced the wrong digest. The bump
stays reverted until the generator's real method is followed.

**Resolution of the open question (2026-07-31, verified not assumed).** The
generator does not read a different path — it **normalises before hashing**.
`normalize_notice_text` (`packaging/generate_rust_notices.py:184`) converts
CRLF/CR to LF, `rstrip()`s every line, `strip()`s the whole text and appends
exactly one trailing newline.

Gegenprobe against the known-good 0.123.9 entry: fetching repository-root
`LICENSE` at `c59270b1…` and hashing it raw does **not** match, exactly as
recorded here. Passing that same text through `normalize_notice_text` first
**does** match, byte for byte — 12,243 B raw → 12,208 B normalised, which is
precisely the recorded length. `path_in_vcs`
(`cranelift/assembler-x64`) carries no `LICENSE` of its own (404); the
repository root is the source.

So the remaining work is mechanical:
1. `cargo update -p wasmtime`; read the new cranelift versions from the lock.
2. Fetch `LICENSE` from `bytecodealliance/wasmtime` at
   `f65ae51bc2527490a5cd8fde805ea9754b81be1f`, run it through
   `normalize_notice_text`, hash the result.
3. Take `revision`/`path_in_vcs` from each crate's `.cargo_vcs_info.json` in
   the registry src dir, and `crate_sha256` from the lockfile entry.
4. Write both entries, run `packaging/generate_rust_notices.py --write`, land
   lock + snapshots + notices in one commit, then re-run cargo-deny/audit.

Ticket stays open only because steps 1-4 have not been executed; the unknown
that blocked it is closed.

**Done (2026-07-31).** wasmtime 36.0.9 -> 36.0.13, cranelift 0.123.9 ->
0.123.13, both snapshot entries rewritten, notices regenerated. `cargo audit`
and `cargo deny check advisories` are clean (`advisories ok`), and the WASM
plugin host builds with 145/145 tests green.

### T3 — What does an exact-head release-candidate run actually have to cover? · **resolved** · `wayfinder:task`

**Resolution (2026-07-31, head `b46cbf91`).** The run is fahrbar and its
verdict is legible:

- **CI: zero failures.** Linux quality, macOS/Windows tests, Ubuntu beta,
  gold-smoke, every feature-flag build, licence notices, WASM ABI, Keet
  standalone — all green.
- **Security: two failing jobs, one cause.** `cargo-audit` and `cargo-deny`
  both stop on `RUSTSEC-2026-0222` (wasmtime). Everything else in that
  workflow passes: trivy, pnpm audit, CodeQL/JavaScript, trusted-main.
- **CodeQL/Rust cannot be dispatched from the CLI** — it is GitHub-managed
  with no workflow file in the repo, so it runs on its own trigger. Making it
  dispatchable is a repo-settings change, not a code change.

What the run has to cover is therefore settled: CI as configured is
sufficient and currently clean; Security is one advisory away from clean; the
only structural gap is CodeQL dispatchability.

Three rounds of fixes were needed to get here, and all three findings were
invisible to any local gate on this machine — see the Unix-path note under
Notes. That is the standing reason this ticket exists.
Full CI, security, CodeQL, feature combinations, three platforms. Cannot start
while any test is knowingly red. Resolution records the exact workflow set and
the observed result per platform.

### T7 — Where should the hand-written text in a generated file live? · open · `wayfinder:grilling` · unblocked
`docs/cli-commands.md` is generated by `packaging`/`NEOTH_REGEN_CLI_DOCS`, but
someone has written into it by hand. Regenerating drops roughly 1,300
characters describing `neoth credential copy` — the private journal, the
capability-bound `~/.neoth/secret-transfers/authority.key` (verified present at
`credential_transfer.rs:529`), and the honest statement that Windows records
namespace durability as `unsupported`.

That text is true and worth keeping, and it is currently in the one place a
regeneration deletes. The decision: promote it into the clap doc comment on
`Copy` so it regenerates (and then also appears in `--help`, which may be too
long for a terminal), or move it into a hand-written companion page that the
generated reference links to. Whichever is chosen, a regeneration must stop
silently discarding operator-facing security documentation.

Found while closing the R3-10 doc-truth slice, which also caught a real defect:
`updater status` claimed to verify the WAL chain and does not.

### T8 — Should the Claude CLI child inherit ambient API keys? · open · `wayfinder:grilling` · unblocked
Found by a three-way parallel sink audit for `GOLD-R4-15d`.

`spawn_claude` does the right shape — `env_clear()` then a whitelisted rebuild
via `scrub_outbound_env_with` (`providers/claude_cli.rs:928`). But the strip
list covers `NEOTH_*` (except `NEOTH_LOG`), CI markers, `CLAUDECODE*` and
`TMUX*`. It does **not** strip `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` or any
other credential in the daemon's own environment, so every `claude` child
inherits them. On Linux that is readable at `/proc/<pid>/environ` by anything
with access for as long as the child runs.

**Why this is not a one-line fix.** `spawn_claude_with_extra_env` is only ever
called with `MAX_THINKING_TOKENS` (`claude_cli.rs:1133`, `:1302`) — NEOTH never
injects an Anthropic key itself. So for an operator who runs the Claude CLI on
an API key rather than OAuth, that ambient inheritance **is** the mechanism
that makes it work. Stripping it would break their setup.

The options:
- **(a)** Strip credential-shaped variables and inject the configured key
  explicitly via `extra_env` when one is set. Controlled and documented; costs
  a config read on the spawn path.
- **(b)** Strip them outright. Cleanest boundary; breaks API-key CLI operators
  loudly (auth failure, not silent corruption).
- **(c)** Leave it and document the inheritance as an accepted property of the
  subprocess path.

(a) is the only one that both closes the exposure and keeps the working setup,
so it is the proposal — but it changes spawn behaviour for real operators, and
that is a decision, not a repair.

**Also found, filed here so it is not lost:** WAL RAW_TEXT (0x01) writes the
operator's prompt bytes verbatim (`cli/chat.rs:6301`) and WAL at-rest
encryption exists but is opt-in (`wal/writer.rs:3178`). Both are by design and
documented; the audit's suggestion was to make encryption default-on with
auto-provisioned key. That is a separate decision of the same class.

### T4 — Which of the 233 pre-tag blockers are genuinely v1.0, and which are v1.1? · open · `wayfinder:grilling` · unblocked
The roadmap counts 1,222 boxes with 233 pre-tag blockers. Some are hard release
contracts (artifacts, installers, parity); others are refinements that a tagged
v1.0 can live without. This ticket produces the split — and it is HITL, because
scope is the operator's call, not the agent's.

**Prepared analysis (2026-07-31) — decision input, not a decision.**

Mechanical extraction of `- [ ] **<ID>` from the roadmap finds **267 open items
carrying an id**; the dashboard comment reports `open=299` raw. The 32-item gap
is items written without an id pattern. Counts below use the 267 that can be
addressed individually.

| Family | Open | What it is |
| :-- | --: | :-- |
| `GOLD-LF-*` | 118 | Lost-feature recovery — capability that existed in an earlier design and is not in the shipped binary |
| `ADOPT31-*` | 65 | The 2026-07-31 eighteen-source adoption wave |
| `GOLD-R4-*` | 46 | Release lane: artifacts, installers, onboarding, GUI parity, Buddy, cluster, mobile, channels |
| `GOLD-NCT-*` | 27 | NIR/1 canonical schema, limits, golden vectors |
| `GOLD-R3-*` | 8 | Hardening lane (WAL authority, skill authority, untrusted framing) |
| other | 3 | `DEP`, `ADOPT`, `RELEASE` singletons |

**The shape of the answer, judged on the `system-design-101` axes** — an item
cannot be deferred if deferring it leaves a failure mode unhandled, a single
point of failure unnamed, or a consent/audit boundary incomplete:

- **`ADOPT31-*` (65) reads as V1.1-BREADTH almost in full.** Adopting a
  capability from another project is by construction *more surface*, not a
  broken promise. None of it makes a shipped feature work; deferring it leaves
  no failure mode unhandled. This is the single largest lever on the number.
- **`GOLD-R4-*` (46) splits hard.** `R4-01`/`R4-02` (artifacts, package
  managers, upgrade matrix) are **V1.0-CONTRACT** — without them there is
  nothing to tag. `R4-12` (mobile companion), `R4-13a..l` (cluster completion),
  `R4-06` (Buddy product-grade), `R4-07` (channel parity) are **V1.1-BREADTH**:
  each is a *new product surface*, not a repair.
- **`GOLD-R3-*` (8) is mostly V1.0-HARD** — it is the hardening lane, and its
  open items sit on audit, authority and untrusted-input boundaries.
  `R3-18A` is the exception worth arguing: it also gates the last ignored test.
- **`GOLD-LF-*` (118) is the real question and cannot be answered mechanically.**
  The split is: *was the lost capability ever advertised?* An advertised
  feature that is absent is V1.0-HARD by the destination's own wording ("no
  advertised feature that is partial or unwired"). One that was only ever an
  internal plan is V1.1. That per-item judgement is the operator's.
- **`GOLD-NCT-*` (27)** hinges on whether NIR/1 is a v1.0 wire contract or a
  v1.1 formalisation of something already working.

**Honest verdict:** if `ADOPT31` and the four named `R4` product surfaces move
to v1.1, the tag-blocking set drops from ~299 to roughly **60–80 items**, most
of them release mechanics and the advertised subset of lost features. That is a
defensible v1.0. The decision that actually moves the number is not 233
individual calls — it is **three**: (1) is the adoption wave v1.1? (2) are
mobile/cluster/Buddy/channel-parity v1.1 surfaces? (3) which lost features were
advertised? Everything else follows.

**Proposal — NOT a decision. Awaiting the operator; nothing below is
authorised.** Built with the `system-design-101` frame, using its Resilience
and Delivery axes, because that is what separates "unfinished" from "narrower
than the vision".

**The test.** An item is v1.0 if deferring it leaves a *failure mode
unhandled* or makes *delivery impossible*. Adding a capability is neither,
however desirable.

**Measured distribution of the 267 open items:** `GOLD-LF` 118, `ADOPT31` 65,
`GOLD-R4` 46, `GOLD-NCT` 27, `GOLD-R3` 8, other 3.

**Delivery axis — without these there is nothing to tag (proposed v1.0):**
`R4-01` (7, artifacts), `R4-02` (2, package managers/upgrade matrix), `R4-08`
(clean-machine qualification), `R3-10` (release truth + exact-head gates),
`GOLD-RELEASE`, `GOLD-DEP`.

**Resilience axis — deferring leaves a failure mode open (proposed v1.0):**
the `GOLD-R3` hardening lane (8) and `R4-15` (14, bounded envelopes — the lane
this session has been closing).

**Breadth, not repair (proposed v1.1):** `ADOPT31` (65) is adoption from other
projects by construction. `R4-06` Buddy, `R4-07` channel parity, `R4-12`
mobile, `R4-13` cluster (13) are each a *new product surface*. `GOLD-LF` (118)
defaults here: the destination forbids shipping an advertised feature that is
partial, and the R3-10 audit found **no BLOCKER** across README, `docs/`, the
config example and crate docs — so nothing missing is currently advertised.

**The exception inside LF.** 26 LF items touch consent, audit, WAL identity or
credentials. They split by the same test — *new surface* (`LF-P1-15` WebChat,
`LF-P2-25` Voice Call, `LF-P2-01` Dreaming) is v1.1; *a hole in a boundary
that already ships* is v1.0. Three qualify on reading: paired INTENT/RESULT
WAL records (`LF-P1-01`), universal WAL `session_id` (`LF-P2-08`),
per-counterparty ingress consent (`LF-P2-22`). The other 23 need the same
one-line judgement when next touched.

**The axis I cannot answer — this is the real question for you.** `WS-NCT`
(27) declares itself "every card below is v1.0.0 Gold work". By the test above
it reads as new capability (cognitive transport, typed cluster delegation),
which would be v1.1. But that binding scope is a prior operator decision, and
overriding it is exactly the silent reclassification the destination forbids.
**Verdict per the skill: Underspecified** — one axis unanswered, so this
proposal is not sound until you settle it.

**Cost of the proposal, stated:** v1.0 becomes ~67 items (~70 with the three
LF carry-overs), matching the 60-80 you estimated. The price is that v1.0 ships
without cluster completion, mobile, full channel parity and a product-grade
Buddy — a narrower product than the vision, defensible only because none of it
is advertised today. If NCT stays v1.0 the count rises to ~94 and the tag moves
out accordingly.

**To decide it, three sentences suffice:** (1) ADOPT31 — v1.0 or v1.1?
(2) R4-06/07/12/13 — v1.0 or v1.1? (3) LF — all v1.1, or v1.1 except the three
boundary-completion items named above? Plus, if you disagree with leaving it
alone: what happens to NCT.

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
