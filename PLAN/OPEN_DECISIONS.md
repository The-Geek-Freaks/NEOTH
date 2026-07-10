# Architecture Decisions Log — NEOTH v1.1

**Status: All eight decisions resolved 2026-05-13 (4-agent advisory
review) + implementations shipped since. The Status table at the
bottom carries the authoritative final-call + per-decision action
trail; the "Question / REC" sections that follow each ID preserve
the original framing for archival reasons.**

Read this file from the bottom up: the per-decision narrative explains
the decision space, the Status table records what was actually
chosen + what shipped. The "Outstanding" list documents follow-up
work that was scoped during the review — items there are tracked in
PROGRESS.md, not here.

V02-09 (PROGRESS.md "OPEN_DECISIONS D-001..D-008 decisions recorded
even 'defer indefinitely' counts") closed by the Status table.

---

## D-001 Binary Release Pipeline

**Question:** How does `cargo install neoth` end up on operator machines?

**Options:**

| Option | Pros | Cons |
|--------|------|------|
| A. `cargo install` only (crates.io) | Simplest. No CI artifact pipeline. Operators must have Rust toolchain. | Slow first install (compiles everything). No binary signing. |
| B. `cargo-dist` + GitHub Releases | Auto-generated installers for Linux/macOS/Windows. Pre-built binaries. Cargo-dist handles changelog → release notes. | Adds one CI dep. Locks us to cargo-dist's conventions. |
| C. `softprops/action-gh-release` + manual `cargo build --release` per OS matrix | Full control. Standard GH Actions matrix. | Hand-rolled release scripts. More to maintain. |
| D. cosign + sigstore signing on top of B or C | Supply-chain integrity. Reproducible verifies. | Adds sigstore infra. Operator must install cosign to verify. |

**REC:** **B (cargo-dist)** for v0.1 through v0.5. Defer D (sigstore) until v1.0 when supply-chain story matters. Most operators won't verify sigs anyway in early days.

---

## D-002 CLI Onboarding UX: Library Choice

**Question:** `dialoguer` for the `neoth init` wizard vs raw stdin parsing?

**Context:** Agent 2 wired `dialoguer 0.11` into Cargo.toml. Day-3 main.rs already routes through `cli::Cli::parse()`. The wizard itself is in `cli/init.rs` (skeleton).

**Options:**

| Option | Pros | Cons |
|--------|------|------|
| A. dialoguer (current) | Pretty TTY UI, validators built-in, fuzzy select for provider choice | 280KB binary cost; doesn't play well with `expect`-style scripted install |
| B. Raw stdin + clap arg parsing | 0KB extra. Works in any TTY or pipe. CI-friendly. | Manual validation. Less polish. |
| C. Both: dialoguer when stdin is a TTY, fall back to clap-only otherwise | Best of both. `neoth init --non-interactive` works in cloud-init. | More code paths. |

**REC:** **C (hybrid).** Operators on a real terminal get the wizard; CI/cloud-init operators run `neoth init --non-interactive --operator-id <your-id> --left-provider claude --telegram-token $T` and skip prompts entirely. Adds ~50 LOC vs A.

---

## D-003 Secret Storage for `~/.neoth/freedom.yaml`

**Question:** Channel tokens and LLM API keys live in `freedom.yaml` mode 0600. Do we also offer OS-keychain integration?

**Options:**

| Option | Pros | Cons |
|--------|------|------|
| A. File only (mode 0600) | Simplest. Works on every OS. | Anyone with file-read can impersonate. |
| B. File + optional OS keychain (macOS Keychain, Win Credential Manager, libsecret on Linux) | Per-secret encryption at rest. Survives accidental commit. | `keyring` crate ~50KB; libsecret has Linux desktop-only quirks. |
| C. File + age/sops encryption | Cross-platform encrypted-at-rest. | Operator must manage age key. |

**REC:** **A for v0.1**, **B as opt-in for v0.5**. Most early operators will run on a dedicated VM/box where file-only is acceptable. Offering keychain as `freedom.yaml: { secret_storage: keychain }` setting later is non-breaking.

---

## D-004 Plugin SDK Distribution

**Question:** WASM plugins (Day-23) need a Rust SDK crate so plugin authors can `use neoth_sdk::*`. Where does it live?

**Options:**

| Option | Pros | Cons |
|--------|------|------|
| A. Re-export from `neothd` (`neothd::plugin::sdk::*`) | Single crate. No version skew. | Plugin authors pull in entire daemon as compile dep. |
| B. Separate `neoth-plugin-sdk` crate in same workspace | Clean separation. Small dep for authors. | Workspace migration (currently single-crate). |
| C. Separate `neoth-plugin-sdk` published independently | Independent versioning, longest-term right answer. | Coordination overhead between daemon and SDK versions. |

**REC:** **B at Day-23** — convert single-crate workspace to multi-crate when we cross that milestone. Cargo.toml already has `[workspace]` block as placeholder. Pre-Day-23 the question is moot.

---

## D-005 Streaming Output Pattern in CLI

**Question:** When `neoth recall --stream` returns search hits, does it stream them as they arrive (server-sent events style) or batch + dump?

**Options:**

| Option | Pros | Cons |
|--------|------|------|
| A. Always batch (collect, then print) | Simpler. Predictable ordering. | Slow queries feel frozen. |
| B. Always stream (line-per-hit, jsonl on stdout) | Snappy UX. Pipeable. | Output interleaving issues with progress bars. |
| C. Default batch; `--stream` flag for jsonl | Best of both. | Two code paths. |

**REC:** **C.** Default human output is a table (batch). `--stream` flips to jsonl-per-line for piping to `jq`, scripts, downstream agents.

---

## D-006 Phase-3 Migration Output Format

**Question:** `neoth migrate import` (Day-63) emits `migration-batch-N.jsonl` files. Should we standardize this as a public "NEOTH import format" so others can write migrators for their own predecessor systems?

**Options:**

| Option | Pros | Cons |
|--------|------|------|
| A. Internal-only format, undocumented | One concern less. Free to change. | Each predecessor system needs custom migrator inside neoth binary. |
| B. Public spec at `docs/import-format.md`, semver-stable | Anyone can write `acme-to-neoth.py` → emit our jsonl → `neoth wal load < file.jsonl` | Stable wire commitment. Format changes need migration tooling. |

**REC:** **B at v1.0**, **A pre-v1.0**. Wait until the wire format has shaken out via our own predecessor migration before promising stability.

---

## D-007 CI Workflow Defaults

**Question:** Agent 4 set up `.github/workflows/` with stub defaults. Three sub-decisions:

**a) Working-directory in workflows** — `SRC/neothd/` is the cargo root, not repo root.

| Option | REC |
|--------|-----|
| Set `working-directory: SRC/neothd` per step | **YES, current state.** Avoids `cd` repetition. |
| Move Cargo.toml to repo root | NO — keeps SRC/ separated from docs/PLAN/scripts/ |

**b) Cosign signing in release workflow** — defer per D-001.

**c) `gh release create` vs `softprops/action-gh-release`** — go with cargo-dist's bundled flow per D-001 once we adopt it.

---

## D-008 Rust on Windows: First-Class or Best-Effort?

**Question:** Day-1/Day-2 build green on Linux (Jarvis VM). Windows not yet tested. NEOTH's WAL design uses `fdatasync(2)` for durability; Windows has `FlushFileBuffers` which is slower and weaker guarantee.

**Options:**

| Option | Pros | Cons |
|--------|------|------|
| A. Linux-only support, document Windows as unsupported | Honest. No phantom guarantees. | Excludes Windows operators. |
| B. Windows best-effort, durability disclaimer | Inclusive. | Operators may rely on durability that isn't there. |
| C. Native Windows support with `FlushFileBuffers` semantics documented | Inclusive + honest. | More dev/test time per release. |

**REC:** **B for v0.1-v0.5**, target **C for v1.0**. Linux is the production target per existing design notes. Windows users get the daemon for dev/testing but the README says "production use: Linux".

---

## D-009 WAL opcode space exhaustion — u8 extension track

**Status:** OPEN (filed 2026-07-10, DES-13-AUTO-RESTORE-01 implementation)

**Context:** The WAL opcode space is a `u8` (0x00–0xFF = 256 slots). As of
`SRC/neothd/src/wal/events.rs`, all 256 values are assigned or reserved.
`classify_event` in `wal_sync.rs` uses `u8` throughout. `idx_foreign_events`
stores `event_type` as `INTEGER` (SQLite, no width limit), so the wire format
could accommodate wider types without schema migration if the encoding layer
changes.

**Options:**

| Option | Pros | Cons |
|--------|------|------|
| A. Reserve 0xF0–0xFF as a 2-byte escape prefix (next byte = extended opcode) | Backward-compatible, incremental | Complicates `decode_frame` / `classify_event`; escape-prefix collisions with current `0xF*` WAL-structure events |
| B. Bump opcode width to u16 in a new WAL version (WAL v2) | Clean design, 65535 opcodes | Full WAL-layer version bump; all tools must migrate; `event_type INTEGER NOT NULL` column stays compatible but all Rust code changes |
| C. Band reservation: stop allocating below 0xFF; create semantic bands above 0xFF using the u16 path | Keeps u8 stable for existing events; new events use u16 | Requires B first |
| D. Emit a structured audit/deprecation log when 90% capacity is reached; freeze opcode alloc until B is shipped | Buys time, no breaking change | Temporary workaround |

**REC:** **D short-term** (freeze new opcode allocation; track usage at 80%+).
**B medium-term** for v1.1 — WAL v2 with `event_type: u16` in the 96-byte
header body (currently only 1 byte of the 96 is used for event_type; a 2-byte
extension fits the existing header layout). Integration point:
`SRC/neothd/src/wal/header.rs` `EventHeaderV2.event_type` field + `frame.rs`
encode/decode + `wal_sync.rs` `classify_event` + `idx_foreign_events` schema.

---

## Decision template (for your responses)

```
D-XXX: [chosen option letter or "Other: <description>"]
Reason: [one line, optional]
```

Lazy-ack ("REC all") is fine for any subset you're comfortable defaulting on.

---

## Status (final after 4-agent advisory review 2026-05-13)

| ID | Decision | Final | Action Taken |
|----|----------|-------|--------------|
| D-001 | Binary release | **C + cosign in v0.2** (REC=B rejected: release.yml already implements C, cargo-dist would fight `SRC/neothd/` layout) | release.yml: softprops SHA-pin v2.0.8, `contents: write`+`id-token: write`, cosign keyless OIDC step, verification instructions in body |
| D-002 | CLI wizard UX | **C with 3 hardening fixes** | `non_interactive` (kebab-flag), `IsTerminal` auto-detection, `dialoguer` behind optional `wizard` Cargo feature, `WizardState` strings → `OperatorRole`/`ProviderKind` enums |
| D-003 | Secret storage | **A + P0 hardening** | `SecretString` newtype (zeroize on drop, Debug→"[REDACTED]"), Telegram/Google OAuth/Slack/Meta redact patterns, SECURITY.md disk-forensics disclaimer, `write_config` mode-0600 TOCTOU comment for Day-3 impl |
| D-004 | Plugin SDK | **C earlier (Day-15)** (REC=B rejected: typestate seal requires separate-crate, workspace-member is monorepo-contrib not plugin-ecosystem) | SPEC_skill_plugin_system.md §6 annotation: `PermissionToken<T>` is Phase-1 compile-time only; WASM enforcement = runtime `hostcall_allowlist`. Crate creation deferred to Day-15. |
| D-005 | CLI streaming | **C with sentinel + global flag** | `Cli.output: OutputFormat` and `Cli.stream: bool` as `global = true`, `Cli::effective_output()` helper, sentinel-line contract documented in `--stream` help text |
| D-006 | Migration format | **A + `_format_version` marker** | RUNBOOK Day-63: every JSONL line MUST start with `"_format_version": "internal-unstable"`, CRLF→LF normalization required before any hash |
| D-007 | CI workflow | **a accept, b cosign-now, c keep current** | ci.yml: artifact upload guarded with `github.event_name != 'pull_request'`, retention 7d → 3d |
| D-008 | Windows support | **B with hard gates** | `main.rs` Windows startup warning, `wal/writer.rs` Windows DACL warning (TODO v0.5 SetNamedSecurityInfoW), SECURITY.md Windows-specific limitations section, SIGTERM/Ctrl+C graceful shutdown handler in main.rs |

## Outstanding (post-review, not yet implemented)

- **Day-15**: spin out `neoth-plugin-sdk` as separate crate, publish 0.1.0 to crates.io, switch dev to `[patch.crates-io]` (D-004).
- **Pre-v0.1 ship**: verify `cli/init.rs::write_config` Day-3 impl uses `.mode(0o600)` on `OpenOptions` BEFORE `open()`, never chmod-after-create (D-003 P0 question).
- **Pre-v0.1 ship**: add `libc::mlock` on the deserialized config struct on Linux (D-003 P0).
- **v0.5**: SetNamedSecurityInfoW DACL restriction on Windows WAL segments (D-008).
- **Day-1 (local)**: verify FILE_FLAG_WRITE_THROUGH effect on Windows WAL latency to confirm durability disclaimer is accurate (D-008).

---

## Session 21 follow-up decisions (added 2026-05-23)

Three decision-notes shipped during Session 21 + are awaiting operator
accept/decline before downstream code can land:

### D-101 (was K-1) — Hyperswarm path for Keet + Cluster

**Decision note:** `QUELLEN/research/R-A1_K1_decision.md`
**Recommendation:** Path 3 (Pears HTTP bridge) + auto-install Pears via the wizard.
**Blocks:** K-2 / K-3 / K-4 / C-1..C-4 / CT-01..CT-04 / G-06.
**3 sub-decisions waiting:**
1. Pears auto-install via wizard? Recommended: yes (matches the
   claude-cli + gemini-cli + codex auto-install precedent).
2. K-2 stub-upgrade scope: minimal reqwest-client first OR with K-3
   pairing UX bundled? Recommended: client first, K-3 separate session.
3. Trigger order: Keet first OR Cluster first? Recommended: Keet —
   bigger operator-visible payoff + same `pears_bridge.rs` infra
   serves cluster afterward.

### D-102 (was E-21) — WASM plugin activation default

**Decision note:** `PLAN/OPEN_QUESTION_E21_wasm_plugin_default.md`
**Recommendation:** Option B — default-inactive on first discovery.
**Blocks:** V10-04 WASM plugin host GA blocker.
**Reasoning:** Matches the AGENTER hard rule + n8n/Obsidian
conservative defaults already shipped. Sandbox bug blast radius is
one operator-confirmed plugin instead of every dropped file.

### D-103 (was E-22) — Skill hot-reload scope

**Decision note:** `PLAN/OPEN_QUESTION_E22_skill_hot_reload.md`
**Recommendation:** Option 3 — everything reloads, active invocations
finish on the old version (`Arc<SkillBody>` clone-at-invocation).
**Blocks:** Future operator iteration loop for skill authors.
**Reasoning:** Standard "watch mode" semantics every modern dev tool
uses (vite, cargo watch, esbuild). Option 1 (no reload) is too
operator-friction; option 4 (abort active) is too surprising.

### Operator action

Reply to this file (or PROGRESS.md commit) with one of:
- "Accept all three recommendations" → Session 22 ships the wiring.
- Per-decision verdict (e.g. "D-101 yes / D-102 yes / D-103 alt 2").
- "Defer D-101 + D-103 until v0.5; D-102 yes" — any subset.

### Resolution — Session 21 (2026-05-23)

Operator handed the three decisions to a 6-agent senior-dev panel:
architect, rust-reviewer, security-reviewer, performance-optimizer,
code-explorer, code-architect. **6/6 unanimous** on every sub-question.

| Decision     | Verdict | Reasoning headline |
|--------------|---------|--------------------|
| **D-101**    | **Path 3 (Pears HTTP bridge)** | Path 1 = 3-5 mo + protocol drift; Path 2 = 60 MiB Node weight + violates self-contained rule; Path 3 = `reqwest` already in deps, zero new workspace dep, lands in already-stubbed `channels/keet/` + `cluster::HyperswarmPeerRegistry` |
| **D-101a**   | **Yes — auto-install Pears via wizard** | `installers/{node,obsidian,obs,tmux,n8n}.rs` precedent already shipped; `installers/pears.rs` is a direct clone of the `npm install -g <runtime>` pattern with `cmd /C` on Windows |
| **D-101b**   | **Minimal reqwest client first (K-2 standalone)** | Bundling K-3 pairing UX (24-word seed + GUI) couples unproven HTTP bridge with stateful pairing protocol; ship transport first, operator-test, then K-3 |
| **D-101c**   | **Keet first** | Shared `pears_bridge.rs` infra strict superset of cluster's needs; bigger operator-visible payoff; cluster C-1..C-4 inherits the implementation with no rework |
| **D-102**    | **Option B — default-inactive** | wasmtime hostcall surface = full operator-secret blast radius; matches n8n/Obsidian conservative defaults; current `wasm_plugin/mod.rs` has NO active-on-discover assumption, zero retro-fit |
| **D-103**    | **Option 3 — `Arc<SkillBody>` clone-at-invocation** | Standard watch-mode semantics (vite, cargo-watch); `arc-swap` already in Cargo.toml + used for FreedomConfig hot-reload; consent boundary stays coherent because the version pinned at invocation start is what the gate evaluated against |

**Blueprints (per code-architect agent):**
- D-101: `installers/pears.rs` (mirror `node.rs`) + `channels/pears_bridge.rs` (reqwest POST/subscribe surface)
- D-102: `activation: Pending|Active|Disabled` on `WasmPluginEntry` in `wasm_plugin/discovery.rs`; wizard step 7b in `cli/init.rs` (multiselect bulk-enable)
- D-103: split `Skill` → `SkillManifest` + `SkillBody` in `skills/schema.rs`; `notify::RecommendedWatcher` in `skills/loader.rs::watch_skills_dir`; daemon main task atomically swaps registry `Arc`

Implementation lands progressively across Session 22+. Each ship updates
the relevant PROGRESS.md line in the same turn per
[[neoth-progress-md-update-rule]].
