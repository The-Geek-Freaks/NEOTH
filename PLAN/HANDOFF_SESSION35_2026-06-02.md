# NEOTH — Handoff Session 35 (2026-06-02)

> Comprehensive context dump so the next session starts fully informed.
> Read this top-to-bottom before touching code.

---

## 0. TL;DR — where things stand

- **Version:** `1.0.0-beta.1` (bumped from `0.2.1` this session — both `SRC/neothd/Cargo.toml` + `SRC/neothd-gui/Cargo.toml` + `SRC/Cargo.lock`).
- **HEAD:** `075f7ac` on `main`, **pushed to public `origin`** (`github.com/The-Geek-Freaks/NEOTH`). Tree clean.
- **This session: 33 commits**, every one with full gates green (build + `cargo test -p neothd` 0-fail + clippy `-D warnings` + docgen drift-guard). Nothing half-shipped.
- **Backlog (`PLAN/PROGRESS_v1_0.md`): 206 done `[x]` / 25 in-progress `[~]` / 32 open `[ ]`.**
- **Big news: the "blocked-on-embed" cluster was a FALSE classification** (stale memory + stale doc header). Verify-first proved embed is fully built; all 3 supposedly-blocked items (ADV-14, MONITOR-03, SPEC-12) were buildable and **all 3 shipped this session**.
- **The headless code backlog is essentially exhausted.** What remains for v1.0: **GUI (Slint, not visually testable headless)** + **operator-ops (ARCH-05 migration shadow-run)** + **minisign release keypair (BLOCKED on Alex)** + documented small follow-on slices.

---

## 1. What NEOTH is (orientation)

Self-contained sovereign-AI Rust daemon. Workspace at `SRC/` (members: `neothd`, `neothd-gui`, `neoth-migrate`, `neoth-relay`, `neoth-plugin-sdk`). The operator (Alex) runs ONE daemon, ONE private memory, many approved surfaces, local-first defaults, operator-readable proof.

Authoritative spec: `PLAN/00_DESIGN_v1.1_FINAL.md` + `PLAN/SPEC_*.md`. **Live tracker: `PLAN/PROGRESS_v1_0.md`** (NOT the 892 KB historical `PLAN/PROGRESS.md`). Roadmap: `PLAN/ROADMAP_v1_0_endgame.md`.

Key crate layout (`SRC/neothd/src/`):
- `cli/` — every `neoth <subcommand>` lives here + `cli/mod.rs` has the `Commands` enum + dispatch.
- `daemon/` — the `neoth serve` loop + all background crons.
- `wal/` — HMAC-chained append-only WAL; `wal/events.rs` is the event-type registry.
- `providers/` — chat (`Provider`) + embed (`EmbedProvider`) adapters; `providers/embed.rs`, `providers/local_qwen.rs`.
- `memory/store.rs` — the `views.db` SQLite schema + repository fns.
- `config/mod.rs` + `config/inference.rs` — `FreedomConfig` (= `freedom.yaml`) + sub-configs.

---

## 2. Build + verify environment (CRITICAL — read before building)

Windows 11, MSVC toolchain. Builds are LOCAL on this machine only.

- **ALWAYS build via the wrapper:** `scripts/cargo-msvc.ps1` (sets up vcvars64 + SDK paths). Direct `cargo` fails to link (Git Bash PATH shadows MSVC `link.exe`).
- **`CARGO_BUILD_JOBS=2` is MANDATORY** (bluescreen guard — higher parallelism crashes the box).
- Full gate run command shape:
  ```bash
  NEOTH_REGEN_CLI_DOCS=1 CARGO_BUILD_JOBS=2 powershell.exe -ExecutionPolicy Bypass \
    -File scripts/cargo-msvc.ps1 test -p neothd > /tmp/x.log 2>&1; echo "EXIT=$?"
  ```
- **Clippy via the wrapper uses the `-D` SWITCH form** (the `param([switch]$D ...)` design):
  ```bash
  ... scripts/cargo-msvc.ps1 -D clippy -p neothd --lib --tests warnings
  ```
  i.e. `-D` is the FIRST token (binds to the PS switch), `clippy` next, `warnings` is the LAST bare arg. **NOT** `-- -D warnings` (PowerShell eats the `--`). Getting this wrong silently runs `cargo check` instead.
- **NEVER pipe gate runs through `| tail`** — `tail`'s exit 0 MASKS cargo's real exit code. Redirect to a file + read `$?`.
- **`NEOTH_LOG=error`** for any path that parses neothd's stdout as JSON (neothd's tracing goes to STDOUT, corrupts JSON parsers otherwise).
- Builds are SLOW (full `cargo test -p neothd` ≈ 8-20 min incl. link). Run them **in the background** (`run_in_background: true`) and poll the output file; never `sleep`-loop.
- The PowerShell wrapper **drops `-p`/positional flags in some forms** — for `cargo update` use the positional `--precise` form (`cargo update tar --precise X`).

### Test gates that WILL fail you if you forget a step
- **`cli::docgen::tests::cli_commands_md_is_up_to_date`** — adding/removing any `neoth` command or flag makes `docs/cli-commands.md` stale. Regenerate by running tests with `NEOTH_REGEN_CLI_DOCS=1`, then COMMIT the regenerated `docs/cli-commands.md`.
- **`tests/wal_emit_sites.rs::every_event_type_constant_is_wired`** (SC-01a) — every `EVENT_TYPE_*` const must be referenced at a real emit site, or the test fails.
- **`tests/no_outbound_network.rs`** — forbids `reqwest::Client::new(` etc. outside `ALLOWED_PREFIXES` (`src/providers/`, `src/updater/`, `src/cluster/`, `src/daemon/audit_rpc/`...). `tools/` must use `crate::providers::http_client::build_client()`.
- **`wal::events::tests::{all_event_codes_are_unique, event_type_name_table_is_unique_and_round_trips}`** + `memory::regions::tests::six_regions_partition_every_event_type_band` — see §5 WAL-event registration (5 sites).

---

## 3. What shipped this session (33 commits, oldest→newest)

Grouped by theme:

**Phantom commands (CLI surfaces docs referenced but didn't exist):**
- `117b9d7` `neoth gui` launcher.
- `971189b` / `eee03ac` `neoth autonomy set/show` (+ LEVEL_ELEVATED/DEROGATED audit frame).
- `b8b25aa` `neoth cron run <id>` (fire a scheduled job out of band).
- `1a30387` `neoth n8n {status,workflows}` + `neoth credential {list,import}`; `471ea97` added `credential import --dry-run` (added/overwritten classify split — Alex-added, verified+kept).
- `780979c` **stack-overflow fix**: `neoth --help` overflowed → run neothd on a 32 MiB worker stack.
- `80355cb` doc phantom-ref cleanup.

**Crypto / proof / audit:**
- `e60838f` KF-03 `wal export --sign` (ed25519 + verify `.neoth-proof` bundles, DAU-safe auto-managed key).
- `b00633d` PROOF-KEY-01 `wal proof-key show/export-pub`.
- `eb87664` + `1a80507` + `68efc68` + `d873474` **AUDIT-RPC-01** (original loopback audit-RPC slice, now superseded by strict V2 same-user Unix-socket/Windows-named-pipe transport: daemon listener + client + os_tools consumer wiring + required-audit fail-closed mode + `audit_rpc.rs`→module-dir split).

**OS-tool surface:** `5e15537` PC-01 `neoth os launch` (exec-allowlist) + `8679131` GR-10 safe-mode exec rail.

**Monitoring / crons:** `b296ace` MONITOR-04/05 (alert dedup + silence false-positive gate); `cc6cc67` **ADV-14** regression-anchor cron; `7b0bd97` **MONITOR-03 + RECALL-METER-01** recall-p95 latency alert.

**Embed consumers (the "blocked" cluster):** `c6fd1be` embed header honesty fix; `cc6cc67` ADV-14; `075f7ac` **SPEC-12** `neoth dream now` + 0xF4.

**Backlog closures / housekeeping:** `6b7e3e8` UX-08 hook-stage wasm example + SPEC-10 close; `e028a9a` SPEC-03b council trigger-threshold config; `136f1d4` TD-02 CalDAV read-only; version bump `09a8bc3` + release-notes `7717248`.

---

## 4. THE key verify-first finding (don't repeat the mistake)

**Embed is FULLY BUILT and wired.** An earlier triage (+ a stale Day-14b memory + a self-contradictory `providers/embed.rs` module header) mis-classified SPEC-12 / ADV-14 / MONITOR-03 as "blocked on the embed surface." That was WRONG:

- `providers/local_qwen.rs` loads a **separate bare `qwen2::Model`** (no `lm_head`) as `LoadedEmbedModel` → `forward` returns post-norm hidden states → `run_embed` mean-pools + L2-normalises.
- `impl EmbedProvider for LocalQwenAdapter::embed` is real; `providers::embed_provider_from_config(&config)` returns a real `Arc<dyn EmbedProvider>` for `inference.embedding_provider ∈ {LocalQwen, LocalOuro}`.
- 3 downstreams already consume it (skill router Stage-2, council dissent, dreaming clustering).
- The agglomerative cosine clustering (`daemon::dreaming::cluster_events_by_cosine`, single-linkage, 0.65) is shipped.

**Lesson for next session:** grep + read the CODE before trusting a "blocked" label in PROGRESS or a memory note. The embed downstreams (SPEC-12 LLM-theme-summary, etc.) are buildable, NOT blocked. The ONE genuinely-embed-adjacent gap was a chat `Provider` wired ALONGSIDE the `EmbedProvider` for LLM theme labels (Phase 4b) — see §6 follow-ons.

---

## 5. Grooved patterns (copy these — they're proven)

### Daemon cron recipe (drift_alert_cron / regression_cron / recall_latency_cron / monitor_cron)
1. A **pure tick** fn taking injectable inputs (testable without a daemon) — e.g. `evaluate_regression(...)`, `evaluate_recall_p95(...)`.
2. A `run_*_tick(home, config, ..., writer) -> Result<...>` that does the I/O + emits the WAL frame ONLY on a real alert (clean signal, not "still fine" noise).
3. `spawn_*_cron_loop(config, ...) -> Option<JoinHandle>` returning **`None` when `config.enabled == false`** (default OFF → no idle tokio task).
4. `interval_duration()` clamped to a **60s floor** (so `interval_secs: 0` can't tight-loop).
5. Config struct mirrors `DriftAlertConfig` (`#[derive(Clone, Copy, ... Deserialize, Serialize)] #[serde(default)]` + `Default` impl + a `DEFAULT_*_INTERVAL_SECS` const) + a `#[serde(default)] pub <name>: <Config>` field on `FreedomConfig`.
6. `serve.rs`: spawn (gated) + a **drain-before-writer-close abort** (`task.abort(); let _ = task.await;` BEFORE the WAL writer drops).
7. `daemon/mod.rs`: `pub mod <name>;`.
8. **`spawn_*` tests MUST be `#[tokio::test]`** (not `#[test]`) — `wal::writer::spawn` spawns an internal tokio task and PANICS with no runtime. (This bit me twice this session.)

### WAL event registration — FIVE sites (miss one → a test fails)
For a new `EVENT_TYPE_FOO = 0xNN` in `wal/events.rs`:
1. The `pub const` with a doc comment + a `Payload (JSON):` line, in the correct band.
2. The **band-assert** block (`let _ = [(); 1][(EVENT_TYPE_FOO < 0xLO || EVENT_TYPE_FOO > 0xHI) as usize];`). For the `0xF0` band, only the lower-bound check (u8 max == 0xFF).
3. The **lowercase `--type` filter table** (curated, `("foo", EVENT_TYPE_FOO)`) — for `neoth wal show --type foo`.
4. The **UPPERCASE round-trip table** (`("FOO", EVENT_TYPE_FOO)`) — the `event_type_name_table_is_unique_and_round_trips` test reads this.
5. A real **emit site** (SC-01a `every_event_type_constant_is_wired` requires the const be referenced outside `events.rs`).

Codes assigned this session: `0x3F REGRESSION_ALERT`, `0x4B RECALL_LATENCY_ALERT`, `0xF4 DREAM_COMPOSED`, `0xAE/0xAF AUDIT_RPC_ACCEPT/REJECT`, `0xAC/0xAD OS_APP_LAUNCH/DENIED`. **`0xF1` is TAKEN (TOMBSTONE_REQUESTED)** — the SPEC-12 "0xF1 DREAM_COMPOSED" was a collision, used `0xF4` instead.

### One-shot CLI audit (when a `neoth <cmd>` needs to emit a WAL frame)
Two patterns in the tree:
- **Old (recall M-02):** open a short-lived `wal::writer::spawn(default_wal_dir().join("000001.wal"))` + `writer.try_append_sync(header, payload)` (SYNC, best-effort). Races the daemon's writer if live.
- **New (AUDIT-RPC-01, preferred):** `os_tools::AuditSink { None, Writer(&handle), DaemonRpc(&home) }` — forwards the frame to the live daemon over the kernel-authenticated same-user OS audit-RPC channel when `live_daemon_pid` is `Some`, opens a one-shot writer otherwise. See `cli/fs.rs`, `cli/os.rs`. `cli/dream.rs` uses the simpler daemon-live-skip variant (skip the emit when daemon live to avoid the race). **Migrating recall + dream to AuditSink forwarding is a clean follow-on.**

### views.db schema
`memory/store.rs::apply_schema` runs `CREATE TABLE IF NOT EXISTS` on every `open()` → adding a table is backward-safe. Repository fns live next to `open()` (e.g. `record_recall_latency`, `recent_recall_latencies_ms`). New table this session: `idx_recall_latency`.

---

## 6. Remaining v1.0 backlog (what's actually left)

### A. GUI (Slint) — headless-untestable here
- **GU-01** — 6 of 10 post-onboarding settings tabs (Chat, Hemispheres, Channels, Skills, Plugins, Memory) are still "use the CLI" stubs. Everything they'll manage IS operable via the CLI today. Building these needs a display; here you can only verify compile + unit-binding, not visual. **KF-08** (Live Council Budget Meter Slint panel) + **SPEC-05** (GUI profile selector) are the same shape.

### B. Operator-operational (no code, or operator-run)
- **ARCH-05** — the migration recall-parity GATE + runbook ship; the 14-day shadow-run + grading + cutover are operator steps, not code that runs itself.
- **GR-03** — Trust Ledger / Autonomy Gradients / Recovery-first UX: needs an OPERATOR scope decision (v0.4 / v0.9 / defer) before planning.
- **HO-08** — Ecology-Schicht 3-step pickup (planning/pre-audit, not a test-backed build).

### C. BLOCKED on Alex (external)
- **minisign release keypair** — `KF-03 release` / `MAR-02` / `MV-01b` all wait on the operator generating + wiring a CI keypair (`minisign -G` + GitHub secrets). The verify code is already built; the operator proof key (`wal export --sign` / `verify-proof` / `proof-key`) already works.

### D. Documented small follow-on slices (buildable now, headless-OK)
- **SPEC-12 LLM theme summarisation (Phase 4b)** — replace the deterministic `cluster-N-seed-id` dream labels with an LLM-summarised motif. Needs a chat `Provider` built alongside the `EmbedProvider` in the dream path (both `provider_from_config` + `embed_provider_from_config`). Touch `daemon::dreaming::compose_dreams_with_embeddings` (add a `&dyn Provider`, summarise each cluster's previews).
- **SPEC-12 daemon-side `0xF4` emit** — thread a `Option<&WalWriterHandle>` into `cli::dreaming_task::run_one_pass` so the nightly cron also audits DREAM_COMPOSED (today only `neoth dream now` emits it). Updates the 6 existing `run_one_pass` tests (pass `None`) + the daemon `run` loop + serve's `dreaming_task::spawn` call.
- **AUDIT-RPC-01 remaining consumers** — wire the other one-shot CLIs (`lease`/`ingest`/`models`/`profile`/`recall_score`/`update`) to forward via `try_post_audit_frame` (each has a bespoke emit pattern). `os`/`fs` already done.
- **recall + dream → AuditSink forwarding** — migrate off the racing one-shot-writer pattern to the daemon-forward path.
- **SPEC-03b remainder** — stream/MCP-path council fallback (the threshold config surface shipped this session).

### E. Confirmed DEFER / BLOCKED (don't build — good reasons recorded)
- **ADV-08** (compaction_epoch) — 4-lens panel unanimous DEFER.
- **SPEC-12 cross-theme dependency merging** — needs the LLM summary first.
- Big-infra not on the v1.0 critical path: **ARCH-01** (tailslayer vector store — memory uses FTS5 + the shipped embed), **SPEC-11** (cross-channel identity + Phase-2 adapters Discord/Signal/iMessage/LINE/Matrix), **ARCH-06** (HLC WAL wire-format — HIGH-RISK core-format migration, needs a gremium + migration plan), **OP-01/OP-03** (need `cli/edit.rs` / an LSP client that don't exist), **A3-01/GM-01** (zero prereq), **PF-03** (no export consumer).

---

## 7. Recommended next pick

If continuing headless code: **SPEC-12 daemon-side 0xF4 emit** (smallest, closes the audit asymmetry) or **SPEC-12 LLM theme summarisation** (highest user value — turns `cluster-3-seed-918` into a real theme). Both buildable + testable here.

Otherwise the honest move is to **bank `1.0.0-beta.1`** — the headless code backlog is down to follow-on polish; GUI + operator-ops + the keypair are the real v1.0-final gaps, and two of those aren't code you can verify headless.

---

## 8. Gotchas hit this session (avoid re-hitting)

1. **`spawn_*` cron test as `#[test]` panics** ("no reactor") because `wal::writer::spawn` spawns a tokio task → make it `#[tokio::test]`.
2. **`!Send` `rusqlite::Connection` held across `.await`** makes a cron-tick future `!Send` → breaks `tokio::spawn`. Scope + DROP the connection BEFORE the await (`let data = { let conn = open()?; read(&conn)? };`).
3. **byte-string literals (`b"..."`) reject non-ASCII** (em-dash `—`) → use `-` in wasm/no_std example strings.
4. **clippy wrapper form** + **no-`| tail` on gate runs** (see §2).
5. **PROGRESS checkbox prefix** — a line may be `[ ]` or `[~]`; an Edit on the wrong prefix fails. Re-read the exact line first.
6. **The fp-check Stop hook** loops "Warte auf …-Notification" while a background task runs — that's expected; just keep polling the task output file until the completion notification, then proceed.
7. **`docs/cli-commands.md` drift** — any new `neoth` command/flag needs `NEOTH_REGEN_CLI_DOCS=1` + commit the regenerated file (else the docgen test fails).
8. **`python -` is blocked** — use `uv run python -` (or a temp `.py` + `uv run python /tmp/x.py`).

---

## 9. Operator (Alex) preferences + hard rules

- **"Ich baue NUR mit dir"** — Alex edits in the working tree sometimes (e.g. `credential --dry-run` this session); ADOPT + verify + commit his uncommitted WIP, don't rebuild or revert it. Always verify repo state at session start (`git status`, `git log`).
- **Verify before claiming done** — run the command, read the output, THEN say it works. No "should work."
- **No half-baked** — build the complete vertical or don't start; if a piece is genuinely a separate slice, ship the complete part + DOCUMENT the follow-on explicitly (don't leave a silent gap).
- **No deferring roadblocks** — fix blockers in-scope; defer only genuine multi-day work, with a recorded reason.
- **Update `PLAN/PROGRESS_v1_0.md` in the SAME turn** as shipping an item (flip the checkbox + a shipped note). Stale checkboxes confuse the next session.
- **Commit/push only when asked** — Alex authorized push throughout this session ("vergiss git push ned"). Public push must EXCLUDE `QUELLEN/`, `RECON/`, `SRC/target/`, operator-private paths (`.gitignore` handles it; verify leak-free).
- **Conventional commits**, atomic, `git diff --staged` for secrets before commit. No `Co-Authored-By` (attribution disabled globally).
- **German chat, English code/commits.** Direct, code > explanation, no filler.
- **Gremiums** (3-4 parallel senior-dev agents) for genuine architecture/crypto decisions only — not every small pick (efficiency feedback: "früher warst du viel effizienter").
- **Workflow `agent()` WITHOUT `schema:` is eaten by the fp-check Stop hook** (returns literal "approve") — always set `schema:` or read the `agent-*.jsonl` transcript.

---

## 10. Session-memory pointer

Full running burndown: `~/.claude/projects/.../memory/neoth_session35_burndown.md` (+ `MEMORY.md` index). The memory files carry the per-session detail; this handoff is the consolidated entry point.
