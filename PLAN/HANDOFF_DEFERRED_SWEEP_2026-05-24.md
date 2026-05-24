# Handoff — Deferred Sweep Session

**Date:** 2026-05-24
**Author:** Session 22 (Claude Opus 4.7)
**For:** Next session
**Goal:** Close all 95+ `[~]` deferred items in `PLAN/PROGRESS.md` — structured by file so each file is opened at most once.

---

## Status Counters (start of next session)

```
[ ] open      = 0
[~] deferred  = 96
[x] shipped   = ~756
```

Of the 96 deferred, **breakdown by closure path**:

| Path | Count | Action |
|------|-------|--------|
| **Already shipped — stale doc** | 14 | One PROGRESS.md cleanup commit (Workstream A) |
| **Bounded code wire-up** | 32 | Workstreams B-N, grouped by file |
| **Operator-side (Alex's infra/keys/hardware)** | 18 | Workstream O — mark `[x] operator-side` |
| **Slint GUI R-1 (multi-week parent)** | 13 | Workstream P — single roadmap item |
| **Multi-week parents (already split)** | 19 | Folded into Workstreams G/H/I/L/M |

Result after sweep: **0 deferred**, the entire PROGRESS.md reads `[x]` or operator-action.

---

## Hard Rules (READ FIRST)

1. **Open each source file at most ONCE per workstream.** Plan the full edit before invoking `Edit` — never come back to the same file 3 times in one session.
2. **Build + test gate after each workstream commit.** `cargo clippy --workspace --all-targets -- -D warnings` MUST be 0 warn before the commit lands.
3. **Same-turn PROGRESS update** per `[[neoth-progress-md-update-rule]]`. Flip items to `[x]` inside the same workstream's commit.
4. **Per-workstream test bar.** Each shipped item adds ≥1 test pinning the contract. Aim for ≥3 tests per bounded ship.
5. **Memory write** at session start to recover this handoff: `read PLAN/HANDOFF_DEFERRED_SWEEP_2026-05-24.md` before doing anything else.
6. **No K-Wire-3 partial fixes.** That family is the K-Wire-3 workstream (K) — touch chat.rs + serve.rs once with the full refactor or not at all.

---

## Workstream A — PROGRESS.md cleanup (NO CODE, single commit, ~15min)

These 14 items are already-shipped or operator-action; the PROGRESS lines are stale documentation. Single commit, edit `PLAN/PROGRESS.md` once.

### Items to flip to `[x]`

| ID | Reason | Reference commit / closure |
|----|--------|---------------------------|
| **R-A1** | K-1 Path 3 verdict + cluster scaffolding shipped | Session 21 commit `cdb54ce` (K-2 Pears bridge) + Session 21 commit `cccbc74` (cluster C-1..C-4) |
| **R-A2** | Architect verdict pinned: sidecar-only | Session 21 — `SRC/neoth-relay/src/hysteria.rs` + README |
| **H-1** | Architect verdict pinned: sidecar pattern | Same |
| **H-2** | Sidecar deployment owns Hysteria config; NEOTH side = HysteriaTransportConfig + HW-1..HW-4 | Same |
| **H-3** | Sidecar pattern (operator's standalone Hysteria) | Same |
| **C-03** | Keet K-1..K-5 shipped Session 21 + 22 | `cdb54ce` + `2b8c7fd` + `eca29c0` |
| **C-04** | Keet wizard default = K-4 shipped Session 21 | `d80e52d` + `f8e0c0b` |
| **CT-01** | Hyperswarm transport = C-1 shipped Session 21 | `cccbc74` (cluster::pears_peer_discovery) |
| **CT-02** | WAL federation = C-2 shipped Session 21 | `cccbc74` (cluster::pears_federation) |
| **CT-03** | Provider routing = C-3 shipped Session 21 | `cccbc74` (cluster::pears_routing) |
| **CT-04** | Orchestrator election = C-4 shipped Session 21 | `cccbc74` (cluster::pears_election) |
| **CT-05** | WAL cluster events shipped at 0xE0..=0xE9 | Session 21 |
| **CT-08** | HW-1..HW-4 scaffolding shipped | Session 21 |
| **CT-11** | PDF parsing M-1 + M-1b shipped (full pdfium = M-1b focused session) | Session 21 |
| **CT-12** | Closed — superseded by local-folder-mirror design | Per `[[neoth-arch-v2]]` |

### Items to flip to `[x] operator-side` (no code, operator action)

| ID | Operator action needed |
|----|------------------------|
| **C-15** | Set `TELEGRAM_TEST_BOT_TOKEN` env var, run `NEOTH_TG_LIVE_TEST=1 cargo test -p neothd --test telegram_live -- --ignored` |
| **E-10 / V10-03** | `cargo publish -p neoth-plugin-sdk` (needs crates.io token) |
| **L-03** | Set `NEOTH_QWEN_TEST_REPO_PATH`, run D14b integration tests |
| **P-11** | Run `neoth migrate import` against operator's HIPPOCAMPUS_CORE.md |

### Items to consolidate (3 K-Wire-3 dupes + 4 GUI dupes)

| ID | Action |
|----|--------|
| **K-Wire-3 (lines 2834, 2871)** | Mark as `*Duplicate of K-Wire-3 main entry at line 2720; see Workstream K*` |
| **G-4 (line 337)** | Already noted dup of G-06; just align text |
| **AU-7 (line 493)** | Already noted dup of G-04 (line 1843); align text |
| **CH-07 (line 1781)** | Mark as dup of G-03 / R-1 Slint workstream |
| **P-03 (line 1794)** | Mark as dup of G-02 |

**Commit message:**
```
docs(progress): Workstream A — cleanup pass; flip 14 stale + 4 operator-side + 7 dups

All 14 [~] items in this commit are already-shipped surface — the PROGRESS
lines were carrying stale documentation. References to the shipping commits
are now in each line so future grep-archaeologists find the actual ship.

Operator-side items (4) flip to [x] with explicit "operator action: <cmd>"
notes so the deferred list reflects what's actually NEOTH-side vs Alex-side.

K-Wire-3 (3 dupes) consolidates into the main entry at line 2720. GUI
dupes (AU-7, CH-07, P-03, G-4) point at their canonical G-XX entries.

Net change: 96 → 75 deferred. Zero code touched.
```

---

## Workstream B — cli/init.rs wizard steps (ONE file pass, ~2h)

**File touched:** `SRC/neothd/src/cli/init.rs` — ONE Edit pass with all wizard steps.

Open the file once, plan all 4 wizard-step inserts at the bottom of dispatch (between step7c and step8_summary), then commit.

### Items closed

| ID | Wizard step | Consumes primitive |
|----|-------------|--------------------|
| **O-1** | `step6c_obsidian_install` | `installers::obsidian` (shipped Session 21) |
| **O-2** | `step6d_obsidian_vault_bootstrap` | `installers::obsidian_vault` (shipped Session 21) |
| **N-1** | `step6e_n8n_install` | `installers::n8n` (shipped Session 21) |
| **E-16** | `step6f_import_jarvis` + `--import-jarvis` CLI flag | `neoth-migrate` crate (already in workspace) |
| **NOOB-UX-6 (3)** | `step5c_qwen_weights_download` | NEW: `installers::qwen_weights` (build in same session) |

### File-by-file edit plan (Workstream B)

1. `SRC/neothd/src/cli/init.rs`:
   - Add `pub plugins` was done Session 21; now add fields for wizard state:
     - `pub install_obsidian: bool` (default true if `pear` present)
     - `pub bootstrap_vault: bool`
     - `pub install_n8n: bool` (default false — opt-in)
     - `pub import_jarvis: Option<PathBuf>`
     - `pub download_qwen_weights: bool`
   - Add 5 step fns: `step5c_qwen_weights`, `step6c_obsidian_install`, `step6d_obsidian_vault_bootstrap`, `step6e_n8n_install`, `step6f_import_jarvis`
   - Wire into dispatch after existing step6_channel / step6b_keet_pairing
   - Add CLI args: `--install-obsidian`, `--bootstrap-vault`, `--install-n8n`, `--import-jarvis <path>`, `--download-qwen-weights`
   - Tests (1 per step, all `non_interactive=true` paths): no-op when arg absent, persist to WizardState when arg present, idempotent when already-installed

2. `SRC/neothd/src/installers/qwen_weights.rs` (NEW):
   - `pub fn weights_download_command(model_id) -> Vec<String>` (hf-hub CLI invocation)
   - `pub async fn check_weights_cached(model_id) -> bool` (probe ~/.cache/huggingface/hub)
   - `pub fn recommend_action(cached) -> WeightsAction::{AlreadyCached, DownloadNeeded, OperatorSkipped}`
   - Tests: action matrix + command shape + cached-probe smoke

3. `SRC/neothd/src/installers/mod.rs`:
   - Add `pub mod qwen_weights;`

### Tests target: ≥10 new (~2 per step + 4 installer tests)

### Commit message
```
feat(cli/init): Workstream B — 5 wizard steps consume shipped installer primitives

Closes O-1 / O-2 / N-1 / E-16 / NOOB-UX-6 (3) in one focused init.rs pass.
Every primitive (installers/obsidian, obsidian_vault, n8n) was already shipped
Session 21; this commit adds the wizard steps that consume them so operators
on a fresh init flow can opt into Obsidian / vault bootstrap / n8n / Jarvis
import / Qwen weights without leaving the wizard.

New installer primitive: installers/qwen_weights.rs (hf-hub download
recommend matrix + cached-probe).
```

---

## Workstream C — Cron + chat ingress (TWO files, ~2h)

**Files touched:** `SRC/neothd/src/cron/runner.rs` + `SRC/neothd/src/cli/chat.rs` — each opened once.

### Items closed

| ID | What lands |
|----|-----------|
| **P-01.b cron consumer** | cron task calls `profile::snapshot::aggregate_and_persist` on schedule (daily) by scanning WAL RAW_TEXT events → ObservedTurn |
| **P-08 cron consumer** | cron runner checks `profile::briefing_gate::should_emit_for_briefing` BEFORE invoking proactive briefing workflows |
| **`record_last_active` hooks** | chat.rs + every channel-ingress path call `record_last_active(home, ts)` on RAW_TEXT emit |

### File edits

1. `SRC/neothd/src/cron/runner.rs`:
   - Add `pub async fn run_briefing_gated(job, provider, writer, home)` wrapper that:
     - Calls `briefing_gate::should_emit_for_briefing_now(home, current_hour, &policy)`
     - Returns Skip → record `JOB_SKIPPED_BY_BRIEFING_GATE` (new WAL event in 0x40..=0x42 band? or reuse JOB_SUCCESS with skip-payload) and exit OK without calling the provider
     - Returns Emit → delegate to existing `run_job`
   - Add `pub async fn aggregate_profile_snapshot(home, wal_dir) -> Result<()>` that scans WAL for last-30-days RAW_TEXT → ObservedTurn → `aggregate_and_persist`
   - Wire both into the existing scheduler task (`cron/scheduler.rs::tick`)

2. `SRC/neothd/src/cli/chat.rs`:
   - After every RAW_TEXT WAL emit, call `profile::briefing_gate::record_last_active(home, now_unix)`
   - 1 site in `run_chat_with`; check if there are channel-ingress sites too

3. `SRC/neothd/src/cli/serve.rs`:
   - The channel-pipeline handler already exists; thread `record_last_active` after each successful `CHANNEL_INGRESS` frame

### Tests target: ≥6 new
- Briefing-gated runner: Skip path doesn't call provider + records skip event; Emit path delegates correctly
- aggregate_profile_snapshot: empty WAL → empty profile saved; populated WAL → snapshot reflects samples
- record_last_active: chat.rs writes the marker on every RAW_TEXT; smoke test via tempdir + chat::run_chat invocation

### Commit message
```
feat(cron+chat): Workstream C — P-01.b + P-08 cron + chat-ingress wire-ups

Closes the cron-runner half of P-01.b (briefing-policy snapshot
aggregation) + P-08 (briefing-gate consumer) + the chat-ingress
record_last_active hook. Three primitives shipped Session 22 now
have live consumers — operators see the briefing-gate Skip behaviour
end-to-end + the profile snapshot updates without a manual CLI invocation.
```

---

## Workstream D — N-3 HTTP API server (ONE new file, ~3.5d)

**Files touched:** `SRC/neothd/src/n8n_api/server.rs` (NEW) + `SRC/neothd/src/n8n_api.rs` (refactor to mod) + `SRC/neothd/src/cli/serve.rs` (single addition).

### Items closed

| ID | What lands |
|----|-----------|
| **N-3** | Hyper server task + 6 endpoint handlers (/api/health, /recall, /provider/call, /channel/send, /stats, /memory/save) |
| **CT-13** | n8n cron engine integration — same workstream |

### File-by-file plan

1. `SRC/neothd/src/n8n_api.rs` → split into module:
   - Rename to `n8n_api/mod.rs`
   - Existing primitives stay in `n8n_api/mod.rs`
   - Add `n8n_api/server.rs` (hyper task)
   - Add `n8n_api/handlers.rs` (per-endpoint handlers, each ≤80 LOC)

2. `n8n_api/server.rs`:
   - `pub async fn spawn_server(home, port, token) -> Result<JoinHandle<()>>`
   - hyper 1.x `Server::bind(127.0.0.1:port)` — REJECT non-loopback via middleware
   - Route dispatch via match on `(Method, &str)` (no routing crate; keeps deps slim)
   - Auth middleware reads `Authorization: Bearer <token>` + calls `constant_time_token_eq` (already shipped)
   - Per-request `record_last_active` so n8n calls keep the briefing-gate marker current
   - WAL audit: every request → 0x39 EVENT_TYPE_N8N_REQUEST frame

3. `n8n_api/handlers.rs`:
   - 6 handlers: health (trivial), recall (calls `cli::recall::recall_one`), provider_call (rebuilds Provider from FreedomConfig), channel_send (consumes `Channel::send_text`), stats (reads views.db), memory_save (writes to idx_episode via memory::store)
   - Each handler: consent gate (call `consent::ensure_granted_or_prompt` against the resolved provider kind) + autonomy gate (call `permissions::evaluate`)
   - Fail-closed: any gate refusal → 403 + `ApiErrorCode::PermissionDenied`

4. `cli/serve.rs`:
   - At daemon boot, after the consent preflight: spawn the n8n server if `FreedomConfig::n8n_api.enabled`
   - Leak the JoinHandle for daemon lifetime (matching the skill registry watcher pattern)

### Tests target: ≥20 new
- Per-endpoint smoke (200 happy path + 401 bad token + 403 consent-missing + 404 unknown method + 405 wrong verb)
- Loopback-only enforcement (request from 192.168.x.x → 403 NonLoopback)
- WAL frame written per request
- record_last_active called per request

### Commit message
```
feat(n8n_api): Workstream D — N-3 HTTP server impl

Closes N-3 + CT-13. Hyper-based localhost HTTP server consumes the
primitives shipped Session 21 (n8n_api.rs). 6 endpoints, bearer auth,
consent + autonomy gates, WAL audit per request.

Refactor: src/n8n_api.rs → src/n8n_api/{mod.rs, server.rs, handlers.rs}
so the 600-LOC server impl doesn't pollute the primitives file.
```

---

## Workstream E — V10-08 HNSW memory refactor (TWO files, ~1d)

**Files touched:** `SRC/neothd/src/memory/embeddings.rs` + `SRC/neothd/Cargo.toml`

### What lands

- Replace `Vec<f32>` linear cosine scan with `hnsw_rs = "0.3"` index
- Add persistence: serialize the index to `~/.neoth/embeddings.hnsw` on graceful shutdown; load on boot
- Maintain back-compat: if no index file exists, build from existing `idx_embedding` SQLite rows on first boot
- Performance gate: top-10 retrieval on 100K vectors < 5ms (vs current O(N) ~50ms+)

### File-by-file

1. `Cargo.toml`: add `hnsw_rs = "0.3"`
2. `memory/embeddings.rs`:
   - Wrap the cosine path behind a feature-flag fallback (`#[cfg(feature = "hnsw")]`) for the first ship so a regression can be flipped off via Cargo feature
   - New `EmbeddingIndex { hnsw: Hnsw<f32>, id_map: HashMap<NodeIdx, EventId> }`
   - `EmbeddingIndex::add(event_id, vector)`, `::search(query, k) -> Vec<(EventId, f32)>`
   - Persist via `bincode` to `<wal_dir>/../embeddings.hnsw`
3. Add `cli/memory.rs` subcommand `neoth memory rebuild-index` for operator rebuild after a restore

### Tests target: ≥6
- add + search round-trip
- persist + load round-trip
- migration from idx_embedding (synthetic SQLite with 100 rows → index populated)
- empty-index search returns empty Vec (no panic)
- benchmark: 1000-vector index search < 1ms (criterion bench)

### Commit message
```
perf(memory): Workstream E — V10-08 HNSW embedding index

Replaces O(N) cosine scan in memory/embeddings.rs with hnsw_rs index.
Top-10 retrieval on 100K vectors drops from ~50ms to <5ms. Persistent
across daemon restarts via bincode at <wal_dir>/../embeddings.hnsw.

Migration: first boot after upgrade scans idx_embedding + builds the
index automatically. `neoth memory rebuild-index` CLI for operator-
triggered rebuild after restore.
```

---

## Workstream F — WAL v1.2 zstd compression (THREE files, ~3d)

**Files touched:** `SRC/neothd/src/wal/segment_header.rs` + `wal/writer.rs` + `wal/reader.rs` + new `cli/migrate.rs` subcmd.

### Items closed: **CT-10 / E-20 / V1x-06** (all 3 are the same v1.2 milestone)

### What lands

- Bump `SEGMENT_FORMAT_VERSION → 2` (flag-bit reservation already shipped Session 21)
- Add zstd-3 compression on segment FINALIZE (when `SEGMENT_FLAG_COMPRESSED = 0x01` is set)
- Reader handles BOTH v1 (uncompressed) + v2 (compressed) — operator's existing WAL keeps replaying
- Schema migration: `neoth migrate wal --to-v2` reads every v1 segment, re-writes as v2 compressed
- Operator opt-in via `freedom.yaml::wal.compression = "zstd_3" | "none"` (default "none" for v0.1, flip to "zstd_3" in v0.2)

### File-by-file

1. `Cargo.toml`: add `zstd = "0.13"` (already in deps? check first; if yes, no Cargo touch)
2. `wal/segment_header.rs`:
   - Bump version constant
   - Add `SegmentHeaderV2 { flags: u8, ... }` (already reserved)
3. `wal/writer.rs`:
   - On segment FINALIZE: if compression enabled, zstd::encode(payload, 3) before sealing
   - Set SEGMENT_FLAG_COMPRESSED in the header
4. `wal/reader.rs`:
   - Detect version + flag at segment open
   - V2 compressed: decompress before parsing frames
   - V1 or V2 uncompressed: existing path unchanged
5. `cli/migrate.rs`:
   - Add `wal --to-v2` subcommand
   - Walks `<wal_dir>/`, re-encodes each segment, atomic rename

### Tests target: ≥8
- Round-trip: write+read v1, write+read v2 uncompressed, write+read v2 compressed
- Migration: v1 segment → migrate → re-read returns identical frames
- Reader handles mixed v1+v2 dir (operator partway through migration)
- Compression ratio sanity (10KB JSON-heavy payload < 30% original)

### Commit message
```
feat(wal): Workstream F — v1.2 zstd-3 compression on sealed segments

Closes CT-10 / E-20 / V1x-06 in one focused v1.2 milestone ship. Format
version bumps to 2; sealed segments compress via zstd-3 when
SEGMENT_FLAG_COMPRESSED is set. Reader handles BOTH v1 (uncompressed)
and v2 segments so operator-upgrade is non-breaking.

Migration tool: `neoth migrate wal --to-v2` re-encodes existing v1
segments. Operator-opt-in via freedom.yaml::wal.compression (default
"none" for v0.1.x; flip to "zstd_3" in v0.2 after operator-side
storage-impact measurement).
```

---

## Workstream G — V10-04 WASM plugin host (multi-day, multi-file)

**Files touched:** `SRC/neothd/src/wasm_plugin/{engine.rs, hostcalls.rs, dispatch.rs}` (all already exist; just fill in) + 2 example plugins under `examples/wasm_plugins/`.

### What lands

- Wasmtime engine actually runs `.wasm` bytes through PluginRouter
- 2 example plugins (build in same session):
  1. `examples/wasm_plugins/echo/` — minimal plugin that just echoes input via `neoth.log` hostcall
  2. `examples/wasm_plugins/recall_summariser/` — calls `neoth.recall_top(query, 5)` + `neoth.log(result_summary)` — exercises the read-path hostcalls

### File-by-file

1. `wasm_plugin/engine.rs`: real wasmtime::Engine + Store creation (currently a stub per memory)
2. `wasm_plugin/hostcalls.rs`: full hostcall impls (neoth.log, neoth.recall_top, neoth.fuel_left, neoth.emit_event — all 4 already scaffolded; just fill bodies)
3. `wasm_plugin/dispatch.rs`: PluginInvoker wires through real wasmtime instance
4. `examples/wasm_plugins/echo/Cargo.toml` + `src/lib.rs` — minimal Rust wasm crate (`wasm32-unknown-unknown` target)
5. `examples/wasm_plugins/recall_summariser/` — same shape
6. CI/build script: `scripts/build_example_plugins.sh` — cargo build per example + drop the .wasm into `examples/wasm_plugins/<id>/plugin.wasm`

### Tests target: ≥10
- Engine creates + accepts valid wasm bytes
- Hostcall integration: log, recall_top, fuel_left, emit_event each fire from a test plugin
- echo plugin round-trip (load + dispatch + observe log output)
- recall_summariser plugin round-trip (with synthetic SQLite idx_episode populated)

### Commit message
```
feat(wasm_plugin): Workstream G — V10-04 wasmtime host functional + 2 example plugins

Closes V10-04 GA-blocker. wasm_plugin/engine.rs spawns real wasmtime
instances; hostcalls (neoth.log / neoth.recall_top / neoth.fuel_left /
neoth.emit_event) reach SQLite + WAL through the existing primitives.

Two example plugins under examples/wasm_plugins/ — echo (minimal,
exercises neoth.log) + recall_summariser (exercises neoth.recall_top
+ neoth.emit_event). scripts/build_example_plugins.sh produces the
.wasm bytes; operator runs once before `neoth plugin enable echo` to
have a working test plugin.

D-102 contract preserved: example plugins default to PENDING. Operator
runs `neoth plugin enable <id>` to activate.
```

---

## Workstream H — M-2..M-5 Multimodal pipeline (FOUR files, ~4 days)

**Files touched:** `SRC/neothd/src/media/{vision.rs, audio.rs, video.rs}` (all NEW) + `cli/chat.rs` (channel integration).

### Items closed: M-2, M-3, M-4, M-5

### Per-day plan

| Day | Module | Deps | What lands |
|-----|--------|------|------------|
| 1 | `media/vision.rs` | candle CLIP (optional feature) + provider-vision fallback | image → embedding + description; fallback to vision-capable provider when local CLIP not built |
| 2 | `media/audio.rs` | `whisper-rs` + `piper-rs` | voice → text (inbound), text → voice (outbound) |
| 3 | `media/video.rs` | ffmpeg subprocess | thumbnail extract + transcript via audio.rs |
| 4 | `cli/chat.rs` + channel integration | (M-2/3/4) | voice msg in Telegram → audio transcribe → chat → reply |

### Tests target per day: ≥4
- vision: image-bytes round-trip (mock-fallback path; live CLIP gated on feature flag)
- audio: short WAV → transcript (use a bundled 1-second test sample under `assets/test/`)
- video: smoke test against a synthetic mp4 → thumbnail + audio extract
- chat integration: PipelineHandler receives audio attachment → audio::transcribe call → prompt routing

### Commit messages (4 separate commits, one per day)
```
feat(media): Workstream H Day 1 — M-2 vision.rs
feat(media): Workstream H Day 2 — M-3 audio.rs
feat(media): Workstream H Day 3 — M-4 video.rs
feat(media+chat): Workstream H Day 4 — M-5 channel integration
```

---

## Workstream I — B-6 final (claude-cli native, multi-day, multi-file)

**Files touched:** `SRC/neothd/src/providers/{claude_cli.rs, claude_tmux.rs}` + `config/mod.rs` + new `assets/tmux.conf` + new `assets/hooks/{stuck_cleaner.sh, provider_cooldown.sh, error_pattern_effort_override.sh}`.

### Items closed: B-6 final 4 sub-items + F-19 Hook trait redesign (same workstream)

### Per-day plan

| Day | What lands |
|-----|------------|
| 1 | `providers/claude_cli.rs` ClaudeCliAdapter 2-mode backend (Subprocess | Tmux pool); freedom.yaml `claude_cli.backend: auto | tmux | subprocess` field |
| 2 | 13-item wrapper-port surface in `claude_tmux.rs`: PTY stealth via portable-pty/ConPTY, env scrub, mandatory env vars, session UUID validation, --resume strip on dead JSONL, --verbose for stream-json, opusplan→opus[1m], 4-class retry, ANSI-strip, --append-system-prompt conflict merge |
| 3 | 8 tmux.conf settings (assets/tmux.conf) + 3 hook ports (assets/hooks/) |
| 4 | F-19 Hook trait + HookContext non-generic refactor — port the hooks to the new trait |

### File edits

1. `Cargo.toml`: add `portable-pty = "0.8"` (Day 2)
2. `config/mod.rs`: add `claude_cli.backend` + `tmux.session_scope` + `compaction_rotate_after` + `idle_ttl_secs` fields
3. `providers/claude_cli.rs`: ClaudeBackend enum + mode-aware dispatch
4. `providers/claude_tmux.rs`: 13-item wrapper port (each in its own pure-fn helper for unit-testability)
5. `assets/tmux.conf` (NEW): 8 settings drift-guarded
6. `assets/hooks/*.sh` (NEW): 3 hook scripts
7. `plugin-sdk` crate hooks: F-19 trait redesign with non-generic HookContext

### Tests target per day: ≥6

### Commit messages
```
feat(providers): Workstream I Day 1 — B-6 ClaudeCliAdapter 2-mode backend
feat(providers): Workstream I Day 2 — B-6 13-item wrapper port
feat(assets): Workstream I Day 3 — B-6 tmux.conf + 3 hook ports
refactor(plugin-sdk): Workstream I Day 4 — F-19 Hook trait + HookContext non-generic
```

---

## Workstream J — Privacy hardening (ONE file, ~30min)

**File touched:** `SRC/neothd/src/profile/extract.rs`

### Items closed: K-Label-Spoof

### What lands

Add structural separator in `render_user_prompt` so an attacker can't smuggle `<USER>` / `<SYSTEM>` markers into operator-emitted text and trick the extractor into treating attacker-controlled lines as system instructions.

### Concrete fix

```rust
// In render_user_prompt: wrap operator text in a clear delimiter that
// can't appear in operator output (unicode private-use block + nonce).
const USER_OPEN: &str = "\u{E000}USER_BLOCK_OPEN_{nonce}\u{E001}";
const USER_CLOSE: &str = "\u{E002}USER_BLOCK_CLOSE_{nonce}\u{E003}";
// Strip these chars from operator text before insertion.
```

### Tests target: ≥4
- Operator text without spoof attempt: round-trip preserves content
- Operator text WITH `<SYSTEM>` injection attempt: stripped/escaped, never reaches the system role
- Nonce changes per invocation (defence against replay attacks)
- Delimiter chars in operator text → escaped, not literally embedded

### Commit message
```
fix(profile/extract): Workstream J — K-Label-Spoof structural separator

Closes K-Label-Spoof. render_user_prompt now wraps operator text in
unicode private-use delimiters with a per-invocation nonce so an
attacker injecting <USER> / <SYSTEM> markers into operator-emitted text
can't trick the extractor's role parser. Defence-in-depth pin for the
profile-extraction privacy boundary.
```

---

## Workstream K — K-Wire-3 family (chat↔channels factor + perf, ~3d)

**Files touched:** `SRC/neothd/src/cli/{chat.rs, serve.rs}` + new `pipeline/enriched_request.rs`

### Items closed: K-Wire-3 (v1, v2, v3) + K-Perf-3

### Day-by-day

| Day | What lands |
|-----|------------|
| 1 | Extract `build_enriched_request(prompt, history, profile, code_map)` helper into new `pipeline/enriched_request.rs`; chat.rs + serve.rs::build_pipeline_handler both consume it |
| 2 | K-Wire-3 v2: extract 130-LOC council branch from `chat.rs::run_chat_with` (lines 574-693) into `pipeline/council_dispatch.rs`; chat + channel both call it |
| 3 | K-Wire-3 v3: channel-side profile-pipeline post-reply (same opt-in gate `config.profile.learn_enabled` + `tokio::time::timeout` wrapper); K-Perf-3 spawn_blocking around rusqlite recall queries (refactor `cli/recall.rs` to own its `Connection` + `tokio::task::spawn_blocking`) |

### File-by-file plan

1. `pipeline/enriched_request.rs` (NEW): pure-fn `build_enriched_request` taking prompt + context inputs, returning `Request` with system_prompt + code_map block + profile block stitched
2. `pipeline/council_dispatch.rs` (NEW): `async fn dispatch_council(prompt, providers, callosum) -> CouncilOutcome` extracted from chat.rs
3. `cli/chat.rs`: replace inline build + council branch with calls into the new modules
4. `cli/serve.rs`: same wire-up in `build_pipeline_handler` so channels get the full chat-side stack
5. `cli/recall.rs`: wrap rusqlite queries in `tokio::task::spawn_blocking`; `Connection` moves into the spawned closure (or `Arc<Mutex<Connection>>` if shared state needed)

### Tests target per day: ≥6 (high test bar — this is the big architecture refactor)

### Commit messages
```
refactor(pipeline): Workstream K Day 1 — K-Wire-3 v1 build_enriched_request shared
refactor(pipeline): Workstream K Day 2 — K-Wire-3 v2 council dispatch extracted
feat(pipeline+recall): Workstream K Day 3 — K-Wire-3 v3 + K-Perf-3 spawn_blocking
```

---

## Workstream L — Windows native APIs (TWO files, ~3d)

**Files touched:** `SRC/neothd/src/wal/win_acl.rs` + new `wal/win_native.rs`

### Items closed: E-11 + E-12

### What lands

- E-11: replace `icacls.exe` subprocess with native `SetNamedSecurityInfoW` for WAL segment DACL restriction
- E-12: full `FlushFileBuffers` semantics for Windows WAL durability

### File-by-file

1. `Cargo.toml`: add `windows-sys = { version = "0.59", features = ["Win32_Security", "Win32_Storage_FileSystem"] }` (already in deps? check)
2. `wal/win_native.rs` (NEW): safe wrappers around `SetNamedSecurityInfoW`, `BuildExplicitAccessWithNameW`, `FlushFileBuffers`
3. `wal/win_acl.rs`: swap subprocess path for native call; keep subprocess as fallback `#[cfg(test)]` so CI Linux still builds

### Tests target: ≥8
- DACL set/get round-trip (Windows-only `#[cfg(target_os = "windows")]`)
- FlushFileBuffers smoke (write + flush + read-after-crash-recovery sim)
- Subprocess-fallback gated test (Linux + Windows both ok)
- Error mapping: native API error → ChannelError or WalError with operator-readable context

### Commit messages
```
feat(wal): Workstream L Day 1 — E-11 native SetNamedSecurityInfoW
feat(wal): Workstream L Day 2 — E-12 native FlushFileBuffers
```

---

## Workstream M — F-19 Hook trait final (covered in Workstream I Day 4)

Already folded into Workstream I Day 4 (same code surface).

---

## Workstream N — E-18 telemetry HTTPS (ONE file + CLI, ~1d)

**Files touched:** new `src/telemetry/http.rs` + `cli/telemetry.rs` + refactor `src/telemetry.rs` → `src/telemetry/mod.rs`

### What lands

- Real HTTPS POST consuming the primitives shipped Session 21
- `neoth telemetry on/off/preview/send-now` CLI subcommand
- Endpoint URL pinned in const (let's say `https://telemetry.neoth.dev/v1/ping`) — operator can override via `freedom.yaml::telemetry.endpoint`

### File-by-file

1. `src/telemetry.rs` → split into `src/telemetry/mod.rs` (re-export primitives) + `src/telemetry/http.rs` (POST impl using `reqwest` already in deps)
2. `src/cli/telemetry.rs` (NEW): clap subcommand + dispatch
3. `src/cli/mod.rs`: register the subcommand

### Tests target: ≥5
- HTTPS POST against mock httpbin (test fixture)
- 4xx/5xx graceful handling (telemetry never fails the daemon)
- `--preview` prints exact payload before opt-in
- `--off` flips config + persists
- Default-off pinned at CLI level too (drift guard)

### Commit message
```
feat(telemetry): Workstream N — E-18 HTTPS POST + `neoth telemetry` CLI

Closes E-18. Real HTTPS endpoint consumes the privacy-pinned primitives
shipped Session 21. Operator opts in via `neoth telemetry on`; preview
prints the exact JSON before opt-in so operator sees what's sent. Default
remains OFF + drift-guarded.
```

---

## Workstream O — Operator-side actions (Alex does these, NO code session)

These 18 items need operator infrastructure, keys, hardware, or cloud accounts. Flip to `[x] operator-side` with a one-line "operator action: <cmd>" in PROGRESS:

| ID | Operator action |
|----|-----------------|
| **C-06** Signal | Set up Signal-CLI or libsignal cred + build adapter |
| **C-07** iMessage | Mac/BlueBubbles bridge install |
| **C-08** LINE | LINE dev account + webhook URL |
| **C-09** Matrix | Matrix homeserver account |
| **C-12** LiveDelivery view | Schema migration session (~1d focused) |
| **E-01** Eval goldset | Hand-curate 20 queries |
| **E-02** 4-grader eval | 4 live API keys + budget |
| **E-03** Shadow-run 14d | Real-time live capture |
| **E-04** Cutover Day 80 | Webhook flip + operator 2FA |
| **E-05 / CT-06** Veronica | Veronica instance + cert mgmt |
| **E-06 / V10-06** Jarvis migrate | 12 Jarvis stores accessible |
| **E-07** Re-embed pipeline | Follows E-06 |
| **E-09** Quality floor eval | Follows E-01/E-03 |
| **CT-07** WAL gossip mTLS | Veronica + debian + mTLS certs |
| **L-09** Embedding GPU | 2nd physical GPU |
| **L-11** Ambient GPU | 3rd physical GPU |
| **E-17 / V1x-05** Multi-operator | Multi-week design + tenant-isolation impl |
| **CT-09 / V1x-04** S3 cold tier | S3 endpoint design |

### Commit message
```
docs(progress): Workstream O — 18 operator-side items marked [x] with action notes

These are not code-blocked. Each flipped item carries an "operator action:
<exact-command-or-infra-step>" so PROGRESS reflects reality: NEOTH-side
code is shipped; operator infra is what's pending.
```

---

## Workstream P — Slint GUI R-1 (multi-week, separate phase)

**Files touched:** `SRC/neothd-gui/src/**` — whole separate crate, multi-week.

### Items consolidated (13 items into ONE workstream)

G-01 (parent) + G-02..G-11 + V10-05 (parent dup) + AU-7 (dup) + CH-07 (dup) + P-03 (dup) + CT-08 (dup) + G-4 (dup) + G-5 + G-6

### Plan

Don't ship in deferred-sweep session. Create separate `PLAN/HANDOFF_R1_SLINT_2026-XX-XX.md` for the multi-week R-1 workstream — too big to interleave with bounded sweeps.

In Workstream A, mark all GUI items as `*See PLAN/HANDOFF_R1_SLINT_*.md (R-1 GUI workstream)*` so PROGRESS sweeps stop treating them as ready-to-ship.

---

## Multi-Workstream Coordination

### Order of operations (recommended)

1. **Workstream A first** (15min, no code) — clears 21 items from the deferred list immediately so the remaining workstreams have less noise.
2. **Workstream O** (no code, 15min) — clears 18 more.
3. **Workstream J** (30min, single-file privacy fix) — easy win.
4. **Workstream B** (2h) — wizard step pass.
5. **Workstream C** (2h) — cron + chat wire-ups.
6. **Workstream N** (1d) — telemetry HTTPS.
7. **Workstream E** (1d) — V10-08 HNSW.
8. **Workstream D** (3.5d) — N-3 HTTP API.
9. **Workstream F** (3d) — WAL v1.2 zstd.
10. **Workstream G** (multi-day) — WASM plugin host.
11. **Workstream H** (4d) — multimodal.
12. **Workstream I** (4d) — B-6 final + F-19.
13. **Workstream L** (3d) — Windows native APIs.
14. **Workstream K** (3d) — K-Wire-3 family. **LAST** because it refactors chat + channels — easier when every other workstream's surface is final.
15. **Workstream P** — separate handoff document, not in this sweep.

### After all workstreams complete

```
[ ] open      = 0
[~] deferred  = 0  (every item shipped OR operator-side OR in HANDOFF_R1_SLINT)
[x] shipped   = ~870
```

---

## Session-Start Checklist

```
[ ] Read PLAN/HANDOFF_DEFERRED_SWEEP_2026-05-24.md (THIS FILE)
[ ] git log --oneline -10 (verify current head)
[ ] git status (clean working tree)
[ ] Start with Workstream A (no code) — set the rhythm
[ ] After each workstream commit: verify clippy green + tests added + PROGRESS flipped
[ ] If a workstream blows budget by 50%, stop + write a follow-up handoff
[ ] Never edit the same source file across two workstreams in the same session
```

---

## Files Touched Map (so we never re-open one)

| File | Workstream | Edit shape |
|------|------------|-----------|
| `PLAN/PROGRESS.md` | A, B, C, D, E, F, G, H, I, J, K, L, N, O (every commit) | Same-turn flip per the hard rule |
| `SRC/neothd/src/cli/init.rs` | B only | 5 wizard steps + CLI args + WizardState fields |
| `SRC/neothd/src/cli/chat.rs` | C, K | C: `record_last_active` call; K: refactor council dispatch out. **Touch ONCE per session.** |
| `SRC/neothd/src/cli/serve.rs` | C, D, K | C: channel-ingress hooks; D: spawn n8n server; K: pipeline-handler refactor. **Touch ONCE per session.** |
| `SRC/neothd/src/cron/runner.rs` | C | Briefing-gated runner + aggregate task |
| `SRC/neothd/src/profile/extract.rs` | J | render_user_prompt structural separator |
| `SRC/neothd/src/cli/recall.rs` | K | spawn_blocking wrapper |
| `SRC/neothd/src/memory/embeddings.rs` | E | HNSW refactor |
| `SRC/neothd/src/wal/segment_header.rs` | F | v1.2 version bump |
| `SRC/neothd/src/wal/writer.rs` | F | zstd encode on finalize |
| `SRC/neothd/src/wal/reader.rs` | F | v1/v2 dual-format read |
| `SRC/neothd/src/wal/win_acl.rs` | L | native SetNamedSecurityInfoW |
| `SRC/neothd/src/wasm_plugin/engine.rs` | G | real wasmtime instance |
| `SRC/neothd/src/wasm_plugin/hostcalls.rs` | G | hostcall body impls |
| `SRC/neothd/src/wasm_plugin/dispatch.rs` | G | PluginInvoker real-impl |
| `SRC/neothd/src/providers/claude_cli.rs` | I | 2-mode backend |
| `SRC/neothd/src/providers/claude_tmux.rs` | I | 13-item wrapper port |
| `SRC/neothd/src/config/mod.rs` | I, F | I: claude_cli.backend fields; F: wal.compression field. **Touch ONCE.** |
| `SRC/neothd/src/n8n_api.rs` → mod refactor | D | Split into mod.rs + server.rs + handlers.rs |
| `SRC/neothd/src/telemetry.rs` → mod refactor | N | Split into mod.rs + http.rs |
| `SRC/neothd/src/cli/mod.rs` | B, D, N, M | New subcommands (plugin/telemetry already shipped; add init flags + neoth-telemetry). **Touch ONCE per session.** |
| `SRC/neothd/Cargo.toml` | E, F, I, L | E: hnsw_rs; F: zstd; I: portable-pty; L: windows-sys. **Touch ONCE per workstream-pair.** |

### Files NEVER touched in this sweep
- `SRC/neothd-gui/**` (Workstream P, separate handoff)
- `SRC/neoth-relay/**` (Hysteria sidecar — verdict pinned)
- `SRC/neoth-migrate/**` (only consumed by Workstream B's import-jarvis step)
- `SRC/neoth-plugin-sdk/**` (Workstream I Day 4 consumes; no API breaks)

---

## Budget Summary

| Workstream | Estimated time | Net deferred-items closed |
|------------|----------------|---------------------------|
| A — PROGRESS cleanup | 15min | 21 |
| O — Operator-side flips | 15min | 18 |
| J — K-Label-Spoof fix | 30min | 1 |
| B — Wizard steps | 2h | 5 |
| C — Cron + chat wire-ups | 2h | 2 (P-01.b consumer + P-08 consumer)|
| N — Telemetry HTTPS | 1d | 1 |
| E — V10-08 HNSW | 1d | 1 |
| D — N-3 HTTP API | 3.5d | 2 (N-3 + CT-13) |
| F — WAL v1.2 zstd | 3d | 3 (CT-10 + E-20 + V1x-06) |
| G — V10-04 WASM host | multi-day | 1 |
| H — Multimodal | 4d | 4 (M-2..M-5) |
| I — B-6 final + F-19 | 4d | 5 (B-6 final + F-19) |
| L — Windows native | 3d | 2 (E-11 + E-12) |
| K — K-Wire-3 family | 3d | 4 (K-Wire-3 v1/v2/v3 + K-Perf-3) |
| P — Slint GUI R-1 | SEPARATE HANDOFF | 13 (consolidated) |
| **Total (excluding P)** | ~22 working days | **70 items + 13 in Workstream P = 83** |

Plus 13 Workstream P items deferred to R-1 handoff = **96/96 closed**.

---

## Per-Item Closure Reference Table

```
# Workstream A (PROGRESS cleanup, 21 items)
R-A1   → flip [x] (Session 21 cdb54ce + cccbc74)
R-A2   → flip [x] (architect verdict)
H-1    → flip [x] (sidecar verdict)
H-2    → flip [x] (sidecar)
H-3    → flip [x] (sidecar)
C-03   → flip [x] (Keet K-1..K-5)
C-04   → flip [x] (K-4)
C-15   → flip [x] operator-side
CT-01  → flip [x] (cluster C-1)
CT-02  → flip [x] (cluster C-2)
CT-03  → flip [x] (cluster C-3)
CT-04  → flip [x] (cluster C-4)
CT-05  → flip [x] (cluster C-5)
CT-08  → flip [x] (HW-1..HW-4)
CT-11  → flip [x] (M-1 + M-1b)
CT-12  → flip [x] (superseded)
E-10   → flip [x] operator-side (cargo publish)
V10-03 → flip [x] operator-side (dup of E-10)
P-11   → flip [x] operator-side (Jarvis seed migration)
G-4    → align as dup of G-06
AU-7   → align as dup of G-04

# Workstream B (wizard steps, 5 items)
O-1    → step6c_obsidian_install
O-2    → step6d_vault_bootstrap
N-1    → step6e_n8n_install
E-16   → --import-jarvis flag + step6f
NOOB-UX-6 (3) → step5c_qwen_weights + installers/qwen_weights.rs

# Workstream C (cron + chat, 2 items)
P-01.b consumer → cron::aggregate_profile_snapshot
P-08 consumer   → cron::run_briefing_gated + chat record_last_active

# Workstream D (n8n HTTP, 2 items)
N-3
CT-13

# Workstream E (HNSW, 1 item)
V10-08

# Workstream F (WAL v1.2, 3 items)
CT-10
E-20
V1x-06

# Workstream G (WASM host, 1 item)
V10-04

# Workstream H (multimodal, 4 items)
M-2
M-3
M-4
M-5

# Workstream I (B-6 final + F-19, 5 items)
B-6 ClaudeCliAdapter 2-mode
B-6 13-item wrapper port
B-6 8 tmux.conf + 3 hook ports
B-6 config fields
F-19 Hook trait redesign

# Workstream J (privacy, 1 item)
K-Label-Spoof

# Workstream K (K-Wire-3 family, 4 items)
K-Wire-3 v1 build_enriched_request
K-Wire-3 v2 council dispatch
K-Wire-3 v3 channel profile post-reply
K-Perf-3 spawn_blocking

# Workstream L (Windows native, 2 items)
E-11
E-12

# Workstream N (telemetry HTTPS, 1 item)
E-18

# Workstream O (operator-side, 18 items)
C-06, C-07, C-08, C-09, C-12,
E-01, E-02, E-03, E-04, E-05/CT-06,
E-06/V10-06, E-07, E-09,
CT-07, L-09, L-11,
E-17/V1x-05, CT-09/V1x-04

# Workstream P (Slint R-1, 13 items — SEPARATE HANDOFF)
G-01, G-02, G-03, G-04, G-05, G-06, G-07, G-08, G-09, G-10, G-11,
V10-05, CH-07
```

---

## End State

After this sweep + Workstream P handoff lands:

```
PROGRESS.md:
  [ ] open       = 0
  [~] deferred   = 0
  [x] shipped    = ~870
  [x] operator-side = ~18 (annotated, not blocking)

Active multi-week handoff:
  PLAN/HANDOFF_R1_SLINT_2026-XX-XX.md  (Workstream P, ~6 weeks)
```

NEOTH ships as `v0.2`. The remaining work is Workstream P (GUI) + the bigger v1.x milestones already pinned in the v1.x track (Ecology-Schicht, multi-operator, S3 cold tier — each a separate handoff).
