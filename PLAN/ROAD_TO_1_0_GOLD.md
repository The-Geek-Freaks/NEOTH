# NEOTH — Road to 1.0 GOLD (Leitlinien / Master Plan)

---

## 0. START HERE (fresh session)

**What is NEOTH?** A local-first sovereign personal-AI daemon written in Rust. Single operator, runs on the operator's machine. Core primitives: hemisphere council (Left/Right/Cerebellum provider routing), append-only WAL audit log (cryptographically signed frames), consent-gated tool execution, skills system, memory tiers (hot/warm/cold + groundtruth), channel adapters (Telegram, WhatsApp, Slack, Discord, Keet/Pears), and a coding-buddy subsystem. The binary is `neothd` (daemon + CLI). A GUI companion `neothd-gui` runs Slint. Architecture spec: `PLAN/00_DESIGN_v1.1_FINAL.md`.

**Current HEAD:** `3df06b5` · branch `main` · clean.

**What this file is:** The single source of truth for every task needed to reach the 1.0 GOLD release tag. Read it from top to bottom. Pick the first `[ ]` OPEN task in a workstream, do it, flip it to `[x]`, update `PLAN/PROGRESS_v1_0.md` in the same commit, push. Repeat.

**Rule: OPEN = `[ ]`, DONE = `[x]`. Nothing else.** No `[~]`, no "deferred", no "partial" markers. If something is half-shipped, the shipped part gets `[x]` and the remainder gets `[ ]`.

**How to pick work:** Go workstream by workstream (WS-A through WS-H). Within a workstream, prerequisites come first (tasks are ordered). Batch all work on a single file using the FILE-BATCH INDEX in section 4.

**Source artifacts:** All audit findings are in `REVIEWS/_gold_audit/`. The 6 agent audit files and `_wiring_results.md` are the primary input. Research files for Gold-TODO features are in `REVIEWS/_gold_audit/research/`.

---

## 1. Build & Test Recipe

Windows + MSVC only. `cargo` must run inside vcvars64 via a throwaway `SRC/_run.bat`:

```bat
@echo off
set "PATH=C:\Program Files (x86)\Microsoft Visual Studio\Installer;%PATH%"
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
set "INCLUDE=%INCLUDE%;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt"
set "LIB=%LIB%;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64"
cd /d C:\Users\Shadow-PC\CascadeProjects\AGENTER\SRC
cargo %*
echo RUN_EXIT=%ERRORLEVEL%
```

Invoke: `cmd.exe //c 'C:\Users\Shadow-PC\CascadeProjects\AGENTER\SRC\_run.bat' test -p neothd --lib`

Background it; read `RUN_EXIT=`; `tail` masks exit code — never pipe on gate runs.

**Delete `_run.bat` before committing.**

- vcvars MUST be UNREDIRECTED — `>nul` breaks `cl.exe` → cc-rs `ToolNotFound` on ring/zstd-sys.
- `neothd-gui` is a BIN crate → `cargo test -p neothd-gui` (no `--lib`). os-clipboard feature: `--features os-clipboard`.
- Clippy gate: `clippy -p neothd --tests --no-deps -- -D warnings`
- CLI doc drift: adding/removing a CLI command/flag → `NEOTH_REGEN_CLI_DOCS=1 cargo test -p neothd --lib cli_commands_md_is_up_to_date`
- Per-item workflow: flip `[ ]`→`[x]` in `PROGRESS_v1_0.md` AND this file in the SAME commit; conventional commit; tests green before claiming done; `git push`.

---

## 2. WAL / Code Gotchas

- **0xA band FULL.** Free WAL slots: `0x52-5F`, `0x69-6F`, `0x78-7F`, `0x85-8F`, `0x9D-9F`, `0xBE-BF`, `0xCE-CF`, `0xDB-DF`, `0xF6+`.
- **Adding a WAL event = 5 sites:** const + compile-time band-assert + `EVENT_NAME_TABLE` + `all_event_codes_are_unique` + emit-site; plus `immediate_sync` default.
- **Exhaustive `Action` matches** live in `permissions/mod.rs` (`evaluate_strict/standard/elevated/full` + `lease_scope_for`) — adding a new `Action` variant requires updating all four arms.
- **Pastejack guards** must be `chars()`-based, not byte-slice based.
- **release.yml** uses default features — a default-OFF feature ships only if `--features X` added to the native step.
- **`#[test]` calling `wal::writer::spawn`** panics — use `#[tokio::test]`.
- **vcvars `>nul` breaks cl.exe** — arboard Wayland feat = `wl-clipboard-rs`; always unredirected.
- **Workflow `agent()` without `schema:`** eaten by fp-check Stop hook — use `schema:` or `SendMessage`.
- **`wal::scan` v2/zstd divergence in production:** `rollback.rs`, `indexer.rs`, `undo.rs`, `updater.rs` use bare `SEGMENT_HEADER_LEN` with no zstd decompress — silently skip compressed segments.
- **SQLite mutex over `.await`:** `ConnBorrow::Shared(shared.lock().await)` held for full LLM pipeline — `#[allow(clippy::await_holding_lock)]` is a suppression, not a fix.
- **Raw byte-slice panics:** `&s[..N]` where `s` has multibyte UTF-8 causes panic — use `chars().take(N).collect()` or `floor_char_boundary`.
- **0xDB, 0xDC, 0xDD** are claimed by multiple research plans — coordinate before assigning new WAL events in the 0xD* band.

---

## 3. Status Dashboard

| Workstream | Total tasks | OPEN | DONE |
|------------|-------------|------|------|
| WS-A Security hardening | 35 | 22 | 13 |
| WS-B Honesty / truth-in-advertising | 26 | 26 | 0 |
| WS-C Correctness / reliability | 34 | 34 | 0 |
| WS-D Feature wiring (unwired modules) | 12 | 12 | 0 |
| WS-E Architecture debt | 22 | 22 | 0 |
| WS-F Gold-TODO feature build-out | 16 | 16 | 0 |
| WS-G Repo adoptions | 9 | 9 | 0 |
| WS-H PROGRESS carry-forward | 19 | 15 | 4 |
| **TOTAL** | **173** | **156** | **17** |

_Progress log: 2026-06-06 — GOLD-SEC-01/17 (relay auth + cap) · GOLD-SEC-02/27 (backup zip-slip + creds opt-out) · GOLD-SEC-03 (skills installer id traversal) · GOLD-SEC-04/28/34 (LIKE-escape + GDPR idx_profile cascade) · GOLD-SEC-05/06 (blocking-async offload) · GOLD-SEC-07 (OMI SSRF allowlist) · GOLD-SEC-08 (rate-limit bounded map) · GOLD-SEC-09 (canonical cloud-egress classifier)._

**Verdict:** NEOTH has a strong security/crypto core (ed25519-signed WAL, consent gates, GDPR forget, PII redaction), but the surface over-promises on several fronts: migration (`apply` is a `bail!`), device-sync (memory ingest silently dropped), GUI (6 of 10 settings tabs are stubs), local TTS (deferred). Real exploitable bugs exist on operator paths: zip-slip in backup restore, path traversal in skill installer, LIKE wildcard mass-delete in GDPR forget, blocking code on async executor, and self-reported test results auto-promoting tasks. Both reviews are folded in: beta @ `35c94d2` (all A-01..A-10 still true); Roman @ `3ef9771` (14 net-new findings, CR-002 HLC is fixed, all others stand).

---

## 4. FILE-BATCH INDEX

When a session opens a file, do ALL tasks for that file before closing it.

| Hot file | Task IDs that touch it |
|----------|------------------------|
| `SRC/neoth-relay/src/serve.rs` | GOLD-SEC-01, GOLD-SEC-17 |
| `SRC/neoth-migrate/src/main.rs` | GOLD-HON-01, GOLD-HON-02, GOLD-FEAT-04 |
| `SRC/neothd/src/cli/monitor.rs` | GOLD-COR-01 |
| `SRC/neothd/src/cli/wal.rs` | GOLD-COR-01, GOLD-COR-02 |
| `SRC/neothd/src/cli/doctor.rs` | GOLD-COR-01, GOLD-WIRE-06, GOLD-ARCH-06 |
| `SRC/neothd/src/cli/chat.rs` | GOLD-COR-01, GOLD-COR-09, GOLD-COR-17, GOLD-WIRE-02, GOLD-ARCH-04, GOLD-FEAT-01, GOLD-FEAT-08 |
| `SRC/neothd/src/coding/intent.rs` | GOLD-COR-02 |
| `SRC/neothd/src/coding/second_opinion.rs` | GOLD-COR-02 |
| `SRC/neothd/src/cli/lease.rs` | GOLD-COR-02 |
| `SRC/neothd/src/cli/jobs.rs` | GOLD-COR-02 |
| `SRC/neothd/src/coding/dispatcher.rs` | GOLD-COR-03, GOLD-COR-19, GOLD-HON-18 |
| `SRC/neothd/src/daemon/backup.rs` | GOLD-SEC-02, GOLD-SEC-27 |
| `SRC/neothd/src/skills/installer.rs` | GOLD-SEC-03 |
| `SRC/neothd/src/memory/forget.rs` | GOLD-SEC-04, GOLD-SEC-13, GOLD-COR-20, GOLD-SEC-28 |
| `SRC/neothd/src/memory/regions.rs` | GOLD-SEC-04 |
| `SRC/neothd/src/memory/embeddings.rs` | GOLD-WIRE-07, GOLD-WIRE-08 |
| `SRC/neothd/src/memory/vector_index.rs` | GOLD-WIRE-07, GOLD-WIRE-08 |
| `SRC/neothd/src/coding/review.rs` | GOLD-COR-04 |
| `SRC/neothd/src/coding/provider_worker.rs` | GOLD-COR-04, GOLD-WIRE-01 |
| `SRC/neothd/src/wal/events.rs` | GOLD-COR-06, GOLD-COR-22, GOLD-COR-23, GOLD-SEC-25, GOLD-FEAT-01, GOLD-FEAT-02, GOLD-FEAT-03, GOLD-FEAT-04, GOLD-FEAT-08 |
| `SRC/neothd/src/config/mod.rs` | GOLD-SEC-09, GOLD-HON-11, GOLD-HON-20, GOLD-COR-13, GOLD-ARCH-05, GOLD-FEAT-01, GOLD-FEAT-03, GOLD-FEAT-08 |
| `SRC/neothd/src/config/presets.rs` | GOLD-FEAT-01 |
| `SRC/neothd/src/cli/init.rs` | GOLD-HON-10, GOLD-COR-07, GOLD-FEAT-01, GOLD-FEAT-04 |
| `SRC/neothd/src/permissions/mod.rs` | GOLD-COR-05, GOLD-FEAT-07 |
| `SRC/neothd/src/cluster/hyperswarm.rs` | GOLD-HON-03, GOLD-COR-21, GOLD-WIRE-09 |
| `SRC/neothd/src/wal/compress.rs` | GOLD-SEC-11 |
| `SRC/neothd/src/updater/self_update.rs` | GOLD-SEC-10, GOLD-SEC-11 |
| `SRC/neothd/src/rate_limit.rs` | GOLD-SEC-08 |
| `SRC/neothd/src/installers/omi.rs` | GOLD-SEC-07, GOLD-SEC-09 |
| `SRC/neothd/src/credentials/chrome_linux.rs` | GOLD-SEC-12, GOLD-SEC-21 |
| `SRC/neothd/src/credentials/chrome_macos.rs` | GOLD-SEC-12, GOLD-SEC-21, GOLD-ARCH-10 |
| `SRC/neothd/src/credentials/firefox.rs` | GOLD-SEC-12, GOLD-SEC-25 |
| `SRC/neothd/src/dreaming.rs` | GOLD-SEC-14 |
| `SRC/neothd/src/worktree.rs` | GOLD-SEC-14 |
| `SRC/neothd/src/config/credentials.rs` | GOLD-SEC-15 |
| `SRC/neothd-gui/src/main.rs` | GOLD-SEC-15, GOLD-SEC-31 |
| `SRC/neothd/src/mcp/sanitizer.rs` | GOLD-SEC-19 |
| `SRC/neothd/src/mcp/client.rs` | GOLD-COR-26 |
| `SRC/neothd/src/wasm_plugin/discovery.rs` | GOLD-SEC-20 |
| `SRC/neothd/src/media/multimodal_synth.rs` | GOLD-SEC-22 |
| `SRC/neothd/src/models/sources/gemini.rs` | GOLD-SEC-22 |
| `SRC/neothd/src/installers/obs.rs` | GOLD-SEC-23 |
| `SRC/neothd/src/tools/github.rs` | GOLD-SEC-23 |
| `SRC/neothd/src/paperless/webhook_server.rs` | GOLD-SEC-24 |
| `SRC/neothd/src/wal/proof_bundle.rs` | GOLD-SEC-26, GOLD-SEC-33 |
| `SRC/neothd/src/daemon/isolation.rs` | GOLD-SEC-29 |
| `SRC/neothd/src/channels/webhook_listener.rs` | GOLD-COR-08, GOLD-ARCH-12 |
| `SRC/neothd/src/channels/slack_socket.rs` | GOLD-COR-08 |
| `SRC/neothd/src/channels/whatsapp_webhook.rs` | GOLD-COR-10 |
| `SRC/neothd/src/channels/telegram.rs` | GOLD-COR-11, GOLD-COR-32 |
| `SRC/neothd/src/council/budget.rs` | GOLD-COR-14 |
| `SRC/neothd/src/cli/serve.rs` | GOLD-COR-16, GOLD-COR-34, GOLD-WIRE-07, GOLD-WIRE-08, GOLD-ARCH-01, GOLD-ARCH-07, GOLD-FEAT-03 |
| `SRC/neothd/src/providers/mod.rs` | GOLD-WIRE-03, GOLD-COR-13 |
| `SRC/neothd/src/providers/ouro/adapter.rs` | GOLD-COR-12 |
| `SRC/neothd/src/aws_sigv4.rs` | GOLD-COR-15 |
| `SRC/neothd/src/azure_openai.rs` | GOLD-COR-15 |
| `SRC/neothd/src/council/types.rs` | GOLD-WIRE-04 |
| `SRC/neothd/src/council/orchestrator.rs` | GOLD-WIRE-04 |
| `SRC/neothd/src/config/inference.rs` | GOLD-WIRE-04, GOLD-HON-11 |
| `SRC/neothd/src/providers/claude_cli.rs` | GOLD-WIRE-05, GOLD-WIRE-06 |
| `SRC/neothd/src/providers/model_roles.rs` | GOLD-WIRE-03 |
| `SRC/neothd/src/recall/conversational.rs` | GOLD-WIRE-02 |
| `SRC/neothd/src/cli/recall.rs` | GOLD-WIRE-07, GOLD-WIRE-08 |

---

## WS-A — Security Hardening (GOLD-SEC-NN)

External/unauthenticated exploits first, then operator-data-loss, then defense-in-depth.

- [x] **GOLD-SEC-01** Add bearer-token check at the top of `route()` in neoth-relay before dispatching any POST/GET branch, or gate public-bind with mandatory `--token` flag — *files:* `SRC/neoth-relay/src/serve.rs`, `SRC/neoth-relay/src/main.rs` — *test:* unauthenticated request to public-bind returns 401 — *origin:* A-01 — ✅ **DONE:** `route()` auth-gate (constant-time compare, checked before dispatch incl. unknown paths) + `extract_bearer` + `public_bind_requires_token` predicate + fail-closed startup bail on non-loopback bind without `--token`/`NEOTH_RELAY_TOKEN`; token never logged. 49 tests / 0 fail, clippy `-D warnings` clean.
- [x] **GOLD-SEC-02** Before `entry.unpack(&dest)` in backup restore, canonicalize `dest` and bail if it does not start with `target_home` to prevent zip-slip path traversal — *files:* `SRC/neothd/src/daemon/backup.rs` — *test:* tar with `../../../tmp/pwned` entry is rejected — *origin:* A-06 — ✅ **DONE:** added `safe_join` (rejects `..`/absolute/root components → always contained) used for every restore entry, PLUS reject symlink/hard-link entries outright (NEOTH backups are regular files+dirs only). Tests: `safe_join_allows_normal_paths_and_rejects_escapes` + `restore_rejects_symlink_entry` (tar-rs itself refuses to write a `..` entry — write-side defense in depth). 28 backup tests / 0 fail, clippy clean.
- [x] **GOLD-SEC-03** Call `crate::skills::creator::validate_skill_id(&manifest.id)?` before `target_skills_dir.join(&manifest.id)` in `install_from_local` — *files:* `SRC/neothd/src/skills/installer.rs` — *test:* id of `"../etc/cron.d/x"` returns `Err` — *origin:* A-07 — ✅ **DONE:** replaced the weak empty-only check with `super::creator::validate_skill_id` (allows only `[a-zA-Z0-9_-]`, ≤64 → rejects `..`/`/`/`\`/empty) before the id becomes a path component. Tests: `install_from_local_rejects_path_traversal_id` + updated empty-id test. 13 installer tests / 0 fail, clippy clean.
- [x] **GOLD-SEC-04** Create `escape_like(s: &str) -> String` escaping `\`, `%`, `_` and add `ESCAPE '\\'` to every LIKE clause in `forget.rs` and `regions.rs` — *files:* `SRC/neothd/src/memory/mod.rs`, `SRC/neothd/src/memory/forget.rs`, `SRC/neothd/src/memory/regions.rs`, `SRC/neothd/src/memory/embeddings.rs`, `SRC/neothd/src/cli/memory.rs` — *test:* `--forget "%"` does not delete entire memory tier — *origin:* A-08, A-44 — ✅ **DONE:** shared `memory::escape_like` (escapes `\`/`%`/`_`) + `... COLLATE NOCASE LIKE ?n ESCAPE '\'` across all forget tiers, `wipe_by_source_ref_pattern`, both `recall_from_region` branches, and the `cli/memory` dry-run counts (preview now matches the real delete). Test `forget_escapes_like_wildcards_no_mass_delete` proves `%`/`_` are literal. 304 memory tests / 0 fail, clippy clean.
- [x] **GOLD-SEC-05** Wrap `apply_patch_via_worktree` (sync, calls `std::process::Command` + `std::thread::sleep`) in `tokio::task::spawn_blocking`; replace `std::thread::sleep` with `tokio::time::sleep` inside spawn_blocking — *files:* `SRC/neothd/src/coding/dispatcher.rs` — *test:* `cargo clippy -- -D clippy::await_holding_lock` passes; `tokio::time::timeout` in tests does not deadlock — *origin:* A-05 — ✅ **DONE:** the apply call is now `spawn_blocking(move || apply_patch_via_worktree(&task_c,&outcome_c,&cfg_c))` (all three args are `Clone`, so the `Send+'static` closure never captures the `!Send` conn). The git subprocesses + `run_worktree_tests` poll-loop run off the executor; `std::thread::sleep` is KEPT (it is correct on a blocking thread — `tokio::time::sleep` would need an async ctx). `dispatch_session_with_apply` is only awaited (never spawned) so the conn-across-await is fine. 33 dispatcher tests / 0 fail, clippy clean.
- [x] **GOLD-SEC-06** Move post-recall Hebbian writes in `cli/recall.rs:239` inside `spawn_blocking` so SQLite writes never execute on async task thread — *files:* `SRC/neothd/src/cli/recall.rs` — *test:* clippy no `await_holding_lock`; recall round-trip integration test — *origin:* A-05, A-66 — ✅ **DONE:** the Hebbian reinforcement loop (N synchronous SQLite UPDATEs) now runs INSIDE the recall `spawn_blocking` block; the conn stays on the blocking thread (no longer returned out) and only `(rows, reinforcements)` cross back — the async side does just the WAL audit emit. `RecallTaskOutput` type alias added (clippy type_complexity). 114 recall tests / 0 fail, clippy clean.
- [x] **GOLD-SEC-07** Rewrite `is_local_endpoint` in `installers/omi.rs` to parse host and check loopback (127.x, ::1) and RFC-1918 (10/8, 172.16/12, 192.168/16), then call it again at ingest-task startup — *files:* `SRC/neothd/src/installers/omi.rs`, `SRC/neothd/src/daemon/omi_ingest_task.rs` — *test:* `http://evil.com` rejected; `http://192.168.1.50` accepted — *origin:* A-19 — ✅ **DONE:** real allowlist — `extract_host` (strips scheme/userinfo/port, handles `[ipv6]`) + `is_local_host` (localhost / loopback / RFC-1918 / fc00::/7 only; non-IP hosts rejected). Re-validated fail-closed at `run_omi_ingest_task` startup. Tests: public host / `8.8.8.8` / link-local `169.254` / userinfo-smuggle `localhost@evil.com` / public IPv6 all rejected; loopback+LAN+ULA accepted. Fixed a stray-underscore port typo in a probe test. 20 omi tests / 0 fail, clippy clean.
- [x] **GOLD-SEC-08** Add LRU eviction (or sweep entries older than `REFILL_PERIOD`) to `rate_limit.rs::allow` to prevent unbounded HashMap growth — *files:* `SRC/neothd/src/daemon/rate_limit.rs` — *test:* after 10 000 unique senders, map size stays bounded — *origin:* A-18 — ✅ **DONE:** `evict_if_needed` after each `allow` — high/low-watermark (`MAX_BUCKETS=10000` → trim to `LOW_WATER=7500`): O(1) fast-path until the cap, then one TTL-sweep (drop idle/fully-refilled buckets) + keep-most-recent. Memory hard-capped regardless of attacker sender_id flooding. `bucket_count()` accessor added. Tests: 12.5k unique-sender flood stays ≤ MAX_BUCKETS (0.05s); small load keeps all. 9 rate_limit tests / 0 fail, clippy clean.
- [x] **GOLD-SEC-09** Add `is_cloud_egress() -> bool` to `ProviderKind` and replace the partial match arms in `init.rs`, `jobs.rs`, and `serve.rs` with it; include `AnthropicApi` and `Cohere` — *files:* `SRC/neothd/src/consent.rs`, `SRC/neothd/src/cli/jobs.rs`, `SRC/neothd/src/cli/init.rs` — *test:* `is_cloud(AnthropicApi)` returns true; jobs verdict gates anthropic/cohere — *origin:* A-25 — ✅ **DONE:** the canonical classifier already existed (`consent::is_cloud`) — made it an EXHAUSTIVE match (new ProviderKind variants now fail to compile until classified) and routed the two divergent sites through it: `jobs.rs` cost/consent verdict (its inline set silently MISSED `anthropic_api`+`cohere_api` → those metered jobs escaped the gate) and `init.rs` step8 inline-consent pre-grant (same omission → operators on those providers hit an opaque consent-failure on first chat). Pin-test now covers ALL 11 variants. NOTE: serve.rs:3174 is a ProviderKind→slug *string* map (ARCH dedup C-12 / GOLD-ARCH), not a cloud gate — out of this security scope. 45 consent + 8 jobs tests / 0 fail, clippy clean.
- [ ] **GOLD-SEC-10** Default `require_signature = true` on manual update path in `cli/update.rs:218`; allow `--allow-unsigned` opt-out; update any docs claiming updates are signed until CI keypair is provisioned — *files:* `SRC/neothd/src/cli/update.rs`, `SRC/neothd/src/updater/self_update.rs` — *test:* unsigned release is rejected by default path — *origin:* A-22
- [ ] **GOLD-SEC-11** Add `take(MAX_DECOMPRESS_BYTES)` wrappers before decompression in `wal/compress.rs` and `updater/self_update.rs` (xz + gz paths) — *files:* `SRC/neothd/src/wal/compress.rs`, `SRC/neothd/src/updater/self_update.rs` — *test:* 300 MiB zstd stream is rejected; WAL segment decompression respects quota — *origin:* A-29
- [ ] **GOLD-SEC-12** Wrap `DecryptedChromeCredential.password` and Firefox decrypt output in `Zeroizing<Vec<u8>>` / `SecretString` so credentials are zeroed on drop — *files:* `SRC/neothd/src/credentials/chrome_linux.rs`, `SRC/neothd/src/credentials/chrome_macos.rs`, `SRC/neothd/src/credentials/firefox.rs` — *test:* valgrind / LSAN shows no plaintext cred in memory after struct drop — *origin:* A-32, A-86
- [ ] **GOLD-SEC-13** Return `Err` (not `AuditSink::None` warn-and-continue) in `cli/os.rs` when WAL-spawn fails for gated launches — *files:* `SRC/neothd/src/cli/os.rs` — *test:* WAL-spawn-failure returns error to caller — *origin:* A-44
- [ ] **GOLD-SEC-14** Apply `redact_text` in `compose_dream` before building the summary string; write `.neoth-test-output.log` with `OpenOptions::mode(0o600)` and pass output through `redact_text` — *files:* `SRC/neothd/src/dreaming.rs`, `SRC/neothd/src/coding/worktree.rs` — *test:* generated dream summary contains no raw PII tokens; log file has 0600 perms — *origin:* A-33
- [ ] **GOLD-SEC-15** Use tmp+rename on both platforms for credentials write; set ACL/mode on tmp before rename; return `Err` (not warn) on DACL failure — *files:* `SRC/neothd/src/config/credentials.rs`, `SRC/neothd-gui/src/main.rs` — *test:* mid-write crash leaves no partially-written credentials file — *origin:* A-34
- [ ] **GOLD-SEC-16** Gate `pub mod cluster` behind a `cluster` Cargo feature (default-on in release, opt-out for source builds) to reduce binary attack surface for solo-node operators — *files:* `SRC/neothd/src/lib.rs`, `SRC/neothd/Cargo.toml` — *test:* `cargo build --no-default-features` compiles without cluster code — *origin:* B-03
- [x] **GOLD-SEC-17** Add `Arc<Semaphore>` connection cap (e.g. 1024) to neoth-relay serve loop; allocate buffer only after permit acquired — *files:* `SRC/neoth-relay/src/serve.rs` — *test:* 2000 concurrent connections do not exhaust memory — *origin:* A-53 — ✅ **DONE:** `Semaphore(1024)` permit acquired via `acquire_owned()` BEFORE spawn (serial accept loop → OS-backlog backpressure at cap; 64 KB buffer allocated only inside the permitted task); added a 10 s read-timeout to close the slowloris angle so a stalled client can't pin a permit. 49 tests / 0 fail, clippy clean.
- [ ] **GOLD-SEC-18** Gate browser-credential-decrypt tree behind `feature = "browser-import"` (default-off in release binary) — *files:* `SRC/neothd/Cargo.toml`, `SRC/neothd/src/credentials/mod.rs` — *test:* `cargo build` without `browser-import` compiles without chrome/firefox modules — *origin:* B-06, B-13
- [ ] **GOLD-SEC-19** Replace `lc_san.find(&lc_pat)` with case-insensitive `replace_all` in `mcp/sanitizer.rs`; add test for double-payload — *files:* `SRC/neothd/src/mcp/sanitizer.rs` — *test:* prompt with injection phrase twice is fully sanitized — *origin:* A-82
- [ ] **GOLD-SEC-20** Add `is_symlink()` check in `wasm_plugin/discovery.rs::load_one()` before each `fs::read` — *files:* `SRC/neothd/src/wasm_plugin/discovery.rs` — *test:* symlink inside accepted plugin dir is rejected — *origin:* A-56
- [ ] **GOLD-SEC-21** Decode Firefox `decrypt_login_entry` directly into `SecretString`/`SecretBytes`; zero intermediate string before drop — *files:* `SRC/neothd/src/credentials/firefox.rs` — *test:* intermediate String is empty after function returns — *origin:* A-86
- [ ] **GOLD-SEC-22** Move Gemini API key from `?key=` URL query to `x-goog-api-key` header in `media/multimodal_synth.rs` and `models/sources/gemini.rs` — *files:* `SRC/neothd/src/media/multimodal_synth.rs`, `SRC/neothd/src/models/sources/gemini.rs` — *test:* no `key=` appears in request URL in wiremock test — *origin:* A-60
- [ ] **GOLD-SEC-23** Pass OBS password via tmpfile or stdin instead of CLI arg; insert `--` before user-controlled `gh` arguments — *files:* `SRC/neothd/src/installers/obs.rs`, `SRC/neothd/src/tools/github.rs` — *test:* OBS password not in `ps aux` output; gh title starting with `--` is rejected — *origin:* A-85
- [ ] **GOLD-SEC-24** Enforce loopback on `bind_addr` in `paperless/webhook_server.rs`; reuse `constant_time_token_eq`; add body-size cap before collect — *files:* `SRC/neothd/src/paperless/webhook_server.rs` — *test:* non-loopback bind rejected; timing attack not possible on token compare — *origin:* A-84
- [ ] **GOLD-SEC-25** Return `Result<Vec<u8>>` from `proof_bundle::canonical_bytes` and `keet_wal::to_bytes` instead of `unwrap_or_default`; callers propagate error — *files:* `SRC/neothd/src/wal/proof_bundle.rs`, `SRC/neothd/src/wal/keet_wal.rs`, `SRC/neothd/src/wal/events.rs` — *test:* serialization failure returns `Err` not empty bytes — *origin:* A-48, D-26
- [ ] **GOLD-SEC-26** Add `validate_pub_key_hex` call in `cluster::discover_scan` to filter invalid peers before they reach the picker; replace `&p.pub_key_hex[..16.min(len)]` with `short_key(s: &str) -> &str { s.get(..16).unwrap_or(s) }` — *files:* `SRC/neothd/src/cluster/cluster.rs` — *test:* non-ASCII pubkey from mDNS does not panic — *origin:* A-28
- [x] **GOLD-SEC-27** Add plaintext-secrets warning at backup creation when `credentials.yaml` is included; make credentials.yaml opt-in until age-encryption lands — *files:* `SRC/neothd/src/daemon/backup.rs`, `SRC/neothd/src/cli/backup.rs` — *test:* backup creation prints warning; `--no-credentials` flag excludes the file — *origin:* A-73 — ✅ **DONE:** `write_backup` returns `BackupOutcome { included, included_plaintext_credentials }`; `credentials.yaml` bundled by default (preserves restore completeness) but `cli/backup.rs` prints a loud plaintext-secrets ⚠ warning + `--no-credentials` opt-out skips it; module doc honesty-fixed (A-73 self-contradiction). Tests: `backup_includes_credentials_by_default_and_flags_them` + `backup_excludes_credentials_when_opted_out`. docgen regenerated for the new flag.
- [x] **GOLD-SEC-28** Fix GDPR erasure cascade: `forget_by_topic` must also DELETE from `idx_profile` table — *files:* `SRC/neothd/src/memory/forget.rs` — *test:* after `neoth memory forget <topic>`, `idx_profile` has no matching rows — *origin:* CR-007 — ✅ **DONE:** `forget_by_topic` now deletes `idx_profile` rows where `field` OR `value_json` match the topic; `ForgetReport.profile_rows` added (+ in `total()` + audit payload + dry-run preview). Test `forget_cascades_to_idx_profile` (AcmeCorp claim erased, pizza claim survives). 304 memory tests / 0 fail.
- [ ] **GOLD-SEC-29** Implement DACL ownership check via `win_acl.rs` in `daemon/isolation.rs::check_home_isolation` for Windows (currently always `Ok(())`); or document as Unix-only with prominent warning in Windows build — *files:* `SRC/neothd/src/daemon/isolation.rs` — *test:* world-readable home dir on Windows surfaces warning — *origin:* A-87
- [ ] **GOLD-SEC-30** Add `0xDB SUDOMODE_ENABLED` / `0xDC SUDOMODE_DISABLED` WAL events and ensure consent-audit gets a WAL trail for the grant/revoke file-marker path — *files:* `SRC/neothd/src/wal/events.rs` — *test:* `neoth wal show --type sudomode_enabled` shows frame after autonomy change — *origin:* SR-017
- [ ] **GOLD-SEC-31** Fix `neothd-gui/ui/chat.slint` role name mismatch: align Slint `neoth`/`system` roles with Rust `assistant`/`error` sender; add `error` arm to bubble-color if-chain so error bubbles render red — *files:* `SRC/neothd-gui/ui/chat.slint`, `SRC/neothd-gui/src/main.rs` — *test:* error response is rendered with red background in GUI screenshot — *origin:* E-16
- [ ] **GOLD-SEC-32** Require a daily LLM-call hard cap gate in `TriggerPolicy` that fires independently of EUR budget tracking — *files:* `SRC/neothd/src/council/trigger.rs` — *test:* with `daily_call_cap: 20`, 21st council convene is rejected — *origin:* B-19
- [ ] **GOLD-SEC-33** Implement Windows home isolation DACL check in `daemon/isolation.rs` — *files:* `SRC/neothd/src/daemon/isolation.rs` — *test:* (see GOLD-SEC-29 — same file, consolidated) — *origin:* A-87
- [x] **GOLD-SEC-34** Add `ESCAPE '\\'` to `LIKE` queries in `memory/forget.rs` and all other LIKE-based memory queries; add shared `escape_like` helper — *files:* `SRC/neothd/src/memory/forget.rs` — *test:* (consolidated with GOLD-SEC-04) — *origin:* A-08 (consolidated) — ✅ **DONE as part of GOLD-SEC-04** (shared `memory::escape_like` + ESCAPE across all memory LIKE sites).
- [ ] **GOLD-SEC-35** Fix `hysteria.rs` YAML injection: double-quote + escape `auth`/`server` YAML fields; pass proxy env via builder not `set_var` — *files:* `SRC/neothd/src/installers/hysteria.rs` — *test:* auth string with YAML special chars produces valid config — *origin:* A-69

---

## WS-B — Honesty / Truth-in-Advertising (GOLD-HON-NN)

Doc/claim ≠ code fixes AND wiring the truthful behavior.

- [ ] **GOLD-HON-01** Downgrade `neoth-migrate` README and `RUNBOOK_phase3_cutover.md` text to "dry-run/Preview only; apply is post-v1.0" — *files:* `SRC/neoth-migrate/src/main.rs` (clap help text), relevant docs — *test:* `neoth-migrate apply --help` says "preview only" — *origin:* B-01, A-02
- [ ] **GOLD-HON-02** Align `operator-journey.md` §5 + FAQ offline table to README's own "Partial" admission that memory-ingest is deferred; remove "Shared memory across devices is the goal here" without marking it as not yet functional — *files:* `docs/operator-journey.md` — *test:* doc review passes — *origin:* B-02
- [ ] **GOLD-HON-03** Derive `peer_count` from `registry::load(&home)?.peers.len()` in `cluster.rs::run_status` instead of hardcoded `0usize`; derive `mode`/`policy` from actual config — *files:* `SRC/neothd/src/cluster/cluster.rs` — *test:* `neoth cluster status` shows non-zero peers when paired — *origin:* A-13
- [ ] **GOLD-HON-04** Fix `media/mod.rs` table: Audio = "STT local (whisper-rs) / TTS cloud-or-OS-native"; remove "full-stack local multimodal" phrasing where it implies local TTS is shipped — *files:* `SRC/neothd/src/media/mod.rs`, relevant docs — *test:* mod.rs doc-comment is accurate — *origin:* B-08
- [ ] **GOLD-HON-05** Add two-path cost callout to `operator-journey.md` §1/§4 distinguishing fully-local (~0 EUR/month) from cloud-council subscription floor — *files:* `docs/operator-journey.md` — *test:* doc review passes — *origin:* B-09
- [ ] **GOLD-HON-06** Add access date + version anchor to each compare page's competitor baseline; mark competitor cells with "(as of [date])" — *files:* `docs/compare/hermes.md`, `docs/compare/openclaw.md`, `docs/compare/openhuman.md` — *test:* all compare pages have access date — *origin:* B-10, B-23
- [ ] **GOLD-HON-07** Mark `claude_plugins` module as "parser-only, not active at runtime" in plugin docs; gate behind `#[cfg(feature = "claude-plugins")]` or document clearly — *files:* `SRC/neothd/src/claude_plugins/mod.rs`, docs — *test:* module doc is accurate — *origin:* B-11
- [ ] **GOLD-HON-08** Update `sub_agents/mod.rs` module doc to correctly list all 18 built-in agents instead of 3 — *files:* `SRC/neothd/src/sub_agents/mod.rs` — *test:* module doc count matches `built_ins_include_all_eighteen()` test — *origin:* B-12
- [ ] **GOLD-HON-09** Add explicit "GU-01 GUI settings in progress" note to operator-journey/FAQ where post-onboarding GUI is presented as a full settings surface — *files:* `docs/operator-journey.md` — *test:* doc accurately reflects 6-tab stub state — *origin:* B-07
- [ ] **GOLD-HON-10** Add `step1d_onboarding_mode` wizard step for new vs migration question; update wizard step ordering — *files:* `SRC/neothd/src/cli/init.rs` — *test:* `neoth init` presents mode choice before identity step — *origin:* Gold-TODO #4 (v1.0-WIRE item)
- [ ] **GOLD-HON-11** Add explicit "LOWKEY/RASKAL/ARCHON security-research skills ship by default; disable via freedom.yaml" callout to README and quickstart; add `TopologyMode::Single` label to wizard and CLI for explicit single-provider confirmation — *files:* `README.md`, `docs/quickstart.md`, `SRC/neothd/src/config/inference.rs` — *test:* README mentions security-skill default — *origin:* B-16, Gold-TODO #26
- [ ] **GOLD-HON-12** Clarify `channels/mod.rs:12-14` comment: "no mandatory external relay/backend for Memory/WAL/Inference in the default single-node path; cluster/relay/webhook are opt-in operator-deployed surfaces" — *files:* `SRC/neothd/src/channels/mod.rs` — *test:* comment is accurate — *origin:* B-17
- [ ] **GOLD-HON-13** Surface warning in `freedom.yaml` docs and GUI when `inference.council_depth > 1`; document the 3^depth cost curve — *files:* `docs/freedom.yaml.md`, GUI settings pane — *test:* setting depth=4 shows cost warning — *origin:* B-18
- [ ] **GOLD-HON-14** Change README comparison table row "WASM plugin capability sandbox" from "Yes" to "Partial (V10-04, feature-gated, not in default release binary)" — *files:* `README.md` — *test:* README is accurate — *origin:* B-20, C-16
- [ ] **GOLD-HON-15** Add `--features wasm-plugin-host` to `release.yml` native build step OR update `Cargo.toml` / README to "opt-in only, not in release binary" — *files:* `.github/workflows/release.yml`, `SRC/neothd/Cargo.toml` — *test:* release binary matches documented state — *origin:* C-16
- [ ] **GOLD-HON-16** Propagate `emit_identity_merged` result back to caller; use `warn!` (not `debug!`) on daemon-live failure path; print "audit forward FAILED" if emit errors — *files:* `SRC/neothd/src/cli/identity.rs` — *test:* emit failure surfaces to operator — *origin:* A-27
- [ ] **GOLD-HON-17** Fix `pears_bridge.rs` doc-comment line 24: change "bearer token defends against confused-deputy attacks" to "bearer token not yet active — K-3 TODO" OR gate `post_message` to return error when no token is set — *files:* `SRC/neothd/src/channels/pears_bridge.rs` — *test:* doc matches behavior — *origin:* A-39
- [ ] **GOLD-HON-18** Remove false doc claims from `plan_writer.rs`; fix `pick_next_backlog_task` to use `WHERE status='backlog' LIMIT 1` SQL; remove unused `_workers` param — *files:* `SRC/neothd/src/coding/plan_writer.rs`, `SRC/neothd/src/coding/dispatcher.rs` — *test:* `pick_next_backlog_task` uses SQL filter, not linear scan — *origin:* A-41, C-33
- [ ] **GOLD-HON-19** Rename "MemPalace" in any marketing/docs to avoid collision with Letta's MemPalace brand — *files:* search and replace in docs/README — *test:* grep `MemPalace` returns 0 hits in user-visible docs — *origin:* SR-001
- [ ] **GOLD-HON-20** Add `memory::moral_core` module note; also add "v1.1" tag to `is_live(_provider)` always-true in `cloud/mod.rs`; add "hysteria TCP-only probe" note — *files:* `SRC/neothd/src/cloud/mod.rs` — *test:* `is_live` returns accurate value per connector mode — *origin:* A-17
- [ ] **GOLD-HON-21** Add `--features os-clipboard,wasm-plugin-host` to release.yml OR update docs — already tracked in GOLD-HON-15; consolidated — *origin:* C-16
- [ ] **GOLD-HON-22** Fix lying comments: `ouro.rs` "read-only", `calendar.rs` "sorts internally", `tmux_sweeper_task.rs` "aborts when dropped" (Tokio detaches), `shared_state.rs` "Atomic" (has remove+rename window), `redact.rs` "per-frame fsync" — *files:* `SRC/neothd/src/providers/ouro/adapter.rs`, `SRC/neothd/src/calendar.rs`, `SRC/neothd/src/cli/tmux_sweeper_task.rs`, `SRC/neothd/src/cli/wizard_checkpoint.rs`, `SRC/neothd/src/security/redact.rs` — *test:* comments match actual behavior — *origin:* D-10
- [ ] **GOLD-HON-23** Rename `is_greeting_regression` to `is_refusal_or_capability_disclaimer`; rename `forge_skill_from_dream` to `build_skill_proposal_from_dream`; rename `karpathy_preamble` to `code_discipline_preamble` — *files:* `SRC/neothd/src/security/refusal_detect.rs`, `SRC/neothd/src/dreaming.rs`, `SRC/neothd/src/providers/context_guards.rs` — *test:* grep old names returns 0 — *origin:* E-22, E-23
- [ ] **GOLD-HON-24** Update stale module headers: `channels/slack.rs`, `whatsapp.rs`, `webhook_verify.rs`, `channel.rs`, `discord_gateway.rs`, `keet.rs`, `wasm_plugin/mod.rs`, `rollback.rs`, `dreaming.rs` — *files:* multiple — *test:* module doc describes current implementation — *origin:* D-11, E-07
- [ ] **GOLD-HON-25** Fix stale counts in docs/code: `routing_weights.rs` schema v8→v11, `bundled.rs` "21 skills"→actual count, `slash/mod.rs` "4 built-ins"→21, `startup_credential_audit.rs` "8 chars"→12 — *files:* relevant source files — *test:* grep stale numbers returns 0 — *origin:* D-34
- [ ] **GOLD-HON-26** Rename `pub_fail_count` → `fail_count` in `sub_agents/parallel.rs`; delete wrapper method and false comment — *files:* `SRC/neothd/src/sub_agents/parallel.rs` — *test:* clippy passes; no `pub_fail_count` references — *origin:* C-25

---

## WS-C — Correctness / Reliability (GOLD-COR-NN)

- [ ] **GOLD-COR-01** Replace `std::process::exit(1)` in `cli/monitor.rs:266`, `cli/telemetry.rs:157`, `cli/wal.rs:229`, `cli/wal.rs:878`, `cli/doctor.rs:712` with `anyhow::bail!`; thread exit status through `Result` to main — *files:* `SRC/neothd/src/cli/monitor.rs`, `SRC/neothd/src/cli/telemetry.rs`, `SRC/neothd/src/cli/wal.rs`, `SRC/neothd/src/cli/doctor.rs` — *test:* `neoth monitor` exits cleanly after alert; WAL drain is not skipped — *origin:* A-03
- [ ] **GOLD-COR-02** Replace every raw `&s[..N]` byte-slice with `chars().take(N).collect::<String>()` or `floor_char_boundary` in `coding/intent.rs:212`, `coding/second_opinion.rs:57`, `cli/lease.rs:164`, `cli/jobs.rs:323` — *files:* `SRC/neothd/src/coding/intent.rs`, `SRC/neothd/src/coding/second_opinion.rs`, `SRC/neothd/src/cli/lease.rs`, `SRC/neothd/src/cli/jobs.rs` — *test:* "Übung" input does not panic — *origin:* A-04
- [ ] **GOLD-COR-03** Add `applied: bool` flag to `TestSummary` (or `KanbanTask`); set it only when apply+test path actually ran tests; gate `check_auto_promotable` on `summary.applied` — *files:* `SRC/neothd/src/coding/review.rs`, `SRC/neothd/src/coding/dispatcher.rs`, `SRC/neothd/src/coding/provider_worker.rs` — *test:* task with self-reported green but no `--apply` does not auto-promote — *origin:* A-10
- [ ] **GOLD-COR-04** For security-bearing WAL frames (CHANNEL_PRIVILEGE_BLOCKED, HOOK_BLOCKED, INGEST_EXTRACTED, EMBED_PERSISTED, CONFIG_RELOADED): add `required_audit` flag that returns `Err` to the caller on append failure instead of logging-and-continuing — *files:* `SRC/neothd/src/cli/serve.rs` — *test:* WAL writer failure for CHANNEL_PRIVILEGE_BLOCKED surfaces as error to pipeline — *origin:* A-11
- [ ] **GOLD-COR-05** Add `Action::PatchApplyToRepo` and related exhaustive match arms audit; confirm no new `Action` variant is missing from `evaluate_strict/standard/elevated/full` — *files:* `SRC/neothd/src/permissions/mod.rs` — *test:* adding a new `Action` variant without match arm fails compilation — *origin:* A-05 (exhaustive match requirement)
- [ ] **GOLD-COR-06** Add `0x77 KANBAN_TASK_PROGRESS` to the compile-time band assertion const-block in `wal/events.rs`; add frame-header length self-consistency check in `from_le_bytes` — *files:* `SRC/neothd/src/wal/events.rs` — *test:* compile-time assertion catches missing band member — *origin:* A-80
- [ ] **GOLD-COR-07** Allocate distinct wizard step marker for 6b (e.g. 63); convert step markers to a named enum; add uniqueness test — *files:* `SRC/neothd/src/cli/init.rs` — *test:* `step_markers_are_unique` test passes — *origin:* A-26
- [ ] **GOLD-COR-08** Fire-and-forget webhook dispatch via `tokio::spawn` in `webhook_listener.rs::handle_meta` and `slack_socket.rs` dispatch loop; return 200/ACK before pipeline runs — *files:* `SRC/neothd/src/channels/webhook_listener.rs`, `SRC/neothd/src/channels/slack_socket.rs` — *test:* 200 returned before LLM dispatch completes — *origin:* A-12
- [ ] **GOLD-COR-09** Aggregate token sums from `LoopOutcome::responses` and thread them through the return tuple in council/MCP branches — *files:* `SRC/neothd/src/cli/chat.rs` — *test:* `neoth chat` shows non-None token count after council call — *origin:* A-14
- [ ] **GOLD-COR-10** Set `message_id: Some(m.id.clone())` in `decode_payload` for text/media message branches — *files:* `SRC/neothd/src/channels/whatsapp_webhook.rs` — *test:* inbound WhatsApp message has non-None message_id — *origin:* A-21
- [ ] **GOLD-COR-11** Set `channel_ts_unix` from `msg.date.timestamp()` (provider time) instead of `SystemTime::now()` in Telegram handler — *files:* `SRC/neothd/src/channels/telegram.rs` — *test:* Telegram message timestamp matches provider time, not receive time — *origin:* A-38, E-08
- [ ] **GOLD-COR-12** Return `device_for(self.accelerator)` from `model_device()` in `providers/ouro/adapter.rs` instead of hardcoding `Cpu` — *files:* `SRC/neothd/src/providers/ouro/adapter.rs` — *test:* ouro adapter uses CUDA device when accelerator=cuda — *origin:* A-36
- [ ] **GOLD-COR-13** Define `ProviderKind::as_str()`, `to_inference()`, `catalog_key()`, `as_provider_id()` methods; migrate all 143 match arms across `init.rs`, `jobs.rs`, `serve.rs`, Slint files — *files:* `SRC/neothd/src/config/mod.rs` (or `providers/mod.rs`), `SRC/neothd/src/cli/serve.rs`, `SRC/neothd/src/cli/jobs.rs` — *test:* `Skip => "unconfigured"` vs `"none"` drift eliminated — *origin:* C-12, D-09
- [ ] **GOLD-COR-14** Add `used: u32` to `BudgetExhausted`; populate at call site; update `Display` impl to show actual used vs cap — *files:* `SRC/neothd/src/council/budget.rs` — *test:* budget exhausted error shows "20 LLM calls charged against cap of 20" — *origin:* A-45
- [ ] **GOLD-COR-15** Percent-encode path segments in `aws_sigv4.rs::sign()` (preserve `/`); validate `deployment_name` against `[A-Za-z0-9._-]+` in `AzureOpenAiAdapter::new()` — *files:* `SRC/neothd/src/aws_sigv4.rs`, `SRC/neothd/src/azure_openai.rs` — *test:* model ID with `:` is percent-encoded in canonical URI — *origin:* A-37
- [ ] **GOLD-COR-16** Replace pidfile TOCTOU check with exclusive `flock`/`LockFile` on segment before spawn in `model_download_audit.rs`, `todo.rs`, `security.rs`, `os.rs`, `profile.rs` — *files:* `SRC/neothd/src/cli/serve.rs`, relevant modules — *test:* concurrent writes to same segment do not corrupt frames — *origin:* A-16
- [ ] **GOLD-COR-17** Replace inline CLI council recovery block (`chat.rs:~1358-1520`) with call to `dispatch_council_with_recovery` — *files:* `SRC/neothd/src/cli/chat.rs` — *test:* council recovery in CLI path uses same logic as daemon path — *origin:* C-10
- [ ] **GOLD-COR-18** Serialize `registry::refresh_rtt` + `refresh_stability` mutations through a process-wide `Mutex<()>`; log errors from `let _ =` discards — *files:* `SRC/neothd/src/cluster/registry.rs` — *test:* concurrent `refresh_rtt` + `refresh_stability` don't lose-update — *origin:* A-43
- [ ] **GOLD-COR-19** Parallelize `coding/dispatcher.rs` serial session dispatcher — replace serial-for-now comment with concurrent hemisphere dispatch — *files:* `SRC/neothd/src/coding/dispatcher.rs` — *test:* two hemisphere workers run concurrently — *origin:* CR-031
- [ ] **GOLD-COR-20** Emit `CALENDAR_WRITE_DENIED/FAILED` frame inside the `Err` arm before propagating in `calendar.rs::create_event_against` — *files:* `SRC/neothd/src/calendar.rs` — *test:* network failure on calendar write leaves audit frame — *origin:* A-20
- [ ] **GOLD-COR-21** Replace EOF detection via Display string match in `cluster/hyperswarm.rs:1468`; match on `JoinError` variant separately in `tailscale::enumerate` instead of `unwrap_or(false)` — *files:* `SRC/neothd/src/cluster/hyperswarm.rs`, `SRC/neothd/src/cluster/tailscale.rs` — *test:* EOF is a typed variant; panic in JoinHandle surfaces as error — *origin:* A-47
- [ ] **GOLD-COR-22** Read `segment_start_ts_ns` from parsed header at WAL reopen so 24h age-rotation fires correctly after daemon restart — *files:* `SRC/neothd/src/wal/writer.rs` — *test:* segment opened 25h ago rotates on next write after restart — *origin:* A-81
- [ ] **GOLD-COR-23** Bind the WAL quota re-measure to a `compare_exchange` on a separate `in_remeasure` `AtomicBool` to make the ceiling guarantee strict — *files:* `SRC/neothd/src/wal/writer.rs` — *test:* quota ceiling is not exceeded under concurrent writers — *origin:* A-50
- [ ] **GOLD-COR-24** Fix `firefox_pbes2.rs` PBKDF2 iteration count: before `.first()`, check `to_u32_digits().1.len() > 1` and return `KdfItersOutOfRange`; same fix for `kdf_key_length` — *files:* `SRC/neothd/src/credentials/firefox_pbes2.rs` — *test:* 2^33 iteration count returns error not truncated value — *origin:* A-31
- [ ] **GOLD-COR-25** Replace `keet_udp.rs` placeholder `send_to` returning `RecvTimeout` with `DialOutcome::Sent`; size buffer at `MAX_DATAGRAM_BYTES + 1` so overflow check is reachable — *files:* `SRC/neothd/src/channels/keet_udp.rs` — *test:* `send_to` returns `Sent` on success; oversized datagram check fires — *origin:* A-30
- [ ] **GOLD-COR-26** Skip non-matching IDs in `mcp/client.rs:222-234` instead of hard Protocol error; serialize tool result via `serde_json::json!` — *files:* `SRC/neothd/src/mcp/client.rs` — *test:* server notification with non-matching id does not kill client — *origin:* A-83
- [ ] **GOLD-COR-27** Fix WASM hook stage enum divergence: `wasm_plugin/manifest.rs` uses `PreProvider`; `hooks/stages.rs` uses `PreProviderCall` — unify wire forms — *files:* `SRC/neothd/src/wasm_plugin/manifest.rs`, `SRC/neothd/src/hooks/stages.rs` — *test:* WASM plugin declaring `pre_provider` stage fires in dispatcher — *origin:* PAT-002
- [ ] **GOLD-COR-28** Replace `Vec::remove(0)` in `event_ledger/mod.rs:124-127` with `VecDeque`; change `find_ci` in `tools/web_fetch.rs` to use `memchr` or single lowercase pass — *files:* `SRC/neothd/src/event_ledger/mod.rs`, `SRC/neothd/src/tools/web_fetch.rs` — *test:* 16 MiB HTML does not cause quadratic CPU usage — *origin:* A-79
- [ ] **GOLD-COR-29** Replace `memory/archive.rs` TOCTOU `path.exists()` with `create_new(true)`; sanitize session_id to `[A-Za-z0-9_-]` — *files:* `SRC/neothd/src/memory/archive.rs` — *test:* concurrent archive writes do not race — *origin:* A-62
- [ ] **GOLD-COR-30** Serialize `memory/channel_weights.rs:208-232` load/mutate/write JSON with Mutex or move to SQLite — *files:* `SRC/neothd/src/memory/channel_weights.rs` — *test:* concurrent acceptance increments are not lost — *origin:* A-63
- [ ] **GOLD-COR-31** Verify `clear_kv_cache()` placement in `ouro/forward.rs` and `ouro/quantized_forward.rs`; move to once-per-`forward` call if correct — *files:* `SRC/neothd/src/providers/ouro/forward.rs`, `SRC/neothd/src/providers/ouro/quantized_forward.rs` — *test:* real-weight inference test (mark `#[ignore]` + document in test) — *origin:* C-23
- [ ] **GOLD-COR-32** Apply `clean_topic_en` fixpoint loop (same as `clean_topic_de`) to English path in `recall/conversational.rs` — *files:* `SRC/neothd/src/recall/conversational.rs` — *test:* English phrase "do you remember when we talked about" is correctly cleaned — *origin:* E-29
- [ ] **GOLD-COR-33** Acquire DB lock only for synchronous DB ops in `serve.rs`; release before any `.await` in `ConnBorrow::Shared` pipeline path (CR-010) — *files:* `SRC/neothd/src/cli/serve.rs` — *test:* concurrent channel requests do not serialize on DB lock — *origin:* CR-010, A-15
- [ ] **GOLD-COR-34** Wrap all 11 remaining detached `tokio::spawn` in `cli/serve.rs` in JoinSet for graceful shutdown and WAL drain — *files:* `SRC/neothd/src/cli/serve.rs` — *test:* `SIGTERM` allows WAL drain before exit — *origin:* CR-011

---

## WS-D — Feature Wiring: Complete Built-but-Unwired Features (GOLD-WIRE-NN)

Operator hard rule: unwired modules are FEATURES TO WIRE, never deletions.

- [ ] **GOLD-WIRE-01** Wire `coding/tool_router` into `ProviderWorker::execute()`: call `model_profile::get_profile` + `tool_router::routing_mode_for_profile` at top; dispatch TwoStage selector call before task prompt on small-context models — *files:* `SRC/neothd/src/coding/provider_worker.rs` — *test:* TwoStage mode fires a second provider.complete call; Direct mode skips it; unknown category reply falls back to Direct — *origin:* _wiring_results.md tool_router
- [ ] **GOLD-WIRE-02** Wire `recall/conversational` into `chat.rs::run_chat_with`: after RAW_TEXT WAL write, add `detect_recall_intent` check; on match, query memory and format reply without LLM call — *files:* `SRC/neothd/src/cli/chat.rs`, `SRC/neothd/src/cli/serve.rs` — *test:* "Weißt du noch als wir über X geredet haben?" triggers memory reply; no PROVIDER_REQUEST WAL frame written — *origin:* _wiring_results.md conversational_recall
- [ ] **GOLD-WIRE-03** Wire `providers/model_roles::ModelRoleTable` into `providers::from_config`: replace hardcoded `.unwrap_or_else(|| "claude-opus-4-7"...)` fallbacks with `role_table.resolve(provider_id, ModelRole::Flagship)` — *files:* `SRC/neothd/src/providers/mod.rs` — *test:* changing `default_table()` flagship entry changes provider model selection — *origin:* _wiring_results.md model_roles
- [ ] **GOLD-WIRE-04** Wire `CouncilVoice` into `orchestrator.rs::run_one()`: prepend `v.system_prompt_fragment()` to prompt when hemisphere has configured voice; add `voice: Option<CouncilVoice>` to `HemisphereSlot`; add `CouncilAction::Voices` CLI subcommand — *files:* `SRC/neothd/src/council/orchestrator.rs`, `SRC/neothd/src/council/types.rs`, `SRC/neothd/src/config/inference.rs`, `SRC/neothd/src/cli/council.rs` — *test:* hemisphere with SecurityEngineer voice prepends security fragment — *origin:* _wiring_results.md council_voice
- [ ] **GOLD-WIRE-05** Wire `claude_pid_hunter::scan_stuck_processes` into `cli/doctor.rs` as a new check entry; add doctor check that detects deadlocked claude processes — *files:* `SRC/neothd/src/cli/doctor.rs`, `SRC/neothd/src/providers/claude_pid_hunter.rs` — *test:* stuck claude process surfaces as WARN in doctor output — *origin:* _wiring_results.md claude_cli_recovery
- [ ] **GOLD-WIRE-06** Wire `claude_retry::classify_failure` + `retry_decision` into `complete_tmux_uncached()` error match arm — wrap send_and_wait in retry loop driven by `RetryDecision`; wire `strip_dead_resume_args` at session-start branch — *files:* `SRC/neothd/src/providers/claude_cli.rs` — *test:* Auth failure surfaces immediately; Empty result triggers retry with backoff — *origin:* _wiring_results.md claude_cli_recovery
- [ ] **GOLD-WIRE-07** Wire `EmbeddingIndex` boot load into daemon startup; add `EmbeddingIndex::add` after each embeddings upsert; replace `find_similar` brute-force with `find_similar_hnsw` dispatch at recall sites; gate via `freedom.yaml::memory.vector_index.backend` — *files:* `SRC/neothd/src/cli/serve.rs`, `SRC/neothd/src/cli/recall.rs`, `SRC/neothd/src/memory/vector_index.rs` — *test:* after indexing 50k+ vectors, recall uses HNSW path; cold start boots index from disk — *origin:* _wiring_results.md hnsw_embedding_index, vector_index_backends, A-09
- [ ] **GOLD-WIRE-08** Mark `SqliteVec`/`HnswRs` unimplemented variants in `vector_index.rs` with accurate doc; mark `IndexedVectorIndex::find_top_k` returning `None` explicitly — *files:* `SRC/neothd/src/memory/vector_index.rs` — *test:* doc accurately reflects None-returning stubs — *origin:* _wiring_results.md (honesty fix)
- [ ] **GOLD-WIRE-09** Wire `hlc_tick_receive` into gossip accept path in `cluster/hyperswarm.rs:782`; add `hlc: Hlc` field to `GossipFrame`; embed current HLC in `build_outbound` — *files:* `SRC/neothd/src/cluster/hyperswarm.rs`, `SRC/neothd/src/cluster/wal_sync.rs`, `SRC/neothd/src/cluster/gossip_wire.rs` — *test:* accepted gossip frame advances local HLC past peer's causal frontier — *origin:* _wiring_results.md hlc_gossip_receive, B-04
- [ ] **GOLD-WIRE-10** Wire `domain_events` as `KF-08` forward-infra: add a single producer call (e.g. from council dispatch) and wire to GUI budget meter instead of deleting — *files:* `SRC/neothd/src/domain_events/`, `SRC/neothd/src/council/orchestrator.rs` — *test:* council call emits domain event that GUI budget meter receives — *origin:* _wiring_results.md (domain_events cluster)
- [ ] **GOLD-WIRE-11** Expose `fact_check::assess` as `neoth fact-check <claim>` CLI subcommand — *files:* `SRC/neothd/src/cli/mod.rs`, `SRC/neothd/src/profile/fact_check.rs` — *test:* `neoth fact-check "NEOTH uses Rust"` returns FactCheckReport — *origin:* _wiring_results.md (fact_check cluster), C-17
- [ ] **GOLD-WIRE-12** Delete `COST_WARN_USD` re-export (0 callers), dead `tmux_sweeper.rs` wrappers, `OuroLayer`/`Ouro` O-1 scaffold (`#[allow(dead_code)]` `_placeholder` bodies) — wire or delete `parse_catalog_model_ids` and `check_fields` — *files:* `SRC/neothd/src/coding/mod.rs`, `SRC/neothd/src/cli/tmux_sweeper.rs`, `SRC/neothd/src/providers/ouro/model.rs` — *test:* clippy `--warn dead_code` passes — *origin:* C-32, C-14

---

## WS-E — Architecture Debt (GOLD-ARCH-NN)

- [ ] **GOLD-ARCH-01** Decompose `cli/serve.rs::run_serve` (2724 LOC) and `build_pipeline_handler` (1609 LOC): introduce `DaemonTaskRegistry`; extract named `spawn_*` modules per subsystem; decompose closure into named `async fn handle_inbound_*` stages — *files:* `SRC/neothd/src/cli/serve.rs` — *test:* file < 1500 LOC; named stage fns have their own tests — *origin:* C-01, D-03
- [ ] **GOLD-ARCH-02** Decompose `cli/chat.rs::run_chat_with` (2082 LOC): extract `build_prompt_bundle`, `enforce_preflight`, `dispatch_provider`, `run_post_reply_pipelines` phase functions — *files:* `SRC/neothd/src/cli/chat.rs` — *test:* each phase function has unit tests; integration test confirms same behavior — *origin:* C-02, D-02, CQ-001
- [ ] **GOLD-ARCH-03** Extract `wal::scan::for_each_frame(seg_bytes, cb)` handling v1/v2+zstd uniformly; migrate all 57+ callers (incl. `rollback.rs`, `indexer.rs`, `undo.rs`, `updater.rs`) — *files:* `SRC/neothd/src/wal/` (new module), 57+ callers — *test:* v2/zstd segment frames are not silently skipped in indexer and rollback — *origin:* C-09, D-01, A-65
- [ ] **GOLD-ARCH-04** Split `config/mod.rs` (3583 LOC, ~45 subsystem structs) into domain files: `config/observability.rs`, `config/proactive.rs`, etc. — *files:* `SRC/neothd/src/config/mod.rs` — *test:* file < 800 LOC; all subcommands still compile — *origin:* C-06, D-05
- [ ] **GOLD-ARCH-05** Split `cli/init.rs` (6262 LOC) into `cli/init/` subdirectory with `steps/`, `validation.rs`, `io.rs`, `catalog.rs` — *files:* `SRC/neothd/src/cli/init.rs` — *test:* each step file < 800 LOC; init integration tests still pass — *origin:* C-07
- [ ] **GOLD-ARCH-06** Split `cli/doctor.rs` (3487 LOC): extract `doctor/checks/*.rs` per domain; route via `&[fn(&Path)->CheckOutcome]` slice — *files:* `SRC/neothd/src/cli/doctor.rs` — *test:* adding a new check does not require editing more than one file — *origin:* C-08, D-08
- [ ] **GOLD-ARCH-07** Extract `crate::time::{now_unix_secs, now_unix_ns, now_unix_i64}` helpers with defined overflow semantics; migrate 47 private helper definitions and 206 inline occurrences — *files:* new `SRC/neothd/src/time.rs`, 47+ files — *test:* `grep "duration_since.*UNIX_EPOCH"` returns 0 outside `time.rs` — *origin:* C-11, D-07, A-71
- [ ] **GOLD-ARCH-08** Extract `credentials/chrome_common.rs` with shared `ChromeLoginRow`, `DecryptedChromeCredential`, decrypt loop, constants (V10/V11/SALTYSALT/IV); platform files supply only iteration count + keyring source — *files:* `SRC/neothd/src/credentials/chrome_linux.rs`, `SRC/neothd/src/credentials/chrome_macos.rs`, new `chrome_common.rs` — *test:* both platforms pass existing chrome decrypt tests — *origin:* C-13, D-14
- [ ] **GOLD-ARCH-09** Extract `atomic_write(path, bytes)` helper; replace all `remove_file + rename` callers (paperless, wizard) with it — *files:* new `SRC/neothd/src/util/atomic_write.rs`, multiple callers — *test:* `atomic_write` test verifies tmp+rename on Windows and Unix — *origin:* D-15
- [ ] **GOLD-ARCH-10** Cache compiled `Regex` in `HookDef` via `OnceLock`; reuse for both `fires` check and `Replace` action (currently double-compiles per dispatch) — *files:* `SRC/neothd/src/hooks/dispatcher.rs` — *test:* `hooks_dispatch_benchmark` shows 2× improvement — *origin:* A-40, C-24
- [ ] **GOLD-ARCH-11** Generify `ouro/forward.rs` and `ouro/quantized_forward.rs` via trait over native vs quantized Linear; eliminate near-verbatim duplicate forward loops — *files:* `SRC/neothd/src/providers/ouro/forward.rs`, `SRC/neothd/src/providers/ouro/quantized_forward.rs` — *test:* both paths produce identical output for same input — *origin:* D-18, C-14
- [ ] **GOLD-ARCH-12** Extract `async fn append_audit(writer, event_type, payload, level)` helper; replace repeated WAL-emit arms in `webhook_listener.rs:481-627` — *files:* `SRC/neothd/src/channels/webhook_listener.rs` — *test:* all audit arms use same helper — *origin:* D-20, C-15
- [ ] **GOLD-ARCH-13** Extract `run_pipeline` input struct `RunPipelineInputs` (currently 11 args); extract `DetectAssembleInputs` (10 args) — *files:* `SRC/neothd/src/profile/runner.rs`, `SRC/neothd/src/detect.rs` — *test:* clippy `too_many_arguments` passes — *origin:* D-16
- [ ] **GOLD-ARCH-14** Extract shared `installers::probe::cli_version(binary, args, timeout)` helper; eliminate 8× duplicated `cli_version` in `n8n.rs`, `ollama.rs`, etc. — *files:* new `SRC/neothd/src/installers/probe.rs`, 8 callers — *test:* all installer version probes use shared helper — *origin:* D-35
- [ ] **GOLD-ARCH-15** Move `QaVerdict`/`FailureItem` from `council/quality_score.rs` to `council/qa_verdict.rs` — *files:* `SRC/neothd/src/council/quality_score.rs`, new `council/qa_verdict.rs` — *test:* import sites updated; tests pass — *origin:* D-22, C-21
- [ ] **GOLD-ARCH-16** Remove dead code: `recovery/turn_journal.rs` Drop no-op, dead `tmux_sweeper.rs` wrappers, `claude_tmux.rs::truncate_at_idle_prompt`, `runner.rs::ensure_redaction_module_used` — *files:* respective files — *test:* clippy `dead_code` passes — *origin:* D-29
- [ ] **GOLD-ARCH-17** Extract `crate::util::url_encode`; replace hand-rolled hex `format!("{b:02x}")` with `hex::encode` everywhere; replace inline FNV with crate — *files:* new `SRC/neothd/src/util/url_encode.rs`, `SRC/neothd/src/media/gmail.rs`, `SRC/neothd/src/media/calendar.rs`, `SRC/neothd/src/profile/runner.rs` — *test:* URL encoding output is identical to stdlib behavior — *origin:* C-34, D-31
- [ ] **GOLD-ARCH-18** Replace `config/reload.rs` field-enumeration diff with `serde_yaml::Value` diff over both configs — *files:* `SRC/neothd/src/config/reload.rs` — *test:* adding a new field to `FreedomConfig` does not require editing reload.rs — *origin:* C-19
- [ ] **GOLD-ARCH-19** Implement `WizardState` serialization via `#[serde(skip)]` on secrets; delete `from_state`/`apply_to` manual mirror — *files:* `SRC/neothd/src/cli/wizard_checkpoint.rs` — *test:* wizard state round-trips without manual field list — *origin:* C-22
- [ ] **GOLD-ARCH-20** Newtype WAL scope/category (naked u32); `WizardStep` enum instead of magic u8; structured YAML migration instead of `String::replace` — *files:* `SRC/neothd/src/wal/header.rs`, `SRC/neothd/src/cli/init.rs` — *test:* `WizardStep` variants are exhaustive; `String::replace` migration calls return 0 — *origin:* D-32
- [ ] **GOLD-ARCH-21** Consolidate `ClusterId`/`PeerId`/`PeerPubkey` three peer-identity types into single type; rename UUID variant to `PeerSessionId` — *files:* `SRC/neothd/src/cluster/mod.rs`, `SRC/neothd/src/cluster/pears_election.rs`, `SRC/neothd/src/cluster/gossip_wire.rs` — *test:* single peer identity type used across cluster modules — *origin:* E-09
- [ ] **GOLD-ARCH-22** Cache `Box::leak` worker names as `Arc<str>` in `cli/code.rs:334-335` (3 leaks per dispatch) — *files:* `SRC/neothd/src/cli/code.rs` — *test:* worker name allocation does not grow over repeated dispatches — *origin:* A-59

---

## WS-F — Gold-TODO Feature Build-Out (GOLD-FEAT-NN)

v1.0-WIRE items first, then v1.1 builds.

**v1.0-WIRE (wiring of existing pieces):**

- [ ] **GOLD-FEAT-01** Build sudomode CLI + zero-friction onboarding preset + single-provider hemisphere mode: new `cli/sudomode.rs` + WAL events `0xDB/0xDC/0xDD`; extend `Preset` with opt-in fields; new `wizard/zero_friction.rs`; extend `HemisphereAction::Mode`; GUI toggle — *files:* `SRC/neothd/src/cli/sudomode.rs` (new), `SRC/neothd/src/wizard/zero_friction.rs` (new), `SRC/neothd/src/wal/events.rs`, `SRC/neothd/src/config/presets.rs`, `SRC/neothd/src/cli/init.rs`, `SRC/neothd/src/cli/mod.rs`, `SRC/neothd-gui/ui/settings.slint` — *test:* `neoth sudomode on` sets `AutonomyLevel::Full`; zero-friction preset flips all expected flags; hemisphere mode single written to freedom.yaml — *origin:* Gold-TODO #18/#19/#26 → full plan: `REVIEWS/_gold_audit/research/sudomode_zerofriction_singleprovider.md`
- [ ] **GOLD-FEAT-02** Add huihui-ai Qwen3.x-abliterated family to wizard recommendation table with VRAM-gated quant selection: update `wizard/recommend.rs` with VRAM probe → quant mapping; add ollama pull command guidance — *files:* `SRC/neothd/src/wizard/recommend.rs`, `SRC/neothd/src/models/catalog.rs` — *test:* wizard with 16 GiB VRAM recommends Q4_K; wizard with 24 GiB recommends Q6_K — *origin:* Gold-TODO #17 → full plan: `REVIEWS/_gold_audit/research/model_choice_abliterated.md`
- [ ] **GOLD-FEAT-03** Build NEOTH self-wiki Obsidian pipeline (SW-01/02/03): new `wiki/` module (sources/renderer/writer/ingest); CLI `neoth obsidian wiki-build`; background `wiki_build_task`; WAL `0x4E`/`0x4F`; `SelfWikiConfig` in FreedomConfig; wiki-cache tier in operator_md loader — *files:* `SRC/neothd/src/wiki/mod.rs` (new), `SRC/neothd/src/wiki/sources.rs` (new), `SRC/neothd/src/wiki/renderer.rs` (new), `SRC/neothd/src/wiki/writer.rs` (new), `SRC/neothd/src/wiki/ingest.rs` (new), `SRC/neothd/src/cli/wiki_build_task.rs` (new), `SRC/neothd/src/cli/obsidian.rs`, `SRC/neothd/src/config/mod.rs`, `SRC/neothd/src/wal/events.rs` — *test:* `neoth obsidian wiki-build --dry-run` generates expected pages; SPEC files appear as wiki leaves; wiki pages push to groundtruth — *origin:* Gold-TODO #1/#2 → full plan: `REVIEWS/_gold_audit/research/self_wiki_obsidian.md`
- [ ] **GOLD-FEAT-04** Implement `neoth-migrate apply` path: `wal_emit::OperatorWalEmitter`; source readers (openclaw, hermes, openhuman, scripts); WAL events `0xDB/0xDC/0xDD` (MIGRATION_STARTED/BATCH/COMPLETE); wizard `step0b_install_mode` with auto-detection — *files:* `SRC/neoth-migrate/src/wal_emit.rs` (new), `SRC/neoth-migrate/src/source_readers/` (new), `SRC/neoth-migrate/src/main.rs`, `SRC/neothd/src/cli/init.rs`, `SRC/neothd/src/wal/events.rs` — *test:* `neoth-migrate dry-run` still read-only; apply writes WAL frames; wizard detects ~/.openclaw and prompts — *origin:* Gold-TODO #4, B-01, A-02, CR-026 → full plan: `REVIEWS/_gold_audit/research/migration_onboarding.md`

**v1.1 builds (net-new, after v1.0 complete):**

- [ ] **GOLD-FEAT-05** Build NEOTH self-reprogramming: `Action::SelfSourceEdit`; `coding/self_source.rs` + `self_source_gate.rs`; 5-layer safety stack (freedom.yaml kill-switch, allowed_modules allowlist, permission gate, worktree isolation, green-test gate); WAL `0xDB SELF_EDIT_PROPOSED`/`0xDC SELF_EDIT_APPLIED`; CLI `neoth self-edit` — *test:* Strict/Standard level denies; `src/wal/` path in diff is rejected; `src/cli/dummy.rs` comment addition passes — *origin:* Gold-TODO #3 → full plan: `REVIEWS/_gold_audit/research/self_reprogramming.md`
- [ ] **GOLD-FEAT-06** Build exo-style swarm dashboard: `NodeResourceSnapshot` + gossip piggyback on heartbeat; `SwarmTable` in-memory; `daemon/resource_snapshot_cron.rs`; `neoth cluster swarm [--watch]`; WAL `0xDB SWARM_RESOURCE_SNAPSHOT`/`0xDC LOCAL_SNAPSHOT`; Slint `SwarmNodeCard` in cluster tab — *test:* `neoth cluster swarm --output json` returns rows with cpu_pct, ram, vram; GUI card renders; stale entries pruned — *origin:* Gold-TODO #5 → full plan: `REVIEWS/_gold_audit/research/swarm_dashboard_exo.md`
- [ ] **GOLD-FEAT-07** Build LOWKEY moral core framework: `MoralCoreConfig`; `memory/moral_core/` (block.rs, loader.rs); `EnrichmentInputs.moral_core` at position 0; `security/local_shadow.rs` with synthetic-conversation injection; WAL `0xBE MORAL_CORE_APPLIED`/`0xBF LOCAL_SHADOW_FIRED`; `neoth moral-core import/list/preview/doctor` CLI; wizard step 6b — *test:* moral_core dir with tagged MD injects compact directives; local shadow fallback fires on refusal when enabled; moral_core=disabled skips injection — *origin:* Gold-TODO #16 → full plan: `REVIEWS/_gold_audit/research/lowkey_moral_core.md`
- [ ] **GOLD-FEAT-08** Build refusal → local abliterated Qwen fallback (Gold #24): detect refusal after cloud model; route to `AbliteratedProvider`; inject shadow answer as synthetic prior-assistant-turn (Approach 1) or system-prompt context (Approach 2 fallback); cloud model continues — note: Anthropic Claude 4.6+ blocks trailing assistant prefill; use synthetic conversation turn instead — *test:* refusal from cloud model triggers local call; cloud model receives shadow context and produces answer; `0xBF LOCAL_SHADOW_FIRED` WAL frame emitted — *origin:* Gold-TODO #24 → full plan: `REVIEWS/_gold_audit/research/refusal_abliterated_fallback.md`, `REVIEWS/_gold_audit/research/lowkey_moral_core.md`
- [ ] **GOLD-FEAT-09** Build autofixer watchdog: probe n8n/Ollama/Obsidian on `resource_watch` cadence; 3-consecutive-failures before restart; exponential backoff + jitter; max K restarts per N-min window; WAL audit frames; freedom.yaml `watchdog.*` config — *test:* simulated n8n crash triggers restart after 3 failures; restart rate-limit prevents thrashing — *origin:* Gold-TODO #20 → full plan: `REVIEWS/_gold_audit/research/autofixer_watchdog.md`
- [ ] **GOLD-FEAT-10** Add channel parity with openclaw — implement Signal (signal-cli subprocess), Matrix (matrix-rust-sdk), LINE (REST webhook), iMessage (macOS/AppleScript, platform-gated), IRC (irc crate) adapters implementing the `Channel` trait — *test:* Signal inbound message routes through pipeline; Matrix join/send round-trip — *origin:* Gold-TODO #21 → full plan: `REVIEWS/_gold_audit/research/channel_parity_openclaw.md`
- [ ] **GOLD-FEAT-11** Build onboarding + proactivity parity with openhuman/hermes: post-init health checklist; `quiet_hours` on proactive drain; `idle_only` gate on checkin nudges; LLM-generated checkin bodies (casual_checkin, resume_prompt, unfinished_thread_nudge); `/goal` cross-turn goal persistence; skill-curator 7-day cycle — *test:* checkins respect quiet_hours; goal is injected into system prompt across turns — *origin:* Gold-TODO #22/#23 → full plan: `REVIEWS/_gold_audit/research/onboarding_proactivity_parity.md`
- [ ] **GOLD-FEAT-12** Token optimization + Jarvis/Veronica memory mining: Anthropic `cache_control` on system prompt (system as array with `{type:"ephemeral"}` blocks); OP-01 hashline edits in `cli/edit.rs`; D-block dedup via xxh3; local summarization for warm-tier recall; `prefer_local_for_classification` hemisphere flag — *test:* AnthropicApi adapter sends system as array with cache_control; OP-01 produces hashline diff format — *origin:* Gold-TODO #25/#27/#28 → full plan: `REVIEWS/_gold_audit/research/tokenopt_jarvis_memory.md`

---

## WS-G — Repo Adoptions (GOLD-ADOPT-NN)

Verdict table from `REVIEWS/_gold_audit/research/repo_adopt_batch_a.md` and `repo_adopt_batch_b.md`:

| Repo | Verdict | Reason | Integration |
|------|---------|--------|-------------|
| knowledge-work-plugins | ADOPT-NATIVE | 6 engineering skills (code-review, incident-response, system-design, tech-debt, testing-strategy, documentation) convert 1:1 to NEOTH skill.yaml; plugin infra layer skipped | Bundled skills in `assets/skills/` |
| ai-engineering-from-scratch | GROUND-TRUTH-KNOWLEDGE | 503-lesson curriculum; Phase 14/16/17 agent patterns → one bundled skill; rest → Obsidian brain | One bundled skill `agent_engineering_patterns` |
| compound-engineering-plugin | GROUND-TRUTH-KNOWLEDGE | TypeScript plugin infra; relevant patterns → Obsidian brain | Obsidian note only |
| ECC (affaan-m) | EVALUATE-FIRST | Agent-gremium evaluation needed per operator instruction | Gremium evaluation before any adoption |
| Anthropic-Cybersecurity-Skills | ADOPT-NATIVE | Security skill prompts map to NEOTH skill.yaml trigger_keywords + system_prompt | Bundled skills |
| Scrapling | GROUND-TRUTH-ADOPT | Python runtime violates self-contained rule; native Rust scraper + stealth-fetch via headless chromium subprocess | `tools/web_extract.rs` + `tools/web_selector_cache.rs` with `scraper` crate |
| stop-slop | EVALUATE-FIRST | Gremium evaluation needed | Gremium evaluation before adoption |
| claudeclaw | EVALUATE-FIRST | Gremium evaluation needed | Gremium evaluation before adoption |
| adhd (UditAkhourii) | EVALUATE-FIRST (HIGH PRIORITY) | Operator flagged as personally important; gremium evaluation first | Gremium evaluation |
| odysseus | GROUND-TRUTH-KNOWLEDGE + GUI-INSPIRATION | GUI inspiration for Slint improvements; no direct code adoption | GUI design reference; Obsidian note |

- [ ] **GOLD-ADOPT-01** Port 6 engineering skills from knowledge-work-plugins to NEOTH bundled skills: `engineering_code_review`, `engineering_incident_response`, `engineering_system_design`, `engineering_tech_debt`, `engineering_testing_strategy`, `engineering_documentation` — *files:* `SRC/neothd/assets/skills/engineering_*/skill.yaml` (6 new), `SRC/neothd/src/skills/bundled.rs` — *test:* `neoth skill list` shows 6 new skills; trigger keywords fire correctly — *origin:* GOLD-ADOPT (knowledge-work-plugins)
- [ ] **GOLD-ADOPT-02** Port 6 cybersecurity skill prompts from Anthropic-Cybersecurity-Skills to NEOTH bundled skills — *files:* `SRC/neothd/assets/skills/cybersec_*/skill.yaml` (new), `SRC/neothd/src/skills/bundled.rs` — *test:* security skill triggers on relevant keywords — *origin:* GOLD-ADOPT (Anthropic-Cybersecurity-Skills)
- [ ] **GOLD-ADOPT-03** Create bundled skill `agent_engineering_patterns` from ai-engineering-from-scratch Phase 14/16/17 content — *files:* `SRC/neothd/assets/skills/agent_engineering_patterns/skill.yaml` (new), `SRC/neothd/src/skills/bundled.rs` — *test:* skill triggers on "multi-agent", "agentic system" keywords — *origin:* GOLD-ADOPT (ai-engineering-from-scratch)
- [ ] **GOLD-ADOPT-04** Build native web extraction layer from Scrapling patterns: `tools/web_extract.rs` (CSS/XPath via `scraper` crate); `tools/web_selector_cache.rs` (adaptive re-find); WAL `0xCE WEB_EXTRACT_HIT`/`0xCF WEB_EXTRACT_SELECTOR_STALE`; `neoth fetch --selector` flag — *files:* `SRC/neothd/src/tools/web_extract.rs` (new), `SRC/neothd/src/tools/web_selector_cache.rs` (new), `SRC/neothd/src/wal/events.rs`, `SRC/neothd/src/cli/mod.rs` — *test:* CSS selector on mock HTML returns correct text nodes; stale selector emits WAL frame — *origin:* GOLD-ADOPT (Scrapling)
- [ ] **GOLD-ADOPT-05** Run agent-gremium evaluation on ECC (affaan-m/ECC) and produce verdict: adopt-native / ground-truth / skip + integration note — *files:* `REVIEWS/_gold_audit/gremium_eval_ecc.md` (new) — *test:* verdict document with concrete adopt/skip decision — *origin:* GOLD-ADOPT (ECC)
- [ ] **GOLD-ADOPT-06** Run agent-gremium evaluation on stop-slop (hardikpandya/stop-slop) and produce verdict — *files:* `REVIEWS/_gold_audit/gremium_eval_stop_slop.md` (new) — *test:* verdict document — *origin:* GOLD-ADOPT (stop-slop)
- [ ] **GOLD-ADOPT-07** Run agent-gremium evaluation on claudeclaw (moazbuilds/claudeclaw) and produce verdict — *files:* `REVIEWS/_gold_audit/gremium_eval_claudeclaw.md` (new) — *test:* verdict document — *origin:* GOLD-ADOPT (claudeclaw)
- [ ] **GOLD-ADOPT-08** Run agent-gremium evaluation on adhd (UditAkhourii/adhd) — high priority per operator — and produce verdict — *files:* `REVIEWS/_gold_audit/gremium_eval_adhd.md` (new) — *test:* verdict document — *origin:* GOLD-ADOPT (adhd, HIGH PRIORITY)
- [ ] **GOLD-ADOPT-09** GUI design pass inspired by odysseus: produce list of odysseus GUI features not in NEOTH's Slint GUI; implement top-3 most impactful; Obsidian note with design reference — *files:* `REVIEWS/_gold_audit/gremium_eval_odysseus_gui.md` (new), `SRC/neothd-gui/` (changes per analysis) — *test:* 3 implemented GUI improvements; Obsidian note created — *origin:* GOLD-ADOPT (odysseus)

---

## WS-H — PROGRESS Carry-Forward (GOLD-PROG-NN)

Items from `PLAN/PROGRESS_v1_0.md` at HEAD. Shipped parts are `[x]`, open remainders are `[ ]`.

- [x] **GOLD-PROG-01** AP-08 verify-crypto e2e shipped (commit `d6825c2`) — flip stale `[~]` to `[x]` in PROGRESS_v1_0.md — *origin:* agent6 Section C
- [x] **GOLD-PROG-02** MONITOR-02 real-time worker-task death detection (0x4D WORKER_DIED) shipped (`7383abd`) — *origin:* session 39 burndown
- [x] **GOLD-PROG-03** F4-01 winner-chain council win-distribution shipped (`35c94d2`) — *origin:* session 39 burndown
- [x] **GOLD-PROG-04** PC-01 clipboard R/W (0xBC/0xBD) shipped (`10adfad`) — *origin:* session 39 burndown
- [ ] **GOLD-PROG-05** SL-02 cluster topology GUI panel — CLI shipped; GUI panel display-gated; build Slint topology panel consuming `neoth cluster topology --output json` — *files:* `SRC/neothd-gui/ui/settings.slint`, `SRC/neothd-gui/src/main.rs` — *test:* cluster tab shows peer list with RTT/stability — *origin:* agent6 Section C SL-02
- [ ] **GOLD-PROG-06** SL-01/SL-01b cluster task-accept full loop — transport shipped; complete ProactiveChannelSend consumer wiring for task-accept — *files:* `SRC/neothd/src/cluster/hyperswarm.rs`, `SRC/neothd/src/cli/serve.rs` — *test:* remote task arrives via cluster and is dispatched — *origin:* agent6 Section C SL-01
- [ ] **GOLD-PROG-07** SL-03 local LLM resource tab GUI — headless telemetry shipped; build Slint panel for VRAM/load/power — *files:* `SRC/neothd-gui/ui/settings.slint`, `SRC/neothd-gui/src/main.rs` — *test:* GUI tab shows live VRAM reading — *origin:* agent6 Section C SL-03
- [ ] **GOLD-PROG-08** KF-08 live council budget meter Slint GUI widget — headless `telemetry/council_meter.rs` shipped; build Slint widget + tokio broadcast wiring — *files:* `SRC/neothd-gui/ui/settings.slint`, `SRC/neothd-gui/src/main.rs` — *test:* GUI meter updates after council call — *origin:* agent6 Section C KF-08
- [ ] **GOLD-PROG-09** OP-01 hashline content-hash edits in `cli/edit.rs` (-61% output tokens) — implement `hashline_diff(old, new)` + `--hashline` flag + `freedom.yaml::tokens.hashline_edits` toggle — *files:* `SRC/neothd/src/cli/edit.rs` — *test:* `neoth edit --hashline` produces `@@ <sha256_8> +N:` format — *origin:* agent6 Section C OP-01
- [ ] **GOLD-PROG-10** OP-03 LSP diagnostics loop on every write — implement LSP server integration for real-time diagnostics — *files:* new `SRC/neothd/src/lsp/` module — *test:* `neoth edit <file>` triggers LSP diagnostics — *origin:* agent6 Section C OP-03
- [ ] **GOLD-PROG-11** QU-10c `--verify-tests` flag on `neoth finish`/`neoth branch` — requires `finish`/`branch` subcommand first — *files:* new CLI subcommands — *test:* `neoth finish --verify-tests` runs test suite before closing task — *origin:* agent6 Section C QU-10c
- [ ] **GOLD-PROG-12** ADV-08 `compaction_epoch: u32` in `SegmentHeader` — fixes idempotency-key collision after mid-rename crash; WAL format change needs migration — *files:* `SRC/neothd/src/wal/header.rs`, migration logic — *test:* mid-rename crash + restart does not produce duplicate frames — *origin:* agent6 Section C ADV-08
- [ ] **GOLD-PROG-13** MV-01b CI minisign keypair — operator action: provision `NEOTH_RELEASE_MINISIGN_PUBKEY` CI secret; code is complete — *operator-input needed:* Alex must add keypair to GitHub Actions secrets — *files:* `.github/workflows/release.yml` — *test:* signed release artifact verifies against public key — *origin:* agent6 Section C MV-01b
- [ ] **GOLD-PROG-14** MV-01c model-version-agnostic `pub(crate)` blocker resolution — *files:* `SRC/neothd/src/providers/mod.rs` — *test:* model catalog passthrough works without hardcoded whitelist — *origin:* agent6 Section C MV-01
- [ ] **GOLD-PROG-15** PC-02 Chrome DevTools MCP — operator decision needed on license + forced `CHROME_DEVTOOLS_MCP_NO_USAGE_STATISTICS=1` + telemetry confirm before build — *operator-input needed:* Alex must approve license — *files:* new MCP plugin — *test:* Chrome DevTools MCP connects and tools are accessible — *origin:* agent6 Section C PC-02
- [ ] **GOLD-PROG-16** SPEC-11 Phase 2 adapters: Discord, Signal, iMessage, LINE, Matrix channel adapters (5 channels, ~3-5d each) — *files:* `SRC/neothd/src/channels/discord.rs` (new), signal/imessage/line/matrix adapters (new) — *test:* each adapter passes inbound message through pipeline — *origin:* agent6 Section C SPEC-11
- [ ] **GOLD-PROG-17** PROOF-KEY-01 full operator proof-key lifecycle CLI (`neoth wal proof`) — primitive ed25519 signing shipped; build full CLI + UX + docs — *files:* `SRC/neothd/src/cli/wal.rs`, docs — *test:* `neoth wal proof sign` + `verify` round-trip — *origin:* agent6 Section C PROOF-KEY-01
- [ ] **GOLD-PROG-18** SPEC-05 user adaptation estimator quality verification + full adaptation loop consumer — cron wired; complete verify pass for 5 passive estimators — *files:* `SRC/neothd/src/profile/`, relevant modules — *test:* adaptation loop updates profile based on detected patterns — *origin:* agent6 Section C SPEC-05
- [ ] **GOLD-PROG-19** ARCH-06 full 96-byte WAL header with HLC physical+logical fields — HLC tick local in builder; complete 96-byte header format verification — *files:* `SRC/neothd/src/wal/header.rs`, `SRC/neothd/src/wal/builder.rs` — *test:* header size is exactly 96 bytes; physical + logical clock fields decode correctly — *origin:* agent6 Section C ARCH-06

---

## 5. Definition of GOLD (Release Gate)

All of the following must be `[x]` before tagging `v1.0-gold`:

- [ ] WS-A: All GOLD-SEC-NN tasks done
- [ ] WS-B: All GOLD-HON-NN tasks done
- [ ] WS-C: All GOLD-COR-NN tasks done
- [ ] WS-D: All GOLD-WIRE-NN tasks done
- [ ] WS-E: GOLD-ARCH-01 through GOLD-ARCH-09 (security-critical arch debt) done; GOLD-ARCH-10 through GOLD-ARCH-22 strongly recommended
- [ ] All HIGH findings from beta review (A-01..A-10) are `[x]`
- [ ] All HIGH findings from Roman review (CR-007, CR-010, CR-011, CR-031, PAT-002, SR-001, SR-017) are `[x]`
- [ ] WS-G: Gremium evaluations complete for all EVALUATE-FIRST repos; adopt-verdicts implemented
- [ ] WS-H: All non-operator-blocked GOLD-PROG-NN tasks done; operator-blocked tasks (GOLD-PROG-13 minisign keypair, GOLD-PROG-15 PC-02 license) have operator decisions recorded
- [ ] Full build + clippy + test green on Windows+MSVC: `cargo clippy -p neothd --tests --no-deps -- -D warnings` exits 0; `cargo test -p neothd --lib` exits 0
- [ ] `NEOTH_REGEN_CLI_DOCS=1 cargo test -p neothd --lib cli_commands_md_is_up_to_date` exits 0 (no CLI doc drift)
- [ ] README/docs honesty pass merged (GOLD-HON-01..GOLD-HON-26 all done)
- [ ] Signed release artifacts exist (cargo-dist or manual) with sha256 companion hashes

**WS-F (Gold-TODO features):** GOLD-FEAT-01..GOLD-FEAT-04 are v1.0-WIRE and must complete before tag. GOLD-FEAT-05..GOLD-FEAT-12 are v1.1 and ship after v1.0 tag. WS-G evaluations complete.

---

## 6. Appendix — Source Artifacts

**Audit files (all verified at HEAD `3df06b5`, 2026-06-06):**
- `REVIEWS/_gold_audit/agent1_strategic.md` — B-01..B-23 strategic/honesty findings
- `REVIEWS/_gold_audit/agent2_security_high.md` — A-01..A-10 HIGH security (all STILL-TRUE)
- `REVIEWS/_gold_audit/agent3_arch_medium.md` — A-11..A-50 MEDIUM findings
- `REVIEWS/_gold_audit/agent4_arch_low_cleancode.md` — A-51..A-88 + Clean Code D + Naming E
- `REVIEWS/_gold_audit/agent5_code_quality.md` — C-01..C-39 code quality / unwired modules
- `REVIEWS/_gold_audit/agent6_feature_gap.md` — Gold-TODO map + Roman-review 14 kept findings + PROGRESS open/partial
- `REVIEWS/_gold_audit/_wiring_results.md` — 8 clusters with concrete wiring paths

**Research files (Gold-TODO feature plans, one per feature):**
- `REVIEWS/_gold_audit/research/sudomode_zerofriction_singleprovider.md` — GOLD-FEAT-01
- `REVIEWS/_gold_audit/research/model_choice_abliterated.md` — GOLD-FEAT-02
- `REVIEWS/_gold_audit/research/self_wiki_obsidian.md` — GOLD-FEAT-03
- `REVIEWS/_gold_audit/research/migration_onboarding.md` — GOLD-FEAT-04
- `REVIEWS/_gold_audit/research/self_reprogramming.md` — GOLD-FEAT-05
- `REVIEWS/_gold_audit/research/swarm_dashboard_exo.md` — GOLD-FEAT-06
- `REVIEWS/_gold_audit/research/lowkey_moral_core.md` — GOLD-FEAT-07
- `REVIEWS/_gold_audit/research/refusal_abliterated_fallback.md` — GOLD-FEAT-08
- `REVIEWS/_gold_audit/research/autofixer_watchdog.md` — GOLD-FEAT-09
- `REVIEWS/_gold_audit/research/channel_parity_openclaw.md` — GOLD-FEAT-10
- `REVIEWS/_gold_audit/research/onboarding_proactivity_parity.md` — GOLD-FEAT-11
- `REVIEWS/_gold_audit/research/tokenopt_jarvis_memory.md` — GOLD-FEAT-12
- `REVIEWS/_gold_audit/research/repo_adopt_batch_a.md` — GOLD-ADOPT-01..05
- `REVIEWS/_gold_audit/research/repo_adopt_batch_b.md` — GOLD-ADOPT-04..09

**Original reviews:**
- `REVIEWS/neoth beta review/NEOTH-Findings-Register.md` — B-01..B-23 (written at `35c94d2`)
- `REVIEWS/roman review/findings.html` — CR-* / PAT-* / SR-* / CQ-* findings (written at `3ef9771`)

**Progress tracker:** `PLAN/PROGRESS_v1_0.md` — the live OPEN/DONE tracker; must be updated in the same commit as each task.

**Architecture spec:** `PLAN/00_DESIGN_v1.1_FINAL.md` — authoritative design. SPEC files: `PLAN/SPEC_*.md`.
