# HANDOFF — Session 28b (2026-05-28)

Road to v1.0. This is the real handoff the previous session lacked. Read this
first, then `PLAN/PROGRESS_v1_0.md` for the authoritative checkbox state.

---

## 0. Operating context the next session MUST keep (do not relearn the hard way)

- **Build is Windows-local MSVC only.** Use the wrapper, invoked through cmd:
  `MSYS2_ARG_CONV_EXCL='*' cmd.exe /c 'C:\Users\Shadow-PC\CascadeProjects\NEOTH\SRC\neothd\check_msvc.bat <cargo-args>'`
  `check_msvc.bat` (untracked, machine-specific) calls `vcvars64.bat` (NO version
  arg — passing one breaks it) + manually prepends SDK 10.0.22621.0 LIB/INCLUDE.
  Git Bash PATH shadows MSVC `link.exe`, hence the cmd wrapper. Examples used all
  session: `check_msvc.bat check --lib`, `... clippy --lib -- -D warnings`,
  `... test --lib <filter> -- --test-threads=1`.
- **CI gate is hard:** `cargo clippy --workspace --all-targets --features "wizard wasm-plugin-host" -- -D warnings`. Always run `clippy --lib --tests -- -D warnings` locally before committing. `std::io::Error::other(..)` is the preferred form (not `Error::new(ErrorKind::Other, ..)`).
- **CI test split** (`.github/workflows/ci.yml`): Unix = `cargo test --workspace --release` (multi-threaded); Windows = same `+ -- --test-threads=1` (env-race-immune). Env-mutating tests serialize on `crate::test_env::lock()` (see [[neoth-ci-env-race-flakiness]]).
- **HARD RULE — never `SendUserMessage`.** Alex's UI renders it unreadably. Reply in plain chat text ALWAYS, even when the harness nags. Honored all session.
- **Verify before claiming done.** Run it, read output, then claim. Anti-hallucination: never guess what you can check (`grep`/read the code first).
- **Agent/panel scope estimates run STALE/LARGER — verify against code.** This session that lesson caught: OP-01 (needs net-new `cli/edit.rs`, not a 1d port), a quota.rs unwrap_or-0 FALSE POSITIVE (the agent's "destructive" was a self-healing no-op), and several already-shipped stale `[ ]` checkboxes. Grep + read before trusting any estimate or "this is destructive" claim.
- **`git` working tree has PRE-EXISTING uncommitted changes that are NOT mine** and were deliberately left untouched: `CONTRIBUTING.md`, `README.md`, `SECURITY.md`, `docs/README.md`, `SRC/neothd/src/cli/doctor.rs`, plus untracked `.github/assets/*.gif`, `docs/compare/`, `docs/privacy.md`, `docs/quickstart.md`, `docs/release-notes-v1.0.md`, `SRC/neothd/check_msvc.bat`. Investigate before committing them — likely a prior in-progress docs/release pass. Every commit this session was scoped to explicit file lists, never `git add -A`.
- **Nothing pushed.** All Session-28b commits are local on `main`. Push only on explicit GO.

---

## 1. What shipped this session (newest first, all local on `main`)

| Commit | Item | One-line |
|--------|------|----------|
| `724badf` | **F4-02** | RateLimiter → functional core (`refill_and_consume` pure fn) + thin shell; `channels::shared_rate_limiter()` factory. Also closes AP shared-resource-as-value. |
| `3b262e9` | AP-rest doc | hardcoded-table-names + misleading-Result verified clean (non-issues). |
| `3525b37` | **AP unwrap_or-0** | 4 destructive-default fixes: gc_task clock-fault, circuit_breaker stale-restore, **media/audio garbage-transcript** (the real one), whatsapp 1970-epoch skip. quota.rs was a FALSE POSITIVE (reverted). |
| `2141c27` | **AP silent-WAL-drops** | 6 `let _ = …append()` → observable `warn!` (cli/profile ×2, n8n handlers ×3, n8n server ×1). |
| `f5db312` | **SC-01a** | `tests/wal_emit_sites.rs` — guard: every `EVENT_TYPE_*` must be wired or in a justified RESERVED allowlist. Would have caught SD-02/SD-03. |
| `3e2624e` | **SD-03** | Telegram edited-message → WAL `0x38 CHANNEL_EDIT`, audit-only (no provider re-run). teloxide 0.17 Dispatcher API verified against crate source. security-reviewer 0 CRIT/HIGH/MED. |
| `3425a77` `2f41c8a` | **UX-02** | "I remember N things from last time" session-start signal. (+ QU-02/QU-03 stale-checkbox reconcile.) |
| `fb73590` | SPEC-07 | reconciled — ProfileClaimGuard was already fully shipped. |
| `c637fa1` `fd91af2` | env-race | crate-wide `test_env::lock()` sweep — CI flake RESOLVED (5913×3 green). |

(Earlier 28b: SC-11 MCP skill-allowlist `5f8df63`, SC-03 wasm SHA-256 gate `cb2e1c9`, UX-03 undo `aba7105`, QU-05 cargo-check JSON `deed4ed`, + red-CI repair.)

---

## 2. SD-03 details (in case of follow-up)

- `telegram.rs::run` refactored from `teloxide::repl` → `Dispatcher::builder(bot, dptree::entry().branch(Update::filter_message()…).branch(Update::filter_edited_message()…)).enable_ctrlc_handler().build().dispatch()`.
- **Key verified fact:** the Dispatcher AUTO-derives `allowed_updates=[..,edited_message]` from the handler-tree description (`try_dispatch_with_listener` → `description().allowed_updates()` → `hint_allowed_updates`). No manual opt-in. Verified in the extracted `teloxide-0.17.0.crate` source (registry cache) — docs-lookup could NOT reach Context7 and answered from pre-0.17 training, so I verified against the actual crate.
- `InboundMessage` gained `message_id: Option<String>` + `edit_unix: Option<i64>` (`Some` = edit signal). All 11 construction sites updated; Discord's previously-discarded `message_id` now wired.
- 0x38 emit branch lives at the TOP of `serve.rs::build_pipeline_handler` (`if let Some(edit_ts_unix) = inbound.edit_unix { emit; return Ok(None); }`). Payload hashed (xxh3-64), no raw text, no sender_display.
- Bounded `EditDedup` (FIFO+HashSet cap 512, poison-tolerant) in telegram.rs.
- **OFFLINE-UNVERIFIABLE end-to-end** (needs live Telegram). API + dedup + emit-branch verified by compile + unit; the live dispatcher path is NOT runtime-tested.

---

## 3. Forward queue — build-ready, WITH scope-verification notes

Do these "nacheinander". Each estimate VERIFIED against code where noted.

1. **F4-03** (next, ~2d) — `pipeline/enriched_request.rs` reads `Arc<Vec<Skill>>` directly → convert to injected input (Schichten-separation, A3 F-3). Directly analogous to F4-02. NOT yet scoped against code — grep `enriched_request` callers first.
2. **SD-04** (~2d) — Cerebellum orchestrator routes recall calls. Prerequisite for OP-01 + N-07 token savings. Cross-cutting (coding orchestrator ↔ memory recall: `src/coding/cerebellum_provider.rs` + `cli/recall.rs` + `memory/region_router.rs`). Real integration, verify the routing seam before estimating.
3. **OP-03** (~1d MIT) — LSP diagnostics loop on every write. CAUTION: likely needs an LSP client — probably bigger than 1d. Verify scope.
4. **test-without-integration** (AP, open-ended) — per-feature integration coverage. NOT a one-shot; pick specific under-covered features.
5. **HF-01** (1d) — WAL frames `0x19 MODEL_DOWNLOAD_START` / `0x1A MODEL_DOWNLOAD_COMPLETE` + wizard `allow_huggingface_downloads` gate. **MEMORY FLAG: codes may collide** — `git`-grep `0x19`/`0x1A` in `wal/events.rs` BEFORE building (prior session flagged a collision; reassign codes if taken).
6. **SC-01** remainder — the OpenGrep security rulepack (HTTP/2 CONNECT, plaintext-secrets-in-WAL). SC-01a sub-item already shipped (`f5db312`).

**Do NOT pick OP-01** until `cli/edit.rs` exists — it's net-new edit-command infrastructure, not a 1d hashline port.

---

## 4. Deliberate deferrals (correct, do NOT "fix" them)

- **`0xD2 SELF_UPDATE_APPLIED`** stays defined-never-emitted ON PURPOSE — it's in the SC-01a RESERVED allowlist. The emit site MUST be a daemon-internal scheduled-update task, NOT `neoth update --self --apply` (CLI): the CLI runs in a separate process and a 2nd WAL writer on the live segment would corrupt the append-only log (single-writer safety). `cli/update.rs::run_self_apply` documents this at the `let _ = repo;` site. Real emit lands with the auto-update scheduler (multi-day).
- **`0x37 CHANNEL_ACK`** RESERVED — SP-5 C-prime deferred until a 2nd production messenger.
- **`daemon::rate_limit::RateLimiter`** is a SEPARATE limiter from `channels::rate_limit` (different purpose: daemon-internal vs per-(channel,sender) inbound). F4-02 only touched the channels one. Possible future consolidation, out of scope.
- **quota.rs `now_unix()` unwrap_or(0)** — verified NOT destructive (roll_daily_counter with now=0 is a self-healing no-op). Don't "fix" it.

---

## 5. SC-01a guard — how to satisfy it when adding a new event type

`tests/wal_emit_sites.rs` fails if a new `pub const EVENT_TYPE_*` in `events.rs`
has zero whole-token references anywhere else under `src/`. To pass: either wire
a real emit/handler site, OR add the const to the `RESERVED` array in that test
WITH a justification. A RESERVED code that later gets wired ALSO fails (stale-
allowlist hygiene) until removed from RESERVED.

---

## 6. Authoritative refs

- Spec: `PLAN/00_DESIGN_v1.1_FINAL.md` + `SPEC_*.md` are authoritative (NOT `v1.0_FINAL` despite the name — see [[neoth-design-v11-is-norm]]).
- Backlog/checkboxes: `PLAN/PROGRESS_v1_0.md` (update in the SAME turn an item ships — hard rule [[neoth-progress-md-update-rule]]).
- Road map: `PLAN/ROAD_TO_1_0.md`.
- Public release safety: exclude `QUELLEN/` + `RECON/` + `SRC/target/` (see [[neoth-public-release-safety]]).
