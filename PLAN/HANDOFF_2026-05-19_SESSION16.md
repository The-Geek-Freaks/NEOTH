# NEOTH — Session 16 Handoff (2026-05-19)

> Status: Session 16 closed clean. 8 picks shipped on top of Session 15
> (Picks 32-37 + follow-ups #34b + #37b). Cross-workspace tests
> **~2220 grün** (+34 von Session 15 baseline 2186). clippy
> `-D warnings` + fmt clean durchgehend.
>
> Builds on top of `PLAN/HANDOFF_2026-05-19.md` (Session 15) — every
> hard rule there still applies. This file documents only the delta.

## 1. Session 16 deltas (what changed since Session 15)

**6 fresh Picks shipped:**

| # | Pick | LOC | Tests added |
|---|------|-----|-------------|
| #32 | GUI Settings panel — 8-tab layout (Chat / Hemispheres / Channels / Skills / Plugins / Memory / Privacy / Config) | ~290 | 0 (GUI 8 unchanged) |
| #33 | GUI Chat surface (post-onboarding primary view, mined `QUELLEN/openhuman`) | ~340 | 0 |
| #34 | V10-04 wasmtime hostcalls (`build_linker` + 4 hostcalls under `neoth.*` namespace) | ~270 | +6 hostcalls / +12 with feature |
| #35 | V10-06 Sqlite + FaissFlat readers (`neoth-migrate`); Lance + Git deferred per C-dep rationale | ~200 | +6 (11 → 17) |
| #36 | V10-08 `vector_index` trait foundation (BruteForce + indexed stub) | ~165 | +6 |
| #37 | Discord WSS scaffold extension (envelope / identify / resume / seq tracker) | ~150 | +9 (5 → 14) |

**2 follow-up increments:**

| # | Pick | LOC | Tests added |
|---|------|-----|-------------|
| #34b | 4 plugin WAL event codes (`0xC2 PLUGIN_LOADED`, `0xC3 PLUGIN_REJECTED`, `0xC4 PLUGIN_HOSTCALL`, `0xC5 PLUGIN_FUEL_EXHAUSTED`) + band check + cli/events registry rows | ~50 | +2 |
| #37b | `build_heartbeat_payload` + `reconnect_backoff_secs` + `GatewayAction` enum + `classify_envelope` pure fn | ~120 | +11 |

**Tests cross-workspace evolution:**
- Session 15 end: ~2186 grün
- Session 16 after Picks 32-37: ~2207 grün (+21)
- Session 16 final (after #34b + #37b): **~2220 grün** (+34 total)

## 2. Current state (Session 16 end)

- **Tests**: `2177 + 7 + 1 + 17 + 10 + 8 = ~2220 cross-workspace grün`.
  clippy `-D warnings` + fmt clean.
- **Workspace**: 4 crates — `neothd` (daemon + CLI), `neoth-plugin-sdk`
  (alpha publish-ready), `neothd-gui` (Slint frontend), `neoth-migrate`
  (Phase-3 cutover, Sqlite + FaissFlat + Markdown + JSON readers).
- **Build wrapper**: `C:/Temp/build-neoth.cmd` — same as Session 15.
- **wasmtime feature**: `wasm-plugin-host` — opt-in for source builds,
  default-ON for shipped release binaries per memory rule.

## 3. Architectural delta (modules added Session 16)

```
SRC/neothd-gui/ui/
├── settings.slint              NEW — 8-tab post-onboarding view
├── chat.slint                  NEW — Composer + Bubble + sidebar
└── components.slint            extended — TabButton, PanelHeader, PendingPanel

SRC/neothd/src/wasm_plugin/
└── hostcalls.rs                NEW — Linker + 4 hostcalls (feature-gated)

SRC/neoth-migrate/src/
└── readers.rs                  extended — scan_sqlite + scan_faiss_flat

SRC/neothd/src/memory/
└── vector_index.rs             NEW — VectorIndex trait + IndexBackend enum

SRC/neothd/src/channels/
└── discord_gateway.rs          extended — Envelope + Identify + Resume + seq tracker + classify_envelope + heartbeat builder

SRC/neothd/src/wal/
└── events.rs                   extended — 4 plugin event codes (0xC2-0xC5)
```

## 4. Picks 33-37 follow-ups (what next session ships)

Per Alex's "alles davon nacheinander" — every follow-up is its own
focused sprint with clear scope. Recommended order:

### Pick #34 voll — wasmtime Linker actual wiring (~200 LOC)

**Today**: `hostcalls::build_linker` returns Linker mit 4 hostcalls,
but `neoth.emit_event` + `neoth.recall_top` log to `tracing` instead
of doing real work.

**Next**: wire `emit_event` to the WAL writer using the new 0xC4
PLUGIN_HOSTCALL event code (Pick #34b shipped the constant). Wire
`recall_top` to a views.db connection. Plug discovered plugins into
the existing `hooks::HookStage` dispatcher so they fire at the
right pipeline points. Emit `0xC2 PLUGIN_LOADED` on successful
compile, `0xC3 PLUGIN_REJECTED` on failure, `0xC5 PLUGIN_FUEL_EXHAUSTED`
on trap.

**No Chorus-gremium needed** — surface is locked, just wire it.

### Pick #37 voll — Discord WSS live receive (~250 LOC)

**Today**: pure functions for envelope parse / heartbeat build /
classify / backoff calc + seq tracker (Pick #37 + #37b shipped).

**Next**: `connect_async` against `GATEWAY_WSS_URL` (tokio-tungstenite
already in deps), spawn heartbeat task ticking `heartbeat_interval`
ms from HELLO, drive the receive loop via `classify_envelope` →
dispatch into `InboundMessage`. Reconnect-with-backoff using the
shipped `reconnect_backoff_secs`. Use `slack_socket.rs` as reference
template — same shape, different opcodes.

**No Chorus-gremium needed** — `classify_envelope` already pinned
the state-machine decisions.

### Pick #33 voll — Rust-side chat store + streaming (~300 LOC)

**Today**: GUI ChatView renders `chat-messages: [ChatMessage]` but
Rust side has no message store + no streaming pipeline.

**Next**: `neothd-gui/src/chat_store.rs` — Vec<ChatMessage> backed
state with append-on-send + append-on-stream-chunk semantics. Wire
`chat-send-clicked` callback to dispatch via existing
`cli::chat::run_chat_with` (might need lib refactor of neothd to
expose, OR subprocess via `neoth chat <msg>` since gui doesn't dep
on neothd). Streaming: Slint Property updates per chunk per handoff
§7 strategy. Slash autocomplete dropdown content from
`slash::built_in_commands()` + `slash::load_all()`.

**Chorus-gremium recommended** für: subprocess-vs-lib-refactor
decision (the gui crate doesn't depend on neothd today; pulling
neothd in as a lib means restructuring the main bin into bin+lib).

### Pick #36 voll — sqlite-vec vs hnsw_rs swap-in (~150 LOC)

**Today**: VectorIndex trait + BruteForceIndex marker + IndexedVectorIndex
stub. `active_backend()` returns `BruteForce`.

**Next**: CHORUS-GREMIUM REQUIRED FIRST. Decision: sqlite-vec
(C-dep, sqlite-extension-loaded, requires forked rusqlite OR
custom static link, violates NEOTH self-contained rule) vs hnsw_rs
(pure-Rust HNSW, sidecar index file, needs rebuild trigger logic).
After decision: add dep, implement `IndexedVectorIndex::find_top_k`,
add index rebuild trigger (on upsert? scheduled? operator-fired?),
load full corpus at daemon start vs lazy. Wire freedom.yaml
`memory.vector_index.backend` toggle.

**Chorus prompt template**:
```
artifact: "NEOTH needs to replace O(N) brute-force cosine search in
memory/embeddings.rs::find_similar with an indexed implementation.
50k vectors is the documented ceiling; past that the warn-once
sentinel fires. Two options: sqlite-vec (C extension, must bundle
rusqlite + statically link, violates self-contained rule) or
hnsw_rs (pure-Rust HNSW, sidecar file at ~/.neoth/hnsw.idx).
Hard rule: NEOTH stays self-contained (memory:
neoth_hard_rule_self_contained). Index rebuild strategy: on every
upsert (write-heavy) vs scheduled (consistency lag) vs operator-fired
(manual). Decision needed: pick backend + rebuild strategy."

work: "stress-test this design / find holes"
```

### Pick #35 voll — LanceArrow + GitTree readers + apply path (~600 LOC)

**Today**: Markdown + JSON + Sqlite + FaissFlat readers shipped.
LanceArrow + GitTree explicit deferred (C-deps).

**Next**: add `lance` + `git2` to `neoth-migrate/Cargo.toml` behind
optional features (the migrator is a separate bin; it CAN carry
C-deps because it's not the daemon). Implement `scan_lance_arrow`
+ `scan_git_tree`. Then add `apply` subcommand that takes the
dry-run report + emits WAL frames for every store entry via
`writer.append`. Drift guard test compares `neoth-migrate::STORES`
against `neothd::migrate::JARVIS_STORES`.

**Chorus-gremium recommended** für: reader-by-reader vs streaming-all-at-once
(memory budget); failure handling (abort vs skip-and-log per store);
resume support (checkpoint + restart vs single-shot).

## 5. Memory rules in effect (Session 15 + 16)

5 hard rules in `~/.claude/projects/.../memory/MEMORY.md`:

1. **`neoth-design-v11-is-norm`** — v1.1_FINAL ist die Norm
2. **`neoth-features-default-on-runtime-toggle`** — release default-ON
3. **`neoth-gui-first-screen-and-settings-parity`** — Mode-Selection +
   GUI ↔ CLI parity + mine QUELLEN
4. **`neoth-slash-commands-and-settings-parity`** — slash menu contract
5. (Pre-existing: tmux mandatory, build locality, PROGRESS update,
   v0.1 ship status, etc.)

## 6. v1.0 GA Position nach Session 16

| V10-blocker | Status |
|---|---|
| V10-01 OPEN_DECISIONS | ✅ recheck-closed |
| V10-02 Cosign | ✅ recheck-closed |
| V10-03 Plugin SDK publish | 🟡 publish-ready (`cargo publish` = operator action) |
| V10-04 WASM plugin host | 🟡🟡 engine + manifest + discovery + hostcalls + WAL codes shipped — Linker wiring + dispatch verbleibend (~150 LOC) |
| V10-05 R-1 Slint GUI | 🟡🟡 Theme + 8 wizard screens + Mode-Selection + Settings 8-tab + Chat surface shipped — Rust chat store + streaming verbleibend (~300 LOC) |
| V10-06 Phase-3 migration | 🟡 4 of 6 readers shipped (Markdown / Json / Sqlite / FaissFlat) — Lance + Git + apply path verbleibend (~600 LOC) |
| V10-07 H3 profile privacy | 🟡 config layer + WARN + classifier shipped — runner caller wiring verbleibend |
| V10-08 HNSW / sqlite-vec | 🟡🟡 telemetry + trait + brute-force + indexed stub shipped — Chorus-gremium decision + impl verbleibend (~150 LOC) |
| V10-09 Multi-platform CI | ✅ recheck-closed |
| V10-10 Security disclosure | ✅ recheck-closed |

**Progress vs Session 15**: V10-04 + V10-05 + V10-06 + V10-08 alle
einen substantial step weiter (🟡 → 🟡🟡 for those with full layers
shipped). 4 V10-blockers closed, 6 with code-foundation across
multiple layers.

## 7. Verify build / test / lint

Same as Session 15 (no changes to wrapper or commands).

```bash
C:/Temp/build-neoth.cmd test                                              # all crates
C:/Temp/build-neoth.cmd clippy --workspace --all-targets -- -D warnings
C:/Temp/build-neoth.cmd fmt --all -- --check
C:/Temp/build-neoth.cmd build -p neothd --features wasm-plugin-host       # opt-in feature build
```

Expected: ~2220 grün, clippy clean, fmt clean.

## 8. Key files added Session 16

- `neothd-gui/ui/settings.slint` — 8-tab post-onboarding view
- `neothd-gui/ui/chat.slint` — Composer + Bubble + sidebar
- `neothd/src/wasm_plugin/hostcalls.rs` — Linker + 4 hostcalls (feature-gated)
- `neothd/src/memory/vector_index.rs` — VectorIndex trait + backends
- `neothd-gui/ui/assets/glyph_cli.svg` + `glyph_gui.svg` (from Session 15 Pick #29 — referenced here for completeness)

Extended Session 16:
- `neothd/src/channels/discord_gateway.rs` — Envelope + Identify +
  Resume + seq tracker + heartbeat + classify + backoff
- `neoth-migrate/src/readers.rs` — Sqlite + FaissFlat
- `neothd/src/wal/events.rs` — 4 plugin event codes
- `neothd/src/cli/events.rs` — REGISTRY rows for plugin events
- `neothd-gui/ui/main.slint` — WizardStep::Settings + WizardStep::Chat
- `neothd-gui/src/main.rs` — on_settings_reload_clicked + on_settings_wizard_rerun_clicked + on_cli_mode_chosen
- `neoth-migrate/Cargo.toml` — rusqlite bundled feature

## 9. Critical operator-facing flows (Session 16 additions)

### 9.1 Slash `/reload` (Pick #31 from Session 15) round-trip

1. Operator types `/reload` in chat.
2. `dispatch_action(ReloadConfig, ...)` writes sentinel-file at `~/.neoth/.reload-requested`.
3. Daemon polling loop (`serve.rs:290`) picks up within 2s.
4. `ReloadController::try_reload()` validates + atomic `ArcSwap`.
5. WAL `0xD0 CONFIG_RELOADED` emitted.

### 9.2 GUI Settings → Reload button (Pick #32 mirror)

1. Operator clicks "Reload config" in Settings → Config tab.
2. `on_settings_reload_clicked` callback fires in `neothd-gui/src/main.rs`.
3. Rust drops sentinel-file at `~/.neoth/.reload-requested`.
4. Same daemon path picks up — GUI ↔ CLI parity holds.

### 9.3 GUI Mode-Selection → Wizard → Chat → Settings flow

1. `neoth-gui` launches with `WizardStep::ModeSelection`.
2. Operator picks GUI → 8-step wizard → Finish.
3. After Finish, lands on `WizardStep::Chat` (primary daily view).
4. ⚙ icon in chat sidebar → `WizardStep::Settings` (8-tab).
5. Settings "Re-run wizard" button resets to ModeSelection.

## 10. Chorus gremium triggers für Session 17

Per Alex's hard rule + handoff §13:

**MUST-FIRE Chorus before starting Pick #36 voll**:
- sqlite-vec vs hnsw_rs decision
- Index rebuild strategy (on-upsert / scheduled / operator-fired)
- Cold-start latency (load full corpus at daemon start?)

**MAY-FIRE Chorus für Pick #33 voll**:
- subprocess-vs-lib-refactor decision (neothd-gui crate doesn't dep
  on neothd today; full chat pipeline integration might need lib
  surface)
- Streaming render strategy (Slint Property updates per chunk vs
  buffer-per-chunk+flush vs incremental render)

**MAY-FIRE Chorus für Pick #35 voll**:
- reader-by-reader vs streaming-all-at-once (memory budget tradeoff)
- failure handling (abort entire migration vs skip-and-log per store)
- resume support (checkpoint + restart vs single-shot only)

## 11. Recommended Session 17 sequence

Per "low-risk first + bigger items later" + Chorus-gremium gating:

1. **Pick #34 voll** — clearest scope, no decisions, ~150 LOC. Wire
   `emit_event` + `recall_top` to actual writers. Foundation for
   plugin dispatch.
2. **Pick #37 voll** — clearest scope, no decisions, ~250 LOC. Live
   WSS dial using `slack_socket` as template. Pure-function classify
   already pinned the state machine.
3. **Pick #33 voll** — Chorus check optional, ~300 LOC. Wire Rust
   chat store + streaming.
4. **Pick #36 voll** — Chorus REQUIRED first. After decision,
   ~150 LOC.
5. **Pick #35 voll** — Chorus optional, ~600 LOC. Last because
   biggest + Phase-3 deliverable (Day-65), not v1.0 GA critical
   path.

After all five: NOOB-UX backlog (5 items per Session 15 PROGRESS) +
Type #13 Phase 3 cleanup.

## 12. Memory + persistent context für Session 17

Auto-memory at `~/.claude/projects/.../memory/MEMORY.md` auto-loads.
No new memory rules added Session 16 — the five from Session 15
cover the slash-commands-and-settings-parity contract and the
GUI ↔ CLI parity contract.

If Session 17 hits an architectural decision NOT in the existing
five rules: add a new memory file under
`~/.claude/projects/.../memory/neoth_<topic>.md` + add a pointer
in MEMORY.md (line under 150 chars).

## 13. Communication template (unchanged from Session 15)

```markdown
**Session N: Pick #X shipped.** <test count> grün, fmt + clippy clean.

## Was geliefert

<3-5 line summary>

## Cumulative status nach N picks

**<count> backlog items closed sequentially.**

## Was als nächstes

<recommended next pick + alternatives>

Continue?
```

German wenn Alex Deutsch schrieb. Direct chat text — NEVER
SendUserMessage (Alex's hard rule from CLAUDE.md).

---

*Last updated: 2026-05-19 Session 16 end (8 picks shipped on top of
Session 15's 31). Tests: ~2220 cross-workspace grün (+34 from
Session 15 baseline 2186). Next session starts with Pick #34 voll
(no Chorus needed, smallest verbleibend).*
