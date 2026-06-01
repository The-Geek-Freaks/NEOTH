# Handoff — Session 23 (execution-ready)

**Date:** 2026-05-24
**Predecessor:** Session 22 closed 88/96 deferred items (91.6%). See
`PLAN/HANDOFF_DEFERRED_SWEEP_2026-05-24.md` for the original sweep
plan, `PLAN/HANDOFF_FOLLOWUP_SESSION23.md` for the summary.

This handoff **supersedes** the summary with executable pickup
instructions: exact file paths, code anchors, recommended order,
per-workstream test target, lessons learned from Session 22's
parallel-agent coordination experience.

---

## State at session start

```
[ ] open      = 0
[~] deferred  = 8
[x] shipped   = ~960
```

The 8 remaining items map to **4 real multi-day workstreams**:

| Workstream | Items | Estimate | Risk |
|-----------|-------|----------|------|
| **K** — K-Wire-3 main (`build_enriched_request` extract) | 1 line | 3-5d | High — touches 200+ LOC across `cli/chat.rs` + `cli/serve.rs` |
| **D** — N-3 hyper server (6 endpoints) | 1 line | 3-4d | Med — primitives shipped, hyper task + handlers are bounded |
| **H** — M-2..M-5 multimodal | 4 lines | 4d | High — 3 new heavy deps (candle, whisper-rs, ffmpeg subprocess) |
| **I** — B-6 final 4 sub-items | 2 lines | 4d | Med — primitives shipped; 13-item wrapper port + tmux.conf + 3 hook ports |

---

## Hard rules (carry-over from Session 22)

1. **Cargo wrapper:** `powershell.exe -ExecutionPolicy Bypass -File scripts\cargo-msvc.ps1 <args>` — wrap via temp `.ps1` + `Start-Process` with `-RedirectStandardOutput/-RedirectStandardError`. Direct `cargo` from bash fails on MSVC env init.
2. **Gates after every commit:** `cargo fmt --all` (apply) + `cargo test --workspace --all-targets` → 0 failures + `cargo clippy --workspace --all-targets -- -D warnings` → 0 warnings. Session 22 caught one clippy regression after a parallel agent claimed gates green; verify post-merge.
3. **Same-turn PROGRESS flip:** every code commit pairs with the `[~]` → `[x]` flip in the same commit. Stale doc lines cost Session 22 time.
4. **CRLF warnings benign:** git autocrlf shows warnings on every modified file; rustfmt enforces LF via `rustfmt.toml`. Ignore.
5. **`SendUserMessage` is forbidden** per global CLAUDE.md. Always reply in plain chat.

---

## Lessons from Session 22 parallel agents — READ BEFORE SPAWNING

Session 22 spawned 4 background agents (E + F + L + G) in parallel.
Three coordination problems surfaced:

1. **PROGRESS.md is shared** — the handoff Files-Touched Map missed it.
   Every workstream flips its own item; concurrent agents race on the
   same file. Mitigation: each agent flips ONLY its own item ID via
   `Edit` with the exact existing line as `old_string` — line offsets
   may have shifted by the time the agent gets there, so use the
   line CONTENT not the line NUMBER.

2. **Stash races** — one agent did `git stash` to clean its tree before
   committing; this swept ANOTHER agent's mid-flight work + my
   uncommitted P-02 changes into the stash. When the stash popped, the
   first agent's commit accidentally bundled the second agent's files
   (E's commit included my P-02 + L's `win_native.rs`).
   Mitigation: agents MUST stage with explicit file paths
   (`git add path1 path2`) — never `git add -A` or `git add .`.
   And — never `git stash` from an agent task.

3. **Cargo.lock contention** — agents adding deps all modified
   `Cargo.lock`. The serial-commit-with-explicit-files approach
   handles this safely.

**Recommendation for Session 23:** if parallelism is wanted, give each
agent an isolated `git worktree`. Otherwise run agents serially.

---

## Recommended order: K → D → H → I

Rationale:

- **K first** — only refactor (no new deps). The refactored helper
  becomes a primitive D + H consume. Risk of merging K LAST after D/H
  ship: each one independently builds its own enrichment composition,
  making the unify-later refactor twice as painful.
- **D second** — primitives shipped, just needs hyper task. D's
  `/provider/call` handler benefits from K's `build_enriched_request`.
- **H third** — independent of K + D. Heavy deps but isolated files.
- **I last** — most chat.rs surface contention if it tries to alter
  the provider call site, which K just refactored.

---

## Workstream K — `build_enriched_request` extract (1 item, ~3-5d)

### Goal

Factor the enrichment composition (prompt + operator_md + skills +
modes + MCP + profile_block + code_map_block + system_prompt layering)
into a single `pipeline::build_enriched_request` helper. Both
`cli/chat.rs::run_chat_with` and
`cli/serve.rs::build_pipeline_handler` call it.

### Files

| File | Touch |
|------|-------|
| `SRC/neothd/src/pipeline/mod.rs` | NEW (declares `pub mod enriched_request;`) |
| `SRC/neothd/src/pipeline/enriched_request.rs` | NEW (~200 LOC helper) |
| `SRC/neothd/src/lib.rs` | `pub mod pipeline;` declaration |
| `SRC/neothd/src/cli/chat.rs` | Replace ~150-line inline composition with `pipeline::build_enriched_request(...)` call |
| `SRC/neothd/src/cli/serve.rs` | Same — replace channel-side composition |

### Code anchors

- `cli/chat.rs:184-380` — operator_md / skills / modes / MCP / system_prompt layering. Read these in order to understand the current composition.
- `cli/chat.rs:1047` — `profile_block_for_callosum` consumer.
- `cli/chat.rs:107` — `resolve_prompt(&args)` is the prompt entry point.
- `cli/serve.rs:1344` — `build_pipeline_handler` is the channel-side equivalent.

### Helper signature (proposed)

```rust
pub struct EnrichmentInputs<'a> {
    pub prompt: &'a str,
    pub operator_id: Option<&'a str>,
    pub home: &'a Path,
    pub cwd: &'a Path,
    pub config: &'a FreedomConfig,
    pub explicit_system: Option<&'a str>,
    pub mode_hit: Option<&'a ResolvedMode>,
    pub skill_match: Option<&'a SkillMatch>,
    pub profile_block: Option<&'a str>,
    pub code_map_block: Option<&'a str>,
    pub mcp_servers_enabled: bool,
}

pub struct EnrichedRequest {
    pub prompt: String,
    pub system: Option<String>,
    pub used_skill_id: Option<String>,
}

pub fn build_enriched_request(inputs: EnrichmentInputs<'_>) -> EnrichedRequest;
```

### Tests target ≥10

- Pure prompt (no operator_md, no skills, no MCP) → system=None.
- + operator_md → system contains operator-readable block.
- + skill match → system_prompt layered correctly.
- + mode_hit → system_prompt_delta merged.
- + MCP → system carries MCP block.
- Profile block + code_map block compose at the right layer.
- Repo context block layers above operator_md.
- Empty `explicit_system` is no-op.
- Snapshot test: known inputs → exact serialised system string (drift guard).

### Commit message template

```
refactor(pipeline): Workstream K — build_enriched_request shared helper

Extracts the 200-line enrichment composition (operator_md + skills +
modes + MCP + profile + code_map + system layering) from cli/chat.rs
+ cli/serve.rs into a single pipeline::build_enriched_request helper.
Both call sites now call the helper; channel-side reaches CLI parity
on every composition step.

Closes K-Wire-3 main (the build_enriched_request extract). v1/v2/v3
shipped Session 6 (2026-05-17) per prior PROGRESS closeouts.

Tests: ≥10 new pipeline::enriched_request tests + existing chat/serve
tests unchanged (behaviour-preserving).

Gates: fmt + test + clippy all green.
Refs: PLAN/HANDOFF_SESSION23_2026-05-24.md Workstream K.
```

---

## Workstream D — N-3 hyper HTTP API server (1 item, ~3-4d)

### Goal

Real hyper server task consuming the primitives shipped Session 21 at
`src/n8n_api.rs`. 6 endpoints + bearer auth + autonomy/consent gate +
WAL audit per request + loopback enforcement + `cli/serve.rs` spawn.

### Files

| File | Touch |
|------|-------|
| `SRC/neothd/src/n8n_api.rs` → `n8n_api/mod.rs` | Rename + add `pub mod server; pub mod handlers;` |
| `SRC/neothd/src/n8n_api/server.rs` | NEW — hyper task + auth middleware + loopback gate |
| `SRC/neothd/src/n8n_api/handlers.rs` | NEW — 6 endpoint handlers |
| `SRC/neothd/src/config/mod.rs` | Add `n8n_api: N8nApiConfig` field |
| `SRC/neothd/src/cli/serve.rs` | Spawn `n8n_api::server::spawn_server` at daemon boot when `config.n8n_api.enabled` |
| `SRC/neothd/tests/no_outbound_network.rs` | Allowlist `src/n8n_api/` — incoming HTTP, but hyper internals may trip the lint |

### Endpoint matrix

| Path | Method | Handler reuses |
|------|--------|----------------|
| `/api/health` | GET | trivial — uptime + version |
| `/api/recall` | POST | `cli::recall::recall_one` |
| `/api/provider/call` | POST | `providers::from_config(config)` + `Provider::complete` |
| `/api/channel/send` | POST | `Channel::send_text` |
| `/api/stats` | GET | reads `views.db` |
| `/api/memory/save` | POST | `memory::store::insert` |

### Tests target ≥20

- Per endpoint: 200 happy path + 401 bad token + 403 consent-missing + 404 unknown method + 405 wrong verb.
- Loopback-only enforcement (request from 192.168.x.x → 403 NonLoopback).
- WAL 0x39 frame written per request.
- `record_last_active` called per request (Workstream C hook).

### Commit message template

```
feat(n8n_api): Workstream D — N-3 hyper HTTP API server impl

Closes N-3 (the hyper server task + handlers). Builds on the Session
21 primitives. 6 endpoints (health / recall / provider/call /
channel/send / stats / memory/save) behind bearer auth + autonomy +
consent + loopback-only enforcement. WAL 0x39 audit per request.

Cargo: no new deps (hyper already pulled in transitively via reqwest).

Tests: ≥20 across endpoint matrix + loopback + WAL audit.
Gates: fmt + test + clippy all green.
Refs: PLAN/HANDOFF_SESSION23_2026-05-24.md Workstream D.
```

---

## Workstream H — M-2..M-5 Multimodal pipeline (4 items, ~4d)

### Goal

Vision + audio + video extraction so channels can ingest images, voice
messages, and videos through NEOTH's existing inbound pipeline.

### Files

| File | Touch |
|------|-------|
| `SRC/neothd/src/media/vision.rs` | NEW — candle CLIP (feature-gated) + provider-vision fallback |
| `SRC/neothd/src/media/audio.rs` | NEW — whisper-rs transcribe + piper-rs TTS |
| `SRC/neothd/src/media/video.rs` | NEW — ffmpeg subprocess (thumbnail + audio extract) |
| `SRC/neothd/src/media/mod.rs` | Wire 3 new modules |
| `SRC/neothd/src/cli/chat.rs` | M-5 — channel adapter integration: voice → audio.rs → chat |
| `SRC/neothd/Cargo.toml` | `candle-core` (feature `vision`), `whisper-rs`, `piper-rs`, no ffmpeg (subprocess) |

### Per-day plan

| Day | Item | Files |
|-----|------|-------|
| 1 | M-2 vision | `media/vision.rs` + Cargo (candle feature) |
| 2 | M-3 audio | `media/audio.rs` + Cargo (whisper-rs + piper-rs) |
| 3 | M-4 video | `media/video.rs` (ffmpeg subprocess, no Cargo dep) |
| 4 | M-5 channel | `cli/chat.rs` channel integration + test sample bundling under `assets/test/` |

### Tests target per day ≥4

- vision: image-bytes round-trip (mock fallback; live CLIP gated on feature flag).
- audio: 1-second test WAV → transcript (sample under `assets/test/`).
- video: synthetic mp4 → thumbnail + audio extract smoke.
- chat integration: PipelineHandler receives audio attachment → audio::transcribe → prompt routing.

### Commit messages (4 separate commits)

```
feat(media): Workstream H Day 1 — M-2 vision.rs (candle CLIP + fallback)
feat(media): Workstream H Day 2 — M-3 audio.rs (whisper-rs + piper-rs)
feat(media): Workstream H Day 3 — M-4 video.rs (ffmpeg subprocess)
feat(media+chat): Workstream H Day 4 — M-5 channel adapter integration
```

---

## Workstream I — B-6 final 4 sub-items (2 items, ~4d)

### Goal

Close the 4 remaining B-6 sub-items per Session 5 closeout note at
`PLAN/PROGRESS.md:177`:
1. ClaudeCliAdapter 2-mode backend (Subprocess | Tmux pool)
2. `freedom.yaml::claude_cli.backend` + `tmux.session_scope` +
   `compaction_rotate_after` + `idle_ttl_secs` fields
3. 13-item wrapper-port surface (PTY stealth via portable-pty, env
   scrub, mandatory env vars, session UUID validation, --resume strip
   on dead JSONL, --verbose for stream-json, opusplan→opus[1m],
   4-class retry, ANSI-strip, --append-system-prompt conflict merge)
4. 8 tmux.conf settings + 3 hook ports (stuck-cleaner,
   provider-cooldown, error-pattern effort-override) under
   `assets/tmux.conf` + `assets/hooks/*.sh`

### Files

| File | Touch |
|------|-------|
| `SRC/neothd/src/providers/claude_cli.rs` | ClaudeBackend enum + mode dispatch |
| `SRC/neothd/src/providers/claude_tmux.rs` | 13-item wrapper port (each in own pure-fn helper) |
| `SRC/neothd/src/config/mod.rs` | `claude_cli.backend` + `tmux.session_scope` + `compaction_rotate_after` + `idle_ttl_secs` |
| `SRC/neothd/Cargo.toml` | `portable-pty = "0.8"` |
| `SRC/neothd/assets/tmux.conf` | NEW — 8 settings drift-guarded |
| `SRC/neothd/assets/hooks/stuck_cleaner.sh` | NEW |
| `SRC/neothd/assets/hooks/provider_cooldown.sh` | NEW |
| `SRC/neothd/assets/hooks/error_pattern_effort_override.sh` | NEW |

### Per-day plan

| Day | Items |
|-----|-------|
| 1 | Sub-item 1 + 2: ClaudeCliAdapter 2-mode backend + config fields |
| 2 | Sub-item 3 first half: PTY stealth + env scrub + UUID validation + --resume strip |
| 3 | Sub-item 3 second half: --verbose + opusplan + 4-class retry + ANSI-strip + --append-system-prompt merge |
| 4 | Sub-item 4: tmux.conf + 3 hook ports + integration tests |

### Tests target per day ≥6

### Commit messages

```
feat(providers): Workstream I Day 1 — B-6 ClaudeCliAdapter 2-mode + config
feat(providers): Workstream I Day 2 — B-6 wrapper port half 1 (PTY/env/UUID)
feat(providers): Workstream I Day 3 — B-6 wrapper port half 2 (retry/ANSI/prompt)
feat(assets): Workstream I Day 4 — B-6 tmux.conf + 3 hook ports
```

---

## Final cleanup after all 4 workstreams

When Workstreams K + D + H + I all land:

1. **Verify deferred count = 0** via `grep -c "^- \[~\]" PLAN/PROGRESS.md`.
2. **Update `PLAN/PROGRESS.md` summary header** (search for "deferred" near top of file).
3. **Run final gates:** `cargo fmt --all --check` + `cargo test --workspace --all-targets` + `cargo clippy --workspace --all-targets -- -D warnings`.
4. **Commit doc-update:** `docs(progress): all v0.x deferred items shipped — ready for v0.2 release`.
5. **Push** + tag if operator confirms: `git tag v0.2.0 && git push origin v0.2.0`.

After v0.2 release, the v1.x track opens with handoffs already written:
- `PLAN/HANDOFF_R1_SLINT_2026-05-24.md` (Workstream P GUI, ~6 weeks)
- `PLAN/HANDOFF_ECOLOGY_SCHICHT_2026-05-24.md` (E-19/V1x-01, ~12 days)
- `PLAN/HANDOFF_V1x_DRIFT_DETECTION_2026-05-24.md` (V1x-03 Hebbian)

---

## Session-start checklist for Session 23

```
[ ] Read PLAN/HANDOFF_SESSION23_2026-05-24.md (this file)
[ ] git pull --rebase origin main + verify clean tree
[ ] Run `cargo test --workspace --lib` once to confirm 4088+ tests green
[ ] Pick workstream from the K → D → H → I order
[ ] Open ONLY the files listed in that workstream's table
[ ] Code → tests → fmt → clippy → PROGRESS flip → commit
[ ] Don't touch any file from another workstream
[ ] Push after each workstream's commit
```

End-state target: `[~] deferred = 0`, ready for v0.2 release.
