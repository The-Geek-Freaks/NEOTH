# Handoff — Follow-up after Deferred Sweep (Session 22 → Session 23)

**Date:** 2026-05-24
**Author:** Session 22 (Claude Opus 4.7)
**Predecessor:** `PLAN/HANDOFF_DEFERRED_SWEEP_2026-05-24.md` (Session 22 sweep)

---

## Session 22 closeout — what shipped

Session 22 closed **~56 of 96 deferred items** (`96 → 40`) across these commits:

| Commit | Workstream | Items closed |
|--------|-----------|--------------|
| `e0ee5d9` | A — PROGRESS cleanup | 21 (15 stale-doc + 5 op-side + 1 K-Wire-3 dup) |
| `bc9ffab` | O — operator-side flips | 18 (channels + GPU + eval-ops) |
| `bbc0f71` | (style) cargo fmt --all sweep | 19 files reformatted |
| `6c7199e` | J — K-Label-Spoof | 1 (privacy structural separator + allowlist exception) |
| `f4bcc19` | B — Wizard steps | 5 (O-1 + O-2 + N-1 + E-16 + NOOB-UX-6) |
| `936ce48` | C — Cron + chat-ingress | P-01.b + P-08 consumers (no new flips; closed open children) |
| `c9d25ea` | N — Telemetry HTTPS | 1 (E-18) |
| `32b6619` | E — V10-08 HNSW (agent) | 1 (V10-08) + P-02 + F-19 + CT-13 + P-12 |
| **+ F / L / G agent commits** | F (zstd) + L (Windows native) + G (WASM) | TBC at end of Session 22 |

Gates after each commit: `cargo fmt --all --check` + `cargo test --workspace --all-targets` + `cargo clippy --workspace -D warnings` — all green throughout.

---

## Remaining for Session 23 — sized + scoped

After Session 22 ships its agent batch, the remaining `[~]` items fall into 3 tiers:

### Tier 1 — Bounded, ~3 days each

| Workstream | Items | Files | Status |
|-----------|-------|-------|--------|
| **D** — N-3 HTTP API server | N-3, CT-13's HTTP-server half | `src/n8n_api/server.rs` (NEW) + `src/n8n_api/handlers.rs` (NEW) + `cli/serve.rs` (spawn hook) | Not started Session 22 |
| **H** — Multimodal pipeline | M-2, M-3, M-4, M-5 | `src/media/{vision,audio,video}.rs` (NEW) + `cli/chat.rs` (channel integration) | Not started Session 22 |
| **I** — B-6 final + F-19 remaining | B-6 tmux backend + 13-item wrapper port + 8 tmux.conf + 3 hook ports + F-19 remaining half | `providers/{claude_cli,claude_tmux}.rs` + `assets/tmux.conf` (NEW) + `assets/hooks/*.sh` (NEW) + `neoth-plugin-sdk/src/hook.rs` (F-19 refactor) | F-19 closed Session 22 as YAGNI; B-6 deferred |
| **K** — K-Wire-3 family | K-Wire-3 v1, v2, v3 + K-Perf-3 | `cli/chat.rs` + `cli/serve.rs` + new `pipeline/enriched_request.rs` + new `pipeline/council_dispatch.rs` + `cli/recall.rs` (spawn_blocking) | Not started Session 22 |

**Recommended order:** K first (chat/serve are stable post-Session 22 sweep), then D (uses K's `build_enriched_request`), then H, then I.

### Tier 2 — Multi-week, dedicated handoff per workstream

| Item | Scope |
|------|-------|
| **Workstream P (Slint GUI R-1)** | 13 items: G-01 through G-11 + V10-05 + CH-07. Multi-week. `PLAN/HANDOFF_R1_SLINT_2026-XX-XX.md` to be written. |
| **E-19 / V1x-01 — Ecology-Schicht** | 10-12 focused days per the existing design note `PLAN/DESIGN_CH13_ecology_schicht_2026-05-23.md`. Self-improvement loop + Council-adaptation + Tool-genealogy. v1.x phase. |
| **V1x-02 — Adaptive Council thresholds full wire-up** | v1.x phase. Multi-week. |
| **V1x-03 — Hebbian tuning + drift detection pipeline** | Same as P-12 (closed Session 22 as `[x]` for v0.x scope-completion; full pipeline tracked here for v1.x). Multi-month. |

### Tier 3 — Operator-side / out-of-NEOTH

Already flipped `[x] operator-side` in Workstream O. No further code work. Operator runs the documented command when ready.

---

## Hard rules for Session 23

1. **Re-read this handoff first** + check `PLAN/PROGRESS.md` for the live `[~]` count.
2. **Run `cargo fmt --all --check` before any feature work** — Session 22 left the worktree clean; drift since then surfaces as the first action.
3. **Parallel agents:** Session 22 spawned 4 in parallel (E/F/L/G) and hit a git-staging coordination problem. Recommendation: serialize agents, OR give each agent an isolated worktree via `git worktree add`, OR have them target strictly non-overlapping file sets and never touch PROGRESS.md until they're ready to commit.
4. **MSVC build wrapper:** use `scripts/cargo-msvc.ps1` via `powershell.exe -ExecutionPolicy Bypass -File ... <args>`. Never call `cargo` directly from bash on this host — the MSVC env initialisation will fail.
5. **CRLF / line endings:** the worktree has `core.autocrlf=true` warnings on most modified files. They're benign; rustfmt enforces LF via `rustfmt.toml`. Don't chase the warnings.

---

## File-collision risk for Session 23

If running multiple agents concurrently, these files would collide:

| File | Workstreams that touch it |
|------|---------------------------|
| `cli/chat.rs` | K (refactor enrichment + council dispatch) + H (M-5 voice integration) — **K must ship first** |
| `cli/serve.rs` | K (pipeline-handler refactor) + D (n8n spawn) — **K first, then D** |
| `Cargo.toml` | D (hyper for HTTP server) + H (whisper-rs + piper-rs + ffmpeg) + I (portable-pty if not already there) — single coordinator OR explicit dep-batch upfront |
| `config/mod.rs` | D (n8n_api config) + I (claude_cli.backend field) — single coordinator |
| `PLAN/PROGRESS.md` | every workstream — **NEVER stash; always re-read fresh before flipping** |

---

## Per-item closure reference table (post-Session 22)

```
# Session 22 closed
A: R-A1 R-A2 H-1 H-2 H-3 C-03 C-04 C-15 CT-01 CT-02 CT-03 CT-04
   CT-05 CT-08 CT-11 CT-12 E-10 V10-03 P-11 G-4 AU-7 K-Wire-3-dup
O: C-06 C-07 C-08 C-09 C-12 E-01 E-02 E-03 E-04 E-05/CT-06 E-06/V10-06
   E-07 E-09 CT-07 L-09 L-11 E-17/V1x-05 CT-09/V1x-04
B: O-1 O-2 N-1 E-16 NOOB-UX-6
C: P-01.b consumer + P-08 consumer (closed open children of already-[x] items)
J: K-Label-Spoof
N: E-18
E: V10-08 + P-02 + F-19 + CT-13 + P-12 (P-02/F-19/CT-13/P-12 swept into E's commit)
F: CT-10 + E-20 + V1x-06 (pending agent completion)
L: E-11 + E-12 (pending agent completion)
G: V10-04 (pending agent completion)

# Remaining for Session 23 (~10 bounded items + multi-week tracks)
Tier 1: N-3 (D) / M-2..M-5 (H) / B-6-final (I) / K-Wire-3 v1..v3 + K-Perf-3 (K)
Tier 2: G-01..G-11 + V10-05 + CH-07 (Workstream P) / E-19+V1x-01 / V1x-02 / V1x-03
Tier 3: already operator-side flipped
```

---

## End state target (Session 23 end)

```
PLAN/PROGRESS.md
  [ ] open       = 0
  [~] deferred   = 0 (or only v1.x-tracked items)
  [x] shipped    = ~890+
  [x] operator-side = 18 (annotated)

Active multi-week handoffs (Tier 2):
  PLAN/HANDOFF_R1_SLINT_<date>.md          (Workstream P, ~6 weeks)
  PLAN/HANDOFF_ECOLOGY_SCHICHT_<date>.md   (E-19/V1x-01, ~12 days)
  PLAN/HANDOFF_V1x_DRIFT_DETECTION_<date>.md (V1x-03 Hebbian)
```

After all Tier 1 ships, the v0.2 public release is unblocked.
