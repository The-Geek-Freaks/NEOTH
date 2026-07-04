# NEOTH — GOLD FINISH LOOP PLAN

**Created:** 2026-07-02 · **Base:** `d9d6c9d0` (= origin/main, verified) · **Owner:** autonomous loop (any model — Fable 5, Opus, Sonnet)

This is the complete, self-contained execution plan to drive `PLAN/ROAD_TO_1_0_GOLD.md` from **68 open + 9 partial = 77 items** to **zero**, plus the error-hunt, research, and release phases that make NEOTH 12/10. A fresh session with NO prior context must be able to run the loop from this file alone.

---

## 0. Mission

1. Every `[ ]` and `[~]` in `PLAN/ROAD_TO_1_0_GOLD.md` resolved: **built fully** (not scaffolded), **wired to a real production caller**, tested, or **closed with a recorded verdict** (skip/operator-decision) — never silently dropped.
2. Adaptations are **deep-analyzed then ported** — read the actual source in `QUELLEN/` / on Jarvis, understand the algorithm, re-implement it natively on NEOTH's Rust/WAL substrate. Never approximate from an item's one-line summary.
3. The loop **finds and fixes its own bugs**: review waves, adversarial verification, unwired-primitive audits are scheduled work, not afterthoughts.
4. CI green on all platforms, release gate (§5 of the tracker) fully `[x]`, signed artifacts, tag `v1.0-gold`.

**Source-of-truth hierarchy:** tracker `PLAN/ROAD_TO_1_0_GOLD.md` > this plan > memory notes. When an item's spec conflicts with current code, **verify-first wins** (grep/read before trusting any line number or "exists" claim — refs drift; ~10 items were closed by commits `01d0b2c4..d9d6c9d0` alone).

---

## 1. Ground truth (verified 2026-07-02)

| Fact | Value |
|---|---|
| HEAD / origin/main | `d9d6c9d0` — identical, clean tree |
| Tracker | `PLAN/ROAD_TO_1_0_GOLD.md`, 1426 lines, 68 `[ ]` + 9 `[~]` + 717 `[x]` |
| **CI on main** | **RED** — run `28449569723`: `ubuntu-24.04/stable` + `ubuntu-24.04/beta` FAILED after 5h (hang). Windows, macOS, all feature-flag builds, gold-smoke: green. Security workflow: green. |
| Build wrappers | `SRC/_check.bat`, `_clippy.bat`, `_test.bat`, `_build.bat`, `_feat.bat`, `_check_feat.bat` — **`SRC/_run.bat` referenced in tracker §1 no longer exists** (tracker drift, fix in B1). All bats hardcode `cd /d C:\Users\Shadow-PC\CascadeProjects\AGENTER\SRC` → **they always build the main checkout, never a worktree**. |
| Worktrees | `AGENTER` (main, THE loop workspace) · `AGENTER-loop` (loop-gold, stale-ok) · `AGENTER-wsg` (Alex's parallel worktree — do not touch) |
| Evidence dirs | `REVIEWS/_gold_audit/research/*.md` (per-feature research) · `REVIEWS/_gold_audit/_jarvis_2026-06-12/*.md` (Jarvis algorithms, file:line) · `REVIEWS/_gold_audit/_alex_repos_2026-06-12/{openhuman,hermes,jarvis_veronica_lowkey,mnemo,odysseus,rscrypto}.md` · `REVIEWS/Neoth 1.0 GOLD - TODO.txt` (59 lines) |
| Vendored sources | `QUELLEN/` (~40 repos: odysseus, openhuman, hermes-webui, goose, mempalace, mnemo, smallcode, superpowers, headroom, LMCache, …) · `QUELLEN/JARVIS_LIVE/` (236 scripts + memory-lancedb-pro + systemd, pulled 2026-06-12 — **stale, re-sync in B16**) · `QUELLEN/DO_NOT_ADOPT.md` (rejection register — append on every skip) |
| Jarvis | `ssh tgf@192.168.178.117` — **key-auth works, no password needed**. Daemon = `openclawd` (systemd `openclaw-gateway`), config/workspace = `~/.openclaw/` (`~/openclaw` is a dead symlink to `/usr/bin/openclaw`). Workspace: `~/.openclaw/workspace/{CLAUDE.md,MEMORY_MATRIX.md,FLOWS.md,knowledge/,hooks/,lib/,bin/}`, cron `~/.openclaw/cron/jobs.json`, skills `~/.openclaw/skills/`. |
| graphify | `SRC/neothd/src/graphify-out/` exists. Query: `cd SRC/neothd/src && py -m graphify query "<q>"` / `explain <node>` / `affected <node>`. Refresh after each batch: `py -m graphify update .` (from `SRC/neothd/src`). |

---

## 2. Session bootstrap (fresh session, any model)

```bash
cd C:/Users/Shadow-PC/CascadeProjects/AGENTER
git fetch origin && git status -sb          # MUST be main, clean. If "behind": git pull --ff-only  (this checkout was found 21 commits behind on 2026-07-02 — always pull first)
git log -3 --oneline                        # orient
```

1. Read this file top to bottom.
2. Read tracker sections `0`–`2` (`PLAN/ROAD_TO_1_0_GOLD.md` L1–120: intro, build recipe, WAL-band + gotcha appendix) and the **Builder's guide** at ~L828–850. These two blocks contain the per-item workflow and every recurring integration pattern (cron/config/WAL/CLI/GUI/memory/provider). Do not re-derive them.
3. Regenerate the open-item list (do NOT trust stale copies):
   ```
   grep -n "^- \[ \]\|^- \[~\]" PLAN/ROAD_TO_1_0_GOLD.md | head -100
   ```
4. Find the current batch: `## LOOP STATE` block at the bottom of this file. Resume there.
5. `chorus status` → if not running and a review-gate is near: `chorus start` (optional; agent reviews suffice when Chorus is down).

**Hard session rules (from real incidents):**
- **NEVER run `cargo fmt`** (destroys hand-formatting repo-wide).
- **NEVER pipe gate commands through `tail`/`head`** — masks exit code. The bats echo `BUILD_EXIT=`/`TEST_EXIT=`/`CLIPPY_EXIT=`; read that token.
- Run bats via `cmd.exe //c "C:\\Users\\Shadow-PC\\CascadeProjects\\AGENTER\\SRC\\_check.bat"` from Git Bash (double slash), or as Bash tool `run_in_background` for long runs. vcvars output must stay UNREDIRECTED (`>nul` breaks cl.exe detection).
- Long builds/tests: `run_in_background: true`, then poll the output file — **no sleep/poll loops in foreground**.
- `neoth init` writes to hardcoded `~/.neoth` — NEVER run it as a smoke test on this box. Use `NEOTH_HOME`-respecting test helpers only.
- Env-var tests race → they already use `crate::test_env::lock`; new env-touching tests must too.
- Multibyte panics: never `&s[..N]` on user/LLM text — `chars().take(N)`.
- Never hold a SQLite/Mutex guard across `.await`; blocking `std::fs` on the async reactor → `spawn_blocking`.
- New WAL event = **5 sites** (const + band-assert + `EVENT_NAME_TABLE` + uniqueness test + emit) — pick a free slot from tracker §2 band table FIRST.
- New CLI command/flag → run the CLI-doc-drift gate (below) or CI fails.
- Discord `sender_id` = snowflake, not username. peeroxide `SecretStream::read` is not cancel-safe (read-to-completion, no `select!`).
- Secrets never in code/commits/logs. `git diff --staged` before every commit.

---

## 3. Build & gate recipe (VERIFIED 2026-07-02)

All bats: vcvars64 + ucrt paths + `cd` to main-checkout `SRC/`, echo `*_EXIT=%ERRORLEVEL%` at the end.

| Gate | Command (from Git Bash) | Pass token |
|---|---|---|
| Type-check | `cmd.exe //c "...AGENTER\\SRC\\_check.bat"` (cargo check -p neothd) | `BUILD_EXIT=0` |
| Clippy (hard gate) | `cmd.exe //c "...AGENTER\\SRC\\_clippy.bat"` (clippy -p neothd --lib --tests -- -D warnings) | `CLIPPY_EXIT=0` |
| Tests | `cmd.exe //c "...AGENTER\\SRC\\_test.bat" <filter>` (cargo test -p neothd --lib, `%*` appended — **pass at most ONE filter token**) | `TEST_EXIT=0` |
| Full build | `cmd.exe //c "...AGENTER\\SRC\\_build.bat"` | `BUILD_EXIT=0` |
| Feature matrix (when touching gated code) | `_feat.bat` / `_check_feat.bat` | exit token |
| CLI-doc drift (after CLI changes) | `_test.bat` with env `NEOTH_REGEN_CLI_DOCS=1`, filter `cli_commands_md_is_up_to_date` — or regenerate + commit `docs/CLI_COMMANDS.md` | `TEST_EXIT=0` |
| GUI (when touching neothd-gui) | `cargo check -p neothd-gui` via a temp bat copy (BIN crate — no `--lib`; os-clipboard: `--features os-clipboard`) | exit token |

**Per-commit gate (minimum):** check + clippy + targeted tests of touched modules.
**Per-batch gate (before push):** clippy + full `cargo test -p neothd --lib` + CLI-doc gate if CLI touched + GUI check if GUI touched.
**Flake protocol:** a test that fails once → rerun the single test exe directly (`cargo test --no-run` once, then run `neothd-<hash>.exe <filter>`); artifact-dependent tests `cli::demo`, `code_map::risk` are known skip-worthy under contention. A genuinely flaky test = a bug: fix root cause (see memory: lock-ordering mutex-first pattern), never `#[ignore]`.
**Known-red guard:** if clippy is already red at session start, the failure predates you — fix it first (loop history shows pushes without `--all-targets` gating leak clippy-RED to main).

---

## 4. Loop protocol (per batch)

```
SELECT   next batch from §5 (or LOOP STATE override)
VERIFY   verify-first every item in the batch against HEAD:
           - grep the named modules/fns — do refs still exist? already shipped?
           - graphify query for structure questions (callers/defs/flow) BEFORE blind grep
           - item already done → flip [x] with evidence note, drop from batch
           - item spec stale → correct the tracker line in the same commit that ships it
RESEARCH deep-read the evidence file(s) for every remaining item (§6). For ports:
           open the REAL source in QUELLEN/<repo>/ at the cited file:line, extract the
           algorithm/prompts/constants EXACTLY. AGPLv3 (odysseus) → re-implement, never paste.
DESIGN   only if the item is genuinely architectural (new subsystem, schema change):
           3-4 parallel senior-dev agents as a panel, synthesize, verify-first the panel
           output (every panel run has ≥1 false premise — check each claim).
BUILD    implement FULLY ([x]-quality: wired to a production caller + tests). Follow the
           Builder's-guide integration patterns (tracker ~L832-841). Batch same-file work
           into ONE edit pass. No placeholders, no TODO stubs, no speculative flags.
GATE     §3 per-commit gates green. Fix everything the gate finds NOW (no deferring
           in-scope roadblocks).
REVIEW   code-reviewer agent (+ rust-reviewer) on the batch diff. Security-relevant
           surface (channels, tokens, exec, network, crypto) → security-reviewer too.
           CRITICAL/HIGH findings: fix immediately. MEDIUM: fix if <30min, else file as
           tracker item (never lose it).
COMMIT   conventional commit per coherent slice; flip tracker [ ]→[x] AND update
           PLAN/PROGRESS_v1_0.md in the SAME commit. git diff --staged first.
PUSH     git push origin main. Then: gh run list --limit 2 → confirm CI triggered.
           CI red → fixing it becomes the immediate next task (never build on red >1 batch).
UPDATE   graphify refresh (py -m graphify update . from SRC/neothd/src) +
           rewrite the ## LOOP STATE block at the bottom of this file (same push or next).
```

**Wave cadence (self-error-hunting is scheduled work):**
- After **every batch**: reviewer pass on the diff (above).
- After **every 3 batches**: ERROR-HUNT WAVE (§7).
- After **every 5 batches** or before any long feature batch: full-suite run + `gh run list` CI confirm + PROGRESS/tracker consistency audit (counts match, no orphaned `[~]`).

**Stuck rule:** 2 failed fix attempts on the same root cause → stop, run an investigation panel (3 agents: repro-minimizer / upstream-source-reader / alternative-hypothesis), then decide. Never burn >90 min blind-looping one bug.

---

## 5. Batch map (ordered; IDs are tracker anchors — grep the ID, line numbers drift)

> Effort key: S<0.5d · M 0.5-2d · L>2d. Items sharing files are batched to minimize rebuild + token cost. Every batch ends with the §4 GATE/REVIEW/COMMIT/PUSH tail.

### B0 — CI GREEN (P0, do first, nothing ships on red)
Ubuntu stable+beta hung 5h on `d9d6c9d0`. Diagnose: `gh run view 28449569723 --log-failed | tail -200` (background; the log is huge — grep for the last test name started before the hang). Prime suspects (all Linux-only, new in the last 21 commits): `media/docling.rs` subprocess tests (60284ce3 fixed "can deadlock/hang" — may be incomplete on Linux), `lsp/` child-reap tests (f0704f66), no-outbound-network guard allowlist (9b48718e), SSE-relay delivery test. Fix root cause, add a per-test timeout guard where a subprocess is involved, push, watch run to green. **Exit: full CI matrix green on main.**

### B1 — Tracker hygiene + dedupe (S, pure-docs commit, big downstream savings)
- Enforce tracker L13 rule (**no `[~]` allowed**): split all 9 `[~]` — shipped part `[x]` with evidence, remainder a new `[ ]` line with concrete rest-spec: `GOLD-ARCH-07` (remaining inline `now`-call sites — count them first), `GOLD-FEAT-03` (self-wiki rest), `GOLD-FEAT-10`+`GOLD-PROG-16` (**merge — same 5 channel adapters tracked twice**; verify which of Discord/Matrix already shipped, keep ONE item listing only missing adapters), `GOLD-PROG-13`/`GOLD-PROG-15` (→ §9 operator-decision records), `GOLD-ADAPT-JV-SEC-01..09` (split 2 shipped / 7 open as individual lines), `GRILL-02`/`GRILL-04` (→ B3).
- Delete duplicate `GOLD-ADAPT-HANDY-02` (appears at ~L678 AND ~L761 — keep the deep-read-panel one).
- Close decided SKIPs as recorded verdicts, not open boxes: `GOLD-ADAPT-CCS-06` (⛔137 CCS bundles) and the agentsview SKIP note (~L1090) → `[x] SKIP — verdict recorded <date>` + `QUELLEN/DO_NOT_ADOPT.md` rows.
- Fix §1 build recipe: `SRC/_run.bat` → the 6 real bats (§3 table). Fix stale `Current HEAD` line. Dedupe the double `PROGRESS_v1_0.md` bullet in §6 appendix.
- Sweep `REVIEWS/Neoth 1.0 GOLD - TODO.txt` (59 lines): confirm every line maps to a tracker item; orphans become new `[ ]` items.
- Cross-check `PLAN/PROGRESS_v1_0.md` against tracker counts; repair drift.

### B2 — Global verify-first sweep (S-M, kills phantom work)
For each of the ~75 remaining items run the cheap existence check (grep module/fn; graphify `explain`). Known overlap candidates to resolve here: `GOLD-ADAPT-JV-PRO-08` vs shipped `GOLD-TASK-07` (`263993ef` capability_evolver + collector cron — PRO-08 is likely ⊂ shipped; flip or write the delta-spec); `GOLD-ADAPT-ODY-12` (UiControl) vs whatever `JV-MODE-04` needs; watchdog pieces of `JV-SEC` vs `daemon/` state at HEAD. Output: corrected worklist + flipped items, committed as `docs(plan): verify-first sweep`.

### B3 — Wiring & unwired-primitive audit (M) — *the "primitives voll einbauen" batch*
- `GOLD-ADAPT-GRILL-02`: give `coding/plan_review.rs::review_plan` its production caller (kanban decompose path or `neoth code` plan step — the evidence file names the intended hook).
- `GOLD-ADAPT-GRILL-04`: production caller for `coding/brainstorm.rs::evaluate_with_rounds`.
- `GOLD-PROG-06`: complete ProactiveChannelSend consumer wiring for cluster task-accept (`cluster/hyperswarm.rs` + `cli/serve.rs`).
- `GOLD-ADAPT-G-02`: full shipped-but-unwired + duplicate-logic sweep. Method: for every `pub fn`/module with 0 non-test callers (graphify `affected` + `cargo +nightly udeps`-style grep; the 2026-06-12 adversarial list: plan_writer, cluster foreign-event ingest, plugin WAL events — re-verify each), either wire it to its intended consumer or delete it (Rule of Three; replace-don't-deprecate). Findings that are >30min each → new tracker items in the right workstream, then burn them in the matching batch.

### B4 — Memory/context core (M-L, one subsystem, one push)
`GOLD-ADAPT-SPEAKR-01` (5-layer prompt composition → `memory/summarize_prompt.rs`) · `GOLD-ADAPT-SPEAKR-03` (format-before-truncate in `memory/ctx.rs`) · `GOLD-ADAPT-TRAIL-02` (preupdate-hook change bus `memory/change_bus.rs` → gui-stream push) · `GOLD-ADAPT-TRAIL-03` (`Reactive<Arc<FreedomYaml>>` config derive-graph — touches `config/mod.rs`, coordinate with anything else config-touching in flight) · `GOLD-ADAPT-ODY-26` (session auto-sort cron over HindsightCard titles; AGPL → fresh Rust) · finish `GOLD-ARCH-07` (migrate the counted remaining inline time-call sites via the line-based migrator pattern, DRY-RUN first) · `GOLD-ADAPT-HR-06`: run the deferred-decision — implement the lossless tabular compaction only if SmartCrusher metering shows the 10-50-row homogeneous-array case actually occurs in live WAL samples; otherwise record skip verdict + DO_NOT_ADOPT row.

### B5 — Loop engine (M-L; NEOTH's own autonomous-loop feature)
Order: `GOLD-LOOP-02` (CLI `neoth loop` + `loop_engine/` core) → `GOLD-LOOP-04` (L1/L2/L3 autonomy mapping) → `GOLD-LOOP-05` (token-budget enforcement, reuse 0x2F + new 0x6D) → `GOLD-LOOP-06` (skill YAML `loop: true` + verifier/loop-triage stdlib skills) → `GOLD-LOOP-07` (run log + `--history/--show`). Evidence: loop-engineering repo refs in item text (`QUELLEN/` batch-2 sources). GUI panel LOOP-03 deferred to B8.

### B-DELTA — Babel-Index / RDelta core (GOLD-DELTA-01..12; operator-prioritized 2026-07-02, runnable any time after B0)
Wire the EXISTING `analytics/babel/` scaffolding (~1.8k LOC, uncommitted-then-committed 2026-07-02, green in the full suite) into the daemon: order 01→02→03→04 (config→store→cron→spawn), then 05/06/07 (norm/epsilon/labels), 08/09 (export+CLI, CLI-doc gate!), 11 (SSE), 12 (integration tests); 10 (federation) LAST and only after the §9 operator answers (wizard opt-in scope). Spec = `REVIEWS/_gold_audit/research/delta_kosmologie_babel_2026-07-02.md` §4; constraints: SQLite-only (WAL bytes exhausted 255/256), federate default-false consent-gated. Upstream delta-kosmologie repo fixes (report §2 FINDING-01..09) ship separately in that repo.

### B6 — Task pipeline & sovereign mode (M-L)
`GOLD-TASK-01` (route ANY inbound → kanban decomposer, reuse QU-10b task_executor) · `GOLD-ADAPT-ODY-12` (LLM→UI control events; prereq for MODE-04) · `GOLD-ADAPT-JV-MODE-02` (sovereign/full-autonomy mode — operator-selectable, council-on-demand or single-provider, explicit consent ceremony; evidence `_jarvis_2026-06-12/proactivity_crons.md` + `_SYNTHESIS.md`) · `GOLD-ADAPT-JV-MODE-04` (self-activation: NEOTH toggles own skills/crons under sovereign mode) · `GOLD-ADAPT-JV-PRO-08` delta from B2 · `GOLD-ADAPT-ODY-14` (inline entity deep-links).

### B7 — GUI wave 1: component library (M, ALL in components.slint/theme.slint/app_shell.slint/chat.slint — single batch, single GUI check)
`GOLD-ADAPT-GUI-01..08` (shimmer, ease-back, SegBar, Led, TypedStatus ticker, focus-dim, NeothButton loading + size variants) + `GOLD-LOOP-03` (loop.slint panel, `gui-loop` display-gate). Slint 3-file pattern per Builder's guide. Verify with `cargo check -p neothd-gui` + screenshot via desktop-commander if available.

### B8 — GUI wave 2: panels & onboarding UX (L)
`GOLD-ADAPT-ODY-01` (sessions sidebar from `hindsight::list_cards`) · `ODY-02` (ctx-window chip — extend `--stream` sentinel) · `ODY-03` (attachment strip, `rfd` picker) · `ODY-04` (stall watchdog + auto-continue) · `ODY-05` (per-message metrics chip, feeds from WAL times) · `GOLD-ADAPT-AOS-01..06` (settings: skills index, presets panel, wizard project-context step, config domain-sections, why-active pane, spec-shape entry) · `GOLD-ADAPT-OH-12` (first-run tour). **Close with the design-taste gate: run `impeccable /audit` + `design-review` skill on the GUI; fix findings — no default-AI-slop UI.**

### B9 — Channel parity (L; merged FEAT-10/PROG-16 item from B1)
Implement the verified-missing adapters (expect: **Signal** (signal-cli JSON-RPC/SSE), **LINE** (REST webhook), **iMessage**, **IRC** (irc crate)) on the `Channel` trait, following the channel-adapter template (memory: session 2026-06-15b shipped 6 channels off one template; research: `REVIEWS/_gold_audit/research/channels_*_2026-06-13.md`). Each: feature-gated, wizard step, consent-gated egress, spoof-hardened sender IDs, adapter tests. One adapter = one commit; gate per adapter.

### B10 — Media/voice (M)
`GOLD-ADAPT-HANDY-02` (SmoothedVad + Silero via `vad-rs` → `media/vad/`, pre-STT gating) · `GOLD-ADAPT-HANDY-04` (model download manager: SHA-256 + resumable + atomic extract → `media/model_manager.rs`; first-use STT auto-download) · `GOLD-ADOPT-25` (dictation mode: whisper-rs local + OpenAI-compat fallback, `whisper-stt` feature + `freedom.yaml::input.dictation` default-off). Sources: handy + speakr in `QUELLEN/`.

### B11 — Security/API surface (M) — security-reviewer MANDATORY on this diff
`GOLD-ADAPT-ODY-31` (scope-gated API tokens, bcrypt, fine-grained scopes, AGPL→fresh) · `GOLD-ADAPT-JV-SEC-01..09` remaining 7 (watchdog/auto-recovery cron + security-audit, secrets-scan, nmap-recon, pentagi, ping/dns/firewall bundled skills → `assets/skills/` + `os_tools/`; consent-gated, operator-authorized) · `GOLD-ADAPT-JV-PAPERLESS-01` (email→Paperless→Obsidian pipeline: IMAP ingestion + 60-pattern content scanner + quarantine gate; source scripts in `QUELLEN/JARVIS_LIVE/scripts/`).

### B12 — Skills bundles (S-M, pure `assets/skills/` + small tool shims)
`GOLD-ADAPT-JV-MISC-01..15` (humanizer, deepwiki, agent-architect, meta-agent, advanced-skill-creator + `skills/creator.rs`, oracle-agent, marketing-mode, log-analyzer, firecrawl-search → `tools/web_extract.rs`, omniparser + `media/vision.rs`, news-aggregator, home-assistant + entity-index, diagram/mermaid, …) — port the PROMPT CONTENT from Jarvis skills verbatim-quality (steal the real content), adapt tool calls to NEOTH dispatch · `GOLD-ADAPT-DRAW-02` (bundle rustimports.py + autolayout.py as skill scripts). Batch by tens; router-index test per skill.

### B13 — RMAS experimental sidecar (M, strictly gated)
`GOLD-ADAPT-RMAS-01` (config + Cargo-feature scaffold, default-off) → `RMAS-02` (VRAM resource-gate) → `RMAS-03` (`ProviderKind::RecursiveMas` Python sidecar for council deliberation). Design constraint from memory: latent-weights method can't drive text-API agents — VRAM-gated local-only optional.

### B14 — Big features (L each; last because they consume everything before them)
`GOLD-FEAT-03` finish (self-wiki Obsidian pipeline rest) · `GOLD-ADAPT-OH-01` (migration-first onboarding — pairs with shipped GOLD-FEAT-04 migrate-apply; wizard first question new-vs-migrate; sources: openclaw/hermes/openhuman readers already in neoth-migrate) · `GOLD-FEAT-05` (self-reprogramming with the 5-layer safety stack — kill-switch, allowlist, permission gate, worktree isolation, review gate; evidence `research/self_reprogramming.md`; security-reviewer mandatory) · `GOLD-FEAT-06` (exo-style swarm dashboard: NodeResourceSnapshot gossip + `neoth cluster swarm --watch`).

### B15 — WS-G eval-repo queue (research batch; parallelizable — interleave whenever a build batch is blocked)
Queue (tracker, grep "Eval-repos queue"): `anthropics/knowledge-work-plugins` · `rohitg00/ai-engineering-from-scratch` · `EveryInc/compound-engineering-plugin` · `affaan-m/ECC` · `mukul975/Anthropic-Cybersecurity-Skills` · `D4Vinci/Scrapling` · `hardikpandya/stop-slop` · `UditAkhourii/adhd` (operator: "wichtig") · `moazbuilds/claudeclaw` (TODO:19 — restored by the B1 TODO.txt sweep). Protocol per repo = §6.2 gremium deep-read. Output per repo: verdict (adopt-native / ground-truth / skip) + concrete steal-list items appended to WS-I with evidence file — then IMPLEMENT the adopts (they join the matching subsystem batch), record skips in `DO_NOT_ADOPT.md`. Release gate requires: evaluations complete + verdicts implemented.

### B16 — Jarvis + Veronica live re-sync (research batch; needs LAN/Tailscale access)

> Veronica (Claw2, `tgf@100.86.138.18`, same key-auth) gets the same delta treatment — TODO:51-55 names BOTH brains; `QUELLEN/VERONICA_FILES/` + the Deep-Audit VERONICA DELTA section are the baselines.
1. Inventory delta since 2026-06-12: `ssh tgf@192.168.178.117 "find ~/.openclaw/skills ~/.openclaw/cron ~/.openclaw/workspace/knowledge ~/scripts -newermt 2026-06-12 -type f | head -100"` + compare skill/cron lists vs `QUELLEN/JARVIS_LIVE/skill_plugin_inventory.txt`.
2. Pull new/changed sources: `ssh tgf@192.168.178.117 "tar czf - -C ~ <paths>" | tar xzf - -C QUELLEN/JARVIS_LIVE_2026-07/` (redact credentials — NEVER commit secrets; follow the redaction pattern in `QUELLEN/SOURCES_INVENTORY.md`).
3. Deep-read the delta (§6.2 panel): what did Jarvis gain that NEOTH lacks? New crons, new memory mechanisms, prompt evolutions in CLAUDE.md/MEMORY_MATRIX.md lineage, watchdog changes.
4. New steal-items → tracker WS-I with evidence; implement in matching batches. Also verify earlier JV ports against live behavior where cheap (constants drift: dedup=0.85, link=0.50, hippo thresholds).

### B17 — Release gate + 12/10 polish (final)
1. Definition-of-GOLD checklist (tracker §5, L1350-1363): work each unchecked box — WS-D/WS-E/A-01..A-10/Roman-HIGH boxes are roll-ups: re-verify their workstreams actually total 100% and flip; WS-G/WS-H/WS-I boxes close when B15/§9/WS-I empty.
2. Full-matrix local run: check + clippy + full tests + feature bats + GUI + CLI-doc gate. Then CI green **3 consecutive pushes**.
3. FINAL ERROR-HUNT WAVE ×2 (§7) — second wave must come back empty (loop-until-dry).
4. Docs honesty re-pass: README + `docs/` claims vs shipped reality (HON discipline: surface must not over-promise).
5. Signed release artifacts (minisign per GOLD-PROG-13 decision, sha256 companions), `packaging/` flow, CHANGELOG, tag `v1.0-gold`, GitHub release.
6. Write `PLAN/ROAD_TO_1_1.md` seeded from every v1.1-deferred item (TODO:56 — "erst wenn 1.0 complete"): FEAT-05..12 v1.1 halves, FEAT-10b stretch channels, RMAS follow-ons, CCPARITY deferred pair, HR-06 if skipped.
7. Post-tag: update this plan's LOOP STATE to COMPLETE; write session memory.

---

## 6. Deep-research protocol

### 6.1 Per-item (before writing any port code)
1. Open the item's evidence file (tracker names it; default locations §1 table). It contains source `file:line` + the algorithm. 
2. Open the REAL source in `QUELLEN/<repo>/...` at that location. Read the whole mechanism (not just the cited lines): data model, constants, edge cases, failure paths.
3. Write the port as: NEOTH-native module using the Builder's-guide pattern + the source's exact constants/prompts (constants ARE the feature — e.g. Jarvis 0.85/0.50 thresholds, promotion gates ≥2 sources + 0.85 confidence).
4. License check: odysseus AGPLv3 → clean-room re-implement (logic yes, code no). mnemo/MIT → port freely. rscrypto → never as dep. Jarvis/openhuman/hermes/lowkey = operator-owned.
5. If the evidence file is missing/thin → spawn 2-3 read-only research agents on the vendored repo (grep+read fan-out), synthesize, THEN build. Panel outputs get verify-first.

### 6.2 Per-repo gremium (WS-G queue + Jarvis delta)
Deploy 3-4 parallel read-only agents per repo: (a) what-it-actually-does from code, (b) where it beats NEOTH (specific logic + file vs our file:line), (c) steal-list ranked with our integration point, (d) skeptic (license, dead-code, marketing-vs-reality). Synthesize; **verify-first every claimed NEOTH-gap against HEAD** (panels hallucinate gaps that were shipped). Verdict + items into tracker; skips into `DO_NOT_ADOPT.md`. Only steal what has a real consumer — no primitive-ahead-of-consumer.

### 6.3 Standing research rules
- GitHub search (`gh search code/repos`) + Context7 docs BEFORE hand-rolling anything a battle-tested crate covers; check `DO_NOT_ADOPT.md` first (don't re-evaluate rejected deps).
- New dep → license + RUSTSEC check (`deny.toml` + cargo-audit `--ignore` list must stay in sync — BOTH files).
- Model-version-agnostic HARD RULE: provider code passes through ANY model id; selection reads live `models::catalog`. Never hand-patch for a new model name.

---

## 7. Error-hunt wave (every 3 batches; 2× at release)

Run as parallel read-only agents over the delta since the last wave (`git diff <last-wave-tag>..HEAD` + touched modules), each with a distinct lens:
1. **rust-reviewer** — ownership/unsafe/async-holding-locks/cancel-safety.
2. **security-reviewer** — OWASP+STRIDE on any new surface (channels, tokens, subprocess, network, WAL).
3. **silent-failure-hunter** — swallowed errors, `let _ =` on fallible sends, error paths that skip WAL audit.
4. **Unwired sweep** (G-02 method, §B3) — new pub items with 0 production callers.
5. **Logic skeptic** — re-derive each new algorithm vs its QUELLEN source (the SPEAKR-Fbank incident: shape-tests passed, algorithm was wrong — compare against REAL upstream, not the item text).
Then **fp-check adversarial verify** on every CRITICAL/HIGH finding before fixing (panels produce false positives; verify exploitability/reality first). Fix confirmed findings immediately; deduped MEDIUMs become tracker items. A wave that finds nothing twice in a row at release = done.
Optional cross-model second opinion when available: Chorus template `codex-gemini-review` (`POST 127.0.0.1:7707/chats`, answers in `~/.chorus/chats/:id/round-1/reviewer-*/answer.md`) or `/codex` skill.

---

## 8. Recovery & salvage

- **Crash/reconnect mid-batch (dirty tree):** do NOT reset. (1) `git status -sb` + `git diff --stat` to size the salvage; (2) run §3 gates on the dirty tree; (3) green → commit the completed slices with correct tracker flips; red → finish or `git checkout -p` away only the broken fragment; (4) push. (This is the `salvage_loop` procedure from memory, scripts lost — the procedure is what matters.)
- **Post-reconnect bash flakiness:** compound/pipe/redirect commands may break → issue single simple commands; desktop-commander MCP is the fallback shell when harness bash dies (`line 103 EOF`).
- **`.git/index.lock` stuck:** kill stray git processes, then `rm .git/index.lock` (verified-safe recovery).
- **Shared-.git corruption (only if worktrees get used):** repair with `git fetch --refetch origin` (non-destructive). Prefer NOT using worktrees for this loop — bats hardcode the main checkout.
- **Context compaction:** the LOOP STATE block + tracker are the durable state; a fresh session re-bootstraps from §2 in <5 min. Update LOOP STATE before any risky long operation.
- **Box overheat (known):** heavy parallel builds crash the machine → `-j2` builds, ≤4-agent panels, one build at a time.

---

## 9. Operator-blocked / decision records (park list — ask Alex, don't guess)

| Item | Decision needed |
|---|---|
| `GOLD-PROG-13` | Run `neoth release setup` on the release machine (minisign keypair provisioning) — needs operator to execute + store pubkey; code complete. |
| `GOLD-PROG-15` | PC-02 Chrome-DevTools-MCP license/telemetry acceptance — config shipped; operator go/no-go for default recommendation. |
| `GOLD-HR-00` | Host-level tooling install (`uv tool install headroom-ai[proxy]` + CC plugin hooks) — outside repo; operator's Claude-Code setup. |
| `GOLD-ADAPT-JV-MODE-02` consent ceremony | Sovereign-mode default wording/level — propose, Alex ratifies. |
| Release tag timing | `v1.0-gold` tag + GitHub release publish = operator confirms. |

Record each decision as a dated line in the tracker item, then the release-gate box can close.

---

## 10. Efficiency rules (token + wall-clock)

1. **Batch by file/subsystem** (the batch map already does): one read → all edits → one gate.
2. **graphify before grep** for any structure question (~276× cheaper); refresh after each batch.
3. **ctx sandbox for bulk reads** (tracker parses, log mining, CI logs) — only derived lines enter context. NEVER `ctx_execute_file` on a file you keep (it clobbers its `path` arg) — use `ctx_execute` + readFileSync.
4. Agents: fan-out for RESEARCH and REVIEW (read-only, parallel, ≤4); implementation stays in the main thread (quality + no worktree collisions).
5. One gate run per batch tail, targeted test filters during development (ONE filter token per `_test.bat` call).
6. Tracker/PROGRESS flips ride the feature commit (no separate docs commits except B1).
7. Long ops (full test, CI watch) in background; keep building meanwhile on non-conflicting files.
8. Don't re-litigate recorded verdicts (`DO_NOT_ADOPT.md`, §9 decisions, D-101/102/103).

---

## 11. Definition of DONE (the 12/10 bar)

- [ ] Tracker: 0 × `[ ]`, 0 × `[~]` outside §5 gate + §9 park list; every close has evidence.
- [ ] All 11 release-gate boxes (§5 tracker) `[x]`; PROGRESS_v1_0.md consistent.
- [ ] CI: full matrix green on 3 consecutive main pushes.
- [ ] Error-hunt wave returns zero CRITICAL/HIGH twice consecutively.
- [ ] GUI passed design-taste audit (B8) — no slop.
- [ ] WS-G: all 8 eval repos verdicted; adopts implemented; skips registered.
- [ ] Jarvis delta re-synced + mined; new steal-items shipped or verdicted.
- [ ] Docs honest; signed artifacts; `v1.0-gold` tagged (operator-confirmed).
- [ ] Session memory + this plan updated to COMPLETE.

---

## LOOP STATE  *(rewrite this block as batches complete — it is the resume pointer)*

```yaml
updated: 2026-07-04 (Fable 5 session #4 — dead-code salvage + ULTRA closure + B10 rest + B11 verified-done)
session4_final: >
  3 commits e302373a/5a4e7ffc/cfcb9b8c, all pushed. (1) SALVAGE: prior
  session's crate-wide #![allow(dead_code)] removal was dirty-tree —
  fixed the 7 remaining dead_code errors (6 orphaned test helpers
  deleted, resolve_auth_for_cron gate narrowed to imap_fetch-only),
  -316 lines. (2) ChatGPT external feedback verified: 5/6 "Restluecken"
  were ALREADY fixed by the 5 then-UNPUSHED commits 772552fe..e641eb0b
  (now on origin); warm-HNSW = SKIP_BY_DESIGN (WIRE-07b snapshot-refresh
  cron serve_tasks.rs:2665; in-memory warm index would miss CLI-ingested
  vectors, serve.rs:1285). (3) ULTRA quick-wins shipped: hysteria unsafe
  set_var -> http_client::set_process_proxy RwLock slot (env stays
  fallback) + respawn watchdog w/ shutdown-latch (review caught
  abort-race child leak — fixed), dispatcher tasks_blocked 5-site
  reorder, faster-whisper gated on allow_huggingface_downloads
  (unwrap_or_default), rate-limit restart-refill ACCEPTED-by-design
  (module doc). (4) B10 rest closed: neoth dictate CLI (cli/dictate.rs,
  symphonia decode seam audio::decode_file_to_pcm) = production caller
  for transcribe_utterance; feed_with_vad DELETED (0 callers); tracker
  spec-corrections (media.dictation_enabled, hf_hub not model_manager).
  (5) B11 verified COMPLETE by agent sweep (ODY-31, JV-SEC-01..09,
  PAPERLESS-01 all shipped/skip-recorded). Full suite 9847 green x2.
  ULTRA still OPEN (real, tracked): webhook durable inbound spool,
  gossip-WAL ingest (=G02-CLUSTER-02), smart-loader plan_loader unwire,
  doctor advisable-config hints, GUI-parity long-tail.
next_b12: >
  B12 skills rest (research DONE, in wf_9d29bc0b result file): remaining
  of JV-MISC-01..15 = news-aggregator (pure-prompt, rss_feed_task lives,
  LLM-summary layer IS the skill), advanced-skill-creator delta (bundled
  skill.yaml surfacing the live creator.rs wizard), omniparser (needs
  media/vision.rs expansion beyond CLIP), home-assistant+entity-index
  (needs new tools/home_assistant.rs REST shim; JV-IOT-01/02). Register
  via bundled.rs BUNDLED_SKILLS + router test (pattern bundled.rs:1590).
  Then B13 RMAS (gated sidecar), B14 big features (FEAT-03b/05/06,
  OH-01, ODY-12/14, TASK-01, MODE-02/04), B16 Jarvis re-sync, B17 gates.
  27 tracker-open @ cfcb9b8c (11 = B17 rollups, 3 operator-blocked).
b9_final: >
  B9 FULLY SHIPPED (7 commits 40752049/4b68524c/fd897d1b/bb2fe22e/ad6a5490/
  934bbeb8/4fdfac9e). VERIFY-FIRST: the B9 prose (Signal/LINE/iMessage/IRC
  adapters) was STALE — all four existed; real rest per GOLD-FEAT-10b:
  GChat Pub/Sub PULL adapter (feature gchat-channel, jsonwebtoken/ring RS256
  SA-JWT, +2 lock pkgs, long-poll pull/ack-everything + 2s idle guard,
  token_uri https:// gate, topic-IAM caveat), BB send_media (multipart vs BB
  server SOURCE, caption degrade-not-Err), wizard/CLI channel add/remove ×7
  (discord stale-bail killed), routing parity (Destinations 14 families +
  proactive Signal/LINE/Mattermost/iMessage), IRC account-tag hardening
  (cap-req INSIDE registration window — identify() sends CAP END), GUI
  Channels 11→14 rows. GOLD-FEAT-10b [x] + PROGRESS entry. Review-wave:
  verify-first REFUTED maxWaitDuration claim (field absent in REST v1;
  long-poll default) + confirmed CAP-END bug. Foreign commit 8c11ab00
  (docs launch) landed mid-wave, no conflict. Gates: default+feature clippy
  0, module filters green, full suite = see push note. Bats now throttle
  (-j 4 clippy/test + --test-threads=2 hardcoded, operator BSOD directive).
b7_b8_final: >
  B7+B8 FULLY SHIPPED (0752c920..79e7e442, 8 commits): GUI-01..08,
  GOLD-LOOP-03, ODY-01..05, AOS-01..06, OH-12 — all [x] in tracker with
  SHIPPED notes + spec-corrections (AOS-02 was stale/wrong-surface,
  AOS-05's `skill triggers` CLI never existed, LOOP-03 engine-channel
  impossible cross-process). Design-taste gate RAN (agent audit vs
  theme.slint contract): PASS-WITH-FIXES, all P1/P2 applied in 79e7e442
  (inline-hex kill, motion tokens duration-sweep/spin/breathe, settings
  shimmer:false ×19, token'd radii/fonts). Code-review wave: 6 real fixes
  (sentinel line-parse, loop refresh in-flight guard, stderr reader
  thread, ts_start sort, lock-scope, single-pass attach cap) + 1 false
  positive (epoch-0 = absent, by design). neothd-gui tests 127→137;
  cli::chat 96/96 + attach_tests; kanban 24/24 (new `kanban add`).
  Foreign commit 3320b7eb (parallel session: Paperless egress allowlist)
  landed mid-wave — clean, no conflicts.
gui_wave_state: >
  FULL SUITE 9816/9816 green at session start (grew from 9765 — wave-5 tests).
  B7 COMPLETE (0752c920): GUI-01..08 [x] + GOLD-LOOP-03 [x] (spec-corrected:
  record-at-end → history browser + subprocess run/kill; gui-loop cargo
  feature default-on; new loop.slint + SegBar/Led/ease-back/NeothButton
  loading+size+danger in components/theme). Gate = SRC/_gui_check.bat
  (gitignored local bat, `cargo %*`, pass -j 4 BEFORE any `--`).
  B8 CHAT CLUSTER COMPLETE (47803513 + be32b1e6): ODY-01 sessions sidebar
  (HindsightCardMini mirror), ODY-02/05 extended stream sentinel
  (used/limit/input/output/elapsed_ms; limit=effective_cap) + metrics chip
  + popup, ODY-04 stall watchdog (60s banner, Stop kills parked child,
  capped auto-continue w/ refill guard), ODY-03 attachment strip (rfd
  picker GUI + daemon --attach → resolve_prompt extraction blocks, ingest
  helpers pub(crate)). neothd-gui tests 127→133; cli::chat 96/96.
  Screenshot-verify SKIPPED (operator denied screen access — gates+tests
  are the evidence). B8 rest COMPLETE (see b7_b8_final above).
next: B10 media rest — VERIFY-FIRST the tracker: HANDY-04 auto-download
  landed (wave 3), HANDY-02 VAD + ADOPT-25 dictation landed (wave 5) → B10
  may be VOLLSTÄNDIG STALE; check GOLD-ADAPT-HANDY-04 model_manager.rs
  URL+SHA consumer (ADOPT-25/GGUF slice) as the only possible rest. Then
  B11 Security/API rest (ODY-31 [x] wave 4 — verify what remains),
  B12 skill bundles, B13 RMAS, B14 big features, B16 Jarvis re-sync,
  B17 release gate. Open GUI follow-up: Slint Channels tab renders 14 rows
  dynamically (no .slint change was needed).
base: 37249a8c
current_batch: >
  B3 COMPLETE (02b072c1 slice1 + 1b06e94e GRILL loop + f6fa1205 review-wave +
  5607a13d queue-sweep): PROG-06/G-02/GRILL-02/GRILL-04 [x] + review fixes
  (task_id charset gate, ProactiveQueue::modify process-lock + reconcile
  commit_drain — ALL 13 producer/drain sites converted) + G02-QUEUE-01 [x].
  B5 COMPLETE (d0d1b004 + 37249a8c): LOOP-02 (neoth loop run/history/show),
  LOOP-04 (LoopAutonomyLevel L1/L2/L3 + L3-requires-budget), LOOP-05
  (SPEC-CORRECTED: WAL bytes EXHAUSTED 255/256 + 0x6D taken → budget audit
  rides 0x7F payload), LOOP-06 (loop:true skill header + verifier/loop_triage
  stdlib skills + channel-path routing), LOOP-07 (history reader).
  LOOP-03 = GUI wave (B7). B4: ODY-26 [x] (session_sort_cron + recall
  --session-folders), PRO-08 [x] (report-verifier), SPEAKR-01 dup [x].
  B4 COMPLETE: ARCH-07b [x] (8b666efb — ~100 sites migrated, 5 documented
  holdouts, FULL suite 9671/9671 green) + HR-06 [x] (1e2a79cc — skip-with-
  metering: smart_crusher_hr06_bucket counter SHIPPED, reformat stays unbuilt,
  reopen condition recorded). ERROR-HUNT WAVE #1 over B3-B5 diff ran (3 lenses,
  11 findings) — fixes in flight/landed: loop_triage keyword collision,
  is_throwaway folder-tag guard, parse_verdict word-boundary, dreaming_task
  12th producer site, verify_staged race-softening, docgen bool-flag
  placeholders, LOOP-06 outer-branch engage (autoroute-off), loop_cmd
  daemon-running WAL guard. 58 open boxes. New in-flight tracker items:
  G02-COUNCIL-01 [x] (factual_check council wire — orchestrator Wire(a)+Wire(b),
  config gate groundtruth_injection:bool default ON, factual_outcomes field on
  CouncilDebate, 4 tests: no-op/tag-inject/demote/graceful-fallback), G02-CLUSTER-01
  (foreign-event ingest, M-L). Accepted/filed: QUEUE_FILE_LOCK std-mutex on
  async threads = pre-existing blocking-fs pattern (tracker note below).
hazard: >
  ⚠ BOX BSODs (IRQL_NOT_LESS_OR_EQUAL) under parallel test load — 2 crashes
  2026-07-03. MANDATORY: tests via `_feat.bat test -p neothd --lib <filter> --
  --test-threads=2`; builds -j4; NEVER cargo concurrent with multi-agent
  workflows; ≤4 agents. Memory: box_bsod_on_test_load.md.
  ⚠ WAL BYTE SPACE EXHAUSTED (255/256) — §2 free-band table is STALE; no new
  WAL events possible, ride existing payloads (LOOP-05 pattern).
b6_research: >
  DONE (wf_f6fef820-225; full reports at REVIEWS/_gold_audit/research/
  b6_task_sovereign_research_2026-07-03.md). Verdicts: TASK-01 = real build
  (build_pipeline_handler has ZERO decomposer calls; needs general-task
  intent detector + decompose_non_coding + routing branch; spec's "WAL 0x78"
  is TAKEN and byte space exhausted → NO new event, ride existing).
  MODE-02 = sovereign_buddy mode (freedom.yaml flag + consent ceremony +
  reuse 0xDD/0xD0 band events — agent's "0xDE free" claim FALSE); hard
  blocker for MODE-04. MODE-04 = self-activation (Action::SelfSkillToggle
  gates, SelfActivationConfig default-off, disabled-list always wins,
  PromptEdit-only evolver firewall untouched; needs MODE-02 + jobs.yaml
  hot-reload gap). ODY-12 = UiControl sentinel + panel_logic (GUI-coupled).
  ODY-14 = DEFER→B8 GUI wave (display-gated; ChatBubble refactor batched
  with ODY-01..05).
next: B7/B8 GUI MEGA-WAVE (fresh session STRONGLY recommended — this session's context is saturated): ~25 Slint items (GUI-01..08 components, LOOP-03 panel, ODY-01..05/12/14 panels+UiControl, AOS-01..06 settings, OH-12 tour) — gate = cargo check -p neothd-gui (temp bat, BIN crate no --lib) + design-taste skills (impeccable/design-review) per plan §B8. THEN: B13 RMAS (gated sidecar) → B14 (FEAT-03b self-wiki rest, FEAT-05 self-reprogramming [security-reviewer MANDATORY], FEAT-06 swarm dashboard, OH-01 migration-first onboarding) → GChat Pub/Sub adapter + BB send_media + wizard steps (FEAT-10b rest) → G02-CLUSTER-02 persist-then-dedup + G02-TOOLS-01 web_extract wire-or-delete → B16 Jarvis/Veronica re-sync (SSH, key-auth works) → B17 release gate + Definition-of-GOLD roll-ups (11 boxes) + steal-backlog (ScopeContract, verification gates, run_with_feedback — research/b15_eval_wave{1,2}). STATE 2026-07-03 END-OF-SESSION: waves 1-5 + error-hunts #1+#2 COMPLETE. 49 open @ b15cfe15 (from 70 at session start; ~30 commits). Full suite was 9765/9765 green mid-session; wave-5 module filters green (full-suite re-run = first action next session). BSOD throttles + WAL-byte-exhaustion + agents-commit-uninvited gotchas in memory files.
prev_batch: B-DELTA 100% COMPLETE — ALL 16 items shipped incl. the operator-delegated pair: 03=da9a306d, 04=c312f9b0, 05+06=c3b21240, wave#1=eb345671, 07=a96201f2, 08+09=caa32a46, 11=3d346384, 12=5ae8f214, wave#2=5b16f443, 16=9a0f39ec, 13=dc011f9d, 15=34466060, Q1/Q3 panel decisions=a2615f0b (3-lens gremium under operator delegation "spawne agenten, berate, baue fertig"), 10=580c1a16 (pending-first federation submit + CLI federate + consent prompt), 14=77360338 (pooled predictor download, 4 firewalls enforced in code). FULL suite 9631/9631 + feature-matrix green at close. B2 sweep chunks A+B landed in a2615f0b (3 stale flips, HANDY-04 unwired-note).
next: B3   # wiring & unwired-primitive audit (B2 chunks A+B done; a chunk-C re-check of any unswept items folds into B3's G-02 sweep)
completed_addendum: [B-DELTA FULL 2026-07-02 Fable-5 — 16/16 items, 2 clean error-hunt waves, panel-ratified Q1/Q3; memory file neoth_babel_batch_2026_07_02.md]
handoff: PLAN/HANDOFF_OPUS_2026-07-02.md   # full Opus-4.8 handoff — read FIRST on a fresh session; upstream delta repo fixed+pushed a4bd367
next: B2
completed: [B0 (0d4024b1 — ubuntu+windows+features+smoke green; macos was still running at last check), B1 (24d2f96b — 0 partials, dedupes, claudeclaw restored)]
notes: >
  Plan created; counts 68 open + 9 partial verified at d9d6c9d0.
  Local main was 21 commits behind origin on 2026-07-02 — ALWAYS ff-pull at bootstrap.
  B0 root cause (NO hang): ci.yml ran bare `cargo audit` (no ignores) while
  security.yml carried 7 --ignores → lopdf RUSTSEC-2026-0187 + rsa RUSTSEC-2023-0071
  failed ubuntu deterministically; plus quick-xml RUSTSEC-2026-0194/-0195 (2026-06-29)
  broke Security too. Fix: SRC/.cargo/audit.toml = single ignore source (both
  workflows bare `cargo audit`), deny.toml mirror +0194/+0195, neothd quick-xml
  0.38→0.41 (CalDAV). Local proof: cargo audit EXIT=0, cargo deny --all-features
  advisories ok, check+clippy+full tests green. The 5h run duration = runner queue.
  Follow-up (warnings only, non-gating): yanked bitcoin-io 0.1.100 /
  bitcoin_hashes 0.14.100 / crypto-bigint 0.7.4 + memmap2 0.9.10 unsound
  (candle-0.8 chain) — clean up when parent bumps exist.
```
