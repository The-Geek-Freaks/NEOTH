# NEOTH — HANDOFF for Opus 4.8 (2026-07-02)

**You are taking over an autonomous build loop that finishes NEOTH to a 1.0-GOLD release.**
This document is self-contained. Read it fully once, then start at §12 (START HERE). You do not need any prior conversation — everything you need is on disk and named below.

**Operator:** Alex (solo dev, security researcher, full authorization). Language to Alex: German. Code/commits/PRs: English. Alex reads the git diff and the chat — reply in chat (this session uses `SendUserMessage`; if your harness has no such tool, reply in plain chat text).

---

## 1. What NEOTH is (30-second orientation)

A local-first sovereign personal-AI daemon in **Rust**, single operator, runs on the operator's machine. Core primitives: hemisphere **council** (Left/Right/Cerebellum provider routing), append-only **WAL** audit log (ed25519-signed frames), **consent-gated** tool execution, **skills** system, **memory tiers** (hot/warm/cold + groundtruth), **channel adapters** (Telegram/WhatsApp/Slack/Discord/Signal/…), optional **cluster** mode (Hyperswarm/iroh/Keet P2P). Ships MIT OR Apache-2.0, public OSS-grade.

**The goal of your loop:** drive the tracker `PLAN/ROAD_TO_1_0_GOLD.md` from **83 open items → 0**, keep CI green, then tag `v1.0-gold`. Do it by **deep-analyzing then porting** features (never approximating from a one-line summary), **wiring** every built primitive to a real caller, **finding and fixing your own bugs** in scheduled review waves, and **researching autonomously** (agents/panels) when a spec is thin.

---

## 2. The documents you own (read in this order)

| File | What it is | When you read it |
|---|---|---|
| **`PLAN/HANDOFF_OPUS_2026-07-02.md`** | THIS FILE — orientation + the exact procedure | now, fully |
| **`PLAN/LOOP_PLAN_GOLD_FINISH.md`** | The master execution plan: batch map B0–B17 + B-DELTA, loop protocol, build recipe, error-hunt waves, recovery, operator-decision park list. Its `## LOOP STATE` block (bottom) is the resume pointer. | now, fully — this is your playbook |
| **`PLAN/ROAD_TO_1_0_GOLD.md`** | The TRACKER — every task as `[ ]` open / `[x]` done. ~1430 lines, 805 KB (too big to Read whole — grep it). §0–2 (L1–120) = intro + build recipe + WAL-band table + gotcha appendix. Builder's guide ~L828–850. WS-DELTA (Babel) near the bottom. | grep for the item you're building; read §0–2 + Builder's guide once |
| **`REVIEWS/_gold_audit/research/delta_kosmologie_babel_2026-07-02.md`** | Full Babel-Index build spec + verified findings + theorem-test protocol + open operator questions. GOLD-DELTA-01..12 verbatim in §4. | before ANY GOLD-DELTA item |
| Memory: `C:\Users\Shadow-PC\.claude\projects\C--Users-Shadow-PC-CascadeProjects-AGENTER\memory\MEMORY.md` + the `neoth_gold_loop_plan_2026_07_02.md` file it points to | Durable cross-session facts + gotchas. The top line of MEMORY.md points at the loop plan. | if your harness auto-loads memory, it's already in context; else read MEMORY.md once |

**Everything below is a condensed, self-sufficient copy of what matters. If this handoff and the tracker disagree, verify against the actual code (`grep`/read) — the code wins.**

---

## 3. Ground truth (verified 2026-07-02, HEAD `afe2eb13`)

- **Repo:** `C:/Users/Shadow-PC/CascadeProjects/AGENTER`, branch `main`, remote `github.com/The-Geek-Freaks/NEOTH`.
- **HEAD:** `afe2eb13`. Clean tree at handoff time. **Always `git fetch && git status` first** — this checkout was found 21 commits behind origin once (a parallel loop pushed from another worktree). If behind: `git pull --ff-only`.
- **Tracker state:** 83 `[ ]` open, 0 `[~]` (the partial marker is banned — see §7). GOLD-DELTA-01 and -02 are `[x]`; GOLD-DELTA-03..12 are `[ ]`.
- **CI:** GREEN as of the last push. Root cause of the earlier red is fixed (see §6.1) — do not re-investigate it.
- **Rust workspace:** `SRC/` (members: `neothd`, `neothd-gui`, `neoth-plugin-sdk`, `neoth-migrate`, `neoth-relay`). Main crate: `SRC/neothd/`.
- **Windows + MSVC only** for building. Do not run raw `cargo build/test/clippy` — use the wrapper bats (§5). Metadata-only cargo (`cargo tree`, `cargo update`) is fine directly.

---

## 4. Non-negotiable rules (violating these has bitten past sessions — do not test them)

1. **NEVER run `cargo fmt`.** It reformats the whole repo and collides with hand-formatting. CI's fmt check is `continue-on-error: true` (advisory) — it will NOT fail the build. Formatting drift is acceptable; a fmt commit is not.
2. **NEVER pipe a gate command through `tail`/`head`** — it masks the exit code. The wrapper bats echo `BUILD_EXIT=` / `TEST_EXIT=` / `CLIPPY_EXIT=` as the last line; grep for that token to know pass/fail.
3. **`QUELLEN/` and `REVIEWS/` are gitignored** (public-release-safety: vendored source + internal reviews never ship). Files there are local-only. Never `git add -f` them. The Babel research doc lives under `REVIEWS/` — it's local evidence, not a committed artifact.
4. **Secrets never in code/commits/logs.** Run `git diff --staged` before every commit; grep it for `api.key|password|secret_|BEGIN.*PRIVATE`.
5. **`neoth init` writes to a HARD-CODED `~/.neoth`** (ignores `NEOTH_HOME`). NEVER run it as a smoke test on this machine — it clobbers real config. Use `NEOTH_HOME`-respecting test helpers only.
6. **New WAL event type = 5 edit sites** (const + compile-time band-assert + `EVENT_NAME_TABLE` + `all_event_codes_are_unique` test + emit site). BUT: **the WAL byte space is EXHAUSTED (255/256 used).** Do not add WAL events. New subsystems (like Babel) persist to **SQLite** instead.
7. **New CLI command/flag → run the CLI-doc-drift gate** or CI fails (see §5, CLI-doc row).
8. **Multibyte safety:** never `&s[..N]` on user/LLM text → `chars().take(N)`. Never hold a SQLite/Mutex guard across `.await`. Blocking `std::fs` on the async reactor → `spawn_blocking`.
9. **Heavy parallel builds crash this box** (thermal). Build one thing at a time; keep agent panels ≤4.
10. **Model-version-agnostic HARD RULE:** never hard-code a model name/version in provider logic; selection reads the live `models::catalog`. (Relevant to Babel's K_d embedding choice — operator question, §9.)

---

## 5. Build & gate recipe (VERIFIED — copy-paste)

All wrappers live in `SRC/` and are self-contained (they set up vcvars64 + ucrt paths, `cd` into the main checkout `SRC/`, run cargo, and echo the exit token). Run them from Git Bash with a **double slash** `//c`:

```bash
# Type-check (fast, ~1-2 min):
cmd.exe //c "C:\\Users\\Shadow-PC\\CascadeProjects\\AGENTER\\SRC\\_check.bat"      # -> BUILD_EXIT=0

# Clippy — the HARD gate (-D warnings, ~2-3 min):
cmd.exe //c "C:\\Users\\Shadow-PC\\CascadeProjects\\AGENTER\\SRC\\_clippy.bat"     # -> CLIPPY_EXIT=0

# Tests — pass AT MOST ONE filter token (it's appended to cargo test -p neothd --lib):
cmd.exe //c "C:\\Users\\Shadow-PC\\CascadeProjects\\AGENTER\\SRC\\_test.bat" babel # -> TEST_EXIT=0
cmd.exe //c "C:\\Users\\Shadow-PC\\CascadeProjects\\AGENTER\\SRC\\_test.bat"       # (no filter = full lib suite, ~9500 tests, 2 min)

# Full release build:
cmd.exe //c "C:\\Users\\Shadow-PC\\CascadeProjects\\AGENTER\\SRC\\_build.bat"      # -> BUILD_EXIT=0
```

**How to run them without freezing your turn:** use your Bash tool with `run_in_background: true`, then poll the output file for the exit token. Do NOT foreground a long build with sleep loops.

**Reading the result:** grep the log for `BUILD_EXIT=` / `CLIPPY_EXIT=` / `TEST_EXIT=`. `=0` means pass. Anything else = fail; grep the log for `^error` above it.

**CLI-doc-drift gate** (only when you add/remove a CLI command or flag): set env `NEOTH_REGEN_CLI_DOCS=1` and run the test `cli_commands_md_is_up_to_date`, or regenerate and commit `docs/CLI_COMMANDS.md`. Skipping this makes CI red.

**GUI check** (only when you touch `SRC/neothd-gui/`): it's a BIN crate → `cargo check -p neothd-gui` (no `--lib`); os-clipboard feature needs `--features os-clipboard`. Copy a wrapper bat and change the cargo line if you need it.

**Per-commit minimum gate:** `_check` + `_clippy` + `_test <touched-module>`.
**Per-batch gate (before push):** `_clippy` + full `_test` + CLI-doc gate if CLI touched.

---

## 6. Findings already made — do NOT re-discover these

### 6.1 CI was red for a structural reason (fixed in `0d4024b1`)
`ci.yml` ran a bare `cargo audit` with NO ignore flags, while `security.yml` carried 7 `--ignore`s. Once RUSTSEC-2026-0187 (lopdf DoS) + RUSTSEC-2023-0071 (rsa Marvin) entered the advisory DB, ubuntu CI failed **deterministically** (not a hang — the 5h duration was runner queue). Fix: **`SRC/.cargo/audit.toml`** is now the single ignore source (both workflows call bare `cargo audit`, which reads it automatically from `working-directory: SRC`). `SRC/deny.toml` `[advisories].ignore` is the hand-synced documented mirror. **RULE: when you add/remove a RUSTSEC ignore, edit BOTH `SRC/.cargo/audit.toml` AND `SRC/deny.toml` in the same commit.** Also `quick-xml` was bumped 0.38→0.41 (RUSTSEC-2026-0194/-0195).

### 6.2 Tracker hygiene done (`24d2f96b`)
The 9 old `[~]` partial markers are gone (5 flipped `[x]` with explicit remainder items like `GOLD-ARCH-07b`; 4 flipped `[ ]` with honest status). Duplicates merged: `GOLD-PROG-16 == GOLD-FEAT-10` (verify-first proved signal/line/irc/matrix/discord/mattermost/nostr adapters ALL already exist in `channels/` — the channel-parity remainder is only BlueBubbles iMessage + Google Chat). `moazbuilds/claudeclaw` restored to the WS-G eval queue.

### 6.3 Babel formula bug (fixed in `afe2eb13`) — the pattern to watch
The `analytics/babel/` scaffolding (~1.8k LOC, 9 modules) was written in a prior session and had never been through the clippy gate or a math review. `score.rs` computed `B_mult` with the OLD formula `(C*K*M*A*V)/(D*H+ε)` — a real math bug. The correct **ratio form** (upstream fix in the delta-kosmologie repo, commit `a4bd367`) is:
- **B_log (primary):** `log(C)+log(K)+log(M)+log(A/D)+log(V/H)` (natural log; no epsilon)
- **B_mult (interpretability):** `norm((C*K*M) / ((D/A)*(H/V) + ε))`
- **B_bottleneck (stress test):** `min(C,K,M,A,V) / max(D,H)`
- **epsilon rule:** `0.01 * median((D/A)*(H/V))` over the first 10% of windows; rule tag string `0.01_median_buffer_ratio_calibration`.

**Lesson for you: the scaffolding is a DRAFT, not verified truth. Clippy-gate every file you touch in `analytics/babel/`, and re-derive any formula against the delta spec (`REVIEWS/.../delta_kosmologie_babel_2026-07-02.md` §4 + the delta repo's `protocols/babel-index.md`) before trusting it.**

---

## 7. The loop protocol (condensed — full version in `LOOP_PLAN_GOLD_FINISH.md` §4)

For each item (or small batch of same-file items):

1. **SELECT** the next item from the batch map (`LOOP_PLAN_GOLD_FINISH.md` §5, or the `## LOOP STATE` resume pointer). The operator has prioritized **B-DELTA** (Babel GOLD-DELTA-03→12) right now.
2. **VERIFY-FIRST.** grep the modules/functions the item names — do they still exist? Is it already shipped? If already done → flip `[x]` with an evidence note and move on. If the spec is stale → correct the tracker line in the same commit that ships the fix. (Refs drift constantly. This step saves the most time.)
3. **RESEARCH** (for ports): open the real source and the evidence file, read the WHOLE mechanism (constants ARE the feature), re-implement natively. License discipline: odysseus = AGPLv3 → clean-room re-implement, never paste; mnemo = MIT; operator-owned repos (Jarvis/openhuman/hermes) = free to port.
4. **DESIGN** (only for genuinely architectural items): spawn 3–4 read-only agents as a panel, synthesize, then **verify-first the panel output** (every panel run has ≥1 false premise — check each claim against the code).
5. **BUILD** fully: wired to a real production caller + tests. No placeholders, no `todo!()`, no speculative flags. Follow the Builder's-guide patterns (tracker ~L832–841: cron/config/CLI/GUI/memory/provider integration recipes).
6. **GATE:** §5 per-commit gates green. Fix everything the gate finds now.
7. **REVIEW:** run a `code-reviewer` (+ `rust-reviewer`) agent on the diff. Security surface (channels/tokens/exec/network/crypto) → `security-reviewer` too. Fix CRITICAL/HIGH now; MEDIUM if <30 min else file as a tracker item (never lose it).
8. **COMMIT** (conventional commit) — flip the tracker `[ ]`→`[x]` AND update `PLAN/PROGRESS_v1_0.md` in the SAME commit. `git diff --staged` first (secret scan).
9. **PUSH** `origin main`. Then `gh run list --limit 2` to confirm CI triggered. If a later run goes red, fixing it is the immediate next task.
10. **UPDATE** the `## LOOP STATE` block at the bottom of `LOOP_PLAN_GOLD_FINISH.md` so the next session resumes cleanly.

**Rule: the tracker `[ ]` marker is `[ ]` (open) or `[x]` (done) ONLY. No `[~]`.** If something is half-done, the shipped half gets `[x]` and the remainder becomes a new `[ ]` line with a concrete rest-spec.

**Error-hunt waves (scheduled, not optional):** after every 3 items/batches, run a review wave — parallel read-only agents over the diff since the last wave, each with a lens: (1) rust-reviewer (ownership/unsafe/async-locks), (2) security-reviewer (OWASP+STRIDE), (3) silent-failure-hunter (swallowed errors), (4) unwired-sweep (new `pub` items with 0 non-test callers), (5) logic-skeptic (re-derive each new algorithm vs its source spec). Adversarially verify every CRITICAL/HIGH before fixing (panels produce false positives).

---

## 8. Babel-Index / delta-kosmologie — what it is and the self-improvement vision

**What it is:** NEOTH is adopting Alex's own research framework `The-Geek-Freaks/delta-kosmologie` (RDelta / "Babel Index") as a **core observer subsystem**. The Babel Index `B_d` is an engineered score over 7 per-window variables that measures **loss of productive difference** — i.e. an early-warning signal for agent collapse (loops, retry storms, tool-timeout cascades, context-limit failures, semantic degradation, objective failure, tool-selection failure — 8 labels). NEOTH is the framework's first real testbed.

**Architecture (already scaffolded in `SRC/neothd/src/analytics/babel/`):** an **async observer that never blocks inference**, derives metrics only (NEVER prompt/response content), persists to **SQLite** (`views.db`: `idx_babel_windows` / `idx_babel_norm` / `idx_babel_labels`), and can optionally submit **anonymized** window records to a shared research pool over the existing iroh/Hyperswarm transport — **opt-in only** (`babel.federate = false` by default, consent-gated at AutonomyLevel ≥ Elevated).

### 8.1 The self-improvement loop (operator's vision — YES it makes sense; build it as GOLD-DELTA-13..15)

Alex's question: *"Babel should let NEOTH autonomously improve its agents, itself, and its prediction the longer it runs — and other people's participating instances share a self-improve pool through Babel. Does that make sense?"*

**Assessment: yes, and the existing design already anticipates it.** The M0–M4 model ladder in the theorem-test protocol IS a shared predictor. Encode it as three new tracker items (add them to WS-DELTA after DELTA-12), each honest about its firewall:

- **GOLD-DELTA-13 — Local Babel→capability feedback (the "gets better the longer it runs" half).** NEOTH already ships `daemon/self_improvement_collector.rs` + `daemon/capability_evolver.rs` (GOLD-TASK-07). Wire Babel window rows in as a **fitness signal**: when a config/skill/agent change is followed by sustained *lower* `B_d` (and no collapse label within the horizon), reinforce that change; when followed by *higher* `B_d` or a collapse label, flag it for review. More runtime → more windows → better-calibrated `idx_babel_norm` p1/p99 → sharper `B_d` → sharper collapse prediction. **Local only, no egress. Advisory: it proposes, the operator's autonomy level decides whether it auto-applies (same gate as every other self-improvement action).** Effort: M. Depends on DELTA-03/04 (need windows landing in SQLite first).
- **GOLD-DELTA-14 — Federated predictor download (the "everyone shares a pool" half).** Today the federation path only *submits* telemetry (DELTA-10). Add the return path: an instance can *pull* the pooled M0–M4 predictor coefficients (out-of-sample validated across many instances) and use them as an **advisory early-warning from day 1** — a fresh install predicts collapse using the collective's learning instead of waiting to self-calibrate. **Firewall (must be enforced, not optional): the pooled predictor is ADVISORY, never auto-acts; cross-domain comparison is forbidden (`B_neoth` ≠ `B_oss`); poisoning defense = signed records + outlier rejection (already designed in `federation.rs`/`anonymize.rs`); pulling is the same opt-in consent gate as submitting.** Effort: L. Depends on DELTA-10.
- **GOLD-DELTA-15 — Prediction self-calibration (optional, the "prediction improves" half).** Track whether `B_d > threshold` actually preceded a collapse label within horizon h; feed the Brier/log-loss back into a simple online threshold adjustment; log every adjustment. This is what makes the prediction measurably better over time rather than just accumulating data. Effort: S–M. Depends on DELTA-07 (labels) + DELTA-13.

**The one caution to keep straight:** the telemetry has TWO consumers — (a) the *theorem test* (does the Babel Index actually predict collapse? — the M0–M4 falsification ladder) and (b) the *self-improvement loop* (use the signal to make NEOTH better). Do not conflate them: "we improved the agent" is not "we proved the theorem." Keep the two code paths and their claims separate. The theorem test can even *fail* (B_d turns out not to beat the M0 baseline) while the self-improvement loop still works on whatever signal survives.

### 8.2 Babel build order (operator-prioritized — this is your current work)
DELTA-01 ✅, DELTA-02 ✅ done. Now, in order:
- **DELTA-03** cron tick logic (`analytics/babel/cron.rs`: accumulate features per window, close windows, `BabelScores::compute`, persist to SQLite, 15-min threshold check).
- **DELTA-04** daemon spawn (`daemon/babel_cron.rs`: `spawn_babel_cron_loop(...) -> Option<JoinHandle>`, None when disabled; scan WAL via `wal::scan::for_each_frame`; wire into `main.rs` beside `spawn_monitor_cron_loop`).
- **DELTA-05** norm refresh sweep (7-day p1/p99 per variable → `idx_babel_norm`, every 5 min).
- **DELTA-06** epsilon calibration freeze — NOTE: `norm::compute_calibration_epsilon` **already exists** (buffer-ratio version, fixed in `afe2eb13`); DELTA-06 is just wiring it to run once after MIN_SAMPLES and persist to `freedom.yaml`.
- **DELTA-07** collapse-label persistence (`persist_label` + `post_hoc_label_pass`).
- **DELTA-08** export pipeline (`analytics/babel/export.rs` + `neoth babel export` CLI — remember the CLI-doc gate).
- **DELTA-09** CLI surface (`neoth babel status/windows/label/enable/disable`).
- **DELTA-11** GUI SSE hook (push `BabelWindowComputed` over `kanban_sse`).
- **DELTA-12** integration test suite (`tests/babel_cron_integration.rs`).
- **DELTA-10** federation submission — build LAST, and only after the operator answers question 3 (§9). It's the only egress path.
- Then **DELTA-13/14/15** (the self-improve loop, §8.1).

Full per-item file paths, struct names, and tests are in `REVIEWS/_gold_audit/research/delta_kosmologie_babel_2026-07-02.md` §4 — read the item there before building it.

---

## 9. Operator decisions needed (park these — do NOT guess; ask Alex, keep building everything else)

From the Babel research doc §6, plus the loop plan §9. Present them, keep working on unblocked items, record each answer as a dated tracker line.

1. **K_d embedding source** (blocks the higher-fidelity K_d, not the v0). Model-agnostic rule forbids hard-coding a model. Options: (a) reuse the runtime's own last-layer activations (zero external dep), or (b) an optional named sentence-transformer with token-frequency-histogram fallback (`K_d_v0`, already in `feature.rs`). Default while unanswered: keep `K_d_v0`.
2. **D_d v1 (embedding-based differentiation):** post-GOLD milestone, or config-gated alternative now? Default: keep `D_d_v0` (binary schema-conflict flag, already in `feature.rs`).
3. **Federation wizard opt-in (blocks DELTA-10 scope):** offer federation opt-in in the v1.0 onboarding wizard, or defer to a post-v1.0 GUI panel? Default `federate = false`; build DELTA-10 wiring but leave the wizard step out until answered.
4. **Semantic labels (`semantic_degradation`, `objective_failure`):** automatic detection needs K_d infrastructure; is human-confirmation-only acceptable for v0 (`persist_label(human_confirmed=1)`)? Default: human-confirm-only.

Other standing operator-blocked items (loop plan §9): `GOLD-PROG-13` (run `neoth release setup` for the minisign keypair — needs the operator on the release machine), `GOLD-PROG-15` (Chrome-DevTools-MCP license go/no-go), `GOLD-HR-00` (host-level headroom install), release tag timing.

---

## 10. The rest of the road (after B-DELTA) — batch map summary

The full batch map with per-item detail is `LOOP_PLAN_GOLD_FINISH.md` §5. Order after Babel:
- **B2** global verify-first sweep (kill phantom/already-done items).
- **B3** wiring & unwired-primitive audit (GRILL-02/04 need production callers; `GOLD-ADAPT-G-02` full shipped-but-unwired sweep).
- **B4** memory/context core (SPEAKR/TRAIL/ODY-26 + finish `GOLD-ARCH-07b` time-helper migration).
- **B5** loop engine (`neoth loop` CLI + `loop_engine/`).
- **B6** task pipeline & sovereign mode.
- **B7/B8** GUI waves (components + panels) — **close each with the design-taste gate:** run the `impeccable` `/audit` skill + `design-review`; no default-AI-slop UI.
- **B9** channel parity remainder (BlueBubbles iMessage + Google Chat only — everything else exists).
- **B10** media/voice (VAD, model download manager, dictation).
- **B11** security/API surface (scope-gated API tokens, remaining JV-SEC skills, paperless pipeline) — security-reviewer mandatory.
- **B12** skill bundles (`assets/skills/` — port prompt content verbatim-quality).
- **B13** RMAS experimental sidecar (strictly gated).
- **B14** big features (self-wiki finish, migration-first onboarding, self-reprogramming with its 5-layer safety stack, swarm dashboard).
- **B15** WS-G eval-repo queue (8 repos: knowledge-work-plugins, ai-engineering-from-scratch, compound-engineering-plugin, ECC, Anthropic-Cybersecurity-Skills, Scrapling, stop-slop, adhd, + claudeclaw) — gremium deep-read each, verdict + implement adopts, record skips in `QUELLEN/DO_NOT_ADOPT.md`.
- **B16** Jarvis + Veronica live re-sync (`ssh tgf@192.168.178.117` key-auth works; Veronica `tgf@100.86.138.18`) — pull deltas since 2026-06-12, deep-read, mine new features.
- **B17** release gate: tracker §5 checklist all `[x]`, CI green on 3 consecutive pushes, 2× error-hunt wave comes back empty, docs-honesty pass, signed artifacts, seed `PLAN/ROAD_TO_1_1.md` from deferred items, tag `v1.0-gold`.

---

## 11. Recovery (if you crash / reconnect mid-work)

- Dirty tree after reconnect: do NOT reset. `git status -sb` + `git diff --stat` to size it, run the §5 gates on the dirty tree, commit the completed slices with correct tracker flips, `git checkout -p` away only broken fragments, push.
- Bash flakiness after reconnect (compound/pipe commands break): issue single simple commands; the `desktop-commander` MCP is a fallback shell.
- `.git/index.lock` stuck: kill stray git processes, then `rm .git/index.lock`.
- The durable state is the tracker + the `## LOOP STATE` block. A fresh session re-bootstraps from §12 in minutes. Update `LOOP STATE` before any risky long operation.

---

## 12. START HERE (do this first, every session)

```bash
cd C:/Users/Shadow-PC/CascadeProjects/AGENTER
git fetch origin && git status -sb        # must be main; if "behind": git pull --ff-only
git log -3 --oneline                      # orient (expect afe2eb13 or later)
grep -nE '^- \[ \]' PLAN/ROAD_TO_1_0_GOLD.md | head -40   # live open items (do not trust any cached count)
```

Then:
1. Read `PLAN/LOOP_PLAN_GOLD_FINISH.md` fully (playbook) — especially §4 (protocol), §5 (batch map), and the `## LOOP STATE` block at the bottom (resume pointer).
2. Current focus per operator: **B-DELTA / GOLD-DELTA-03** (Babel cron tick). Read its spec in `REVIEWS/_gold_audit/research/delta_kosmologie_babel_2026-07-02.md` §4 before coding.
3. Run the loop (§7). Build DELTA-03 → 04 → 05 → 06 → 07 → 08 → 09 → 11 → 12, then 10 (after operator Q3), then 13/14/15 (the self-improve loop, §8.1).
4. After every 3 items: error-hunt wave. Keep CI green. Update `LOOP STATE` and push.

**You have graphify** (`cd SRC/neothd/src && py -m graphify query "<q>"` / `explain <node>` / `affected <node>` — ~276× cheaper than blind grep for structure questions; refresh with `py -m graphify update .`). **You have agent panels** (spawn ≤4 read-only agents for research/review, verify-first their output). **You have the g-stack skills** (`/review`, `/cso` security, `/codex` cross-model, `/design-review`) — auto-fire the phase-matched one.

**Definition of done (the 12/10 bar):** tracker 0 open (except the operator-decision park list); tracker §5 release gate all `[x]`; CI green 3 pushes running; error-hunt wave returns zero CRITICAL/HIGH twice; GUI passed the taste audit; WS-G repos verdicted; Jarvis/Veronica delta mined; docs honest; signed artifacts; `v1.0-gold` tagged (operator-confirmed).

Build it fully. Wire everything. Verify before claiming done.
