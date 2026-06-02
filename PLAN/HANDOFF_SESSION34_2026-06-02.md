# NEOTH — Session 34 Handoff

> Written at the end of Session 33 (2026-06-02). Read this first; it makes a
> fresh session productive in ~10 minutes. Self-contained + repo-relative
> (no machine-specific paths). The **authoritative live tracker** is
> [`PLAN/PROGRESS_v1_0.md`](PROGRESS_v1_0.md) — this handoff summarises +
> orients, it does not replace it.

---

## 0. What NEOTH is (orientation)

NEOTH is a **self-contained sovereign-AI Rust daemon** on the road to v1.0:
a personal AI that runs on the operator's own hardware, talks to LLM
providers (claude-cli/OAuth = cost-free default, plus native cloud
adapters), keeps an **HMAC-chained append-only WAL** as the audit/loyalty
substrate, learns a profile, dreams/reflects, routes a 3-hemisphere
"council", exposes channels (Telegram/Slack/WhatsApp/Discord), a skill +
wasm-plugin system, a coding workflow, optional cluster mode, and a Slint
GUI. Everything ships in-binary or auto-installs (the "non-technical user
on a fresh Win11 laptop" DAU bar). Public OSS at `The-Geek-Freaks/NEOTH`.

**Workspace layout (`SRC/`):**
- `SRC/neothd/` — the daemon + CLI (the bulk; `src/cli/`, `src/daemon/`,
  `src/wal/`, `src/providers/`, `src/memory/`, `src/profile/`, `src/council/`,
  `src/coding/`, `src/channels/`, `src/skills/`, `src/proactive/`,
  `src/config/`, `src/permissions/`, `src/security/`, …).
- `SRC/neothd-gui/` — Slint GUI (separate crate; not headless-verifiable).
- `SRC/neoth-migrate/` — standalone prior-AI-memory import binary.
- `SRC/neoth-relay/`, `SRC/neoth-plugin-sdk/` — relay + plugin SDK crates.

**Authoritative docs:**
- `PLAN/PROGRESS_v1_0.md` — the LIVE v1.0 tracker (read the open `[ ]`/`[~]`
  items here). NOT `PLAN/PROGRESS.md` (892 KB historical archive).
- `PLAN/00_DESIGN_v1.1_FINAL.md` + `PLAN/SPEC_*.md` — authoritative spec.
  `v1.0_FINAL` despite the name is NOT final.
- `docs/cli-commands.md` — GENERATED CLI reference (drift-guarded; never
  hand-edit unless matching the generator exactly).
- `docs/security/threat-model.md`, `docs/operator-journey.md`.

---

## 1. ⚠️ BUILD / VERIFY REGIME — read before ANY cargo command

**The operator's PC BLUESCREENS on uncapped MSVC builds** (rusqlite-bundled
C compile + parallel codegen pegs all cores → thermal/kernel crash). This is
hardware, not NEOTH. **Rules:**

- **ALWAYS prefix builds with `CARGO_BUILD_JOBS=2`** (halves peak load; the
  PC survives capped, crashes uncapped). This is non-negotiable.
- **Gentle-mode default = `cargo check`** (typecheck only, no codegen/link —
  the lightest stage). Use it for routine verification.
- **Full `cargo test` only with the operator's explicit GO** ("wieder cargo"
  was a standing GO this session, but still cap jobs). Tests are the heavy
  compile (codegen + link) — the crash-risk step.
- Build wrapper: `powershell.exe -ExecutionPolicy Bypass -File scripts/cargo-msvc.ps1 <subcommand> ...`
  — NO leading `cargo`; the PS wrapper has a `-D` switch + repairs `-- -D
  warnings`; positional `-p neothd` works for check/test/clippy. Builds to
  workspace `SRC/target/`. (`cargo update -p` is the one place the wrapper
  drops `-p` → use the `--precise X` positional form.)
- `NEOTH_LOG=error` for any path that parses neothd stdout as JSON (the
  daemon logs to stdout; a banner corrupts JSON parsers — GUI/test seam).

**WAL event discipline** (a new event needs ALL of):
1. `pub const EVENT_TYPE_X: u8 = 0xNN;` in `wal/events.rs` (pick a FREE slot
   in the SEMANTICALLY-CORRECT band — band comment at top of events.rs).
2. A band-membership `static_assert` (the `[(); 1][...]` block).
3. An `EVENT_NAME_TABLE` entry (`("X", EVENT_TYPE_X)`) → gives
   `neoth wal show --type x` (lowercased).
4. A real EMIT site (the SC-01a `tests/wal_emit_sites.rs` guard fails on a
   defined-but-unemitted const). `all_event_codes_are_unique` catches
   collisions. `needs_immediate_sync` is wildcard-default-TRUE (batchable
   denylist) — rare advisories can stay default.

**docgen drift:** any CLI flag/subcommand change → regen with
`NEOTH_REGEN_CLI_DOCS=1 CARGO_BUILD_JOBS=2 <wrapper> test -p neothd cli_commands_md_is_up_to_date`
(the `cli_commands_md_is_up_to_date` test fails until regenerated). A
cargo-fmt PostToolUse hook reformats `.rs` after edits — re-Read before the
next Edit.

---

## 2. What shipped in Session 33

**The full operator-leak cleanup (public-release scrub) — DONE + validated:**
- User-facing strings (CLI `neoth doctor --explain`, wizard asset
  placeholders, GUI hint), machine names/IPs (`policy/mod.rs` leaked a real
  IP), home paths (`/home/<user>`), doc-comment examples — all genericised.
- **A live GitHub PAT was redacted** from `PLAN/S10_PAT_REVOCATION.md` +5
  PLAN docs (it had been public since the initial-release commit; GitHub
  secret-scanning auto-locked it — operator should still rotate whatever it
  accessed). It remains in git HISTORY.
- 530+49-edit bulk genericisation across the tree (8 parallel disjoint-file
  editor agents → one capped build-verify), with assertion-lockstep on
  fixtures.
- **Jarvis-feature genericisation:** `neoth-migrate` is now manifest-driven
  (operator declares stores in `import-manifest.yaml`; the hardcoded
  personal-path `STORES` table is gone; see
  `SRC/neoth-migrate/examples/import-manifest.example.yaml`); dead
  `neothd/src/migrate/mod.rs` schema deleted; `--import-jarvis` →
  `--import-memory`; env-scrub `HARNESS_PREFIXES` (was a hardcoded
  personal-gateway prefix list) → `freedom.yaml::claude_cli.scrub_env_prefixes`
  (default EMPTY). **ZERO operator-name / personal-gateway-prefix strings
  remain in `SRC/`.**

**3 v1.0 features shipped (each pure-core + injectable tick + gated spawn +
WAL-in-correct-band + serve wire + ~6-8 tests, all green):**
- **GR-10** `neoth security safe-mode [--json]` — `collect_rails(&FreedomConfig)`
  surfaces 7 safety rails (`[ENGAGED]`/`[RELAXED]`). Consumer = the command
  (like SC-04 audit). `src/cli/security.rs`.
- **KF-04** Idle-Time Skill Forge — `daemon/skill_forge.rs`
  `forge_skill_from_dream(&Dream) → Option<ProposedAction{kind=Skill}>`,
  wired into `cli/dreaming_task::run_pass` (gated `dreaming.forge_skills`,
  default off) → OB-03 `proactive_queue.json` → `neoth proactive review/accept`.
- **SL-03** ResourcePressureWatcher — `daemon/resource_watch.rs` VRAM>threshold
  cron + `0x47 RESOURCE_PRESSURE_ALERT`; `freedom.yaml::resource_watch`
  (default off); consumer = `neoth wal show --type resource_pressure_alert`.

Full lib suite **6521/0** at session end. Operator memory holds detailed
session burndowns (`neoth_session33_burndown`).

---

## 3. The OPEN + DEFERRED backlog (the core — what to work next)

Bucketed from the Session-33 ground-truth triage (22 candidate items, one
code-reading agent each). **Always verify a `[~]`/`[ ]` against code before
building — many `[~]` have a shipped core + a small open tail, and the triage
caught several "stale" verdicts that grep overturned.**

### 3a. BUILD-NOW (reachable, real consumer, headless-verifiable)
- **HO-07** `neoth-monitor` alerting sidecar — 5 trigger rules (pure fns over
  WAL stats) + new WAL events (the spec's `0x3C-0x3F` partly CLASH —
  `0x3C`=CHANNEL_PRIVILEGE_BLOCKED, `0x3E`=EVAL_CRITICAL_DIVERGENCE are taken;
  only `0x3D`/`0x3F` free there, OR use the cron band `0x48..0x4F`). **Same
  cron recipe as SL-03/drift_alert** — the well-grooved pattern. *The
  recommended next pick.*
- (Re-triage the rest of `PROGRESS_v1_0.md` `[ ]`/`[~]` against code — the
  cron-feature recipe makes several reachable WITH their consumer.)

### 3b. PRIMITIVE-AHEAD (buildable but NO live consumer — DON'T until it exists)
Building these now produces an unexercised path that drifts (the SC-04/SD-04
trap the session hit repeatedly). Build the consumer in the SAME slice:
- **PL-05b** email-threat LLM 2nd-opinion — `assess_email_threat` has no live
  producer (EM-01 IMAP not wired).
- **EM-02b** CalDAV calendar — Google network layer itself not wired yet.
- **OP-01** hashline edits — upstream source not in QUELLEN + no `cli/edit.rs`
  + gated on SD-04. **OP-03** LSP loop — gated on OP-01.
- **KF-05** cross-channel memory unification — both ends absent.
- **SD-04** cerebellum routes recall — `run_routed_recall` zero callers
  (gremium DEFER, build immediately before OP-01).
- **ADV-08**, **ARCH-06** (HLC skew) — gremium DEFER (wrong layer / no
  consumer / blast radius).
- **SPEC-10** last slice (CouncilStrategy), **QU-10c** — gremium DEFER.
- **ADV-14** regression-anchor — semi: the cron is a no-op until the operator
  creates the day-30 anchor file (operator-operational).

### 3c. BLOCKED ON OPERATOR / CI (cannot ship until an external action)
- **minisign keypair** (CI) blocks: KF-03 `--sign` proof bundle, MV-01b
  unattended self-replace, MAR-02 signed launch artifacts, A3-01 `--sign`.
  (The verify infra + `minisign-verify` dep already ship; only the release
  keypair `NEOTH_RELEASE_MINISIGN_PUBKEY` + the release.yml signing step are
  pending — an operator CI action.)
- **OM-01** OMI ingest — needs a self-hosted local OMI backend (operator infra).
- **PC-02** Chrome DevTools MCP plugin — needs a license confirm pre-merge.
- **ARCH-05/SPEC-08** live half — the recall-parity GATE + runbook shipped;
  the 14-day shadow-run + 4-grader grading + cutover are operator-operational.

### 3d. GUI-ONLY (needs a real display / browser-qa — not headless-verifiable)
GU-01 (settings panels), GU-02 (cyber-brand polish), the GR-10 rails panel,
KF-08 budget-meter panel, SL-02/SL-03 resource+topology tabs, MV-01c model
picker, SPEC-05/06/12 GUI surfaces, PF-01-GUI.
**Pattern for GUI work** (proven this road-to-1.0): extract the logic into a
PURE Rust module in the gui crate (zero Slint dep), unit-test it, bind the
`.slint` to it; `slint-build` compile-validates the property bindings (a
wrong name/type fails the build = real binding-correctness proof; pixels =
manual smoke). Defer pixel-verify to a display session.

### 3e. DEFER MULTI-WEEK (large / cross-cutting / under-specified)
ARCH-01 (Tailslayer vector store), F4-01 (Ecology-Schicht scanner, v1.x),
SPEC-12 (R-02 LLM clustering Phase 3), SPEC-11 (cross-channel identity +
LiveDelivery Phase-2 adapters), TD-02-rest (CalDAV + MS-To-Do todo backends),
multimodal IMPL (MM-01b voice / MM-02b video / MM-03b TTS — heavy deps),
EM-01b (live IMAP — ~12-crate OpenSSL dep expansion), PF-03 create slice
(document generation). KF-04 follow-ons (auto-write skill on accept).

---

## 4. Pending operator decisions / actions (surface to the operator)
1. **Rotate** whatever the leaked GitHub PAT could access (GitHub auto-locked
   it, but assume compromised — it's in git history + was public ~12 days).
2. **Provision the minisign release keypair** (unblocks all of §3c-minisign).
3. **GUI work** needs a session with a real display / browser-qa.
4. Operators relying on the old env-scrub must add their gateway prefixes to
   `freedom.yaml::claude_cli.scrub_env_prefixes` (the previously-hardcoded
   personal-gateway prefixes are gone).

---

## 5. Durable conventions / gotchas (project knowledge)
- **Verify-first overturns the tracker.** Many `[x]` were stale-already-done;
  many `[~]` have a shipped core + a tiny open tail. grep + read code before
  building OR before trusting an effort estimate. Flip stale checkboxes.
- **No-deferring-roadblocks** (hard rule): fix a roadblock in scope; defer
  ONLY genuinely multi-day work, with a real lane assignment.
- **PROGRESS update in the SAME turn** as the ship (hard rule).
- **Gremium for design decisions** (operator preference): 3-4 parallel
  senior-dev agents (distinct lenses), synthesise consensus — don't decide
  solo on tradeoffs/architecture. **GOTCHA:** a stop-hook eats bare
  standalone-Agent final messages (they return "approve") → use the
  **Workflow** tool with schema'd output for panels, OR re-emit via
  `SendMessage(agentId)`.
- **Primitive-ahead trap** is the #1 recurring mistake — build the consumer
  in the same slice, or pick a different item.
- **WAL band semantics matter** — don't mis-band an event; reuse an existing
  event where semantically correct (e.g. KF-04 dropped its spec'd `0x78/0x79`
  because they sat in the kanban band AND OB-03 proposals carry no
  per-proposal WAL by design).
- **Communication:** the operator's UI renders `SendUserMessage`
  unreadably — reply in plain chat text (his standing global rule), German
  register, code/diff over prose. He reads plain text fine.
- **The cron-feature recipe** (now well-grooved — GR-10/KF-04/SL-03/drift):
  pure testable core → injectable-input tick (so it's unit-testable without
  the live source) → `spawn_*_loop` returning `None` when a default-OFF
  config flag is unset → WAL event in the correct band → `serve.rs` spawn +
  shutdown abort → ~6-8 tests → `CARGO_BUILD_JOBS=2` check then (with GO) test.

---

## 6. Suggested first moves for Session 34
1. **HO-07 monitor sidecar** (the grooved cron pattern; just find free WAL
   slots — the spec's 0x3C-0x3F partly clash).
2. Re-triage `PROGRESS_v1_0.md` open items against code for the next
   BUILD-NOW batch (the triage-workflow pattern from Session 33 works well).
3. The minisign-blocked artifact/signing items once the operator provisions
   the keypair.
4. The GUI batch when a display is available (use the pure-module + slint-build
   binding pattern).
