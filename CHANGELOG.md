# Changelog

All notable changes to NEOTH are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-05-20 — Initial public release

First public release. Initial commit `a879665` (force-pushed over a
prior placeholder) followed by 14 commits closing audit findings,
shipping the Code Sessions GUI tab, and hardening the security
surface. https://github.com/The-Geek-Freaks/NEOTH

### Added

- **Code Sessions GUI tab** (Pick #8, all six steps shipped):
  static layout → CLI JSON output → Slint model + subprocess binding
  → activity feed WAL parsing → 2s live-tail timer → click-to-detail
  pane → operator action buttons (move + promote). Comment + assign
  defer to v0.2 because they need modal text-input UIs.
- **Worker dispatcher** (Pick #6 Phase 1 + Phase 2):
  - `coding::Worker` trait + `WorkerOutcome` types
  - `HemisphereWorkerSet` builder + `DispatchBudget` (30 min / 20 task
    defaults) + `dispatch_session()` orchestrator with reentrant
    BACKLOG-drain semantics
  - Concrete `LeftWorker`/`RightWorker` impls (Phase 3) pending the
    Chorus verdict on patch-safety (`PLAN/CHORUS_dispatcher_design.md`)
- **LLM second-opinion classifier** (Pick #9) — `coding::second_opinion_classify()`
  routes Ambiguous-bucket tasks to a focused FAST/DEEP prompt against
  the Cerebellum LLM; defaults to Deep on garbage replies (safer
  escalation for unclear intent).
- **Plugin pre-flight + dispatch outcome shape** (Pick #34 follow-up)
  — `wasm_plugin::dispatch::compile_all_discovered()` walks the
  discovery report + compiles every plugin against the live wasmtime
  engine. `InvocationOutcome` is the stable wire shape the hook engine
  pattern-matches before the live `Instance::call_typed_func` lands.
- **Discord gateway session helpers** (Pick #37 follow-up) — pure
  helpers the live WSS loop needs: process-wide `SESSION_ID` tracker,
  `should_resume_after_close()` per Discord's close-code table,
  `is_terminal_close()` for operator-actionable codes, and
  `ReconnectTracker` with `next_delay()` + `record_success()`.
- **Migrator inventory readers for LanceArrow + GitTree** (Pick #35
  follow-up) — pure-Rust scans replace the deferred
  `ReaderNotImplemented`; operators get real dataset / repo counts
  in `neoth migrate scan`. Real row reads land when the Phase-3
  C-dep block (`lance`, `git2`) is allowed.
- **WAL event code `0x77 KANBAN_TASK_PROGRESS`** reserved for the
  dispatcher's 30s heartbeat frame (Q2 verdict).
- **MCP allowlist secure-by-default** — new `trust_all_tools: bool`
  field on `McpServerConfig` (default `false`). The gate denies
  `allow_tools=None && trust_all_tools=false` with
  `GateError::MissingAllowlistSecureDefault` + a `neoth doctor`
  warning that surfaces the broken bucket with an actionable fix
  string. Was a silent pass-through that let a compromised MCP
  subprocess expose arbitrary new tools to the LLM.
- **WASM memory limiter actually enforced** —
  `PluginStoreState::memory_limit_bytes` (default 64 MiB) is now wired
  to wasmtime's `Store::limiter()`. A plugin calling `memory.grow` in
  a loop traps instead of OOM-killing the host. Was dead config
  before.
- **Webhook anti-fragility test pack** (T-SEC-002) — 9 new edge
  tests in `channels::webhook_verify`: empty query, truncated `%XX`,
  bare key without `=`, `&&` separator runs, unknown future keys,
  mixed `+`/`%20`, far-past + future + non-numeric Slack timestamps.
  Pins that the parser never panics + timestamp errors precede
  signature checks (no side-channel leak).
- **Letter-spacing design tokens** —
  `Theme.letter-spacing-tight/wide/extra-wide/brand-bar` replace 31
  hardcoded `1px`/`1.5px`/`2px`/`4px` values across `chat.slint`,
  `components.slint`, `main.slint`, `settings.slint`.

### Changed

- **GUI v0.1 polish (26 of 27 audit findings closed):**
  - WCAG AA contrast: `text-dim` raised `#6b6b6b` → `#909090`
  - Identity field validates `^[a-z0-9-]{3,32}$` via Rust round-trip;
    Continue gate respects the verdict
  - Channels screen disclosure: 8 disabled rows hide behind "Show
    future channels" toggle (DAUs see a two-row screen)
  - Chat composer gets a persistent "MESSAGE" label + shorter
    placeholder + helper line
  - Custom `NeothComboBox` + `NeothCheckBox` + `NeothLineEdit` replace
    `std-widgets` light-mode defaults
  - `← Chat` Back button on the Settings panel
  - `← Mode` Back button on the Welcome screen
  - Channels list now lists every supported channel honestly:
    CLI / Telegram (v0.1) / WhatsApp (v0.2+) / Slack / Discord / Keet
    (v0.3+) / Signal / Matrix / LINE / iMessage (planned)
- **`verify.rs` filename marker** — `REDACTION_MARKER` payload stores
  `Path::file_name()` only; the verifier normalises both sides
  through `file_name()` so `--wal-dir ./relative` against
  absolute-form markers stops false-FAILing.
- **`run_verify` refactor** — 113-line monolith split into a 28-line
  orchestrator + three pure helpers (`collect_authorised_ranges`,
  `verify_segments`, `render_verify_outcome`) + `VerifyOutcome`
  carrier struct.
- **Webhook duplicate-key semantics documented** — last-write-wins
  matches the URL Standard / URLSearchParams contract;
  `tracing::warn` fires when a duplicate is detected (proxy /
  Meta config drift signal).
- **Frameless titlebar spec relaxed** — `docs/superpowers/specs/
  2026-05-15-neoth-uix-design-system.md` §4.1 now documents OS-native
  chrome as the v0.1 default + frameless as v0.2+ opt-in.

### Documentation

- `PLAN/CHORUS_dispatcher_design.md` — Pick #6 architecture draft +
  Chorus-worthy questions (patch safety, streaming cadence, REVIEW
  gating, cycle prevention).
- `PLAN/REVIEWER_GUI_AUDIT_2026-05-20.md`,
  `PLAN/REVIEWER_SECURITY_VERIFY_2026-05-20.md`,
  `PLAN/REVIEWER_VERIFY_AUDIT_2026-05-20.md` — three parallel audit
  reports from a11y-architect, security-auditor, code-reviewer.
- `PLAN/CHANNELS_SPEC_2026-05-20.md` — authoritative shipping matrix
  + GUI gap analysis for every messenger.
- `PLAN/GUI_AUDIT_2026-05-20.md` — full 27-finding GUI audit.

## [Unreleased]

### Added
- Day-1 cargo workspace, `neothd` binary, panic handler, banner
- Day-3 CLI scaffolding via clap 4.5 (`neoth init` wizard skeleton)
- `freedom.yaml` and `policy.yaml` templates (operator-agnostic)
- `umask 0o077` startup hardening (unix)
- Tracing via `tracing-subscriber` with `NEOTH_LOG` env filter
- Rust 2024 edition, MSRV 1.86

### Documentation
- 23 normative specs in `PLAN/` covering wire format, WAL lifecycle, skill plugins, proactive learning, recall parity, local inference, council governance, channels, profile claim guard, mirror refusal
- Adversarial review reports in `PLAN/ADVERSARIAL/` (10 agent reports + summary)
- User-facing docs in `docs/` (getting-started, configuration, channels, profile, council, plugins, local-models, architecture, faq, troubleshooting, cli-reference)
- Install scripts for Linux/macOS (`scripts/install.sh`) and Windows (`scripts/install.ps1`)

### Security
- Initial threat model documented in `SECURITY.md`
- Adversarial findings catalogued (S/H/A class) with status in `PLAN/ADVERSARIAL/00_SUMMARY.md`

## [0.1.0] — Unreleased

First public preview. Not yet feature-complete. Daemon builds green, CLI wizard scaffolded, WAL writer pending.

**What works (Day-1 -> Day-3):**
- `neothd` builds and runs, prints banner
- `neoth init` wizard skeleton (interactive prompts not yet wired to disk writes)
- CLI subcommand structure via clap

**What does not work yet:**
- WAL writer (Day-2 -- pending)
- Telegram channel (Day-7 -- pending)
- WhatsApp, Slack (Day-8, Day-9 -- pending)
- LLM provider adapters (Day-5 onwards -- pending)
- Local Qwen3-4B inference (Day-14 -- pending)
- Council pipeline (Phase 2 -- pending)
- WASM plugin host (Day-23 -- pending)
- Phase-3 migration tooling (Day-63 -- pending, pure-Rust)

See `PLAN/00_DESIGN_v1.1_FINAL.md` Section 10 for the full Day-1 to Day-90 roadmap.

[Unreleased]: https://github.com/owner/neoth/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/owner/neoth/releases/tag/v0.1.0
