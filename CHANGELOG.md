# Changelog

All notable changes to NEOTH are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] — 2026-05-21 — Post-v0.1 follow-up sprint

After the v0.1 release force-push (commit `a879665`), this sprint
closed the dispatcher chain, the WASM-plugin-hook loop, four
multi-day backlog items, and shipped the example plugin fixture.
Every commit pushed to `origin/main`.

### Added (Session 19 — 2026-05-21 follow-on)

- **Smallcode port #2 `coding::model_profile`** — `KNOWN_PROFILES` table mirrored from smallcode (gemma-4 / gemma-4-e4b / qwen3 / qwen2.5-coder / deepseek-coder / codellama / llama-3 / mistral-nemo / starcoder). `ModelProfile { context_length, max_output, supports_tool_calling, tool_format, strengths, weaknesses, matched_key }`. `ToolFormat::{Native,Hermes,Json,Xml,Text}`. Fuzzy matcher with longest-key-wins semantics (`huihui-gemma-4-e4b-it-abliterated` → `gemma-4-e4b`). `needs_two_stage_router()` gates port #5.
- **Smallcode port #3 `security::redact`** — 11 secret-shape regexes (Anthropic / OpenAI / Bearer / GitHub PAT+OAuth / Google API / AWS / JWT / Slack-Discord-Telegram / `.env KEY=VAL` / PEM blocks). `redact_text(&str) -> String` + `redact_if_secret(&str) -> (String, bool)`. Wired into `coding::dispatcher::handle_retryable_failure` + every `wasm_plugin::dispatch::invoke_plugin` error path so provider diagnostics + plugin trap messages no longer leak literal secrets to the WAL.
- **Smallcode port #4 `coding::validate`** — patch-shape validator. `PatchValidation::{Valid, Empty, Malformed { reasons }}`. Five shape rules catch small-LLM failure modes (no marker / mismatched `---`-vs-`+++` count / hunkless headers / hunk-without-body / trailing header). Wired into `coding::review::auto_promote_if_green` + the session sweep — even green tests can't promote a malformed on-disk patch to DONE.
- **Smallcode port #5 `coding::tool_router`** — `ToolCategory::{Read,Write,Search,Run,Plan,CodeIntel}` + `RoutingMode::{Direct,TwoStage}` + `TWO_STAGE_THRESHOLD = 16_384` (inclusive). `routing_mode(ctx_length, env_override)` decision fn with `NEOTH_TOOL_ROUTING=direct|two_stage` operator override. `build_selector_prompt()` Stage-1 menu. Not a tool registry — slots in when NEOTH's MCP surface adds canonical names.
- **Discord Gateway live WSS receive** — `channels::discord_gateway_loop::run_gateway_loop` is the operator-runnable end. `tokio::select!` over `stream.next()` + heartbeat ticker (Discord's `heartbeat_interval` HELLO field; fallback 41 250 ms). IDENTIFY vs RESUME decision via `current_session_id()`. MESSAGE_CREATE → handler → `OutboundSender` closure → `chat.create-message` REST. `DiscordChannel::run` no longer returns `Deferred`. Free-function `channels::discord::post_to_discord` extracted so the loop closure captures `Arc<reqwest::Client>` + `Arc<SecretString>` without holding the whole adapter.
- **V03-09 self-update Phase 2a + 2b** — Phase 1 (check-only) shipped previously. This session closed the apply chain end-to-end:
    - `LatestRelease.assets: Vec<ReleaseAsset>` + `ArchiveFormat::{Zip,TarXz,TarGz}` + `host_target_triple()` + `expected_asset_name(binary, target)` + `find_matching_asset` + `find_sha256_companion` + `resolve_update_assets`.
    - `parse_sha256_companion(text)` (accepts `<hex>  <filename>` and bare-hex forms; rejects truncated digests) + `verify_sha256_bytes(bytes, expected_hex)`.
    - `extract_zip_binary` / `extract_tar_xz_binary` (pure-Rust via `lzma-rs`) / `extract_tar_gz_binary` (via `flate2`). Both top-level + nested `<binary>-<target>/<binary>` archive shapes accepted.
    - `atomic_replace_binary(new, target)` with `target → target.bak.<unix_ms>` rollback path.
    - `apply_downloaded(bytes, companion, format, binary, install_dir)` pure-bytes-in orchestrator + `apply_update(release, target_triple, binary, install_dir)` network wrapper.
    - `freedom.yaml::auto_update` config block (`enabled` / `auto_apply` / `channel` / `check_interval_secs` / `repo` / `target_triple`). Default-OFF for both flags.
    - `neoth update --self --apply` CLI wire — relaxes the `--self` ↔ `--apply` clap conflict and routes to the full Phase 2b flow.
    - `WAL 0xD2 SELF_UPDATE_APPLIED` event code reserved with payload-shape doc.
    - `neoth init` step7b prompts opt-in (both questions default to NO).

### Security (Session 19 — 2026-05-21)

- **wasmtime 26 → 36** — closes 15 RUSTSEC advisories (2025-0046 fd_renumber panic, 2025-0118 shared-memory unsoundness, 2026-0020 WASI exhaustion, 2026-0021 fields panic, 2026-0085 flags-lift panic, 2026-0086 Winch table data leak, 2026-0087 Cranelift f64x2.splat OOB, 2026-0088 pooling-allocator data leak, 2026-0089 Winch table.fill panic, 2026-0091/92/93 string-transcode OOB/panic, 2026-0094 Winch table.grow mask, 2026-0095 Winch sandbox escape, 2026-0096 aarch64 Cranelift sandbox escape). Zero NEOTH code changes — surface we use is wire-compatible.

### Changed (Session 19 — 2026-05-21)

- **Cargo deps**: added `zip = "1"` (deflate-only) + `lzma-rs = "0.3"` (pure-Rust xz). Promoted `tempfile = "3"` from `[dev-dependencies]` to `[dependencies]` because the self-update apply path stages binary swaps in a same-volume tempdir at runtime.
- **`coding::dispatcher::handle_retryable_failure`** redacts the diagnosis string via `security::redact::redact_text` before the trace event hits the WAL subscriber.
- **`wasm_plugin::dispatch::invoke_plugin`** redacts every `InvocationOutcome.error` constructor (instantiate / export-lookup / run-trap).
- **Hooks doctor doc-comments + minor `parse_semver` char-array literals** — clippy hygiene round, zero warnings now.
- **`InitArgs` derives `Default`** for wizard-step test ergonomics.

### Added (Session 18 — 2026-05-20)

- **Pick #6 Phase 3 ProviderWorker** — `coding::provider_worker::ProviderWorker` wraps any `Arc<dyn Provider>` into a synchronous Worker. Hemisphere-aware role-hint prompt; calls provider.complete via internal `tokio::runtime::Handle::block_on`; parses the response (```diff fenced block + `SUMMARY:` line + `TESTS: added/total/passing/failing/skipped`); persists the patch under `<patch_root>/coding-sessions/<sid>/task-<tid>.patch`. Q1 patch-safety placeholder — STORES, does not apply.
- **`neoth code --dispatch`** — end-to-end coding workflow live. Resolves Left/Right/Cerebellum providers via `from_config_for_role`, wraps each in ProviderWorker, binds via HemisphereWorkerSet, calls `dispatch_session()` with default budget. Aggregated outcome (attempted / completed / blocked / unassigned + budget_exhausted) prints after run.
- **Hook engine plugin variant** — `HookAction::Plugin { plugin_id }` 4th action variant + `PluginInvoker` trait + `run_stage_with_plugins()` entry point. Concrete wasmtime stays out of the hook crate.
- **Daemon-side CompiledPluginInvoker** — `wasm_plugin::dispatch::CompiledPluginInvoker` impls `hooks::PluginInvoker`. Holds `(Arc<Engine>, HashMap<plugin_id, Arc<Module>>, Arc<Linker>)`; `invoke(id)` looks up + delegates to `invoke_plugin()`.
- **OnceLock GLOBAL_INVOKER plumbing** — `hooks::dispatcher::register_global_invoker` + `current_global_invoker` API; zero call-site changes for the 6 existing `run_stage` invocations across `cli::serve` + `cli::chat`.
- **`cli::serve::bootstrap_plugin_invoker(home)`** — runs after freedom.yaml load: discover → compile → register. Empty plugins dir silent noop; per-plugin compile failure logs a warn but daemon stays up; engine/linker build failure logs warn + returns. Single info log `plugin invoker registered; hook actions Plugin{..} are live` confirms wire.
- **Example plugin fixture** — `examples/wasm-plugin-hello/` ships the smallest valid NEOTH plugin (exports `fn neoth_run() -> i32`). README documents `wasm32-unknown-unknown` build + install path + hooks.toml entry. Closes Pick #34's last gap for end-to-end testing.
- **R-3 Hysteria URL parser** — `transport::hysteria::parse_hysteria_url("hysteria2://auth@host:port")` with scheme-tolerant + port-default 443 + bare `auth@host` form support. Closes the relay-configuration UX gap.
- **R-7 PeerLoadRegistry** — `cluster::PeerLoadRegistry` in-memory heartbeat tracker. `record_heartbeat` / `prune_stale(now, max_age)` / `known_peers()` fed to `LeastLoaded` routing policy. Hyperswarm wire stays stub until Phase-3 dep block.
- **R-8 Cloud-connector scaffold** — new `cloud` module: `Provider` enum (Dropbox / OneDrive / GoogleDrive / GCS / iCloud / Gmail) + `CloudConfig` + `CloudFile` + `CloudConnector` trait + `StubConnector` per-provider deferred-OpenDAL bail + `load_sources_from()` YAML loader.
- **D14b Phase 2c GPU gates** — `qwen-cuda` + `qwen-metal` cargo features wire `Device::new_cuda(0)` / `Device::new_metal(0)` into `local_qwen::device_for()`. Without features → warn + CPU fallback (preserved).
- **WAL event `0x77 KANBAN_TASK_PROGRESS`** reserved for dispatcher heartbeat frames.
- **SovereignFade component** — G-27 sovereign-curve entry fade (600ms ease-in cubic-bezier) on welcome / done / chat surfaces.
- **`neoth update --self`** — GitHub Releases API self-update check (Phase 1; Phase 2 download+replace pending binary-distribution channel decision).
- **MCP secure-by-default** — `trust_all_tools: bool` field; gate denies `None && !trust_all_tools` with `MissingAllowlistSecureDefault` + WAL emit_reject + doctor warning.
- **WASM memory limiter** — `ResourceLimiter` impl on `PluginStoreState`; was dead enforcement before.
- **T-SEC-002 webhook fuzz** — 9 new edge tests pinning that the parser never panics + timestamp errors precede signature errors.

### Changed

- **GUI v0.1 polish** — 26 of 27 audit findings closed: WCAG-AA contrast, channels-screen disclosure, identity regex validation, chat composer label, NeothComboBox/CheckBox/LineEdit dark-mode replacements, Settings ← Chat back button, Welcome ← Mode back button, honest 11-row channels list, Done-screen Open-Settings shortcut.
- **Code Sessions GUI tab** — all six steps shipped: static layout → CLI JSON output → Slint model binding → activity feed WAL parsing → 2s live-tail timer → click-to-detail pane → operator action buttons (move/promote/comment/assign) + comment-thread rendering.
- **`verify.rs` refactor** — 113 LOC monolith → 28 LOC orchestrator + 3 pure helpers + `VerifyOutcome` struct.
- **`verify.rs` filename marker** — `REDACTION_MARKER` writes `file_name()` only; the verifier normalises both sides via `file_name()`. Path-invariant.
- **Webhook duplicate-key semantics** — last-write-wins documented, `tracing::warn` fires on duplicates.
- **Frameless titlebar spec relaxed** — OS-native chrome as v0.1 default, frameless as v0.2+ opt-in.
- **Letter-spacing tokens** — 31 hardcoded values → 4 design tokens (`tight`/`wide`/`extra-wide`/`brand-bar`).
- **WalWriterHandle + QuotaGuard got `Debug` derives** (hidden behind `wasm-plugin-host` feature gate before).

### Documentation

- **`PLAN/CHORUS_dispatcher_design.md`** — Pick #6 architecture draft + 4 Chorus-worthy questions (patch safety, streaming, REVIEW gating, cycle prevention).
- **`PLAN/REVIEWER_*_AUDIT_2026-05-20.md`** — three parallel audit reports from a11y-architect, security-auditor, code-reviewer.
- **`PLAN/CHANNELS_SPEC_2026-05-20.md`** — authoritative messenger shipping matrix.
- **`PLAN/GUI_AUDIT_2026-05-20.md`** — 27-finding GUI audit.
- **README §Current status refresh** — operator-facing feature summary synced to actual ship state (Pick #6 / Pick #34 voll / Code Sessions / per-hemisphere binding / WASM plugins / secure-by-default).

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
