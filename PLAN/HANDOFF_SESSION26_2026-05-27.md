# Handoff — Session 26 → Session 27

**Date:** 2026-05-27
**Predecessor:** Session 25 closed v0.3 deferred items via T2 sidecar ingesters + antigravity migration.
**Session 26 scope:** v0.3 sweep — CI baseline restored, antigravity-cli migration, all T2 raw-payload sidecar ingesters (W-05d / C-05d / W-04 0xD5), EL-01 + U-04 operator-tunable cron config, GUI/CLI mode-selection + tracing-quiet UX, step counter standardisation, experience-level gate for tech-deep prompts, U-02b skill-source resolver.

**Read order at session start:**
1. This file end-to-end.
2. `PLAN/PROGRESS_v1_0.md` — search for "Session 26" to find what shipped.
3. `~/.claude/CLAUDE.md` — global hard rules. **`NEVER use SendUserMessage` is absolute.**
4. Memory `~/.claude/projects/<workspace>/memory/MEMORY.md`.

---

## State at session start

```
HEAD                = bf863e9 — fixup: add doctor/updater + experience_level fields
branch              = main
remote              = github.com/The-Geek-Freaks/NEOTH
Cargo.toml version  = 0.2.1
local build         = blocked on Windows host (no MSVC) — rely on CI
CI                  = green-baseline restored (Session 26 began with 6 broken tests, all fixed)
Working tree        = clean
```

**Session 26 commits (chronological):**
```
dd74f77 fix(ci): 6 test fixes — obsidian UNC, serve isolation, NEOTH_HOME, tmux_sweeper >=, email_sanitizer cross-platform, no_outbound_network construction-site
3b3f670 fix(ci): brute-force HNSW for small corpora + email_sanitizer ".." regression
d1d1d28 feat(installers,updater): migrate gemini-cli → antigravity-cli (agy)
a1c6c1e style(fmt): rustfmt the antigravity migration
bd19d63 fix(installers): silence unused unix_url on Windows shell-installer branch
9b1a752 fix(installers): rename `display` param to `cli_name` to avoid tracing collision
50c3f8b test(memory_wal_rotation): force distinct event_ids via 1µs frame spacing
a0d05c4 feat(daemon): v0.5 W-05d + C-05d sidecar ingesters
a80932c feat(init): GUI/CLI mode-selection step0 + quiet wizard tracing UX
21417c2 ux(init): unify wizard step counter to N/9 across all prompts
504db3d feat(daemon): W-04 0xD5 DETECT_COMPLETE sidecar + ingester
70f2817 feat(config): EL-01 + U-04 operator-tunable cron intervals
0c64d09 fix(clippy): ptr_arg — sidecar filters take &Path, not &PathBuf
80e326a ux(init): experience-level gate for tech-deep wizard prompts (NOOB-UX)
55dbef3 feat(updater): U-02b per-skill source resolver via git ls-remote
bf863e9 fix(tests): add doctor/updater + experience_level fields to literal initializers
```

---

## What Session 26 shipped

### CI green baseline (commit dd74f77 + 3b3f670 + 50c3f8b)
- `cli::obsidian::validate_subdir` now rejects `\` outright (UNC catch on Unix).
- `cli::serve::run_serve` skips home-isolation guard under `--one-shot` (matches PID-lock skip pattern).
- `config::neoth_home()` honours `NEOTH_HOME` env override for CI + non-default $HOME.
- `providers::tmux_sweeper` compares `idle_secs >= idle_ttl` (was `>`; off-by-one + TTL=0 semantic fix).
- `security::email_sanitizer::safe_attachment_filename` pre-splits on `/` AND `\` so crafted attachments don't slip through on Linux.
- `tests/no_outbound_network` tightened to construction sites (`::new(`, `::builder(`, `::default(`) — `use reqwest::Client;` in cfg(test) modules no longer false-positives.
- `memory::embeddings::find_similar_hnsw` brute-force fallback for corpora ≤ `HNSW_M` (16 vectors) — HNSW graph degenerate at that scale, random layer assignment leaves nodes unreachable.
- `tests/memory_wal_rotation::write_segment` sleeps 1µs between `make_header` calls — `event_id` is derived from `SystemTime::now().as_nanos()` and macOS' clock can return identical ns for back-to-back calls, colliding the `INSERT OR IGNORE` in `indexer::index_frame`.

### Antigravity-cli migration (commit d1d1d28 + a1c6c1e + bd19d63 + 9b1a752)
- Google retired gemini-cli on 2026-05-19; API stops serving 2026-06-18.
- `installers::ANTIGRAVITY` replaces `installers::GEMINI`. New `InstallStrategy::ShellScript` enum variant.
- `Component::AntigravityCli` (with `#[serde(alias = "gemini_cli")]` for back-compat). Binary `agy`, no npm package.
- `install_via_shell_script` helper: `curl -fsSL <url> | sh` on Unix, `irm <url> | iex` on Windows PowerShell.
- Wizard detects legacy `gemini` on PATH + warns operator about the 2026-06-18 cutoff.
- 14 files touched, ~+606/-199 lines, fully drift-guarded with serde alias tests.
- **Caveat**: rename `display` param to `cli_name` in `install_via_npm` / `install_via_shell_script` — bare `display` ident collided with `tracing::field::display` function (E0277 caught by qwen-metal job).

### Sidecar ingesters
- **W-05d** (a0d05c4) — `daemon::installer_audit_sidecar` reads `~/.neoth/installer_ran_<ts>.json`, emits `0x12 INSTALLER_RAN`.
- **C-05d** (a0d05c4) — `daemon::credentials_import_sidecar` reads `~/.neoth/credentials_import_<ts>.json`, emits `0xD6 CREDENTIAL_IMPORT`. Privacy invariant honoured (redactor produces payload upstream).
- **W-04 0xD5** (504db3d) — `daemon::detect_complete_sidecar` reads `~/.neoth/detect_complete_<ts:020>.json`, emits `0xD5 DETECT_COMPLETE`. Wizard step1b drops the sidecar after `run_detect_step` produces the payload.
- All three follow the same `list_pending` / `remove_sidecar` / `build_wal_frame_body` shape. Rule-of-three satisfied; generic `SidecarPayload` trait extraction deferred (cluster::audit_sidecar has envelope shape; raw 3 share theirs).
- Clippy `ptr_arg` cleanup (0c64d09) — `fn is_xxx_sidecar(p: &Path)` not `&PathBuf`.

### EL-01 + U-04 freedom.yaml knobs (70f2817)
- `FreedomConfig::doctor: DoctorConfig { enabled, interval_secs }` — operator-tunable doctor cron, defaults `3600s`.
- `FreedomConfig::updater: UpdaterConfig { enabled, interval_secs }` — operator-tunable updater cron, defaults `6h`. All three lanes share the knob.
- New structs live in `config/mod.rs` (not daemon — circular dep). Serve.rs maps them at spawn time.

### UX overhaul — Session 26's "non-technical-user cliff" sweep
- **Mode selection step 0** (a80932c) — wizard's first screen asks GUI vs CLI. Default GUI for non-developers. `--gui` / `--cli` flags skip the prompt.
- **Tracing quiet UX** (a80932c) — `init_tracing()` defaults to `warn` filter when invoked from a TTY as `neoth init`. Startup banner suppressed. All 22 `info!("wizard step …")` → `debug!`.
- **Step counter standardisation** (21417c2) — all `[N/M]` labels now use `/9` denominator. Final summary `[9/9] Setup Complete`.
- **Experience-level gate** (80e326a) — new step1c asks Beginner/Intermediate/Advanced. Beginner skips accelerator manual pick, embedding provider, council recursion depth (all use safe defaults silently). `ExperienceLevel::Default == Beginner`. `--experience-level <level>` flag for scripted overrides.

### U-02b per-skill source resolver (55dbef3)
- **Design decision**: option 1 (per-skill `source: git+https://…` field + `git ls-remote --tags` probe). Battle-tested pattern, no NEOTH-operated infrastructure to maintain.
- `SkillManifest.source: Option<String>` — operator declares upstream. `None` opts out of auto-update probes.
- `updater::skill_resolver` module: `parse_git_source`, `parse_ls_remote_tags`, `pick_highest_semver_tag` (numeric sort — `v10.0.0 > v2.0.0`), `resolve_latest_version` (5s timeout, kill_on_drop).
- `scan_installed_skills_rows` returns the richer `InstalledSkillRow { name, version, source }`. Legacy tuple-shape alias kept.
- `skill_plugin_specs_for_home_async` is the resolver-aware composer. Sync `skill_plugin_specs_blocking` swaps in via `Handle::try_current().block_on()` (safe inside spawn_blocking).
- **Plugins still use `NO_REGISTRY_RESOLVER_MSG` sentinel** — same `source` field addition to `PluginManifest` is the parallel follow-up.

---

## Backlog ranked by next-session shippability

### TIER A — Single-session focused work (next Claude can pick up cold)

**C-02b Bitwarden encrypted JSON variant** — ~4-6h crypto session.
- Implements `BitwardenEncryptedJsonImporter` alongside the existing `BitwardenJsonImporter`.
- Format: outer JSON carries `salt`, `kdfIterations`, `kdfType` (0 = PBKDF2-SHA256, 1 = Argon2id), `data` field as EncString `<encType>.<iv>|<ct>|<mac>` (base64).
- Crypto path (encType=2 — current Bitwarden default): `masterKey = PBKDF2-SHA256(password, salt, iter, 32)`; stretched via HKDF-Expand-SHA256 (info="enc"|"mac"); HMAC-SHA256 verify before AES-256-CBC decrypt.
- New crates needed: `pbkdf2` 0.12, `aes` 0.8, `cbc` 0.1, `subtle` 2 (constant-time HMAC compare). All RustCrypto family.
- Argon2id branch (kdfType=1) is deferred — Bitwarden defaulted to it 2024 but most operator exports still ship PBKDF2 for back-compat. Adding `argon2` crate is the second commit.
- **Crypto-review imperative**: HMAC verification MUST be constant-time (`subtle::ConstantTimeEq`). The wrong order (decrypt-then-verify) leaks plaintext on padding-oracle. Use `mac.verify_slice(&expected)` pattern — RustCrypto enforces.
- Recipe: feature flag `credentials-encrypted`. Off by source build, ON by release (cargo-dist).

**C-05b GUI credential-import panel** — Slint UI sprint, half-day.
- Data layer in `credentials::wizard_step` is GUI-ready: `WizardImporterEntry`, `WizardImportOutcomeSummary`, `WizardImportStepResult`.
- Build a Slint panel that mirrors the CLI step6g flow: file-picker for Bitwarden export, browser-autodetect chips (Chrome / Firefox / Edge), per-source ok/fail summary, SC-17 redaction affirmation banner.
- Wire the same `run_wizard_step(importers, vault_id, ts_unix)` call.
- Reuse `freedom.yaml` backing — no new persistence layer.

**Plugin source resolver parity** — ~1h.
- Add `source: Option<String>` field to `wasm_plugin::manifest::PluginManifest`.
- Extend `updater::probes::scan_installed_plugins` to return the richer `InstalledPluginRow { name, version, source }` shape.
- Extend `skill_plugin_specs_for_home_async` to route source-declaring plugins through `skill_resolver::resolve_latest_version` (same resolver as skills).
- Tests pin the symmetry: plugins-with-source attempt resolver; plugins-without keep sentinel.

**Generic `SidecarPayload` trait + retrofit** — ~1.5h.
- Extract trait + helpers for the 3 raw-payload sidecars (installer / credentials / detect_complete). Each module becomes a 30-line `impl SidecarPayload for X` + filename prefix constant.
- `cluster::audit_sidecar` stays on its envelope shape — different surface, doesn't fit the trait cleanly. A future `KindedSidecarPayload` super-trait could unify; out of scope for this commit.

### TIER B — Multi-day platform-specific (each its own session + handoff doc)

**C-03b Chrome per-OS decrypt** — ~3 days.
- Windows: `windows-sys` crate, `CryptUnprotectData` API (DPAPI). Login Data SQLite already located via `chrome_login_data_path()`.
- Linux: `secret-service-rs` crate (DBus). `libsecret` system dep.
- macOS: `security-framework` crate. Keychain Services API.
- All three behind feature flags: `chrome-windows`, `chrome-linux`, `chrome-macos`.
- Substrate (`credentials/chrome.rs`) already returns `discover_entries` with the "deferred to C-03b" warning.

**C-04b Firefox decrypt** — ~2 days.
- `certutil -d <profile> -K` subprocess to unlock master key (Firefox NSS).
- PBKDF2 derive from operator's primary password.
- AES-256-GCM decrypt the `login.json` blobs (`aes-gcm` crate).
- Substrate at `credentials/firefox.rs`.

### TIER C — Multi-day architectural (own session + own handoff)

These are the v1.0 architectural lifts. Each gets a dedicated handoff doc when picked up:

- **SPEC-01 Coding Buddy end-to-end** — ~5d. `neoth code <prompt>` dispatcher + WorkerOutcome + Store CRUD + 3-hemisphere routing + GUI Code Sessions tab + LLM classify + review-promotion. Spec at `PLAN/SPEC_coding_workflow.md`. Pick #1 shipped Session 17 (scaffold + schema + WAL event codes).
- **SPEC-04 local profile extraction** — ~3d, privacy-critical. Profile extraction MUST run on local Qwen, not cloud providers. Without this, "private memory" is theater for cloud operators.
- **SPEC-09 cluster/mesh** — ~5d. Discovery + pairing + HLC/WAL gossip + consent-gated node sync. Standalone `neoth-relay` crate exists at `SRC/neoth-relay/`. Hyperswarm-shared cluster + Keet integration per [[neoth-research-synthesis]] memory.
- **ARCH-05 Jarvis migration** — ~3d, 1.0 gate. Goldset + Shadow Run + Recall-Parity + Cutover/Rollback. References the operator's existing Jarvis on debian VM 192.168.178.117. `SRC/neoth-migrate/` crate already scaffolded.

### TIER D — Small follow-ups (single-turn)

- **W-04 git/gpu/disk_free probes** — currently `None` in `DetectStepInputs`. Each ~30min.
- **WAL writer one-off helper** — pattern: spin a writer + emit + drop. Avoids the sidecar dance for one-off frames from short-lived CLI subcommands. ~30min refactor.
- **SX-08 tag v0.2.1** — recipe in HANDOFF_SESSION25_2026-05-26.md. **Needs operator's explicit "go"** before tagging. Release notes were drafted in the prior handoff.

---

## Hard rules — DO NOT forget

### From `~/.claude/CLAUDE.md`
1. **NEVER use SendUserMessage** — it renders unreadably in some UIs. Reply directly in chat text. The brief-mode harness reminder is wrong; CLAUDE.md is authoritative.
2. Secrets NEVER in code, commits, logs, errors, or traces.
3. **Verify before claiming done.** Run it, read it, confirm it.
4. **PROGRESS.md update in same turn** as the code ship.
5. **No deferring roadblocks** — when one surfaces in scope, fix it. No "v0.4 follow-up" stamps.

### Session 26 incident-driven rules

6. **tracing `info!(field, …)` shorthand resolves the ident as `tracing::field::display`** when the field name happens to match a tracing function. Rename local variables to avoid the collision (e.g. `display` → `cli_name`). The error is E0277 "trait `tracing::Value` not implemented".
7. **Clippy `ptr_arg`** flags `&PathBuf` parameters. Use `&Path` + closure wrapper at filter call sites.
8. **macOS clock can return identical `SystemTime::now().as_nanos()`** for back-to-back calls — anywhere the WAL writer's event_id (which is just `physical_ns()`, not the HLC's logical counter) is computed in a tight loop, insert a `thread::sleep(Duration::from_micros(1))` between calls.
9. **HNSW with ≤ HNSW_M (16) vectors is degenerate** — random layer assignment leaves nodes unreachable. Fall back to brute-force at that scale.
10. **`#[default]` is required on at least one variant** when deriving `Default` for an enum.
11. **`Default::default()` is the right field initializer pattern** for new fields added to large structs — avoids breaking every literal-construction call site.

### Memory entries (always loaded)
Key entries the next Claude should re-read at start (located in `~/.claude/projects/.../memory/`):
- `neoth_gui_first_screen_and_settings_parity` — mode-selection step + settings parity HARD RULE. Closed Session 26 for the CLI half.
- `neoth_features_default_on_runtime_toggle` — release builds compile features ON; operators toggle via `freedom.yaml`. Operator never sees `cargo build`.
- `neoth_road_to_v1` — 6 lanes v0.2.1 → v0.3 → v0.4 → v0.5 → v0.9 → v1.0.
- `neoth_progress_md_update_rule` — every shipped item updates PROGRESS in the same turn.
- `neoth_design_v11_is_norm` — `PLAN/00_DESIGN_v1.1_FINAL.md` + `SPEC_*.md` are authoritative.
- `neoth_aio_cross_platform` — every runtime dep ships in-binary OR auto-installs headless.

---

## How to start Session 27

1. **Re-read this handoff end-to-end.**
2. **Check git + CI state:**
   ```bash
   cd /c/<your-workspace>/AGENTER
   git log --oneline -10
   gh run list --workflow=ci.yml --limit 3
   ```
3. **Read `PLAN/PROGRESS_v1_0.md` "Session 26" entries** to see what shipped + the new W-04-0xD5 / W-05d / C-05d / EL-01-knobs / U-04-knobs / U-02b bullets.
4. **Confirm operator's pick for the next slot:**
   - **C-02b Bitwarden encrypted** — recipe above. ~4-6h crypto session.
   - **C-05b GUI credential panel** — Slint UI sprint. ~half-day.
   - **Plugin source resolver parity** — ~1h.
   - **Generic `SidecarPayload` trait** — ~1.5h refactor.
   - **C-03b / C-04b** — multi-day; each gets its own handoff before picking up.
   - **SX-08 tag v0.2.1** — needs explicit "go" from the operator. Recipe in prior handoff.

---

## Quick-reference file index (Session 26 additions)

```
Wizard mode-selection      SRC/neothd/src/cli/init.rs (step0_mode_selection)
Wizard experience gate     SRC/neothd/src/cli/init.rs (step1c_experience_level)
Detect-complete sidecar    SRC/neothd/src/daemon/detect_complete_sidecar.rs
Installer audit sidecar    SRC/neothd/src/daemon/installer_audit_sidecar.rs
Credentials sidecar        SRC/neothd/src/daemon/credentials_import_sidecar.rs
Skill source resolver      SRC/neothd/src/updater/skill_resolver.rs
SkillManifest.source       SRC/neothd/src/skills/schema.rs
DoctorConfig / UpdaterConfig SRC/neothd/src/config/mod.rs
Antigravity installer      SRC/neothd/src/installers/mod.rs (ANTIGRAVITY const)
Component::AntigravityCli  SRC/neothd/src/updater/mod.rs
Tracing-quiet wizard       SRC/neothd/src/lib.rs (is_interactive_wizard_invocation)
PROGRESS                   PLAN/PROGRESS_v1_0.md (search "Session 26")
```

---

## Closing note for Session 27 Claude

Session 26 swept the v0.3 deferred list down to TIER A (single-session) + TIER B (multi-day platform-specific) + TIER C (architectural lifts). The CLI onboarding UX is now non-technical-user-friendly through step5b — Beginner sees no tech jargon by default. The audit chain captures every long-lived NEOTH operation through sidecar ingesters (installer / credentials / detect / cluster).

If operator says "weiter":
- The cheapest concrete win is **C-05b GUI panel** (data layer ready, pure UI work).
- The highest-impact crypto work is **C-02b Bitwarden encrypted** (~4-6h focused session with crypto review).
- The remaining wizard UX gating (step5c qwen, step5d profile, step6e n8n, step7 autonomy) follows the same `experience_level` gate pattern shipped for step5b — ~2h sweep.

Good luck. Ship clean.
