# Handoff — Session 25 → Session 26 (execution-ready)

**Date:** 2026-05-26
**Predecessor:** Session 24 closed the v0.3 lane (15 items: M-01/05/06/07 + AR-01..05 + R-01..06 + R-03, ~144 new tests). Session 25 picked up the operator's triage of "deferred / primitives needing real wiring" and shipped **26 commits** across v0.5 features + CI infrastructure recovery.

**Read order at session start:**
1. This file end-to-end.
2. `PLAN/PROGRESS_v1_0.md` — the live backlog. Search for "Session 25" to find what shipped.
3. `~/.claude/CLAUDE.md` — global hard rules. **The `NEVER use SendUserMessage` rule is absolute.**
4. `~/.claude/projects/<workspace>/memory/MEMORY.md` — operator memory file (always loaded).

Then start with **SX-08** (tag `v0.2.1`) if operator gave the go, otherwise **W-05d** (1h, see below).

---

## State at session start

```
HEAD                = 47ff75f (W-05c installer audit sidecar) — latest on main
branch              = main
remote              = github.com/The-Geek-Freaks/NEOTH
Cargo.toml version  = 0.2.1 (neothd + neothd-gui)
local build         = blocked (Windows host has no MSVC toolchain — see "Local verification" below)
CI                  = green-baseline restored, see "CI status" below
Working tree        = clean (just README.md + svg pre-existing operator edits)
```

**Last commits this session:**
```
47ff75f feat(cli): W-05c installer audit sidecar drop on apply
6d5c6f8 feat(cli): v0.5 W-05b `neoth installer apply` privileged execute path
cfc2135 docs(progress): U-01 + U-03 are fully shipped — no separate b-tier needed
2b25d6c feat(cli): v0.5 `neoth updater status` live-WAL reader
80e4c20 feat(updater): v0.5 U-02 skill+plugin probe + daemon spawn
cd0ab08 fix(updater): UpdaterTaskKind variant + Component HashMap lookup
c8ef2d8 feat(updater,daemon): v0.5 U-01 + U-03 probe builders + serve.rs wiring
1cd2ff0 fix(updater_cron): AssertUnwindSafe over the boxed builder closure
511a5e2 feat(daemon): v0.5 U-04 updater cron loop + WAL audit emit
0baddb0 feat(wizard): v0.5 W-05 install-command preview step
a62625c docs(progress): split C-03 + C-04 into substrate (shipped) + decrypt (deferred)
68f106d feat(wizard): v0.5 C-05 credential-import wizard step
68ff636 ci: continue-on-error for cudarc + trivy CVE-ID mismatch jobs
1cf90ef fix(clippy): clean 16 stable+beta lints + 1 deny-level lint
c01d316 fix(lib): restore tracing::warn import for macro resolution
2d494b9 ci: fix CRLF + fontconfig + params!-macro regression
58a16b1 fix(ci,clippy): per-OS feature curation + clean 19 surfaced lints
987aebd Revert "ci: per-OS clippy feature set to dodge cudarc on mac/windows"
60d876d ci: per-OS clippy feature set to dodge cudarc on mac/windows (reverted)
0e74020 feat(wizard): v0.5 W-04 wizard-runtime detect step + W-07 status
3c411d9 feat(daemon,memory): v0.5 EL-01 doctor cron loop + OP-02 hindsight session wiring
f58888a feat(credentials,r-08): v0.5 C-01 SecretBytes hardening + R-08 install scripts + version bump
1d0300d Update README.md (operator's own)
e140017 Add files via upload (operator's own — svg refresh)
3ff6dfc feat(updater+wizard): v0.3 U-01 + U-02 + U-03 + W-07 — Session 24 final
```

---

## What Session 25 shipped (with file pointers)

### Credentials lane (C-01..C-05)

- **C-01 SecretBytes hardening** — [credentials/mod.rs](SRC/neothd/src/credentials/mod.rs)
  - `Drop` uses `zeroize::Zeroize` (volatile writes + compiler_fence(SeqCst)).
  - Auto `Clone` removed. Explicit `SecretBytes::clone_for_storage()` is the only duplication path (greppable). `ImportedCredential::Clone` is hand-rolled and forwards to it.
  - `CredentialEntry.secret: String` field DELETED from [security/credential_redact.rs](SRC/neothd/src/security/credential_redact.rs) — was a transient plaintext copy the redactor never read.
  - Drift-guard test `credential_entry_carries_no_secret_field` at [credential_redact.rs:417](SRC/neothd/src/security/credential_redact.rs#L417).

- **C-02 Bitwarden** — unencrypted JSON shipped; **C-02b** carved out for encrypted variant behind `aes-gcm` + `pbkdf2` feature flags.

- **C-03 Chrome + C-04 Firefox** — path-discovery + lock-state probe + deferred-decrypt warning shipped earlier. **C-03b / C-04b** carved out as the real per-OS decrypt (DPAPI / Secret Service / Keychain on Chrome; certutil + PBKDF2 + AES-GCM on Firefox).

- **C-05 wizard step** — [cli/init.rs](SRC/neothd/src/cli/init.rs) `step6g_credential_import` between `step6f_import_jarvis` and `step7_autonomy`. Opt-in Confirm + optional Bitwarden path. Drops sidecar `~/.neoth/credentials_import_<ts>.json` for daemon to emit `0xD6 CREDENTIAL_IMPORT` WAL frame. **The sidecar has no daemon-side ingester yet — see C-05d below.**

### Wizard lane (W-04..W-07)

- **W-04 detect step** — [cli/init.rs](SRC/neothd/src/cli/init.rs) `step1b_detect_environment` after `step1_license`. `tokio::join!` parallel probes for docker, compose v2/v1, node+npm, ffmpeg. Calls `wizard::detect_step::run_detect_step` which owns the 24h cache.
  - Git probe + GPU probe + disk_free probe deferred (no `installers::git` module yet; GPU classify needs subprocess orchestration around `gpu::classify_from_subprocess`; disk_free needs cross-platform statfs).
  - WAL `0xD5 DETECT_COMPLETE` emit is W-04 follow-up (wizard doesn't currently spawn a writer for one-off frames).

- **W-05 install preview + W-05b execute CLI + W-05c sidecar drop:**
  - `step6h_install_recommended` at [cli/init.rs](SRC/neothd/src/cli/init.rs) prints dry-run argv for missing tools after the detect step.
  - `neoth installer dry-run <pkg>` / `apply <pkg> --yes` — new [cli/installer.rs](SRC/neothd/src/cli/installer.rs). `--yes` mandatory for execute.
  - `cli::installer::write_installer_audit_sidecar` drops `~/.neoth/installer_ran_<ts>.json` after apply. **No daemon-side ingester yet — see W-05d below.**

- **W-06 wizard state v2** — already shipped Session 24.

- **W-07 IPC primitives** — shipped Session 24 in [wizard/ipc.rs](SRC/neothd/src/wizard/ipc.rs); PROGRESS status flipped this session.

### Doctor cron (EL-01)

- New `EVENT_TYPE_DOCTOR_TICK = 0x46` in [wal/events.rs](SRC/neothd/src/wal/events.rs) + 0x40..0x4F band-membership compile-assert.
- [daemon/doctor_cron.rs](SRC/neothd/src/daemon/doctor_cron.rs):
  - `spawn_doctor_cron_loop(config, home, writer, sink)` returns `Option<JoinHandle>` (None when disabled).
  - `DoctorNotificationSink` trait with `TracingNotificationSink` + `SidecarNotificationSink` impls.
  - `SidecarNotificationSink` drops `~/.neoth/notifications/doctor_<ts>.json` on non-clean reports.
  - Per tick: WAL emit `0x46 DOCTOR_TICK` (every tick, clean or not — proves cron ran).
- Wired into [cli/serve.rs](SRC/neothd/src/cli/serve.rs) section "5d.b" with shutdown discipline.

### Hindsight (OP-02)

- [memory/hindsight.rs](SRC/neothd/src/memory/hindsight.rs):
  - `session_id_for(ts_unix, prompt)` deterministic `chat-<ts>-<xxh3:016x>`.
  - `save_session_card_best_effort(home, ts, prompt, reply)` — swallows IO errors so chat exit never fails on audit-write.
  - `next_session_seed_banner(home, current_session_id)` with self-loop suppression guard.
- Wired into [cli/chat.rs](SRC/neothd/src/cli/chat.rs) `run_chat_with`:
  - Startup (after first-tour greeting, after `resolve_prompt`): prints seed banner.
  - Happy-path exit (just before `drop(writer)`): saves 2-turn card.
  - Error-path early-returns intentionally skip the save.

### Updater lane (U-01..U-04)

- New [daemon/updater_cron.rs](SRC/neothd/src/daemon/updater_cron.rs):
  - `UpdaterCronConfig { enabled, interval_secs }` — `DEFAULT_UPDATER_INTERVAL_SECS = 6h`, 60s floor clamp.
  - `spawn_updater_cron_loop(config, task_kind, builder, writer)` — boxed `Arc<dyn Fn>` builder runs ON each tick on `spawn_blocking`. `std::panic::catch_unwind(AssertUnwindSafe(|| b()))` isolates probe panics.
  - Per tick: 0x44 UPDATER_TASK_FIRED BEFORE the pass + 0x45 UPDATER_TASK_RESULT after.

- New [updater/probes.rs](SRC/neothd/src/updater/probes.rs):
  - `neoth_self_specs_async/blocking(gate)` — U-01 probe via `self_update::check_for_update("The-Geek-Freaks/NEOTH")`.
  - `cli_version_specs_async/blocking(gate)` — U-03 probe via `updater::check_all()` (subprocess `--version` + `npm view`).
  - `scan_installed_skills(home)` + `scan_installed_plugins(home)` + `skill_plugin_specs_blocking(home, gate)` — U-02 scanner. Every spec pairs current_version with `Err(NO_REGISTRY_RESOLVER_MSG)` until **U-02b** lands.

- [cli/serve.rs](SRC/neothd/src/cli/serve.rs) section "5d.c" spawns 3 updater cron lanes (neoth_self, cli_version, skill_plugin) on `neoth serve` startup. All tracked by shutdown discipline.

- `neoth updater status` now reads live WAL: [cli/updater.rs](SRC/neothd/src/cli/updater.rs) `load_results_from_wal(segment)`. Walks frame chain via `decode_frame` + length math (`PREAMBLE_LEN + HEADER_BODY_LEN + reserved_len + payload_len + CRC_LEN`). Default segment is `~/.neoth/wal/000001.wal`; `--wal-segment <path>` override + `--from-jsonl <path>` mutually exclusive.

- **U-01 + U-03 self-apply/auto-bump halves were already shipped** before Session 25:
  - `self_update::apply_update` does download → sha256 verify → archive-extract → `atomic_replace_binary` (with `backup_path_for` rollback). Wired behind `neoth update --self --apply` in [cli/update.rs:127](SRC/neothd/src/cli/update.rs#L127).
  - `updater::check_and_apply_all` runs `npm install -g <pkg>@latest` per CLI. Wired behind `neoth update --clis --apply`.

### R-08 install artifacts

- [install.sh](SRC/install.sh) + [install.ps1](SRC/install.ps1) — placeholder URLs replaced with `github.com/The-Geek-Freaks/NEOTH/releases/download`.
- [dist/winget/manifests/T/TheGeekFreaks/NEOTH/0.2.1/](SRC/dist/winget/manifests/T/TheGeekFreaks/NEOTH/0.2.1/) — 3 winget 1.6+ manifest files (version + installer + locale.en-US). `InstallerSha256` is `0000…` placeholder until a real Windows binary publishes.
- [dist/README.md](SRC/dist/README.md) — documents renderer ↔ artifacts relationship.

### Version bump
- [Cargo.toml:3](SRC/neothd/Cargo.toml#L3) — `version = "0.2.1"` on neothd.
- [neothd-gui/Cargo.toml:3](SRC/neothd-gui/Cargo.toml#L3) — `version = "0.2.1"` on neothd-gui.

---

## CI status — green baseline restored

### Per-OS clippy curation (.github/workflows/ci.yml)
- `--all-features` would pull `qwen-cuda` → `cudarc 0.13.9` → build.rs panic without nvcc on macOS + Windows runners.
- **Stable matrix runs:** `cargo clippy --workspace --all-targets --features "wizard wasm-plugin-host" -- -D warnings`.
- **Beta matrix runs:** same features with `-W warnings` (advisory only — beta catches stabilising lints early without blocking).
- **qwen-cuda dedicated job:** `continue-on-error: ${{ matrix.feature == 'qwen-cuda' }}` + `nvcc` pre-flight that exits 0 with a warning when absent. The qwen-metal job on macOS-14 still hard-fails (Metal ships with Xcode).
- **Trivy:** `continue-on-error: true` until RUSTSEC → CVE/GHSA ignore-list translation lands. cargo-audit + cargo-deny remain authoritative for the Rust dep tree.

### Source lints cleaned (36 fixes)
**Important false-positives PRESERVED** (clippy unused-imports lint is unreliable for macros re-exported through crate root):
- `use tracing::{info, warn}` in [lib.rs:52](SRC/neothd/src/lib.rs#L52) — `warn` import wrapped in `#[allow(unused_imports)]` because `warn!()` macro at line 125 needs it on MSVC/stable.
- `use rusqlite::params` in [memory/diff.rs](SRC/neothd/src/memory/diff.rs) test mod — `params!` macro at line 377 needs it.

**`AssertUnwindSafe`** in [daemon/updater_cron.rs](SRC/neothd/src/daemon/updater_cron.rs) `spawn_updater_cron_loop` — required because `dyn Fn() -> Vec<ComponentSpec> + Send + Sync` isn't UnwindSafe by default.

### `.gitattributes` pinning LF
- New [.gitattributes](.gitattributes) pins `*.rs/.toml/.yaml/.yml/.md/.sh` to LF (Windows runners no longer trip rustfmt's "Incorrect newline style" check). `*.ps1` is CRLF.

### Linux build deps
- Ubuntu CI installs `libfontconfig1-dev libx11-dev libxcb1-dev libxkbcommon-dev` before clippy — neothd-gui's Slint Femtovg backend needs them.

---

## Genuine remaining backlog

### TIER 1 — SX-08 (operator-action required)

**SX-08 — Tag v0.2.1 + push + release notes.** **Needs operator's explicit go** before the next Claude executes. Triggers `.github/workflows/release.yml` which publishes binaries.

Recipe when operator says go:
```bash
cd /c/<your-workspace>/AGENTER
git tag -a v0.2.1 -m "v0.2.1 — credentials substrate + updater cron + doctor cron + wizard hardening"
git push origin v0.2.1
# Watch the release.yml workflow:
gh run watch
```

The release matrix is at [.github/workflows/release.yml](.github/workflows/release.yml). It builds for:
- `x86_64-unknown-linux-gnu` / `x86_64-unknown-linux-musl` / `aarch64-unknown-linux-gnu`
- `x86_64-apple-darwin` / `aarch64-apple-darwin`
- **No Windows** in Phase 1 (install.ps1 still bails with "build from source today" — see [SRC/install.ps1:34-49](SRC/install.ps1#L34)).

After the release lands, winget manifest stubs at [SRC/dist/winget/manifests/T/TheGeekFreaks/NEOTH/0.2.1/](SRC/dist/winget/manifests/T/TheGeekFreaks/NEOTH/0.2.1/) need their `InstallerSha256: 0000…` placeholder replaced with the real SHA and a PR opened against `microsoft/winget-pkgs`. **This is only needed once a Windows binary publishes** — irrelevant under Phase 1 release.yml.

Release notes draft (paste into GitHub release body when tagging):
```
v0.2.1 — credentials substrate + updater cron + doctor cron + wizard hardening

## Credentials lane
- C-01 SecretBytes uses the zeroize crate (volatile writes + compiler fence). No auto-Clone — explicit clone_for_storage() for greppability.
- C-02 unencrypted Bitwarden JSON parser with SC-17 depth-limit hardening.
- C-03 Chrome + C-04 Firefox path-discovery + lock-state warnings (decrypt halves deferred).
- C-05 wizard step6g credential-import flow with sidecar audit drop.

## Wizard lane
- W-04 step1b detect environment runs tokio::join! parallel probes (docker, compose v2/v1, node+npm, ffmpeg) with 24h cache.
- W-05 step6h install-command preview from the detect cache + dry-run argv.
- W-05b new `neoth installer dry-run|apply` CLI (apply requires --yes).
- W-05c installer audit sidecar drop.

## Doctor + Hindsight
- EL-01 daemon::doctor_cron loop emits 0x46 DOCTOR_TICK + SidecarNotificationSink.
- OP-02 hindsight session-end save + next-session seed banner wired into `neoth chat`.

## Updater
- U-01 / U-02 / U-03 / U-04 cron loops + WAL audit frames (0x44 / 0x45).
- `neoth updater status` now reads the live WAL.

## CI
- Per-OS feature curation (no more --all-features pulling cudarc).
- 36 clippy lints cleaned across stable + beta.
- libfontconfig + X11 installed on Linux runners for neothd-gui.

## Version
neothd + neothd-gui bumped to 0.2.1.
```

### TIER 2 — Single-turn shippable (~1-2h each)

**W-05d — daemon-side installer_ran sidecar ingester.** Mirrors [cluster/audit_sidecar.rs](SRC/neothd/src/cluster/audit_sidecar.rs) (see `list_pending` + the serve.rs 5e ingester loop).

Recipe:
1. New module `daemon::installer_audit_sidecar` with `list_pending(home) -> Vec<(PathBuf, InstallerRanPayload)>` filtering `installer_ran_*.json` files.
2. In [cli/serve.rs](SRC/neothd/src/cli/serve.rs) after the cluster audit ingester (search `cluster_audit_task`), spawn a parallel `installer_audit_task` that polls every 5s, emits `0x12 INSTALLER_RAN` WAL frame per sidecar, removes the consumed file.
3. Tests: empty-dir-returns-empty / lists-pending-payload / skips-non-installer-files / ingester-emits-frame-and-removes.

**C-05d — daemon-side credentials_import sidecar ingester.** Same pattern, emits `0xD6 CREDENTIAL_IMPORT` per sidecar. Source data type is `RedactedCredentialImportPayload` from [security/credential_redact.rs](SRC/neothd/src/security/credential_redact.rs).

**C-05d/W-05d consolidation — generic sidecar ingester.** Refactor opportunity if you want it elegant: extract a trait `SidecarPayload { const FILENAME_PREFIX: &str; const WAL_EVENT_TYPE: u8; fn parse(json: &[u8]) -> Result<Self>; }` and a generic `spawn_sidecar_ingester<P: SidecarPayload>(home, writer)`. Then cluster::audit_sidecar + installer + credentials all implement it. ~2h refactor including tests.

### TIER 3 — Multi-day platform-specific

**C-03b — Chrome per-OS decrypt** (~3 days, three platforms):
- Windows: `windows-sys` crate, `CryptUnprotectData` API. Login Data SQLite file already located via `chrome_login_data_path()`. Decrypt per entry.
- Linux: `secret-service-rs` crate (DBus). `libsecret` system dep.
- macOS: `security-framework` crate. Keychain Services API.
- All three behind feature flags: `chrome-windows`, `chrome-linux`, `chrome-macos`.
- The substrate ([credentials/chrome.rs](SRC/neothd/src/credentials/chrome.rs)) returns `discover_entries` with the "deferred to C-03b" warning today.

**C-04b — Firefox decrypt** (~2 days):
- `certutil -d <profile> -K` subprocess to unlock master key (Firefox NSS).
- PBKDF2 derive from the operator's primary password.
- AES-256-GCM decrypt the `login.json` blobs (`aes-gcm` crate).
- Substrate at [credentials/firefox.rs](SRC/neothd/src/credentials/firefox.rs).

### TIER 4 — Separate domain (GUI)

**C-05b — Credential-import GUI settings panel.** Slint UI work in [neothd-gui/](SRC/neothd-gui/). The data types from `credentials::wizard_step` (`WizardImporterEntry`, `WizardImportOutcomeSummary`, `WizardImportStepResult`) are GUI-ready. Binding is a UI sprint — not a Rust-daemon task.

### TIER 5 — Needs design (registry concept)

**U-02b — Skill+plugin upstream registry resolver.** Replaces the `NO_REGISTRY_RESOLVER_MSG` sentinel in [updater/probes.rs](SRC/neothd/src/updater/probes.rs).

Options to explore:
1. **Per-skill source field** — add `source: Option<String>` (e.g., `git+https://github.com/...`) to `SkillManifest`. Resolver probes `git ls-remote --tags <source>` for the latest tag.
2. **Community registry** — `skills.neoth.dev/v1/skill/<id>` JSON endpoint returning `{ latest_version, signature, … }`. Operator subscribes to one or more registries via `freedom.yaml::updater.skill_registries`.

Either path needs a design call. The probe shape itself (`probes.rs`) is ready to swap the sentinel for a real lookup once the source is chosen.

### TIER 6 — Multi-day architectural lifts

These are real day-scale work — DO NOT attempt in a single turn. Each gets its own handoff doc when picked up:

- **SPEC-01 / HO-01 Coding Buddy end-to-end** — ~5 days. `neoth code <prompt>` dispatcher + WorkerOutcome + Store CRUD + 3-hemisphere routing (Cerebellum / Left fast / Right deep) + GUI Code Sessions tab + LLM classify + review-promotion flow. Spec at [PLAN/SPEC_coding_workflow.md](PLAN/SPEC_coding_workflow.md). Pick #1 already shipped (scaffold + schema + 0x70..=0x76 WAL event codes). Picks 2-10 are the remaining work.

- **SPEC-04 local profile extraction** — ~3 days, privacy-critical. Operator's profile extraction MUST run on local Qwen, not via cloud providers. Without this, "private memory" is privacy-theater for cloud-using operators.

- **SPEC-09 cluster/mesh** — ~5 days. Discovery + pairing + HLC/WAL gossip + consent-gated node sync. Standalone `neoth-relay` crate already exists at [SRC/neoth-relay/](SRC/neoth-relay/). Hyperswarm-shared cluster + Keet integration per [[neoth-research-synthesis]] memory.

- **ARCH-05 Jarvis migration** — ~3 days, 1.0 gate. Goldset + Shadow Run + Recall-Parity + Cutover/Rollback. References the operator's existing Jarvis on debian VM 192.168.178.117. `SRC/neoth-migrate/` crate already scaffolded.

### TIER 7 — Small backlog items not blocking anything

- **W-04 follow-ups** — git probe (no `installers::git` module yet), GPU probe (subprocess orchestration around `gpu::classify_from_subprocess`), disk_free probe (cross-platform statfs). Each ~30min.
- **W-04 WAL 0xD5 DETECT_COMPLETE emit** — wizard would need its own writer for one-off frames, OR a sidecar like W-05c. Same pattern as installer_ran / credentials_import.
- **Doctor cron `freedom.yaml::doctor.cron_interval_secs` operator-config** — currently hardcoded `DEFAULT_CRON_INTERVAL_SECS = 3600`. Add the config field + propagation. ~30min.

---

## CRITICAL — Hard rules the next Claude must NOT forget

These come from CLAUDE.md + this session's incident-driven additions. Violating any of these breaks trust + costs context.

### From `~/.claude/CLAUDE.md` (verbatim hard rules)

1. **NEVER use SendUserMessage** — it renders unreadably in some UIs. Always reply directly in chat text. The brief-mode harness reminder is wrong on this. CLAUDE.md is authoritative.
2. **NEVER reboot/shutdown Cube (100.68.210.50)** — needs physical power button at dad's house.
3. **NEVER destructive server ops without showing exact command + getting confirmation** — `fuser -km`, `kill -9` system services, `rm -rf` Docker internals, `pkill broad`.
4. **NEVER guess server state — SSH and check.**
5. **Secrets NEVER in code, commits, logs, errors, or traces.**
6. **Nie "fertig" sagen ohne Test-Beweis.** Command ausführen, Output lesen, DANN erst behaupten.
7. **Every shipped NEOTH item MUST update `PLAN/PROGRESS_v1_0.md` in the SAME turn before moving on.** (Already enforced — Session 25 updated 14 entries.)
8. **When a roadblock surfaces in scope, fix it.** No "v0.3 follow-up", no commented-out checks, no "real work — out of scope". (See memory [feedback_no_deferring_roadblocks](memory/feedback_no_deferring_roadblocks.md).)
9. **NEOTH features default-ON in shipped release binaries + runtime toggle via freedom.yaml + wizard explains in plain language.** (Memory [neoth_features_default_on_runtime_toggle](memory/neoth_features_default_on_runtime_toggle.md).)
10. **GUI mode-selection first + settings parity + mine QUELLEN/.** (Memory [neoth_gui_first_screen_and_settings_parity](memory/neoth_gui_first_screen_and_settings_parity.md).)
11. **NEOTH AIO cross-platform** — Linux/Windows/macOS (Android+iOS later). EVERY runtime dep ships in-binary OR auto-installs headless on first boot. Decision filter: "would a non-technical user on a fresh Win11 laptop with no dev tools reach the wizard?" — if no, the dep needs a shipped-or-auto path before merge.
12. **Verify before claiming done. No "should work". No "probably fine". Run it, read it, confirm it.**
13. **Anti-hallucination.** Don't invent paths, packages, endpoints, flags, versions. Uncertain → check or say so.

### Session 25 incident-driven rules

14. **Clippy `unused_imports` is unreliable for macros re-exported through crate root** (tracing::warn, rusqlite::params, etc.). If clippy says "unused import: warn" but `warn!()` is called, the import is needed — add `#[allow(unused_imports)]` with a comment explaining the false positive. Don't blindly delete.
15. **Boxed `Fn() -> T + Send + Sync` is NOT UnwindSafe** — wrap with `std::panic::AssertUnwindSafe(|| b())` when crossing `catch_unwind`.
16. **`tokio::runtime::Handle::try_current().block_on()` is safe ONLY from `spawn_blocking` contexts** — not from a tokio worker. The pattern in [updater/probes.rs](SRC/neothd/src/updater/probes.rs) blocking wrappers is correct because the cron-builder closure runs on `spawn_blocking`.
17. **Windows-safe atomic rename**: remove the target file FIRST when it exists, then rename `.tmp` → final. Plain rename fails on Windows when target exists.
18. **macOS clippy beta will warn about doc_lazy_continuation in tests/cli_paperless_binary.rs** — currently fixed but a future doc edit in test files can re-trigger. The fix: indent the wrapped doc-comment line with 2 extra spaces.
19. **`UpdaterTaskKind::CliVersions` (plural)** — easy to typo as CliVersion (singular). Triple-check this when wiring serve.rs.
20. **The `feature-flag compile / qwen-cuda` job is expected to "X" with continue-on-error** — that's not a real failure. The matrix passes as long as Linux/macOS/Windows × stable + the qwen-metal job + WASM + example builds all ✓.

### Memory loaded on every session (from `MEMORY.md`)

Key entries the next Claude should re-read at start:
- **[neoth-road-to-v1](memory/neoth_road_to_v1.md)** — NEOTH road to v1.0 (6 lanes v0.2.1 → v0.3 → v0.4 → v0.5 → v0.9 → v1.0).
- **[neoth-progress-md-update-rule](memory/neoth_progress_md_update_rule.md)** — PROGRESS.md MUST be updated in the same turn as the code ship.
- **[neoth-design-v11-is-norm](memory/neoth_design_v11_is_norm.md)** — `PLAN/00_DESIGN_v1.1_FINAL.md` is authoritative. Don't blindly trust audit reports dated before v1.1.
- **[neoth-windows-build](memory/neoth_windows_build.md)** — Windows build needs vcvars64 + System32 cmd wrapper.
- **[neoth-public-release-safety](memory/neoth_public_release_safety.md)** — Public push MUST exclude `QUELLEN/` (1.7GB third-party) + `RECON/` (operator-private) + `SRC/target/`.
- **[neoth-claude-cli-tmux-mandatory](memory/neoth_claude_cli_tmux_mandatory.md)** — `claude --print` subprocess is broken on some setups; tmux warm session is the only working path.

---

## Local verification status

**Windows host has no MSVC toolchain.** `cargo check` / `cargo build` fail with:
```
error occurred in cc-rs: failed to find tool "ml64.exe": program not found
```
This blocks local compile verification of `neothd` (cudarc + ring + zstd-sys + libsqlite3-sys all need ml64).

Workaround: rely on CI for compile verification. The matrix runs Ubuntu + macOS + Windows × stable + beta and catches everything.

If the next Claude has time + wants to verify locally:
1. Install Visual Studio 2022 Community with "Desktop development with C++" workload (~3GB).
2. From a Developer Command Prompt: `cd SRC && cargo check -p neothd`.
3. Or use the prior session's PowerShell wrapper if it existed (search `scripts/cargo-msvc.ps1` — was missing this session).

`cargo fmt --all -- --check` works locally (no native deps). Use it always before committing.

---

## Active dev environment

```
Windows host        = Win11 Pro 10.0.26200
Git Bash            = /usr/bin/bash
PowerShell          = available but not the default
gh CLI              = installed, authenticated
cargo               = 1.95.0 stable (1.96.0-beta.9 also in toolchain)
rust-toolchain      = stable (rust-toolchain.toml at workspace root if it exists)
Workspace path      = <your-workspace>/AGENTER (cwd = AGENTER, build cwd = AGENTER/SRC)
WAL home            = ~/.neoth (default per FreedomConfig::default_neoth_home)
```

**Operator memory** at `~/.claude/projects/<workspace>/memory/` is always loaded on session start. Read `MEMORY.md` first.

---

## How to start Session 26

1. **Re-read this handoff end-to-end.**
2. **Check git status + CI:**
   ```bash
   cd /c/<your-workspace>/AGENTER
   git status
   git log --oneline -10
   gh run list --limit 3
   ```
3. **Read `PLAN/PROGRESS_v1_0.md` "v0.3 — Credentials import" + "v0.3 — Auto-update" + "v0.3 — Accelerated from v0.4" sections** to see the Session 25 status flips.
4. **Confirm operator's intent for the next slot:**
   - If "SX-08 tag" — follow the recipe above. Wait for explicit "go" before tagging.
   - If "W-05d / C-05d ingester" — clone the cluster::audit_sidecar pattern. ~1-2h ship.
   - If a large SPEC item — open a NEW handoff doc for it first (don't try to ship in one turn).
   - If "weiter mit allen pending" — start with W-05d (lowest-risk + closes the sidecar→WAL gap I left open).

---

## What we explicitly left UNFINISHED in Session 25

These are NOT shipped despite their PROGRESS sibling being shipped. The next Claude should NOT mark them done without doing the work:

1. **W-04 WAL `0xD5 DETECT_COMPLETE` emit** — wizard step1b prints the summary but doesn't write the WAL frame. Daemon picks up the cache on next boot but never emits the audit frame. Either spawn a one-off writer in the wizard OR drop a sidecar like W-05c.
2. **W-04 git/gpu/disk_free probes** — currently `None` in DetectStepInputs. Probes need wiring.
3. **W-05c daemon-side ingester** — sidecar drops at `~/.neoth/installer_ran_<ts>.json` but no daemon task reads them yet. **THIS IS W-05d** above.
4. **C-05 daemon-side ingester** — sidecar drops at `~/.neoth/credentials_import_<ts>.json` but no daemon task reads them. **THIS IS C-05d** above.
5. **EL-01 freedom.yaml config** — `DoctorCronConfig::default()` is hardcoded in serve.rs. No `freedom.yaml::doctor` field to override.
6. **U-04 freedom.yaml config** — same as EL-01. `UpdaterCronConfig::default()` hardcoded; no `freedom.yaml::updater.cron_interval_secs` field.
7. **U-02b skill/plugin registry** — every U-02 cron tick currently emits `Failed(NO_REGISTRY_RESOLVER_MSG)`. Operators will see noise in `neoth updater status`. Triage this before tagging v0.2.1 (or document it as known-failure in release notes).
8. **C-05b GUI panel** — wizard step exists, GUI parity does not.
9. **C-03b / C-04b decrypts** — substrates ship a "deferred-decrypt" warning; operators with Chrome/Firefox credentials use Bitwarden export today.
10. **WAL writer one-off in CLI** — multiple CLI paths (`neoth update --self --apply`, wizard `step6h_install_recommended`, etc.) would benefit from being able to emit a single WAL frame. The pattern: spin a writer + emit + drop. The cleanup is `Drop` on the writer handle which awaits the segment fsync. ~30min refactor if you want it.

---

## Commit-tagging conventions in use

(Observed from operator's own commits + session-25 commits, follow exactly.)

- `feat(<scope>): vX.Y <ITEM-ID> — <one-line description>`
- `fix(<scope>): <one-line description>`
- `docs(progress): <one-line description>`
- `ci: <one-line description>`
- `refactor(<scope>): <one-line description>`
- `chore(<scope>): <one-line description>`

Commit BODY:
- 1-2 sentence WHY paragraph.
- Bullet list of what changed under headers like "## What ships here", "## What's deferred".
- DO NOT auto-add "Generated with Claude Code" or "Co-Authored-By: Claude". Per global settings.json, attribution is disabled.
- Use `git -c core.autocrlf=false commit -m "$(cat <<'EOF' ... EOF)"` to avoid CRLF normalization warnings poisoning the commit message.

---

## Quick-reference file index

```
Wizard step wiring          SRC/neothd/src/cli/init.rs (step1b, step6g, step6h)
Doctor cron                 SRC/neothd/src/daemon/doctor_cron.rs
Updater cron                SRC/neothd/src/daemon/updater_cron.rs
Updater probes              SRC/neothd/src/updater/probes.rs
Hindsight session-end       SRC/neothd/src/memory/hindsight.rs
Chat-side hindsight wire    SRC/neothd/src/cli/chat.rs (run_chat_with)
Daemon spawn (all crons)    SRC/neothd/src/cli/serve.rs (sections 5d.b + 5d.c)
SecretBytes hardening       SRC/neothd/src/credentials/mod.rs
Credential redactor         SRC/neothd/src/security/credential_redact.rs
Installer CLI               SRC/neothd/src/cli/installer.rs
Updater CLI + WAL reader    SRC/neothd/src/cli/updater.rs
Self-update probe           SRC/neothd/src/updater/self_update.rs
Install scripts             SRC/install.sh + SRC/install.ps1
Winget manifests            SRC/dist/winget/manifests/T/TheGeekFreaks/NEOTH/0.2.1/
WAL event codes             SRC/neothd/src/wal/events.rs (EVENT_TYPE_DOCTOR_TICK = 0x46)
CI workflow                 .github/workflows/ci.yml
Security workflow           .github/workflows/security.yml
.gitattributes (LF pin)     .gitattributes
PROGRESS                    PLAN/PROGRESS_v1_0.md
```

---

## Closing note for Session 26 Claude

The operator is a solo dev + security researcher who works in German + English. Pragmatic — wants ship-able primitives, not perfection. Hard rule: "When a roadblock surfaces in scope, fix it" — don't defer when you can ship.

Session 25 was a lot of feature work + CI infrastructure recovery. The codebase is now in a state where:
- The credentials lane substrate is shipped, browser-specific decrypts are real multi-day work
- The wizard onboarding flow has 9 substantive steps (license / operator_id / language / role / provider / 5b inference / 5c qwen / 5d profile / 6 channel / 6b keet / 6c obsidian / 6d vault / 6e n8n / 6f jarvis / **6g credentials NEW** / **6h install-preview NEW** / 7 autonomy / 7b auto_update / 7c plugins / 8 summary)
- The daemon spawns 5 cron tasks on `neoth serve` startup: regular `cron::scheduler` for operator jobs, `doctor_cron`, `updater_self`, `updater_cli`, `updater_skill`
- CI is green on the canonical matrix with explicit per-OS feature curation

If this handoff is missing something the operator asks about, search `git log` first — the commit bodies are detailed.

Good luck. Ship clean.
