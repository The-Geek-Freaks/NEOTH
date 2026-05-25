# PROGRESS — v1.0 working backlog

**Date:** 2026-05-24
**Predecessor archive:** `PLAN/PROGRESS_v0_2_FINAL.md` (4612 lines, historical record of v0.1 → v0.2 closeout)
**Reference docs:**
- `PLAN/v1_0_OPERATOR_WISHLIST_2026-05-24.md` — 35-bucket verbatim operator wish-list
- `PLAN/ROAD_TO_1_0.md` — 5-lane roadmap (v0.3 → v1.0)

This file is the working backlog. Items roll `[ ] open` → `[~] in flight` → `[x] shipped` exactly the way `PROGRESS_v0_2_FINAL.md` tracked v0.2. Every shipped item carries a commit hash + line of evidence. Same-turn PROGRESS flip rule from v0.2 carries over: every code commit pairs with the `[~]` → `[x]` flip in the same commit.

**Synthesis source:** 6-agent Gremium deployed 2026-05-24 (A1 Product Strategist / A2 Feature-Synergy / A3 Architecture Provocateur / A4 UX-Journey / A5 Security/Privacy/Ops / A6 Killer-Features). All 6 reports preserved in `C:\Temp\claude\...\tasks\` agent transcript files; this backlog is the deliverable.

---

## State at session start

```
v0.2 closed       = 96/96 items     (PROGRESS_v0_2_FINAL.md)
v1.0 open         = 130 items below (5 lanes + 1 hotfix lane)
v1.0 in flight    = 0
v1.0 shipped      = 0
```

Total estimated effort: ~210-260 person-days across the 6 lanes.

---

## Lane priorities

| Order | Lane | Target | Est. | Gate |
| :-- | :-- | :-- | :-- | :-- |
| 1 | **v0.2.1 SECURITY HOTFIX** | 2-3 days | ~7d | A5 critical findings before any v0.3 work merges |
| 2 | **v0.3 — Wizard + Auto-update + Crash recovery** | 5-6 weeks | ~42-50d | "Alex's mom on Win11 with no dev tools" path lands |
| 3 | **v0.4 — Confirm-fatigue kill + Memory verify + n8n smarts + Killer-#1/2/7** | 4-5 weeks | ~30-38d | Trust + speed wins, first 3 small-effort killer features |
| 4 | **v0.5 — Multimodal + Paperless + Email/Cal + Obsidian-as-scratchpad** | 6-7 weeks | ~45-55d | Real-life ingestion surface; PL-04/PL-05 gate EM-* |
| 5 | **v0.9 — Proactivity + Slave coupling + Native PC + Arxiv + killer-#1/4/5/8** | 7-8 weeks | ~55-65d | "Anticipates what I want"; cluster as nodes |
| 6 | **v1.0 — Polish + Security + Perf + GUI 12/10 + 14 SC-items + killer-#3/6/9/10** | 5-6 weeks | ~50-60d | Public-release-quality bar |

Each lane ships independently with its own tag (`v0.2.1` / `v0.3.0` / `v0.4.0` / `v0.5.0` / `v0.9.0` / `v1.0.0`). No lane merges with red gates.

---

## v0.2.1 — SECURITY HOTFIX  (must ship before v0.3 work merges)

Source: A5 audit critical findings + 2 CI gaps. ~7 days.

- [x] **SX-01** `tools/web_fetch.rs`: `validate_url_not_private()` step at top of `fetch()`. Resolve hostname → IP, reject RFC-1918 + RFC-4193 + loopback + link-local + cloud metadata endpoints (169.254.169.254 + GCP + Azure). Reject non-`http(s)` schemes via parsed URL scheme, not string prefix. — A5 CRIT-01 — **v0.5 ingest blocker** — 1d — ✅ 2026-05-25 Session 24. `validate_url()` parses via `url::Url::parse`, scheme allow-list (http/https only), hostname blocklist (`metadata.google.internal`, `metadata.azure.internal`, literal `169.254.169.254`), DNS pre-resolve + every IP against `is_private_ip` (loopback, RFC-1918, link-local, RFC-4193 fc00::/7, fe80::/10, RFC-6598 CGNAT 100.64/10, RFC-2544 benchmarking, IPv4-mapped-IPv6 bypass `::ffff:127.0.0.1`, broadcast, multicast, unspecified). Redirect bypass closed via new `http_client::build_client_no_redirect()` (`reqwest::redirect::Policy::none()`) — operator sees 3xx + Location header instead of being silently forwarded. Added `url = "2"` direct dep. 20 new `#[tokio::test]` rejection cases + pure-fn matrix-test for `is_private_ip` (DNS-free). Test-only `LoopbackGuard` thread-local opt-in (`#[cfg(test)]` — never compiled into release) so the 5 existing wiremock round-trip tests still work against `127.0.0.1`.
- [ ] **SX-02** `wal/snapshot.rs`: redact `ChannelSend` `before_state` via `redact_text()`. Test at line 530 currently pins the wrong invariant — invert it. Update production callsites `channels/mod.rs:490-505` + `:534-547` to verify redacted bytes land in WAL. — A5 CRIT-02 — **1-line fix + test invert** — 0.5d
- [ ] **SX-03** `wasm_plugin/hostcalls.rs:165`: pipe `msg` through `security::redact::redact_text()` before `tracing::info!`. Add OpenGrep rule that grep finds any other plugin-supplied-bytes → tracing path. — A5 CRIT-03 — 0.5d
- [x] **SX-04** `.github/workflows/security.yml:54`: drop `|| true` from `cargo audit --json` step. CI currently swallows vulnerabilities silently. — A5 SC-12 — 0.1d — ✅ 2026-05-24 Session 24. GHA bash default `set -eo pipefail` now propagates cargo-audit's non-zero exit on RUSTSEC findings.
- [x] **SX-05** `deny.toml`: add `x86_64-pc-windows-msvc` to `[graph].targets`. Windows-only transitive deps (`windows-sys` sub-features, `portable-pty` ConPTY path) are currently never checked by `cargo deny`. — A5 SC-13 — 0.2d — ✅ 2026-05-25 Session 24. Already shipped in `SRC/deny.toml:20` at initial public release (the live config); the duplicate root `deny.toml` was dead/stale. Dead root config `git rm`'d as part of SX-05b cleanup. (Verification-driven discovery: the original handoff line-anchor pointed at the dead config.)
- [x] **SX-05b** cargo-deny config cleanup uncovered by SX-05 verify: (a) migrate `SRC/deny.toml` to schema v2 (drop deprecated `yanked`/`unmaintained`/`notice`/`vulnerability` severity scalars and `[licenses].deny` list — all removed in cargo-deny ≥0.16 per PR #611); (b) add `CDLA-Permissive-2.0` + `BSL-1.0` to license allow-list (webpki-roots, xxhash-rust transitives); (c) add advisory ignores for 4 unmaintained-but-no-vuln transitives (bincode RUSTSEC-2025-0141, number_prefix -0119, paste -2024-0436, xsalsa20poly1305 -2023-0037); (d) eliminate banned `openssl-sys` from the graph by bumping `hf-hub` 0.3.2 → 0.5.0 with `default-features = false, features = ["tokio", "rustls-tls"]` and renaming the 4 `.get(filename)` callsites to `.download(filename)` per the 0.5 API. **Discovery:** security CI silent-red since at least 3 prior pushes (2-14s runs = schema-parse fail; gate never executed). Now all 4 deny classes (advisories/bans/licenses/sources) report `ok`. — ✅ 2026-05-25 Session 24.
- [ ] **SX-06** Verify gate: re-run `cargo audit` + `cargo deny check` on the secured surface; smoke-test SSRF block list with hand-crafted URLs (`http://169.254.169.254/...`, `http://localhost:9744/api/health`, `file:///etc/passwd`) — 0.5d
- [ ] **SX-07** Documentation: add `docs/security/threat-model.md` describing the 6 outbound surfaces NEOTH controls + the consent gates that protect them. Operator-readable. — 1d
- [ ] **SX-08** Tag `v0.2.1`, push, release-notes "security hotfix". — 0.1d

**Gate:** fmt + clippy `-D warnings` + tests green + manual SSRF smoke + cargo-audit + cargo-deny all clean. Tag `v0.2.1.`

---

## v0.3 — Wizard + Auto-update + Crash recovery

A1 acceleration: **EL-01 doctor + OP-02 Hindsight + P-01 7-tier classifier promoted from v0.4** (behavioral change, not infrastructure dependency).

### v0.3 — Wizard expansion (from A4 architect report)

- [ ] **W-01** `installers/detect.rs` + `installers/gpu.rs` — central `DetectReport` + `GpuKind::{Cuda,Rocm,Metal,Cpu}` probe with VRAM read. Cached at `~/.neoth/detect_cache.json` with 24h TTL. — 2d
- [ ] **W-02** 8 new installer modules: `ffmpeg.rs`, `ollama.rs`, `tailscale.rs`, `hysteria2.rs`, `paperless.rs`, `omi.rs` + extend `tmux.rs` + `obsidian_vault.rs`. Each follows the existing `recommend_install_path` + `check_xxx` pattern. — 4d
- [ ] **W-03** `wizard/recommend.rs` — pure-fn `RecommendationEngine`. VRAM ≥ 24GiB → qwen2.5-72b / 8-23GiB → qwen2.5-7b / <8GiB → cloud. Binary-detect-based channel + VPN recommendations. **Plus W-03a sub-item (A2 #13): expose `operator_complexity_level() -> ComplexityLevel` method so GU-03 calls the same entry point at v1.0 time.** — 1.5d
- [ ] **W-04** `wizard/detect_step.rs` — wizard step wiring + `tokio::join!` parallel probes + 24h cache. New WAL frame `0x11 DETECT_COMPLETE`. — 2d
- [ ] **W-05** `wizard/install_step.rs` — fallback chain (winget→choco / apt / dnf / pacman / brew) + dry-run + WAL `0x12` extend. **Plus W-05a sub-item (A2 #9): extract `PkgManagerHandle` trait with `install` + `upgrade` so W-05, U-01, U-03 share the same fallback impl.** — 3.5d
- [ ] **W-06** `wizard/shared_state.rs` — `WizardStateV2` with `#[serde(flatten)] base` for v0.2 freedom.yaml round-trip. — 1d
- [ ] **W-07** GUI wizard parity via shared IPC channel to `run_probes()`. **A4 critical: GUI wizard onboarding is the single biggest "Alex's mom" cliff.** — 3d
- [ ] **W-08** New WAL frames: `0x11 DETECT_COMPLETE`, extended `0x12 INSTALLER_RAN` (add `dry_run` + `wizard_step` + `cli_name` + `pkg_mgr` fields), `0x15 CREDENTIAL_IMPORT` (with `services_redacted=true` per A5 SC-17). — 1d

### v0.3 — Credentials import (from A4)

- [ ] **C-01** `credentials/mod.rs` + `types.rs` — `CredentialImporter` trait + `ImportedCredential` with SecretString+mlock+zeroize. No on-disk plaintext copy. — 2d
- [ ] **C-02** `credentials/bitwarden.rs` — accepts encrypted export JSON, parses in-process. **A5 SC-17: add depth limit before `serde_json::from_slice` to prevent stack overflow on adversarial JSON.** — 2.5d
- [ ] **C-03** `credentials/chrome.rs` — Login Data SQLite + DPAPI (Win) / DBUS Secret Service (Linux) / Keychain (macOS). **A5: warn operator if Chrome DB appears locked.** — 3d
- [ ] **C-04** `credentials/firefox.rs` — key4.db + logins.json + NSS via subprocess `certutil`. — 2d
- [ ] **C-05** Wizard step + settings panel parity + `services_redacted=true` WAL field per A5 SC-17. — 2d

### v0.3 — Auto-update (operator wish-list B)

- [ ] **U-01** Self-update for the `neoth` binary (signed-release verify + atomic swap + rollback). Reuses W-05a `PkgManagerHandle` trait. — 3d
- [ ] **U-02** Skills + plugins auto-update — `~/.neoth/skills/<id>/skill.yaml` + `plugins/<id>/plugin.json` re-resolve on schedule. Operator chooses cadence. — 3d
- [ ] **U-03** Detected CLI environment updaters: `claude` / `codex` / `gemini` CLI versions tracked + bumped via W-05a `PkgManagerHandle`. — 2d
- [ ] **U-04** Cron-task `0x4? updater task` writes WAL frame per check. Operator-readable `neoth updater status`. — 1d

### v0.3 — Crash recovery + UX gaps (from A2 + A4)

- [ ] **R-01** Turn-Journal write-ahead JSONL for `neoth chat` mid-stream durability. New WAL band `0x05 TURN_JOURNAL_OPENED` / `0x06 TURN_JOURNAL_CLOSED`. — 1d (hermes adopt)
- [ ] **R-02** `.bak` session recovery — snapshot-on-shrink + startup compare-and-restore. — 1d (hermes adopt)
- [ ] **R-03** TPS metering SSE in chat header (1Hz streaming / 10Hz idle / 60min rolling). — 1d (hermes adopt)
- [ ] **R-04** Wizard resume after crash — `wizard_checkpoint.json` after every step. **A4 zero-coverage gap.** — 0.5d
- [ ] **R-05** Auto-start daemon after wizard step 9 (`"Start NEOTH now? [Y/n]"`) + first proactive message: "Hi, I'm running. Want a quick tour?" **A4 delight moment.** — 0.5d
- [ ] **R-06** `neoth recover` command — checks for `*.bak` + journal entries, presents "incomplete session from [ts] — resume?" UI layer for R-01/R-02. — 1d
- [ ] **R-07** Auto-scheduled backup — wizard adds `auto_backup_weekly: true` default + `~/.neoth/backups/` rolling 4-copy retention. **A4 zero-coverage gap.** — 1d
- [ ] **R-08** Zero-install entry: `cargo-dist` artifact in GitHub Releases + winget manifest stub + `curl | sh` script. **A4 critical: today there is no Alex's-mom path at all without `cargo build`.** — 2d

### v0.3 — Accelerated from v0.4 (per A1 + A4)

- [ ] **EL-01** `neoth doctor` cron + actionable findings + WAL audit. **A1 promote: day-1 trust builder for non-dev.** — 2d
- [ ] **OP-02** Hindsight session compression on session-end (oh-my-pi port). **A1 promote: cheap, high-impact on every session.** — 1.5d (MIT license confirmed)
- [ ] **P-01** 7-tier approval classifier (`readonly_scoped` / `readonly_search` / `mutating` / `exec_capable` / `control_plane` / `interactive` / `unknown`) — auto-approve safe tiers at `standard` autonomy. **A1+A4 critical: promoted to v0.3 — behavioral change, kills confirm fatigue before v0.5 surfaces multiply tool calls.** — 1.5d (openclaw adopt)

### v0.3 — Architecture quick-wins (from A3)

- [ ] **AR-01** PrePipeline `preset_injector` built-in hook — **BUG FIX**: 5 personality presets exist in `profile/presets.rs` but `apply_preset` returns `PresetData` only at wizard-time. Runtime `neoth profile preset apply lowkey` does not take effect until daemon restart. — A3 #9 — 0.5d
- [ ] **AR-02** `neoth hook trace --since 2h` — band `0x80..0x8F` is reserved but **all hook lifecycle events are undefined**. Add `0x80 HOOK_FIRED`, `0x81 HOOK_MUTATED`, `0x82 HOOK_BLOCKED`, `0x83 HOOK_TIMED_OUT`. — A3 #3 — 1.5d
- [ ] **AR-03** Hook chain composition `[hook_chain.PreChannelIngress]` with ordered priority + `fail_fast: bool` in freedom.yaml. — A3 #6 — 1d
- [ ] **AR-04** `neoth cron preview <id>` — dry-run + token-cost estimate + autonomy-check before commit. — A3 #8 — 1.5d

**v0.3 total: ~42-50 days. Tag: `v0.3.0`. Gate: full workspace tests green + GUI wizard manual walk-through + Linux+Win+macOS install dry-runs.**

---

## v0.4 — Confirm-fatigue kill + Memory verify + n8n smarts + First killer features

### v0.4 — Memory + brain verification (from A5 + A2 dependency analysis)

- [ ] **M-01** Hebbian reinforce on warm + cold tier hit. Currently `memory/tiers.rs:139::hebbian_reinforce_event` hardcoded to `idx_episode`. SPEC `PLAN/SPEC_memory_tiers.md` requires all-tier. — A5 M-1 — 1d
- [ ] **M-02** CLI recall emits `0x93 IMPORTANCE_REINFORCED` WAL frame. Currently `cli/recall.rs:197` skips → tamper-evident log hole. — A5 M-2 — 0.5d
- [ ] **M-03** Replace `now_ns = unwrap_or(0)` with fail-safe skip in `memory/decay_task.rs:57`. Clock failure currently triggers mass hot→warm migration. — A5 M-3 — 0.5d
- [ ] **M-04** Fix misleading `decay_task::run() -> Result<()>` signature for infinite-loop body. — A5 M-4 — 0.3d
- [ ] **M-05** DB-level constraint on `day` column ISO-8601 format for warm→cold SQL string compare. — A5 M-7 — 1d
- [ ] **M-06** Surface `cold_swept` in `PassReport` (currently `tracing::debug!` only). — A5 M-5 — 0.3d
- [ ] **M-07** Memory integration test suite under `SRC/neothd/tests/memory_*.rs`. **A1 top-priority gap #1; A2 sequence: must ship before M-09 and OM-01.** — 4d
- [ ] **M-08** 6-region SQLite view cooperation verification — hippocampus + amygdala + insula + cerebellum + basal-ganglia + hypothalamus each work AND coordinate. — 2d
- [ ] **M-09** Recall routing per region — query type → region selection logic. Replace flat search. — 2.5d
- [ ] **M-09b** Conversational recall wrapper — intercept "do you remember when ..." in chat pipeline, route to `recall::run_recall`. Format as "Yes — on [date] you said: [quote]". — A4 F3-1 — 1d

### v0.4 — Confirm-fatigue kill (from A2 openclaw adopts)

- [ ] **P-02** `allow-once / allow-always / deny` tri-state for consent gate. `allow-always` promotes to persistent allow-list via WAL `0x30 CONSENT_DECISION` (claim band). — A2 — 1d
- [ ] **P-03** Domain Event Bus — non-exhaustive `DomainEvent` enum + `tokio::sync::broadcast` for council / sub_agents / cron decoupling. — A2 (openhuman adopt) — 1.5d
- [ ] **P-04** Tiered RPC dispatch + `redact_params_for_log` — secret-key redaction before any debug trace. — A2 (openhuman adopt) — 1d
- [ ] **P-05** Event Ledger (lightweight JSON sidecar, lock+atomic-writes) for Slint GUI cold-start replay without decrypting WAL. — A2 (openclaw adopt) — 2.5d

### v0.4 — Day-7 reflection (A1 + A4 acceleration from v0.9)

- [ ] **G-01-mini** Minimal Day-7 reflection cron: 1 hardcoded template "Du hast diese Woche an [X], [Y], [Z] gearbeitet — willst du an einem mehr dranbleiben?" No pattern engine yet. **A4 F2-3 + A1: prevents the "chat client not agent" misclassification in week 1.** — 1d
- [ ] **G-01a** `ProactiveQueue` struct (priority + dedup key + channel target + source tag). Drained max 3/day default. **A2 #11: prerequisite for PL-03 + OB-03 not creating notification storms in v0.5.** — 1d

### v0.4 — n8n smarts + MCP token wins (A1 keeps n8n adopt)

- [ ] **N-04** Smart MCP loader — don't ship all MCPs in every chat context; load on first slash-command / first explicit reference. — 2.5d
- [ ] **N-05** `cron-vs-n8n` decision rule lifted from `docs/cron-vs-n8n.md` into runtime `cli/cron.rs` guidance. — 1d
- [ ] **N-06** n8n workflow registry — top-10 starter workflows beyond existing 3 bootstrap. **A2 #2 sequencing dependency: ships after OB-01 in v0.5.** — 2d (moves to v0.5)
- [ ] **N-07** codegraph as auto-launched MCP provider in `cli/code.rs`. -35% cost / -70% tool calls measured. — A3 + A6 sequencing #6 — 1d (MIT)

### v0.4 — Quick wins from A3 (other architecture gaps)

- [ ] **Q-01** claude-plugins-official schema adoption — `plugin.json` with commands/agents/skills/.mcp.json convention. — 0.5d
- [ ] **Q-02** Book of Secret Knowledge → TOML skill catalog parser. — 0.5d (MIT)
- [ ] **AR-05** `neoth profile conflicts` + resolve workflow. **A3 #5: prerequisite for G-02 in v0.9.** — 1.5d

### v0.4 — First three small-effort killer features (A6)

- [ ] **KF-02** `neoth memory diff --region amygdala --from 7d --to now` (A6 #2 / A3 #4 merged). — 2d
- [ ] **KF-06** `neoth permissions audit` — every permission decision + downstream effect. — A6 #6 — 2d
- [ ] **KF-07** Hebbian drift report `neoth memory drift` — beliefs fading from ground-truth tier. — A6 #7 — 2d

**v0.4 total: ~30-38 days. Tag: `v0.4.0`. Gate: M-07 test suite must produce coverage report + P-01..P-05 walk-through + 3 killer features demoable.**

---

## v0.5 — Multimodal + Paperless + Email/Cal + Obsidian-as-scratchpad

A1 binding: **PL-04 + PL-05 hard pre-condition before any EM-* item merges.** A5 binding: **CRIT-01 SSRF guard from v0.2.1 must be live before paperless URL ingestion goes live.**

### v0.5 — Multimodal final 10%

- [ ] **MM-01** Voice call live-transcript — streaming Whisper + Piper TTS reply (channel + GUI). — 5d
- [ ] **MM-02** Video call live frame ingest + multimodal council (image + audio + text fused). — 6d
- [ ] **MM-03** Piper-rs / vendor TTS dispatcher for outbound `send_audio` path. New module `media/tts.rs`. — 3d

### v0.5 — Email + Calendar (A1 scope decision)

**Gated on PL-04 + PL-05 + SX-01 (SSRF) shipping first.**

- [ ] **EM-01** Gmail OAuth/IMAP ingest skill (read + send + draft). **A1: includes Proton via Bridge in same lane — one-line addition.** — 4d
- [ ] **EM-02** Calendar adapter (Google + CalDAV) — read + create. — 3d
- [ ] **EM-04** Email draft generation for high-importance unread (operator approves before send). — A1: EM-03 (auto-calendar entry) **deferred post-v1.0** to prevent "NEOTH deleted my meeting" incident in first week. — 2d

### v0.5 — Paperless (security-gated first)

- [ ] **PL-04** Prompt-injection gate on every paperless ingest + email body. **A5 SC-16: not a "reuses ingress_sanitizer" — explicit call-site audit + new email-MIME normalization (SC-15) + paperless OCR sanitization (SC-16) before any PL-* / EM-* merges.** — 2d
- [ ] **PL-05** Spam + phishing + malware detection on email body (rules engine + LLM second-opinion). — 3.5d
- [ ] **PL-04a** Adversarial OCR test fixture targeting the ingress sanitizer paperless path. **A2 #4 sub-item.** — 0.5d
- [ ] **PL-01** paperless-ngx + paperless-ai auto-install via wizard (W-02 followup). — 2d
- [ ] **PL-02** OCR ingest → Obsidian `.md` knowledge via `cloud/obsidian` sync; tag as ground-truth. — 3d
- [ ] **PL-03** Proactive paperless consultation: cron checks new docs → emits via `G-01a ProactiveQueue`. — 2d

### v0.5 — Obsidian-as-scratchpad

- [ ] **OB-01** Dreaming pipeline writes nightly themes to `~/Obsidian/NEOTH/Dreams/YYYY-MM-DD.md`. — 1.5d
- [ ] **OB-01a** `DreamSummary::to_obsidian_md()` shared serializer — **A2 #2 sub-item**: prevents G-01 + N-06 from duplicating formatting logic. — 0.3d
- [ ] **OB-02** Reflection + self-improvement notes auto-archived to vault `Reflections/`. — 2d
- [ ] **OB-03** Proactive action staging: NEOTH proposes a cron / skill / config tweak → writes draft `.md` for operator approval. Drains via `G-01a ProactiveQueue`. — 2d

### v0.5 — Codebase analysis (A1 demoted from earlier)

- [ ] **UA-01** Optional `neoth code analyze` step that consumes `understand-anything` JSON output. — A1 demoted to v0.5 from v0.5 (kept here; was earlier-positioned). — 1d

### v0.5 — Security additions (A5 SC-15..18)

- [ ] **SC-15** Email-specific sanitizer: MIME normalize → quoted-reply block strip → attachment filename sanitization. New stage in `ingress_sanitizer`. — A5 — 2d
- [ ] **SC-16** Every paperless OCR path runs through `ingress_sanitizer::sanitize()` before memory or LLM. Explicit call-site audit. — A5 — 1d

**v0.5 total: ~45-55 days. Tag: `v0.5.0`. Gate: SX-01 SSRF guard + PL-04/PL-05 verified before EM-01 merge; email walk-through + paperless walk-through; multimodal voice-call demo.**

---

## v0.9 — Proactivity + Slave coupling + Native PC control + Arxiv + killer features

### v0.9 — Proactivity (full from operator wish-list G)

- [ ] **G-01** Self-initiated message engine — pattern-detection cron emits "I noticed X, want me to do Y?" via operator-preferred channel. Drains `G-01a ProactiveQueue`. — 4d
- [ ] **G-02** Confidence-threshold profile claim surfacing. **A3 #5 prerequisite: AR-05 `neoth profile conflicts` must ship first to prevent surfacing wrong self-knowledge.** — 3d
- [ ] **G-03** Self-correction loop — every reply scored against operator feedback signal (👍/👎 via channel reaction or follow-up tone). — 4d

### v0.9 — Slave / cluster coupling (A1 sequencing decision)

- [ ] **SL-01** OpenClaw-slave + Hermes-slave + OpenHuman-slave adapter contracts — discover via cluster pairing + register as nodes. **A1: master first + thin slave shim (registry entry + accept-task endpoint) in same lane; full slave logic deferred to v1.0 hardening.** — 5d
- [ ] **SL-02** Cluster topology view in CLI + GUI — node health, channel mesh status, hysteria/tailscale RTT, stability score. — 4d
- [ ] **SL-03** Local LLM / cluster resource tab — VRAM/load/power, currently-loaded models, RAM vs VRAM. **Plus A2 #3 sub-item: `ResourcePressureWatcher` task on 30s tick comparing live readings against W-03 VRAM rules + emit advisory WAL frame when VRAM > 90%.** — 5d
- [ ] **SL-01a** Capability Lease primitive — TTL-bounded scoped `Action` grant for sub-agents/plugins. **A3 #2: unblocks G-01 (bounded write access for proactive) and SL-01 (slave delegation). New WAL band `0xA4/A5/A6 LEASE_GRANTED/EXPIRED/REVOKED`.** — 2.5d
- [ ] **SL-01b** Cluster WAL gossip — `src/cluster/wal_sync.rs` with band-filter as ACL boundary. New WAL frame `0xE8 CLUSTER_WAL_SYNC_SENT`. **A3 #10: SL-01 slave can't be context-aware without WAL gossip.** — 3.5d
- [ ] **SL-01c** Cluster pair by hostname not raw pubkey. **A4 F5-1 + memory sync prompt.** — 1d

### v0.9 — Native PC control (A1 scope decision)

- [ ] **PC-01** OS-tool surface — file/folder ops, app launch, window mgmt, clipboard, system audio control. **A1 binding: default-safe whitelist gated by autonomy; operators at `elevated`/`full` extend via `freedom.yaml::tools.os.allowed_paths`. NO registry / system-paths / process-kill in defaults. All actions WAL-auditable.** — 7d
- [ ] **PC-02** Chrome DevTools MCP as optional plugin **with forced `CHROME_DEVTOOLS_MCP_NO_USAGE_STATISTICS=1` env var + license confirm pre-merge**. **A3 hard-blocker from earlier audit.** — 1d once unblocked

### v0.9 — Error + arxiv learning

- [ ] **EL-02** arxiv paper ingest skill (operator-curated topic feed) + summary → memory tier. **A1: but DEMOTED priority — researcher-persona feature.** — 3d
- [ ] **EL-03** Learn-from-arxiv pipeline. **A1: DEFERRED post-v1.0 unless time permits.** — _post-v1.0 stretch_
- [ ] **EL-03a** Obsidian front-matter schema for self-dev proposals (`status`, `source: arxiv:<id>`). **A2 #8 sub-item.** — _ships when EL-03 ships_

### v0.9 — oh-my-pi adopts (A1 priority order)

- [ ] **OP-01** hashline content-hash edits port into `cli/edit.rs` (-61% output tokens measured). — 1d (MIT)
- [ ] **OP-03** LSP diagnostics loop on every write. — 1d (MIT)

### v0.9 — OMI integration (A3 sequencing + A5 SC-14)

- [ ] **OM-01** OMI ingest skill — subscribe to Jarvis-local OMI backend; action items → `idx_kanban_*`; transcripts → ground-truth seed. **A5 SC-14: code-level assertion validates `omi.endpoint` is Jarvis-local; aborts loudly if `api.omi.me`. A2 sequencing: M-07 + M-09 must ship in v0.4 before OM-01 lands.** — 1d (MIT)
- [ ] **OM-01a** WAL frame `0x94 OMI_ACTION_PROMOTED` — **A2 #1 sub-item**: emits when OMI transcript item crosses confidence threshold from hot to ground-truth. — 0.3d
- [ ] **SC-18** OMI batched sanitizer for stream rate. Quarantine → halt feed + notify operator, never silent drop. — A5 — 1.5d
- [ ] **HF-01** WAL frames for HF model downloads (`0x19 MODEL_DOWNLOAD_START` / `0x1A MODEL_DOWNLOAD_COMPLETE`) + wizard `allow_huggingface_downloads: bool` gate. **A5 HIGH-04.** — 1d

### v0.9 — Four medium-effort killer features (A6)

- [ ] **KF-01** Council Replay Glass — `neoth council replay <session-id>` reconstructs hemisphere transcripts + dissent + verdict. New WAL frames `0x50 COUNCIL_SESSION_OPEN` / `0x51 COUNCIL_SESSION_CLOSE`. — 5d
- [ ] **KF-04** Idle-Time Skill Forge — dreaming pipeline writes YAML skills for operator review. New WAL frames `0x78 SKILL_FORGE_PROPOSED` / `0x79 SKILL_FORGE_ACCEPTED`. — 5d
- [ ] **KF-05** Cross-Channel Memory Unification — extend `EnrichedRequest` with `channel_provenance: ChannelContext`. New `memory/channel_weights.rs`. — 4.5d
- [ ] **KF-08** Live Council Budget Meter — Slint GUI panel + tokio broadcast from `telemetry/council_meter.rs`. — 5.5d

### v0.9 — UX gaps from A4

- [ ] **UX-01** `neoth connect` discovery command for post-wizard channel on-ramp. — A4 F2-1 — 1d
- [ ] **UX-02** "Memory is working" session-start signal — single line "I remember N things from last time." — A4 F2-2 — 0.5d
- [ ] **UX-03** `neoth undo` last 5 mutating WAL frames with timestamps + select rollback. — A4 F3-3 — 2d
- [ ] **UX-04** `neoth profile show` with human-readable knobs + per-key `neoth config set` hints. — A4 F4-1 — 1.5d
- [ ] **UX-05** 30-day unlock moment — wizard hook on day 30 surfaces 3 unactivated features. — A4 F4-2 — 1d
- [ ] **UX-06** `neoth skill create` wizard — YAML-only skill authoring path for non-Rust operators. **A4 F7-1 critical: bridge to power-user transition.** — 2.5d
- [ ] **UX-07** `neoth plugin test <path>` harness — sandboxed host + WAL capture for pre-deployment plugin verification. — A4 F7-2 — 1.5d
- [ ] **UX-08** Example slash-command skill at `src/examples/wasm_plugins/slash_demo/`. — A4 F7-3 — 0.5d

**v0.9 total: ~55-65 days. Tag: `v0.9.0`. Gate: cluster handshake demo + native-PC whitelist walkthrough + 4 killer features demoable.**

---

## v1.0 — Polish + Security + Perf + GUI 12/10 + final killer features

### v1.0 — Security hardening (A1 + A2 #12 + A5 14 SC-items)

- [ ] **SC-01** OpenGrep security rulepack in CI — port openclaw rules + add NEOTH-specific (no raw HTTP/2 CONNECT, no plaintext-secrets-in-WAL). **Plus A2 #12 sub-item: rule `WAL_EVENT_DEFINED_BUT_NOT_EMITTED` to catch SD-02 / SD-03 class issues at PR time. Plus SC-01a: shell-script CI test grepping all EventType variants → assert each has emit call site.** — 1d
- [ ] **SC-02** Checkpoint / rollback API with strict path-traversal regex `[A-Za-z0-9_-][A-Za-z0-9_.-]{0,63}`. — 2.5d (hermes adopt)
- [ ] **SC-03** Plugin signature verification + revocation list. — 3d
- [ ] **SC-04** `neoth security audit` command — runs all gates + prints summary. — 2d
- [ ] **SC-08** n8n_api_token DPAPI wrap on Windows; DACL failure → blocking `neoth doctor` error. — A5 HIGH-01 — 1.5d
- [ ] **SC-09** Disaster-recovery runbook for DPAPI-bound HMAC key — wizard warning + opt-in plaintext key backup path + `neoth wal verify` error message improvement. — A5 HIGH-02 — 1d
- [ ] **SC-10** HF model download consent gate (lands earlier as HF-01 in v0.9; this SC-* tracks v1.0 polish: per-model download policy + cache-pruning command). — 1d
- [ ] **SC-11** Skill `tool_allowlist` enforcement at MCP gate, not just schema validation. — A5 HIGH-05 — 1d
- [ ] **SC-17** Credentials import WAL redact — verify `0x15` payload does not include credential name / URL / username. — A5 — 0.5d

### v1.0 — Spec ↔ code deltas (A5 §5)

- [ ] **SD-02** Wire `0x77 KANBAN_TASK_PROGRESS` events at the kanban write sites. **SPEC_coding_workflow.md Pick #1 claimed shipped but events are still "not yet wired".** — 1d
- [ ] **SD-03** Wire `0x38 CHANNEL_MSG_EDIT` event handler in `channels/telegram.rs`. — 2d
- [ ] **SD-04** Cerebellum orchestrator routes recall calls. **A2 sequencing #6: prerequisite for OP-01 + N-07 token savings to actually compose.** — 2d

### v1.0 — Anti-pattern cleanups (A5 §6)

- [ ] **AP-01..08** 8 anti-patterns from logic audit — silent WAL drops / unwrap_or-0 / misleading Result signatures / hardcoded table names / shared-resource-as-value / unobservable side effects / runtime-format SQL / test-without-integration. **Several already covered by M-01..M-06 + AR-01 above; remaining ~4 items here.** — 5d aggregated

### v1.0 — Framework 4.1 reconciliation (A3 + A5)

- [ ] **F4-01** Ecology-Schicht Rust scanner — read-only fitness scanner emitting human-readable reports. — 4d
- [ ] **F4-02** Via-Negativa restoration: `RateLimiter` is currently an entity (`Mutex<HashMap>`) — convert to stateless operation, single shared `Arc<RateLimiter>` from `channels/mod.rs`. — A5 I-2 + A3 F-2 — 2d
- [ ] **F4-03** Schichten-separation: `pipeline/enriched_request.rs` currently reads `Arc<Vec<Skill>>` directly — convert to injected input. — A3 F-3 — 2d

### v1.0 — Perf + parity

- [ ] **PF-01** Active skill usage — NEOTH self-routes through skill library by default, not only on keyword match. **A1 #14 PARTIAL.** — 3d
- [ ] **PF-02** All-LLM-provider coverage — Anthropic / OpenAI / Gemini / Bedrock / Azure / Ollama / Cohere / Mistral / Groq / Together. — 4.5d
- [ ] **PF-03** All-document-formats — DOCX / XLSX / PPTX / EPUB / PDF / ODT / RTF read + create. New `media/document/` module. — 5.5d

### v1.0 — GUI 12/10 (A1 cyber-brand decision)

- [ ] **GU-01** Settings panel parity audit — every operator-tweakable config + every wizard step has GUI surface. — 4d
- [ ] **GU-02** Cyber-brand pass (NOT mirror Linear/Raycast/Arc): Raycast command-surface clarity + Ghostty terminal-first + custom dark/amber/teal NEOTH palette. Animations, transitions, micro-interactions, accessibility. — A1 — 6.5d
- [ ] **GU-03** Persona-adaptive depth — settings panels collapse/expand based on `RecommendationEngine::operator_complexity_level()` (W-03a). — A2 #13 sequencing — 3d

### v1.0 — Todoist + todolist (operator wish-list W)

- [ ] **TD-01** Todoist adapter (read + create + complete). — 2d
- [ ] **TD-02** Generic todo-list compat (CalDAV VTODO + Google Tasks + Microsoft To Do). — 4d

### v1.0 — Hermes adopts (clarify + goal)

- [ ] **CL-01** Clarify-prompt interrupt — mid-turn open question via SSE, 120s timeout. — 2.5d (hermes adopt)
- [ ] **GM-01** Goal manager + turn budget — self-terminate when goal satisfied. — 3d (hermes adopt)

### v1.0 — Final four killer features (A6)

- [ ] **KF-03** Tamper-Evidence Export — signed `.neoth-proof` bundle for any WAL window. **Merges with A3 #7 `neoth wal export --signed`.** — 3d
- [ ] **KF-09** WASM Plugin Capability Ledger — per-plugin-per-session usage log via `plugins/capability_ledger.rs`. New WAL frame `0x60 PLUGIN_CAP_USED`. — 4.5d
- [ ] **KF-10** Structured-Forgetting Export — pre-decay summary drafts to Obsidian `~/Obsidian/NEOTH/PreDecay/`. New WAL frame `0x94 MEMORY_PRE_DECAY_DRAFT`. — 3d
- [ ] **A3-01** `neoth transfer --dest <pubkey>` signed encrypted memory bundle. — A3 #1 — 3.5d

### v1.0 — Documentation + Launch (A1 added named item)

- [ ] **DOC-01** README + comparison table + 4 new SVGs in NEOTH cyber-CI palette. Refresh competitor table with v1.0 capabilities. **A1 binding: this is a NAMED v1.0 item, not afterthought — without it, launch post has no shareable assets.** — 3d
- [ ] **DOC-02** Comprehensive operator-journey docs covering 7 segments from A4 (first 5 min / day 1 / month 1-3 / power user / multi-device / failure recovery / mastery). — 2.5d
- [ ] **DOC-03** `docs/security/threat-model.md` (started in v0.2.1 hotfix as SX-07) expanded with all v1.0 surfaces. — 1.5d

### v1.0 — A1 "ADD as named v1.0 items" (operator wish-list AD)

- [ ] **MAR-01** Marketing comparison table refresh + screenshots gallery. — 2d
- [ ] **MAR-02** Launch post drafted + signed release artifacts published. — 1.5d

**v1.0 total: ~50-60 days. Tag: `v1.0.0`. Final gate: signed release artifacts + security audit pass (cargo-audit + cargo-deny + OpenGrep + manual SSRF + manual credential-handling review) + perf baseline doc + full cross-distro install verification + GUI screenshot gallery + threat-model.md complete + 4 final killer features demoable in a single 10-min screen recording.**

---

## Items deferred post-v1.0

- **EM-03** auto-calendar entry from email — A1: "NEOTH deleted my meeting" risk in first week
- **EL-03** learn-from-arxiv pipeline — A1: serves neither persona near-term
- **Exchange / Outlook 365 / Fastmail** adapters — A1: enterprise tier
- **Full slave logic** for SL-01 — A1: thin shim in v0.9, deep in v1.0+

---

## Sequencing rules (carry-over + new from A2)

1. **Each lane ships independently.** v0.2.1 hotfix MUST tag before any v0.3 work merges. v0.3 must tag and be public-ready before v0.4 work starts on `main`.
2. **WAL frame band reservations** — claim event-type IDs in this file BEFORE implementation. v0.3 claims `0x11`, `0x12 extend`, `0x15`, `0x80..83`, `0x05/06`. v0.4 claims `0x30`. v0.9 claims `0x19/1A`, `0x50/51`, `0x60`, `0x78/79`, `0x94`, `0xA4/A5/A6`, `0xE8`. v1.0 claims final cleanup band. Coordinate via this file before any new WAL event lands.
3. **Wizard is the activation surface for every lane.** Every new operator-facing feature ships with a wizard step + a settings-panel entry (GUI ↔ CLI parity hard rule).
4. **Security blockers are pre-merge.** PC-02 Chrome DevTools MCP requires env-var force + license confirm BEFORE the PR opens, not in v1.0 hardening. CRIT-01/02/03 from A5 must ship in v0.2.1 hotfix lane BEFORE any v0.3 work merges.
5. **A2 critical sequencing dependencies:**
   - W-05 (installer trait) ships before U-01/U-03
   - M-07 (memory tests) → M-09 (region routing) → OM-01 (OMI ingest)
   - P-01+P-02 (approval tiers) → PC-01 (OS tool surface) — sonst brutale confirm fatigue
   - G-01 with `G-01a ProactiveQueue` → PL-03 / OB-03 — sonst notification storm
   - OB-01 (dreaming→vault) → G-01 (trigger) → N-06 (workflow delivery)
   - W-03 with `operator_complexity_level()` → GU-03 (panel collapse rule engine)
   - AR-05 `neoth profile conflicts` → G-02 (proactive surfacing wrong claims)
6. **No "next-version" debt creep.** Items deferred from a lane move to the explicit `_post-v1.0_` column above, not silently into the next lane.

---

## How to use this file

- Pick the highest-priority lane that's not yet shipped.
- Pick an item from the top of that lane's section.
- Flip `[ ]` → `[~]` in the same commit you start work.
- Ship code + tests + same-turn `[~]` → `[x]` flip with commit hash + 1-line evidence.
- Push.
- Repeat.

---

## Round-3 Forgotten-Items Sweep (2026-05-24)

A third Gremium of 6 agents (F1 SPEC / F2 HANDOFF / F3 archive / F4 ADVERSARIAL / F5 QUELLEN / F6 GREMIUM-verdicts) walked every PLAN/, PLAN/archive/, and PLAN/ADVERSARIAL/ file and cross-referenced against `PROGRESS_v0_2_FINAL.md` + the 152 backlog items above. They surfaced **70 forgotten commitments / open decisions / unfixed risks** that fell through the cracks.

Three of A5's earlier CRITICAL items overlap with F4's ADV-01/02/03 findings — those are tracked once below in the appropriate lane. SPEC-02 was a false alarm (n8n localhost API IS shipped Session 23, commit `76c4fbe`). Conductor 3-layer context skill was double-flagged by F3 (ARCH-03) + F5 (QU-06) → priority +1.

### Cross-validated high-confidence items (multiple agents flagged the same gap)

| Cross-flag | Item | Lane |
| :-- | :-- | :-- |
| F3 ARCH-03 + F5 QU-06 | Conductor 3-layer context skill (`skills/conductor.yaml`) | v0.3 |
| F3 ARCH-02 + F4 ADV-12 + F1 SPEC-08 | Council adversarial test suite (`tests/council_adversarial.rs` 7 tests + `GROUND_TRUTH_TAG` fix) | v0.4 |
| A5 SX-02/03 + F5 QU-04 | Centralized output redaction (`security/redact.rs`) | v0.2.1 |
| F3 ARCH-05 + F1 SPEC-08 + F2 HO-07 | Jarvis migration runbook + recall parity gate + neoth-monitor sidecar | v0.9 |
| F2 HO-01 + F1 SPEC-01 | Coding workflow dispatcher + Picks 2-10 | v0.3-v0.9 |

### Round-3 v0.2.1 SECURITY HOTFIX additions

- [ ] **ADV-01** WAL `.cpt` crash-recovery files use only CRC32c + xxh3-64 (non-cryptographic). Attacker pre-places crafted `.cpt` with injected `PROFILE_DELTA` events. Add HMAC-SHA256 over `.cpt` content + verify before apply + re-run region_tag validation on recovered frames. — F4 — S 1-2d
- [ ] **ADV-02** `MmapMut` active WAL segment permanently write-mapped — plugin code im neothd-user space kann silent zero-fill `importance: f32` (no CRC mismatch → silent GC erasure at next compaction). Switch active-segment write to `WalWriterTask` with `O_DSYNC`; sealed segments stay read-only `Mmap`. — F4 — M 2-4d
- [ ] **ADV-03** Profile Block-B injection has zero untrusted-data boundary. Adversarial paste from Telegram → schema-valid `idx_profile` → injected verbatim in Left-hemisphere system prompt → Hebbian amplifies to ≥0.95 confidence over 26 turns. XML delimiters wrap + `is_quoted_content` pre-filter + flip `require_approval` default true + prompt-injection eval corpus under `eval/prompt_injection_corpus/`. **A5's PL-04 only scoped to paperless/email — profile-extraction path was the missed surface.** — F4 — M 3-5d
- [ ] **ADV-11** `inventory` crate silent-empty on Windows GNU target (`x86_64-pc-windows-gnu`). All plugin hooks silently fail to register: build green, direct-call tests pass, `inventory::iter::<Hook>().count() == 0` at runtime. **Dev runs on Windows.** Add `.cargo/config.toml` linker flag `-Wl,--whole-archive` OR enforce MSVC target in README + CI. — F4 — XS <0.5d
- [ ] **GR-01** WhatsApp `LIVE` label honesty — pipeline produced outbound is currently dropped. **Operator pick A (XS rename to `INBOUND-LIVE`) OR pick B (S wire webhook_listener → WhatsApp Graph API send helper).** R7 evaluator: release-gate blocker. — F6 — XS / S
- [ ] **GR-02** Channel-flapping doctor check label-fix — `check_channel_flapping` measures provider error-rate. **Pick A (XS rename "provider flapping") OR pick B (S add channel/surface field to `UsageEvent`).** — F6 — XS / S
- [ ] **GR-04** Circuit breaker wire-in — `providers/circuit_breaker.rs` shipped with 12 tests but no `Provider::complete`/`stream` call site uses `try_acquire`/`record_success/failure`. Reliability claim currently vacuous. — F6 — S
- [ ] **GR-08** Webhook query parser RFC 3986 last-write-wins doc comment in `webhook_verify.rs`. — F6 — XS
- [ ] **GR-12** Five GUI code-audit findings shipped nowhere: H-1 `chat-channel-switched` callback never bound in Rust (sidebar clicks silent); **H-2 Autonomy ComboBox visual shows "strict" but writes "standard" to freedom.yaml — DATA-INTEGRITY BUG**; H-3 hardware probe blocks main UI thread; H-4 kanban fetch blocks startup; M-1 wizard re-entry blank operator-id/provider from defaults (not parsed freedom.yaml). — F6 — S total
- [ ] **GR-13** Pre-v0.1 P0 verify: `cli/init.rs::write_config` uses `.mode(0o600)` on `OpenOptions` BEFORE `open()` (not chmod-after-create race) AND `libc::mlock` on deserialized config struct on Linux. — F6 — XS verify / S fix if wrong
- [ ] **GR-05** GUI `Apply active` E2E test with fake `neothd` subprocess. — F6 — XS
- [ ] **GR-06** Document `OnSessionStart` `Block` semantics (logged, does not stop daemon). — F6 — XS
- [ ] **GR-07** Segment numeric sort vs lexicographic — close as accepted risk (single call site enforces `{:06}.wal` zero-padding) OR add the 5-line defensive numeric parse. — F6 — XS

### Round-3 v0.3 additions

- [ ] **SPEC-06** Wizard step 5d (three provider pickers for left/right/cerebellum) + `neoth hemispheres {show, set, test}` CLI + `providers::from_config_for_role` real per-role construction wired to ALL call sites + WAL `0x1F HEMISPHERE_REBOUND` + Slint sidebar switcher panel. **`InferenceTopology` per-hemisphere slots shipped but operator UX is missing.** — F1 — S 4d
- [ ] **HO-01** Coding workflow dispatcher — `Worker` trait + `WorkerOutcome` + workspace dispatch loop (BACKLOG → hemisphere worker → patch+test → IN_PROGRESS → REVIEW). Chorus-gated questions never answered. **Makes `neoth code` useful end-to-end.** — F2 — L >5d
- [ ] **HO-03** Five cluster single-session bites: `neoth cluster discover` policy verdict pre-scan / doctor `mdns announcer` check / `neoth cluster confirm --interactive` / `freedom.yaml::cluster.listen_port` knob / Slint settings panel cluster section. — F2 — M 2-5d
- [ ] **HO-05** `tweaks.toml` runtime theme/persona parser (~30 keys, R-21 deliverable). **Prerequisite für jede GUI theming work in Workstream P.** — F2 — S <2d
- [ ] **HO-06** NEOTH startup credential-pattern scanner — `~/.neoth/policy.yaml::git.remote_urls.forbid_inline_tokens` + `startup_audit.scan_paths` for `ghp_`/`sk-`/`AKIA` patterns. — F2 — S <2d
- [ ] **HO-02** GUI fallback for missing Cerebellum ("no Cerebellum bound — run wizard step 5d") + stale-Planning-session reaper on dispatcher startup. — F2 — XS each
- [ ] **ARCH-03 / QU-06** Conductor 3-layer context skill (`skills/conductor.yaml`, product/spec/plan injection, claimed -29% runtime / -17% tokens) — **cross-flagged by F3 + F5.** — XS 1h
- [ ] **QU-01** SmallCode EarlyStopDetector — repetition-loop tail-scan + patch-spiral counter (4 failures → full-rewrite) + greeting-regression detector. `coding/retry_policy.rs` ~220 LOC. Today every failure → silent `Blocked`. — F5 — S 3-4h
- [ ] **QU-02** SmallCode per-model capability profiles — `ModelProfile` struct (`context_length` / `tool_format` / `strengths`). **Today: identical prompt format → silent JSON parse fail on wrong backend.** — F5 — S 200 LOC
- [ ] **QU-03** SmallCode 2-stage tool router for ≤16k contexts — `select_category` first → category-specific schemas. ~50% schema-token reduction. Gates on QU-02. — F5 — S 180 LOC
- [ ] **QU-04** Centralized output redaction `security/redact.rs` — pattern-based API key detection + `ALWAYS_REDACT_KEYS` deny-list + ANSI strip + path traversal block. **Today: `.env` lines + Bearer tokens land raw in WAL.** — F5 + cross-flag mit A5 — S 120 LOC
- [ ] **QU-05** SmallCode validate→fix→escalate loop — `cargo check --message-format=json` post-write, re-inject errors (max 2 attempts), escalate to Right hemisphere via new `WorkerOutcome::Escalate`. — F5 — M 250 LOC
- [ ] **QU-07** Six LOWKEY skill YAMLs als first-class drops — `lowkey_base.yaml` / `magi_ultra.yaml` / `omega_prime.yaml` / `archon.yaml` / `raskal.yaml` / `pme.yaml` + `max_plus_plus.yaml`. **Today LOWKEY in refusal-recovery uses hardcoded constants.** — F5 — S 1d
- [ ] **QU-09a** agency-agents top-2: EvidenceCollector + RealityChecker as `sub_agents` builtins. — F5 — S 1d total
- [ ] **QU-10a** 8 superpowers individual skill YAMLs not in Q21/Q24 bundle: systematic-debugging / test-driven-development / requesting-code-review / receiving-code-review / writing-skills / finishing-a-development-branch / executing-plans / using-git-worktrees. — F5 — S 5h
- [ ] **QU-10b** SP-A1 task_executor.rs controller loop iterating `idx_kanban_pending` — closes "chat-pipeline wiring still open" gap aus shipped review.rs. — F5 — M 1-2d
- [ ] **QU-10c** SP-H2 `--verify-tests` flag on `neoth finish`/`neoth branch`. — F5 — S 0.5d
- [ ] **ADV-04** PROFILE_REDACT re-extraction block — `profile.apply` consults redaction history before emitting `PROFILE_DELTA`; redacted claim does NOT reborn on next mention. — F4 — S 1-2d
- [ ] **ADV-05** PII gate Block-B injection guard — `profile.inject_into_block_b()` skips claims whose PII category is currently disabled (today: extraction-only, historical claims continue für 276 days nach disable). — F4 — XS
- [ ] **ADV-06** Per-sub-field `identity.{name,age,role,location,languages}` granularity in freedom.yaml schema + `test_profile_location_subfield_gate`. — F4 — S 1-2d
- [ ] **ADV-07** Mirror-refusal feedback loop guard — `derived_from_mirror_pipeline: bool` flag on PROVIDER_RESPONSE; `profile.extract` skips `operator_preferences` category on mirror-triggered turns. **Today: closed self-amplifying loop "Alex values limitation-reflection".** — F4 — S 1-2d
- [ ] **ADV-08** Define + persist `compaction_epoch: u32` in `SegmentHeader` — atomic increment before `.cpt.tmp` write. Fixes idempotency-key collision after mid-rename crash. — F4 — S 1-2d
- [ ] **ADV-09** Telegram operator command privilege ceiling in `SPEC_channels.md` — destructive ops (`profile redact`, `wal admin`, `profile export`) reject Telegram-sourced with explicit error requiring CLI+local-auth. — F4 — S 1.5d
- [ ] **ADV-10** HTTP 429 explicit handlers in `profile_learn.yaml` (skip extraction + log `PROFILE_EXTRACT_SKIPPED`) AND `council_debate.yaml` (degrade to 2-participant with documented verdict confidence penalty). — F4 — S 1-2d
- [ ] **GR-10** Unified safe-mode status surface — single source of truth for active safety rails (`{ rail: "plugin_blocked", reason: "..." }`) + GUI panel within 1s. Trust Ledger family. — F6 — M
- [ ] **GR-11** Property/fuzz tests for `webhook_verify.rs` signature canonicalization + timestamp windows via `proptest`. — F6 — S
- [ ] **GR-14** `neoth-plugin-sdk` workspace spin-out — convert single-crate to multi-crate; SDK published independently. — F6 — S
- [ ] **GR-15** Shared `provider_call_with_breaker_and_usage()` wrapper — `record_now` heute über 4 call sites duplicated (chat-sync / chat-stream / council-hemisphere / MCP-loop). — F6 — S

### Round-3 v0.4 additions

- [ ] **SPEC-03** Council smart-trigger pipeline + per-provider 429 cascade with fallback chains + `council.toml` budget + WAL `0x3D`/`0x3E`/`0x3F` + `neoth council {list, inspect, suppress, budget set}` CLI. **Without smart-trigger gates every security-keyword query fires council at 25-35% rate, draining quota by 14:00.** — F1 — M 3-4d
- [ ] **SPEC-05** User adaptation — 5 passive estimators (Temporal/Cadence/Length/Topic/Tone) + daily cron → `idx_profile` + `neoth self-dev review` CLI + `propose_adjustments` module + WAL `0x1C`/`0x1D`/`0x1E` + GUI profile selector (Slint step5c + sidebar switcher). — F1 — M 10d
- [ ] **SPEC-07** `ProfileClaimGuard` Schicht-0 gate zwischen `profile.extract` and `profile.apply` — redaction registry / first-person attribution / daily LLM-call cap / timestamp normalization / typed extension registry. WAL `0x38 PROFILE_DELTA_BLOCKED` + `idx_profile_redactions` SQLite migration. **Five ADVERSARIAL risks share this single fix point.** — F1 — S 3d
- [ ] **SPEC-10** Refusal recovery layer — per-hemisphere refusal detection (`CouncilStrategy` enum + `hemisphere_role` extension to `0x16` payload) + `RefusalCause::infer_cause` + LOWKEY reframing catalogue (6 reframings) + `recovery::orchestrate` state machine + WAL `0x19 REFUSAL_REROUTED` + `neoth refusal recovery {test, history, disable}` CLI + doctor check. — F1 — M 7d
- [ ] **ARCH-02** Council adversarial test suite — 7 named tests (`test_all_three_agree_and_wrong` / `test_emergent_divergence_explosion` / `test_callosum_self_destructs` / `test_fuzz_input_against_council` / `test_token_budget_exhaustion` / `test_prompt_bundle_replay_determinism` / `test_left_dominates_right_unfairly`) at `tests/council_adversarial.rs`. — F3 — M 3-5d
- [ ] **ARCH-04** Block-layer hard token caps + graceful degradation (D oldest 50% → C lowest-importance 50% → Conductor.plan/spec, never A/B/E) + WAL `0x2F BUDGET_EXCEEDED` + paired `prompt_token_estimate`/`prompt_token_actual` on PROVIDER_REQUEST. **Pre-condition für KF-08.** — F3 — S <2d
- [ ] **ARCH-07** LOWKEY skill versioning — `content_hash = SHA-256(yaml || template)` at load + `disabled_for_eval_sessions` in freedom.yaml + `prompt_bundle_hash = SHA-256(BlockA..E)` per PROVIDER_REQUEST + `0x29 SKILL_INJECT_SKIPPED`. **Prerequisite für ARCH-02 replay-determinism test.** — F3 — XS
- [ ] **ADV-12** Council `test_all_three_agree_and_wrong` strukturelle Fix — embed `[GROUND_TRUTH_TAG]` in prompt context; `factual_contradiction_check` compares against ground truth not hemisphere agreement. Fixture format `tests/council_adversarial/fixtures/unanimous_wrong_*.json`. — F4 — S 1-2d
- [ ] **HO-04** Register 4 operator design decision stubs for R-2 + R-02 Phase 3 — port strategy / cadence / embedding model / channel-ingress privacy. — F2 — XS register; L follow-on
- [ ] **QU-08** `idx_episode` 60-min temporal-window view — `src/wal/views/episode.rs` Hippocampus episode summaries. — F5 — S 100 LOC
- [ ] **QU-09b** 11 remaining agency-agents sub-personas: BackendArchitect / IncidentResponder / MinimalChangeReviewer / DbOptimizer / OnboardingGuide / SreMonitor / ApiTester / TestResultsAnalyzer / IdentityGraphOperator / McpServerBuilder / TaskDecomposer. — F5 — L 6d
- [ ] **QU-10d** SP-A2 parallel dispatch mode alongside sequential in task_executor.rs (gates on QU-10b). — F5 — M 1d
- [ ] **QU-11** ARS-6 `resume_from_passport` — multi-session pipeline recovery via WAL `0xB3 MODE_CHECKPOINT` + `recall::reconstruct_from_checkpoint` + `cli/chat.rs` "resume from [hash]" command. — F5 — S 1d

### Round-3 v0.5 additions

- [ ] **ARCH-01** Tailslayer dual-replica vector store — `tailslayer-rs` crate (hugepage-backed `ReplicatedBuffer<f32>`). Cargo.toml hat heute nur comment stub. Cut auf mmap-only linear-scan in v0.8 MVP scope, nie zu v1.0 backlog migriert. — F3 — M 2-5d
- [ ] **SPEC-04** Local Qwen3-4B-INT4 für profile extraction — `LocalInference` Rust impl via candle + `neoth model fetch` + `profile_learn.yaml` updated to `model: local_qwen3_4b` + health-check task + `freedom.yaml::inference.allow_cloud_fallback=false` default + `neoth privacy audit` CLI + WAL `0x3A`/`0x3B`/`0x3C` + `ProviderTarget` typed field on PROVIDER_REQUEST. **Without this, every profile-extraction turn sends Alex's conversation content to Gemini API (privacy theater).** Gated on Day-14b forward-pass unstuck. — F1 — M 5d
- [ ] **SPEC-13** Ouro LoopLM provider — 24 shared layers × 4 recurrent passes candle model + `OuroAdapter` Provider impl + `ProviderKind::Ouro` config variant + wizard step-5 option + GUI provider-choice + hemisphere sub-panel + optional Q8 quantization. **Operator explicitly requested ("als Qwen alternative"); nothing in PROGRESS references Ouro.** — F1 — M 6.5d (8.5d with Q8)
- [ ] **ADV-13** Deterministic pre-extraction timestamp normalization stage — NLP parses relative time expressions ("3 years ago") against conversation's actual `hlc_ns` before LLM call. — F4 — S 2d
- [ ] **GR-16** Windows WAL `SetNamedSecurityInfoW` DACL restriction — D-008 final verdict, never placed in backlog. — F6 — S

### Round-3 v0.9 additions

- [ ] **ARCH-05** Jarvis migration runbook — eval-goldset (100 queries aus live Jarvis `recall.sh`), shadow-run 14 days mit Telegram-mirror dual-write, recall parity ≥ 0.85 Cohen's Kappa, YubiKey/TOTP-gated cutover + rollback in 30 min. **Highest-risk omission — NEOTH cannot become primary memory store ohne this gate.** PROGRESS heute springt von v0.9 zu v1.0 ohne migration lane. — F3 — L >5d
- [ ] **ARCH-06** HLC integration in WAL header — v0.8 §4 96-byte wire format hat `hlc { ns: u64, logical: u32 }` at offset 32 replacing `ts_ns` + WAL `0x2E CLOCK_SKEW_DETECTED`. **Conflict: scoped "Phase 3+ only" aber v0.8 sagt "ship Day 1 cannot retrofit". Prerequisite für SL-01b cluster WAL gossip.** — F3 — S <2d
- [ ] **SPEC-08** Recall parity methodology — 100-query goldset extraction + 4-grader protocol (A/B/C + external family-D + operator-anchor) + kappa computation + parity-score formula + absolute-quality floors + CRITICAL divergence detection (WAL `0x3E EVAL_CRITICAL_DIVERGENCE`) + `GROUND_TRUTH_TAG` fix. **Go/no-go gate für Phase 3 Jarvis cutover (folds into ARCH-05).** — F1 — M 19d
- [ ] **SPEC-09** Cluster auto-discovery Phases 2-4 — `mdns-sd` mDNS announcer + listener (`neoth cluster discover`) + Tailscale magic-DNS scan + consent gate + `cluster.yaml` persistence + `neoth cluster {confirm, revoke, status}` + doctor surface + WAL `0xE0`/`0xE2` + wizard step 8. **Without Phases 2-4 `neoth cluster` ist empty + "shared memory across devices" use case unreachable.** — F1 — L 5-6d
- [ ] **SPEC-11** Cross-channel identity view `idx_human_identity` (UUID v7) + `neothctl identity merge` + `LiveDelivery` Rust struct (send-or-edit + finalize für Telegram/Slack/WhatsApp) + Phase 2 channel adapters (Discord/Signal/iMessage/LINE/Matrix). **SP-5 C-prime trigger ("second production adapter") has no backlog item.** — F1 — M for identity+LiveDelivery; L >5d each for Phase 2 adapters
- [ ] **SPEC-12** R-02 LLM clustering Phase 3 — embedding-based theme clustering (cosine + agglomerative, 0.65 threshold) + LLM theme summarisation prompt + cross-theme dependency merging + `compose_themed_dreams_for_day` + WAL `0xF1 DREAM_COMPOSED` + `neoth dream {now, CLI}` + privacy gate. **Phase 1+2 in tree, Phase 3 macht dreams useful (semantic compression).** Gated on Day-14b. — F1 — M 14d
- [ ] **SPEC-14** Phase 6.1 gossip wire-protocol spec doc — vector-clock representation + replay envelope + LWW conflict-resolution rules. **Single-session deliverable, prerequisite für SL-01b implementation.** — F1 — XS spec-only
- [ ] **HO-07** `neoth-monitor` alerting sidecar — post-cutover hot-watch daemon mit 5 trigger rules + 4 neue WAL events (`0x3C MONITOR_PERF_ALERT` / `0x3D MONITOR_PANIC_EVENT` / `0x3E MONITOR_CHANNEL_SILENT` / `0x3F MONITOR_CRC_RATE_ALERT` — re-bandnumbered weil 0x38..0x3B mit CHANNEL_MSG_EDIT clash) + 30min channel-silence + 0.1%/day CRC threshold. **Required vor Day-80 cutover per ARCH-05.** — F2 — M 2-5d
- [ ] **ADV-14** Longitudinal recall regression anchor — `eval/regression_anchor_day30.jsonl` (20 query+response pairs at cutover) + weekly cron re-run + alert on `cosine(embed(current), anchor) < 0.70` + WAL `0x3F REGRESSION_ALERT`. — F4 — S 1.5d setup

### Round-3 v1.0 additions

- [ ] **SPEC-01** Coding workflow implementation Picks 2-10 — Store CRUD + heuristic classifier + decomposer + `neoth code` CLI + worker dispatcher + activity feed CLI + GUI Code Sessions tab + LLM classify + review flow. **Without Picks 2-10 operator cannot use `neoth code` at all.** ~3050 LOC across 9 picks. (Overlaps mit HO-01 dispatcher — HO-01 ist Pick 5; Picks 2-4 + 6-10 here.) — F1 — L >5d
- [ ] **GR-03** Trust Ledger + Autonomy Gradients + Recovery-first UX — Gremium-identified primary differentiators vs OpenClaw/Hermes/OpenHuman. **Operator pick: v0.4 or v0.9 or defer.** — F6 — M-L each
- [ ] **GR-09** GUI screen-transition fade animation (deferred at Session 18 G-27, never placed). Add to GU-02 polish OR formal close. — F6 — S
- [ ] **HO-08** Ecology-Schicht 3-step pickup procedure + 2 new file targets (`council/adaptation.rs` + `skills/genealogy.rs`) + pre-audit of `profile/self_dev.rs` + `council/callosum.rs` + `skills/registry.rs`. — F2 — XS planning
- [ ] **HO-09** V1x-03 drift detection 4 deliverables — `profile/baseline_diff.rs` (NEW pure-fn) + cron consumer wrapper + `freedom.yaml::drift_alert` config block + `neoth profile drift {report, baseline, reset}` CLI. — F2 — M 2-5d

---

## Round-3 totals + WAL band re-coordination

- **70 new items** added across 6 lanes (v0.2.1 hotfix + v0.3 + v0.4 + v0.5 + v0.9 + v1.0).
- **Additional effort: ~95-130 person-days** on top of the original 210-260. Total v1.0 scope: ~305-390 person-days.
- **WAL band conflict resolved:** F2 HO-07 originally claimed `0x38..0x3B` for monitor events, but `0x38 CHANNEL_MSG_EDIT` already lives there. Re-routed to `0x3C..0x3F` as `MONITOR_*` band. Update sequencing rule #2 accordingly.
- **Operator picks still needed:** GR-01 (WhatsApp A or B) / GR-02 (flapping A or B) / GR-03 (Trust Ledger lane) / HO-04 (R-2 + R-02 Phase 3 four decisions). All four block their respective lane starts.

The Round-3 sweep stops here. Implementation begins with v0.2.1 SX-01 (SSRF guard) — unchanged from Round-2 verdict. The Round-3 ADV-01..03 + ADV-11 + GR-12 H-2 items fold INTO the same v0.2.1 hotfix lane.
