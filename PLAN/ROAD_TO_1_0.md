# ROAD TO 1.0 — NEOTH v0.3 → v1.0 roadmap

**Date:** 2026-05-24
**Source of truth:** `PLAN/v1_0_OPERATOR_WISHLIST_2026-05-24.md` (operator-typed wish-list, 35 buckets A..AG)
**Predecessor:** v0.2 closed Session 23, commit `9b952b2`, 0 deferred, 4240 tests green.
**Status:** **DRAFT — A1 + A5 audit agents still running.** Sections marked `[A1]` / `[A5]` get filled when those reports land. Everything else is built from A2 (QUELLEN-diff), A3 (new-repos), A4 (wizard architect).

This document supersedes the v1.1 design files as the **execution
roadmap**. Architectural specs in `PLAN/00_DESIGN_v1.1_FINAL.md` + the
`PLAN/SPEC_*.md` series remain normative for shape; ROAD_TO_1.0.md
decides **sequencing + lane assignment**.

---

## Lane definitions

| Lane | Theme | Ship-target | Gating principle |
| :-- | :-- | :-- | :-- |
| **v0.3** | Wizard expansion + auto-update + crash recovery | 4-6 weeks | Anything a non-developer operator hits in the first 5 minutes |
| **v0.4** | Confirm-fatigue kill + memory verification + n8n smarts | 4 weeks | Frequent operator-touch surfaces; trust + speed wins |
| **v0.5** | Multimodal completion + paperless + email/cal + obsidian-as-scratchpad | 5-6 weeks | The "remembers + acts on your real life" surface |
| **v0.9** | Proactivity + slave coupling + native PC control + arxiv learning | 6-8 weeks | The "anticipates what I want" surface; cluster as nodes |
| **v1.0** | Polish + security audit + perf + cross-distro hardening + GUI 12/10 | 4 weeks | Public-release-quality bar |

Total: ~6 months end-to-end. Each lane ships independently with its
own PROGRESS column + tag (v0.3.0 / v0.4.0 / ...). Every lane has a
fmt + clippy + test gate at the end; no lane merges with red gates.

---

## v0.3 — Wizard + Auto-Update + Crash Recovery

**Theme:** "Alex's mom on Win11 with no dev tools" path lands.

### v0.3 — must-haves (from A4 wizard architect)

| ID | Item | Build-ready spec | Effort |
| :-- | :-- | :-- | :-- |
| `W-01` | `src/installers/detect.rs` + `gpu.rs` + GPU/VRAM probe with `GpuKind::{Cuda,Rocm,Metal,Cpu}` | A4 §Auto-Detect Contract | 2d |
| `W-02` | 8 new installer modules (ffmpeg, ollama, tailscale, hysteria2, paperless, omi + extend existing) | A4 §Module Breakdown | 4d |
| `W-03` | `src/wizard/recommend.rs` — RecommendationEngine pure-fn (VRAM rules + binary-detect rules) | A4 §Recommendation Engine | 1d |
| `W-04` | `src/wizard/detect_step.rs` — wizard step wiring + `tokio::join!` parallel probes + 24h cache | A4 §Architecture Diagram | 2d |
| `W-05` | `src/wizard/install_step.rs` — fallback chain (winget→choco / apt / dnf / pacman / brew) + dry-run + WAL 0x12 extend | A4 §Install Contract | 3d |
| `W-06` | `src/wizard/shared_state.rs` — `WizardStateV2` with `#[serde(flatten)] base` so v0.2 freedom.yaml round-trips | A4 §CLI ↔ GUI Parity | 1d |
| `W-07` | GUI wizard parity via shared IPC channel to `run_probes()` | A4 §CLI ↔ GUI Parity | 3d |
| `W-08` | New WAL frames: `0x11 DETECT_COMPLETE`, extended `0x12`, `0x15 CREDENTIAL_IMPORT` | A4 §WAL Frame Design | 1d |

### v0.3 — credentials import (from A4)

| ID | Item | Notes | Effort |
| :-- | :-- | :-- | :-- |
| `C-01` | `src/credentials/mod.rs` + `types.rs` — `CredentialImporter` trait + `ImportedCredential` with SecretString+mlock+zeroize | safest: no on-disk plaintext copy | 2d |
| `C-02` | `bitwarden.rs` importer — accepts encrypted export JSON, parses in-process | start here; no OS-keychain dep | 2d |
| `C-03` | `chrome.rs` importer — Login Data SQLite + DPAPI (Win) / DBUS Secret Service (Linux) / Keychain (macOS) | OS-keychain hard | 3d |
| `C-04` | `firefox.rs` importer — key4.db + logins.json + NSS via subprocess certutil | medium | 2d |
| `C-05` | Wizard step + settings panel parity + `services_redacted=true` WAL field for audit privacy | UI work | 2d |

### v0.3 — auto-update (operator wish-list B)

| ID | Item | Notes | Effort |
| :-- | :-- | :-- | :-- |
| `U-01` | Self-update for the `neoth` binary itself (signed-release verify + atomic swap + rollback) | reuse `updater/` if shipped | 3d |
| `U-02` | Skills + plugins auto-update — `~/.neoth/skills/<id>/skill.yaml` + `plugins/<id>/plugin.json` re-resolve on schedule | needs registry index | 3d |
| `U-03` | Detected CLI environment updaters: `claude` / `codex` / `gemini` CLI versions tracked + bumped via package-manager hook | reuse wizard install pipeline | 2d |
| `U-04` | Cron-task `0x4? updater task` writes WAL frame per check; operator-readable `neoth updater status` | audit shape | 1d |

### v0.3 — crash recovery (from A2 hermes-webui patterns)

| ID | Item | Adopt-from | Effort |
| :-- | :-- | :-- | :-- |
| `R-01` | Turn-Journal write-ahead JSONL for `neoth chat` mid-stream durability | hermes `api/turn_journal.py` | <1d |
| `R-02` | `.bak` session recovery — snapshot-on-shrink + startup compare-and-restore | hermes `api/session_recovery.py` | <1d |
| `R-03` | TPS metering SSE in chat header (1Hz streaming / 10Hz idle / 60min rolling) | hermes `api/metering.py` | 1d |

**v0.3 total estimate:** ~32-38 person-days. Sequence W-01..W-08 → C-01..C-05 → U-01..U-04 → R-01..R-03. v0.3.0 tag at end.

---

## v0.4 — Confirm-fatigue kill + Memory verify + n8n smarts

**Theme:** "I trust NEOTH because I see what it's doing AND it stops bothering me about every safe action."

### v0.4 — from A2 (openclaw approval patterns)

| ID | Item | Adopt-from | Effort |
| :-- | :-- | :-- | :-- |
| `P-01` | 7-tier approval classifier (`readonly_scoped` / `readonly_search` / `mutating` / `exec_capable` / `control_plane` / `interactive` / `unknown`) — auto-approve safe tiers at `standard` autonomy | openclaw `acp/approval-classifier.ts` | 1-2d |
| `P-02` | `allow-once / allow-always / deny` tri-state for the consent gate; `allow-always` promotes to persistent allow-list via WAL | openclaw `permission-relay.ts` | 1d |
| `P-03` | Domain Event Bus — non-exhaustive `DomainEvent` enum + `tokio::sync::broadcast` for council / sub_agents / cron decoupling | openhuman `event_bus/events.rs` | 1-2d |
| `P-04` | Tiered RPC dispatch with `redact_params_for_log` — secret-key redaction before any debug trace | openhuman `core/dispatch.rs` | 1d |
| `P-05` | Event Ledger (lightweight JSON sidecar, lock+atomic-writes) for Slint GUI cold-start replay without decrypting WAL | openclaw `event-ledger.ts` | 2-3d |

### v0.4 — memory + brain verification (operator wish-list E + A5 logic audit)

| ID | Item | Source / file:line | Effort |
| :-- | :-- | :-- | :-- |
| `M-01` | Hebbian reinforce on warm + cold tier hit (current code only updates `idx_episode`) | A5 M-1; `src/memory/tiers.rs:139`, `cli/recall.rs:198-213` | 1d |
| `M-02` | CLI recall emits `0x93 IMPORTANCE_REINFORCED` WAL frame (currently CLI path skips → tamper-evident log hole) | A5 M-2; `cli/recall.rs:197` | <1d |
| `M-03` | Replace `now_ns = unwrap_or(0)` with fail-safe skip in decay/consolidate tasks (clock failure currently triggers mass hot→warm migration) | A5 M-3; `memory/decay_task.rs:57` | <1d |
| `M-04` | Fix `decay_task::run() -> Result<()>` misleading signature (infinite loop body — make `-> !` or change contract) | A5 M-4 | <1d |
| `M-05` | DB-level constraint on `day` column ISO-8601 format (warm→cold SQL string compare currently assumes format) | A5 M-7; `memory/consolidate.rs:141-182` | 1d |
| `M-06` | Surface `cold_swept` in `PassReport` (currently `tracing::debug!` only) | A5 M-5 | <1d |
| `M-07` | Memory integration test suite under `SRC/neothd/tests/memory_*.rs` (A1 #6 — zero dedicated tests today) | A1 top-prio #1 | 3-4d |
| `M-08` | 6-region SQLite view coop verification: hippocampus + amygdala + insula + cerebellum + basal-ganglia + hypothalamus each work AND coordinate | new tests | 2d |
| `M-09` | Recall routing per region: query type → region selection logic (currently flat search) | builds on M-08 | 2-3d |

### v0.4 — n8n smarts (operator wish-list AC + AA)

| ID | Item | Notes | Effort |
| :-- | :-- | :-- | :-- |
| `N-04` | Smart MCP loader — don't ship all MCPs in every chat context; load on first slash-command / first explicit reference | reuse skills router patterns | 2-3d |
| `N-05` | n8n vs cron decision rule lifted into `cli/cron.rs` — operator-readable "use n8n when X, cron when Y" runtime guidance | builds on existing `docs/cron-vs-n8n.md` | 1d |
| `N-06` | n8n workflow registry / "best practice" library (top-10 starter workflows beyond the existing 3 bootstrap) | data-only ship | 2d |

### v0.4 — n8n + MCP token wins (from A3, codegraph)

| ID | Item | Adopt-from | Effort |
| :-- | :-- | :-- | :-- |
| `N-07` | codegraph as auto-launched MCP provider in `cli/code.rs`; -35% cost / -70% tool calls on coding | colbymchenry/codegraph (MIT) | <1d |

### v0.4 — quick-wins from A3

| ID | Item | Adopt-from | Effort |
| :-- | :-- | :-- | :-- |
| `Q-01` | claude-plugins-official schema adoption: `plugin.json` with commands/agents/skills/.mcp.json convention | anthropics repo (Open) | <1d |
| `Q-02` | Book of Secret Knowledge skill seed — markdown→TOML catalog parser | trimstray repo (MIT) | <1d |

**v0.4 total estimate:** ~16-22 person-days + A5 memory items. v0.4.0 tag at end.

---

## v0.5 — Multimodal complete + Paperless + Email/Calendar + Obsidian-as-scratchpad

**Theme:** "NEOTH knows my real life inputs and acts on them."

### v0.5 — multimodal final 10% (operator wish-list D)

- v0.2 already shipped: image (CLIP) / audio (whisper) / video (ffmpeg audio + thumbnail) / PDF.
- v0.5 fills: **voice calls** (live transcript via Whisper streaming + Piper TTS reply) + **video calls** (camera feed → live vision frames + transcript merge) + **multi-modal council** (image-aware deep hemisphere).

| ID | Item | Notes | Effort |
| :-- | :-- | :-- | :-- |
| `MM-01` | Voice call live-transcript via streaming Whisper + Piper TTS for reply (channel + GUI) | builds on M-3 shipped | 5d |
| `MM-02` | Video call live frame ingest + multimodal council (image + audio + text fused) | builds on M-2 + M-3 + M-4 | 6d |
| `MM-03` | PiPer-rs / vendor TTS dispatcher for outbound (channel `send_audio` path) | new module `media/tts.rs` | 3d |

### v0.5 — paperless (operator wish-list T + U)

| ID | Item | Notes | Effort |
| :-- | :-- | :-- | :-- |
| `PL-01` | paperless-ngx + paperless-ai auto-install via wizard (W-02 followup) + native config | reuses W-05 | 2d |
| `PL-02` | OCR ingest → Obsidian `.md` knowledge via `cloud/obsidian` sync path; tag-as-ground-truth | reuses memory tier | 3d |
| `PL-03` | Proactive paperless consultation: cron checks new docs → emits proactive message via `proactive.enabled=true` | gates on G-01 below | 2d |
| `PL-04` | Prompt-injection gate on every paperless ingest + email body (reuses `ingress_sanitizer`) | extends existing | 1d |
| `PL-05` | Spam + phishing + malware detection on email body before NEOTH reads it (rules engine + LLM second-opinion) | new module | 3-4d |

### v0.5 — email + calendar (operator wish-list S)

| ID | Item | Notes | Effort |
| :-- | :-- | :-- | :-- |
| `EM-01` | Gmail IMAP/OAuth ingest skill (read + send + draft) | new `channels/gmail` adapter | 4d |
| `EM-02` | Calendar (CalDAV / Google) read + create | new `channels/calendar` adapter | 3d |
| `EM-03` | Email → auto calendar entry — LLM extracts date/time/participants, operator confirms | builds on EM-01+EM-02 | 2d |
| `EM-04` | Email draft generation for high-importance unread (operator approves before send) | reuses consent gate | 2d |

### v0.5 — obsidian as scratchpad (operator wish-list F)

| ID | Item | Notes | Effort |
| :-- | :-- | :-- | :-- |
| `OB-01` | Dreaming pipeline (R-02) writes nightly themes to `~/Obsidian/NEOTH/Dreams/YYYY-MM-DD.md` | builds on shipped `cli/dreaming_task.rs` | 1-2d |
| `OB-02` | Reflection + self-improvement notes auto-archived to vault `Reflections/` | reuses self-dev WAL | 2d |
| `OB-03` | Proactive action stagings: NEOTH proposes a cron / skill / config tweak → writes a draft `.md` for operator to approve | gates on G-01 | 2d |

### v0.5 — Understand-Anything codebase graph (from A3)

| ID | Item | Adopt-from | Effort |
| :-- | :-- | :-- | :-- |
| `UA-01` | Optional `neoth code analyze` step that consumes `understand-anything` JSON output (or ports the analysis pipeline) | Lum1104 repo (MIT) | 1-3d |

**v0.5 total estimate:** ~37-48 person-days. v0.5.0 tag at end.

---

## v0.9 — Proactivity + Slave coupling + Native PC control + Arxiv learning

**Theme:** "NEOTH anticipates and acts."

### v0.9 — proactivity (operator wish-list G)

| ID | Item | Notes | Effort |
| :-- | :-- | :-- | :-- |
| `G-01` | Self-initiated message engine — pattern detection cron emits "I noticed X, want me to do Y?" via the operator's preferred channel | reuses C-16 proactive flag | 4-5d |
| `G-02` | "Knows things about you you don't know" — surfaces profile claims with new confidence above threshold as proactive suggestions | reuses profile WAL | 3d |
| `G-03` | Self-correction loop — every reply scored against operator feedback signal (👍/👎 via channel reaction or follow-up tone) | new module | 4d |

### v0.9 — slave / cluster coupling (operator wish-list H)

| ID | Item | Notes | Effort |
| :-- | :-- | :-- | :-- |
| `SL-01` | OpenClaw-slave + Hermes-slave + OpenHuman-slave adapter contracts — discover via cluster pairing + register as nodes | builds on shipped `cluster/` | 5-6d |
| `SL-02` | Cluster topology view in CLI + GUI (operator wish-list Y): show node health, channel mesh status, hysteria/tailscale RTT, stability score | new GUI panel | 4d |
| `SL-03` | Local LLM / cluster resource tab (operator wish-list X): VRAM/load/power visualisation, currently-loaded models, RAM vs VRAM split per model | new GUI panel | 5d |

### v0.9 — native PC control (operator wish-list O)

| ID | Item | Notes | Effort |
| :-- | :-- | :-- | :-- |
| `PC-01` | OS-tool surface — file/folder ops, app launch, window mgmt, clipboard, system audio control — gated through autonomy + WAL | new `tools/os/` module | 6-8d |
| `PC-02` | Chrome DevTools MCP as optional plugin **with forced `CHROME_DEVTOOLS_MCP_NO_USAGE_STATISTICS=1`** + license confirm before merge | A3 explicit blocker | 1d once unblocked |

### v0.9 — error + arxiv learning (operator wish-list P + Q)

| ID | Item | Notes | Effort |
| :-- | :-- | :-- | :-- |
| `EL-01` | Self-error-check cron — `neoth doctor` runs periodically + writes findings to WAL + surfaces actionable items | reuses doctor | 2d |
| `EL-02` | arxiv paper ingest skill (operator-curated topic feed) + summary → memory tier | data-only | 3d |
| `EL-03` | Learn-from-arxiv pipeline: extract patterns from papers operator marks as relevant → propose self-dev adjustments | gates on G-02 | 3d |

### v0.9 — oh-my-pi adopts (from A3, high-leverage)

| ID | Item | Adopt-from | Effort |
| :-- | :-- | :-- | :-- |
| `OP-01` | hashline content-hash edits port into `cli/edit.rs` (-61% output tokens measured) | can1357/oh-my-pi (MIT) | 1d |
| `OP-02` | Hindsight memory compression on session-end (operator session → mental model on next load) | oh-my-pi | 1-2d |
| `OP-03` | LSP diagnostics loop on every write — every edit immediately queries LSP, surfaces inline | oh-my-pi | 1d |

### v0.9 — OMI integration (from A3)

| ID | Item | Adopt-from | Notes | Effort |
| :-- | :-- | :-- | :-- | :-- |
| `OM-01` | OMI ingest skill — subscribe to Jarvis-local OMI backend; action items → `idx_kanban_*`; transcripts → ground-truth seed | BasedHardware/omi (MIT) | MUST validate `omi.endpoint` is Jarvis-local, abort if `api.omi.me` | <1d |

**v0.9 total estimate:** ~45-55 person-days. v0.9.0 tag at end.

---

## v1.0 — Polish + Security + Perf + GUI 12/10

**Theme:** "Public-release-quality."

### v1.0 — security hardening

| ID | Item | Adopt-from | Effort |
| :-- | :-- | :-- | :-- |
| `SC-01` | OpenGrep security rulepack in CI — port rules + add NEOTH-specific (no raw HTTP/2 CONNECT, no plaintext-secrets-in-WAL, etc.) | openclaw `security/opengrep/` (A2) | ½d |
| `SC-02` | Checkpoint / rollback API with strict path-traversal regex `[A-Za-z0-9_-][A-Za-z0-9_.-]{0,63}` | hermes `api/rollback.py` (A2) | 2-3d |
| `SC-03` | Plugin signature verification + revocation list | builds on existing wasm plugin | 3d |
| `SC-04` | `neoth security audit` command — runs all gates, prints summary | new CLI surface | 2d |

### v1.0 — perf + parity

| ID | Item | Notes | Effort |
| :-- | :-- | :-- | :-- |
| `PF-01` | Active skill usage (operator wish-list L) — NEOTH self-routes through its skill library by default, not only on keyword match | reuses skills registry | 3d |
| `PF-02` | All-LLM-providers coverage (operator wish-list I) — confirm Anthropic / OpenAI / Gemini / Bedrock / Azure / Ollama / Mistral / Cohere / Groq all wired + documented | audit + plug gaps | 3-5d |
| `PF-03` | All-document-formats coverage (operator wish-list R) — DOCX / XLSX / PPTX / EPUB / PDF / ODT / RTF read + create | new `media/document/` module | 5-6d |

### v1.0 — GUI 12/10 (operator wish-list N + R + X + Y)

| ID | Item | Notes | Effort |
| :-- | :-- | :-- | :-- |
| `GU-01` | Settings panel parity for every operator-tweakable config + every wizard step | full audit | 4d |
| `GU-02` | "12/10 hübsch" pass — animations, transitions, micro-interactions, dark/light theme parity, accessibility | design + code | 5-8d |
| `GU-03` | Persona-adaptive depth (from A3 Understand-Anything) — settings panels collapse / expand based on operator profile (LOWKEY → simple defaults; pro → all knobs) | builds on profile presets | 3d |

### v1.0 — todoist + todolist (operator wish-list W)

| ID | Item | Notes | Effort |
| :-- | :-- | :-- | :-- |
| `TD-01` | Todoist adapter (read + create + complete tasks) | new `channels/todoist` | 2d |
| `TD-02` | Generic todo-list compat (CalDAV VTODO + Google Tasks + Microsoft To Do) | new adapters | 4d |

### v1.0 — clarify-prompt + goal manager (from A2)

| ID | Item | Adopt-from | Effort |
| :-- | :-- | :-- | :-- |
| `CL-01` | Clarify-prompt interrupt (mid-turn open question via SSE, 120s timeout) | hermes `api/clarify.py` | 2-3d |
| `GM-01` | Goal manager + turn budget — self-terminate when goal satisfied | hermes `api/goals.py` | 2-4d |

### v1.0 — final cleanup (A1 + A5 derived)

**Framework 4.1 reconciliation (A5 F-1..F-3):**

| ID | Item | Notes | Effort |
| :-- | :-- | :-- | :-- |
| `F4-01` | Ecology-Schicht Rust scanner (read-only fitness scanner emitting human-readable reports — closest today is `memory/gc_task.rs` which is GC not fitness) | A5 F-1 | 4d |
| `F4-02` | Via-Negativa-Kern principle restoration: `RateLimiter` is currently an entity (`Mutex<HashMap>`), not a stateless operation | A5 F-2 | 2d |
| `F4-03` | Schichten-separation: `pipeline/enriched_request.rs` currently reads `Arc<Vec<Skill>>` directly — convert to injected input | A5 F-3 | 2d |

**Spec ↔ code deltas (A5 §5):**

| ID | Spec | Delta | Effort |
| :-- | :-- | :-- | :-- |
| `SD-01` | `SPEC_memory_tiers.md` requires all-tier reinforce | code is hot-only (resolved by M-01) | (folded into M-01) |
| `SD-02` | `SPEC_coding_workflow.md` Pick #1 claims 0x70-0x77 wired | `0x77 KANBAN_TASK_PROGRESS` defined at `events.rs:393` but "not yet wired" | 1d |
| `SD-03` | `SPEC_channel_api.md` (SP-5) WAL `0x38 CHANNEL_MSG_EDIT` defined but `channels/telegram.rs` has no edit-message handler | 2d |
| `SD-04` | `SPEC_coding_workflow.md` Cerebellum orchestrator routes by task type | `cli/recall.rs` bypasses orchestration | 2d |

**Anti-pattern cleanups (A5 §6):**

| ID | Item | Effort |
| :-- | :-- | :-- |
| `AP-01..08` | 8 anti-patterns A-1..A-8 from the logic audit (silent WAL drops, unwrap_or-0 destructive defaults, misleading Result signatures, hardcoded table names, shared-resource-as-value, missing observable side effects, runtime-format-assumption SQL, test-without-integration) | aggregated 5d |

**A1 hidden-features-to-expose (where primitives exist but aren't operator-surfaced):**

| ID | Item | A1 evidence | Effort |
| :-- | :-- | :-- | :-- |
| `H-01` | Live VRAM/load polling exposure — `AcceleratorInfo` knows backend type but not current VRAM/power (#29) | one `nvml` call away | 2d |
| `H-02` | Skill auto-invocation during dreaming/idle (skills are reactive only today; spec mentions proactive) | builds on G-01 | 2d |
| `H-03` | Llama + Unsloth in `models/catalog.rs` (currently Qwen + Ouro only) | 2d |
| `H-04` | Cohere / Mistral / Groq / Together provider adapters (#11 — major hosted providers only) | covered by PF-02 | (folded) |

**v1.0 total estimate:** ~50-65 person-days (40-55 baseline + F4-01..03 + AP-01..08 + SD-02..04 + H-01..03). v1.0.0 tag at end with: signed release artifacts, security audit pass, perf baseline doc, full cross-distro install verification, GUI screenshot gallery, comparison-table refresh.

---

## Sequencing rules

1. **Each lane ships independently.** v0.3 must be tag-and-public-ready before v0.4 work starts on main.
2. **WAL frame band reservations** — claim event-type IDs as part of the spec, not the implementation. Lane v0.3 gets 0x11 + 0x15 (new) + 0x12 extend. v0.4 might claim 0x16..0x18 for clarify + goal events. Coordinate via this file before any new WAL event lands.
3. **Wizard step is the activation surface for every lane.** Every new operator-facing feature gets a wizard step + a settings-panel entry (GUI ↔ CLI parity hard rule).
4. **Security blockers are pre-merge.** chrome-devtools-mcp (A3) needs the env var force + license confirm BEFORE the PR opens, not in v1.0 hardening.
5. **No "next-version" debt creep.** Items deferred from a lane move to the explicit "deferred" column of `PROGRESS.md`, not silently into the next lane's work.

---

## Open questions for operator

1. **Lane sequencing.** Is the order v0.3 → v0.4 → v0.5 → v0.9 → v1.0 fine, or do you want v0.5 (paperless + email/cal) pulled forward because that's the most "real-life-noticeable" win?
2. **GUI re-skin.** GU-02 ("12/10 hübsch") is a design decision — do you have reference UIs you want me to mirror (Linear, Raycast, Arc Browser, OpenHuman, etc.) or do I scope a fresh "NEOTH cyber-brand" pass?
3. **Slave coupling shape.** SL-01 (OpenClaw/Hermes/OpenHuman as slaves/nodes) — do you want NEOTH-as-master only, or also NEOTH-as-slave so other orchestrators can use it?
4. **Email scope.** EM-01..EM-04 — Gmail + IMAP only, or also Exchange / Outlook 365 / Fastmail / Proton?
5. **Native PC control bounds.** PC-01 — operator-visible whitelist (e.g. only known apps + safe directories), or full operator-trust model gated only by autonomy levels?

---

## A1 + A5 audit summary (all 5 agents landed 2026-05-24)

**A1 (35-item implementation-status audit):**
- 2 SHIPPED (item 11 all-LLM-providers, item 34 n8n smart routing)
- 24 PARTIAL (primitives present, exposure / final-mile work needed)
- 9 MISSING (memory tests, email+cal, paperless, OMI, todoist, credentials import, docx/xlsx, video calls, OMI Phase 2+)
- Top-10 priority gaps drive `M-07` (memory tests), `EM-01..04` (email/cal), `W-07` (GUI wizard parity), `G-01` (proactive trigger loop), `H-01` (VRAM panel), `PL-01..05` (paperless), `N-04` (MCP token-budget), `PF-03` (docx/xlsx), `C-01..05` (credentials import), `OM-01` (OMI).

**A5 (logic + integration audit) — two CRITICAL flags retracted after verification:**
- A5 I-1 "K-Wire-3 dead on channel path" → **false alarm** (helper IS wired at `cli/serve.rs:1843` inside `build_pipeline_handler` closure; A5 grepped `src/channels/*` adapter modules — wrong layer).
- A5 I-3 "consent gate bypass" → **false alarm** (`Gate::for_level(autonomy)` wired at `cli/serve.rs:1717` + `:2590`, `consent::ensure_all_still_granted` mid-run at `:2037`).
- A5's other findings are valid and incorporated as `M-01..M-06`, `F4-01..03`, `SD-01..04`, `AP-01..08`.

**A2 (QUELLEN diff)** — 12 candidates from hermes-webui / openhuman / openclaw → `R-01..03` (crash recovery), `P-01..05` (confirm-fatigue kill), `SC-01..02` (security hardening), `CL-01`, `GM-01`.

**A3 (new repos + OMI)** — 7 source feasibility → `N-07` (codegraph), `Q-01..02` (claude-plugins schema + secret-knowledge), `UA-01` (Understand-Anything), `OP-01..03` (oh-my-pi hashline + Hindsight + LSP), `OM-01` (OMI), `PC-02` (chrome-devtools-mcp BLOCKED on telemetry env var force + license confirm).

**A4 (wizard architect)** — full build-ready spec → `W-01..08` (detect + install + recommend + WAL frames) + `C-01..05` (credentials import).

---

## Next step

Read this file end-to-end. The five `Open questions for operator` section above gates lane sequencing + scope decisions. Once you answer those, I generate `PROGRESS_v1_0.md` as the working backlog with `[ ]` items in build-order across v0.3 / v0.4 / v0.5 / v0.9 / v1.0 lanes.
