# NEOTH Feature Evaluation — Consolidated Agent Findings (2026-05-15)

7 specialist agents reviewed ~80 candidate features against NEOTH's shipped code, design specs, and architectural invariants. This document is the consolidated decision surface. Source dumps live at the agent task-id paths under `C:\Temp\claude\.../tasks/`.

## Agents Run

1. **architect #1** (`aa0ea24f`) — architectural-fit scoring (NATIVE/EASY/ADAPT/HARD/INCOMPAT) across all blocks + top-10
2. **code-explorer** (`a609ba89`) — ground-truth gap analysis with 0%/25%/50%/75%/100% status per item
3. **security-reviewer** (`a51628ba`) — OWASP-LLM Top-10 risk classes, attack surface, mitigations
4. **performance-optimizer** (`af9bd6b2`) — cost class + latency class + first-run footprint per item
5. **planner** (`a5e7e8b1`) — 7-phase roadmap + top-20 quarterly + 3 architectural decisions
6. **code-architect** (`af1b1c51`) — design-spec alignment audit + 5 concrete blueprints
7. **architect #2** (`aff905ec`) — deep design notes for Block C items #1, #5, #9, #10, #11, #14, #15, #16

---

## Architectural Decisions the Operator Must Make Before Roadmap Locks

Five decisions surfaced across agents. Each blocks at least one phase.

| ID | Decision | Surfaced by | Phase blocked |
|----|----------|-------------|---------------|
| **AD-1** | Mobile UI: Slint cross-platform vs native (Compose Multiplatform / SwiftUI / React-Native+Rust-core) | planner + architect#1 | Phase 5 mobile clients |
| **AD-2** | Hyperswarm transport strategy: native Rust port / Node-Pears subprocess / drop Keet entirely | planner | Phase 2 channels, Phase 19 cluster |
| **AD-3** | WhatsApp path: Meta Cloud API (webhook + HTTPS) / Baileys subprocess (Node, ToS-grey) / drop in favour of Signal | planner | Phase 2 channels |
| **AD-4** | GDPR forget: WAL segment rewrite (HMAC chain preserved) vs HMAC-chain-break for tombstoned frames | architect#2 | C-15 implementation |
| **AD-5** | TEE attestation realistic scope: skip entirely / "local attestation-lite" via 0x52 WAL only / dedicated security sprint with TDX hardware | architect#2 | C-5 verifiable behaviour |

Recommended defaults (based on agent convergence):

- **AD-1**: Slint for desktop (already shipping), **React Native + Rust core static lib** for mobile (architect#1's pick), PWA via `/healthz` listener as interim. Reasoning: Slint's mobile story is not production-grade in mid-2026.
- **AD-2**: Path 3 (Pears HTTP bridge) when trigger fires. Operator who wants Keet already runs Pears. Already documented in `QUELLEN/research/R-A1_hyperswarm.md`.
- **AD-3**: Meta Cloud API + Hysteria tunnel for the webhook endpoint. Mandates Hysteria but stays self-contained per the hard rule.
- **AD-4**: Retain TOMBSTONE frames + wipe payload + recompute HMAC over the tombstone. Audit trail says "deletion happened"; content is unrecoverable. Both architect#2 and security-reviewer agree.
- **AD-5**: Skip TEE for v0.1. Ship "local attestation-lite" with WAL event 0x52 LOCAL_INFERENCE_USED so operators can audit which turns stayed local. Full TEE → Phase 3+ security sprint.

---

## Cross-Agent Consensus — Top 10 to Ship Q3 2026

Items where **at least 4 of 7 agents** converged as top-priority. Each row carries the source agent picks + the planner's phase tag.

| Rank | ID | Name | Agent consensus | Build cost | Phase |
|------|----|------|-----------------|------------|-------|
| 1 | **C-14** | Cost transparency ex-ante (predict €0.07 before call) | architect#1, code-explorer (50%), security, perf #1, planner Ph1, architect#2 top-3, code-architect blueprint | 1-2 days | Phase 1 |
| 2 | **C-1 + C-11** | Anti-sycophancy + adversarial critic sub-agent | architect#1, code-explorer (50% via `sub_agents/review.rs`), perf #6, planner Ph1, architect#2 top-3 | 1-2 days | Phase 1 |
| 3 | **C-15** | Real GDPR forgetting (cascade across tiers + embeddings + archive) | architect#1, code-explorer (75%), security top-10, planner Ph1, architect#2 top-3 | 3 days | Phase 1 |
| 4 | **A-24** | ArXiv learner (operator-requested) | architect#1 #1 pick, planner Ph3, perf top-10, security low-risk | 1-2 days | Phase 3 |
| 5 | **A-20 / A-21** | Web Search + Web Fetch (Brave/Tavily + reqwest → MD) | architect#1, planner Ph3, perf top-10, code-architect blueprint | 1-2 days each | Phase 3 |
| 6 | **B-rollback** | `/rollback` snapshot before file-mutating ops | architect#1, perf top-10, security medium-risk | 2-3 days | Phase 1 |
| 7 | **A-7 Slack** | Live Slack channel (xoxb + xapp socket-mode) | architect#1, code-explorer (25% scaffold), planner Ph2, security medium-risk | 2-3 days | Phase 2 |
| 8 | **A-3 / A-4** | GitHub PR + Issues workflow (gh CLI shim) | architect#1, perf top-10, planner Ph4, security medium-risk | 1-2 days each | Phase 4 |
| 9 | **A-45 TTS** | piper-rs for local voice replies (pairs with shipped whisper STT) | architect#1, planner Ph6, perf low cost | 1 week | Phase 6 |
| 10 | **C-7 "Her" layer** | Persona warmth via `tweaks.toml::persona_override` + groundtruth | architect#1 top-3, planner Ph1, perf cheap | 1-2 days config + ongoing polish | Phase 1 |

**Top bottom-5 — DO NOT ship without stronger trust model** (security CRITICAL):

1. **B-Composio** — 850+ SaaS tokens transit third-party broker; structural supply-chain risk
2. **B-CloakBrowser** — binary blob bypasses third-party security controls; legal exposure + unsigned binary in process
3. **B-Mcporter from chat** — tool poisoning via MCP descriptions; needs sanitizer extension + signed allowlist first
4. **B-Capability-Evolver** — LLM-writes-code-NEOTH-runs-it without WASM sandbox staging
5. **B-macos-computer-use** — desktop steering has no `Action::DesktopSteer` gate yet; runs under `ExecArbitrary` which is wrong

---

## Block A scorecard (50 mainstream features)

Full table at `C:\Temp\claude\.../tasks/a609ba89...output` (code-explorer) — selected highlights:

### Already at 100%
- A-11 Telegram bot (photo + voice + audio + audit events)
- A-33 Memory backend (4-tier WAL + idx_embedding + FTS5 + Hebbian — strongest in class)
- A-37 Long-term conversation search (FTS5 porter+trigram+fuzzy + vector recall)
- A-44 STT (whisper-large-v3-turbo)

### At 75% — finish in 1-week sprint
- A-25 Claude Code delegation (tmux V2 deferred)
- A-26 OpenAI Codex delegation (installer + updater done; provider adapter missing — PROGRESS-MISMATCH flagged)
- A-44 STT text wiring (whisper loads; AudioExtractor needs Phase 2b transcription loop wired)
- A-48 SecureClaw / OWASP-LLM hardening (ingress_sanitizer ships; OWASP report output missing)
- A-49 Workflow Engine (cron + sub_agents ship; typed approval gates + Kanban UI missing)
- A-8 Obsidian vault (sync timer + auto-mirror ship; plugin curation + read-query API missing)

### At 25-50% — scaffold present, runtime path missing
- A-7 Slack — credential scaffold; needs tokio-tungstenite + event routing
- A-13 WhatsApp — credential scaffold; needs hyper webhook + `/messages` Graph API call
- A-30 Python/Node runtime — skills engine ships; no built-in language skill
- A-40 Markdown converter — multimodal text extraction ships; no Markdown serializer

### Mostly 0% but EASY (1-3 days each)
- A-12 Discord (ChannelKind variant exists; needs serenity adapter)
- A-20 Web search; A-21 web fetch; A-22 OSM; A-23 Tenor; A-24 ArXiv — all "skill YAML + http_client + 1 day"
- A-27 OpenCode CLI delegation (mirror Codex installer pattern)
- A-28 Git operations (skill YAML with subprocess + ExecScripts gate)
- A-38-43 Content creation skills (blog/SEO/Excalidraw/Drawio — provider call + skill YAML)

### INCOMPATIBLE with hard rules
- A-6 Jira via Composio (Composio = external broker → self-contained-rule violation)
- A-50 Composio Universal Connector (same reason)
- A-46 Twilio Voice Call (public HTTPS webhook → operator decision needed)

---

## Block B scorecard (Power-user heavy hitters)

### EASY (1-3 days)
- **B-web-fetch** (built-in HTML→MD via htmd) — 1 day
- **B-firecrawl** (REST overlay with API-key probe) — 1 day; falls back to web-fetch
- **B-rollback** (`/rollback` snapshot before file ops) — 2-3 days; reuses `daemon/backup.rs`
- **B-arxiv-learner** (cron-scheduled ArXiv + recall injection) — 2 days
- **B-cron-subagents wiring** (cron module + sub_agents both ship; needs 1 plumbing call) — 1-2 days

### ADAPT (1-2 weeks)
- **B-gogcli** Google Workspace via single binary; Phase 20 CL-2..CL-5 already mapped
- **B-playwright** Playwright MCP v2 — needs MCP host (A-31) prerequisite
- **B-camoufox / nodriver** — feasible behind ExecArbitrary gate; ~1 week
- **B-skill-vetter** ClawDex pre-install scanner — fits `skills/test_harness.rs` scaffold
- **B-capability-evolver** — Hebbian + consolidation are the signal; LLM-driven mutation loop
- **B-honcho** dialectic user-modeling — cron consolidation upgrade; ~2 weeks
- **B-1password** — `op` CLI subprocess with ExecScripts gate

### HARD (3+ weeks) or operator-decision-blocked
- **B-cloakbrowser** — 200 MB C++ patched Chromium; bundling violates size spirit; subprocess wrapper feasible; **needs operator decision**
- **B-macos-cu** desktop steering — needs new `Action::DesktopSteer` variant + accessibility APIs; macOS-only
- **B-mobile-nodes** iOS/Android — companion app per platform; see AD-1
- **B-atropos** RL trajectory export — WAL export sufficient; full RL training pipeline external to NEOTH scope

### INCOMPAT
- **B-moltbook / molthub** — social network feature requires shared external server

---

## Block C scorecard (18 "everyone wants, nobody builds")

| # | Name | Status | Top-3 to ship? | Compat | Build |
|---|------|--------|----------------|--------|-------|
| 1 | Anti-sycophancy / disagrees | 25% | ✓ | EASY | 1-2d |
| 2 | Agent w/ own goals | 0% | | ADAPT | 1 week |
| 3 | Group / Family Mode | 0% | | HARD | 3+ weeks (needs Phase 19 Hyperswarm) |
| 4 | Skin in the Game | 0% | | HARD | needs external escrow primitive |
| 5 | TEE attestation | 0% | | HARD | AD-5 decision; defer to Phase 3+ |
| 6 | Death of the Prompt (proactive) | 25% | | ADAPT | 1 week (calendar integ + cron) |
| 7 | "Her" personality layer | 25% | ✓ | EASY | 1-2 days config |
| 8 | Real federation | 0% | | HARD | requires multi-user trust primitive |
| 9 | Live steering | 0% | | ADAPT | 1 week (tokio cancellation tokens) |
| 10 | Persistent identity | 50% | | ADAPT | scope: persona block in groundtruth |
| 11 | Adversarial multi-agent | 50% | ✓ | EASY | 1-2 days new built-in |
| 12 | Embodiment / smart home | 0% | | HARD | needs sensor-ingress channel type |
| 13 | Capability decay tracking | 0% | | ADAPT | 1 day per architect#2 (skill smoke tests) |
| 14 | Cost transparency ex-ante | 50% | ✓ | EASY | 1-2 days |
| 15 | Real GDPR forgetting | 75% | ✓ | NATIVE/ADAPT | 3 days (depends on AD-4) |
| 16 | Inner-monologue audit | 25% | | ADAPT | 1 week (Claude stream-json mode) |
| 17 | Sub-200ms voice | 0% | | HARD | 3+ weeks (streaming VAD + decode + duplex audio) |
| 18 | Quality signal (not stars) | 0% | | ADAPT | 1 week (WAL event + operator rating CLI) |

**Top-3 to ship FIRST** (architect#2 consensus): **C-14 Cost transparency**, **C-15 Real forgetting**, **C-1 Anti-sycophancy**. Order of implementation.

---

## Design Spec Alignment (code-architect finding)

`docs/superpowers/specs/` contains exactly **three files**, all brand/UI/UX:

1. `2026-05-15-neoth-brand-identity.md` — visual identity, palette, logo SVGs
2. `2026-05-15-neoth-uix-design-system.md` — UIX-DS v1.0 (layering, motion, typography, platform rules)
3. `2026-05-15-neoth-readme-manifesto.md` — README structure rules

**No architectural specs exist in this directory.** The runtime architecture authority is the `memory/neoth_arch_*.md` files + the shipped code. The spec directory is authoritative for rendering surfaces only.

### Concrete drift to fix
- **CLI theme**: UIX-DS §4.3 mandates `#00ff80` for `N >` prompt — no `cli/theme.rs` module exists; each CLI module writes its own format
- **Slint wizard**: probably uses raw hex values per screen; no shared `neoth-theme.slint` token component
- **Channel API**: `ChannelKind::Discord` declared but no `channels/discord/` module — variant ahead of impl
- **Skill SDK**: hook-only surface, no `Skill` trait, no skill manifest format, no lifecycle WAL band — entire skill story is stub
- **`Action::ExecSkill / WebFetch / McpCall`** missing from `permissions/mod.rs` — needed by Phase 3+ work

### Concrete blueprints delivered (code-architect)
For 5 features the agent produced full file-structure + trait + WAL events + build-order + tests:

1. **Skill Plugin SDK + Vetter** — `skills/{mod,manifest,loader,runner,vetter}.rs` + `cli/skill.rs`; WAL band 0xB0-0xBF; new `Action::ExecSkill`
2. **Discord Channel Adapter** — `channels/discord/{mod,slash,embed}.rs`; reuses 0x30-0x3F; serenity/twilight dep
3. **Web Fetch + Firecrawl** — `tools/{mod,web_fetch,firecrawl}.rs`; new WAL band 0xC0-0xCF; new `Action::WebFetch`
4. **Cost Transparency Gate** — `providers/cost.rs`; extend meter; reuse 0xA0-0xAF (0xA4); config-driven threshold
5. **Persistent Provider Identity** — `identity/{mod,persona,injector}.rs`; `idx_groundtruth` scope=persona; PreProviderCall hook

These are buildable from the doc alone.

---

## Performance / Cost Highlights

### TokenJuice equivalent (Reddit $131/day root cause)
NEOTH's session layer currently passes the full `prompt: String` to providers. The compressor belongs at session-assembly, not provider-trait. Concretely: a `pre_llm_call` TOML hook with `replace` action that invokes the local Qwen to summarize tool-call outputs >500 tokens before the main LLM sees them. **Implementation: 1 module, 1 hook stage extension. Already plumbed via `hooks/dispatcher.rs::run_stage`.**

### Pre-flight cost prediction (C-14)
The Meter (`providers/meter.rs`) records post-call. Adding `predict(input_tokens)` with `tiktoken-rs` (~2MB, microseconds) + a static `price_table.toml` (input/output cents per Mtok per model) + rolling-average expected output tokens from prior turns → covers the use case. **Implementation: `providers/cost_predictor.rs`, 1 day.**

### Sub-200ms voice (C-17)
Current path: whisper batched per 30-second chunk → 800ms-2s. Missing for sub-200ms:
- Streaming VAD (silero-vad ONNX, ~1MB, CPU, <5ms/frame)
- Streaming whisper decode (candle 0.8 supports it; replace batch loop)
- TTS interruption (tokio::sync::watch stop channel)
- Duplex audio I/O (CPAL continuous ring-buffer, currently one-shot)

LLM call itself is 1-3s — sub-200ms applies only to STT leg. Full duplex turn-around: still 1-2s, vastly better than walkie-talkie. **Implementation: 3 weeks.**

### Cold-start strategy
8.2 GiB upfront is operator-hostile. Wizard should offer three tiers:
- **Minimal** (0 dl): text-only, cloud providers. Start in <10s.
- **Standard** (~1.6 GiB whisper)
- **Full** (~8.2 GiB whisper + CLIP + Qwen)
Background pull path already exists. Wire into post-init step.

### Cost classes (selected)
- **FREE local**: A-3 GitHub, A-15 SMTP, A-18 Playwright, A-21 web fetch, A-28 git ops, A-33 memory, A-44 STT, A-48 SecureClaw, A-49 workflow engine, B-arxiv, B-rollback, C-1, C-9, C-13, C-14, C-15
- **CHEAP** ($≤0.01/call): A-1, A-2, A-5, A-7, A-12-13, A-20 (~$0.001/Brave; $0.01/Tavily), A-45 TTS cloud, A-50 Composio
- **EXPENSIVE** (defer or strict-gate): A-46 Twilio (~$0.013/min), A-47 FLUX local (4-24GB GPU), C-4 Skin-in-game, C-5 TEE (SGX hardware), C-8 federation

---

## Security Posture (security-reviewer finding)

### CRITICAL — refuse to ship without primitives in place
- **B-CloakBrowser / camoufox / nodriver** — binary blob, no signature chain, bypasses third-party security controls. Gate at `autonomy=elevated` minimum + signed source-tarball build-from-source in CI.
- **B-Composio Universal Connector** — 850+ SaaS tokens through third-party broker. Existential blast radius. WASM sandbox + per-connector allowlist mandatory before shipping.
- **B-Mcporter agent-driven OAuth** — tool poisoning via MCP descriptions. Allowlist + sanitizer extension required.
- **B-Terminal backends** (Modal/Daytona/SSH/Singularity/Vercel) — each is arbitrary remote shell. Need `Action::RemoteShell { backend, host, command_class }` variant; current `ExecArbitrary` is too coarse.

### HIGH — ship with guardrails
- **B-1Password / Dashlane** — strict read-only scope, `PermissionToken<Dangerous>` per fetch, never logged plaintext, WAL `0xA4 CREDENTIAL_FETCH` (reserve)
- **B-AppleEcosystem** (macos-computer-use) — new `Action::DesktopSteer { app }`; map Deny at strict/standard/elevated, Confirm at full only, WAL `0xB2/0xB3`
- **B-Capability-Evolver** — output must stage into WASM plugin-sdk pipeline; not `ExecArbitrary`. Token-budget ceiling per invocation.
- **A-2 Google Workspace via gogcli** — OAuth refresh token in OS keychain only, never WAL/Obsidian; scrub subprocess stderr

### MEDIUM — already-have mitigations apply
- A-7 Slack, A-12 Discord, A-13 WhatsApp — apply `ingress_sanitizer::sanitize()` per message + sender-trust tiers
- A-3 GitHub PR workflow — `WriteOutsideHome` gate fires per fs write; merge requires `autonomy >= elevated`
- A-18 Playwright — URL allowlist or DangerousTarget deny-list; sanitize page content before LLM
- A-15 Email — rate-limit outbound; DKIM/SPF required; recipient allowlist at standard

### New WAL bands to reserve (security)
- `0xB0..=0xBF` — Plugin/Skill lifecycle (SKILL_INSTALLED/INVOKED/COMPLETED/FAILED/TAMPER_DETECTED)
- `0xC0..=0xCF` — Tool invocation (TOOL_INVOKED/COMPLETED/FAILED + RemoteShell session start/end)

---

## Roadmap (planner finding)

### Phase 0 — Cleanup (1-2 days)
- F-17/F-18/F-19/F-20 plugin SDK spec closure
- D14b-1..5 candle Qwen3 forward pass
- B-6..B-10 ClaudeCli bridge V2 (tmux + SSE)

### Phase 1 — Operator UX (1 week)
- **C-14 Cost transparency ex-ante** (predictor + permission gate)
- **C-1 Anti-sycophancy persona layer** (tweaks.toml + system-prompt injection)
- **C-9 Live steering** (`/pause` `/correct` `/resume` slash commands)
- **C-10 Persistent identity** (groundtruth scope=persona + PreProviderCall hook)
- **C-15 DSGVO real forgetting** (`neoth forget <pattern>` cascade-delete)
- **A-28/A-29 provider + channel CLI** (live add/list/test/remove)
- **AU-7 GUI autonomy radio**

### Phase 2 — Channels (2 weeks) — gated by AD-2 + AD-3
- A-7 Slack adapter (socket-mode WebSocket)
- A-15 Email channel (SMTP/IMAP)
- A-13 WhatsApp (depends on AD-3)
- K-1..K-5 Keet (depends on AD-2)
- Phase 18 F-1..F-4 per-messenger formatter
- A-14 Signal

### Phase 3 — Browser + Web (2 weeks)
- A-21 web fetch + A-20 web search + A-18 Playwright MCP
- B-firecrawl
- A-24 ArXiv learner
- A-22 OpenStreetMap / OSRM
- A-40 Markdown converter

### Phase 4 — Skill Marketplace (3 weeks)
- A-35 Skill Workshop / Skill Factory
- A-36 Self-improving Curator
- B-SkillVetter pre-install scanner
- B-Mcporter MCP discovery + OAuth
- A-31 generic MCP client
- A-50 Composio (only with guardrails per security)
- A-3/A-4 GitHub PR + Issues
- A-2 Google Workspace via gogcli
- A-1 Notion

### Phase 5 — Mobile Clients (4 weeks) — gated by AD-1
- Block D desktop (macOS/Windows/Linux Slint)
- Block D Android (Compose/Slint per AD-1)
- Block D iOS (SwiftUI/Slint per AD-1)
- B-Mobile Nodes (camera/canvas/device actions)
- Phase 20 CL-1..CL-9 OpenDAL cloud connectors

### Phase 6 — Self-Improvement (4 weeks)
- C-2 Agent with own goals (autonomous research loop)
- C-6 Death of the Prompt (proactive context prep)
- Phase 22 N-1..N-4 n8n integration
- A-49 Workflow Engine (Lobster pipeline + approval gates)
- C-11 Adversarial multi-agent debate
- A-34 memU hierarchical knowledge graph
- A-45 TTS outbound replies
- A-47 image generation (cloud-only default)
- Phase 19 C-1..C-5 real Hyperswarm cluster

### Phase 7 — Federation (deferred — needs multi-user trust primitive first)
- C-8 real federation
- C-3 Group / Family mode
- C-4 Skin in the Game
- C-5 verifiable behaviour (TEE)
- C-16 inner-monologue audit
- A-16 Microsoft Teams
- A-17 Feishu/Lark/WeCom/DingTalk

---

## Obsidian Plugin Auto-Config (planner finding)

The auto-config should drop these into `.obsidian/plugins/` + `community-plugins.json`:

1. **dataview** — SQL-style queries over vault frontmatter; renders WAL-materialised daily notes as live dashboards
2. **periodic-notes** — daily/weekly/monthly note schedule; integrates with Phase 6 morning-brief cron
3. **templater** — template engine for session-archive note headers
4. **smart-connections** — local-embedding semantic search complementing NEOTH's FTS5 recall
5. **obsidian-git** — auto-commits vault changes to local git; tamper-evident paper trail
6. **advanced-uri** — deep-link callbacks from NEOTH's CLI into running Obsidian window
7. **canvas** — explicitly enable for Phase 4 Skill Factory visual skill maps

---

## What NEOTH Already Does Better Than the 50

(synthesised from agent findings against the candidate list)

- **Memory backend (#33)** — 4-tier WAL + idx_embedding + Hebbian decay + ground-truth + HMAC compaction. Strongest-in-class by every agent's read; OpenClaw/Hermes/OpenHuman have one or two of these, not all five.
- **Multimodal pipeline (R-9)** — pure-Rust decode (PDF/image/audio/video) + CLIP text+image embeddings + whisper large-v3-turbo with auto-language detect + temperature fallback. None of OpenClaw/Hermes/OpenHuman ship full-stack local multimodal.
- **Long-term conversation search (#37)** — FTS5 (porter + trigram + fuzzy) AND vector recall in one query. Most competitors are one or the other.
- **Autonomy levels + Permission gates (#48 superset)** — strict/standard/elevated/full/custom + typed `Action` enum + `PermissionToken<L>` typestate for plugins. Most competitors have role-based ACLs at best.
- **Self-contained hard rule** — single binary, every dep wizard-installable, no external services. OpenClaw needs Composio, Hermes needs Honcho service, OpenHuman has cloud auto-fetch.
- **WAL audit + HMAC compaction** — tamper-evident audit trail with detached HMAC signing. Reddit specifically complains that competing agents have no objective behaviour log.
- **TOML hooks engine** (8 stages, 3 actions) — operator-overridable behaviour without writing Rust. Hermes hooks are JS-only; OpenClaw needs plugin SDK.
- **Memory tier consolidation + Hebbian decay** — automatic warm→cold→long-term promotion. Competitors have flat stores or operator-curated tiers.
- **Ingress sanitizer + ground-truth + autonomy stack** — three layers of injection defence. SecureClaw is the closest analogue and doesn't ship by default.

---

## Concrete Next Action Queue

1. **Decide AD-1 through AD-5** (operator)
2. **Phase 0 cleanup** in parallel (F-17..F-20 plugin SDK spec closure + D14b Qwen3 forward pass)
3. **Phase 1 sprint** in order:
   - C-14 cost predictor (1-2d)
   - C-1 anti-sycophancy + C-11 critic sub-agent (1-2d)
   - C-15 GDPR forget (3d, gated by AD-4)
   - C-9 live steering (1 week)
   - C-10 persistent identity (1 week)
4. **Phase 0.5 — security primitives BEFORE Phase 4**:
   - WASM plugin sandbox completion
   - `Action::ExecSkill`, `Action::WebFetch`, `Action::McpCall` variants
   - `Action::DesktopSteer` if Apple ecosystem is on the table
   - `Action::RemoteShell { backend, host, command_class }` granular gate
   - WAL bands 0xB0-0xBF (skill) + 0xC0-0xCF (tool) reservation
5. **Continue 5+** per planner roadmap

---

**Total agent-recommended ship-this-quarter items**: ~20. Estimated build cost summed: ~12 weeks at 1-dev. Tier 1 (top-10) is achievable in 6 weeks; Tier 2 stretches into Q4.
