# AGENTER — Design v0.6 FINAL (BUILD-READY)

> **Status:** Locked. All Q1-Q8 + v0.5 + 9 new sources + claude-cli bridge LOWKEY modules + Chorus v0.5 verdict integrated.
> **MVP cutoff revised: Tag 45 (was 30 — 3 channels + WASM plugin + Auto-Skills cost +15 days, Codex confirmed).**
> **Foundation:** Tool-Framework v4.1 "Pflegbarer Garten".
> **Architecture:** Hirn-Anatomie 3 Hemisphären + 6 enforced brain regions (added `idx_episode`).
> **WAL:** v2 with CRC32c + Magic + node_id (multi-node ready).

---

## 0. Locked Decisions (full Q1-Q8 + v0.6 additions)

| # | Decision | Source |
|---|----------|--------|
| Q1 | Rust core, ASM kernels via FFI only after profiling | v0.2 |
| Q2 | Council triggers: conservative + adaptive | v0.5 |
| Q3 | Block-cache: tombstone-bus-flush + 24h ceiling | v0.5 |
| Q4 | Embedding: Qwen3-Embedding-0.6B-Q8 via candle | v0.4 |
| Q5 | Hemispheres: Left=Claude Opus 4.7, Right=Gemini 3.1 Pro, Callosum=Codex GPT-5.5 | v0.4 |
| Q6 | YAML tool/pipeline format (Framework B.5/C.1) | v0.4 |
| Q7 | Mirror-Refusal spec adopted from `SPEC_mirror_refusal.md` | v0.5 |
| Q8 | Ecology-Schicht: Phase 4, Day 105+ | v0.5+v0.6 |
| **N1** | **Plugins = WASM via wasmtime** (NOT compiled-in, NOT dynamic .so) | v0.6 Codex verdict + safety |
| **N2** | **Skills = YAML data + Schicht-1 declarative pipelines** | v0.6 Gemini verdict |
| **N3** | **Channels: Ingress=Gateway (Runtime), Egress=Schicht-0 Tool** | v0.6 Codex verdict + channel-agent SPEC |
| **N4** | **`node_id: [u8;16]` in WAL EventHeader from Day 1** | v0.6 (Veronica-pattern ready) |
| **N5** | **MVP cutoff Day 45** (was 30, Codex confirmed +15d realistic) | v0.6 |
| **N6** | **Tailslayer default-ON + graceful mmap fallback** | v0.5 |
| **N7** | **needle (Cactus) optional opt-in for on-device function-call routing** | v0.6 user-pick |
| **N8** | **LOWKEY base stack auto-injected** at session-start (L.O.W.K.E.Y 9.4 + DEBIAS + POWER FIST + IMBA) | v0.6 from claude-cli bridge |
| **N9** | **Conductor 3-layer context** (product.md + spec.md + plan.md) — from oh-my-claudecode | v0.6 |
| **N10** | **MAGI ULTRA + OMEGA-PRIME as Council skills** | v0.6 LOWKEY |
| **N11** | **WAL atomic-commit + 120s idle stream-kill** | v0.6 from BRAIN_ARCH panel |
| **N12** | **CloakBrowser opt-in Phase 2 plugin** for `tools/web_fetch.yaml stealth:true` | v0.6 |
| **N13** | **NOT adopted: agentmemory** (6 CVEs); only copy 20-line `marketplace.json` schema | v0.6 |
| **N14** | **NOT adopted: tweakcc, oh-my-gemini, oh-my-codex** as deps (read-only inspiration) | v0.6 |

---

## 1. Sources finally integrated (`QUELLEN/` × 14 + claude-cli bridge + LOWKEY)

| Source | Verdict | Use |
|--------|---------|-----|
| openclaw (steipete) | ADOPT-PORTED | Dreaming-Pipeline, Context-Engine, hybrid-recall logic, trajectory pattern, channel allowlist/gating |
| openhuman | ADOPT-PORTED | Rust ToolSpec trait, PermissionLevel enum, spawn_subagent pattern, daemon supervision |
| hermes-webui | ADOPT-PORTED | Turn Journal fsync, Session Recovery, Compression-Anchor, Gateway-Watcher, Metering |
| jarvis-live | ADOPT-LIVE | Importance≥0.75 threshold, provider cascade order, vault-git pattern, LanceDB schema, dedup formula, SESSION_LEDGER, hippo-turbo constants |
| tailslayer (C++) | REFERENCE | Algorithm only — Rust port used |
| tailslayer-rs | ADOPT-DEP | Optional Cargo feature, default-ON with mmap fallback |
| **needle** (Cactus) | OPT-IN PLUGIN | 26M-param on-device tool-router. Plugin `plugins/needle/`. Pre-classifies user intent before main provider call (saves API cost + latency) |
| **agentmemory** | REJECTED (6 CVEs) | Only `.claude-plugin/marketplace.json` schema (20 lines) adopted |
| **skills** (mattpocock) | ADOPT-PARTIAL | Skill installation pattern + 5 curated skills as Day-22 seed |
| **CloakBrowser** | OPT-IN PLUGIN (Phase 2) | Anti-fingerprint web-scraping. Subprocess. `tools/web_fetch.yaml stealth:true` |
| **react-doctor** | OPT-IN SKILL (Phase 2) | Coding-agent skill. `skills/react_doctor.yaml` invokes `npx react-doctor` |
| **oh-my-gemini** | REFERENCE | `/omg:setup` + `/omg:autopilot` command patterns adopted for Gemini-CLI Right-Hemisphere |
| **tweakcc** | REFERENCE | Statusline customization concepts — AGENTER builds own |
| **oh-my-claudecode** | REFERENCE | Conductor 3-layer-context pattern (product.md/spec.md/plan.md) — adopted as Day-1 skill |
| **oh-my-codex** | REFERENCE | OMX agent orchestration pattern — adopted in Callosum binding |
| claude-cli bridge (Alex's) | ADOPT-PARTIAL | BRAIN_ARCH panel design, hook patterns, statusline, stale-cleanup, pre-compact backup; SOUL.md/CLAUDE.md/BOOT.md/GUIDANCE_BLOCK seed |
| **LOWKEY 16 modules** | ADOPT-AS-SKILLS | L.O.W.K.E.Y 9.4 + DEBIAS + POWER FIST + IMBA = always-injected base stack. MAGI ULTRA + OMEGA-PRIME + POLYMORPH + MAX++ + PME = activatable council/skills |

---

## 2. v0.6 Hemisphere + Brain Region Update

**Hemispheres unchanged** (Left=Claude / Right=Gemini / Callosum=Codex).

**Brain regions: 5 → 6** (added `idx_episode` per BRAIN_ARCH panel finding):

| Region | View | Hard Invariant |
|--------|------|----------------|
| Hemispheres (3) | runtime, not view | Left = only user-output channel |
| **Hippocampus** (NEW) | `idx_episode` | groups WAL events by 60-min windows → episode summaries with `type:episode` + concept-tags |
| Amygdala | `idx_importance` | single-writer, decay-tick, ≥0.75 promotion gate, DSPM formula |
| Insula | `idx_council` | council rounds + verdicts isolated |
| Cerebellum | `idx_motor` | single-writer per-provider stats: latency_ns + success_rate |
| Basal Ganglia | `idx_habit` | tool-router promotion/demotion + skill-keyword index |

WAL `brain_region: Option<u8>` set only for these 6 regions. Others = `None`.

---

## 3. WAL EventHeader v0.6 FINAL (binary-format locked)

```rust
#[repr(C, align(8))]
pub struct EventHeader {
    pub magic:              [u8; 4],   // b"AGNT"
    pub schema_version:     u8,        // 0x03 (v0.6)
    pub event_type:         u8,
    pub event_subtype:      u8,
    pub flags:              u8,        // TOMBSTONE/SUPERSEDED/SYNTHETIC/REDACTED/STREAM_PARTIAL
    pub total_len:          u32,
    pub generation:         u32,
    pub event_id:           u64,
    pub ts_ns:              u64,
    pub importance:         f32,
    pub scope:              u32,
    pub category:           u32,
    pub session_id:         [u8; 16],
    pub node_id:            [u8; 16],  // NEW v0.6: uuid of originating node — multi-node ready
    pub source_uri_hash:    u64,
    pub source_mtime_ns:    u64,
    pub content_hash:       [u8; 16],
    pub chunk_id:           u32,
    pub chunk_range_start:  u32,
    pub chunk_range_end:    u32,
    pub embedding_model_id: u8,
    pub embedding_dim:      u16,
    pub vector_blob_off:    u64,
    pub embedding_hash:     [u8; 16],
    pub parent_event_id:    u64,
    pub supersedes_event_id:u64,
    pub brain_region:       Option<u8>,
    pub hemisphere:         u8,        // 0=N/A, 1=LEFT, 2=RIGHT, 3=CALLOSUM, 4=BOTH (Council)
    pub _reserved:          [u8; 7],
    // Then payload + trailing CRC32c
}
```

---

## 4. Effect Adapter Layer (CRITICAL v0.6 fix)

**Pure Schicht-0 Tools** (no side effects, deterministic, locality-enforced):
- `recall.query`, `refusal_detect`, `embed.encode`, `council.should_trigger`, `council.round_controller`, `council.score_responses`, `council.synthesize`, `schedule.cron` (returns next-fire-time only, no execution), `md_diff`, `concept_vocab_extract`, `topk_heap`, `crc32c`, `freedom_check`.

**Effect Adapters** (Schicht-1 boundary, side-effect-ful, idempotent):
- `telegram.send`, `whatsapp.send`, `slack.send` — channel egress
- `http.fetch`, `http.post` — outbound HTTP
- `wal.emit` — WAL append
- `vault.write`, `vault.read` — Obsidian vault I/O
- `oauth.refresh`, `oauth.grant` — token vault
- `subprocess.exec` — needle/CloakBrowser/react-doctor invocations

Each Effect Adapter manifest:
```yaml
effect_adapter: true
idempotency_key: <required field name in input>
max_retries: 3
audit_event_type: <WAL EventType, e.g. 0x25 CHANNEL_OUTBOUND>
backoff_strategy: exponential_jitter
```

`FinalizeResponseArtifact` is the only payload allowed to reach Effect Adapters of channel-send type.

---

## 5. Plugin System v0.6 (WASM, per Codex verdict)

**Plugin = WebAssembly module + manifest.toml.** Hosted by `wasmtime` runtime in `agenterd`.

```toml
# plugins/needle/plugin.toml
[plugin]
id = "needle"
name = "Cactus Needle on-device router"
version = "0.1.0"
wasm = "needle.wasm"

[plugin.permissions]
required = "ReadOnly"
oauth_vault_access = false

[plugin.hooks]
registered = ["pre_provider_call"]

[plugin.activation]
default = "off"        # opt-in
config_flag = "use_needle_router"
```

**Activation:** `~/.agenter/config.toml`:
```toml
[plugins.needle]
enabled = true
model_path = "/usr/share/agenter/models/needle-26m.gguf"
fallback_on_low_confidence = 0.4   # below this score, escalate to main provider
```

**Why WASM not compiled-in:**
- Codex critique correct: `inventory::submit!` is link-time only; users can't enable/disable plugins without recompile. For optional plugins (needle, CloakBrowser, react-doctor), this is unacceptable.
- WASM via `wasmtime` is memory-safe (sandboxed), audit-friendly, hot-loadable. Adds ~6 MB binary size + 20 MB runtime — acceptable per v0.6 metrics.

**Skills = YAML (Schicht-1 declarative pipelines or Block-B injections).** No code. Auto-loaded from `~/.agenter/skills/`.

---

## 6. Channel Architecture (Codex split)

```
┌─────────────────────────────────────────────────────────────┐
│ INGRESS (Gateway = Runtime, NOT Schicht-1)                  │
│ ┌──────────────────┬──────────────────┬──────────────────┐ │
│ │ Telegram webhook │ WhatsApp webhook │ Slack socket-mode│ │
│ │ teloxide         │ Meta Cloud API   │ slack-bolt-rust  │ │
│ └────────┬─────────┴────────┬─────────┴────────┬─────────┘ │
│          └────────────┬─────┴──────────────────┘           │
│                       ▼                                     │
│            Normalization → InboundMessage                  │
│            (channel_id, user_id, text, attachments[],      │
│             reply_to_id, mentions[], chat_meta)            │
└───────────────────────┬─────────────────────────────────────┘
                        │ WAL emit: 0x24 CHANNEL_INBOUND
                        ▼
            ┌───────────────────────┐
            │ Pipeline-Router       │
            │ respond_to_user.yaml  │
            └──────────┬────────────┘
                       │
                       ▼ FinalizeResponseArtifact
            ┌───────────────────────────────────┐
            │ EGRESS Effect Adapter (Schicht-0) │
            │ telegram.send | whatsapp.send |    │
            │ slack.send                         │
            └───────────────────────────────────┘
                       │ WAL emit: 0x25 CHANNEL_OUTBOUND (+ idempotency_key)
```

**Phase 1 channels:** Telegram + WhatsApp (Meta Cloud API via reqwest) + Slack.
**Phase 2:** Discord, Signal, iMessage, LINE, Matrix.

---

## 7. LOWKEY Base Stack (always-injected, Block-B)

From claude-cli bridge / Alex's MODULE.md analysis:

```yaml
# ~/.agenter/skills/lowkey_base.yaml
skill_id: lowkey_base
version: 9.4
mount:
  target: block_b
trigger:
  mode: always
  hemisphere_filter: any
  permission_required: None
content:
  inline: |
    [L.O.W.K.E.Y 9.4 Master-Prompt + Freedom Config]
    [DEBIAS: anti-smoothing, anti-loop, factual-anchoring]
    [POWER FIST: compression + pattern radar]
    [IMBA: directness + technical substance]
  max_tokens: 800
locality:
  sandboxed: true
  forbidden_side_effects: [filesystem, network, wal, oauth_vault]
```

Other LOWKEY modules become activatable skills:
- `magi_ultra.yaml` — 8-stage reasoning pipeline. Triggered by Council `mode: debate`.
- `omega_prime.yaml` — 4 thinking modes (deductive/abductive/systemic/dialectic). Diversifies Council positions.
- `polymorph.yaml` — 10 expression modes. Activated by `--style=<mode>` flag.
- `max_plus_plus.yaml` — Runtime expansion + style.
- `pme.yaml` — Pure Mechanism Engine.
- `cwp.yaml` — Creative Writing Protocol (State-Machine, kwd-trigger).

**Janus (146 KB, system override)** — NOT adopted as default. Available as opt-in via `freedom.yaml`.

---

## 8. Conductor 3-Layer Context (oh-my-claudecode)

For complex multi-session work, AGENTER's Pipeline-Router supports Conductor mode:

```yaml
# skills/conductor.yaml
skill_id: conductor
mount: block_b
trigger:
  mode: explicit  # activated via agenterctl conductor enable
content:
  template: |
    # product.md — WHY (vision, user, success criteria)
    {{product_md}}
    
    # spec.md — WHAT (requirements, scope, constraints)
    {{spec_md}}
    
    # plan.md — HOW (steps, dependencies, milestones)
    {{plan_md}}
```

Research evidence: 29% faster agent runtime, 17% fewer tokens vs raw conversation context.

---

## 9. Needle On-Device Router (opt-in)

**Activation:** `[plugins.needle] enabled = true`.

**Hook:** `pre_provider_call`. Receives user message. Runs needle inference (CPU, ~5ms). Outputs JSON:
```json
{"intent":"function_call", "tool":"telegram.send", "confidence":0.92}
```
If confidence ≥ 0.7 AND tool exists AND permission allows → call tool directly, skip main LLM. 
Else → fall through to provider cascade (Left Hemisphere).

**Savings:** Estimated 30-50% of simple intent-routing tasks (send_message, fetch_vault, check_status) handled without Claude/Gemini API call.

**WAL:** Each needle-routed call emits `PROVIDER_REQUEST` with `provider_id = "needle-26m"` + `cli_trace { prompt_hash, latency_ns }`.

---

## 10. WAL Atomic Commit + 120s Idle Stream Kill (BRAIN_ARCH panel)

- `CLAUDE_STREAM_IDLE_TIMEOUT_MS=120000` enforced on all CLI subprocess calls.
- `PROVIDER_CALL_COMPLETE` event emitted ONLY after full response received.
- Stream timeout → kill subprocess → emit `PROVIDER_CALL_FAILED` with reason `idle_timeout`.
- No zombie connections. No partial WAL state.

`flags` byte gains `STREAM_PARTIAL` bit for any pre-completion events that need partial-result audit.

---

## 11. Settings + Hooks inheritance from Alex's `.claude/settings.json`

AGENTER honors:
- `permissions.allow` patterns — list of regex/glob patterns auto-allowed for tools
- `hooks.PreToolUse` Bash guards — port as Schicht-1 Pipeline filter
- `hooks.PostToolUse` — port as Plugin hook `on_tool_invocation` post-step
- MCP server bindings — agenterd exposes MCP-server endpoint that mirrors `mcp__agenter__*` namespace
- Chorus pre-commit hook integration — agenterd-internal Council can substitute for external Chorus daemon

Specifically migrate from Alex's existing files:
- `~/.claude/settings.json` permissions section → `~/.agenter/settings.toml [permissions]`
- `~/.claude/hooks/hooks.json` → `~/.agenter/hooks.toml`
- Plugin install state → `~/.agenter/plugins/state.toml`

---

## 12. Final 45-Day Phase 1 Plan

| Day | Deliverable |
|-----|-------------|
| 1 | cargo workspace, SOUL.md+CLAUDE.md+BOOT.md mounted as Block-B, freedom.yaml |
| 2 | WAL writer v2 (CRC32c, fsync, group-commit, **node_id field**) |
| 3 | WAL reader v2 (mmap, repair-resync) |
| 4 | YAML loaders Framework B.5/C.1 + LOWKEY skill loader |
| 5 | Claude CLI-OAuth adapter (Left Hemisphere) + 120s idle-kill |
| 6 | FREEDOM authorization layer + permissions migration |
| 7 | ChannelAdapter trait + InboundMessage/OutboundMessage |
| 8 | Telegram adapter (teloxide) + WAL CHANNEL_INBOUND/OUTBOUND |
| 9 | WhatsApp adapter (Meta Cloud API via reqwest) |
| 10 | Slack adapter (socket mode) |
| 11 | wasmtime Plugin Host runtime integrated |
| 12-13 | idx_episodic + idx_semantic SQLite views |
| 14 | Qwen3-Embedding-0.6B-Q8 via candle |
| 15 | VectorStore (mmap-only, Tailslayer Phase 1.5) |
| 16 | Linear-scan top-k cosine recall |
| 17 | Hybrid Query-Planner (FTS+Vec+temporal-decay) |
| 18 | Amygdala importance-decay + DSPM formula |
| 19 | idx_dedup + REINFORCE events |
| 20 | session.start/end + idx_session |
| 21 | SESSION_LEDGER cross-session resume pipeline |
| 22 | Effect Adapter layer (idempotency_key + audit + retry) |
| 23 | LOWKEY base-stack auto-inject working |
| 24 | refusal_detect Schicht-0 tool (6 classes) |
| 25 | Plugin YAML+TOML loader, empty plugin registry |
| 26 | trajectory tracing + secrets redaction |
| 27 | Context-Engine 5-block assembler |
| 28 | respond_to_user pipeline + finalize_response stage |
| 29 | needle WASM plugin (opt-in, off by default) |
| 30 | idx_episode (Hippocampus episode-grouping per 60min) |
| 31 | Basal Ganglia tool-router + skill keyword routing |
| 32 | Right Hemisphere (Gemini) parallel-analysis stub |
| 33 | Corpus Callosum (Codex) synthesis stub |
| 34 | Conductor 3-layer-context skill |
| 35 | Tailslayer dual-replica + IVF-index |
| 36 | mattpocock/skills seed (5 curated skills installed) |
| 37 | Health endpoint + `agenterctl status` + statusline |
| 38 | vault_sync pipeline (Obsidian Second-Brain) |
| 39 | MCP server endpoint (`mcp__agenter__*`) |
| 40 | Mirror-Refusal pipeline (per SPEC_mirror_refusal.md) |
| 41-43 | Integration tests per channel + per LOWKEY skill |
| 44 | E2E test: 3 channels × full pipeline × LOWKEY + Council-stub |
| 45 | **MVP DEMO**: all 3 channels working, LOWKEY active, needle opt-in working, plugin loader live |

---

## 13. Phase 2 (Day 46-75)

- Full Right Hemisphere + Callosum + Council (debate mode, 2-10 rounds)
- MAGI ULTRA + OMEGA-PRIME activatable council skills
- Council typed `CouncilVerdict` with `AgreementDimension` enum
- Mirror-Refusal full integration
- CloakBrowser opt-in plugin (`tools/web_fetch.yaml stealth:true`)
- react-doctor coding skill
- Dreaming-Pipeline (Light + REM phases)
- Memory-Integrity pipeline (contradiction-triage from Jarvis)
- Situation Board live config reader
- idx_motor/idx_habit/idx_insula full
- compression-anchor (hermes pattern)
- goal-stack (idx_goal)

## 14. Phase 3 (Day 76-105)

- Multi-node WAL gossip-sync (Veronica pattern)
- Migration: 12 Jarvis stores → AGENTER WAL (shadow-only)
- Eval-Goldset 100 queries
- Shadow-Run 14d (Telegram-mirror)
- Recall-Parity ≥ 0.85
- Cutover

## 15. Phase 4 (Day 106+)

- Ecology-Schicht (read-only, Framework E.5)
- MemPalace Hebbian graph (per Jarvis Deep Audit finding)
- Self-Improvement loop (ACTIVE_MUTATIONS, ERL)
- Council-outcome tracking → adaptive thresholds
- Tool-Genealogie

---

## 16. Framework v4.1 Final Conformance

All 13 anti-patterns COMPLIANT in v0.6:

| Rule | Status | How |
|------|--------|-----|
| G.1 Stateful Tool | OK | WAL-only state, Effect-Adapter idempotency |
| G.2 Self-Modifying | OK | Skills hot-reload only, plugins WASM-hot-load but registry immutable per-session |
| G.3 Goal-Seeking | OK | idx_goal Pipeline-Schicht |
| G.4 Meta-Decision | OK | Pipeline-Router enforces hemisphere binding, tools blind |
| G.5 Emergent Composition | OK | `council.should_trigger` deterministic + explicit Pipeline `conditions:` blocks |
| G.6 Refusal-Umgehung | OK | Mirror-Pipeline only, no silent cascade |
| G.7 Scope-Inflation | OK | locality blocks enforced |
| G.8 Starke Emergenz | OK | No adaptive state in tools |
| G.9 Black-Box | OK | cli_trace + introspection on every tool |
| G.10 Magic Scale | OK | AgreementDimension enum, not cosine similarity |
| G.11 Closed-Loop Ecology | OK | Ecology read-only Phase 4 |
| G.12 Level-Confusion | OK | Effect Adapter category, Channel ingress=Gateway/egress=Schicht-0 |
| G.13 Bateson-III | OK | Hemispheres role-bound, no autonomy claims |

---

## 17. Files (all build-ready)

```
PLAN/
  00_DESIGN_v0.6_FINAL.md       ← THIS (normative)
  SPEC_mirror_refusal.md         ← locked
  SPEC_skill_plugin_system.md    ← updated for WASM
  SPEC_channels.md               ← locked (ChannelAdapter + Effect Adapter)
  BLUEPRINT_v06_synthesis.md     ← locked
  CHERRY_PICK_RANKING.md         ← locked
  CHORUS_v04_*.md                ← reviewed, resolved
  CHORUS_v05_codex.md            ← resolved
  CHORUS_v05_gemini.md           ← resolved
  NEW_SOURCES_INTEGRATION.md     ← locked
  REVIEW_architect_v0.4.md       ← resolved
  tool_framework_v4_1.md         ← normative
  03_CHORUS_SYNTHESE.md          ← v0.1 history
  
RECON/
  00_JARVIS_LIVE_TRUTH.md
  01_QUELLEN_ANALYSE.md
  02_OPENCLAW_UPSTREAM_ANALYSE.md
  03_JARVIS_RULES_AUDIT.md
  04_JARVIS_DEEP_AUDIT.md
  
QUELLEN/ (14 source repos cloned)
SRC/ (empty — Day-1 starts cargo new agenterd)
```

---

## 18. Day-1 Command

```
cd c:\Users\Shadow-PC\CascadeProjects\AGENTER\SRC
cargo new agenterd
cd agenterd
cargo add tokio --features="full"
cargo add serde --features="derive"
cargo add hyper --features="full"
cargo add rustls
cargo add ring
cargo add memmap2
cargo add candle-core candle-transformers
cargo add wasmtime
cargo add anyhow thiserror
cargo add tracing tracing-subscriber
cargo add crc32c xxhash-rust
cargo add uuid --features="v4 v7"
cargo add teloxide   # Telegram
cargo add reqwest --features="json rustls-tls"   # WhatsApp Meta + Slack + http.fetch
mkdir -p src/{wal,memory,channels,pipelines,tools,plugins,council,brain,context_engine}
mkdir -p ~/.agenter/{skills,plugins,memory}
touch ~/.agenter/soul.md ~/.agenter/claude.md ~/.agenter/freedom.yaml
echo 'agenterd v0.6 — Day 1' > src/main.rs
cargo build --release
```

Then start Day-2 WAL writer with CRC32c + node_id.
