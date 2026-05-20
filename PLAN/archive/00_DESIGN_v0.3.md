# AGENTER — Design v0.3 (Tailslayer + Native Multi-LLM Council + Context Split + CLI-OAuth)

> Diff zu v0.2: 6 neue Features integriert.

## Neue Features in v0.3

1. **Tailslayer-Integration** (Rust-Port) für sub-µs DRAM-Tail-Latency in vectors.bin Lookup.
2. **Multi-LLM Council** als **native, toggleable Feature** (kein externer Chorus-Daemon nötig).
3. **Dialog-Runden konfigurierbar 2–10**.
4. **Context-Split: Tools getrennt von Text** — Token-Effizienz.
5. **CLI-OAuth Standard**: Claude Code, Codex CLI, Gemini CLI via OAuth.
6. **API als Sekundär-Path** — gleicher Code, andere Auth.

---

## 1. Tailslayer-Integration (vectors.bin Hot-Path)

### Was Tailslayer ist (re-confirmed nach Repo-Klon)

C++ Library `LaurieWired/tailslayer` (2 544 stars, Apache 2.0). Reduziert DRAM-tail-latency via hedged reads über mehrere RAM-Channels mit unkorrelierten Refresh-Schedules. Default 2 Channels × 2 Replicas, 1 GiB Hugepages, eliminiert ~3 µs DRAM-Refresh-Spikes.

**Rust-Port `OctopusTakopi/tailslayer-rs`** (4 stars, Apache 2.0, edition 2024) — frisch (v0.1.0), aber API redesigned und idiomatischer:
- `ReplicatedBuffer<T>` — hugetlb-backed table
- `HedgedRuntime<T>` — one worker per replica, races load
- `LinuxHedgedReader<T>` — closer to C++ original, callback-driven
- Deps: nur `libc 0.2` (clean)

### Wo es in AGENTER lohnt

| Bereich | Fit | Begründung |
|---------|-----|-----------|
| `vectors.bin` Lookup im Hot-Path | **JA** | Read-mostly, integer-indexed (event_id → vector_blob_off), tail-latency dominiert p99/p999 |
| BPE-Token-Vocabulary (Qwen3 151k) | **JA** | Read-only, integer-indexed, hot lookup pro Embed-Call |
| Static config tables (provider-metadata, model-catalog) | JA | Read-once, lookup-frequent |
| `events.bin` WAL | NEIN | Append-frequent, nicht read-mostly |
| FTS posting lists | NEIN | Variable size, nicht `Copy` |
| Importance heap | NEIN | Mutating |

### Realistic Win

- p50 Cosine-Top-K bei 1M × 1024d: ~50-80 ms (memory-bandwidth bound, AVX-512 + prefetch)
- p99 Spike-Reduktion: **~3 µs DRAM-Refresh-Spike eliminiert pro Lookup**
- p999 Effekt: kumulativ stärker, da viele Lookups pro Query
- **Target: p99 → p95 enger, p999 → p99 enger.** Median bleibt etwa gleich.

### Integration

```toml
# Cargo.toml
[features]
default = ["tailslayer"]
tailslayer = ["dep:tailslayer"]
no-tailslayer = []  # for systems without hugepages / dev workstation

[dependencies]
tailslayer = { version = "0.1", optional = true }
```

```rust
// src/memory/vectors.rs
#[cfg(feature = "tailslayer")]
pub struct VectorStore {
    inner: tailslayer::ReplicatedBuffer<[f32; VECTOR_DIM]>,
    runtime: tailslayer::HedgedRuntime<[f32; VECTOR_DIM]>,
}

#[cfg(not(feature = "tailslayer"))]
pub struct VectorStore {
    mmap: memmap2::Mmap,  // fallback: regular mmap
}

impl VectorStore {
    pub fn load(&self, blob_off: u64) -> Result<[f32; VECTOR_DIM]> {
        #[cfg(feature = "tailslayer")]
        return self.runtime.read(blob_off as usize / VECTOR_BYTES);

        #[cfg(not(feature = "tailslayer"))]
        return self.read_mmap(blob_off);
    }
}
```

### Hugepage-Setup (Linux-Provisioning)

```bash
# 1 GiB pages: 16 pages = 16 GiB für vectors.bin Replicas
echo 16 | sudo tee /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages

# 2 MiB pages für Dev-Workstation:
echo 1024 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
```

Default-Profile in `~/.agenter/config.toml`:

```toml
[memory.vectors]
backend = "tailslayer"  # "tailslayer" | "mmap"
replicas = 2
hugepage_size = "1GiB"  # "1GiB" | "2MiB"
core_pins = [4, 5]      # worker cores
channel_validation = true
```

### Migration-Pfad bei Tailslayer-Failures

Hugepages nicht verfügbar → graceful fallback auf `mmap`-Backend, log-warning, Feature an/aus toggleable per Config-Reload (kein Restart).

---

## 2. Multi-LLM Council — Native Feature (Chorus eingebaut)

### Konzept

Statt externem `chorus`-Daemon (Node.js, lokal :7707) wird das Multi-LLM-Beratungs-Pattern direkt in `agenterd` integriert. Toggleable pro Request **und** global. Bei komplexen Tasks reden 2-N LLMs in 2-10 Runden miteinander, bis Konsens oder Round-Limit.

### API

```rust
// HTTP API: POST /v1/council
{
  "task": "Stress-test this architecture",
  "artifact": "...",
  "mode": "council",            // "single" | "council" | "debate"
  "participants": [             // 2 to 5 LLM endpoints
    { "id": "claude", "auth": "cli" },
    { "id": "codex",  "auth": "cli" },
    { "id": "gemini", "auth": "cli" }
  ],
  "rounds": 4,                  // 2..=10
  "agreement_threshold": 0.66,  // 2-of-3, 3-of-5 etc.
  "early_stop_on_consensus": true,
  "share_session": true,        // each model sees prior round responses
  "shipping_action": "ask"      // "ask" | "auto-apply" | "none"
}
```

### Wire-Protocol (intern)

```
Round 1:
  - Send identical artifact + task to all participants
  - Collect N answers in parallel
  - Score: similarity matrix (cosine of response embeddings)
  - If agreement_score >= threshold AND early_stop → return consensus

Round 2..N:
  - For each participant: assemble prompt
      = original task
      + "Prior round responses from peers: <peer_outputs>"
      + "Your prior response: <self_output>"
      + "Identify disagreements, refine your answer or hold position with reason"
  - Collect new responses in parallel
  - Re-score, early-stop check

Final:
  - Synthesize: pick majority-vote OR most-elaborated OR ranked
  - Return: consensus_answer, all_round_transcripts, dissent_log, scores
```

### Modi

| Mode | Beschreibung | Default Rounds |
|------|-------------|----------------|
| `single` | Standard: 1 LLM, 1 Antwort. | 1 |
| `council` | N LLMs, parallele Antworten, kein Cross-Talk, Voting. | 1 |
| `debate` | N LLMs sehen jeweils Peer-Antworten, refinen über mehrere Runden. | 3 |
| `adversarial` | 1 Doer + (N-1) Reviewer, optional ship-after-quorum. | 2 |
| `chain` | Sequential: LLM₁ → LLM₂ → LLM₃, each builds on prior. | 3 |

### Default-Trigger (automatic council)

```toml
[council]
enabled = true
auto_trigger_on = [
  "architecture",       # keywords in task
  "security",
  "refactor",
  "destructive",
]
auto_min_complexity_tokens = 800   # task description length
default_mode = "debate"
default_rounds = 3
default_participants = ["claude", "codex", "gemini"]
```

User kann pro Request override-en:
- CLI: `agenterctl ask --council=debate --rounds=5 --participants=claude,codex,gemini ...`
- HTTP: explicit body fields
- Toggle global: `agenterctl council disable`

### Persistierung

Jede Council-Runde emittiert WAL-Events:
- `0x22 COUNCIL_ROUND` — round_id, mode, participants, scores
- `0x23 COUNCIL_VERDICT` — final consensus, dissent_log

→ Audit Trail. Future-Self kann sehen welche Council-Beratungen wie endeten.

### Cost-Tracking

```rust
pub struct CouncilCost {
    pub tokens_in: HashMap<ParticipantId, u32>,
    pub tokens_out: HashMap<ParticipantId, u32>,
    pub usd_estimated: f32,
    pub wall_clock_ms: u32,
}
```

In Metric-Snapshot-Event 0x21 enthalten. CLI: `agenterctl metrics council --since 24h`.

---

## 3. Context-Split: Tools getrennt von Text (Token-Effizienz)

### Problem

Aktuelle LLM-APIs (Anthropic/OpenAI/Google) erlauben Prompt-Caching auf bestimmten Block-Boundaries. Wenn Tools + System-Prompt + Memory-Recall + User-Message in **einem** Block landen, müssen Tools bei jedem Request re-tokenized werden, obwohl sie identisch sind. Standard-OpenClaw/Jarvis: 5-15k Tokens Tools pro Request × 100 Requests/Tag = 1.5M Tokens vermeidbar.

### Lösung: Block-Layer-Aware Assembly

Context-Engine baut Request als geschichtetes Multi-Block-Payload:

```
┌──────────────────────────────────────────────────────────┐
│ Block A — TOOL DEFINITIONS (stable, cached)              │
│ - Schema-only JSON of all registered tools               │
│ - SHA-256 hash for cache-key                             │
│ - "cache_control": {"type": "ephemeral"} (Anthropic)     │
│ - Refreshed only when tool list changes                  │
├──────────────────────────────────────────────────────────┤
│ Block B — SYSTEM PROMPT (stable per persona, cached)     │
│ - SOUL.md + AGENTS.md core behavior                      │
│ - cache_control                                          │
├──────────────────────────────────────────────────────────┤
│ Block C — STABLE MEMORY RECALL (cached, ttl 5min)        │
│ - Top-k from Hippocampus-Core (high-importance, stable)  │
│ - cache_control                                          │
├──────────────────────────────────────────────────────────┤
│ Block D — VOLATILE MEMORY RECALL (no cache)              │
│ - Session-local goals, recent events, current trajectory │
├──────────────────────────────────────────────────────────┤
│ Block E — USER MESSAGE (no cache)                        │
└──────────────────────────────────────────────────────────┘
```

### Token-Savings (geschätzt)

Bei typischem Jarvis-Request:
- Tools: 8k tokens, repeated → cached saves ~95% (refunded as cache-hit-tokens, charged 0.1x)
- System: 3k tokens, cached, same savings
- Stable Recall: 2k tokens, cached
- Volatile Recall: 800 tokens, fresh
- User Msg: 200 tokens, fresh

Bei 1000 Requests/Tag:
- **Ohne Split:** 14k × 1000 = 14M tokens
- **Mit Split:** Block A+B+C 1× → 13k tokens + 1000 × cached-hit 1.3k + 1000 × fresh-1k = ~3.3M effektiv-billable
- **Ersparnis: ~75% Token-Cost.**

### Implementation in agenterd

```rust
pub struct AssembledRequest {
    pub blocks: Vec<Block>,
}
pub struct Block {
    pub kind: BlockKind,         // Tools | System | StableRecall | VolatileRecall | User
    pub content: String,
    pub cache_key: Option<Sha256>,
    pub cache_ttl: Option<Duration>,
    pub provider_hints: ProviderHints, // cache_control flags per provider
}

impl ContextEngine {
    pub fn assemble(&self, query: &Query, session: &Session) -> AssembledRequest {
        // 1. Stable blocks built once, hash-keyed
        // 2. Volatile blocks built per-request
        // 3. Provider-specific hints applied at serialize time
    }
}
```

### Provider-spezifische Cache-Markers

| Provider | Cache-Pattern | Wir setzen |
|----------|---------------|-----------|
| Anthropic Claude | `cache_control: {type: "ephemeral"}` auf Block-Boundary | je auf A/B/C |
| OpenAI/Codex | automatisch nach 1024 token prefix-match | gleiche Reihenfolge garantieren (A→B→C deterministisch) |
| Google Gemini | implicit prefix-cache, Cache-IDs | wir geben Block-Hashes als optional cache_ids |
| Local Qwen/Llama | prompt-cache server-side wenn vLLM/llama.cpp | gleiche Block-Reihenfolge |

---

## 4. CLI-OAuth Standard (Claude Code, Codex CLI, Gemini CLI)

### Default-Auth-Quelle: lokale CLIs

User authentifiziert sich 1× via `claude login`, `codex login`, `gemini auth`. AGENTER nutzt deren persistierte Tokens:

| CLI | Token-Storage | Wie wir lesen |
|-----|---------------|---------------|
| Claude Code | `~/.claude/.credentials.json` (anthropic-auth-cli format) | parse JSON, refresh on 401 |
| Codex (`@openai/codex`) | `~/.codex/auth.json` | parse JSON, refresh via OpenAI OAuth refresh-token |
| Gemini CLI (`@google/gemini-cli`) | `~/.config/gcloud/application_default_credentials.json` oder `~/.gemini/auth.json` | gcloud ADC or OAuth flow |

### Auth-Profil-Resolver

```rust
pub enum AuthMode {
    Cli { cli: CliVendor },           // default
    Api { env_var: String },          // fallback
    OAuthInteractive,                 // first-time setup
}

pub struct Provider {
    pub id: String,                   // "claude" | "codex" | "gemini" | ...
    pub auth: AuthMode,
    pub fallback: Vec<AuthMode>,      // tries in order
}
```

Default-Config `~/.agenter/providers.toml`:

```toml
[[provider]]
id = "claude"
auth.mode = "cli"
auth.cli = "claude-code"   # reads ~/.claude/.credentials.json
fallback.mode = "api"
fallback.env_var = "ANTHROPIC_API_KEY"

[[provider]]
id = "codex"
auth.mode = "cli"
auth.cli = "codex"
fallback.mode = "api"
fallback.env_var = "OPENAI_API_KEY"

[[provider]]
id = "gemini"
auth.mode = "cli"
auth.cli = "gemini-cli"
fallback.mode = "api"
fallback.env_var = "GOOGLE_API_KEY"

[[provider]]
id = "qwen-local"
auth.mode = "none"
endpoint = "http://localhost:8080/v1"
```

### Token-Refresh

Bei 401-Response:
1. Re-read CLI token file (User hat ggf. in der CLI re-authed).
2. Wenn unverändert → trigger CLI refresh-token-flow per `claude refresh` / equivalent.
3. Bei wiederholtem Fail → fallback auf API-Mode.
4. Bei API-Mode fail → fallback auf nächsten Provider in der Cascade.

### Security: keine Token-Persistierung in agenterd

Tokens werden **nur in-memory** gehalten, jeder Request liest CLI-File neu (zero-trust). Bei OAuth-Vault (Layer 6) speichern wir nur **eigene** Tokens (z.B. Telegram-Bot-Token, GitHub-PAT der Tools nicht der LLM-Provider).

### CLI-Modus-Vorteile

| Vorteil | Begründung |
|---------|-----------|
| Keine API-Key-Verwaltung | User authenticated 1× pro CLI |
| Automatic Refresh | CLI handhabt Refresh-Token-Drehung |
| Same Quota Pool | Subscription-Pro-User-Quota statt API-Pay-as-go |
| Spend-Limit | CLI-Spend-Caps gelten automatisch |
| Audit | CLI-Logs zeigen genau welche Anfragen agenterd absetzte |

---

## 5. Provider-Cascade v2 (mit CLI-First-Auth)

```toml
[cascade]
# Primary path: cheapest+fastest first, escalate on refusal/error
chain = [
  { provider = "claude",      model = "claude-opus-4-7" },
  { provider = "codex",       model = "gpt-5.5" },
  { provider = "gemini",      model = "gemini-3.1-pro-preview" },
  { provider = "qwen-local",  model = "Qwen2.5-72B-Instruct-Q5_K_M" },
]
retry_on_refusal = true
retry_on_rate_limit = true
auto_council_for_critical = true   # see §2 auto_trigger_on
```

---

## 6. Update zur Sprach-Strategie

Bleibt **Rust** (Entscheidung aus v0.2). Tailslayer-rs ist Rust → passt nahtlos. C++ Tailslayer-Original behalten wir in `QUELLEN/tailslayer/` als Referenz für Algorithmus-Details (channel-scrambling Discovery-Tool), nicht als FFI.

**Falls Rust-Port v0.1 Bugs zeigt:** Fallback-Plan = C++ Tailslayer via `cxx` Crate FFI, oder eigene Reimplementation (~600 LOC, da Algorithmus jetzt bekannt aus Original-Header).

---

## 7. Komponenten-Schichtung v0.3 (Update auf §6 v0.2)

```
┌────────────────────────────────────────────────────────────────────────┐
│ CLI agenterctl │ REPL │ Telegram │ Inotify Watcher │ Council CLI       │
└─────────────────────────┬──────────────────────────────────────────────┘
                          │ UNIX-Sock + HTTP
┌─────────────────────────┴──────────────────────────────────────────────┐
│                      agenterd (Rust)                                   │
│ ┌────────────────────────────────────────────────────────────────────┐ │
│ │ Gateway (hyper) | Trajectory | Streaming (SSE)                     │ │
│ ├────────────────────────────────────────────────────────────────────┤ │
│ │ Council Engine  (modes: single|council|debate|adversarial|chain)   │ │
│ │  - Round Manager   (rounds 2..10, agreement threshold)             │ │
│ │  - Score Matrix    (cosine-of-responses)                           │ │
│ │  - Verdict Synth   (majority|elaboration-rank|user-pick)           │ │
│ ├────────────────────────────────────────────────────────────────────┤ │
│ │ Session / Goal / Compression Anchor / Memory Hook                  │ │
│ ├────────────────────────────────────────────────────────────────────┤ │
│ │ Context Engine — Block-Layer Assembly                              │ │
│ │  - Block A Tools     │ stable, cache_control                       │ │
│ │  - Block B System    │ stable, cache_control                       │ │
│ │  - Block C StableMem │ ttl 5min cache                              │ │
│ │  - Block D Volatile  │ no cache                                    │ │
│ │  - Block E User      │ no cache                                    │ │
│ │  + Query Planner + Budget Assembler                                │ │
│ ├────────────────────────────────────────────────────────────────────┤ │
│ │ Memory Engine v2 (WAL + Views + Dreaming)                          │ │
│ │  - WAL writer with CRC32c                                          │ │
│ │  - 13 Views (mmap + Tailslayer for vectors.bin)                    │ │
│ │  - Dreaming Pipeline                                               │ │
│ ├────────────────────────────────────────────────────────────────────┤ │
│ │ Vector Store ─── Tailslayer ReplicatedBuffer<f32; DIM>             │ │
│ │  Backend: tailslayer | mmap (fallback)                             │ │
│ │  Hugepages: 1GiB or 2MiB                                           │ │
│ │  Worker pinning: dedicated cores                                   │ │
│ ├────────────────────────────────────────────────────────────────────┤ │
│ │ Embedding (candle Qwen3-0.6B-Q8)                                   │ │
│ │ Crypto (ring) | TLS (rustls) | HTTP (hyper) | JSON (sonic-rs)      │ │
│ ├────────────────────────────────────────────────────────────────────┤ │
│ │ Provider Cascade (CLI-OAuth First)                                 │ │
│ │  Auth resolver: cli > api > oauth-interactive                      │ │
│ │  Refresh: claude refresh, codex refresh, gemini auth refresh       │ │
│ ├────────────────────────────────────────────────────────────────────┤ │
│ │ Tool Router │ OAuth Vault (own tokens, not LLM provider tokens)    │ │
│ ├────────────────────────────────────────────────────────────────────┤ │
│ │ Channels (Phase 1: Telegram)                                       │ │
│ ├────────────────────────────────────────────────────────────────────┤ │
│ │ tokio-uring (Linux) | tokio-IOCP (Win) | tokio-kqueue (Mac)        │ │
│ └────────────────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────────┘
```

## 8. Update auf Phase-1 Reihenfolge (v0.2 §13 ergänzt)

| Tag | Neu/Update |
|-----|-----------|
| 14-17 | **Block-Layer-Context-Engine** zuerst (war §22-26 in v0.2 generic) — wichtig für Token-Effizienz ab Tag 1 |
| 18-21 | IVF-Vector-Index unverändert |
| 22-25 | **Tailslayer-Backend für vectors.bin** mit feature-flag (parallel zu mmap-fallback) |
| 26-30 | Context-Engine + Query-Planner |
| 36-40 | **CLI-OAuth-Auth-Resolver** zuerst (war Provider §36-40) — vor Cascade-Logic |
| 41-44 | Council-Engine MVP (mode=single+council, 1-3 rounds) |
| 45-48 | Council-Engine v2 (mode=debate+adversarial+chain, 2-10 rounds) |
| 49-53 | Telegram-Channel + Dreaming-Pipeline parallel |
| 54-57 | Shadow-Run + Eval-Parity |
| 58-60 | Cutover |

## 9. Erfolgs-Metriken v0.3 (mit Tailslayer)

| Metrik | v0.2 Target | v0.3 Target | Begründung |
|--------|------------|------------|-----------|
| Recall p50 (1M corpus) | < 8 ms | < 8 ms | unchanged |
| Recall p95 | < 25 ms | < 15 ms | Tailslayer reduziert p95-Spikes |
| Recall p99 | n/a | < 25 ms | Tailslayer killt DRAM-Refresh-Spikes |
| Token-Cost-Effizienz | n/a | **-70% vs Jarvis heute** | Context-Split + Cache-Control |
| Council 3-LLM 3-round | n/a | < 12 s wall-clock | parallele provider calls |
| Idle-RSS (no model loaded) | 42 MB | **75 MB** | +Tailslayer-Worker-Threads + Council-State |
| Active-RSS (model+vectors+tailslayer) | 580 MB | **~16 GB** | wenn Tailslayer 1 GiB Pages × N Replicas (großer Sprung — Trade-Off bewusst) |
| Active-RSS (model+vectors+mmap fallback) | 580 MB | 580 MB | unchanged |

**Wichtig:** Tailslayer-Mode opfert RSS für Latency-Determinismus. Default-Profile:
- `default`: mmap-Backend, low-RAM
- `low-latency`: Tailslayer 2-replica × 2 MiB Pages (~4 GB) für Workstations mit ≥16 GB RAM
- `hft`: Tailslayer 4-replica × 1 GiB Pages (~16 GB) für Server mit ≥32 GB RAM

User kann pro Deployment wählen via `~/.agenter/config.toml`.

## 10. Sicherheits-Update

Council-Mode hat eigene Risiken:
- **Prompt-Leak zwischen Providern:** Block-D + Block-E werden an N Provider geschickt → wenn ein Provider unbedacht logged, leaked alles. → **Provider-Trust-Tier System**: nur Tier-1-Providers in Council ohne Volatile-Memory.
- **Cost-Runaway:** 5 Provider × 10 Runden × 14k Tokens = brutal teuer. → Per-Council-Hard-Cap (`max_usd_per_council = 0.50`).
- **Adversarial Disagreement Loop:** wenn LLMs nicht konvergieren bis Round 10. → `max_rounds_no_convergence_abort = 5`.
- **Tool-Definition-Leak via Cache-Hash:** Block-A hash gleich überall → kein Risk (deterministisch).

## 11. Sources jetzt im QUELLEN/

```
QUELLEN/
├── openclaw/          (17,433 files, steipete upstream)
├── hermes-webui/      (Python WebUI for Hermes Agent)
├── openhuman/         (Tauri Desktop AI)
├── tailslayer/        (C++ DRAM tail-latency, LaurieWired)
└── tailslayer-rs/     (Rust port, OctopusTakopi v0.1)
```

## 12. Verbleibende offene Fragen Phase-1

Aus v0.2 übernommen (Embedding-Model, HNSW vs IVF, channel-Prio Telegram-only, CPU vs GPU, Goldset-Größe, MUSL vs glibc). Plus neu:

7. **Tailslayer Default an oder aus?** Wenn an: braucht jeder User Hugepages. Wenn aus: opt-in via Flag.
8. **Council-Default-Trigger:** Welche Keywords/Komplexitätsmaß triggert auto-council? Conservative (rare) vs aggressive (frequent)?
9. **CLI-OAuth Refresh-Strategy:** wenn CLI nicht installiert ist → silent fail oder interactive prompt?
10. **Block-Cache-TTL-Defaults:** wie aggressiv flushen wenn Memory-Layer-Update kommt? 5 min vs auf-Tombstone-Event-Bus?
