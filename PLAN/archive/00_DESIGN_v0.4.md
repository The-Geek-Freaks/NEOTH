# AGENTER — Design v0.4 (Framework v4.1 "Pflegbarer Garten" + Hirn-Anatomie)

> **Foundation:** `tool_framework_v4_1.md` (3 Schichten, 5 Zutaten, GoL-Pattern, Via-Negativa-Kern).
> **Architektur-Metapher:** menschliches Hirn. Zwei Hemisphären-LLMs + Corpus-Callosum-LLM, 12 Memory-Layer als anatomische Regionen.
> **Locked-In Entscheidungen (User 2026-05-12):**
> - Sprache: Rust core + ASM-Kernels via FFI
> - Tailslayer: **default ON** (Profile `low-latency`, 2 MiB Hugepages)
> - Embedding: **Qwen3-Embedding-0.6B-Q8.gguf** (1024d), llama.cpp via candle
> - Multi-LLM Council: native, toggleable, 2–10 Runden
> - Context-Split: 5 Block-Layer, cache-aware
> - Auth: CLI-OAuth first (Claude Code / Codex CLI / Gemini CLI), API-Key fallback

---

## 1. Framework v4.1 als Grundlage

### 1.1 Die drei Schichten (übertragen auf AGENTER)

| Schicht | Framework | AGENTER-Mapping |
|---------|-----------|-----------------|
| **Schicht 0 — Tool** (Micro, stateless, deterministic, Sekunden) | Einzelne Werkzeug-Aufrufe | Tool-Router-Aufrufe: telegram.send, vault.read, embed.encode, http.fetch, oauth.refresh. Jeder ist ein `tools/<name>.yaml` Spec + Rust-Impl. |
| **Schicht 1 — Pipeline** (Meso, deklarativ, Minuten) | Orchestrierte Multi-Tool-Flows | `pipelines/<name>.yaml`: Recall-Pipeline, Dreaming-Pipeline, Council-Pipeline, Embed-Pipeline, Vault-Sync-Pipeline. Mit Budget-Constraint (Token-Limit, Time-Limit, USD-Cap). |
| **Schicht 2 — Ecology** (Macro, observing, mit Memory, Wochen) | Beobachtung über Wochen | Memory-Drift-Detection, Tool-Genealogie, Importance-Decay-Histogramme, Council-Outcome-Tracking. **Nicht-Teil von Phase 1** (gemäß Framework v4.1 Build-Plan-Korrektur). |

### 1.2 Die 5 Zutaten (GoL-Konformität)

| Zutat | Wo in AGENTER |
|-------|---------------|
| **Variation** | Tool-Populations (jedes Tool hat ≥2 Varianten), Council-Modi, Provider-Cascade |
| **Constraints** | WAL-Schema-CRC, Tool-Locality-Enforcement, Pipeline-Budget, Top-down-Constraints aus SOUL.md |
| **Memory** | WAL `events.bin` + 13 Views (Schicht 2 in Wochen-Skala) |
| **Selektion** | Importance-Decay-Tick, Hippocampus-Threshold, Provider-Score, Council-Agreement |
| **Laufzeit** | drei Zeit-Skalen parallel: Tool (Sekunden), Pipeline (Minuten), Ecology (Wochen) |

### 1.3 Hard-to-Vary-Kern (übernommen aus F.8)

Was AGENTER niemals aufgibt, egal wie sich Implementation ändert:

1. **Ein WAL als Wahrheit.** Alle Views aus L1 reproduzierbar.
2. **Tools sind stateless + deterministic** (Schicht 0).
3. **Pipelines deklarativ + budget-bound** (Schicht 1).
4. **Linke Hemisphäre = einziger Output-Channel zum User.**
5. **Refusal-Handling = Mirror-Pattern, kein Transform** (Framework v4.1 Fix 1).
6. **Schicht-Disziplin:** Tools verhalten sich wie Tools, Pipelines wie Pipelines.
7. **CRC32c + Magic + Schema-Version** in jedem WAL-Frame.
8. **Konzept-First > Spec-First** (Framework H.1).

### 1.4 Anti-Patterns aus Framework v4.1 die AGENTER verbietet

Direkt aus Teil G übernommen:

- G.1 Stateful Tool → AGENTER-Tool darf keinen Zustand zwischen Calls halten (alles → WAL)
- G.2 Self-Modifying Tool → kein Tool darf eigene YAML editieren
- G.3 Goal-Seeking Tool → Goals sind Pipeline-Schicht-Konzept (Goal-Stack)
- G.4 Meta-Decision-Making Tool → Tools entscheiden nicht ob/wann sie laufen — Pipeline tut das
- G.5 Emergente Tool-Komposition → keine "Magic-Composition", alles explizit in Pipeline-YAML
- G.6 Refusal-Umgehung → wenn LLM refused: Mirror, nicht Transform, nicht Bypass
- G.7 Scope-Inflation im Tool → ein Tool = eine Verantwortung
- G.8 Starke Emergenz im Tool → Tool-Output ist immer beweisbar aus Input + Code
- G.9 Black-Box ohne Introspection → jeder Tool muss `introspect()` haben
- G.10 Magic Scale Assumption → kein "wenn wir genug X haben…"
- G.11 Closed-Loop Ecology → Schicht 2 darf nicht Schicht 0/1 direkt mutieren
- G.12 Level-Confusion → Tool ≠ Pipeline ≠ Ecology, keine Vermischung
- G.13 Bateson-III-Claims → AGENTER reklamiert keine autonome Identitäts-Reorganisation

---

## 2. Hirn-Anatomie-Metapher

### 2.1 Drei-LLM-Topologie

```
                  ┌──────────────────────────────┐
                  │   USER (Stimme / Telegram /  │
                  │   WhatsApp / CLI / Web)      │
                  └──────────────┬───────────────┘
                                 │ Input: roh
                                 ▼
        ┌────────────────────────────────────────────────┐
        │   THALAMUS  (Sensory Relay = Context-Engine)   │
        │   • Block-Layer Assembly                        │
        │   • Query Planner                               │
        │   • Token-Budget Cut                            │
        └────────────────┬───────────────┬───────────────┘
                         │               │
       ┌─────────────────▼─────┐  ┌──────▼──────────────────────┐
       │ RIGHT HEMISPHERE LLM  │  │ LEFT HEMISPHERE LLM         │
       │ holistic / spatial /  │  │ linguistic / sequential /   │
       │ pattern-match /       │  │ logical / code /            │
       │ novelty / gestalt /   │  │ tool-precision /            │
       │ associations          │  │ produces final user output  │
       │                       │  │                             │
       │ CANNOT speak to user  │  │ ONLY voice to outside world │
       │ Provider: Gemini      │  │ Provider: Claude            │
       │ default 3.1 Pro       │  │ default Opus-4.7            │
       └──────────┬────────────┘  └──────────────▲──────────────┘
                  │                              │
                  │  inter-hemispheric channel   │
                  │  (no user-visible egress)    │
                  ▼                              │
       ┌──────────────────────────────────────────────────┐
       │  CORPUS CALLOSUM LLM                             │
       │  • translates right→left                         │
       │  • surfaces dissent, conflict, gestalt           │
       │  • synthesises both hemispheres                  │
       │  • can request more rounds                       │
       │  Provider: Codex GPT-5.5 (default)               │
       │  NEVER speaks to user                            │
       └──────────────────────────────────────────────────┘
```

### 2.2 Why this split (Begründung)

- **Linke Hemisphäre = Output-Monopol.** Im Hirn ist Broca/Wernicke meist links → Sprache. Beim System: nur ein definierter Output-Pfad → keine widersprüchlichen User-Antworten.
- **Rechte Hemisphäre = paralleles Mustererkennen.** Sieht Anomalien, semantische Verbindungen, "das fühlt sich falsch an"-Signale. Liefert ihre Erkenntnisse als strukturierte Daten an Corpus Callosum, NIE als finalen Text.
- **Corpus Callosum = Konflikt-Übersetzung.** Wenn Hemisphären-Outputs divergieren, synthetisiert oder fordert weitere Runden an. Triggert Council bei strukturellem Disagreement.
- **Provider-Wahl per Default** ist Hypothese:
  - Claude Opus 4.7 → links (best language production, sequence-precision)
  - Gemini 3.1 Pro → rechts (long-context pattern-search, multimodal)
  - Codex GPT-5.5 → mitte (code-precision, structural reasoning)
- **Override**: in `~/.agenter/brain.toml` swappable.

### 2.3 Brain-Region → Memory-Layer Mapping

13 Sichten auf 1 WAL, jede als anatomische Region typisiert. Macht jeder Sicht ihre Funktion klar:

| Region | View | Funktion biologisch | Funktion AGENTER |
|--------|------|---------------------|------------------|
| **Hippocampus** | `idx_episodic` (time-sorted) | episodic memory, neue Erinnerungen | Session-Transcripts, Daily Notes |
| **Cortex (sensory/association)** | `idx_semantic` (FTS + concepts) | semantic memory, konsolidierte Fakten | konsolidierte Synthesis-Events nach Dreaming |
| **Amygdala** | `idx_importance` (importance heap, decay-aware) | emotional valence gating | importance-scoring, "wichtig vs nebensächlich" |
| **Basal Ganglia** | `idx_habit` (tool-invocation-frequency) | habit / action selection | tool-router cache, am häufigsten benutzte tools-first |
| **Cerebellum** | `idx_motor` (provider-call-stats, retry-pattern) | fine motor control, calibration | Provider-Cascade-Stats, Retry-Pattern-Lernen |
| **Thalamus** | Context-Engine (kein File, runtime) | sensory relay, gating | Block-Layer-Assembly + Query-Planner |
| **Prefrontal Cortex** | `idx_goal` (Goal-Stack per Session) | executive function, planning | Goal-LIFO, Compression-Anchor |
| **Mirror Neurons** | refusal-handler (kein File, runtime) | imitation, empathy | Mirror-Pattern aus Framework E.2 |
| **Default Mode Network** | Dreaming-Pipeline | self-reflection during rest | Memory-Consolidation alle 2h |
| **Brain Stem** | daemon-lifecycle | vital functions | health-check, restart, watchdog |
| **Mediotemporal Lobe** | `idx_source` (source-uri-hash → events) | declarative provenance | "wo kommt diese Info her" |
| **Insula** | `idx_council` (council-rounds) | interoception, self-vs-other | Multi-LLM-Council-State |
| **Pineal/Suprachiasmatic** | scheduler (kein File) | circadian | Cron-internal, dreaming-trigger, decay-tick |

### 2.4 WAL-Event-Types mit Hirn-Mapping

Erweitere v0.3 Event-Types um Brain-Region-Tag:

```rust
pub struct EventHeader {
    // ... v0.3 fields ...
    pub brain_region: u8,  // see BrainRegion enum
    pub hemisphere: u8,    // 0=N/A, 1=LEFT, 2=RIGHT, 3=CORPUS_CALLOSUM, 4=BOTH
}

pub enum BrainRegion {
    Hippocampus = 1,     // episodic
    Cortex = 2,          // semantic
    Amygdala = 3,        // importance
    BasalGanglia = 4,    // habit
    Cerebellum = 5,      // motor/provider
    Thalamus = 6,        // gating
    PrefrontalCortex = 7,// goal
    MirrorNeurons = 8,   // refusal
    DefaultMode = 9,     // dreaming
    BrainStem = 10,      // lifecycle
    MedialTemporal = 11, // provenance
    Insula = 12,         // council
    Pineal = 13,         // scheduler
}
```

---

## 3. Tool-Schicht — YAML-Format (Framework Teil B übernommen)

Jedes Tool = ein File `tools/<name>.yaml` (+ Rust-Implementation in `src/tools/<name>.rs`).

```yaml
# tools/telegram_send/standard.yaml
name: telegram.send
version: 1.0.0
population_default: true
description: Send a message to a Telegram chat
schicht: 0   # MUST be 0

inputs:
  chat_id: { type: i64, required: true }
  text: { type: string, max_len: 4096, required: true }
  parse_mode: { type: enum, values: [markdown, html, plain], default: markdown }

outputs:
  message_id: { type: i64 }
  success: { type: bool }

cost:
  category: network
  estimated_ms: 200
  estimated_usd: 0.0
  rate_limit: 30/sec

constraints:
  locality: io_external
  side_effects: yes  # sends to outside world
  network: yes
  filesystem: no
  refusal_handling:
    mode: mirror   # NEVER transform — Framework Fix 1

introspection:
  call_count: yes
  last_invoked: yes
  error_history: yes

brain_metadata:
  invoked_by: [left_hemisphere]  # only left can call send-tools
  invoked_during: [user_response, daily_briefing]
```

Tool-Populations (Framework B.6): jedes Tool hat ≥ 2 Varianten z.B. `telegram_send/standard.yaml` + `telegram_send/silent.yaml` (no notification) + `telegram_send/markdown_strict.yaml`.

---

## 4. Pipeline-Schicht — YAML-Format (Framework Teil C übernommen)

```yaml
# pipelines/respond_to_user.yaml
name: respond_to_user
version: 1.0.0
schicht: 1

trigger:
  - telegram.message_received
  - whatsapp.message_received
  - cli.user_input

budget:
  tokens_max: 12000
  time_max_ms: 8000
  usd_max: 0.05

execution_model: sequential_with_fanout

steps:
  - id: thalamus_assemble
    pipeline: context_engine.assemble_blocks
    schicht: 1
  
  - id: right_hemisphere_analysis
    fanout:
      - llm: gemini-3.1-pro
        role: right_hemisphere
        prompt_template: "see_patterns.tmpl"
    schicht: 1
  
  - id: left_hemisphere_generate
    llm: claude-opus-4-7
    role: left_hemisphere
    inputs:
      - thalamus_assemble.blocks
      - right_hemisphere_analysis.patterns
    schicht: 1
  
  - id: corpus_callosum_check
    llm: gpt-5.5
    role: corpus_callosum
    inputs:
      - left_hemisphere_generate.draft
      - right_hemisphere_analysis.patterns
    if_dissent_score > 0.4:
      trigger: pipelines/council_debate.yaml
    schicht: 1
  
  - id: emit_response
    tool: telegram.send
    inputs:
      text: left_hemisphere_generate.final
    schicht: 0  # call to Tool-Schicht

failure_handling:
  on_step_failure: continue_with_degraded
  on_budget_exceeded: emit_partial
  on_refusal: pipelines/mirror_refusal.yaml
```

---

## 5. Council-Pipeline (Multi-LLM Debate auf Pipeline-Schicht)

```yaml
# pipelines/council_debate.yaml
name: council_debate
version: 1.0.0
schicht: 1

triggers:
  manual_invocation: true
  auto_trigger_keywords: [architecture, security, refactor, destructive, breaking]
  auto_trigger_complexity_tokens: 800
  dissent_score_threshold: 0.4  # from corpus_callosum

budget:
  rounds_min: 2
  rounds_max: 10
  rounds_default: 3
  agreement_threshold: 0.66
  early_stop_on_consensus: true
  usd_max: 0.50
  time_max_ms: 60000

participants:
  - id: left
    llm: claude-opus-4-7
    auth: cli
  - id: right
    llm: gemini-3.1-pro
    auth: cli
  - id: callosum
    llm: gpt-5.5
    auth: cli

execution_model: parallel_per_round

steps:
  - id: round_1_parallel
    fanout_to_participants: true
    prompt: "task + artifact"
  
  - id: score_round_1
    tool: council.score_responses
    method: cosine_of_response_embeddings
  
  - id: rounds_2_to_N
    loop_while: agreement_score < threshold AND round < rounds_max
    fanout_to_participants: true
    prompt: "task + artifact + prior_round_responses + 'identify disagreements'"
  
  - id: verdict_synthesis
    tool: council.synthesize
    method: majority_vote_or_elaboration_rank
  
  - id: persist
    tool: wal.emit_event
    event_type: COUNCIL_VERDICT
    brain_region: insula
```

---

## 6. Hard-Locked v0.4 Defaults

| Komponente | Wert | Quelle |
|-----------|------|--------|
| Sprache | Rust edition 2024 (MSRV 1.86) | v0.2 User-Pick |
| Tailslayer | **default ON, low-latency profile (2 MiB Hugepages)** | v0.4 User-Pick |
| Embedding-Modell | **Qwen3-Embedding-0.6B-Q8.gguf, 1024d** | v0.4 User-Pick |
| Embedding-Runtime | candle (Rust) mit GGUF-Loader | v0.3 |
| TLS | rustls 0.23+ | v0.2 Chorus |
| Crypto | ring (AES-GCM, SHA-256, ChaCha20) | v0.2 Chorus |
| HTTP | hyper async tokio | v0.2 |
| JSON | sonic-rs (SIMD) | v0.2 |
| WAL | own format, CRC32c framed | v0.2 |
| Vector Backend | tailslayer-rs ReplicatedBuffer (Hugepages 2 MiB × 2 Replicas) | v0.4 default |
| Council | native, 3 LLMs, 2-10 rounds | v0.3 User-Pick |
| LLM-Auth | CLI-First (claude-code / codex / gemini-cli), API fallback | v0.3 User-Pick |
| Context-Split | 5 Block-Layer (Tools/System/StableMem/Volatile/User), cache_control | v0.3 User-Pick |
| Provider Cascade | claude → gpt-5.5 → gemini → qwen-local | v0.3 |
| Tool-Format | YAML-Spec + Rust-Impl (Framework B.5) | v0.4 |
| Pipeline-Format | YAML deklarativ (Framework C.1) | v0.4 |
| Brain-Topology | Left/Right/Callosum, Left = einziger Output-Channel | v0.4 User-Pick |
| Brain-Region-Tag | jedes WAL-Event hat `brain_region` + `hemisphere` u8 | v0.4 |
| Ecology-Schicht | **nicht-Teil von Phase 1** | Framework v4.1 Build-Plan-Fix |

---

## 7. Verbleibende offene Fragen v0.4

Aus v0.3 erledigt: Q1 Tailslayer-Default ✓, Q4 Embedding-Model ✓.

Noch offen:
- Q2 **Council-Auto-Trigger Keywords**: conservative (rare, only "architecture/security/destructive") vs aggressive (alle non-trivial Tasks)?
- Q3 **Block-Cache-TTL** bei Memory-Updates: feste 5 min vs Event-Bus-Flush on tombstone?
- Q5 **Hemisphere-Provider-Default** wirklich Claude=links, Gemini=rechts, Codex=callosum? Oder umkehrbar (Gemini hat das längste Context-Window — vielleicht passt es besser als rechts mit Pattern-Search; aber default).
- Q6 **Tool-YAML-Schema strict-vs-loose**: Framework v4.1 setzt YAML voraus — wollen wir TOML stattdessen (idiomatischer in Rust-Welt)? **Vorschlag: YAML beibehalten** weil Framework darauf baut und mehrzeilige Strings einfacher sind.
- Q7 **Refusal-Mirror-Implementation** konkret: was emittieren wir wenn ein LLM refused? Mirror-Pattern aus Framework E.2 — leg ich Konkret-Spec separat ab.
- Q8 **Ecology-Schicht später** — wann? Phase 4? Welche Trigger? Framework sagt "Phase 3 nach Phase 1-2 stabil".

---

## 8. Was kommt als nächstes

Reihenfolge in `01_LINUX_PHASE1_STEPS.md` muss revidiert werden (v0.4-Step-Plan):

1. **Phase 1.0 — Skeleton (Tag 1-2):** Rust workspace, framework-conform Tool-YAML-Loader, Pipeline-YAML-Loader, WAL v2 mit CRC32c.
2. **Phase 1.1 — Brain-Topology-Skeleton (Tag 3-5):** Provider-Resolver mit hemisphere-binding, 3 LLM-Adapters (Claude/Gemini/Codex CLI-OAuth-first).
3. **Phase 1.2 — Tools Population (Tag 6-10):** 10 essential tools (telegram.send, vault.read, vault.write, embed.encode, http.fetch, wal.emit, recall.query, council.invoke, oauth.refresh, schedule.cron) je in 2 Varianten.
4. **Phase 1.3 — Pipelines (Tag 11-14):** respond_to_user, council_debate, dreaming, vault_sync, mirror_refusal.
5. **Phase 1.4 — Memory Engine (Tag 15-19):** WAL + 13 Views + Tailslayer-vectors.
6. **Phase 1.5 — Embedding (Tag 20-22):** candle + Qwen3-0.6B-Q8 default-on.
7. **Phase 1.6 — Context-Engine (Tag 23-26):** Block-Layer assembly + Query-Planner.
8. **Phase 1.7 — Council Engine (Tag 27-30):** modes single/council/debate, rounds 2-10.
9. **Phase 1.8 — Channels (Tag 31-33):** Telegram only.
10. **Phase 1.9 — Migration + Eval (Tag 34-42):** Goldset extraction, shadow-import, parity check.
11. **Phase 1.10 — Shadow-Run + Cutover (Tag 43-55):** 14d shadow + switch.

Ecology-Schicht (Schicht 2) explizit auf **Phase 4** verschoben (gemäß Framework v4.1 Build-Plan).
