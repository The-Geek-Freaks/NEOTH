# LOST FEATURES — 1.0 RECOVERY (2026-07-18)

> **Zweck:** Features, die auf dem Weg zu 1.0 verloren gingen — geplant/entschieden/
> gewünscht, aber nie in den Master-Tracker überführt, still gedroppt, als
> "deferred" versenkt oder nur oberflächlich adoptiert. Operator-Auftrag 2026-07-18.
>
> **Methodik:** 6-Korpora-Archäologie (Early-Design, QUELLEN_ADOPT+Reevaluations
> R1–R7, alle SPECs, Wishlists/Handoffs/Archive, REVIEWS/_gold_audit+RECON,
> Root-Waisen/docs/plans) → 79 deduplizierte Kandidaten → adversarialer
> 4-Agenten-Verify gegen Code (SRC/neothd, SRC/neothd-gui) + Tracker
> (ROAD_TO_1_0_GOLD.md, GUI_TOP_TIER_PLAN.md). Nur bestätigte Verluste stehen
> unten; Killed-Archiv am Ende verhindert Wieder-Ausgraben.
>
> **Zähler:** 79 Kandidaten → 8 ALREADY_BUILT, 11 ALREADY_TRACKED,
> 3 REJECTED_STANDS, ~4 Duplikate → **53 bestätigte Verluste** (23 P1, 30 P2).
>
> **Tracking-Regel:** Jedes hier gelistete Item wandert als Checkbox in
> ROAD_TO_1_0_GOLD.md (Codex-Lane) bzw. GUI_TOP_TIER_PLAN.md (Design-Lane).
> Dieses Doc ist die Quelle, nicht der lebende Tracker.

---

## P1 — SOLLTE in 1.0 (bestätigt verloren, hoher Hebel)

### Sicherheit / Audit / WAL

- **ADR-009 INTENT/RESULT-WAL-Paare — 5 Effektklassen nie gebaut** `[CODEX]`
  Quelle: PLAN/ADR/009-intent-result-wal-audit-pairing.md. Versprochen:
  OsFileWriteIntent, ChannelEgressIntent, MediaCallIntent, SelfUpdateIntent,
  OsAppLaunchIntent als INTENT/RESULT-Paare. Beweis der Abwesenheit: 0 Treffer
  in wal/events.rs; GR-079 fixte nur die Band-Kollision, nie die Events.
  Integration: `wal/events.rs` ExtendedSubtype + Emit-Sites (File-Write,
  Channel-Egress, Media-Cloud, Self-Update, App-Launch).
- **Mirror-Refusal Stages 2–6** `[CODEX]`
  Quelle: PLAN/SPEC_mirror_refusal.md. Nur Schicht-0-Detection shipped
  (security/refusal_detect.rs:1, wal/events.rs:447 "v0.1.x ships the Schicht-0
  only"; chat.rs:10082 nennt Stages 2–6 explizit ausstehend). Integration:
  Schicht-0-Output als Stage-2-Input; neue `security/right_hemisphere.rs` +
  `callosum.rs`, Wiring in refusal_recovery.rs (dort steht wörtlich "no
  hemisphere switching here (that's R-04)").
- **Tool-Output-Redaction uniform in WAL-Coding-Frames** `[CODEX]` *(underresearched)*
  Quelle: PLAN/SMALLCODE_AUDIT_2026-05-21.md §5#4. dispatcher.rs:1252 wendet
  sanitize_tool_output an, aber recall/store.rs hat 0 Redact-Pässe und
  mcp/dispatch_loop.rs redigiert Tool-RESULTS nicht. Research: exakte
  Opcode-Pfade der CODING_TOOL_RESULT-Frames klären (payloads_w08.rs teilt nur 2 Treffer).
- **WAL-Replay-Fenster: HLC-Ordering statt naivem ±300s-Wall-Clock** `[CODEX]`
  Quelle: PLAN/CLAUDE_v07_review.md §11. cluster/wal_sync.rs:800
  `FOREIGN_EVENT_MAX_CLOCK_SKEW_SECS=300` ist Wall-Clock; wal::hlc::Hlc existiert,
  wird aber nur für Display genutzt. Research: HLC-Merge-Semantik für
  EventHeaderV2 (node_id+ts_ns) ohne Bruch bestehender WAL-Consumer.
- **Trust-Ledger als per-Decision Append-Only-Timeline** `[CODEX]`
  Quelle: PLAN/GREMIUM_EXECUTION_BACKLOG_2026-05-20.md#P3. trust.rs hat nur den
  globalen AutonomyLevel; kein TrustEvent/TrustLedger. Integration: neues
  `memory/trust_ledger.rs` + WAL-Event je Entscheidungsgrenze.

### Council / Recall / Inference

- **AgreementDimension-Enum fürs Council-Scoring** `[CODEX]`
  Quelle: PLAN/BLUEPRINT_v06_synthesis.md §8. Skalar-Similarity statt
  per-Dimension-Scoring (FactualClaims, RiskAssessment, …). Research:
  Gewichtungsformel je Dimension ist Spec-Lücke.
- **H7: Externer-Familien-Grader als Pflicht im Recall-Parity-Gate** `[CODEX]`
  Quelle: PLAN/00_DESIGN_v1.1_FINAL.md H-Fix H7. parity_run.rs rechnet Kappa
  über N Grader ohne Familien-Constraint. Integration: family_tag im
  Grader-Config + Gate auf Cross-Family-Präsenz.
- **Recall-Parity-Evaluations-Harness (Goldset-Mining + 4-Grader-Protokoll)** `[CODEX]`
  Quelle: PLAN/SPEC_recall_parity_methodology.md. Scoring-Backend existiert
  (goldset.rs), Orchestrierung fehlt komplett: Jarvis-WAL-Extraktion,
  Operator-Labeling, 4-Grader-Batch, Family-Bias-Clustering. Research: 4
  Subsysteme einzeln designen (~4–6 Wochen — ggf. 1.0-Scope-Entscheid nötig).
- **Ouro O-5c: QuantizedOuroLayer + QuantizedOuroModel Forward-Pass** `[CODEX]`
  Quelle: PLAN/SPEC_ouro_thinking_provider_2026-05-23.md. quantize.rs deferiert
  selbst auf O-5c; Q8-Inferenz end-to-end nicht funktional. Research: candle-API
  für quantisierten Forward-Pass gegen O-5b-Primitives prüfen.
- **C-16 Inner-Monologue-Audit (Streaming-CoT-Surface)** `[CODEX]`
  Quelle: PLAN/FEATURE_EVAL.md C#16. Kein show_thinking/stream-reasoning-Pfad
  in chat.rs/Providern. Integration: dispatch_provider-Streaming-Pfad.
- **C-6 Death of the Prompt (Proaktive Kontext-Vorbereitung)** `[CODEX]`
  Quelle: PLAN/FEATURE_EVAL.md C#6. Kein context_prefetch/PreloadContext.
  Integration: serve_pipeline Session-Start oder neuer `daemon/context_preloader.rs`.
- **ARS-3 Citation-Live-Lookup (Crossref/OpenAlex/SemanticScholar)** `[CODEX]`
  Quelle: PLAN/QUELLEN_ADOPT_academic_2026-05-21.md#3.2. citation_check ist
  offline-only (recall.rs:82). Research: Outbound-HTTP-Allowlist-Scope vorab klären.
- **C-17 Sub-200ms-Voice: Streaming-Capture-Loop** `[CODEX]` *(underresearched)*
  Quelle: PLAN/FEATURE_EVAL.md C#17. VAD-Basis shipped (media/vad/, Silero),
  aber kein Streaming-Capture-Loop ("feed_with_vad() deleted; re-derive when a
  live capture loop lands"). Research: Silero-ONNX compiled-in vs. Scaffold prüfen.

### Channels / Daemon

- **Proaktive Delivery jenseits Telegram** `[CODEX]`
  Quelle: proactive_dispatcher.rs:279/393/425 — alle Nicht-Telegram-Kanäle
  SidecarOnly, obwohl send_proactive-Stubs in discord.rs:268/line.rs:108
  existieren. Integration: plan_delivery()-Routing je Kanal.
- **WebChat als First-Class-Surface** `[CODEX]`
  Quelle: plans/001-openclaw-channel-migration-parity.md#channel-ledger.
  0 Treffer in channels/. Integration: neuer HTTP/WS-Adapter + Registry.
- **ChannelAccountId end-to-end (F-01)** `[CODEX]`
  Quelle: plans/001#gap-F-01. registry.rs:899 definiert den Typ, Kommentar
  "legacy single-account layout for now"; kein Threading durch InboundMessage.
- **Channel-Flapping-Doctor-Check misst Provider- statt Kanal-Rate** `[CODEX]` *(underresearched)*
  Quelle: PLAN/REEVALUATION R7#P1. doctor.rs:807 check_provider_flapping;
  per-Channel-Dimension in UsageEvent fehlt. Research: UsageEvent-Struct prüfen.
- **Wizard-IPC: echtes MPSC-Wire-up GUI↔Daemon** `[CODEX]`
  Quelle: plans/003#gap-SURF-01. wizard/ipc.rs:22 dokumentiert sich selbst als
  Stub ("lands when cli::serve opens the channel"); kein anderer Consumer.

### GUI / Operator-Sichtbarkeit

- **Local-LLM-Resource-Tab** `[EITHER]`
  Quelle: PLAN/v1_0_OPERATOR_WISHLIST_2026-05-24.md §X. Kein Ollama-Poll, kein
  Panel. Integration: Daemon-Poll + neues GUI-Panel (Resources-Tab-Erweiterung).
- **Sidebar Last-Message-Preview** `[CLAUDE-DESIGN]`
  Quelle: PLAN/GUI_BEAT_OPENHUMAN.md. chat.slint:1041 hardcodet `''`;
  panel_logic push_message-Pfad füllt nichts. Kleiner Fix, großer Alltagseffekt.
- **Per-Turn-Silence-Watchdog (120s, rearm-on-signal)** `[CLAUDE-DESIGN]`
  Quelle: PLAN/GUI_BEAT_OPENHUMAN.md. main.rs:2015 hat nur 2s-Read-Timeout.
  ~40 LOC im gui_stream-Loop.
- **Per-Hemisphere-Provider-Wizard-Step 5d** `[CLAUDE-DESIGN]`
  Quelle: PLAN/SPEC_hemisphere_provider_selection.md. CLI-Verben + Datenmodell
  komplett, Wizard-Step fehlt (steps_topology.rs:1094 ist Profile-Gate, kein
  Hemisphere-Picker). Integration: 3 Radio-Picker (left/right/cerebellum).

### Tracker-Hygiene (Meta, aber P1 — sonst versanden 65 Items erneut)

- **plans/001/002/003 verwaiste Done-Criteria → GOLD-Checkboxen** `[EITHER]`
  ~65 offene Work-Items (BUG-*, DX-*, SURF-*, DIRECTION-*, MIGRATION-*) sind in
  keinem Tracker; GOLD referenziert die drei Files nur als Links. Aktion:
  Items extrahieren, triagieren, als Checkboxen unter R4-01/04/05/06/07 einhängen.

---

## P2 — SOLLTE in 1.0 wenn Kapazität, sonst explizit 1.1 taggen

### Memory / Selbstorganisation
- **Dreaming 3-Phasen-Protokoll (Light/REM/Repair)** `[CODEX]` — CHERRY_PICK #1
  openclaw-Adopt; dreaming.rs hat keinen DreamPhase-Dispatch.
- **Hippocampus 0.75-Importance-Threshold-Cron** `[CODEX]` — Jarvis #1 Cherry-Pick;
  decay_task.rs + Importance-Feld fehlen.
- **Vault-Git-Commit-Nightly als WAL_MIRROR-Backup** `[CODEX]` — Jarvis #3.
- **Reflection-Hygiene komplett** `[CODEX]` — Retention ≤90d, Jaccard-Topic-Dedup,
  Yearly-Synthesis aus PeriodReflections, Topic-Synonym-Map (REFLECT_BACKLOG §A).
- **Self-Improve Proposal-Qualitäts-Schema** `[CODEX]` — quality_schema_version,
  eval_source, corpus_hash, regressions (REFLECT_BACKLOG §B; Proposal-Struct
  vorher lesen — dreaming_task.rs:339 hat nur status/skill/confidence).
- **C-13 Capability-Decay-Tracking** `[CODEX]` — Provider-Qualitätsmetrik.
- **EXP-FD-1..5 Fraktal-Dimension-Experimente** `[CODEX]` — dimension.rs:13 gated;
  Research: CoT-Depth-Klassifikation (Lit-Review nötig).
- **WAL-Header session_id universell genullt** `[CODEX]` — builder.rs:54;
  VIEW-01 stampte nur den 0x21-PAYLOAD. make_header + Emit-Sites threaden.

### Agents / Skills / Tools
- **C-2 Agent mit eigenen Zielen (Autonomous-Research-Loop)** `[CODEX]`
- **SP-H1 Session-Start-Skill-Registry-Injection** `[CODEX]`
- **CG-2/3/5 CodeGraph-Edges (ImportGraph, TypeHierarchy, BFS-API)** `[CODEX]` —
  CG-1 (CallGraph) existiert (code_map/graph.rs:125).
- **Per-Skill-Autonomie-Gradienten** `[CODEX]` — AutonomyLevel::Custom existiert,
  per-Skill-Override-Map nicht.
- **CloakBrowser Stealth-Web-Fetch-Plugin** `[CODEX]` — Research: playwright-rs
  vs. chromiumoxide für headless Win11.
- **Ralph-Retry (error-aware LLM-Retry-Tool)** `[CODEX]`
- **Role-Enforcement-Pipeline (Hemisphären)** `[CODEX]`
- **E-22 Skill-Hot-Reload Arc<SkillBody>-Pinning** `[CODEX]` — ArcSwap swappt
  zwischen Turns; Invocation-Pinning (Option 3) fehlt.
- **omniparser-Reopen-Entscheid** `[EITHER]` — DO_NOT_ADOPT.md:38 Reopen-Bedingung
  (PC-01/PC-02) ist seit GOLD:958/970 erfüllt, nie revisited. Decision-only:
  600MB-ONNX vs. Fresh-Win11-Filter neu bewerten, Verdict in DO_NOT_ADOPT
  aktualisieren. NICHT bauen ohne neuen Entscheid.

### Cluster / Infra
- **Per-Node-Skill-Assignment + Channel-Binding** `[CODEX]` — Veronica-Delta §6;
  Research: Routing-Table-Design im Cluster-Handshake.
- **Cluster-BudgetToken-Konsens (Raft, Phase 6)** `[CODEX]` — heute per-request-only.
- **n8n/Paperless-Installs gepinnt+verifiziert** `[CODEX]` — Version-Pin + sha256
  im Installer (heute nur Port-Stabilitäts-Tests).
- **neoth-archive-bridge Obsidian-Plugin** `[EITHER]` — externes TS-Projekt;
  NEOTH-Seite (obsidian.rs sync_archive) ist der Pairing-Punkt.
- **Per-Counterparty-Consent-Gate für Channel-Ingress-Clustering** `[CODEX]` —
  ADR-005; dreaming_task liest Episoden ohne Consent-Dimension.
- **ADR-003 dream.cron_enabled + Wizard-Nudge** `[CODEX]`
- **BGE-M3-Fallback-Embed-Model (Opt-in + GUI-Parity)** `[EITHER]` — ADR-004.
- **Voice-Call First-Class-Surface** `[CODEX]` — plans/001 Channel-Ledger.

### GUI-Polish (Design-Lane, klein)
- **Three-Phase-Streaming-Indicator** `[CLAUDE-DESIGN]` — StreamState-Enum + ~30 LOC.
- **Citation-Chips für Recall-Hits** `[CLAUDE-DESIGN]` — CitationChip-Komponente
  + WarmHit-Score-Feld.
- **C-18 Quality-Signal (non-star Per-Response-Feedback)** `[EITHER]` —
  GR-RESID-F35 war Recall-Link-Feedback, nicht Response-Qualität.
- **Live-TPS-Meter im Chat-Header (R-03)** `[CLAUDE-DESIGN]` — per-Message-Chip
  existiert; 1Hz-Rolling-Counter fehlt.

---

## Unvollständiges Research — Vertiefungsaufträge

1. **HLC-Merge-Semantik** (P1): Wie kodiert EventHeaderV2 node_id+ts_ns eine
   HLC-Komponente ohne WAL-Consumer-Bruch? → Design-Note vor Implementierung.
2. **Recall-Parity-Harness** (P1): 4 Subsysteme (Transcript-Extractor,
   Labeling-UI, Multi-Hemisphere-Batch, Bias-Clustering) je einzeln designen;
   Scope-Entscheid 1.0 vs. 1.1 nötig (~4–6 Wochen).
3. **Sub-200ms-Voice** (P1): Streaming-Capture-Architektur (cpal-Loop → VAD →
   Streaming-Whisper); prüfen ob Silero-Backend compiled-in ist.
4. **AgreementDimension-Gewichtung** (P1): Formel je Dimension ist Spec-Lücke.
5. **CoT-Depth-Klassifikation für EXP-FD-1** (P2): Lit-Review Reasoning-Depth-
   Estimatoren.
6. **CloakBrowser-Engine-Wahl** (P2): playwright-rs vs. chromiumoxide, Win11-headless.
7. **omniparser-Re-Evaluation** (P2): Decision-only, Verdict-Update.

---

## @Codex / ChatGPT Work — Zuweisung

> Kontext: Claude arbeitet die Design-Lane (GUI_TOP_TIER_PLAN.md). Die folgenden
> P1-Items sind Daemon-/Backend-Arbeit und passen in die GOLD-Rollup-Lane.
> Bitte als Checkboxen in ROAD_TO_1_0_GOLD.md aufnehmen (IDs frei wählbar):

1. **ADR-009 INTENT/RESULT-Paare** — 5 Effektklassen in wal/events.rs + Emit-Sites.
2. **Mirror-Refusal Stages 2–6** — right_hemisphere.rs + callosum.rs, Wiring in
   refusal_recovery.rs (SPEC_mirror_refusal.md ist die Spec).
3. **Tool-Output-Redaction** — recall/store.rs Redact-Pass + MCP-Result-Sanitize.
4. **HLC-Ordering wal_sync.rs:800** — Design-Note zuerst (siehe Research #1).
5. **Trust-Ledger** — memory/trust_ledger.rs + WAL-Event je Decision.
6. **Proactive-Delivery-Routing** — plan_delivery() auf existierende
   send_proactive-Stubs (discord.rs:268, line.rs:108) routen.
7. **ChannelAccountId end-to-end** — registry.rs:899 durch InboundMessage threaden.
8. **WebChat-Adapter** — HTTP/WS, Registry-Eintrag.
9. **Wizard-IPC-Wire-up** — cli/serve öffnet Channel, GUI connectet (SURF-01).
10. **Doctor per-Channel-Flapping** — UsageEvent um Channel-Dimension erweitern.
11. **Ouro O-5c** — QuantizedOuroModel Forward-Pass.
12. **C-6 Context-Preloader**, **C-16 CoT-Surface**, **ARS-3 Citation-Lookup**,
    **H7 Cross-Family-Grader**, **AgreementDimension** — je nach Kapazität.
13. **plans/001-003 → GOLD-Checkboxen** — Tracker-Konvertierung (~65 Items);
    Claude übernimmt die GUI-anteiligen davon.

Claude-Design-Lane übernimmt: Wizard-Step 5d, Sidebar-Preview, Silence-Watchdog,
Streaming-Indicator, Citation-Chips, TPS-Meter, Local-LLM-Tab (GUI-Hälfte).

---

## Vom Verify gekillt (Beleg-Archiv — nicht wieder ausgraben)

- **ARS-5 Research-Skill-YAMLs** — ALREADY_BUILT: assets/skills/academic_research/
  skill.yaml trägt 15 Modi (QM-23-Port); andere Architektur, gleiche Substanz.
- **WhatsApp-Outbound-Send** — ALREADY_BUILT: GOLD:745 GOLD-HON-24 send_text live
  via /messages Graph API.
- **Conductor 3-Layer-Context** — ALREADY_BUILT: skills/loader.rs:432,
  enriched_request.rs:332, tokens/budget.rs Conductor-Block.
- **Token-Budget-Caps A–E** — ALREADY_BUILT: tokens/budget.rs:37 Block-Enum
  komplett + Tests.
- **Phase-3-Cutover-Runbook** — ALREADY_BUILT: PLAN/RUNBOOK_phase3_cutover.md.
- **neoth export** — ALREADY_BUILT: cli/export.rs:54 run_export; DD-01 fixte nur
  veraltete Docs.
- **channel_statuses 5/15** — ALREADY_BUILT: channel.rs:184-256 deckt alle
  15 Kanäle inkl. Testplänen.
- **E-21 WASM-Wizard-Bulk-Enable** — ALREADY_BUILT: steps_autonomy.rs:237 (D-102 7c).
- **Hysteria-Relay-Client-Transport** — ALREADY_TRACKED: GOLD:1818 GR-009
  (multi-week deferred, explizit).
- **HR-06 headroom Tabular-Compression** — ALREADY_TRACKED: GOLD:1455
  SKIP-with-metering, Counter shipped.
- **n8n-API v2** — REJECTED_STANDS: Spec selbst deferiert bis Operator-Usage-Daten.
- **WAL-S3-Cold-Tier** — REJECTED_STANDS: SPEC_wal_lifecycle Phase 4 / v1.2.
- **Keet native DHT/NOISE/Hypercore Phasen 3–5** — REJECTED_STANDS: Architektur-
  Entscheid Companion-Bridge (channels/keet.rs Modul-Doc) ersetzt das bewusst.
- **9 GUI-Items (H6/H11/H15/H17/H20/H22/I15/D1-Residual/F3-Umfeld)** —
  ALREADY_TRACKED: leben als offene Checkboxen in GUI_TOP_TIER_PLAN.md.
