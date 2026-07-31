# LOST FEATURES — 1.0 RECOVERY (2026-07-18)

> **Zweck:** Features, die auf dem Weg zu 1.0 verloren gingen — geplant/entschieden/
> gewünscht, aber nie in den Master-Tracker überführt, still gedroppt, als
> "deferred" versenkt oder nur oberflächlich adoptiert. Operator-Auftrag 2026-07-18.
>
> **Methodik:** 6-Korpora-Archäologie (Early-Design, QUELLEN_ADOPT+Reevaluations
> R1–R7, alle SPECs, Wishlists/Handoffs/Archive, REVIEWS/_gold_audit+RECON,
> Root-Waisen/docs/plans) → 79 geprüfte Rohkandidaten → adversarialer
> 4-Agenten-Verify gegen Code (SRC/neothd, SRC/neothd-gui) + Tracker
> (ROAD_TO_1_0_GOLD.md, GUI_TOP_TIER_PLAN.md). Nur bestätigte Verluste stehen
> unten; Killed-Archiv am Ende verhindert Wieder-Ausgraben.
>
> **Zähler:** 79 Kandidaten = 52 CONFIRMED_LOST + 8 ALREADY_BUILT +
> 11 ALREADY_TRACKED + 3 REJECTED_STANDS + 5 DUPLICATE. Die 52 bestätigten
> Verluste teilen sich exakt in **23 P1 + 29 P2**. Jede Rohkandidaten-Disposition
> steht in `PLAN/lost_features_1_0_inventory.json`.
>
> **Tracking-Regel:** `PLAN/ROAD_TO_1_0_GOLD.md` ist der autoritative lebende
> v1.0-Tracker für alle 52 bestätigten Verluste. `GUI_TOP_TIER_PLAN.md` bleibt
> unterstützende Design-Evidenz, ersetzt aber keine ROAD-Checkbox. Dieses Doc
> und das Kandidaten-Ledger sind die forensische Quelle.

---

## P1 — VERPFLICHTEND in 1.0 (bestätigt verloren, hoher Hebel)

### Sicherheit / Audit / WAL

- **ADR-009 INTENT/RESULT-WAL-Paare — GESCHLOSSEN** `[CODEX]` `GOLD-LF-P1-01`
  **DONE (`e20f6b56`, `cac92ee1`, + Media-Commit).** Alle vier realen
  Effektklassen haben jetzt einen durablen Prä-Mutations-Intent, gepaart über
  `intent_id`, Nutzlast metadaten-only:

  | Klasse | Subtypes | Emit-Site |
  |---|---|---|
  | OS-Dateischreibung | 0x1C/0x1D | `os_tools/gate.rs` |
  | OS-App-Launch | 0x1E/0x1F | `os_tools/gate.rs` |
  | Channel-Egress | 0x20/0x21 | `channels/live_delivery.rs`, `channels/webhook_listener.rs` |
  | Media-Call (Cloud-Vision) | 0x22/0x23 | `media/video_dispatch.rs` |

  **Drei Fehler in der Item-Beschreibung, beim Lesen korrigiert:**
  1. **Die Quelle existiert nicht.** `PLAN/ADR/009-intent-result-wal-audit-pairing.md`
     ist nicht im Repo, `PLAN/ADR/` gibt es gar nicht (C9-Klasse).
  2. **Vier Klassen, nicht fünf.** `SelfUpdateIntent` ist redundant — R3-18
     `UpdaterLeafIntent`/`Result` binden bereits jeden Updater-Leaf.
  3. **„0 Treffer in wal/events.rs" beschrieb die falsche Lücke.** Alle vier
     Klassen hatten *Outcome*-Frames; gefehlt hat die *Prä*-Mutations-Spur.

  **Fail-closed-Politik, bewusst uneinheitlich und je begründet:** autoritative
  Senke lehnt Intent ab → Effekt unterbleibt. Unerreichbarer Audit-RPC-Forward
  → Effekt läuft (AUDIT-RPC-01 hat das ratifiziert; gemeldet als
  `ForwardUnavailable`, nicht still widerrufen). Kein Writer konfiguriert →
  Auditing ist aus, kein Fehler.

  `telegram::audit_notice_egress` bleibt absichtlich unangetastet — reines
  Nach-Audit bereits gesendeter Operator-Notizen; ein Intent dort würde eine
  Prä-Mutations-Spur behaupten, die es nie gab.

- **Mirror-Refusal Stages 2–6 — STALE ITEM, Design abgelöst** `[CODEX]` `GOLD-LF-P1-02`
  **GESCHLOSSEN ohne Code (2026-08-01), verifiziertes Negativergebnis.** Die
  behauptete Abwesenheit stimmt nicht; die Fähigkeiten existieren, nur unter
  der ablösenden Architektur statt unter den Namen der Mirror-Spec.

  **Die Spec sagt es selbst.** `PLAN/SPEC_mirror_refusal.md` trägt im Titel
  „NEOTH **v1.1**", ihr Status-Feld markiert Stages 2–6 als `DEFERRED`, und ihr
  Scope-Block (R-3 Gremium 2026-05-16) verweist ausdrücklich weiter:
  *„Automated retry orchestration, per-hemisphere detection, cause
  classification, LOWKEY reframings … live in `SPEC_refusal_recovery.md`, which
  **supersedes this SPEC** for those items."*

  **Die vier angeblich fehlenden Stufen, je mit Beleg:**

  | Item-Behauptung | Realität |
  |---|---|
  | Right-hemisphere structural analysis | `security/refusal_cause.rs` (13 KB) — Ursachen-Klassifikation |
  | Corpus-Callosum synthesis | `security/refusal_reframings.rs` (13 KB) — LOWKEY-Katalog |
  | Left-hemisphere relay | `cli/chat.rs:4911` R-04-Wire ersetzt `response_text` bei Erfolg |
  | Persistent-refusal guard (EC-4) | `refusal_recovery.rs:680` `emit_persistent_audit` → `0x1A REFUSAL_PERSISTENT` (`wal/events.rs:673`), Test `multi_attempt_emits_persistent_audit_after_all_attempts_fail` |

  Dazu ungenannt und ebenfalls gebaut: D23-Hard-Block-Floor
  (`refusal_abliterated.rs`, 29 KB) VOR jeder Recovery, Abliterated-Fallback,
  Teacher-Eskalation, `0x19 REFUSAL_REROUTED`-Audit je Versuch.
  `refusal_recovery.rs` ist 56 KB.

  **Wie der Fehler entstand:** `refusal_recovery.rs:11` sagt „no hemisphere
  switching here (that's R-04 …)". Das ist eine **Modulgrenze** — „R-04 liegt
  woanders" —, gelesen wurde es als „R-04 fehlt". `cli/chat.rs:4911` trägt
  genau diesen R-04-Marker und ist voll verdrahtet.

  **Warum hier NICHT gebaut wird:** `security/right_hemisphere.rs` +
  `callosum.rs` anzulegen erzeugte eine zweite, parallele
  Refusal-Recovery-Architektur neben der bereits ausgelieferten — dieselbe
  Doppel-Aufzeichnungs-Falle, aus der `SelfUpdateIntent` in P1-01 gestrichen
  wurde. Ein Item, das eine abgelöste Spec nachbaut, ist keine offene Arbeit.

- **Tool-/Provider-Output-Redaction vor abgeleiteten dauerhaften Senken** `[CODEX]` `GOLD-LF-P1-03`
  Quelle: PLAN/SMALLCODE_AUDIT_2026-05-21.md §5#4, gegen aktuellen Source
  nachgeprüft 2026-07-18. Der ursprüngliche Wortlaut war falsch: weder eine
  `recall/store.rs` noch ein `CODING_TOOL_RESULT`-Opcode existiert. Der reale
  MCP-WAL-Frame ist bereits metadata-only; die offene Kette war rohe MCP-Text-
  Ausgabe -> Model-Block -> persistentes File-CCR sowie Provider-/Coding-
  Diagnosen und Recall-/Code-Map-Egress. Integration: eine kanonische
  Raw->Sanitized-Grenze nach MCP-Wire-Accounting und vor Elicitation,
  TokenJuice, Prompt und CCR; strukturierte JSON-Feldredaktion; Coding-
  Testlog/Failure-WAL/Provider-Artefakte; Recall- und Code-Map-Egress; echte
  dekodierte-WAL-, SQLite-/Datei-CCR- und Legacy-Recall-Sentineltests. Bewusst
  rohe Operator-Quellen und semantiktragende Patch-/Job-Artefakte brauchen
  einen expliziten owner-only/scan/fail-closed-Ausnahmevertrag statt heimlichem
  Byte-Rewriting. **SHIPPED 2026-07-18:** vollständig über MCP, Coding,
  Transcript-/Session-/Dream-Persistenz, Recall, Code-Map und File-CCR verdrahtet;
  unsichere ausführbare Patches werden vor Persistenz und Apply verweigert.
  Regressionsevidenz: 34/34 `lf_p1_03_`, 142/142 Sanitizer-Familie sowie je 1/1
  Operator-Source-, Dream-Cloud- und CLI-Doc-Contract.
- **WAL-Replay-Fenster: HLC-Ordering — PRÄMISSE FALSCH, geschlossen** `[CODEX]` `GOLD-LF-P1-04`
  **GESCHLOSSEN (2026-08-01), verifiziertes Negativergebnis.** Das Item stellt
  ±300s-Wall-Clock und HLC als Alternativen für dieselbe Aufgabe dar. Sie
  lösen verschiedene Aufgaben, und die eigentliche Ordnung ist längst gebaut:

  1. **±300s ordnet gar nichts.** `cluster/wal_sync.rs:815` prüft `received_at`,
     und der Kommentar an der Stelle sagt ausdrücklich, dass dieser Wert immer
     lokal via `now_unix_i64()` entsteht und *„a peer cannot inject this
     value"*. Es ist eine Plausibilitätsprüfung gegen die **eigene** Uhr, kein
     Ordnungsmechanismus.
  2. **Kausale Ordnung existiert — als VectorClock, nicht HLC.** `GossipFrame`
     führt eine `VectorClock` (`cluster/gossip_wire.rs:240`), und der
     Frontier-Merge ist echt und getestet:
     `accepted_gossip_frame_advances_local_clock_past_peer_causal_frontier`
     prüft, dass die lokale Uhr nach dem Merge **strikt hinter** der
     Peer-Frontier liegt, nicht bloß gleich. Test läuft grün.
  3. **HLC wäre ein Rückschritt.** Vector Clocks geben *exakte* Kausalität,
     HLC nur eine Näherung. Den einen durch den anderen zu ersetzen verlöre
     Garantien.

  **Echter Nebenbefund, gefixt:** `wal/mod.rs` behauptete im Contract-Absatz
  „the gossip-receive path (which calls `hlc_tick_receive`)". Diesen Aufrufer
  gibt es nicht — `hlc_tick_receive` wird **nirgends** aufgerufen. Die
  Falschaussage ist entfernt und durch den tatsächlichen Mechanismus ersetzt.
  Doku, die eine nicht existierende Aufrufstelle benennt, ist schlimmer als
  Schweigen: sie macht die Lücke unauffindbar. Genau diese Zeile hat das Item
  erzeugt.

- **Trust-Ledger als per-Decision Append-Only-Timeline** `[CODEX]` `GOLD-LF-P1-05`
  Quelle: PLAN/GREMIUM_EXECUTION_BACKLOG_2026-05-20.md#P3. trust.rs hat nur den
  globalen AutonomyLevel; kein TrustEvent/TrustLedger. Integration: neues
  `memory/trust_ledger.rs` + WAL-Event je Entscheidungsgrenze.

### Council / Recall / Inference

- **AgreementDimension-Enum fürs Council-Scoring** `[CODEX]` `GOLD-LF-P1-06`
  Quelle: PLAN/BLUEPRINT_v06_synthesis.md §8. Skalar-Similarity statt
  per-Dimension-Scoring (FactualClaims, RiskAssessment, …). Research:
  Gewichtungsformel je Dimension ist Spec-Lücke.
- **H7: Externer-Familien-Grader als Pflicht im Recall-Parity-Gate** `[CODEX]` `GOLD-LF-P1-07`
  Quelle: PLAN/00_DESIGN_v1.1_FINAL.md H-Fix H7. parity_run.rs rechnet Kappa
  über N Grader ohne Familien-Constraint. Integration: family_tag im
  Grader-Config + Gate auf Cross-Family-Präsenz.
- **Recall-Parity-Evaluations-Harness (Goldset-Mining + 4-Grader-Protokoll)** `[CODEX]` `GOLD-LF-P1-08`
  Quelle: PLAN/SPEC_recall_parity_methodology.md. Scoring-Backend existiert
  (goldset.rs), Orchestrierung fehlt komplett: Jarvis-WAL-Extraktion,
  Operator-Labeling, 4-Grader-Batch, Family-Bias-Clustering. Research: 4
  Subsysteme als eigene v1.0-Subcontracts designen und liefern (~4–6 Wochen;
  Aufwand ändert die Reihenfolge, nicht den Scope).
- **Ouro O-5c: QuantizedOuroLayer + QuantizedOuroModel Forward-Pass** `[CODEX]` `GOLD-LF-P1-09`
  Quelle: PLAN/SPEC_ouro_thinking_provider_2026-05-23.md. quantize.rs deferiert
  selbst auf O-5c; Q8-Inferenz end-to-end nicht funktional. Research: candle-API
  für quantisierten Forward-Pass gegen O-5b-Primitives prüfen.
- **C-16 Inner-Monologue-Audit (Streaming-CoT-Surface)** `[CODEX]` `GOLD-LF-P1-10`
  Quelle: PLAN/FEATURE_EVAL.md C#16. Kein show_thinking/stream-reasoning-Pfad
  in chat.rs/Providern. Integration: dispatch_provider-Streaming-Pfad.
- **C-6 Death of the Prompt (Proaktive Kontext-Vorbereitung)** `[CODEX]` `GOLD-LF-P1-11`
  Quelle: PLAN/FEATURE_EVAL.md C#6. Kein context_prefetch/PreloadContext.
  Integration: serve_pipeline Session-Start oder neuer `daemon/context_preloader.rs`.
- **ARS-3 Citation-Live-Lookup (Crossref/OpenAlex/SemanticScholar)** `[CODEX]` `GOLD-LF-P1-12`
  Quelle: PLAN/QUELLEN_ADOPT_academic_2026-05-21.md#3.2. citation_check ist
  offline-only (recall.rs:82). Research: Outbound-HTTP-Allowlist-Scope vorab klären.
- **C-17 Sub-200ms-Voice: Streaming-Capture-Loop** `[CODEX]` `GOLD-LF-P1-13` *(underresearched)*
  Quelle: PLAN/FEATURE_EVAL.md C#17. VAD-Basis shipped (media/vad/, Silero),
  aber kein Streaming-Capture-Loop ("feed_with_vad() deleted; re-derive when a
  live capture loop lands"). Research: Silero-ONNX compiled-in vs. Scaffold prüfen.

### Channels / Daemon

- **Proaktive Delivery jenseits Telegram** `[CODEX]` `GOLD-LF-P1-14`
  Quelle: proactive_dispatcher.rs:279/393/425 — alle Nicht-Telegram-Kanäle
  SidecarOnly, obwohl send_proactive-Stubs in discord.rs:268/line.rs:108
  existieren. Integration: plan_delivery()-Routing je Kanal.
- **WebChat als First-Class-Surface** `[CODEX]` `GOLD-LF-P1-15`
  Quelle: plans/001-openclaw-channel-migration-parity.md#channel-ledger.
  0 Treffer in channels/. Integration: neuer HTTP/WS-Adapter + Registry.
- **ChannelAccountId end-to-end (F-01)** `[CODEX]` `GOLD-LF-P1-16`
  Quelle: plans/001#gap-F-01. registry.rs:899 definiert den Typ, Kommentar
  "legacy single-account layout for now"; kein Threading durch InboundMessage.
- **Channel-Flapping-Doctor-Check misst Provider- statt Kanal-Rate** `[CODEX]` `GOLD-LF-P1-17` *(underresearched)*
  Quelle: PLAN/REEVALUATION R7#P1. doctor.rs:807 check_provider_flapping;
  per-Channel-Dimension in UsageEvent fehlt. Research: UsageEvent-Struct prüfen.
- **Wizard-IPC: echtes MPSC-Wire-up GUI↔Daemon** `[CODEX]` `GOLD-LF-P1-18`
  Quelle: plans/003#gap-SURF-01. wizard/ipc.rs:22 dokumentiert sich selbst als
  Stub ("lands when cli::serve opens the channel"); kein anderer Consumer.

### GUI / Operator-Sichtbarkeit

- **Local-LLM-Resource-Tab** `[EITHER]` `GOLD-LF-P1-19`
  Quelle: PLAN/v1_0_OPERATOR_WISHLIST_2026-05-24.md §X. Kein Ollama-Poll, kein
  Panel. Integration: Daemon-Poll + neues GUI-Panel (Resources-Tab-Erweiterung).
- **Sidebar Last-Message-Preview** `[CLAUDE-DESIGN]` `GOLD-LF-P1-20`
  Quelle: PLAN/GUI_BEAT_OPENHUMAN.md. chat.slint:1041 hardcodet `''`;
  panel_logic push_message-Pfad füllt nichts. Kleiner Fix, großer Alltagseffekt.
- **Per-Turn-Silence-Watchdog (120s, rearm-on-signal)** `[CLAUDE-DESIGN]` `GOLD-LF-P1-21`
  Quelle: PLAN/GUI_BEAT_OPENHUMAN.md. main.rs:2015 hat nur 2s-Read-Timeout.
  ~40 LOC im gui_stream-Loop.
- **Per-Hemisphere-Provider-Wizard-Step 5d** `[CLAUDE-DESIGN]` `GOLD-LF-P1-22`
  Quelle: PLAN/SPEC_hemisphere_provider_selection.md. CLI-Verben + Datenmodell
  komplett, Wizard-Step fehlt (steps_topology.rs:1094 ist Profile-Gate, kein
  Hemisphere-Picker). Integration: 3 Radio-Picker (left/right/cerebellum).

### Tracker-Hygiene (Meta, aber P1 — sonst versanden 65 Items erneut)

- **plans/001/002/003 verwaiste Done-Criteria → GOLD-Checkboxen** `[EITHER]` `GOLD-LF-P1-23`
  65 offene Work-Items (BUG-*, DX-*, SURF-*, DIRECTION-*, MIGRATION-*) sind in
  keinem Tracker; GOLD referenziert die drei Files nur als Links. Aktion:
  Items extrahieren, triagieren, als Checkboxen unter R4-01/04/05/06/07 einhängen.

---

## P2 — VERPFLICHTEND in 1.0 (Priorität nach P1, kein Scope-Aufschub)

### Memory / Selbstorganisation
- **Dreaming 3-Phasen-Protokoll (Light/REM/Repair)** `[CODEX]` `GOLD-LF-P2-01` — CHERRY_PICK #1
  openclaw-Adopt; dreaming.rs hat keinen DreamPhase-Dispatch.
- **Hippocampus 0.75-Importance-Threshold-Cron** `[CODEX]` `GOLD-LF-P2-02` — Jarvis #1 Cherry-Pick;
  decay_task.rs + Importance-Feld fehlen.
- **Vault-Git-Commit-Nightly als WAL_MIRROR-Backup** `[CODEX]` `GOLD-LF-P2-03` — Jarvis #3.
- **Reflection-Hygiene komplett** `[CODEX]` `GOLD-LF-P2-04` — Retention ≤90d, Jaccard-Topic-Dedup,
  Yearly-Synthesis aus PeriodReflections, Topic-Synonym-Map (REFLECT_BACKLOG §A).
- **Self-Improve Proposal-Qualitäts-Schema** `[CODEX]` `GOLD-LF-P2-05` — quality_schema_version,
  eval_source, corpus_hash, regressions (REFLECT_BACKLOG §B; Proposal-Struct
  vorher lesen — dreaming_task.rs:339 hat nur status/skill/confidence).
- **C-13 Capability-Decay-Tracking** `[CODEX]` `GOLD-LF-P2-06` — Provider-Qualitätsmetrik.
- **EXP-FD-1..5 Fraktal-Dimension-Experimente** `[CODEX]` `GOLD-LF-P2-07` — dimension.rs:13 gated;
  Research: CoT-Depth-Klassifikation (Lit-Review nötig).
- **WAL-Header session_id universell genullt** `[CODEX]` `GOLD-LF-P2-08` — builder.rs:54;
  VIEW-01 stampte nur den 0x21-PAYLOAD. make_header + Emit-Sites threaden.

### Agents / Skills / Tools
- **C-2 Agent mit eigenen Zielen (Autonomous-Research-Loop)** `[CODEX]` `GOLD-LF-P2-09`
- **SP-H1 Session-Start-Skill-Registry-Injection** `[CODEX]` `GOLD-LF-P2-10`
- **CG-2/3/5 CodeGraph-Edges (ImportGraph, TypeHierarchy, BFS-API)** `[CODEX]` `GOLD-LF-P2-11` —
  CG-1 (CallGraph) existiert (code_map/graph.rs:125).
- **Per-Skill-Autonomie-Gradienten** `[CODEX]` `GOLD-LF-P2-12` — AutonomyLevel::Custom existiert,
  per-Skill-Override-Map nicht.
- **CloakBrowser Stealth-Web-Fetch-Plugin** `[CODEX]` `GOLD-LF-P2-13` — Research: playwright-rs
  vs. chromiumoxide für headless Win11.
- **Ralph-Retry (error-aware LLM-Retry-Tool)** `[CODEX]` `GOLD-LF-P2-14`
- **Role-Enforcement-Pipeline (Hemisphären)** `[CODEX]` `GOLD-LF-P2-15`
- **E-22 Skill-Hot-Reload Arc<SkillBody>-Pinning** `[CODEX]` `GOLD-LF-P2-16` — ArcSwap swappt
  zwischen Turns; Invocation-Pinning (Option 3) fehlt.
- **omniparser-Reopen-Entscheid** `[EITHER]` `GOLD-LF-P2-17` — DO_NOT_ADOPT.md:38 Reopen-Bedingung
  (PC-01/PC-02) ist seit GOLD:958/970 erfüllt, nie revisited. Decision-only:
  600MB-ONNX vs. Fresh-Win11-Filter neu bewerten, Verdict in DO_NOT_ADOPT
  aktualisieren. NICHT bauen ohne neuen Entscheid.

### Cluster / Infra
- **Per-Node-Skill-Assignment + Channel-Binding** `[CODEX]` `GOLD-LF-P2-18` — Veronica-Delta §6;
  Research: Routing-Table-Design im Cluster-Handshake.
- **Cluster-BudgetToken-Konsens (Raft, Phase 6)** `[CODEX]` `GOLD-LF-P2-19` — heute per-request-only.
- **n8n/Paperless-Installs gepinnt+verifiziert** `[CODEX]` `GOLD-LF-P2-20` — Version-Pin + sha256
  im Installer (heute nur Port-Stabilitäts-Tests).
- **neoth-archive-bridge Obsidian-Plugin** `[EITHER]` `GOLD-LF-P2-21` — externes TS-Projekt;
  NEOTH-Seite (obsidian.rs sync_archive) ist der Pairing-Punkt.
- **Per-Counterparty-Consent-Gate für Channel-Ingress-Clustering** `[CODEX]` `GOLD-LF-P2-22` —
  ADR-005; dreaming_task liest Episoden ohne Consent-Dimension.
- **ADR-003 dream.cron_enabled + Wizard-Nudge** `[CODEX]` `GOLD-LF-P2-23`
- **BGE-M3-Fallback-Embed-Model (Opt-in + GUI-Parity)** `[EITHER]` `GOLD-LF-P2-24` — ADR-004.
- **Voice-Call First-Class-Surface** `[CODEX]` `GOLD-LF-P2-25` — plans/001 Channel-Ledger.

### GUI-Polish (Design-Lane, klein)
- **Three-Phase-Streaming-Indicator** `[CLAUDE-DESIGN]` `GOLD-LF-P2-26` — StreamState-Enum + ~30 LOC.
- **Citation-Chips für Recall-Hits** `[CLAUDE-DESIGN]` `GOLD-LF-P2-27` — CitationChip-Komponente
  + WarmHit-Score-Feld.
- **C-18 Quality-Signal (non-star Per-Response-Feedback)** `[EITHER]` `GOLD-LF-P2-28` —
  GR-RESID-F35 war Recall-Link-Feedback, nicht Response-Qualität.
- **Live-TPS-Meter im Chat-Header (R-03)** `[CLAUDE-DESIGN]` `GOLD-LF-P2-29` — per-Message-Chip
  existiert; 1Hz-Rolling-Counter fehlt.

---

## Unvollständiges Research — Vertiefungsaufträge

1. **HLC-Merge-Semantik** (P1): Wie kodiert EventHeaderV2 node_id+ts_ns eine
   HLC-Komponente ohne WAL-Consumer-Bruch? → Design-Note vor Implementierung.
2. **Recall-Parity-Harness** (P1): 4 Subsysteme (Transcript-Extractor,
   Labeling-UI, Multi-Hemisphere-Batch, Bias-Clustering) je einzeln designen;
   alle vier bleiben verpflichtender v1.0-Scope (~4–6 Wochen).
3. **Sub-200ms-Voice** (P1): Streaming-Capture-Architektur (cpal-Loop → VAD →
   Streaming-Whisper); prüfen ob Silero-Backend compiled-in ist.
4. **AgreementDimension-Gewichtung** (P1): Formel je Dimension ist Spec-Lücke.
5. **CoT-Depth-Klassifikation für EXP-FD-1** (P2): Lit-Review Reasoning-Depth-
   Estimatoren.
6. **CloakBrowser-Engine-Wahl** (P2): playwright-rs vs. chromiumoxide, Win11-headless.
7. **omniparser-Re-Evaluation** (P2): Decision-only, Verdict-Update.

---

## @Codex / ChatGPT Work — Zuweisung

> Historische Rollenangabe aus dem Recovery-Lauf. Die Owner-Tags beschreiben
> Arbeitslanes, keinen externen Release-Eigentümer. Alle Items sind heute mit
> den oben fixierten IDs in ROAD_TO_1_0_GOLD.md gebunden.

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
    **H7 Cross-Family-Grader**, **AgreementDimension** — alle v1.0; Reihenfolge
    nach Abhängigkeiten und Risiko.
13. **plans/001-003 → GOLD-Checkboxen** — Tracker-Konvertierung (65 Items);
    GUI-Anteile bleiben ebenso unter dem autoritativen ROAD-Release-Gate.

Design-Lane: Wizard-Step 5d, Sidebar-Preview, Silence-Watchdog,
Streaming-Indicator, Citation-Chips, TPS-Meter, Local-LLM-Tab (GUI-Hälfte).

---

## Vom Verify gekillt (Beleg-Archiv — nicht wieder ausgraben)

- **LF-CAND-011 — ARS-5 Research-Skill-YAMLs** — ALREADY_BUILT: assets/skills/academic_research/
  skill.yaml trägt 15 Modi (QM-23-Port); andere Architektur, gleiche Substanz.
- **LF-CAND-013 — WhatsApp-Outbound-Send** — ALREADY_BUILT: GOLD:745 GOLD-HON-24 send_text live
  via /messages Graph API.
- **LF-CAND-020 — Conductor 3-Layer-Context** — ALREADY_BUILT:
  `SRC/neothd/src/skills/loader.rs`, `SRC/neothd/src/pipeline/enriched_request.rs`
  und `SRC/neothd/src/tokens/budget.rs` (Conductor-Block).
- **LF-CAND-025 — Token-Budget-Caps A–E** — ALREADY_BUILT: tokens/budget.rs:37 Block-Enum
  komplett + Tests.
- **LF-CAND-028 — Phase-3-Cutover-Runbook** — ALREADY_BUILT: PLAN/RUNBOOK_phase3_cutover.md.
- **LF-CAND-063 — neoth export** — ALREADY_BUILT: cli/export.rs:54 run_export; DD-01 fixte nur
  veraltete Docs.
- **LF-CAND-073 — channel_statuses 5/15** — ALREADY_BUILT: channel.rs:184-256 deckt alle
  15 Kanäle inkl. Testplänen.
- **LF-CAND-053 — E-21 WASM-Wizard-Bulk-Enable** — ALREADY_BUILT:
  `SRC/neothd/src/cli/init/steps_autonomy.rs` (D-102 7c).
- **LF-CAND-032 — Hysteria-Relay-Client-Transport** — ALREADY_TRACKED:
  GR-009 ist der historische Deferral-Beleg; der lebende v1.0-Release-Eigentümer
  ist `GOLD-R4-13`, bis der echte Sendepfad konsumiert oder der Transport aus
  dem Produktvertrag entfernt ist.
- **LF-CAND-079 — HR-06 headroom Tabular-Compression** — ALREADY_TRACKED:
  `GOLD-ADAPT-HR-06` SKIP-with-metering, Counter shipped.
- **LF-CAND-031 — n8n-API v2** — REJECTED_STANDS: Die Spec verlangt reale
  Operator-Usage-Daten vor einer neuen API-Oberfläche; ohne v1.0-Consumer oder
  Public Claim wäre der Bau primitive-ahead. Reopen nur mit nachgewiesenem Consumer.
- **LF-CAND-033 — WAL-S3-Cold-Tier** — REJECTED_STANDS: Kein v1.0-Consumer oder
  Public Claim verlangt einen credential-/cloud-abhängigen S3-WAL-Tier; lokale
  Archive/Backups sind der aktuelle Vertrag. Phase 4 bleibt eine neue, separate
  Produktentscheidung und kein verstecktes ROAD-Deferral.
- **LF-CAND-036 — Keet native DHT/NOISE/Hypercore Phasen 3–5** — REJECTED_STANDS: Architektur-
  Entscheid Companion-Bridge (channels/keet.rs Modul-Doc) ersetzt das bewusst.
- **LF-CAND-048 — Cluster topology graph with RTT latency** — ALREADY_TRACKED:
  `GUI_TOP_TIER_PLAN.md#H22`; lebender Release-Parent `GOLD-R4-05`.
- **LF-CAND-049 — Command palette real action dispatcher** — ALREADY_TRACKED:
  `GUI_TOP_TIER_PLAN.md#D1-residual`; lebender Release-Parent `GOLD-R4-05`.
- **LF-CAND-069 — H17 Edit-and-Branch with Variant-Navigator** — ALREADY_TRACKED:
  `GUI_TOP_TIER_PLAN.md#H17`; lebender Release-Parent `GOLD-R4-05`.
- **LF-CAND-070 — H20 Prompt-Library + Multi-Model-Split-View + Fulltext-Search** — ALREADY_TRACKED:
  `GUI_TOP_TIER_PLAN.md#H20`; lebender Release-Parent `GOLD-R4-05`.
- **LF-CAND-071 — H22 Health-Heatmap + Topology-Graph + Cluster-Bar** — ALREADY_TRACKED:
  `GUI_TOP_TIER_PLAN.md#H22`; lebender Release-Parent `GOLD-R4-05`.
- **LF-CAND-072 — I15 Channel-Pairing-Wizard** — ALREADY_TRACKED:
  `GUI_TOP_TIER_PLAN.md#I15`; lebender Release-Parent `GOLD-R4-05`.
- **LF-CAND-075 — H15 Inline-Diffs in chat cards** — ALREADY_TRACKED:
  `GUI_TOP_TIER_PLAN.md#H15`; lebender Release-Parent `GOLD-R4-05`.
- **LF-CAND-077 — H6 Live theme editor** — ALREADY_TRACKED:
  `GUI_TOP_TIER_PLAN.md#H6`; lebender Release-Parent `GOLD-R4-05`.
- **LF-CAND-078 — H11 Buddy click-through/hover/quiet-hours** — ALREADY_TRACKED:
  `GUI_TOP_TIER_PLAN.md#H11`; lebender Release-Parent `GOLD-R4-05`.

### Semantisch zusammengeführte Rohkandidaten (5)

- **LF-CAND-038 — Reflection retention/pruning hygiene** — DUPLICATE_OF
  `LF-CAND-061` / `GOLD-LF-P2-04`; Retention, Dedup und Cleanup bleiben dort erhalten.
- **LF-CAND-039 — Yearly reflection synthesis** — DUPLICATE_OF
  `LF-CAND-061` / `GOLD-LF-P2-04`; PeriodReflection-Synthese und Topic-Merge bleiben erhalten.
- **LF-CAND-040 — Self-improve quality provenance schema** — DUPLICATE_OF
  `LF-CAND-062` / `GOLD-LF-P2-05`; Schema-Version, Quelle, Corpus-Hash und Regressionen bleiben erhalten.
- **LF-CAND-064 — omniparser als NEOTH-MCP-Server** — DUPLICATE_OF
  `LF-CAND-074` / `GOLD-LF-P2-17`; Reopen-Bedingung und Entscheidungsumfang bleiben erhalten.
- **LF-CAND-067 — Mirror-Refusal Stages 2–4** — DUPLICATE_OF
  `LF-CAND-030` / `GOLD-LF-P1-02`; die kanonische Zeile umfasst weiterhin Stages 2–6.

Das vollständige 79er-Ledger mit Originalnamen, Quellen und Dispositionen steht
maschinenlesbar in `PLAN/lost_features_1_0_inventory.json`. Zwei unabhängige
H22-Funde (`LF-CAND-048` und `LF-CAND-071`) bleiben getrennte Rohkandidaten;
das frühere Sammellabel „F3-Umfeld“ war kein Kandidat des Originaljournals.
