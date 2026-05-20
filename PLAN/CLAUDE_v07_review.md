# Claude v0.7 Review (independent, not persona-mode)

> **Reference document.** Captures analysis or synthesis at a specific point in time.
> The normative current state lives in `00_DESIGN_v1.1_FINAL.md` plus the `SPEC_*.md`
> files. Use this for context; not build instructions.

## Score Card

| Dimension | v0.7 |
|-----------|------|
| Wire-Protokoll-Spec | 9/10 |
| Layer-Separation (Schicht-0/1) | 9/10 |
| Security-Modell (Ingress + Subprocess + Needle) | 9/10 |
| Engineering-Disziplin (Day-1 Deps, Tests, MVP-Scope) | 9/10 |
| LOWKEY-Auditability | 9/10 |
| Brain-Region-Metapher-Konsistenz | 5/10 |
| WAL-Lifecycle (Rotation, Compaction, Vektor-Blob) | 4/10 |
| Council-Design (für die emergente Komplexität) | 5/10 |
| Phase-3-Migrationsplan | 3/10 |
| Token-Budget / Cost-Control | 4/10 |

## Was gut ist

- **Wire-Format-Spec Section 3**: Byte-für-Byte Offsets, explizite LE-Encoding, wal_format_version vs event_schema_version sauber getrennt, CRC32c-Grenze explizit. Kafka-/LMDB-Spec-Qualität.
- **Schicht-0/1-Trennung Section 13**: zentrale architektonische Entscheidung. Pure deterministic Tools + Effect Adapters mit idempotency_key + WAL-Audit. Löst openclaw-cli-bridge-elvatis-Bypass strukturell.
- **Needle low_risk_intent Allowlist (Section 7)**: explizite Read-only-Liste, Blockliste für send/write/oauth/subprocess, Fall-through zu LLM, WAL-Event 0x27 NEEDLE_BLOCKED_INTENT. "Operator Approval Gate" ist die Stelle wo 90% aller Agent-Systeme Schiffbruch erleiden.
- **LOWKEY-Versionierung (Section 6)**: version + content_hash + disabled_for_eval_sessions + prompt_bundle_hash pro PROVIDER_REQUEST. Audit-Gold, Replay-Determinismus nicht-trivial.
- **subprocess.exec entfernt (Section 9)**: named per-command tools mit argv_schema, env_allowlist exhaustive, cwd_policy sandboxed_temp, Output-Caps, Secret-Redaction. seccomp-Niveau in YAML.
- **Anti-Pattern-Enforcement-Tests (Section 11)**: konkrete Testnamen, RED→GREEN-Daten, Phase-Mapping. Prüfbar statt deklariert.
- **Day-1 = 9 cargo deps (Section 12)**: cargo build < 30s, "added when needed"-Tabelle. wasmtime/candle/ring/rustls/hyper/reqwest/teloxide NICHT am Day 1. Disziplin.
- **Channel Ingress 6-Control-Spec (Section 4)**: "NO auto-merge across channels. Manual operator merge only." Subtilste Fehlerquelle in Multi-Channel.

## Wo es hakt

### 1. Header_len = 215 Bytes ist zu groß
Kafka-Header ~14B, Avro <50. 215 × 10M Events = 2.15 GB Disk-Druck nur Header. Im Header sitzen viele Felder die der Reader NICHT für Routing/Indizierung braucht:
- `content_hash` (16B), `embedding_hash` (16B), `source_uri_hash` (8B), `prompt_bundle_hash` (32B), `parent_event_id` (8B), `supersedes_event_id` (8B)

Audit jede Spalte gegen "muss Reader das ohne Payload-Parse kennen?". Verschiebe was nein in Payload. Ziel: **header_len ≤ 96 Bytes**. Spart auf 10M Events 1.2 GB.

### 2. Brain-Region-Enum inkonsistent
v0.4=13, v0.7=5 (Hippocampus/Amygdala/Insula/Cerebellum/Basal_Ganglia). Wo Thalamus/PFC/Mirror Neurons (FREEDOM!)/DMN/MTL/Pineal/BrainStem? Ehrliche Verkleinerung gut, aber wenn FREEDOM-Authorization keine Region hat, `brain_region=0=None`. Dann trägt sie nichts. **Entscheidung:** entweder zu Index-Tag degradieren und umbenennen, oder konsequent durchziehen.

### 3. Keine WAL-Rotation/Compaction-Strategie
Q3 referenziert "tombstone-bus-flush + 24h ceiling", aber Section 3 sagt nicht was bei 10 GB on-disk passiert. mmap nicht endlos. **Fehlt:** Segment-Boundary, hot/warm/cold-Tiering, Tombstone-Compaction.

### 4. Vector-Blob-Konsistenz unspezifiziert
`vector_blob_off: u64` impliziert separaten Blob-Store. Wo? Konsistenz mit mmap-WAL? Recovery bei Out-of-Sync? Section 3 sagt "bad-magic repair-resync" für WAL, aber nichts für Vektor-Side-Channel.

### 5. Keine Compression-Politik
Qwen3-Embedding-0.6B Q8 ~512B/Vektor + 215B Header. Volumen wächst schnell. zstd-by-batch? FS-Compression (btrfs/zfs) erwartet? Sollte explizit sein.

### 6. Council größte Black Box
Day 38-40 baut 3-LLM-Debatte. Anti-Pattern-Tests G.5+G.10 sollen absichern, aber emergente Multi-Modell-Konsensus-Pathologien fängt man nicht mit `test_council_trigger_is_deterministic` ein. **Brauchst:** Fuzz-Adversarial-Suites, Divergenz-Metriken zwischen Hemisphären, "was wenn alle drei einig sind und falsch liegen"-Tests. Rest des Dokuments präzise; Council mehrheitlich durch das definiert was es NICHT sein darf.

### 7. Token-Budget für Block A-E fehlt
Block A (System) + B (LOWKEY ~800 Token) + C (Recall) + D (Working) + E (User) + Conductor-3-Layer (N9). Ohne Budget pro Block kein Kosten-Kontrolle. **Wo:** `max_prompt_tokens` per Hemisphere?

### 8. Recall-Parity ≥ 0.85 ohne Methodik
Parity wogegen? Jarvis hippo-turbo? LanceDB? "100 Queries" ohne Rubrik = Zahl ohne Aussage. **Vorschlag:** 100 Queries × 3 Grader × Cohens-Kappa für Inter-Rater-Agreement.

### 9. Phase 3 = "Cutover" (1 Wort)
Phase 1 zeilengenau (30 Tage), Phase 3 = 6 Bullet Points. **Riskanteste Phase** (Jarvis-Migration, Multi-Node-Gossip-Sync, Shadow→Live) hat **wenigste Detailtiefe**. Planungs-Inversion.

### 10. Day-30 "recall working" claim
Day 15 Hybrid-Query-Planner + Day 16 DSPM + Day 17 idx_dedup+REINFORCE + Day 19 SESSION_LEDGER = viel für 5 Tage. Entweder "recall working" flacher als impliziert (Keyword + Top-K Cosine), oder Day 15-19 optimistisch. **Tip:** explizit definieren was "Day 30 recall" können MUSS.

### 11. Replay-Window ±300s clock-skew-naiv für Multi-Node
Mit node_id im WAL + Veronica-Gossip-Sync in Phase 3 wird Clock-Skew zwischen Nodes relevant. ±300s für lokale Channel-Ingress OK, aber für **WAL-Event-Ordering zwischen Nodes** brauchst Hybrid Logical Clocks oder Vector Clocks — nicht NTP-Trust.

## Drei Sofort-Aktionen vor Day 1

1. **Header schlanker.** Audit jede Spalte gegen "muss Reader ohne Payload-Parse kennen?". Verschiebe prompt_bundle_hash + parent/supersedes_event_id + embedding_hash in Payload wenn nein. Ziel: header_len ≤ 96 Bytes. Spart 1.2 GB bei 10M Events.

2. **WAL-Lifecycle-Section schreiben.** Segment-Rotation-Schwelle, Compaction-Trigger, Tombstone-Reaper-Cron, Vektor-Blob-Sync-Protokoll, "what happens at 80% disk full". Day-2-Material, nicht Phase 4.

3. **Phase-3-Cutover-Runbook auf Tageslevel.** Shadow-Run-Stop-Bedingungen, Recall-Parity-Mess-Methodik, Rollback-Triggerbedingungen, Operator-Authentifizierung für Cutover-Schalter. Einzige Phase wo Daten verloren gehen können — verdient Phase-1-Detaillevel.

## Gesamteindruck

Inverse des Jarvis-Audits. Jarvis war über-implementiert und unter-spezifiziert; v0.7 ist über-spezifiziert (in den Bereichen wo spezifiziert) und unter-implementiert in Lifecycle-Themen (Compaction, Cutover, Token-Budget). Bessere Richtung des Ungleichgewichts — Spec-first lässt sich nachimplementieren, Tech-Debt-first kaum nachspezifizieren.
