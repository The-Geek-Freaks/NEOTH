# NEOTH Gremium-Analyse (Top-10-Coder Simulation) — 2026-05-20

## Zielbild
NEOTH soll gleichzeitig **DAU-freundlich** (onboarding, Klarheit, Vertrauen) und **Profi-first-choice** (Kontrolle, Erweiterbarkeit, Verlässlichkeit) sein. Dieses Dokument bündelt Security-, Code-, Produkt- und UX-Findings inkl. ToDos.

## Vergleich mit OpenClaw / Hermes / OpenHuman (strategisch)
- **Aktuelle Stärke NEOTH**: lokale-first Architektur, klare Sicherheits-Primitive (Webhook-Signaturprüfung, Secret-Handling), Governance/Planungsreife.
- **Lücke ggü. Top-Konkurrenz**: Execution-Hardening (Sandbox-Guarantees technisch erzwingen), belastbare E2E-Qualitätsmetriken, UX-Polish und Konsistenz bis ins letzte Detail.
- **Chance**: NEOTH kann gewinnen, wenn es Security-by-default + “invisible complexity” (einfach für DAU, mächtig für Pros) besser verbindet als die Konkurrenz.

## Scorecard (0–10)
- Sicherheit: **7.6** (starke Basis, aber 2 kritische P1-Lücken).
- Code-Qualität: **7.2** (gute Struktur, aber Hotspots mit zu hoher Funktionslast).
- Funktionsumfang/Scope: **8.0** (breit: channels, mcp, plugins, gui, docs).
- Reliability/Smoke/Edge: **6.9** (teilweise gute Tests, aber Coverage-Lücken in kritischen Pfaden).
- UX/Design-System-Kohärenz: **7.0** (klarer Anspruch vorhanden, Inkonsistenzen in Umsetzung).
- Innovationspotenzial (“bester personal buddy”): **9.0** (sehr hoch, wenn Prioritäten sauber exekutiert werden).

## Top-Findings (priorisiert)

### P0/P1 — sofort (Blocker auf dem Weg zu “best in class”)
1. **WASM-Memory-Cap wird nicht robust erzwungen (Policy/Impl-Gap)**
   - Risiko: DoS durch speicherhungrige Plugins.
   - Referenz: `SRC/neothd/src/wasm_plugin/engine.rs`.
   - Aktion: Store/Allocator-Limits hart enforce’n + Negativtests.

2. **Webhook-Listener ohne Concurrency-Backpressure-Limit**
   - Risiko: lokale Überlast/DoS bei Request-Spikes.
   - Referenz: `SRC/neothd/src/channels/webhook_listener.rs`.
   - Aktion: globale Semaphore, 503 bei Überlast, optionale Rate-Limits.

3. **Fragile Verify-Logik (Segment-Match über String-Pfade)**
   - Risiko: Fehlklassifikation autorisierter Redactions.
   - Referenz: `SRC/neothd/src/cli/verify.rs`.
   - Aktion: kanonische Path-Komponenten + strukturierte Segment-IDs.

### P1/P2 — kurzfristig (2–4 Wochen)
4. **MCP Allowlist nicht secure-by-default**
   - Risiko: Privilege Expansion bei kompromittiertem MCP-Server.
   - Referenz: `SRC/neothd/src/mcp/config.rs`.
   - Aktion: Default deny-all; `doctor` als hard fail bei fehlender Allowlist.

5. **Security-kritischer Handshake mit manuellem Query-Parsing**
   - Risiko: Kantenfall-/Encoding-Fehler.
   - Referenz: `SRC/neothd/src/channels/webhook_verify.rs`.
   - Aktion: robusten URL/Query-Parser verwenden, Property-Tests ergänzen.

6. **`run_verify` übernimmt zu viele Verantwortungen**
   - Risiko: Wartbarkeit sinkt, Bugsurface steigt.
   - Referenz: `SRC/neothd/src/cli/verify.rs`.
   - Aktion: in Pipeline-Schritte aufsplitten (extract/verify/classify/report).

### P2/P3 — mittelfristig
7. **Pattern-basierter “no outbound network”-Test ist bypassbar**
   - Referenz: `SRC/neothd/tests/no_outbound_network.rs`.
   - Aktion: semantische Policies (crate allowlist, CI dependency guardrails).

8. **GUI-Designsystem: Kontrast/Hierarchy/Keyboard-Flow inkonsistent**
   - Referenz: `SRC/neothd-gui/ui/*.slint`, `docs/superpowers/specs/*`.
   - Aktion: harte UI-Tokens, Fokus-States, motion/system-chrome konsistent aus Spec ableiten.

## Steve-Jobs-inspirierte GUI-Leitlinien (12/10 Ziel)
1. **Radikale Klarheit**: pro Screen eine dominante Primäraktion.
2. **Content first**: visuelle Deko reduzieren, Signal-zu-Rauschen maximieren.
3. **Progressive Disclosure**: Default simpel für DAU, Power-Optionen “one layer deeper”.
4. **Mikro-Interaktionen mit Zweck**: Animation nur bei Bedeutungsgewinn.
5. **Typografie + Spacing als System**: konsistente Rhythmik für Vertrauen/Lesbarkeit.
6. **Zero-confusion Onboarding**: “Was passiert als nächstes?” jederzeit sichtbar.

## Produktstrategie: “Personal Buddy” + “Pro Tool” gleichzeitig
- **DAU-Modus**: geführte Flows, sichere Defaults, klare Sprache, automatische Recovery.
- **Pro-Modus**: auditierbare Entscheidungen, explizite Policies, reproduzierbare Pipelines.
- **Brücke**: alle Auto-Entscheidungen erklärbar machen (“why this action”).

## 30/60/90-Tage Plan
- **30 Tage**: P0/P1 Security-Hardening + Verify-Refactor-Start + UI-Kontrast/Fokus-Fixes.
- **60 Tage**: E2E-Sicherheits- und Edge-Testmatrix, MCP secure-default rollout, onboarding revamp.
- **90 Tage**: differentiating features (proaktive Assistenz, adaptive UX, trust dashboard).

## Engineering ToDo-Backlog (konkret)
- [ ] Wasmtime memory limiter implementieren + Failing test bei OOM-Plugin.
- [ ] Webhook listener semaphore + overload response + telemetry.
- [ ] `verify.rs` in kleine pure Funktionen trennen; property tests für Redaction-Fenster.
- [ ] Query parsing in webhook verify auf Standardparser migrieren.
- [ ] MCP allowlist default `deny`; Migrationshinweise + doctor fail-mode.
- [ ] Security-CI: dependency/network policy checks verschärfen.
- [ ] GUI token audit (contrast/focus/spacing), keyboard-only journey testen.
- [ ] UX-Spec ↔ Implementation Traceability-Matrix einführen.

## Schlussfazit
NEOTH hat das Potenzial, **besser als OpenClaw + Hermes + OpenHuman zusammen** zu werden, wenn Security-Enforcement, Reliability-Metriken und UI-Kohärenz jetzt kompromisslos priorisiert werden. Die Basis ist stark; der nächste Schritt ist operative Exzellenz in den kritischen 20% mit 80% Wirkung.
