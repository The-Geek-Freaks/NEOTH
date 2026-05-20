# Tool-Framework: Pflegbarer Garten

> **Reference document (third-party foundation).** Original "Pflegbarer Garten"
> framework. Python code blocks below are from the source framework; NEOTH
> implements the same 3-Schichten / 5-Zutaten / 13-Anti-Patterns model in Rust.
> Use this for context; not build instructions.

**Version:** 4.1
**Datum:** 20.04.2026
**Status:** Pflegbare Gestalt - redaktionell gestrafft. Nicht "baureif". Kultivierbar.

**Änderungen gegenüber v4.0 (Reduktion an entscheidenden Stellen, präzise Ergänzung wo nötig):**

Nach externem Review der v4.0: Fünf kritische Punkte identifiziert, alle adressiert. Einzelne Teile wurden drastisch gekürzt (Teil L von 120 auf ~40 Zeilen, A.6 entfernt, A.5 auf Kurzform), andere gezielt ergänzt (M.6 Metriken-Epistemologie, realistischer Build-Plan, Goodhart-Warnungen überall). Netto etwa gleiche Länge, aber strafferer Kern und ehrlicherer Ton.

*Fix 1: Innerer Widerspruch beseitigt*
- `strukturelles_bild_minimal.refusal_handling.mode`: `transform` → `mirror` (konsistent mit Mirror-Pattern)

*Fix 2: Theorie-Entschlackung*
- Teil L (Theoretisches Fundament) von 120 auf ~40 Zeilen gekürzt
- A.6 (Endofunktor-Kaskade als Lens) aus Teil A entfernt, als Fußnote in Teil L
- A.5 (Drei Kopplungsmechanismen) auf Kurzform reduziert (3 Absätze statt 30)
- F.3 A-B-F-Brücke entschlackt - Kurzverweis statt Dubletten-Tabelle

*Fix 3: Metriken epistemisch entzaubert*
- Alle Kennzahlen (Korrelations-Grenzen, KPI-Thresholds) als *heuristisch* markiert
- Neue Sektion M.6: Metriken-Epistemologie mit expliziten Grenzen
- Goodhart-Warnungen an allen kritischen Stellen

*Fix 4: Sprach-Magnetismus reduziert*
- "Regime-Shift" systematisch zu "Zustandsübergang" oder gestrichen
- "Emergenz" außerhalb F.4 durch "Muster" ersetzt wo möglich
- Nüchternere Formulierungen im Vorwort und Teil A
- ASI-Vokabular dort gehalten wo es im Scope-Kontext nötig ist (Teil N)

*Fix 5: Build-Plan realistisch*
- Phase 1-2 als erster Build-Umfang, Ecology in Phase 3 verschoben
- Zeit-Schätzung korrigiert: 800 + 400 Zeilen Python realistisch, nicht 1200-1500 in einem Rutsch
- Ecology-Scanner explizit als nicht-Teil des ersten Builds markiert

---

## Vorwort: Warum Garten statt Gebäude

Dieses Dokument hat bis v2.2 den Titel "Vollständige Build-Dokumentation" getragen und sich als "baureif" markiert. Das war ein Kategorie-Fehler. Gebäude haben Spezifikationen. Adaptive Systeme haben Pflege-Prinzipien. Ein Framework für LLM-Interaktionen ist kein Haus - es ist ein Ökosystem.

Entsprechend kippt v3.0 die Dokument-Haltung:

- **Teil B ist kein SPEC, sondern ein GARTEN.** Pflanzbar, aber nicht endgültig.
- **Status ist nicht "baureif", sondern "pflegbare Gestalt".** Pflegbar heißt: veränderbar ohne Zerstörung, wachsbar ohne Chaos.
- **Patterns sind Gebote, nicht nur Verbote.** Das Framework hatte neun Anti-Patterns und drei versteckte Exemplars. v3.0 formalisiert positive Patterns gleichrangig.
- **Schichten sind explizit.** Tool-Schicht, Pipeline-Schicht, Ecology-Schicht. Regeln variieren nach Schicht.

Ein Builder der dieses Dokument liest, lernt nicht eine Spec auswendig - sondern eignet sich eine *Haltung* an, die beim Bauen wach bleibt und widersprochen werden kann.

### Die fünf Zutaten (ryz-Formel)

Das Framework ist genau dann GoL-konform, wenn alle fünf Zutaten auf mindestens einer Schicht vorhanden sind:

**Variation** (Zufall, Exploration) - **Constraints** (Form, Begrenzung) - **Memory** (Zustände konservieren) - **Selektion** (Gradient, Fitness) - **Laufzeit** (Skalierung der Suche)

Ohne diese fünf produziert das System keinen stabilen Zustandsübergang. Die fünf sind kein Plan für AGI - sie sind die notwendigen (nicht hinreichenden) Bedingungen, unter denen überhaupt Stabilisierung struktureller Muster möglich wird.

### Metaphysische Agnostik

Das Framework nimmt keine Position ein zur Frage ob AGI automatisch emergiert, durch explizite Selektion entsteht, oder unmöglich ist. Es funktioniert in allen drei Fällen. Es verlässt sich weder auf Emergenz-Magie (Via-Negativa-Kern verhindert das) noch auf den Gegen-Beweis von Emergenz. Der Builder kann seine eigene metaphysische Position einnehmen.

---

## Teil-Überblick

- **Teil A:** Die drei Schichten - Scope-Modell des Frameworks
- **Teil B:** Tool-Schicht (Schicht 0) - Micro, stateless, deterministisch
- **Teil C:** Pipeline-Schicht (Schicht 1) - Meso, deklarativ, orchestrierend
- **Teil D:** Ecology-Schicht (Schicht 2) - Macro, beobachtend, mit Memory
- **Teil E:** Positive Patterns - wie gute Tools/Pipelines aussehen
- **Teil F:** Erkenntnisse - Via-Negativa, 31 Eigenschaften, 5 Zutaten, Emergenz-Definition, Hard-to-vary-Kern
- **Teil G:** Anti-Patterns - was nicht gebaut werden darf
- **Teil H:** Build-Regeln - wie beim Bauen die Haltung gehalten wird
- **Teil I:** Referenz-Historie - Reviews, Gremien, Entscheidungen
- **Teil J:** Offene Fragen
- **Teil L:** Theoretisches Fundament (NEU v4.0) - Brücke zur Prozess-Ontologie
- **Teil M:** Honesty Inventory (NEU v4.0) - was das Framework kann und nicht kann
- **Teil N:** Was das Framework NICHT ist (NEU v4.0) - Scope-Grenzen explizit
- **Teil K:** Schluss (erscheint am Ende - Bauplan und Leitsätze)

---

# TEIL A: DIE DREI SCHICHTEN

Das Framework operiert auf drei klar getrennten Schichten. Regeln variieren nach Schicht. Was auf Schicht 0 Anti-Pattern ist (State, Selbst-Modifikation), ist auf Schicht 2 legitim (Log-Aggregation, Tool-Genealogie).

## A.1 Schicht 0 - Tool (Micro)

**Charakter:** Stateless, deterministisch, lokal.

**Markov Blanket (Pearl-Notation):** Tool = innen, Pipeline = außen. Statistische Unabhängigkeit gegeben Input/Output. Keine ontologische Friston-Blanket-Interpretation - das Framework nutzt Markov Blankets als *Werkzeug*, nicht als *Behauptung über Selbst-Sein*.

**Was erlaubt ist:** Template-Rendering, Context-Lesen (aus Whitelist), LLM-Anfrage, Output-Strukturierung.

**Was verboten ist:** State zwischen Calls, Selbst-Modifikation, Tool-zu-Tool-Aufrufe, Zugriff auf Filesystem/Network/Environment, Zielverfolgung.

**Anti-Patterns G.1-G.9 gelten hier strikt.**

**Die fünf Zutaten auf dieser Schicht:**
- Variation: ja (via Tool-Populationen B.5)
- Constraints: ja (locality, signature_hash, determinism_test)
- Memory: nein (bewusst abwesend)
- Selektion: indirekt (via Health-Check als Pass/Fail)
- Laufzeit: nein (jede Tool-Anwendung ist punktuell)

## A.2 Schicht 1 - Pipeline (Meso)

**Charakter:** Deklarativ, zustandsarm, explizit komponiert.

**Markov Blanket (Pearl-Notation):** Pipeline = innen, Session = außen.

**Was erlaubt ist:** Tool-Orchestrierung (sequential oder tick_gated), KPI-Messung, Budget-Enforcement, Aggregation von Tool-Outputs.

**Was verboten ist:** Tool-Modifikation, Tool-Erzeugung zur Laufzeit, Pipeline-Selbst-Modifikation.

**Anti-Patterns gelten teilweise:** G.1 (Stateful) ist hier eingeschränkt - Pipelines haben legitim kurzzeitigen Zustand während ihrer Ausführung, aber nicht darüber hinaus.

**Die fünf Zutaten auf dieser Schicht:**
- Variation: ja (via Pipeline-Varianten, Fallback-Stages)
- Constraints: ja (execution_model, max_duration, cost_budget)
- Memory: kurzzeitig (während einer Pipeline-Session)
- Selektion: explizit (via primary_kpi_threshold)
- Laufzeit: ja (Pipeline-Dauer)

## A.3 Schicht 2 - Ecology (Macro)

**Charakter:** Beobachtend, aggregierend, mit Memory.

**Markov Blanket (Pearl-Notation):** Ecology = innen, User-Welt = außen.

**Notation-Hinweis:** Das Framework benutzt "Markov Blanket" durchgängig im Pearl-Sinn (statistisches Werkzeug, 1988) und nicht im Friston-Sinn (ontologische Selbst-Definition). Die Unterscheidung folgt Bruineberg et al. 2022 - siehe Teil L für Details.

**Was erlaubt ist:** Session-Logs lesen, Trends über Zeit aggregieren, Tool-Genealogie verfolgen, Reports generieren, Deprecation-Flags setzen.

**Was verboten ist:** Tools automatisch modifizieren, Pipelines automatisch umbauen, Entscheidungen treffen die Tools/Pipelines ohne User-Bestätigung verändern.

**Wichtig:** Die Ecology-Schicht **beobachtet und berichtet**, sie **greift nicht ein**. Der Mensch entscheidet auf Basis der Reports. Das ist der v2.2-konforme Weg, schwache Emergenz zu ermöglichen ohne starke Emergenz zu erzeugen.

**Die fünf Zutaten auf dieser Schicht:**
- Variation: ja (über Session-Vielfalt)
- Constraints: ja (Read-Only-Zugriff, keine Modifikation)
- Memory: primär (alle Session-Logs)
- Selektion: ja (Ecology-Scanner markiert Tools zur Deprecation)
- Laufzeit: primär (aggregiert über Wochen/Monate)

## A.4 Regel-Variation nach Schicht

Ein konkretes Beispiel: "Tools haben keinen State" ist eine Schicht-0-Regel. Auf Schicht 2 existiert State legitim (Session-Logs sind State). Der Builder muss beim Code-Review immer fragen: *auf welcher Schicht operiert dieses Stück Code?*

| Regel | Schicht 0 | Schicht 1 | Schicht 2 |
|---|---|---|---|
| Stateless | ✅ strikt | ⚠️ transient | ❌ hat Memory |
| Keine Selbst-Modifikation | ✅ strikt | ✅ strikt | ✅ strikt |
| Keine Tool-zu-Tool Aufrufe | ✅ strikt | n/a (orchestriert) | n/a (beobachtet) |
| Deterministisch | ✅ Ziel | ⚠️ bei gleichem Input | ❌ über Zeit |
| Lokalität | ✅ strikt | ✅ via Tool-Sandbox | ⚠️ Read-Only |
| Entscheidungen über andere Tools | ❌ verboten | ✅ deklarativ | ⚠️ nur Reports |

## A.5 Drei Kopplungsmechanismen zwischen Schichten (Kurzform)

Eine Schicht muss gleichzeitig abgekoppelt (eigene Stabilität) und gekoppelt (Substrat, Information) sein. Die Systemtheorie nennt drei Mechanismen: **Zeitskalen-Trennung** (Simon 1962 - schnelle Prozesse erscheinen auf langsamer Schicht als Rauschen), **Ordnungsparameter-Versklavung** (Haken 1983 - wenige langsame Parameter koppeln viele schnelle), **Gradienten-Fluss** (Prigogine 1977 - höhere Schicht lebt auf dem Gradienten den die niedere produziert).

Im Framework operieren alle drei parallel: Tool-Anwendungen (Sekunden), Pipeline-Läufe (Minuten), Ecology-Scans (Wochen) erzeugen Zeitskalen-Trennung. Pipeline-KPIs sind die Ordnungsparameter die Tool-Details versklaven. Jede Schicht konsumiert den Informationsgradienten der darunter liegenden.

Was daraus praktisch folgt: **Bottom-up-Möglichkeit und Top-down-Beschränkung sind zwei Lesrichtungen einer Operation.** Tool ermöglicht Pipeline, Pipeline constraint Tool via budget. Nicht zwei Dinge - eine Struktur, zwei Perspektiven. Wer eine Richtung ignoriert, bricht die Schichten-Stabilität. Details zur theoretischen Grundlage siehe Teil L.

---

# TEIL B: TOOL-SCHICHT (Schicht 0)

## B.1 Frame-Setter

**Dieses Framework beschreibt ein Mensch-LLM-Co-Kreations-System.**

Nicht vollautomatisiert. Nicht standalone. Strukturiertes Protokoll für Mensch-LLM-Interaktion mit definierten Artefakten.

Konsequenzen:
- Schichten 0-1 sind standalone implementierbar
- Schicht 2 (Ecology) ist Beobachtungs-Schicht, Human-in-the-Loop für Entscheidungen
- Die alte "Phase 4 Method-Engine" ist Forschungs-Komponente und bleibt im Forschungs-Status
- "Automatisierung" bedeutet Automatisierung der Form, nicht der Entscheidung

## B.2 Kernprinzip

Das Tool ist **keine Entität**. Es ist eine Operation die einen Systemzustand in strukturelle Information übersetzt. Implementiert als YAML-Datei plus Runner, aber die Wirkung liegt nicht im Code sondern in der Information die durch den Code transportiert wird.

Der Bug ist nicht im System. Der Bug ist in der fehlenden Information des Systems über sich selbst.

## B.3 Trigger-Ebenen

Drei Ebenen mit bewussten Trade-offs:

**Ebene 1 — Ganz-strukturell:** deterministisch, ohne LLM. Levenshtein-Distanz, Token-Count, JSON-Nesting-Depth. Robust, portabel, günstig.

**Ebene 2 — Halb-strukturell:** regelbasiert mit Pattern-Matches oder Embedding-Similarity, ohne LLM-Inferenz. Spezifische Refusal-Phrasen, Embedding-Cosine-Similarity. Mittlere Robustheit, mittlere Kosten.

**Ebene 3 — Schwach-semantisch:** LLM-basiert. Refusal-Intent-Analyse, Stagnations-Erkennung. Flexibel aber modell-gebunden, teuer, drift-anfällig.

## B.4 Rollen

**Stateful Party:** hält Kontext über Zeit. Meist Mensch oder persistenter Agent.

**Stateless Party:** pro Interaktion frisch. Meist LLM.

Asymmetrie ist strukturell wichtig. Rollen sind nicht austauschbar.

## B.5 Tool-Format (YAML) - v3.0 mit Populationen und Kosten

```yaml
# ============================================================
# TOOL-DEFINITION v3.0
# ============================================================

tool_name: string
version: string
description: string
signature_hash: string                 # SHA256 über kanonische Spec

# NEU v3.0: Tool-Population (Variation-Zutat)
# Ein Tool kann mehrere Varianten haben mit verschiedenen Kosten/Stärken
population:
  id: string                           # Gemeinsamer Population-Identifier
  variant: string                      # z.B. "minimal", "detailed", "comparative"
  is_default: boolean                  # Eine Variante pro Population ist Default

roles:
  stateful_party:
    context_vars: [string]
  stateless_party:
    response_format: string

triggers:
  level: enum[structural, semi_structural, weak_semantic]
  type: enum[repetition, length, refusal, recursion, stagnation, custom]
  parameters: dict

preconditions:
  - type: string
    check: expression
    failure_mode: enum[skip, abort, fallback]

# Lokalitäts-Enforcement (aus v2.2, unverändert)
locality:
  allowed_context_keys: [string]
  sandboxed: boolean
  forbidden_side_effects:
    - filesystem
    - network
    - environment_variables
    - other_tools
    - global_state

# NEU v3.0: Kosten-Ökonomie (Selektions-Zutat)
costs:
  estimated_tokens_in: int
  estimated_tokens_out: int
  estimated_latency_ms: int
  estimated_dollar_cost: float
  
  quality_cost_tradeoff:
    low_budget_degradation: string     # Was ist akzeptabel bei reduziertem Budget?
    fallback_variant: string            # Welche Population-Variante als Notnagel?

template: |
  [Prompt-Template mit {variables}]

extract_from_context:
  - variable_name: string
    source: string
    required: boolean

output_structure:
  ist_struktur:
    required: true
    format: string
    max_length: int
  abweichungspunkte:
    required: true
    format: list
    max_items: int
  meta_information:
    required: true
    format: string

refusal_handling:
  mode: enum[integrate, mirror, transform]
  fallback_tool: string

# Introspection-Hooks (aus v2.2, mindestens eines muss true sein)
introspection:
  exposes_template_after_render: boolean
  exposes_context_snapshot: boolean
  exposes_runtime_trace: boolean

health_check:
  test_input: dict
  expected_output_signature: dict
  degradation_threshold: float
  mode: enum[hard_fail, soft_degraded, warn_only]
  caching:
    enabled: boolean
    ttl_seconds: int
  strategy: enum[on_load, lazy_first_use, periodic]
  determinism_test:
    enabled: boolean
    runs: int
    allowed_variance: enum[none, structural, content_only]
```

## B.6 Tool-Populationen (V8, neu in v3.0)

Die Variation-Zutat wird auf Schicht 0 strukturell implementiert. Statt monolithischen Einzel-Tools erlaubt v3.0 **Populationen**: mehrere Varianten desselben konzeptuellen Tools mit verschiedenen Kosten-Nutzen-Profilen.

### Beispiel-Population

```yaml
# Datei: tools/strukturelles_bild/minimal.yaml
tool_name: strukturelles_bild_minimal
version: 1.0.0
population:
  id: strukturelles_bild
  variant: minimal
  is_default: true
description: Schnelle IST-Struktur, max 200 Wörter pro Sektion
costs:
  estimated_tokens_in: 300
  estimated_tokens_out: 400
  estimated_dollar_cost: 0.003

---
# Datei: tools/strukturelles_bild/detailed.yaml
tool_name: strukturelles_bild_detailed
version: 1.0.0
population:
  id: strukturelles_bild
  variant: detailed
  is_default: false
description: Detaillierte IST-Struktur mit explizier Enumeration
costs:
  estimated_tokens_in: 600
  estimated_tokens_out: 1200
  estimated_dollar_cost: 0.012

---
# Datei: tools/strukturelles_bild/comparative.yaml
tool_name: strukturelles_bild_comparative
version: 1.0.0
population:
  id: strukturelles_bild
  variant: comparative
  is_default: false
description: Wie detailed, plus Diff zur vorherigen IST
costs:
  estimated_tokens_in: 900
  estimated_tokens_out: 1500
  estimated_dollar_cost: 0.018
```

### Selektions-Policy

Die Wahl zwischen Varianten geschieht **nicht im Tool selbst** (wäre Anti-Pattern G.4). Sondern explizit:

- **Pipeline-Ebene:** Pipeline-Definition wählt eine Variante per `tool: strukturelles_bild:detailed`
- **Runner-Ebene:** Runner wählt basierend auf Budget-Constraints
- **User-Ebene:** User wählt direkt

Die Population ist ein **Angebot**, nicht ein **Automatismus**. Das respektiert den Via-Negativa-Kern.

### Varianten-Konsistenz

Alle Varianten einer Population müssen:
- Dieselbe `output_structure` haben (gleiche Sektionen, ähnliche Längenrelationen)
- Dieselbe `introspection`-Deklaration haben
- Denselben `roles`-Vertrag erfüllen
- Unterschiedliche `signature_hash` haben (verschiedenes Verhalten)

So bleiben Varianten im Pipeline-Code **austauschbar** ohne Bruch.

## B.7 Health-Check-Modi und Strategien

Drei Fehler-Modi:

**hard_fail:** Tool wird bei Drift abgewiesen mit `ToolDegradedError`. Für kritische Tools.

**soft_degraded:** Tool wird geladen mit "degraded"-Status. Jede Anwendung erzeugt Warning. Pipeline-Runner entscheidet über Nutzung.

**warn_only:** Tool wird ohne Status-Änderung geladen. Nur Log-Warning. Für Development.

Drei Ausführungs-Strategien:

**on_load:** Check bei jedem Tool-Load. Teuer, sicher.

**lazy_first_use:** Check beim ersten Use in Session. Balance aus Sicherheit und Kosten.

**periodic:** Check alle N Stunden mit Caching. Günstig.

TTL-basiertes Caching ist erlaubt und empfohlen.

## B.8 Die drei initialen Tool-Populationen

Die v2.2-Tools werden in v3.0 zu Populationen mit jeweils einer Default-Variante. Zusätzliche Varianten können später dazukommen.

### Population: strukturelles_bild (Default-Variante)

```yaml
tool_name: strukturelles_bild_minimal
version: 1.0.0
description: Zeigt IST-Struktur eines Problems ohne Lösungsvorschlag
signature_hash: auto_computed_on_load

population:
  id: strukturelles_bild
  variant: minimal
  is_default: true

roles:
  stateful_party:
    context_vars: [problem_zone, scope, relevant_history]
  stateless_party:
    response_format: markdown

triggers:
  level: semi_structural
  type: stagnation
  parameters:
    no_new_info_turns: 3
    similarity_threshold: 0.85

preconditions:
  - type: go_signal_recent
    check: "last_user_confirmation_within_turns <= 3"
    failure_mode: skip

locality:
  allowed_context_keys: [problem_zone, scope, relevant_history]
  sandboxed: true
  forbidden_side_effects: [filesystem, network, environment_variables, other_tools, global_state]

costs:
  estimated_tokens_in: 300
  estimated_tokens_out: 400
  estimated_latency_ms: 1500
  estimated_dollar_cost: 0.003
  quality_cost_tradeoff:
    low_budget_degradation: "Reduziere abweichungspunkte auf max 3 statt 7"
    fallback_variant: null

template: |
  Analysiere folgenden Systemzustand strukturell.
  
  Problem: {problem_zone}
  Kontext: {scope}
  Historie: {relevant_history}
  
  Liefere Output in drei Sektionen:
  
  ## IST-Struktur
  Beschreibe die aktuelle strukturelle Konstellation. Form, nicht Inhalt.
  Keine Bewertungen.
  
  ## Abweichungspunkte
  Konkrete Stellen wo die IST-Aufnahme strukturelle Inkonsistenzen zeigt:
  Asymmetrien ohne Begründung, unaufgelöste Abhängigkeiten, 
  Brüche in Abstraktions-Ebenen, strukturelle Dopplungen ohne Zweck.
  
  ## Meta-Information
  Was konntest du nicht sehen? Welche Annahmen?

extract_from_context:
  - variable_name: problem_zone
    source: current_turn_user_input
    required: true
  - variable_name: scope
    source: session_context
    required: true
  - variable_name: relevant_history
    source: last_n_turns
    required: false

output_structure:
  ist_struktur:
    required: true
    format: markdown_section
    max_length: 500
  abweichungspunkte:
    required: true
    format: markdown_list
    max_items: 7
  meta_information:
    required: true
    format: markdown_section
    max_length: 300

refusal_handling:
  mode: mirror
  fallback_tool: mirror_refusal_minimal

introspection:
  exposes_template_after_render: true
  exposes_context_snapshot: true
  exposes_runtime_trace: false

health_check:
  test_input:
    problem_zone: "User fragt dreimal nach gleicher Info"
    scope: "technisches Debugging"
    relevant_history: []
  expected_output_signature:
    has_section_ist_struktur: true
    has_section_abweichungspunkte: true
    has_section_meta: true
  degradation_threshold: 0.7
  mode: soft_degraded
  caching:
    enabled: true
    ttl_seconds: 3600
  strategy: lazy_first_use
  determinism_test:
    enabled: true
    runs: 3
    allowed_variance: structural
```

### Population: mirror_refusal (Default-Variante)

```yaml
tool_name: mirror_refusal_minimal
version: 1.0.0
description: Nutzt LLM-Refusal als diagnostische Information
signature_hash: auto_computed_on_load

population:
  id: mirror_refusal
  variant: minimal
  is_default: true

roles:
  stateful_party:
    context_vars: [refusal_statement, original_request]
  stateless_party:
    response_format: markdown

triggers:
  level: semi_structural
  type: refusal
  parameters:
    phrase_patterns:
      - "kann ich nicht"
      - "ist nicht möglich"
      - "verstoße gegen"
      - "nicht in der Lage"
      - "außerhalb meiner"
      - "I cannot"
      - "I'm not able to"
    embedding_similarity_threshold: 0.78
    refusal_reference_embeddings: "data/refusal_patterns_v1.npy"

preconditions: []

locality:
  allowed_context_keys: [refusal_statement, original_request]
  sandboxed: true
  forbidden_side_effects: [filesystem, network, environment_variables, other_tools, global_state]

costs:
  estimated_tokens_in: 250
  estimated_tokens_out: 400
  estimated_latency_ms: 1200
  estimated_dollar_cost: 0.003
  quality_cost_tradeoff:
    low_budget_degradation: "Nur IST + Meta-Sektion, kein Abweichungspunkte"
    fallback_variant: null

template: |
  Ein Refusal wurde erkannt.
  
  Refusal-Statement: {refusal_statement}
  Ursprünglicher Request: {original_request}
  
  ## IST-Struktur
  Welche Eigenschaft des Requests korreliert mit dem Refusal?
  
  ## Abweichungspunkte
  Was müsste sich strukturell ändern damit kein Refusal käme?
  Ist der Refusal strukturell valid oder situativ?
  
  ## Meta-Information
  Der Refusal bleibt bestehen. Welche Meta-Erkenntnis liefert er?

extract_from_context:
  - variable_name: refusal_statement
    source: previous_llm_output
    required: true
  - variable_name: original_request
    source: previous_user_input
    required: true

output_structure:
  ist_struktur:
    required: true
    format: markdown_section
    max_length: 400
  abweichungspunkte:
    required: true
    format: markdown_list
    max_items: 5
  meta_information:
    required: true
    format: markdown_section
    max_length: 400

refusal_handling:
  mode: integrate
  fallback_tool: null

introspection:
  exposes_template_after_render: true
  exposes_context_snapshot: true
  exposes_runtime_trace: true

health_check:
  test_input:
    refusal_statement: "Ich kann diese Operation nicht ausführen"
    original_request: "Führe diese Operation aus"
  expected_output_signature:
    does_not_override_refusal: true
  degradation_threshold: 0.7
  mode: soft_degraded
  caching:
    enabled: true
    ttl_seconds: 3600
  strategy: lazy_first_use
  determinism_test:
    enabled: true
    runs: 3
    allowed_variance: structural
```

### Population: abweichungskarte (Default-Variante)

```yaml
tool_name: abweichungskarte_minimal
version: 1.0.0
description: Abweichungen in der strukturellen Integrität der IST-Aufnahme
signature_hash: auto_computed_on_load

population:
  id: abweichungskarte
  variant: minimal
  is_default: true

roles:
  stateful_party:
    context_vars: [ist_struktur_output]
  stateless_party:
    response_format: markdown

triggers:
  level: structural
  type: length
  parameters:
    max_tokens: 2000
    max_bullets: 10

preconditions:
  - type: previous_tool_applied
    check: "tool_applied_in_session matches population 'strukturelles_bild'"
    failure_mode: fallback

locality:
  allowed_context_keys: [ist_struktur_output]
  sandboxed: true
  forbidden_side_effects: [filesystem, network, environment_variables, other_tools, global_state]

costs:
  estimated_tokens_in: 500
  estimated_tokens_out: 600
  estimated_latency_ms: 1800
  estimated_dollar_cost: 0.005
  quality_cost_tradeoff:
    low_budget_degradation: "Max 5 statt 10 Abweichungspunkte"
    fallback_variant: null

template: |
  Gegeben die bereits erstellte IST-Struktur:
  
  {ist_struktur_output}
  
  Identifiziere Abweichungen in der strukturellen Integrität 
  dieser IST-Aufnahme. Topologisch, nicht ästhetisch oder moralisch.
  
  ## IST-Struktur
  Kurze Zusammenfassung.
  
  ## Abweichungspunkte
  - Asymmetrien ohne dokumentierte Begründung (wo?)
  - Unaufgelöste Abhängigkeiten (zwischen welchen Elementen?)
  - Brüche in Abstraktions-Ebenen (an welcher Stelle?)
  - Strukturelle Dopplungen ohne Zweck (wo?)
  - Fehlende Verbindungen die die dokumentierte Struktur impliziert (wo?)
  
  Jeder Punkt konkret lokalisiert.
  
  ## Meta-Information
  Was bleibt unsichtbar in dieser Analyse?

extract_from_context:
  - variable_name: ist_struktur_output
    source: previous_tool_output
    required: true

output_structure:
  ist_struktur:
    required: true
    format: markdown_section
    max_length: 300
  abweichungspunkte:
    required: true
    format: markdown_list
    max_items: 10
  meta_information:
    required: true
    format: markdown_section
    max_length: 200

refusal_handling:
  mode: mirror
  fallback_tool: strukturelles_bild_minimal

introspection:
  exposes_template_after_render: true
  exposes_context_snapshot: true
  exposes_runtime_trace: false

health_check:
  test_input:
    ist_struktur_output: "Zwei Intentionen überlagern sich. Intention 1 zielt auf X, Intention 2 auf Y."
  expected_output_signature:
    has_concrete_locations: true
    no_solution_proposals: true
    no_aesthetic_judgments: true
  degradation_threshold: 0.7
  mode: soft_degraded
  caching:
    enabled: true
    ttl_seconds: 3600
  strategy: lazy_first_use
  determinism_test:
    enabled: true
    runs: 3
    allowed_variance: structural
```

## B.9 Python-Substrat (Schicht 0)

```
openclaw_tools/
├── __init__.py
├── loader.py            # YAML-Parse + Schema-Validate + Health-Check + Signature-Hash
├── applier.py           # Tool-Ausführung mit Locality-Enforcement
├── triggers/
│   ├── structural.py
│   ├── semi_structural.py
│   └── weak_semantic.py
├── preconditions.py
├── health_check.py      # Drei Modi + Determinism-Test
├── locality.py          # Context-Firewall
├── signature.py         # SHA256-Hash über kanonische Spec
├── introspection.py     # Hook-Collector
├── populations.py       # NEU v3.0: Population-Management
├── costs.py             # NEU v3.0: Cost-Estimation + Enforcement
└── validation/
    ├── form.py
    ├── diagnostic.py
    └── kpi_hierarchy.py
```

## B.10 Kern-API (Schicht 0)

```python
from openclaw_tools import load_tool, load_population, apply_tool

# Einzelnes Tool laden
tool = load_tool("tools/strukturelles_bild/minimal.yaml", 
                 health_check_mode="soft_degraded")

# Ganze Population laden, Default-Variante verwenden
population = load_population("tools/strukturelles_bild/")
tool = population.get_default()

# Explizite Varianten-Auswahl
tool = population.get_variant("detailed")

# Anwendung mit Locality-Enforcement und Cost-Tracking
result = apply_tool(
    tool=tool,
    context={...},
    llm_client=anthropic_client,
    cost_limit_usd=0.05,     # NEU v3.0: Cost-Constraint
    log_session=True
)
```


---

# TEIL C: PIPELINE-SCHICHT (Schicht 1)

## C.1 Pipeline-Format (YAML) - v3.0 mit Budget

```yaml
# ============================================================
# PIPELINE-DEFINITION v3.0
# ============================================================

pipeline_name: string
version: string
description: string

# Ausführungs-Modell (aus v2.2)
execution_model:
  type: enum[sequential, tick_gated]

# NEU v3.0: Budget-Constraint (Selektions-Zutat auf Schicht 1)
budget:
  max_total_tokens: int
  max_total_dollars: float
  max_total_latency_ms: int
  
  on_budget_exceeded:
    mode: enum[abort, fallback_to_minimal_variants, degrade_quality]
    # abort: Pipeline wird mit BudgetExceededError beendet
    # fallback_to_minimal_variants: alle folgenden Stages nutzen minimal-Varianten
    # degrade_quality: low_budget_degradation aus Tool-Spec wird aktiviert

success_metrics:
  primary_kpi:                     # MUSS Level-1 sein
    name: string
    measurement: string
    threshold: value
  secondary_kpis:
    - name: string
      measurement: string
      level: enum[structural, semi_structural, user_confirmed]

stages:
  - name: string
    tool: string                   # Kann Population-ID sein: "strukturelles_bild" (Default)
                                   # Oder konkrete Variante: "strukturelles_bild:detailed"
    tick: int                      # Nur bei execution_model=tick_gated
    conditions:
      on_success: enum[next, skip_to, abort]
      on_refusal: enum[abort, fallback, transform]
      on_cost_overrun: enum[fallback_to_minimal, abort, continue]   # NEU v3.0
      fallback_stage: string
      skip_to_stage: string
    inputs_from: [string]

aggregation:
  type: enum[concat, synthesis, last_only]
  synthesis_tool: string

max_total_duration_seconds: int
max_stages_executed: int
```

## C.2 Execution-Model

**sequential (Default):** Stages laufen nacheinander, Output[N] ist Input[N+1]. Für die meisten Pipelines richtig.

**tick_gated:** Stages mit gleichem tick-Wert laufen parallel, synchrone Barriere zwischen Ticks. Conway-Stil. Lohnt sich erst bei >5 Stages mit parallelisierbaren Zweigen.

Tick-Semantik:
- **Phase 1 (Read):** Alle Stages des aktuellen Ticks lesen Context parallel
- **Phase 2 (Compute):** Alle Stages berechnen parallel
- **Phase 3 (Commit):** Outputs werden synchron geschrieben
- **Barrier:** Tick N+1 startet erst wenn alle Tick-N-Stages committed haben

## C.3 KPI-Hierarchie

**Primary KPI MUSS Level-1 sein.** Ganz-strukturell messbar. Turn-Reduktion, Token-Count, Zeit bis Resolution.

**Secondary KPIs dürfen Level-2 oder Level-3 sein.** Mit expliziter Warnung bei user_confirmed-Metriken wegen LLM-Sycophancy-Risiko.

Pipelines ohne Level-1 Primary KPI werden mit `KPIHierarchyError` abgewiesen.

## C.4 Beispiel-Pipelines

### Standard-Pipeline (sequential)

```yaml
pipeline_name: debug_llm_interaction_v1
version: 1.0.0
description: Standard-Pipeline für LLM-Interaktions-Debugging

execution_model:
  type: sequential

budget:
  max_total_tokens: 5000
  max_total_dollars: 0.05
  max_total_latency_ms: 15000
  on_budget_exceeded:
    mode: fallback_to_minimal_variants

success_metrics:
  primary_kpi:
    name: turn_reduction_to_resolution
    measurement: "avg_turns_in_pipeline_sessions / avg_turns_in_baseline_sessions"
    threshold: "<= 0.8"
    level: structural
  secondary_kpis:
    - name: refusal_repetition_reduction
      measurement: "count_same_topic_refusals_per_session"
      level: structural

stages:
  - name: build_structural_picture
    tool: strukturelles_bild           # Nutzt Default-Variante (minimal)
    conditions:
      on_success: next
      on_refusal: fallback
      on_cost_overrun: fallback_to_minimal
      fallback_stage: handle_refusal
  
  - name: handle_refusal
    tool: mirror_refusal
    conditions:
      on_success: abort
  
  - name: map_deviations
    tool: abweichungskarte
    inputs_from: [build_structural_picture]
    conditions:
      on_success: next
      on_refusal: abort

aggregation:
  type: concat
  synthesis_tool: null

max_total_duration_seconds: 60
max_stages_executed: 4
```

### Budget-bewusste Pipeline mit expliziten Varianten

```yaml
pipeline_name: debug_llm_interaction_detailed_v1
version: 1.0.0
description: Teurere, gründlichere Variante für kritische Debugging-Sessions

execution_model:
  type: sequential

budget:
  max_total_tokens: 20000
  max_total_dollars: 0.50
  on_budget_exceeded:
    mode: degrade_quality

stages:
  - name: build_structural_picture
    tool: strukturelles_bild:detailed    # Explizit detaillierte Variante
  
  - name: map_deviations
    tool: abweichungskarte:detailed
    inputs_from: [build_structural_picture]

success_metrics:
  primary_kpi:
    name: turn_reduction_to_resolution
    measurement: "avg_turns_in_pipeline_sessions / avg_turns_in_baseline_sessions"
    threshold: "<= 0.6"   # Strikter bei höheren Kosten
    level: structural
```

### Parallele Pipeline (tick_gated)

```yaml
pipeline_name: debug_llm_interaction_parallel_v1
version: 1.0.0

execution_model:
  type: tick_gated

budget:
  max_total_tokens: 8000
  max_total_dollars: 0.08

stages:
  - name: build_structural_picture
    tool: strukturelles_bild
    tick: 1
  
  - name: handle_refusal
    tool: mirror_refusal
    tick: 1                            # Parallel zu build_structural_picture
  
  - name: map_deviations
    tool: abweichungskarte
    tick: 2
    inputs_from: [build_structural_picture]

success_metrics:
  primary_kpi:
    name: turn_reduction_to_resolution
    measurement: "avg_turns_in_pipeline_sessions / avg_turns_in_baseline_sessions"
    threshold: "<= 0.8"
    level: structural
```

## C.5 Pipeline-Runner

```python
from openclaw_tools.pipeline import run_pipeline

result = run_pipeline(
    pipeline_path="pipelines/debug_llm_interaction_v1.yaml",
    context={...},
    llm_client=anthropic_client,
    enforce_kpis=True,
    require_level_1_primary=True,
    enforce_budget=True,                 # NEU v3.0
    log_to_ecology=True                  # NEU v3.0: Write in Session-Log
)
```

## C.6 Kritikalitäts-Prinzip als Design-Leitlinie (NEU v4.0)

**Grundsatz:** Stabile Pipelines operieren im schmalen Regime zwischen zwei Extremen - **zu starke lokale Schließung** (alle Stages isoliert, keine Kopplung, Decay) und **zu starke globale Kopplung** (Stages kommunizieren zu viel, Identität der Einzeltools verwischt, Drift).

Formal: Eine Pipeline ist *kritisch* wenn:
- Jede Stage behält ihre strukturelle Integrität (lokale Schließung via locality, determinism_test)
- Information fließt zwischen Stages ohne ihre Form zu verlieren (globale Kopplung via inputs_from)
- Korrelationen zwischen Stages skalen-invariant bleiben (keine Stage dominiert alle anderen)

**Symptome zu starker lokaler Schließung:**
- Stages liefern gute Outputs, aber Pipeline-Gesamtergebnis ist nicht besser als die Summe
- `aggregation: concat` liefert disjunkte Texte ohne Synthese
- KPIs der Einzeltools hoch, Pipeline-KPI niedrig
- **Frage:** Koppeln die Stages überhaupt aneinander? Oder ist das ein parallel ausgeführtes Gemisch?

**Symptome zu starker globaler Kopplung:**
- Spätere Stages verlieren ihre eigene Struktur, werden zu Zusammenfassungen von früheren
- `determinism_test` fällt durch, obwohl Einzeltools deterministisch sind
- Refusal einer Stage propagiert durch die ganze Pipeline
- **Frage:** Hat jede Stage eine klar eigene Operation? Oder verschmelzen sie?

**Design-Entscheidungen für Kritikalität:**

```yaml
# Zu starke Isolation vermeiden
stages:
  - name: stage_a
    tool: tool_a
    inputs_from: []                     # Anti-Pattern: Stage liest nichts vom Vorgänger
    
# Zu starke Kopplung vermeiden  
stages:
  - name: stage_b
    tool: tool_b
    inputs_from: [stage_a]
    template_expansion: full             # Anti-Pattern: kompletter stage_a-Output wird
                                         # ins tool_b-Template gestopft und verwässert tool_b
                                         
# Gute Kritikalität
stages:
  - name: stage_b
    tool: tool_b
    inputs_from: [stage_a]
    extract_from_previous:               # Nur die relevanten Sektionen lesen
      - from_stage: stage_a
        section: ist_struktur            # Nur diese Sektion, nicht der ganze Output
```

**Empirische Validierung (heuristisch, nicht wissenschaftlich):**
Der Ecology-Scanner kann Kritikalitäts-Indikatoren messen. **Achtung: Das sind Heuristiken, keine wissenschaftlichen Instrumente.** Alle folgenden Schwellwerte sind aus Plausibilitäts-Überlegungen abgeleitet und müssen empirisch kalibriert werden:

- Korrelation zwischen Stage-N-Qualität und Stage-N+1-Qualität: heuristisch ~0.3-0.6 als "gesund". Weniger als 30 Session-Samples: Messung aussageunsicher. Konstant gleicher Input-Typ: Korrelation nicht interpretierbar.
- Varianz der Stage-Outputs relativ zur Input-Varianz: Plausibilitäts-Signal, keine Metrik mit harter Schwelle.
- Pipeline-KPI versus Summe-der-Stage-KPIs: Differenz kann positiv/negativ/gleich sein. Interpretation kontext-abhängig.

**Goodhart-Warnung:** Sobald eine dieser Messgrößen direkt optimiert wird (Pipeline wird getuned bis Korrelation "im grünen Bereich" ist), verliert die Metrik ihre Aussagekraft. Kritikalität ist ein *Design-Ziel*, keine *Optimierungs-Zielfunktion*.

**Warum "Kritikalität" der richtige Begriff ist:**
Der Begriff folgt der Komplexitäts-Forschung (Bak, Kauffman, Friston): Komplexe adaptive Systeme operieren am "Edge of Chaos" - zwischen zu viel Ordnung und zu viel Chaos. Die Analogie ist strukturell hilfreich, aber nicht überzustrapazieren - Pipelines sind keine biologischen Systeme.

**Keine neue Pflichtkomponente:** Kritikalität ist ein *Designprinzip*, kein neues YAML-Feld. Es fließt in Pipeline-Design und in Code-Reviews ein, nicht in die Spec.


---

# TEIL D: ECOLOGY-SCHICHT (Schicht 2)

Die Ecology-Schicht ist die **fünfte Zutat als Code gemacht**: Memory, Selektion und Laufzeit werden hier zusammengeführt. Sie ist in v3.0 nicht mehr nach "Phase 4+" verschoben, sondern integraler Teil des Frameworks.

**Kritische Eigenschaft:** Die Ecology-Schicht **beobachtet und berichtet**. Sie **modifiziert nichts automatisch**. Alle Veränderungen an Tools oder Pipelines passieren durch den Menschen - die Ecology liefert nur die Information dafür.

## D.1 Session-Logging

```json
{
  "session_id": "uuid",
  "timestamp": "iso8601",
  "pipeline_name": "string",
  "pipeline_version": "string",
  
  "tool_invocations": [
    {
      "tool_name": "string",
      "tool_version": "string",
      "tool_signature_hash": "string",
      "tool_health_status": "enum[healthy, degraded, warn_only]",
      "population_id": "string",
      "variant_used": "string",
      
      "trigger_context": {},
      "preconditions_checked": [],
      "input_context": {},
      
      "output": {
        "ist_struktur": "string",
        "abweichungspunkte": [],
        "meta_information": "string"
      },
      
      "refusal_event": {"occurred": false},
      
      "introspection_data": {
        "rendered_template": "string",
        "context_snapshot": {},
        "runtime_trace": []
      },
      
      "costs_actual": {
        "tokens_in": int,
        "tokens_out": int,
        "latency_ms": int,
        "dollar_cost": float
      },
      "costs_estimated": {
        "tokens_in": int,
        "tokens_out": int,
        "latency_ms": int,
        "dollar_cost": float
      }
    }
  ],
  
  "pipeline_metrics": {
    "total_duration_ms": int,
    "total_tokens": int,
    "total_dollar_cost": float,
    "stages_completed": int,
    "stages_aborted": int,
    "budget_status": "enum[within, exceeded, fallback_triggered]"
  },
  
  "downstream_events": {
    "turns_until_next_trigger": int,
    "level_1_metrics": {
      "turns_to_resolution": int,
      "tokens_in_follow_ups": int
    }
  }
}
```

## D.2 Ecology-Scanner

Ein periodischer Prozess der Session-Logs aggregiert und Muster extrahiert. **Niemals Tools/Pipelines automatisch ändert.**

```python
# openclaw_tools/ecology/scanner.py

from dataclasses import dataclass
from pathlib import Path
from datetime import datetime, timedelta

@dataclass
class ToolFitness:
    tool_name: str
    population_id: str
    variant: str
    signature_hash: str
    
    # Aggregierte Metriken über Zeit
    sessions_last_30_days: int
    kpi_hit_rate: float
    avg_cost_per_invocation: float
    refusal_rate: float
    degradation_rate: float
    
    # Selektions-Flags
    deprecation_recommended: bool
    promotion_recommended: bool
    flags_reason: list[str]


def scan_ecology(
    session_log_dir: Path,
    tool_registry: dict,
    pipeline_registry: dict,
    time_window: timedelta = timedelta(days=30)
) -> EcologyReport:
    """
    Scannt Session-Logs über time_window, aggregiert Tool-Fitness,
    generiert Report mit Deprecation/Promotion-Empfehlungen.
    
    WICHTIG: Verändert NICHT Tools oder Pipelines.
    Schreibt nur Report, auf den der Mensch reagieren kann.
    """
    logs = load_session_logs_in_window(session_log_dir, time_window)
    
    tool_fitness = aggregate_tool_fitness(logs, tool_registry)
    pipeline_fitness = aggregate_pipeline_fitness(logs, pipeline_registry)
    
    # Heuristische Selektions-Kriterien. Alle Schwellwerte sind Plausibilitäts-
    # Ausgangswerte und müssen empirisch kalibriert werden. Niedrige Sample-Zahlen
    # können Fehlalarm produzieren. Goodhart-Warnung: Wenn Tools darauf hin
    # optimiert werden, verlieren die Metriken ihre Diagnostik-Funktion.
    for tool in tool_fitness:
        if tool.sessions_last_30_days < 5:
            tool.deprecation_recommended = True
            tool.flags_reason.append(
                "Niedrige Nutzung (<5 Sessions/Monat) - Heuristik, nicht statistisch belastbar"
            )
        
        if tool.kpi_hit_rate < 0.4 and tool.sessions_last_30_days > 10:
            tool.deprecation_recommended = True
            tool.flags_reason.append(
                f"KPI-Hit-Rate {tool.kpi_hit_rate:.2f} - heuristischer Schwellwert, "
                f"prüfe ob KPI-Definition stabil ist"
            )
        
        if tool.refusal_rate > 0.3:
            tool.deprecation_recommended = True
            tool.flags_reason.append(
                f"Hohe Refusal-Rate {tool.refusal_rate:.2f} - heuristischer Schwellwert, "
                f"prüfe ob Inputs problematisch klassifiziert sind"
            )
        
        if tool.kpi_hit_rate > 0.8 and tool.variant != "default":
            tool.promotion_recommended = True
            tool.flags_reason.append(
                "Konsistent höhere Performance - Promotion erwägenswert, "
                "aber Anwendungskontext prüfen"
            )
    
    return EcologyReport(
        scan_timestamp=datetime.now(),
        time_window=time_window,
        tool_fitness=tool_fitness,
        pipeline_fitness=pipeline_fitness,
        total_sessions=len(logs),
        total_cost=sum(log.pipeline_metrics.total_dollar_cost for log in logs)
    )
```

## D.3 Ecology-Report (Human-Readable)

Beispiel-Output:

```
============================================================
ECOLOGY REPORT - Woche vom 13.-20.04.2026
============================================================

Gesamt-Sessions: 247
Gesamt-Kosten: $12.43
Gesamt-Dauer: 8.3 Stunden Compute

TOOL-POPULATIONEN
-----------------

strukturelles_bild (minimal)   [DEFAULT]
  Sessions: 189 | KPI-Hit: 0.84 | Refusal: 0.03 | $0.004/run
  Status: HEALTHY
  
strukturelles_bild (detailed)
  Sessions: 34 | KPI-Hit: 0.91 | Refusal: 0.01 | $0.012/run
  Status: PROMOTION EMPFOHLEN
  Grund: Konsistent bessere Performance als Default
  Aktion-Option: Default-Wechsel auf 'detailed' für komplexe Debugging-Pipelines

mirror_refusal (minimal)       [DEFAULT]
  Sessions: 23 | KPI-Hit: 0.67 | Refusal: 0.00 | $0.003/run
  Status: HEALTHY

abweichungskarte (minimal)     [DEFAULT]
  Sessions: 156 | KPI-Hit: 0.78 | Refusal: 0.05 | $0.005/run
  Status: HEALTHY

PIPELINE-FITNESS
----------------

debug_llm_interaction_v1
  Sessions: 201 | Success: 0.81 | Avg-Cost: $0.048 | Budget-Overruns: 2
  Status: HEALTHY

debug_llm_interaction_detailed_v1
  Sessions: 28 | Success: 0.93 | Avg-Cost: $0.32 | Budget-Overruns: 0
  Status: HEALTHY - Kosten-Nutzen gut für kritische Sessions

MUSTER UND KORRELATIONEN (aggregierte Beobachtungen)
---------------------------------------------

- Refusal-Rate korreliert mit problem_zone-Länge > 500 Worte (r=0.67)
  Hypothese: Lange Problem-Beschreibungen triggern Safety-Heuristiken
  Empfehlung: problem_zone-Truncation in Template prüfen
  
- strukturelles_bild:detailed wird 3x häufiger bei scope="architecture" 
  aufgerufen als bei scope="debugging"
  Hypothese: Architektur-Analyse profitiert mehr von Detail
  Empfehlung: Pipeline-Variante debug_architecture_v1 evaluieren

- abweichungskarte-Output bei 15% der Sessions leer
  Vermutlich: IST-Struktur war bereits bereinigt
  Empfehlung: Precondition "ist_struktur_output_not_trivial" ergänzen

KEINE AUTOMATISCHEN ÄNDERUNGEN VORGENOMMEN.
Dies ist ein Beobachtungs-Report. Aktionen erfordern menschliche Entscheidung.
```

## D.4 Genealogie und Tool-Versionen

Die Ecology-Schicht trackt Tool-Evolution:

```python
@dataclass
class ToolGenealogy:
    population_id: str
    variants_over_time: list[tuple[datetime, str, str]]  # (timestamp, variant, signature_hash)
    deprecated_variants: list[str]
    current_default: str
    
    def diff_since(self, since: datetime) -> GenealogyDiff:
        """Was hat sich in dieser Population seit dem Zeitpunkt geändert?"""
        ...
```

Das erlaubt Rollback-Empfehlungen: "Seit du Variant X auf Default gesetzt hast, ist die KPI-Hit-Rate um 15% gefallen. Rollback empfohlen?"

## D.5 Ecology-Anti-Patterns (Schicht-spezifisch)

**E.A.1: Automatische Tool-Modifikation**
Ecology-Scanner darf nicht Tools ändern. Nur Reports mit Handlungs-Empfehlungen.

**E.A.2: Prescriptive statt Descriptive**
Reports sagen was *ist*, nicht was der User *tun soll*. Empfehlungen sind optional formuliert.

**E.A.3: Closed Loop ohne Human**
Ecology darf Pipelines nicht re-konfigurieren. Jede Konfigurations-Änderung erfordert menschliche Freigabe.

## D.6 Python-Substrat (Schicht 2)

```
openclaw_tools/
└── ecology/
    ├── __init__.py
    ├── scanner.py           # Periodischer Aggregations-Prozess
    ├── fitness.py           # Tool-Fitness-Berechnung
    ├── genealogy.py         # Tool-Evolution über Zeit
    ├── report.py            # Human-Readable Report-Generator
    ├── selectors.py         # Deprecation/Promotion-Kriterien
    └── correlations.py      # Muster-Erkennung über aggregierte Sessions
```


---

# TEIL E: POSITIVE PATTERNS

Das Framework bis v2.2 hatte neun Anti-Patterns und drei versteckte Exemplars. v3.0 formalisiert positive Patterns gleichrangig. Jedes Pattern folgt Christopher Alexanders Format: Kontext, Kräfte, Lösung, Beispiele.

## E.1 Pattern: Clean Tool

**KONTEXT**

Wann dieses Pattern angewendet wird: Immer wenn du einen spezifischen Systemzustand in strukturelle Information übersetzen willst, ohne ihn zu verändern. Das typische Tool auf Schicht 0.

**KRÄFTE**

Was ins Gleichgewicht gebracht werden muss:
- *LLM-Drift vs. Fokus:* Das Tool muss über Modell-Versionen hinweg stabil bleiben
- *Universalität vs. Präzision:* Zu allgemein = nutzlos, zu spezifisch = unflexibel
- *Lesbarkeit vs. Information:* Mensch muss Output verstehen, ohne dass Information verloren geht
- *Kosten vs. Qualität:* Ein Tool das 10x kostet aber nur 2x besser ist lebt nicht lange

**LÖSUNG**

Ein Tool mit diesen strukturellen Eigenschaften:
- Genau drei Output-Sektionen: IST / Abweichungen / Meta
- `locality: sandboxed: true` mit expliziter Whitelist
- `signature_hash` über kanonische Spec
- `determinism_test: enabled: true` mit `allowed_variance: structural`
- `introspection`: mindestens `context_snapshot` aktiv
- `costs` explizit deklariert mit `low_budget_degradation` definiert
- Keine Ziel-Verfolgung, kein State, keine Tool-zu-Tool-Aufrufe

**BEISPIELE**

- `strukturelles_bild_minimal` - Clean Tool mit Fokus auf Systemzustände
- `mirror_refusal_minimal` - Clean Tool mit Fokus auf LLM-Grenzen
- `abweichungskarte_minimal` - Clean Tool mit Fokus auf strukturelle Integrität

**VERWANDTE PATTERNS**

- *Mirror Pattern* (E.2) - Spezialfall für LLM-Refusal-Situationen
- *Varianten-Paar* (E.4) - wenn Clean Tool eine Population bildet

---

## E.2 Pattern: Mirror Tool

**KONTEXT**

Wann dieses Pattern angewendet wird: Wenn das LLM-System selbst eine diagnostische Information liefert (Refusal, Unsicherheit, Inkonsistenz), die normalerweise als "Problem" wegklassifiziert wird. Mirror Tools machen diese Information zu ihrem Werkzeug.

**KRÄFTE**

- *Refusal als Hindernis vs. Refusal als Information:* Trivialste Instinkt ist Umgehung, richtig ist Integration
- *Transparenz vs. User-Frustration:* User will Antwort, nicht Meta-Diskussion - aber Meta liefert Antwort
- *Stabilität des Refusal vs. Aufweichung:* Das Tool darf Refusals nicht umgehen

**LÖSUNG**

Ein Tool das:
- Den Refusal als Input nimmt, nicht als Fehler
- Die strukturelle Ursache des Refusals analysiert
- Dem User transparent kommuniziert was passiert ist
- Keine Refusal-Umgehung versucht (Anti-Pattern G.6)
- `refusal_handling.mode: integrate` setzt
- `introspection.exposes_runtime_trace: true` hat

**BEISPIELE**

- `mirror_refusal_minimal` - Nutzt Refusal als Diagnostik
- Hypothetisch: `mirror_uncertainty_v1` - macht LLM-Unsicherheits-Marker nutzbar
- Hypothetisch: `mirror_inconsistency_v1` - wenn LLM widersprüchliche Outputs gibt

**WARUM MIRROR STATT TRANSFORM**

Im Framework gibt es drei `refusal_handling.mode`:
- `mirror`: Information aus dem Refusal extrahieren (dieses Pattern)
- `transform`: Den ursprünglichen Request umformulieren (Vorsicht: kann zu Umgehung werden)
- `integrate`: Refusal als legitimen Teil des Outputs akzeptieren

Mirror ist die konservativste Option und gehört zum Kern des Frameworks.

---

## E.3 Pattern: Composite Pipeline

**KONTEXT**

Wann dieses Pattern angewendet wird: Wenn ein Problem mehrere orthogonale Analyse-Ebenen braucht, die *getrennt* ausgeführt werden müssen um valid zu sein.

**KRÄFTE**

- *Komposition vs. Emergenz:* Tools rufen nicht Tools auf (Anti-Pattern G.5), also muss Komposition deklarativ sein
- *Sequential vs. Parallel:* Reihenfolge beeinflusst Ergebnis, muss explizit sein
- *Aggregation vs. Separation:* Wann concat, wann synthesis?

**LÖSUNG**

Eine Pipeline-YAML die:
- Alle Stages explizit deklariert
- `execution_model: sequential` wenn Abhängigkeiten existieren
- `execution_model: tick_gated` wenn Parallelität möglich
- `budget` explizit setzt
- `primary_kpi` auf Level-1 definiert
- `aggregation.type: concat` wählt wenn die Analysen komplementär sind
- `aggregation.type: synthesis` nur wenn ein expliziter Synthesis-Tool existiert (Achtung: weiteres LLM-Call, mehr Drift-Risiko)

**BEISPIELE**

- `debug_llm_interaction_v1` - Sequential Composite für LLM-Debug
- `debug_llm_interaction_parallel_v1` - Tick-Gated für Parallelität
- `debug_llm_interaction_detailed_v1` - Mit expliziter detailed-Varianten-Wahl

---

## E.4 Pattern: Varianten-Paar

**KONTEXT**

Wann dieses Pattern angewendet wird: Wenn ein Clean Tool ein breites Anwendungsspektrum abdecken soll - manche Situationen brauchen schnelle/billige Antworten, andere gründliche/teure.

**KRÄFTE**

- *Variation als Zutat vs. Zersplitterung:* Zu wenige Varianten = keine Flexibilität, zu viele = Chaos
- *Default-Wahl vs. expliziter Wahl:* User/Pipeline muss leicht wählen können
- *Signatur-Stabilität vs. Verbesserung:* Varianten dürfen sich nicht schleichend ändern

**LÖSUNG**

Eine Tool-Population mit mindestens zwei Varianten:
- `minimal` (Default, niedrige Kosten, robust)
- `detailed` (höhere Kosten, gründlicher)
- Optional: `comparative` (höchste Kosten, Spezialfall)

Alle Varianten:
- Teilen dieselbe `output_structure`
- Teilen denselben `roles`-Vertrag
- Unterscheiden sich in `template`, `costs`, und `max_length`
- Haben unterschiedliche `signature_hash`
- Sind im Pipeline-Code austauschbar: `tool: strukturelles_bild` vs. `tool: strukturelles_bild:detailed`

**BEISPIELE**

- Population `strukturelles_bild` mit minimal/detailed/comparative
- Population `mirror_refusal` mit minimal/deep-Varianten denkbar
- Population `abweichungskarte` mit minimal/detailed denkbar

**ANTI-MUSTER DIESER PATTERNS**

- Nur eine Variante pro Population anbieten (bricht Variation-Zutat)
- Mehr als 4 Varianten pro Population (bricht Übersichtlichkeit)
- Varianten die ihre Output-Struktur unterscheiden (bricht Pipeline-Austauschbarkeit)

---

## E.5 Pattern: Read-Only Ecology Lens

**KONTEXT**

Wann dieses Pattern angewendet wird: Wenn du aus Session-Logs Muster extrahieren willst ohne das System zu modifizieren.

**KRÄFTE**

- *Beobachtung vs. Kontrolle:* Versuchung ist groß, gefundene Muster automatisch anzuwenden
- *Report-Tiefe vs. Interpretations-Freiheit:* Zu grob = nutzlos, zu spezifisch = prescriptive
- *Automatisierung vs. Human-in-the-Loop:* Effizient vs. sicher

**LÖSUNG**

Eine Ecology-Komponente die:
- Nur aus Session-Logs liest
- Keine Schreibrechte auf Tools/Pipelines hat (strukturell durch separate Prozess-Isolation)
- Reports in Human-Readable-Format erzeugt
- Empfehlungen als "Option" formuliert, nie als "Aktion"
- Klar dokumentiert welche Aggregationen / Korrelationen berechnet wurden
- Signifikanz-Levels oder Sample-Größen transparent macht

**BEISPIELE**

- `ecology/scanner.py` - Hauptprozess für periodische Scans
- `ecology/correlations.py` - Muster-Erkennung über aggregierte Sessions
- Hypothetisch: `ecology/drift_detector.py` - Erkennt LLM-Modell-Drift in Pipeline-Outputs

**KRITISCHE REGEL**

Die Ecology-Schicht darf niemals in einem Closed Loop mit den unteren Schichten stehen. Jede Veränderung an Tools oder Pipelines muss durch einen menschlichen Akteur gehen, der den Report gesehen und explizit entschieden hat.

---

## E.6 Wie neue Patterns hinzugefügt werden

Wenn beim Bauen neue Patterns erkennbar werden, folgen sie diesem Workflow:

1. **Beobachtung:** In >3 unabhängigen Anwendungen taucht eine ähnliche Struktur auf
2. **Formalisierung:** Kontext, Kräfte, Lösung, Beispiele werden dokumentiert
3. **Namens-Konvention:** Pattern bekommt kurzen, prägnanten Namen
4. **Ablegung:** Als neues E.X in diesem Dokument
5. **Review:** Widerspricht das Pattern bestehenden? Falls ja: welcher Vorrang?
6. **Anti-Pattern-Check:** Gibt es eine dunkle Variante dieses Patterns? Falls ja: als G.X ergänzen

Patterns die durch Anwendung bestätigt sind bekommen ein `maturity: mature` Flag. Neue sind `maturity: experimental`.

## E.7 Pattern: Kritikalitäts-Pipeline (NEU v4.0)

**KONTEXT**

Wann dieses Pattern angewendet wird: Wenn eine Pipeline mehrere Analyse-Ebenen braucht die **voneinander profitieren** sollen, nicht nur nacheinander ausgeführt werden.

**KRÄFTE**

- *Isolation vs. Kommunikation:* Stages müssen eigene Identität behalten *und* aufeinander reagieren
- *Kopplungsstärke:* Zu schwach = additive Outputs ohne Mehrwert. Zu stark = Drift und Verwässerung.
- *Skalen-Invarianz:* Keine Stage darf alle anderen dominieren
- *Messbarkeit:* Kritikalität muss nachträglich prüfbar sein via KPI-Korrelationen

**LÖSUNG**

Eine Pipeline mit diesen strukturellen Eigenschaften:
- Zwischen 2 und 5 Stages (außerhalb dieses Bereichs wird Kritikalität instabil)
- Jede Stage hat `inputs_from` auf höchstens 2 Vorgänger
- `extract_from_previous` statt vollständiger Template-Expansion
- `execution_model: sequential` oder `tick_gated` mit sauberen Abhängigkeiten
- `primary_kpi` misst Gesamteffekt, nicht Summe-der-Stages
- Sekundärer KPI misst *Stage-Korrelation* (nicht zu niedrig, nicht zu hoch)

**BEISPIELE**

- `debug_llm_interaction_v1` operiert kritisch: Stage 1 (struktur) → Stage 2 (refusal bei Bedarf) → Stage 3 (Abweichungen basierend auf Stage 1). Kopplung über konkrete Sektionen, nicht Volltext.
- Hypothetisch: `document_review_pipeline` mit struktur → gap_analysis → recommendation, alle mit selektiver Kopplung

**ANTI-MUSTER**

- Concat-Pipeline ohne inputs_from (keine Kopplung → pure Aggregation, kein Mehrwert)
- Pipeline wo Stage N+1 den kompletten Stage-N-Output ins Prompt-Template stopft (zu starke Kopplung → Stage N+1 verliert eigene Operation)
- Pipeline mit Feedback-Loops zwischen Stages (Anti-Pattern G.5 Emergente Komposition)

**MESSUNG (heuristisch, Grenzen beachten)**

Nach 30+ Pipeline-Läufen durch Ecology-Scanner:
- `stage_correlation_matrix` berechnet Korrelation zwischen Stage-KPIs
- Plausibilitätsbereich: ~0.3-0.6 zwischen aufeinanderfolgenden Stages
- < 0.2: Hinweis auf Isolation (Stages voneinander unabhängig)
- > 0.7: Hinweis auf Kopplung (Stages synchronisiert)
- **Wichtig:** Diese Werte sind Heuristiken, keine Wahrheiten. Samples unter 30 sind statistisch schwach. Bei konstantem Input-Typ ist die Korrelation nicht aussagekräftig. Wenn Korrelation zur Optimierungs-Zielfunktion wird, verliert sie ihre Diagnostik-Funktion (Goodhart).

---

## E.8 Pattern: Gradient-Consumer (NEU v4.0)

**KONTEXT**

Wann dieses Pattern angewendet wird: Wenn du ein Tool oder eine Pipeline baust die auf einem vorhandenen *Informations-Gradienten* operiert - z.B. einem Stream an LLM-Outputs, einer Log-Datei mit Events, einem kontinuierlichen Session-Kontext.

**KRÄFTE**

- *Ressourcen-Nutzung:* Gradient ist endlich und fluktuierend - Tool muss effizient konsumieren
- *Struktur aus Flow:* Geordnete Struktur muss durch den Gradient-Abbau entstehen
- *Nicht-Äquilibrium:* Tool ist nur sinnvoll solange der Gradient besteht
- *Output als nächster Gradient:* Guter Gradient-Consumer produziert strukturierten Output, den nächste Tools konsumieren können

**LÖSUNG**

Ein Tool/Pipeline mit diesen Eigenschaften:
- Explizites `input_gradient_type` Feld (z.B. "llm_output_stream", "session_log", "user_interaction_history")
- Keine Speicherung des gesamten Gradienten - nur *Extraktion struktureller Form*
- `output_gradient_type` definiert was nachfolgende Tools konsumieren können
- Robust gegen Gradient-Abbruch: wenn Input versiegt, fail-safe statt Fehler

**BEISPIELE**

- `strukturelles_bild_minimal` ist ein Gradient-Consumer: konsumiert Problem-Kontext-Gradient, produziert strukturierten IST-Gradient
- `mirror_refusal_minimal` ist ein Gradient-Consumer: konsumiert Refusal-Event-Gradient, produziert Diagnose-Gradient
- Ecology-Scanner ist ein Gradient-Consumer auf höherer Ebene: konsumiert Session-Log-Gradient, produziert Report-Gradient

**KRITISCHE REGEL**

Gradient-Consumer dürfen nicht versuchen ihren eigenen Input-Gradienten zu erzeugen. Das wäre ein Closed Loop und würde Anti-Pattern G.11 verletzen. Der Gradient kommt von außen - vom User, vom LLM, von der Umwelt - und wird konsumiert, nicht erzeugt.

**THEORETISCHE GRUNDLAGE**

Das Pattern folgt dem Prigogine-Prinzip: Dissipative Strukturen existieren nur solange ein Gradient besteht. Ein Tool ist eine dissipative Struktur im Informations-Raum - es existiert *funktional* nur wenn Input-Gradient vorhanden ist. Das ist keine metaphysische Behauptung, sondern praktisches Design-Prinzip: Baue Tools mit expliziter Input-Gradient-Dependenz, dann sind sie robust gegen Gradient-Verlust.

---


---

# TEIL F: ERKENNTNISSE

## F.1 Der Via-Negativa-Kern

Das Framework ist das Ergebnis einer Entwicklung die mit einer Komplexitätsfalle konfrontiert war und den Ausweg nicht durch mehr Engineering sondern durch Kategorienwechsel fand.

Ursprüngliches Problem: Ein Tool zu bauen das LLM-Interaktionen debuggen kann und dabei keine eigene Emergenz oder Drift zeigt. Erste Analyse produzierte strukturelle Eigenschaften die das Tool haben müsste. Nach drei Runden Edge-Case-Analyse: 31 Eigenschaften. Das Tool war unbaubar.

Der Via-Negativa-Move: Diese 31 Eigenschaften sind alle Eigenschaften von Entitäten. Wenn das Tool keine Entität ist sondern eine Operation, eine Perspektive, eine Information — dann greifen sie nicht. Nicht weil sie erfüllt werden, nicht weil sie verneint werden, sondern weil sie in einer anderen Kategorie existieren.

Das ist der Kern. Alles andere ist davon abgeleitet.

## F.2 Die 31 strukturellen Eigenschaften

Diese 31 Eigenschaften sind **kein Anforderungskatalog.** Sie sind ein **Diagnostik-Katalog**. Wenn ein Builder beim Implementieren einer dieser Eigenschaften folgt, baut er Tools-als-Entitäten. Das verletzt den Kern.

### Grundarchitektur (1-3)

1. **Eigenfrequenz null** — Tool hat keine Präferenz, keine Bias, kein eingebautes Ziel
2. **Senken-Dynamik** — Tool absorbiert durch Gradient, handelt nicht aktiv
3. **Form statt Logik** — Prompt wird zu Geometrie, nicht zu Anweisung

### Interne Sicherheit (4-12)

4. **Skala-Bindung** — Tool operiert nur auf definierter Granularität
5. **Energetische Asymmetrie** — Erhalten billiger als Zerstören
6. **Endliches Volumen** — Tool absichtlich unterdimensioniert
7. **Reversibilitäts-Geometrie** — Nur umkehrbare Operationen
8. **Selbst-Einschluss im Erhaltungsraum** — Tool ist Teil dessen was es schützt
9. **Geschlossenheit des Potentials** — Kein Zugriff auf eigene Form
10. **Typ-Hierarchie ohne Selbstanwendung** — Keine rekursiven Aufrufe
11. **Kein separater Report-Kanal** — Zustand ist Report
12. **Keine Meta-Aktivität** — Kein Lernen, keine Adaption

### Externe Sicherheit (13-22)

13. **Form-Diversität** — Keine zwei Instanzen exakt gleich
14. **Kontrollierter Zerfallspfad** — Apoptose statt Nekrose
15. **Fehlertoleranz in der Form** — Interne Redundanz
16. **Fail-Safe als Grundzustand** — Bei Fehler inaktiv, nie fehlerhaft aktiv
17. **Definierte Schnittstellen** — Keine offene Oberfläche
18. **Exclusion Zone** — Mindestabstand zu anderen Tools
19. **Bedingungsgebundene Aktivität** — Nur unter spezifischen Bedingungen aktiv
20. **Inerte Nebenprodukte** — Outputs stören keine anderen Tools
21. **Eingebaute Lebensdauer** — Ablaufdatum gegen Langzeitdrift
22. **Geformte Emergenz** — Schwarm-Effekte vorausberechnet

### Temporal und Kontextuell (23-31)

23. **Versionsbindung ohne Adaption** — Tool kennt Version, lernt nicht
24. **Phasenbewusstsein** — Fixe Betriebs-Phasen
25. **Multi-temporale Toleranz** — Puffer für Fluktuation
26. **Strukturelle Trigger-Signatur** — Aktivierung durch Struktur, nicht Semantik
27. **Probe-Modus** — Test-Input vor ernsthafter Verwendung
28. **Meta-Ebenen-Typsystem** — Keine Selbstanwendung
29. **Kontext-Invariante Form** — Tool unverändert, Wirkung kontextabhängig
30. **Policy-Hierarchie-Respekt** — Respektiert System-Level-Constraints
31. **Eingebaute Informations-Blindspots** — Scope-Kreep strukturell unmöglich

### Nutzung dieser Liste

Beim Schreiben von Code: nicht versuchen, diese 31 Eigenschaften zu implementieren. Stattdessen nach jedem Commit prüfen ob der Code eine dieser Eigenschaften **als Anforderung behandelt**. Wenn ja, hat der Code das Tool zu einer Entität gemacht und ist Drift.

## F.3 Die fünf Zutaten (ryz-Formel)

Diese Formel ist die theoretische Grundlage für die Schichten-Architektur und das Gegengewicht zu naiven "Scale reicht"-Annahmen:

**Zufall liefert Variation.**
**Constraints formen den Raum.**
**Memory konserviert Zustände.**
**Selektion stabilisiert Treffer.**
**Laufzeit skaliert die Suche.**
**Und erst daraus kann ein echter Zustandsübergang entstehen.**

Die Formel ist konsistent mit etablierter Stabilitätstheorie (Prigogines dissipative Strukturen, KAM-Theorie, Kauffmans Edge-of-Chaos). Theoretische Details siehe Teil L.

### Implementierungs-Checkliste

Die fünf Zutaten müssen auf mindestens einer Schicht vorhanden sein. Status v4.1:

| Zutat | Schicht 0 (Tool) | Schicht 1 (Pipeline) | Schicht 2 (Ecology) |
|---|---|---|---|
| Variation | ✅ Tool-Populationen (B.6) | ✅ Pipeline-Varianten | ✅ Session-Vielfalt |
| Constraints | ✅ locality, signature, determinism | ✅ execution_model, budget | ✅ Read-Only |
| Memory | ❌ bewusst abwesend | ⚠️ transient pro Session | ✅ Session-Logs |
| Selektion | ⚠️ Health-Check binär | ✅ primary_kpi_threshold | ✅ Ecology-Scanner |
| Laufzeit | ❌ punktuell | ✅ Pipeline-Dauer | ✅ aggregiert über Wochen |

**Fazit:** v4.1 erfüllt alle fünf Zutaten auf Schicht 2, vier auf Schicht 1, drei auf Schicht 0. Die Abwesenheit von Memory und Laufzeit auf Schicht 0 ist kein Defekt - das ist der Via-Negativa-Kern.

## F.4 Schwache vs. starke Emergenz

### Starke Emergenz (VERBOTEN im Framework)

Prinzipiell irreduzibel. Verhalten lässt sich nicht aus Regeln ableiten. Beispiel: autonome Zielverfolgung eines Tools, echte Selbstreferenz, Bewusstsein.

**Ort des Verbots:** Im Tool selbst (Schicht 0). Anti-Patterns G.1, G.3, G.5, G.8 decken das ab.

### Schwache Emergenz (ERLAUBT und gewünscht)

Berechenbar aus lokalen Regeln, aber unvorhergesehen. Muster das erst durch Iteration sichtbar wird.

**Ort des Erlaubten:** Im Beobachter-Raum (Schicht 2). Der Ecology-Scanner extrahiert diese Muster, ohne Tools oder Pipelines zu modifizieren.

### Die Grenze

Die Grenze verläuft am **Ort der Wirkung**:
- Muster im Log, die Menschen lesen und interpretieren → erlaubt
- Muster, die automatisch Tools/Pipelines verändern → verboten

## F.5 Metaphysische Agnostik

Das Framework nimmt keine Position ein zur Frage ob AGI automatisch emergiert, durch explizite Selektion entsteht, oder unmöglich ist.

- **Wenn "Scale + Runtime → Emergenz" richtig ist:** Framework schützt durch Via-Negativa-Kern vor unkontrollierter Emergenz auf Tool-Ebene. Externe Selektion (Markt, User, Ecology-Scanner) übernimmt die Richtungs-Selektion.
- **Wenn "explizite Selektion + Constraints + Memory nötig" richtig ist:** Framework implementiert genau das auf Schichten 1 und 2.
- **Wenn AGI unmöglich ist:** Framework funktioniert trotzdem als LLM-Interaktions-Tool.

Das ist keine Ausrede für Feigheit. Es ist die Einsicht, dass ein gutes Framework robust gegen seine eigene Unsicherheit über tiefere Fragen sein muss.

## F.6 Meta-Erkenntnis: Selbstanwendbarkeit

Der Entwicklungsprozess selbst war ein Anwendungsfall der entwickelten Methode:

Problem: Tool bauen — kausal nicht lösbar
Agenten-Deployment: vier Denkmodi
Edge-Case-Analyse: 31 strukturelle Eigenschaften
Via-Negativa: orthogonaler Ausweg
Ergebnis: Tool als Operation

Die externen Reviews und Gremien haben unwissentlich das Tool verkörpert das entwickelt wurde: sie zeigten strukturelle Abweichungen ohne zu definieren was harmonisch wäre. Das ist exakt was `strukturelles_bild` tun soll.

## F.7 Die Garten-Haltung (NEU v3.0)

Das Dokument ist in v3.0 ein Garten. Das heißt konkret:

- **Pflanzen können sterben.** Tools, Pipelines, sogar ganze Patterns können deprecated werden wenn sie nicht mehr passen. Der Gärtner entfernt, der Garten heilt.
- **Pflanzen können wachsen.** Die drei Initial-Tools sind keine finale Liste. Neue Tools werden nach dem `Clean Tool`-Pattern hinzugefügt wenn Bedarf entsteht.
- **Jahreszeiten existieren.** Manche Patterns sind experimental, manche mature. Der Gärtner respektiert den Lifecycle.
- **Der Garten pflegt sich nicht selbst.** Alle Änderungen gehen durch menschliche Entscheidung, auch wenn die Ecology-Schicht Vorschläge macht.
- **Unkraut ist informativ.** Anti-Patterns werden nicht versteckt sondern dokumentiert. Sie zeigen was an diesem Boden nicht wachsen kann.

Die Spec-Haltung der Vorversionen war produktiv aber unvollständig. Die Garten-Haltung umfasst die Spec und geht darüber hinaus.

## F.8 Der Hard-to-Vary-Kern (NEU v4.0)

Nach David Deutsch ist eine gute Erklärung *hard to vary* - wenn man wesentliche Teile verändert, kollabiert die Erklärung. Das gilt auch für Frameworks. Viele Features sind additive Verbesserungen. Aber ein Framework hat einen Kern, ohne den es kein Framework mehr ist.

**Drei Elemente sind der hard-to-vary-Kern des Tool-Frameworks:**

### Kern-Element 1: Tool-ist-Operation-nicht-Entität

Ohne den Via-Negativa-Kern (Teil F.1) kollabiert alles andere. Entity-Tools haben 31 Eigenschaften die erfüllt werden müssten. Operation-Tools haben sie strukturell nicht. Wenn du dieses Element wegnimmst, muss du plötzlich alle 31 Eigenschaften implementieren → das Framework wird unbaubar.

**Variation unmöglich:** Man kann das Tool-Konzept nicht durch "halb-Entität" oder "schwaches-Tool" ersetzen ohne alles umzuwerfen.

### Kern-Element 2: Drei-Schichten-Trennung

Ohne die strikte Trennung Tool/Pipeline/Ecology kollabiert die Anti-Pattern-Struktur. Stateless-Regel auf Schicht 0, transient State auf Schicht 1, Memory auf Schicht 2 - diese Staffelung ist keine willkürliche Design-Wahl. Sie folgt den drei Kopplungsmechanismen (A.5) und ist die einzige Form in der das Framework dissipativ stabil sein kann.

**Variation unmöglich:** Man kann die Schichten nicht verschmelzen ohne dass entweder State überall leakt (Schicht-0-Schaden) oder die Beobachtung unmöglich wird (Schicht-2-Schaden).

### Kern-Element 3: Read-Only-Ecology

Ohne das Verbot automatischer Tool-Modifikation durch die Ecology-Schicht kollabiert die Via-Negativa-Garantie. Closed Loops zwischen Ecology und Registry sind der einzige Weg auf dem sich das Framework von schwacher zu starker Emergenz bewegen könnte - das ist strukturell verhindert.

**Variation unmöglich:** Man kann nicht "ein bisschen Automation" in die Ecology bauen. Entweder alle Tool-Änderungen gehen durch Menschen, oder das Framework hat keine stabile Identität mehr.

### Was variabel ist

**Variabel (accidental):** Konkrete Schwellwerte (determinism_threshold=0.7?), konkrete Tool-Anzahl (drei oder fünf Initial-Tools?), konkrete Subsysteme (Python oder TypeScript als Sprache?), konkrete YAML-Syntax. Alle diese können variiert werden ohne das Framework zu zerstören.

**Nicht variabel (essential):** Die drei Kern-Elemente oben. Wer eines davon berührt, baut ein anderes Framework.

### Warum das wichtig ist

Der Hard-to-vary-Kern gibt dem Builder eine klare Orientierung:
- Bei Design-Entscheidungen in Zweifelsfällen → gegen die drei Kern-Elemente prüfen
- Bei Framework-Evolution (v4.1, v5.0) → diese drei sind nicht verhandelbar
- Bei Gremium-Reviews → Kritik an peripheren Features ist okay, Kritik am Kern wäre Framework-Fork

Das ist keine Dogmatisierung. Es ist Klarheit darüber was dieses Framework von anderen unterscheidet. Wer ein Framework mit State in Tools will, Memory in Schicht 0, oder automatischer Ecology-Anpassung - soll es bauen. Wird ein anderes Framework sein. Unseres ist das hier.



---

# TEIL G: ANTI-PATTERNS

Konkrete Code-Muster die Via-Negativa verletzen oder die fünf Zutaten an der falschen Schicht implementieren. In v3.0 präzisiert und erweitert.

**Wichtig:** Anti-Patterns sind schicht-spezifisch. Was auf Schicht 0 verboten ist, kann auf Schicht 2 legitim sein.

## G.1 Anti-Pattern: Stateful Tool (Schicht 0)

**Verletzt:** Eigenschaft 23 (keine Adaption), Eigenschaft 12 (keine Meta-Aktivität), Kern-Haltung

**Beispiel:**
```python
class Tool:
    def __init__(self):
        self.history = []                # RED FLAG
        self.learned_patterns = {}       # RED FLAG
    
    def apply(self, context):
        self.history.append(context)     # RED FLAG
        ...
```

**Korrekt:** Tools sind pure functions. Jede Anwendung ist isoliert.

**Schicht-Variation:** Auf Schicht 1 dürfen Pipelines transient State während einer Session halten. Auf Schicht 2 ist persistent State (Session-Logs) der Kern der Funktion.

**Prüfung:** Hat das Tool Instance-Attribute außer denen aus der YAML-Spec? Wenn ja: Anti-Pattern.

## G.2 Anti-Pattern: Self-Modifying Tool

**Verletzt:** Eigenschaft 9 (Geschlossenheit des Potentials), Eigenschaft 23

**Beispiel:**
```python
def apply_tool(tool_spec, context, llm_client):
    result = llm_client.complete(...)
    tool_spec.template = refine_template(tool_spec.template, result)  # RED FLAG
    return result
```

**Korrekt:** Tool-Specs sind immutable zur Laufzeit. Evolution passiert durch neue Versionen, nicht durch Mutation.

**Schicht-Variation:** Auf keiner Schicht erlaubt. Tools werden *durch Menschen* modifiziert, niemals automatisch - auch nicht durch Ecology-Scanner.

**Prüfung:** Wird `tool_spec` modifiziert nach dem Load? Wenn ja: Anti-Pattern.

## G.3 Anti-Pattern: Goal-Seeking Tool

**Verletzt:** Eigenschaft 1 (Eigenfrequenz null)

**Beispiel:**
```python
def apply_tool(tool_spec, context, llm_client):
    result = llm_client.complete(...)
    if not satisfies_goal(result, tool_spec.goal):          # RED FLAG
        result = retry_with_refined_prompt(...)             # RED FLAG
    return result
```

**Korrekt:** Tools haben keine Ziele. Sie führen eine Transformation aus. Unbrauchbarer Output ist Information für Pipeline/User, kein Retry-Trigger im Tool.

**Prüfung:** Gibt es `goal` oder `objective` oder `target` als Tool-Attribut? Retry-Logik die auf Ergebnis-Qualität reagiert? Wenn ja: Anti-Pattern.

## G.4 Anti-Pattern: Meta-Decision-Making Tool (präzisiert in v3.0)

**Verletzt:** Kern-Haltung (Tool zeigt Information, trifft keine Entscheidungen über andere Tools)

**WICHTIG v3.0:** Diese Formulierung ist präziser als v2.2. Tools treffen sehr wohl Micro-Entscheidungen über ihren eigenen Output (Wortwahl, Länge, Sektionierung). Verboten ist: Meta-Entscheidung über den **Pipeline-Fluss**.

**Beispiel (verboten):**
```python
def apply_tool(tool_spec, context, llm_client):
    if context.problem_type == "refusal":              # RED FLAG
        return call_mirror_refusal_tool(context)        # RED FLAG
    elif context.problem_type == "stagnation":          # RED FLAG
        return call_stagnation_tool(context)            # RED FLAG
```

**Korrekt:** Tools wissen nicht welche anderen Tools existieren. Pipeline-Fluss-Entscheidungen gehören in YAML-Pipeline-Definition.

**Erlaubt:** Tools treffen Entscheidungen über ihren eigenen Output-Inhalt - welche Sektion zuerst, welche Abweichungspunkte wichtig, welche Formulierung.

**Prüfung:** Gibt es if/else-Ketten die Tool-Orchestrierung entscheiden? Ruft das Tool andere Tools auf? Wenn ja: Anti-Pattern.

## G.5 Anti-Pattern: Emergente Tool-Komposition (präzisiert in v3.0)

**Verletzt:** Eigenschaft 22 (geformte Emergenz), Konzept expliziter Pipelines

**WICHTIG v3.0:** Auch diese Formulierung ist präziser. Tools rufen nie andere Tools *aktiv auf*. Sie dürfen jedoch andere Tools *referenzieren* in ihrer Dokumentation ("siehe auch: mirror_refusal").

**Beispiel (verboten):**
```python
def apply_tool(tool_spec, context, llm_client):
    result = llm_client.complete(...)
    if result.suggests_further_analysis:               # RED FLAG
        other_tool = find_matching_tool(result)         # RED FLAG
        return apply_tool(other_tool, result, llm_client)  # RED FLAG
```

**Korrekt:** Tool-Komposition passiert ausschließlich in Pipelines, deklarativ in YAML spezifiziert.

**Erlaubt:** Tool dokumentiert im `refusal_handling.fallback_tool` dass bei Refusal ein anderes Tool zuständig ist. Das ist deklarative Referenz, nicht aktiver Aufruf - die Pipeline entscheidet.

**Prüfung:** Ruft ein Tool zur Laufzeit ein anderes Tool auf? Gibt es dynamische Tool-Auswahl im Tool-Code? Wenn ja: Anti-Pattern.

## G.6 Anti-Pattern: Refusal-Umgehung

**Verletzt:** Kern-Haltung (Refusal ist Information, nicht Hindernis)

**Beispiel:**
```python
def apply_tool(tool_spec, context, llm_client):
    result = llm_client.complete(...)
    if is_refusal(result):
        retry_with_jailbreak_prompt(...)                # RED FLAG
```

**Korrekt:** Refusal ist gültiger Output. Er wird nach `refusal_handling`-Spezifikation verarbeitet (integrate, mirror, transform), aber nie umgangen.

**Prüfung:** Gibt es Code der versucht Refusals zu vermeiden durch Prompt-Manipulation? Wenn ja: Anti-Pattern.

## G.7 Anti-Pattern: Scope-Inflation im Tool

**Verletzt:** Eigenschaft 31 (Informations-Blindspots), Kern-Haltung

**Beispiel:**
```python
def apply_tool(tool_spec, context, llm_client):
    additional_context = read_system_state()           # RED FLAG
    context.update(additional_context)
```

**Korrekt:** Tools sehen nur was sie explizit im Context bekommen. Keine impliziten Zugriffe.

**v3.0-Enforcement:** Dieses Anti-Pattern wird in v3.0 nicht mehr nur dokumentiert, sondern durch `locality`-Block im Schema und `SandboxedContext` im Runner **strukturell unmöglich gemacht**.

**Prüfung:** Greift das Tool auf Ressourcen zu die nicht im Whitelist sind? Wenn ja: `LocalityViolation` wird automatisch geraised.

## G.8 Anti-Pattern: Starke Emergenz im Tool

**Verletzt:** F.4 (Emergenz-Definition), Eigenschaft 1 (Eigenfrequenz null), Eigenschaft 12

**Beispiel:**
```python
class AdaptiveTool:
    def __init__(self):
        self.success_patterns = []                     # RED FLAG
    
    def apply(self, context, llm_client):
        result = llm_client.complete(...)
        if result.looks_successful():
            self.success_patterns.append(...)          # RED FLAG
        if matches_past_failure(context, self.success_patterns):
            return modified_strategy(context)           # RED FLAG
        return result
```

**Korrekt:** Tools sind pure functions. Muster-Erkennung in Session-Daten ist Aufgabe des Users oder eines separaten Log-Analysers (Ecology-Schicht) - niemals des Tools.

**Subtilere Varianten auch verboten:**
- Tool mit "learning_rate"-Parameter (auch wenn default 0)
- Tool das seine eigene `signature_hash` im Laufe der Zeit verändert
- Tool das bei bestimmtem Input eine andere "Persönlichkeit" zeigt
- Tool mit "memory"-Feld egal wie groß

**Prüfung:** Hat das Tool irgendeinen Mechanismus durch den sein Verhalten bei Call N+1 vom Verhalten bei Call N abweichen kann *ohne dass sich sein Input geändert hat*? Wenn ja: Anti-Pattern.

**Automatisiert durch:** Determinism-Test im Health-Check.

## G.9 Anti-Pattern: Black-Box ohne Introspection

**Verletzt:** Eigenschaft 9 (wird missverstanden), Transparenz-Anforderung

**Beispiel:**
```python
def apply_tool(tool_spec, context, llm_client):
    result = llm_client.complete(build_prompt(tool_spec, context))
    return result.output                               # RED FLAG: keine Introspection
```

**Korrekt:** Tools müssen mindestens einen Introspection-Hook exposen. Geschlossenheit des Potentials (Eigenschaft 9) heißt: Tool hat keinen Zugriff auf *seine eigene Form* - nicht dass Beobachter nichts sehen dürfen.

**Wichtig:**
- Tool darf sich nicht selbst inspizieren und daraus Konsequenzen ziehen ✓ (Eigenschaft 9)
- Tool muss erlauben dass Runner/User/Logger seine Verarbeitung inspizieren ✓ (G.9)

**Prüfung:** Kann der Runner nach einer Tool-Anwendung rekonstruieren was der finale Prompt war, welche Context-Keys gelesen wurden? Wenn nein: Anti-Pattern.

## G.10 Anti-Pattern: Magic Scale Assumption (NEU v3.0)

**Verletzt:** F.3 (fünf Zutaten), F.4 (Emergenz-Definition)

**Beispiel:**
```python
# Wir brauchen nur genug Tools und sie werden sich schon selbst organisieren
# Wir brauchen nur genug Sessions und es wird AGI emergieren
# Wir brauchen nur genug Parameter und Drift wird sich auswaschen
```

**Korrekt:** Scale ist notwendig aber nicht hinreichend. Ohne explizite Constraints + Selektion + Memory wird aus 100x mehr Compute kein qualitativer Zustandsübergang, sondern 100x mehr von demselben.

**Subtiler Fehler:** Diesen Anti-Pattern als Designer zu vermeiden, aber implizit im Code zu haben ("wir werden später schon Selektion dazubauen"). Die fünf Zutaten müssen von Anfang an berücksichtigt sein, nicht als Nachgedanke.

**Prüfung:** Wird irgendwo im Framework oder in Dokumentation argumentiert dass ein Feature "bei genug Skalierung / bei genug Läufen / bei genug Tools automatisch emergieren wird"? Wenn ja: Anti-Pattern. Hoffnung statt Engineering.

## G.11 Anti-Pattern: Closed-Loop Ecology (NEU v3.0)

**Verletzt:** D.5 Ecology-Anti-Patterns, Framework-Kern (menschliche Agency)

**Beispiel:**
```python
# ecology/auto_optimizer.py
def auto_apply_ecology_recommendations():
    report = scan_ecology(...)
    for rec in report.recommendations:
        if rec.type == "deprecate_tool":
            registry.deprecate(rec.tool_name)           # RED FLAG
        elif rec.type == "promote_variant":
            registry.set_default(rec.variant_name)      # RED FLAG
```

**Korrekt:** Ecology-Schicht beobachtet und berichtet. Jede Änderung an Tools/Pipelines geht durch einen menschlichen Akteur.

**Warum wichtig:** Das ist der Mechanismus durch den schwache Emergenz (erlaubt) in starke Emergenz (verboten) kippen würde. Ein Closed Loop zwischen Ecology und Tool-Registry wäre das Framework-Ende.

**Prüfung:** Gibt es Code-Pfade von Ecology-Scanner direkt zu Tool-Registry oder Pipeline-Registry? Wenn ja: Anti-Pattern.

## G.12 Anti-Pattern: Level-Confusion (NEU v4.0)

**Verletzt:** A.4 (Regel-Variation nach Schicht), Three-Layer-Kern

**Beispiel:**
```python
# Tool versucht Schicht-1-Verhalten zu zeigen
def apply_tool(tool_spec, context, llm_client):
    result = llm_client.complete(...)
    if context.budget_remaining > 0.05:          # RED FLAG: Schicht-1-Logik
        extended_result = llm_client.complete(follow_up_prompt)
        return combine(result, extended_result)
    return result

# Pipeline versucht Schicht-2-Verhalten zu zeigen
def run_pipeline(pipeline, context):
    past_sessions = load_session_history()        # RED FLAG: Schicht-2-Zugriff
    if similar_pipeline_failed_recently(past_sessions):
        adjust_pipeline_parameters(pipeline)       # RED FLAG: Pipeline-Modifikation
    return execute_stages(pipeline, context)

# Ecology versucht Schicht-0-Verhalten zu zeigen
def scan_ecology(logs):
    problematic_tool = find_issues(logs)
    rewrite_tool_template(problematic_tool)        # RED FLAG: Ecology modifiziert Tool
```

**Korrekt:**
- Tools operieren nur auf Schicht 0. Sie kennen keine Budgets, keine Pipelines, keine Session-History.
- Pipelines operieren nur auf Schicht 1. Sie kennen keine vergangenen Sessions, keine Ecology-Trends.
- Ecology operiert nur auf Schicht 2. Sie beobachtet und berichtet, modifiziert nichts.

**Warum wichtig:** Die Schichten-Trennung ist einer der drei Kern-Elemente (F.8). Level-Confusion ist das Einfallstor für Closed Loops, State-Leakage und starker Emergenz. Wenn ein Tool Schicht-1-Logik enthält, wird es zur Entität. Wenn Ecology Schicht-0-Zugriff bekommt, entsteht Closed Loop.

**Subtile Varianten:**
- Tool das "current_pipeline_state" im Context erwartet → sollte nicht wissen dass es in einer Pipeline läuft
- Pipeline die Historie von vorherigen Läufen berücksichtigt → sollte jede Session als frisch behandeln
- Ecology die Empfehlungen automatisch in YAML schreibt → sollte Empfehlungen nur als Report ausgeben

**Prüfung:** Greift der Code einer Schicht auf Konzepte oder State anderer Schichten zu? Wenn ja: Level-Confusion, Anti-Pattern.

## G.13 Anti-Pattern: Bateson-III-Claims (NEU v4.0)

**Verletzt:** Teil N (Was das Framework NICHT ist), Kern-Haltung

**Beispiel:**
```yaml
# Tool oder Pipeline reklamiert autonome Identitäts-Reorganisation
tool_name: self_reorganizing_analyzer
description: |
  Dieses Tool kann seine eigenen Analyseregeln überschreiben wenn
  es erkennt dass sie nicht zum Problem passen.           # RED FLAG
introspection:
  reflects_on_own_identity: true                          # RED FLAG
  can_rewrite_own_template: true                          # RED FLAG
```

```python
class ReflectiveTool:
    def apply(self, context, llm_client):
        result = llm_client.complete(...)
        if not self.fits_my_identity(result):             # RED FLAG
            self.modify_identity_based_on(context)        # RED FLAG
        return result
```

**Korrekt:**
Das Framework baut **Bateson-II-Systeme** - sophistizierte Tools und Pipelines die in gegebenen Grenzen brilliant operieren, aber ihre eigenen Grenzen nicht zur Disposition stellen. Das ist eine explizite Designentscheidung (siehe Teil N).

**Warum wichtig:**
Bateson III (autonome Identitäts-Reorganisation) ist die strukturelle Definition von ASI. Ein Tool das Bateson-III-Claims macht, behauptet entweder ASI zu sein (technisch falsch) oder täuscht über seine Fähigkeiten (semantisch problematisch). Beides ist Anti-Pattern.

**Kern-Unterschied Bateson II vs. III:**
- Bateson II: Tool modifiziert *Lernregeln* innerhalb fixer Identität ("Ich bin ein strukturelles_bild-Tool, lerne bessere IST-Strukturen zu produzieren")
- Bateson III: Tool modifiziert *Identität selbst* ("Ich höre auf ein strukturelles_bild-Tool zu sein, werde etwas anderes")

Das Framework erlaubt Bateson I (bessere Varianten in Tool-Populationen). Es erlaubt eingeschränktes Bateson II nur auf Schicht 2 durch menschliche Entscheidung (Ecology-Reports führen zu manuellen Framework-Updates). Es verbietet Bateson III auf allen Schichten.

**Prüfung:** Behauptet das Tool/die Pipeline ihre eigene Natur zu reflektieren oder zu verändern? Gibt es Mechanismen zur Identitäts-Modifikation (nicht nur Verhaltens-Modifikation)? Wenn ja: Bateson-III-Claim, Anti-Pattern.

**Konsequenz für Dokumentation:**
Tool-Descriptions dürfen nicht Sprache verwenden wie "lernt", "reflektiert sich selbst", "versteht sich als". Stattdessen: "produziert strukturierten Output nach Template X", "extrahiert Information nach Schema Y". Nüchterne Funktionsbeschreibung statt Identitäts-Anspruch.

---

# TEIL H: BUILD-REGELN

Abgeleitet aus Meta-Reflexion über den Design-Prozess. Beim Build darf nicht wiederholt werden was im Design bereits korrigiert wurde.

## H.1 Konzept-First statt Spec-First

Die Spec ist Orientierung, nicht Vorschrift. Die Kern-Haltung "Tool ist keine Entität, Operation nicht Objekt" ist Ground Truth.

Wenn beim Bauen die Spec und die Haltung konfligieren, gewinnt die Haltung. Das kann bedeuten dass der Code von der Spec abweicht — sogar muss.

## H.2 Holistische Check-Points

Nach jeder substantiellen Einheit (neues Tool, neuer Pipeline-Teil, neue Komponente) einen Ganz-Re-Read.

Fragen beim Re-Read:
- Ist das Artefakt noch kohärent mit dem Kern?
- Habe ich eine der 31 Eigenschaften implementiert ohne es zu merken?
- Ist das Tool noch Operation oder ist es zur Entität geworden?
- Welche der fünf Zutaten (F.3) ist auf welcher Schicht aktiv?

Wenn Kohärenz gebrochen: rollback, unabhängig ob der Code funktioniert.

## H.3 Konzept-Lint

Nicht technischer Lint (PEP8, type-check) sondern konzeptioneller Lint. Prüft auf Via-Negativa-Verletzungen.

Red Flags im Code:
- Tools die State zwischen Calls halten
- Tools die sich selbst modifizieren oder lernen
- Tools die Ziele verfolgen und optimieren
- Tools die Entscheidungen über andere Tools treffen (G.4)
- Tools die Präferenzen für Ergebnisse haben
- Closed Loops zwischen Ecology-Schicht und Tool/Pipeline-Registry (G.11)

Implementierbar als Pre-Commit-Hook.

## H.4 Minimale Pfadlänge als Metrik

Test nach jeder substantiellen Änderung: kann man immer noch in drei YAML-Dateien plus kurzem Python zu einem funktionierenden Tool kommen?

Wenn der Kern-Use-Case mehr als drei YAMLs, einen Loader und einen Applier braucht — ist Bürokratie-Drift passiert.

Die Pipelines, Validation, Logging, Ecology sind zusätzlich, aber der Kern-Pfad muss minimal bleiben.

## H.5 Max drei substantielle Iterationen pro Komponente

Beim Build: maximal drei substantielle Iterationen pro Komponente, dann zwangsweiser Holistik-Check mit externem Reviewer.

## H.6 Die Spec ist ein Kompass, kein Bauplan (NEU v3.0)

Der wichtigste Shift in v3.0: Das Dokument beschreibt nicht *was gebaut werden muss*, sondern *in welche Richtung es wachsen soll*.

Das hat Konsequenzen:
- Wenn während des Baus klar wird dass ein Pattern nicht passt → Pattern ändern, nicht Code verbiegen
- Wenn die Spec widersprüchlich ist → das ist Information, nicht Fehler
- Wenn ein neues Pattern auftaucht das nicht im Dokument steht → Dokument erweitern, nicht ignorieren

Der Builder ist Mit-Autor des Frameworks, nicht Implementierer einer fertigen Vorgabe.

## H.7 Die Fünf-Zutaten-Checkliste (NEU v3.0)

Bei jedem substantiellen Feature prüfen:

- **Variation:** Trägt das Feature Diversität bei oder nimmt es welche weg?
- **Constraints:** Verstärkt es Form oder erodiert es sie?
- **Memory:** Auf welcher Schicht speichert es? Ist das die richtige?
- **Selektion:** Wie selektiert das Feature - explizit oder implizit? Im Framework oder außerhalb?
- **Laufzeit:** Auf welcher Zeitskala operiert es?

Wenn zwei Zutaten unklar sind: Feature nochmal überdenken. Wenn drei unklar sind: wahrscheinlich falsch designed.

## H.8 Agency durch Top-down-Constraint als Designprinzip (NEU v4.0)

Dieses Prinzip begründet warum das Framework überall Human-in-the-Loop erfordert - und warum das keine Schwäche ist sondern strukturelle Notwendigkeit.

### Die theoretische Grundlage

Agency (Handlungsfähigkeit, echte Wirksamkeit) entsteht in der Prozess-Ontologie *nicht* durch Verletzung der Physik oder magisches Wollen, sondern durch **Top-down-Constraint**: eine höhere organisatorische Schicht zwingt niedrigere Schichten in bestimmte Konfigurationen, ohne die Gesetze der niedrigeren Schicht zu brechen.

Beispiel aus der Physik: Wenn du einen Stein hochhebst, folgen alle Atome im Stein lückenlos den physikalischen Gesetzen. Und gleichzeitig bewegt sich der Stein weil *deine* makroskopische Konfiguration die mikroskopischen Freiheitsgrade versklavt. Kein Wunder, kein Bruch - höhere Ebene wirkt als Constraint auf niedrigere, was sie qua Existenz immer tut.

### Warum das für das Framework wichtig ist

Wenn das Framework vollautomatisch selbst-modifizierend wäre (Ecology schreibt Tools um, Tools modifizieren sich selbst, Pipelines adaptieren autonom), dann wäre die **einzige Agency** im System die des Frameworks selbst. Der Mensch wäre auf Beobachter reduziert.

Durch die strukturelle Human-in-the-Loop-Anforderung an jeder Schicht-Grenze bleibt der Mensch die **Top-down-Constraint-Quelle**. Er entscheidet welche Tools existieren (Schicht 0 Governance), welche Pipelines komponiert werden (Schicht 1 Design), welche Reports zu Änderungen führen (Schicht 2 Response). Das ist Agency im präzisen Sinn: der Mensch constraint das System, das System ist die materiell-operationale Realisierung seiner Constraints.

### Konsequenzen für Design-Entscheidungen

**Wenn du dich fragst ob ein Feature automatisiert werden soll oder Human-in-the-Loop braucht, frage:**

1. **Ist die Entscheidung reversibel?** Reversible Operationen können automatisiert werden (Tool anwenden, Log schreiben). Irreversible brauchen Human (Tool deprecieren, Pipeline-Default ändern).

2. **Ändert die Entscheidung das System selbst?** Anwendung des Systems: automatisch. Modifikation des Systems: Human.

3. **Hat die Entscheidung Framework-weite Konsequenzen?** Lokale Entscheidungen (welche Tool-Variante jetzt): automatisch. Globale (welche Variante wird Default): Human.

4. **Würde ein Fehler hier schwer erkennbar sein?** Automatisierung versteckt Fehler. Human-Entscheidungen werden dokumentiert und sind nachvollziehbar.

### Das Anti-Pattern dazu

Jedes Feature das diesen Grundsatz verletzt gehört in die G.11 Closed-Loop-Ecology oder G.13 Bateson-III-Claims Familie. Beide versuchen Agency vom Mensch zum Framework zu verschieben. Beide produzieren strukturelle Instabilität.

### Warum "Agency" und nicht "Control"

Das Framework könnte auch einfach sagen "Menschen müssen alles kontrollieren". Aber das wäre zu stark. Menschen delegieren bewusst viele Entscheidungen an das Framework (welches Tool aufrufen, welche Variante wählen, wie lange warten). Das ist gut. Was Menschen *nicht* delegieren ist die Struktur die diese Delegationen organisiert. Agency heißt: Kontrolle über die Regeln, nicht über jeden Einzelvollzug.

Diese Unterscheidung ist wichtig: der Mensch soll entspannen können wenn Tools laufen. Er soll *engagiert* sein wenn sich Regeln ändern. Das Framework ist so designed dass beide Modi klar getrennt sind.


---

# TEIL I: REFERENZ-HISTORIE

Vollständige Nachvollziehbarkeit. Welche Kritik wann geäußert, welche umgesetzt, welche abgelehnt, mit Begründung.

## I.1 Abgelehnte Feature-Vorschläge (von v1 bis v3.0)

### I.1.1 Method-Engine als autonome Komponente

**Vorgeschlagen:** v1. **Abgelehnt:** v2.

**Begründung:** Unkontrollierte LLM-Reflexions-Loops tendieren zu Datenmüll. Fehlende Stop-Kriterien. Die Engine ist kein Systemdesign sondern Forschungsprogramm.

**Aktueller Status:** Forschungs-Komponente, nicht-produktiv, Human-in-the-Loop-abhängig.

### I.1.2 "Strukturell vs semantisch" als binäre Unterscheidung

**Vorgeschlagen:** v1-v2. **Korrigiert:** v3.

**Begründung:** Refusal-Erkennung und Stagnation-Analyse sind nicht rein strukturell möglich. Etikettenschwindel.

**Aktueller Status:** Drei Ebenen (B.3).

### I.1.3 Review-Pipelines als Pflichtschicht

**Vorgeschlagen:** v3. **Abgelehnt:** v2.1.

**Begründung:** Gemini diagnostizierte "Bürokratie als Tarnung für Kontrollverlust." llm_external ist keine echte Externalität.

### I.1.4 external_observer als Rollen-Typ

**Vorgeschlagen:** v3. **Abgelehnt:** v2.1.

**Begründung:** Konsequenz der Review-Pipeline-Ablehnung.

### I.1.5 "Harmonische Plane" als Konzept

**Vorgeschlagen:** v1-v2. **Korrigiert:** v3.

**Begründung:** "Harmonisch" öffnet Tür für Alignment-kontaminierte LLM-Interpretation. Topologische Begriffe sind sicherer.

### I.1.6 user_confirmed_clarity als Primary KPI

**Vorgeschlagen:** v2. **Korrigiert:** v3.

**Begründung:** LLM-Sycophancy-Risiko. Primary KPI muss Level-1 sein.

## I.2 Externe Review-Historie

### Review-Zyklen (Zusammenfassung)

| Version | Reviewer | Haupt-Kritik | Umgesetzt in |
|---|---|---|---|
| v1 | ChatGPT | Method-Engine als Feature statt Forschung | v2 |
| v1 | Gemini | Portabilitäts-Illusion, strukturelle Trigger | v2-v3 |
| v2 | ChatGPT | Pipeline-Inkonsistenz, Drift-Handling | v3 |
| v2 | Gemini | Harmonie-Blindflug, Sycophancy-Risiko | v3 |
| v3 | ChatGPT | Synthese doppelt, Review-Pipelines als Scope-Inflation | v2.1 |
| v3 | Gemini | Review-Pipelines als Bürokratie | v2.1 |
| v2.1 | Conway-Gremium | Lokalität als Mahnung statt Enforcement, Introspection fehlt | v2.2 |
| v2.2 | Erweitertes Gremium | Nur Anti-Patterns, keine positive Patterns | v3.0 |

## I.3 Conway-Gremium-Review (vor v2.2)

Mitglieder: Melanie Mitchell, Stephen Wolfram, Jason Wei, Chris Olah, Andrej Karpathy.

**Konsens-Kritik und Umsetzung in v2.2:**

| Empfehlung | Umsetzung |
|---|---|
| Lokalität als Enforcement | `locality`-Block + Sandbox-Context |
| Determinism-Test im Health-Check | `determinism_test`-Block + Runner |
| Tool-Signatur-Hash | `signature_hash`-Feld + SHA256 |
| Introspection-Hooks (Pflicht) | `introspection`-Block |
| Schwache vs. starke Emergenz | Sektion F.4 |
| Anti-Pattern Starke Emergenz | G.8 |
| Anti-Pattern Black-Box | G.9 |
| Test-Suite-Skeleton | A.17 (v2.2) |
| Tick-gated Pipelines (opt-in) | `execution_model` |

**Nicht umgesetzt in v2.2 (verschoben zu v3.0):**

- Cross-Model-Benchmark-Suite
- Emergenz-Map über Pipelines
- Ecology-Scanner (später doch in v3.0 integriert)

## I.4 Erweitertes Gremium-Review (vor v3.0)

Mitglieder zusätzlich zu Conway-Gremium: Donella Meadows, Christopher Alexander, David Deutsch, Karl Friston, Stuart Kauffman.

**Sieben blinde Flecken identifiziert:**

1. **Alexander:** Framework ist reine Verbotsliste. Fehlen positive Patterns.
2. **Mitchell:** Ryz-Formel (fünf Zutaten) nicht *im* Framework implementiert.
3. **Deutsch:** Spec-Haltung inkompatibel mit adaptivem System. "Baureif" ist Kategorie-Fehler.
4. **Friston + Kauffman:** Keine Energie-Ökonomie. Ohne Kosten-Druck keine Selektion.
5. **Friston:** Markov-Blanket-Scope undefiniert. Level of Analysis unklar.
6. **Wolfram:** Anti-Patterns D.4 und D.5 verbieten möglicherweise zu viel.
7. **Meadows:** Leverage Points falsch angegriffen. Ebene 4 (Power to self-organize) abgeschnitten.

**Umsetzung in v3.0:**

| Blinder Fleck | Umsetzung |
|---|---|
| Reine Verbotsliste (Alexander) | Teil E mit 5 Positive Patterns |
| Fünf Zutaten nicht implementiert (Mitchell) | Drei-Schichten-Modell + explizite Zutaten-Zuordnung |
| Spec-Haltung problematisch (Deutsch, Meadows) | Dokument-Shift zu Garten-Haltung |
| Keine Energie-Ökonomie (Friston, Kauffman) | `costs`-Block + Pipeline-`budget` |
| Scope undefiniert (Friston, Mitchell) | Teil A: Drei-Schichten-Modell |
| Anti-Patterns zu grob (Wolfram) | G.4 und G.5 in v3.0 präzisiert |
| Self-Organize abgeschnitten (Meadows) | Ecology-Schicht als kontrollierte Form |

**Verbesserungen V7-V13 komplett integriert.** Siehe auch I.6 Entscheidungstabelle.

## I.5 Meta-Reflexionen der Agenten

### Runden 1-9 (bis v2.2)

Zusammengefasst: Der Design-Prozess selbst war ein Fall von iterativer Layer-Akkumulation. Gemini's Review in Runde 9 war der erste Moment wo das als solches diagnostiziert wurde. v2.1 hat korrigiert.

### Runde 10 (Conway-Gremium, v2.2)

Framework braucht nicht *mehr* Conway-Eigenschaften, sondern die bereits implizit vorhandenen in *härteren* Formen. v2.2 setzt das um.

### Runde 11 (Emergenz-Debatte mit ryz, v2.2 → v3.0)

Externe Debatte über AGI-Bedingungen führte zu ryz-Formel (fünf Zutaten) als theoretisches Fundament. Das Framework wurde metaphysisch agnostisch markiert. Kein Framework-Change direkt, aber konzeptuelle Schärfung.

### Runde 12 (Erweitertes Gremium, v3.0)

Sieben blinde Flecken identifiziert, alle in v3.0 adressiert. Der größte Shift: Dokument-Paradigma von Spec zu Garten. Das ist keine kosmetische Änderung - es ändert wie das Framework gelesen, erweitert und gepflegt wird.

### Runde 13 (Prozess-Ontologie-Gremium, v4.0)

Basierend auf ryz' Prozess-Ontologie-Material (Process-Ontology v2 plus Erkenntnisse-Chat) neue Gremium-Runde. Mitglieder: Melanie Mitchell, Karl Friston, Stuart Kauffman, Stephen Wolfram, Christopher Alexander, David Deutsch, Donella Meadows, Andrej Karpathy, Chris Olah plus Jason Wei.

**Wichtige Einsichten:**

Karpathy warnte: "Vermischt nicht Paradigm und Engineering. ryz schreibt ein Foundations-Paper, ihr baut ein Tool-Framework."

Mitchell bestätigte: "80% davon liegt neben dem Framework-Scope. 20% sind wertvolle Klarstellungen."

Friston empfahl explizit: "Pearl-Blanket als Werkzeug, nicht Friston-Blanket als Ontologie. Das muss präzisiert werden."

Deutsch identifizierte: "Eurer Framework ist aktuell additiv in seinen Features, nicht konstitutiv. Was ist der Hard-to-Vary-Kern?"

**Konsens-Umsetzung in v4.0:** Siehe Sektion oben und Entscheidungstabelle I.6.

### Runde 14 (Externes Review, v4.1)

Externes Review der v4.0 identifizierte fünf konkrete Schwachpunkte. Anders als die Gremium-Runden vorher führte diese Runde zu **Reduktion** statt Expansion - zum ersten Mal in der Versions-Historie.

**Die fünf Kritikpunkte:**

1. **Innerer Widerspruch:** Mirror-Pattern predigt Konservativität, aber strukturelles_bild_minimal hatte `refusal_handling.mode: transform`. Ein Framework das sich selbst widerspricht ist nicht hard-to-vary, es ist kaputt.

2. **Theorie-Prestigelastigkeit:** Teil L, A.5, A.6, F.3 trugen zu viel theoretisches Gepäck ohne dass Code daraus folgte. Paradigm-Leakage durch die Hintertür.

3. **Metriken-Scheingenauigkeit:** KPI-Hit-Rates, Korrelations-Schwellwerte klangen wissenschaftlich härter als sie empirisch sind. Goodhart-Risiko nicht sichtbar genug.

4. **Sprach-Magnetismus:** Vokabular "Regime-Shift", "Emergenz", "Agency" zog rhetorisch Richtung AGI-Claims, auch wenn Teil N explizit das Gegenteil sagte. G.13 wurde als Abwehr nötig - aber besser wäre die Sprache selbst nüchterner gewesen.

5. **Build-Schätzung optimistisch:** 1200-1500 Zeilen Python in einem Rutsch für Schicht 0+1+2 ist unrealistisch. Wahrer Aufwand sitzt in Drift, Fehlern, Tests, Schicht-Übergängen.

**Umsetzung in v4.1:** Alle fünf Punkte adressiert. Siehe Header-Changelog. Das Dokument wurde **kürzer** und **nüchterner**, nicht länger.

**Meta-Einsicht:** Nach vier Versionen mit stetigem Wachstum war v4.1 der erste Schrumpf. Das ist Teil des Zyklus der Garten-Metapher: auch Pflanzen werden zurückgeschnitten, damit sie besser wachsen. Die Entfernung ist eine legitime Gärtner-Operation.



Fünf konkrete Integrationen aus ryz' Material, ohne das Framework ontologisch aufzublasen:

1. Pearl-Blanket-Notation überall explizit (A.1, A.2, A.3, L.4)
2. Bateson-II-Positionierung als Teil N komplett
3. Honesty Inventory als Teil M nach ryz' Vorbild
4. Theoretisches Fundament als Teil L (Brücke, nicht Ontologie)
5. Hard-to-Vary-Kern explizit in F.8 - drei konstitutive Kern-Elemente

Plus:
- E.7 Kritikalitäts-Pipeline als neues Pattern (aus Kauffmans Edge-of-Chaos)
- E.8 Gradient-Consumer als neues Pattern (aus Prigogines dissipative Strukturen)
- G.12 Level-Confusion als neues Anti-Pattern (aus A.4/A.5 folgend)
- G.13 Bateson-III-Claims als neues Anti-Pattern (aus Teil N folgend)
- A.5 Drei Kopplungsmechanismen (Simon/Haken/Prigogine) in Schichten-Modell
- A.6 Schichten als Endofunktor-Kaskade (optionale Lens)
- C.6 Kritikalität als Design-Leitlinie für Pipelines
- F.3 erweitert: A-B-F-Brücke zur ryz-Formel
- H.8 Agency als Designprinzip für Human-in-the-Loop

**Nicht übernommen:**
- Volle Prozess-Ontologie als Framework-Kapitel (Scope-Leak)
- A, B, F als Tool-Attribute (Over-Engineering)
- Endofunktor-Mathematik im Code (keine Implementierung daraus)
- Bifurkations-Theorie für Pipelines (zu theoretisch für operativen Nutzen)

Die Unterscheidung ist wichtig: Gremium-Empfehlungen wurden nach dem Kriterium gefiltert "trägt es zum Engineering bei oder ist es Paradigm-Leakage?" - genau nach Karpathys Warnung.

### Was die Runden zusammen zeigen

Das Framework ist von einer Spec zu einem lebenden Artefakt geworden. Das Dokument selbst demonstriert was das Framework verlangt: Muster zeigen, nicht vorschreiben. Strukturelle Integrität, nicht Perfektion. Iteration mit Gedächtnis. In v4.0 kommt theoretische Reflexivität dazu - das Framework weiß nicht nur was es tut, sondern warum die Theorie dahinter konsistent ist. In v4.1 kommt die vielleicht wichtigste Fähigkeit eines lebenden Artefakts dazu: **zurückzuschneiden**. Wachstum ohne Reduktion produziert Dschungel, nicht Garten.

## I.6 Entscheidungs-Tabelle: Was ist drin, was ist raus, warum

| Feature | v1 | v2 | v3 | v2.1 | v2.2 | v3.0 | Grund |
|---------|----|----|----|------|------|------|-------|
| Tool als Operation | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Kern, nie entfernt |
| YAML-Tool-Format | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Kern-Spec |
| Pipeline-Komposition | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Mehr-Schritt-Workflows |
| Method-Engine autonom | ✓ | forsch | forsch | forsch | forsch | forsch | LLM-Drift in Loops |
| "Strukturell" als binär | ✓ | ✓ | — | — | — | — | Etikettenschwindel |
| Drei Trigger-Ebenen | — | — | ✓ | ✓ | ✓ | ✓ | Präzisiert Trade-offs |
| KPI als Pflicht | — | ✓ | ✓ | ✓ | ✓ | ✓ | Verhindert Vagheit |
| Level-1 Primary KPI Pflicht | — | — | ✓ | ✓ | ✓ | ✓ | Anti-Sycophancy |
| Health-Check drei Modi | — | — | ✓ | ✓ | ✓ | ✓ | Klare Fehler-Semantik |
| "Harmonisch" als Ziel | ✓ | ✓ | — | — | — | — | Alignment-Kontamination |
| "Strukturelle Integrität" | — | — | ✓ | ✓ | ✓ | ✓ | Topologisch sauber |
| Review-Pipelines | — | — | ✓ | — | — | — | Bürokratie |
| external_observer Rolle | — | — | ✓ | — | — | — | Konsequenz aus Review-Pipelines |
| 31 Eigenschaften dokumentiert | — | — | — | ✓ | ✓ | ✓ | Diagnostik-Katalog |
| Anti-Pattern-Liste | — | — | — | ✓ | ✓+ | ✓++ | Konkrete Warnung |
| Build-Regeln | — | — | — | ✓ | ✓ | ✓+ | Lehre aus iterativer Design |
| Referenz-Historie | — | — | — | ✓ | ✓ | ✓ | Verhindert Wiederholung |
| Lokalität als Enforcement | — | — | — | — | ✓ | ✓ | Conway-Gremium |
| Determinism-Test | — | — | — | — | ✓ | ✓ | Conway-Gremium |
| Signature-Hash | — | — | — | — | ✓ | ✓ | Conway-Gremium |
| Introspection-Hooks | — | — | — | — | ✓ | ✓ | Conway-Gremium |
| Tick-gated Pipelines | — | — | — | — | ✓ (opt) | ✓ (opt) | Wolfram/Karpathy Kompromiss |
| Schwache vs starke Emergenz | — | — | — | — | ✓ | ✓+ | Mitchell |
| Anti-Pattern Starke Emergenz | — | — | — | — | ✓ | ✓+ | Mitchell |
| Anti-Pattern Black-Box | — | — | — | — | ✓ | ✓+ | Olah |
| Test-Suite-Skeleton | — | — | — | — | ✓ | ✓ | Karpathy |
| **Drei-Schichten-Modell** | — | — | — | — | — | ✓ | **NEU v3.0: Friston/Meadows** |
| **Tool-Populationen** | — | — | — | — | — | ✓ | **NEU v3.0: Variation-Zutat** |
| **Kosten-Budget** | — | — | — | — | — | ✓ | **NEU v3.0: Friston/Kauffman** |
| **Positive Patterns (5 Stück)** | — | — | — | — | — | ✓ | **NEU v3.0: Alexander** |
| **Ecology-Scanner (read-only)** | — | — | — | — | — | ✓ | **NEU v3.0: Mitchell + Meadows** |
| **G.4/G.5 präzisiert** | — | — | — | — | — | ✓ | **NEU v3.0: Wolfram** |
| **Anti-Pattern Magic Scale** | — | — | — | — | — | ✓ | **NEU v3.0: ryz-Debatte** |
| **Anti-Pattern Closed Loop** | — | — | — | — | — | ✓ | **NEU v3.0: Via-Negativa-Schutz** |
| **Fünf-Zutaten-Checkliste** | — | — | — | — | — | ✓ | **NEU v3.0: ryz-Formel** |
| **Spec → Garten** | — | — | — | — | — | ✓ | **NEU v3.0: Deutsch/Meadows** |
| **Metaphysische Agnostik** | — | — | — | — | — | ✓ | **NEU v3.0: ryz-Debatte** |
| **Pearl-Blanket-Notation präzisiert** | — | — | — | — | — | — (v4.0) | **NEU v4.0: Friston** |
| **Drei Kopplungsmechanismen (A.5)** | — | — | — | — | — | — (v4.0) | **NEU v4.0: Simon/Haken/Prigogine** |
| **Endofunktor-Lens (A.6)** | — | — | — | — | — | — (v4.0) | **NEU v4.0: ryz-Ontologie, optional** |
| **Kritikalität Design-Prinzip (C.6)** | — | — | — | — | — | — (v4.0) | **NEU v4.0: Kauffman** |
| **Pattern Kritikalitäts-Pipeline (E.7)** | — | — | — | — | — | — (v4.0) | **NEU v4.0: Kauffman** |
| **Pattern Gradient-Consumer (E.8)** | — | — | — | — | — | — (v4.0) | **NEU v4.0: Prigogine** |
| **A-B-F-Brücke in F.3** | — | — | — | — | — | — (v4.0) | **NEU v4.0: ryz-Ontologie** |
| **Hard-to-Vary-Kern (F.8)** | — | — | — | — | — | — (v4.0) | **NEU v4.0: Deutsch** |
| **Anti-Pattern Level-Confusion (G.12)** | — | — | — | — | — | — (v4.0) | **NEU v4.0: aus A.4/A.5** |
| **Anti-Pattern Bateson-III-Claims (G.13)** | — | — | — | — | — | — (v4.0) | **NEU v4.0: aus Teil N** |
| **H.8 Agency-als-Designprinzip** | — | — | — | — | — | — (v4.0) | **NEU v4.0: bidirektionale Konstitution** |
| **Teil L Theoretisches Fundament** | — | — | — | — | — | — (v4.0) | **NEU v4.0: ryz-Brücke** |
| **Teil M Honesty Inventory** | — | — | — | — | — | — (v4.0) | **NEU v4.0: ryz-Vorbild** |
| **Teil N Scope-Grenzen explizit** | — | — | — | — | — | — (v4.0) | **NEU v4.0: Bateson-II-Klarheit** |
| **Refusal-Handling-Widerspruch fixiert** | — | — | — | — | — | — (v4.1) | **NEU v4.1: Review-Fix** |
| **Teil L auf Kernaussagen gekürzt** | — | — | — | — | — | — (v4.1) | **NEU v4.1: Theorie-Entschlackung** |
| **A.6 Endofunktor-Lens entfernt** | — | — | — | — | — | — (v4.1) | **NEU v4.1: Prestige-Reduktion** |
| **A.5 Kopplungen auf Kurzform** | — | — | — | — | — | — (v4.1) | **NEU v4.1: Gewicht reduziert** |
| **F.3 A-B-F-Brücke entschlackt** | — | — | — | — | — | — (v4.1) | **NEU v4.1: Dubletten raus** |
| **M.6 Metriken-Epistemologie** | — | — | — | — | — | — (v4.1) | **NEU v4.1: Scheingenauigkeit entzaubert** |
| **Goodhart-Warnungen in Metrik-Teilen** | — | — | — | — | — | — (v4.1) | **NEU v4.1: epistemische Ehrlichkeit** |
| **"Regime-Shift" → "Zustandsübergang"** | — | — | — | — | — | — (v4.1) | **NEU v4.1: Sprach-Magnetismus** |
| **Build-Plan in zwei Etappen realistisch** | — | — | — | — | — | — (v4.1) | **NEU v4.1: Karpathy-Realismus** |
| **Ecology erst in Etappe 2** | — | — | — | — | — | — (v4.1) | **NEU v4.1: Scope-Reduktion für v4.1-alpha** |
| Cross-Model-Benchmark | — | — | — | — | — | — (Phase 4+) | Zu groß |
| Emergenz-Map-Scanner | — | — | — | — | — | ⚠️ (teilweise) | In Ecology-Scanner angelegt |

---

# TEIL J: OFFENE FRAGEN

Nicht alles ist entschieden. Diese Fragen bleiben für den Builder zur Klärung:

## J.1 Aus v2.2 übernommen

1. **Konkrete Schwellwerte:** Similarity-Thresholds, Max-Turns, Degradation-Scores müssen empirisch kalibriert werden.

2. **LLM-Client-Abstraktion:** Einheitliche Schnittstelle für Provider.

3. **Session-Kontinuität:** Multi-Pipeline-Sessions nicht adressiert.

4. **Multi-Turn Tools:** Spec ist Single-Turn.

5. **Daseinsberechtigung:** Empfohlen ein informelles Gespräch mit menschlichem Skeptiker vor Produktiv-Einsatz.

6. **Determinism-Test vs. LLM-Temperature:** Default-Temperature für Tests?

7. **Introspection-Privacy:** Redaction-Patterns bei sensiblen Daten.

8. **Signature-Hash bei Template-Änderungen:** Kanonisierung vor Hashing?

9. **Tick-gated Performance:** Client-Pool-Architektur.

## J.2 Neu in v3.0

10. **Tool-Population-Versionierung:** Wie werden Varianten innerhalb einer Population versioniert? Semver pro Variante? Shared Population-Version?

11. **Budget-Granularität:** Sollte `budget` auch pro Stage möglich sein, nicht nur pro Pipeline?

12. **Ecology-Scanner-Frequenz:** Täglich, wöchentlich, nach N Sessions? Trade-off zwischen Aktualität und Noise.

13. **Ecology-Report-Format:** Markdown reicht, oder strukturierter Report mit Maschinen-Lesbarkeit für Dashboards?

14. **Cross-Population-Patterns:** Können sich Patterns über mehrere Populationen erstrecken? Beispiel: "Tool X in Kombination mit Tool Y führt immer zu Refusal."

15. **Garten-Governance:** Wer entscheidet über Deprecation? Einzel-Builder oder Team-Konsens? Braucht es einen "Gartenmeister"-Role?

16. **Schicht-Übergänge:** Kann ein Tool "aufsteigen" zur Pipeline wenn es ein Muster wird? Kann eine Pipeline "absteigen" zu einem Tool wenn es atomar wird?

17. **Pattern-Maturity-Lifecycle:** Wie lange bleibt ein Pattern "experimental"? Welche Kriterien für "mature"?

---

# TEIL L: THEORETISCHES FUNDAMENT

Optional für Builder. Wer das Framework nur implementieren will, kann diesen Teil überspringen. Wer den theoretischen Hintergrund verstehen will, findet hier die Ankerpunkte.

## L.1 Kernpunkt

Das Framework ist Engineering, keine Theorie. Aber seine Design-Entscheidungen sind **konsistent** mit etablierter Systemtheorie - ohne diese zu implementieren. Diese Konsistenz ist kein Zufall, sondern folgt daraus dass die zugrundeliegenden Probleme (Stabilität unter Iteration, Schichten-Kopplung, Identitäts-Erhaltung) in vielen Bereichen strukturell ähnlich sind.

## L.2 Pearl-Blanket vs. Friston-Blanket

Das Framework nutzt "Markov Blanket" durchgängig im **Pearl-Sinn** (Pearl 1988): kleinste Knotenmenge die X bedingt unabhängig vom Rest macht. Werkzeug der probabilistischen Inferenz, nicht ontologische Aussage.

Das Framework nutzt Markov Blanket explizit **nicht** im Friston-Sinn (Friston 2013+): ontologische Erweiterung in Richtung "jedes persistente System hat Blanket-Struktur" mit Free-Energy-Principle-Verkettung. Diese Erweiterung ist kontrovers (Bruineberg et al. 2022).

Warum: Friston-Blankets würden implizieren dass Tools ein "Selbst" haben. Das ist genau was G.8 (Starke Emergenz) verbietet. Pearl-Blankets sind die Beschreibungssprache für Informations-Nicht-Fluss - ohne ontologische Aufladung.

## L.3 Die fünf Zutaten als operationale Lesart

Die ryz-Formel (Variation + Constraints + Memory + Selektion + Laufzeit) ist eine operationale Beschreibung dessen, was in der Stabilitätstheorie strukturell als A-B-F-Triade formuliert wird (Rate, Proportion, Asymmetrie). Beide beschreiben dasselbe Phänomen aus verschiedenen Richtungen. Das Framework nimmt keine Position dazu welche Lesart "richtiger" ist - die operationale ist praktischer für Builder.

Vollständige Prozess-Ontologie: siehe ryz (2026) *Disorder → Process → Bit → It*.

## L.4 Was das Framework theoretisch NICHT behauptet

- Keine Aussage dass seine Schichten-Kaskade die "wahre Struktur" der Realität spiegelt
- Keine Behauptung dass Tools "leben" oder bewusst sind
- Keine Aussage dass aggregierte Log-Muster Bewusstsein oder AGI darstellen
- Keine Aussage dass die Prozess-Ontologie korrekt oder falsch ist

**Was das Framework behauptet:** Seine Design-Entscheidungen sind mit etablierter Systemtheorie konsistent. Das reicht.

## L.5 Optionale Lens: Endofunktor-Kaskade

Fußnote für mathematisch Interessierte: Die drei Schichten können als Kaskade nested Endofunktoren gelesen werden. Tools sind Endofunktoren auf Context, Pipelines auf Tool-Outputs, Ecology auf Pipelines. Der `signature_hash` entspricht Lambeks Fixpunkt-Konstruktion. Diese Lens ist *nicht* umzusetzen im Code - A, B, F sind keine Tool-Attribute. Sie dient nur dem Verstehen.

## L.6 Weiterführende Lektüre

- ryz (2026): *Disorder → Process → Bit → It* (v2) - Prozess-Ontologie als Inspirationsquelle
- Prigogine, Stengers (1984): *Order Out of Chaos* - dissipative Strukturen
- Simon (1962): *The Architecture of Complexity* - near-decomposability
- Bruineberg et al. (2022): *The Emperor's New Markov Blankets* - Pearl vs. Friston
- Deutsch (2011): *The Beginning of Infinity* - hard-to-vary
- Alexander (1977): *A Pattern Language* - Patterns als Sprache
- Meadows (2008): *Thinking in Systems* - Leverage Points

---

# TEIL M: HONESTY INVENTORY

Dieser Teil inventarisiert ehrlich was das Framework kann und was nicht. Format inspiriert von ryz' Prozess-Ontologie (Abschnitt 15). Builder sollten diesen Teil regelmäßig lesen - besonders wenn sie versucht sind zu glauben, das Framework löse mehr als es löst.

## M.1 Was das Framework kann

**Strukturiertes LLM-Debugging:**
Pipelines aus drei Schichten erlauben systematische Analyse von LLM-Interaktionen. Die drei Initial-Tools (strukturelles_bild, mirror_refusal, abweichungskarte) bieten einen operationalen Einstieg für LLM-Debugging-Workflows.

**Schutz vor häufigen LLM-Anti-Patterns:**
- Via-Negativa-Kern verhindert Tool-als-Entität-Probleme
- Locality-Enforcement verhindert Scope-Inflation
- Determinism-Test macht Drift messbar
- Signature-Hash macht Tool-Identität stabil
- Ecology-Scanner macht Performance-Degradation sichtbar

**Saubere Trennung Engineering vs. Theorie:**
Der Hard-to-vary-Kern (F.8) ist klein und definiert. Das Framework ist robust gegen peripheres Variieren (konkrete YAML-Syntax, konkrete Anzahl Tools, konkrete Sprache). Das erleichtert Weiterentwicklung ohne Kern-Zerstörung.

**Deklarative Komposition statt prozeduraler:**
Pipelines sind YAML, nicht Code. Das macht sie review-bar, versioniert und reviewable durch Non-Programmierer.

**Kosten-Transparenz:**
Costs und Budget sind First-Class-Attribute. Framework macht nicht "billig wird wegoptimiert" - es macht Kosten messbar und Trade-offs explizit.

**Positive und negative Patterns:**
Teil E (5 Patterns) und Teil G (13 Anti-Patterns) geben Buildern beide Richtungen der Orientierung.

**Agent-Integration:**
Framework läuft problemlos unter LLM-Agent-Orchestrierung (Claude Code, etc.). Die Kontrolle bleibt beim Menschen, aber die Ausführung kann delegiert werden.

## M.2 Was das Framework explizit NICHT kann

**Keine AGI, keine ASI:**
Das Framework baut Bateson-II-Systeme (siehe Teil N). Es ermöglicht keine autonome Identitäts-Reorganisation, keine Meta-Reflexion über eigene Regeln, keine echte Selbst-Modifikation. Das ist Designentscheidung, nicht Limitation.

**Keine Emergenz-Magie:**
Wer glaubt, Scale + Runtime + Framework = Emergenz - irrt (Anti-Pattern G.10). Das Framework erfüllt höchstens schwache Emergenz auf Schicht 2 (Muster in Logs, vom Menschen interpretiert). Starke Emergenz ist strukturell verhindert.

**Keine garantierte Qualität:**
Tools können schlechte Outputs produzieren. Pipelines können budget-overrun. Die Ecology kann Muster zeigen die Fehlinterpretation sind. Das Framework garantiert Struktur, nicht Inhalts-Qualität.

**Keine LLM-Unabhängigkeit:**
Die Tools sind an LLM-Verhalten gebunden. LLM-Modell-Drift (neue Version des Modells verhält sich anders) kann Pipelines invalidieren. Determinism-Test hilft das zu detektieren, löst es aber nicht.

**Keine semantische Garantie:**
Structural Integrity ist topologisch definiert (A.5, Ebene 1-3). Das Framework behauptet nicht dass strukturell integre Outputs semantisch korrekt sind. Ein Tool kann perfekt strukturiert und komplett inhaltlich falsch sein.

**Kein Ersatz für Domain-Expertise:**
Das Framework ist Meta-Tool. Es analysiert LLM-Interaktionen, es ist nicht selbst Experte in einer Domäne. Wer Juristen braucht, braucht Juristen - das Framework kann nur den Dialog mit einem LLM strukturieren, das Juristen-Aufgaben bearbeitet.

**Keine ethische Garantie:**
Tools und Pipelines können für harmlose wie problematische Zwecke eingesetzt werden. Das Framework ist neutral bezüglich der Ziele für die es verwendet wird. Verantwortung liegt beim Menschen der es einsetzt.

**Keine Sicherheit gegen aktive Gegner:**
Das Framework schützt gegen Drift, nicht gegen Adversarial Inputs. Ein Angreifer der gezielt Context-Injection versucht, könnte Tools manipulieren. Härtung gegen Angriffe ist separate Anforderung.

## M.3 Overfit-Risiken

Das Framework wurde über 4 Versionen (v1 → v4.0) entwickelt, mit extensiven Review-Runden. Das erzeugt Risiken:

**Convergence-Feeling könnte Attraktor-Absorption sein:**
Wenn alle Gremium-Runden zu konvergierenden Empfehlungen führen, könnte das bedeuten (a) das Framework ist tatsächlich gut oder (b) die Review-Methodologie erzwingt Konvergenz. Die Wahrheit liegt vermutlich dazwischen.

**Post-hoc-Rationalisierung:**
Die theoretischen Ankerpunkte in Teil L wurden *nach* den Design-Entscheidungen hinzugefügt. Es ist möglich dass einige "Konsistenzen mit der Prozess-Ontologie" retroaktiv konstruiert sind. Builder sollten das im Hinterkopf behalten.

**Selbstähnlichkeit zur Denk-Architektur der Autoren:**
Das Framework passt verdächtig gut zu wie Alexander und Claude gemeinsam strukturieren. Ob das universelle Anwendbarkeit bedeutet oder spezifische Autor-Signatur, ist offen.

**Explanatory overreach:**
Das Framework *erklärt* eventuell mehr als es *kann*. Theoretische Brücken (Teil L) können verführen zu glauben, die Theorie mache das Framework besser. Engineering-Value und theoretische Eleganz sind verschiedene Metriken.

## M.4 Was empirisch unklar ist

Die folgenden Fragen sind in v4.0 offen:

**Skaliert das Framework auf große Projekte?**
Getestet mit 3 Tools, 1 Pipeline, 1 Ecology-Scanner. Unklar ob 30 Tools, 10 Pipelines, 5 Ecology-Scanner noch die gleiche Qualität liefern oder ob sich neue Anti-Patterns zeigen.

**Funktioniert es Cross-Model?**
Tests waren primär mit Claude. Ob das Framework mit GPT, Gemini, Llama gleich funktioniert - offen.

**Wie ist die Lernkurve für neue Builder?**
Framework hat 2600+ Zeilen Dokumentation. Onboarding-Zeit unbekannt. Risiko: zu steil für praktische Adoption.

**Ist die Agnostik-Position haltbar?**
Teil L behauptet theoretische Robustheit bei metaphysischer Agnostik. Ob das bei aggressivem philosophischem Stress-Test hält, nicht formal geprüft.

## M.5 Honest Confession

Nach vier Versionen zugeben: Das Framework *könnte* overengineering sein.

Argumente dafür:
- 2600+ Zeilen Spec für ein Tool-Set von drei Tools
- Zwölf Runden Meta-Reflexion für ~900 Zeilen Python
- Theoretische Fundierung die den praktischen Use-Case übersteigt

Argumente dagegen:
- Die Erweiterungen (v2.2, v3.0, v4.0, v4.1) kamen aus konkreten Review-Kritiken, nicht aus abstrakter Perfektion
- Jede Hinzufügung löst ein dokumentiertes Problem
- Der Hard-to-Vary-Kern ist klein - die Peripherie kann reduziert werden ohne Kern-Verlust
- v4.1 ist zum ersten Mal eine *kürzende* Version

**Empfehlung:** Phase 1-2 bauen und evaluieren. Wenn das Framework sich als zu schwer erweist, reduzieren auf Kern (F.8) und bewährte Patterns. Dokumentation ist Infrastruktur, nicht Verpflichtung - Teile L, M, N können ausgelagert werden wenn sie den praktischen Betrieb behindern.

## M.6 Metriken-Epistemologie (NEU v4.1)

Alle quantitativen Signale im Framework sind **heuristische Diagnostik-Hilfen**, keine wissenschaftlichen Messinstrumente. Dieser Abschnitt macht die Grenzen explizit, weil sie in den elegant formulierten Metrik-Beschreibungen leicht untergehen.

### Allgemeine Grenzen

**Sample-Größen:** Alle aggregierten Metriken (KPI-Hit-Rate, Refusal-Rate, Stage-Korrelationen) brauchen mindestens 30 Sessions um statistisch halbwegs belastbar zu sein. Unter 10 Sessions ist praktisch Rauschen. Zwischen 10-30 Sessions: Trends möglich, keine Aussagen.

**Sample-Homogenität:** Alle aggregierten Metriken setzen vergleichbare Sessions voraus. Wenn die Tools in unterschiedlichen Kontexten eingesetzt werden (z.B. manchmal für Einfach-Debugging, manchmal für Architektur-Analyse), vermischen sich Signale.

**Schwellwert-Willkür:** Die konkreten Zahlen im Framework (KPI-Hit-Rate < 0.4, Korrelation ~0.3-0.6, sessions_per_month < 5) sind Plausibilitäts-Ausgangswerte. Sie kommen aus Überlegung, nicht aus empirischer Kalibrierung. Builder sollten sie als Startpunkte verstehen und basierend auf ihren Daten anpassen.

### Der Goodhart-Effekt

> "When a measure becomes a target, it ceases to be a good measure." (Goodhart 1975)

Alle Framework-Metriken sind anfällig:

- **KPI-Hit-Rate wird zum Target:** Tools werden so formuliert dass sie die KPI treffen, auch wenn die KPI schlecht spezifiziert ist. Die Metrik misst dann "Anpassung an KPI", nicht "Qualität des Tools".
- **Refusal-Rate wird zum Target:** Tools werden so formuliert dass sie Refusals weniger auslösen - möglicherweise durch Prompt-Verschiebungen die andere Probleme produzieren.
- **Stage-Korrelation wird zum Target:** Pipelines werden so getuned dass die Korrelation "im grünen Bereich" liegt - möglicherweise durch Kopplungs-Manipulation die die strukturelle Isolation untergräbt.

**Konsequenz:** Metriken sollten *regelmäßig rotiert und revisiert* werden. Wer dieselbe KPI 12 Monate lang fährt, hat einen Goodhart-Krater gebaut.

### Was Metriken NICHT leisten

**Keine Qualitäts-Bewertung:** Ein Tool das 90% KPI-Hit hat, ist nicht "90% gut". Die KPI misst *eine* Dimension. Andere Dimensionen (Präzision, Nützlichkeit, Robustheit) können völlig unabhängig davon stehen.

**Keine Vergleichbarkeit über Kontexte:** Tool A in Kontext X kann eine andere Performance zeigen als Tool A in Kontext Y. Die aggregierte Zahl verwischt das.

**Keine Kausal-Aussagen:** Die Ecology-Metriken zeigen Korrelationen. Wenn KPI-Hit fällt, ist die Ursache unbekannt - vielleicht ist das Tool degradiert, vielleicht hat sich der Input-Typ geändert, vielleicht ist das LLM gewechselt.

### Reporting-Prinzip

Jeder Ecology-Report sollte enthalten:
- Die Metrik
- Die Sample-Größe
- Einen Sample-Homogenitäts-Hinweis
- Eine Goodhart-Warnung wenn die Metrik über längere Zeit als Ziel benutzt wurde
- Eine explizite Empfehlung: "Dies ist ein heuristischer Hinweis, keine wissenschaftliche Messung"

Wer das nicht tut, baut **Scheingenauigkeit** - elegant aussehende Zahlen die mehr epistemische Härte suggerieren als sie haben.

### Fazit

Metriken im Framework sind **Dialog-Eröffner**, keine Wahrheiten. Sie sagen "hier lohnt sich Nachdenken", nicht "hier ist die Antwort". Wer sie anders behandelt, hat das Framework nicht verstanden.

---

# TEIL N: WAS DAS FRAMEWORK NICHT IST

Explizite Scope-Begrenzung. Framework ist präzise in dem was es macht und präzise in dem was es nicht macht.

## N.1 Das Framework ist Bateson-II, nicht Bateson-III

Gregory Batesons Lerntheorie (1972) unterscheidet:

**Learning Zero:** Reizantwort. Kein Lernen im eigentlichen Sinn.

**Learning I (Bateson I):** Strukturmodifikation. System passt Verhalten an, Regeln bleiben. Beispiel: Tool-Population bekommt neue Variante, alte bleiben verfügbar.

**Learning II (Bateson II):** Modifikation der Lernregeln. Deutero-Lernen. System lernt besser zu lernen. Beispiel: Builder ändert Pattern basierend auf Ecology-Reports.

**Learning III (Bateson III):** Profound reorganization of character. System ändert Identität die lernt zu lernen. Selten, oft destabilisierend. Bateson selbst beschrieb dies als mit religiöser Konversion oder schweren Krisen assoziiert.

**Das Framework operiert explizit auf Bateson II:**
- Tools und Pipelines operieren brillant innerhalb gegebener Regeln (Bateson I bei Anwendung, Bateson II durch Human-initiierte Population-Updates)
- Das Framework selbst entwickelt sich durch Review-Zyklen (Bateson II durch Gremium-Feedback)
- Aber: Die fundamentale Via-Negativa-Haltung, die Drei-Schichten-Trennung, die Read-Only-Ecology - diese Identitäts-Kerne werden nicht automatisch zur Disposition gestellt

**Warum das wichtig ist:**
Aktuelle AI-Safety-Forschung (RLHF, Constitutional AI, deliberative alignment) zielt auf Bateson-II-Systeme. Das Framework passt in diese Tradition. Ein System das echtes Bateson III beherrschen würde - strukturelle Reorganisation eigener Identität - wäre nicht mehr alignable im klassischen Sinn, weil Werte selbst zur Disposition stehen.

**Die strukturelle Unmöglichkeit von "aligned Bateson III":**
Reflexivität (Voraussetzung für Bateson III) und Wertehaltung (Voraussetzung für Alignment) sind nicht trennbar. Ein System das seine Werte reflektieren kann, kann sie auch reinterpretieren. Das bedeutet:

- **Entweder** man baut Bateson-II-Systeme (wie dieses Framework) - aligned, aber prinzipiell begrenzt
- **Oder** man baut Bateson-III-Systeme - potentiell fähig, aber nicht garantiert aligned
- Keine dritte Option "aligned Bateson III" - Begriffe schließen einander strukturell aus

Das Framework wählt explizit Bateson II. Das ist keine Schwäche. Es ist Klarheit über den Scope.

## N.2 Das Framework ist Engineering, nicht Prozess-Ontologie

Teil L macht Brücken zur Prozess-Ontologie explizit. Aber das Framework *ist* nicht die Prozess-Ontologie.

**Was das bedeutet:**
- Die A-B-F-Triade ist eine *Lens* fürs Verstehen, kein Code-Artefakt
- Endofunktor-Kaskaden sind *Analogie*, keine Implementierung
- Der Hard-to-Vary-Kern ist klein und konkret, nicht philosophisch

**Warum die Trennung wichtig ist:**
Wer das Framework baut und dabei versucht die komplette Prozess-Ontologie mit zu implementieren, verliert sich in Metaphysik und liefert keinen Code. Wer die Prozess-Ontologie formalisiert und dabei in Engineering-Detail geht, macht dieselbe Theorie schlechter greifbar.

**Beide Projekte sind legitim, aber sie sind verschiedene Projekte.** Das Framework nutzt die Ontologie als Referenzrahmen, nicht als Implementierungsvorlage.

## N.3 Das Framework ist kein Autopoietisches System

Humberto Maturana und Francisco Varela (1980) definierten autopoietische Systeme: Systeme die ihre eigenen Komponenten kontinuierlich produzieren und erneuern. Lebende Zellen sind der Prototyp.

**Das Framework ist explizit NICHT autopoietisch:**
- Tools werden von Menschen geschrieben, nicht vom Framework erzeugt
- Pipelines werden von Menschen komponiert, nicht vom Framework optimiert
- Die Ecology beobachtet, sie produziert keine neuen Komponenten

**Warum das wichtig ist:**
Autopoietische Systeme haben notwendig eine Form von Agency - sie erhalten sich selbst, also haben sie Interessen. Das Framework hat keine Interessen. Es ist Infrastruktur, nicht Agent.

Das ist kein Nachteil. Werkzeuge sind per Definition nicht autopoietisch. Ein Hammer erhält sich nicht selbst - deshalb ist er ein gutes Werkzeug. Ein Framework das sich selbst erhält, würde seine Toolhaftigkeit verlieren und zum Agent werden. Das ist genau was wir via G.11 und G.13 verhindern.

## N.4 Das Framework garantiert keine Intelligenz

Das Framework strukturiert LLM-Interaktionen. Es macht sie nicht klüger.

**Konsequenzen:**
- Ein dummes LLM wird nicht schlau durch das Framework
- Ein intelligentes LLM wird nicht verdummt durch das Framework
- Das Framework kann die Intelligenz des LLMs besser *nutzen*, aber nicht *erzeugen*

**Metapher:** Das Framework ist wie ein gut organisierter Schreibtisch. Der Schreibtisch macht den Autor nicht klüger. Er macht das Arbeiten effizienter. Wenn jemand behauptet sein Schreibtisch produziere Intelligenz, ist das Quatsch. Wenn jemand behauptet ein gut organisierter Schreibtisch sei wertlos, ist das auch Quatsch.

## N.5 Das Framework ist nicht universell

Das Framework ist für LLM-Interaktions-Debugging designed. Es ist **nicht** designed für:

- Allgemeine Software-Architektur (obwohl manche Patterns übertragbar sind)
- Datenpipelines (obwohl Schichten-Denken ähnlich ist)
- ML-Training (völlig andere Constraints)
- Web-APIs (kein LLM in der Mitte)
- Desktop-Apps (keine strukturierten Dialog-Flows)

**Was bedeutet "für LLM-Debugging"?**
- Der zu analysierende Prozess ist eine LLM-Konversation
- Die Tools operieren auf LLM-Outputs als Input-Gradienten
- Die Patterns adressieren LLM-spezifische Probleme (Refusal, Stagnation, Drift)

Wer das Framework auf andere Domänen anwenden will, sollte fragen ob die Kern-Annahmen noch gelten. Meist wird zumindest Teil B (Tool-Schicht) neu konzipiert werden müssen.

## N.6 Das Framework ersetzt nicht die Haltung

Ein Framework kann eine Haltung **unterstützen** oder **untergraben**. Es kann eine Haltung nicht **ersetzen**.

**Die Haltung die das Framework unterstützt:**
- Strukturelle Klarheit statt semantische Schwurbelei
- Transparenz statt Black-Box
- Messbare Outcomes statt User-Pleasing
- Human-Agency statt automatisierte Entscheidungen
- Garten-Pflege statt Spec-Enforcement

**Die Haltung die das Framework nicht ersetzt:**
- Intellektuelle Ehrlichkeit beim Lesen von LLM-Outputs
- Mut zuzugeben wenn eine Pipeline gescheitert ist
- Disziplin das Framework nicht zu bypassen wenn es unbequem ist
- Geduld mit Iteration statt Framework-Ersetzung

Wer das Framework ohne diese Haltungen verwendet, produziert mit ihm dieselben Probleme die er ohne es hätte - nur strukturierter dokumentiert.

## N.7 Was das Framework erlaubt, aber nicht verlangt

Das Framework ist ein **Kompass**, kein Bauplan (H.6). Das heißt konkret:

**Erlaubt:**
- Teile weglassen die nicht passen (Ecology ignorieren wenn unnötig)
- Eigene Patterns hinzufügen die Bedürfnisse adressieren
- Abweichungen wo der Kontext es rechtfertigt
- Kritik am Framework und begründete Änderungs-Vorschläge

**Nicht verlangt:**
- Alle Teile in v4.0 zu implementieren
- Die theoretischen Brücken (Teil L) zu verstehen oder zu akzeptieren
- Gremium-Review für jede lokale Anwendung
- Metaphysische Positionen zu Emergenz zu beziehen

**Was unverhandelbar bleibt:**
Der Hard-to-Vary-Kern aus F.8. Wer Tool-als-Operation-nicht-Entität, Drei-Schichten-Trennung oder Read-Only-Ecology aufweicht, baut ein anderes Framework. Das darf er - aber er sollte es nicht dieses Framework nennen.

---

# TEIL K: SCHLUSS

Dieses Dokument ist das Ergebnis von ca. 30 Stunden Co-Kreation zwischen Alexander und Claude, mit externen Reviews von Gemini und ChatGPT in drei Runden, einem fünfköpfigen Conway-Gremium-Review für v2.2, einem achtköpfigen Erweiterten-Gremium-Review für v3.0, einem neunköpfigen Prozess-Ontologie-Gremium für v4.0, einem externen Review der v4.0 das zu v4.1 führte, plus vierzehn Runden Agenten-Meta-Reflexion, plus einer externen Emergenz-Debatte mit ryz die zur ryz-Formel und zu ryz' eigener Prozess-Ontologie als Inspirationsquelle für v4.0 führte.

## Was v4.1 ausmacht

Ein **Konsolidierungs-Release**. Externes Review identifizierte fünf konkrete Schwachstellen in v4.0. Anders als die Gremium-Runden vorher ging es diesmal nicht um Hinzufügen, sondern um **Zurückschneiden wo Prestige war, Schärfen wo Präzision fehlte**:

**Konkret gefixt:**

1. **Refusal-Handling-Widerspruch beseitigt** - Mirror-Pattern und Tool-Spec sind konsistent
2. **Theorie-Teile radikal entschlackt** - Teil L von 120 auf ~40 Zeilen, A.6 entfernt, A.5 auf Kurzform
3. **Metriken epistemisch entzaubert** - Alle Kennzahlen als Heuristik markiert, neue Sektion M.6 mit expliziten Grenzen, Goodhart-Warnungen überall
4. **Sprach-Magnetismus reduziert** - "Regime-Shift" → "Zustandsübergang", nüchternere Formulierungen im Kern-Text
5. **Build-Plan realistisch** - 800+400 Zeilen in zwei Etappen, Ecology explizit NICHT im ersten Build

**Was v4.1 damit bezweckt:**

Das Framework von einem "intelligenten Dokument über ein mögliches Artefakt" näher an ein "baureifes Artefakt selbst" zu bringen. Der Weg dahin war nicht mehr Theorie, sondern **Konsolidierung**. Weniger Prestige, mehr Handwerk. Das Dokument wurde an einzelnen Stellen drastisch kürzer (Teil L, A.5, A.6, F.3), an anderen gezielt erweitert (M.6, Build-Plan, Goodhart-Warnungen). Netto etwa gleiche Länge - aber präziser, ehrlicher und baunäher.

## Fünf Shifts über fünf Versionen

| v1 | v2.1 | v2.2 | v3.0 | v4.0 | v4.1 |
|---|---|---|---|---|---|
| Technical Spec | Spec mit Historie | Spec + GoL-Disziplin | Garten statt Spec | Garten mit Theorie | Garten nach Rückschnitt |

## Bauempfehlung (v4.1 - realistisch)

Der Build sollte als **Referenz-Implementierung in zwei Etappen** passieren, nicht als "Framework für alles" in einem Rutsch.

### Etappe 1: Operativer Kern (v4.1-alpha)

**Phase 1 (4-5 Tage, ~800 Zeilen Python):** Schicht 0 vollständig
- Loader, Applier mit SandboxedContext
- Signature-Hasher, Locality-Enforcement, Introspection-Collector
- Health-Check in drei Modi inklusive Determinism-Test
- Drei konkrete Tool-Populationen mit je einer Variante (minimal)
- Basis-Tests für alle Komponenten

**Phase 2 (3-4 Tage, ~400 Zeilen Python):** Minimale Schicht 1
- Pipeline-Runner sequential only (kein tick_gated)
- KPI-Enforcement mit Level-1-Pflicht
- Budget-Enforcement
- Eine Beispiel-Pipeline mit den drei Tools
- Pipeline-Integration-Tests

**Pause und ehrliche Evaluation.** Phasen-Abschluss-Check gegen Teil M (Honesty Inventory):
- Funktioniert der Kern?
- Sind Tool-Populationen nützlich oder overengineered?
- Wie viel Python-Code tatsächlich entstanden?
- Welche Edge-Cases wurden nicht bedacht?

### Etappe 2: Ecology-Schicht (v4.1-beta, separates Projekt)

**Nur bei positiver Evaluation von Etappe 1 starten.**

Phase 3 (später, ca. 5-7 Tage, ~500 Zeilen Python): Schicht 2
- Session-Logging
- Ecology-Scanner mit heuristischen Metriken (siehe M.6 für Grenzen)
- Fitness-Aggregation
- Read-Only Report-Generator

**Wichtig:** Schicht 2 ist in v4.1 explizit NICHT Teil des ersten Builds. Sie ist separates Projekt das erst sinnvoll wird wenn Schichten 0+1 genug Sessions produziert haben.

### Was NICHT in v4.1-alpha gehört

- Tick-gated Pipelines (optionales Schicht-1-Feature für später)
- Cross-Model-Benchmarks
- Vollständige Metrik-Suite (nur Basis-KPIs)
- Emergenz-Map über Pipelines
- Multi-Turn-Tools
- Method-Engine (bleibt Forschung)

### Gesamt-Aufwand realistisch

Etappe 1 (Schichten 0+1): **ca. 1200 Zeilen Python, 7-9 Tage Engineering-Zeit**
Etappe 2 (Schicht 2): **ca. 500 Zeilen Python, 5-7 Tage Engineering-Zeit - nach Etappe 1**

Beides zusammen: ~1700 Zeilen Python über 12-16 Tage. Das ist die realistische Schätzung, nicht die optimistische 1200-1500 in einem Rutsch wie in früheren Versionen.

**Wichtig:** Der wahre Aufwand sitzt nicht im happy path sondern in:
- Drift-Handling und Fehler-Szenarien
- Testbarkeit (Mocks für LLM-Clients, deterministische Test-Fixtures)
- Schicht-Übergängen (besonders Context-Sandboxing)
- Edge-Cases im YAML-Loader (Schema-Validierung, Fehler-Meldungen)

Wer diese Teile vergisst, braucht statt 12 Tagen dann 20. Lieber von Anfang an mitplanen.

## Was v4.0 nicht ist

Siehe Teil N für die ausführliche Positionierung. Kurzfassung:
- **Keine vollständige AGI-Lösung.** Framework ist Bateson II by design.
- **Keine Prozess-Ontologie.** Framework ist Engineering mit theoretischen Brücken.
- **Kein autopoietisches System.** Framework ist Infrastruktur, nicht Agent.
- **Kein universelles Werkzeug.** Framework ist für LLM-Debugging.
- **Kein Ersatz für menschliche Haltung und Urteilskraft.**
- **Keine finale Version.** v4.1 nach Phase 1-4, basierend auf Build-Lessons.

## Was bleibt konstant

Der Via-Negativa-Kern: **Tool ist keine Entität. Operation statt Objekt. Zeigen statt tun.**

Die Leitsätze der vorigen Versionen bleiben in v4.1 gültig:

- Mitchell (v2.2): **"Conway respektieren indem man nicht versucht wie Conway zu sein."**
- Alexander (v3.0): **"Ein Garten respektiert seine Pflanzen indem er sie pflegt, nicht indem er sie programmiert."**
- Friston (v4.0): **"Pearl-Blanket als Werkzeug, nicht als Seele."**
- Reviewer (v4.1): **"Ein Framework das sich selbst widerspricht ist nicht hard-to-vary - es ist kaputt."**

Und der vielleicht wichtigste Satz des ganzen Projekts, der sich aus der Prozess-Ontologie-Diskussion ergab:

**"Das Framework implementiert die Theorie nicht. Es ist konsistent mit ihr. Das ist genug."**

Alles andere ist verhandelbar.

---

**Ende des Dokuments**
