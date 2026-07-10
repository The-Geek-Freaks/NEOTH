---
title: "NEOTH Vault Architecture Report"
date: "2026-07-06"
tags: [obsidian, vault, pkm, lyt, para, architecture, template, dataview]
author: "Vault Template Thief Scout"
type: "moc"
---

# NEOTH Vault Architecture Report

[INTENT: EXECUTIVE_SUMMARY]
Dieser RAG-Report synthetisiert die besten Praktiken aus führenden Obsidian "Second Brain" und Developer-Vaults (LYT Kit, PARA, IDEA, Obfluence, Claude/AI Starters) für das Projekt **NEOTH**. Die Architektur ist darauf ausgelegt, KI-gestützte Workflows, MOCs (Maps of Content) und Dataview-Tracking nativ zu unterstützen. Der Fokus liegt auf "Fluidität" und Metadaten statt auf starrer Ordner-Hierarchie.

[INTENT: DIRECTORY_ARCHITECTURE]
Die ideale Struktur für einen AI/Developer-Vault verbindet die Action-Orientierung von PARA mit der dynamischen Vernetzung von LYT (ACE-Framework). Das vermeidet tiefe Verschachtelungen:

```text
📁 00_Meta          # Templates, Scripts, Dataview-Snippets, Canvas, Assets
📁 01_Inbox         # Drop-Zone für neue Notizen, Web-Clippings, AI-Dumps
📁 02_Atlas         # MOCs (Maps of Content), Globale Indizes, Dashboards
📁 03_Efforts       # Aktive Projekte, Sprints, Epics (PARA: Projects)
📁 04_Spaces        # Kern-Wissensbereiche (PARA: Areas/Resources, z.B. AI, Dev)
📁 05_Calendar      # Daily Notes, Meeting Notes, Logbücher
📁 09_Archive       # Abgeschlossene Projekte, veraltetes Wissen
```

[INTENT: METADATA_PROPERTIES]
Ein standardisiertes YAML-Frontmatter ist essentiell für Dataview und externe AI-Parser (wie RAG-Systeme). Jedes Template sollte diese Properties erzwingen:

```yaml
---
aliases: []
tags: []
type: "note" # [note, moc, effort, meeting, source]
status: "seed" # [seed, incubation, evergreen, active, completed]
created: "{{date}} {{time}}"
updated: "{{date}} {{time}}"
effort: "" # Link zum übergeordneten Projekt (Effort)
due: "" # Optional für Tasks/Efforts
---
```

[INTENT: TAGGING_TAXONOMY]
Anstatt Ordner als primäre Kategorisierung zu nutzen, verwenden Profis ein starkes, dimensionales Tagging-System:
- **Zustand (Digital Garden):** `#status/seed` (Roh), `#status/incubation` (In Arbeit), `#status/evergreen` (Verifiziertes Wissen)
- **Typologie:** `#type/moc`, `#type/template`, `#type/meeting`, `#type/architecture`
- **Domäne/Topic:** `#dev/python`, `#ai/llm`, `#ai/rag`, `#infra/docker`

[INTENT: DATAVIEW_QUERIES]
Diese Queries sind der "Motor" des NEOTH Vaults und machen MOCs zu dynamischen Dashboards. Sie gehören in die Index-Dateien im Ordner `02_Atlas`.

**1. Globale MOC Übersicht (Zeigt alle Maps of Content):**
```dataview
LIST 
FROM #type/moc
SORT file.name ASC
```

**2. Active Efforts Tracker (z.B. für `02_Atlas/Project_Dashboard.md`):**
```dataview
TABLE status, due, file.mtime as "Last Updated"
FROM "03_Efforts"
WHERE status != "completed" AND type = "effort"
SORT due ASC
```

**3. Inbox Processing / Needs Attention (Für das Daily Dashboard):**
```dataview
TABLE created, tags
FROM "01_Inbox"
WHERE status = "seed"
SORT created DESC
```

[INTENT: NEOTH_INTEGRATION_PLAN]
Um diese Struktur optimal in den Workspace von `The-Geek-Freaks/NEOTH` zu integrieren, sind folgende Schritte nötig:
1. **Verzeichnis-Skelett anlegen:** Erstelle die Root-Verzeichnisse (`00_Meta` bis `09_Archive`).
2. **Templates ausrollen:** Lege ein `Base_Note.md` und ein `Effort_Template.md` mit dem exakten YAML-Frontmatter (siehe oben) im Ordner `00_Meta/Templates` ab.
3. **Core-Konfiguration:** Richte das *Templates* (oder Templater) Plugin so ein, dass es direkt auf `00_Meta/Templates` verweist.
4. **Dependencies installieren:** Stelle sicher, dass das *Dataview* Plugin aktiv ist, um die Indizes funktionsfähig zu machen.
5. **Startpunkt setzen:** Erstelle eine `02_Atlas/000_Home.md` (Home MOC) und binde dort die Dataview-Queries für "Active Efforts" und "Inbox Processing" ein, um einen sofort nutzbaren Workspace-Einstieg zu bieten.
