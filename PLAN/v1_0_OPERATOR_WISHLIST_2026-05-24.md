# v1.0 Operator wish-list — verbatim dump

**Date:** 2026-05-24
**Source:** operator-typed plain text (local file)
**Status:** raw — to be triaged into ROAD_TO_1.0.md by 5-agent review (audit / QUELLEN-diff / new-repos research / wizard architect / logic-integration audit).

This file is the canonical capture so the wish-list survives long
after the original .txt is moved/deleted. Every line below is a
real operator request — the triage step decides shape + sequencing,
not whether to do the work.

---

## A — Wizard + onboarding

- Wizard in GUI + CLI verbessern: mehr auto-detect + Empfehlung. Welches Modell? Lokal? Welche Skills? Welche Plugins? Welche Schnittstelle? Welcher VPN — Hysteria oder Tailscale? Welcher Messenger? Plus "keep default" path.
- Wizard MUSS alles mit-shippen + installieren was ausgewählt wird + Schritt-für-Schritt-Einrichtung sowohl in GUI als auch in CLI.
- Wizard activation für alles: jedes Feature easy im Wizard aktivierbar; NEOTH richtet alles von allein ein auf jeder Distro + funktioniert.

## B — Auto-update everywhere

- Auto-update aller Features.
- Auto-update aller deps.
- Auto-update aller Skills + Plugins.
- Auto-update der erkannten CLI-Umgebungen (claude, codex, gemini, etc).

## C — Local models (expanded)

- Mehr Auswahl lokaler Modelle, optional als auto-download falls gewählt.
- Qwen 3.6 Modelle, Llama, Unsloth, etc. — die besten bis 27B.
- Auch größere Modelle FALLS Hardware das erlaubt.

## D — Multimodal complete

- Audio, Video, Text, Sprachnachrichten, Video-calls — alles lokal / LLM-Provider integriert.

## E — Memory + brain verification

- Memory testen + Logik der "brains" (6 SQLite-views).

## F — Obsidian erweitert

- Obsidian nicht nur Memory / Storage / Knowledge-Base.
- Auch Zwischenspeicher für Dreaming, Reflexion, Verbesserung, proaktives Handeln.

## G — Profiling + Proaktivität

- NEOTH muss User konstant profilen + sich besser auf den User einstellen + Wünsche ernst nehmen.
- Anhand gelernter Muster vorausahnen was der User will.
- Von selbst melden + dem User schreiben wenn NEOTH denkt er kann was Hilfreiches beitragen.
  - Muster oder Crons oder Reflexion sagen NEOTH: "Hey das wäre gut", "Hey das sieht der User nicht", "Hey das weiß ich was der User über sich selbst nicht weiß — vielleicht will er ja dafür einen Cron oder was bauen das ihm hilft".

## H — Cluster / slave coupling

- NEOTH soll koppelbar mit OpenClaw-slaves, Hermes-slaves, OpenHuman-slaves sein + sie als Nodes nutzen können.

## I — Provider Coverage

- Alle gängigen LLM-Provider auswählen + nutzen können.

## J — Desktop client

- Desktop-Client für alle gängigen Distros.

## K — Feature parity + more

- ALL features UND MEHR von OpenClaw, Hermes, OpenHuman.

## L — Active skill usage

- NEOTH soll seine Skills aktiv nutzen.

## M — Performance + Optimierung

- NEOTH muss optimiert + besser werden als die Konkurrenz.

## N — GUI quality

- SEHR hübsches GUI + Wizards.
- Alle Features + Funktionen + einstellbaren Settings in der GUI DAU-friendly + übersichtlich einstellbar.

## O — Native PC control

- NEOTH soll nativ den PC steuern können.

## P — Self-error-checking

- NEOTH soll sich selbst immer auf Fehler überprüfen.

## Q — Learn from errors + arxiv

- NEOTH soll aus Fehlern + arxiv-Papern lernen.

## R — Document formats

- Alle gängigen Dokumentenformate kennen, lesen, erstellen.

## S — Email + Calendar

- Kalender, Gmail, E-Mails: schicken, lesen, lernen, bearbeiten, nachforschen.
- E-Mails lesen + automatisch Kalender einpflegen + Termine speichern + vorschlagen wie man wichtige Mails beantwortet + Drafts machen.

## T — Paperless integration

- paperless-ngx + paperless-ai mit-shippen + nativ beherrschen + aware sein.
- OCRs in Obsidian speichern als `.md` knowledge die NEOTH lesen / editieren / verwenden kann.
- Knowledge aus den Paperless-Docs = ground-truth für NEOTH, jederzeit verfügbar, proaktiv damit umgehen + den User beraten.

## U — Security gates für emails + paperless

- E-Mails + Dokumente aus Paperless IMMER auf prompt-injection prüfen.
- Spam automatisch erkennen + löschen / flaggen / warnen.
- Auch Phishing + Malware.

## V — OMI compatibility

- Kompatibel mit OMI + automatisch die OMI-Pipeline haben die Jarvis auch hat.
- Tiefe Recherche auf Jarvis + Pipeline + OMI + OMI-relevante Docker.

## W — Todoist + todolist compat

- NEOTH soll Todoist + gängige todolist kompatibel sein + auch im Wizard helfen bei Konnektierung + Onboarding.

## X — Local LLM / cluster resource view

- Eigener Tab in UI + CLI für lokale LLM-Modelle, Cluster, Pools, Embeddings, Vision-Modelle, Whisper.
- Hübsch anzeigen wieviel VRAM verbraucht wird, Load, Strom.
- Grafisch bisschen hübscher als gpu-HOT-docker.
- Wie eine Lautstärke-Anzeige oder Tank-Füllstand.
- Welches Modell aktuell geladen ist + ob VRAM oder normaler RAM.
- Auch für verbundene Cluster + deren Auslastung.

## Y — Cluster / channel topology view

- Optionale Ansicht in CLI oder GUI wie Cluster + Channels verbunden sind.
- Hysteria, Tailscale, WhatsApp, Keet, etc.
- Stabilität + Geschwindigkeit der Verbindungen.

## Z — Repo integrations (new)

NEOTH braucht Features + Fähigkeiten + Funktionen / Logiken aus diesen Repos, angepasst auf NEOTH-Design + Logik + Funktion, sodass NEOTH verbessert wird und das Knowledge dazu nativ nutzt:

- https://github.com/anthropics/claude-plugins-official
- https://github.com/colbymchenry/codegraph
- https://github.com/Lum1104/Understand-Anything
- https://github.com/trimstray/the-book-of-secret-knowledge
- https://github.com/ChromeDevTools/chrome-devtools-mcp
- https://github.com/can1357/oh-my-pi

## AA — Smart MCP loading

- NEOTH muss smart sein: nicht immer alle MCPs in Kontext laden bei einer normalen Unterhaltung — dafür optimieren wir Tokens.

## AB — QUELLEN refresh + diff-adopt

- Neueste Updates von Hermes, OpenHuman, OpenClaw herunterladen in QUELLEN.
- Durchsuchen was neu ist zu den letzten Versionen im QUELLEN-Ordner.
- Diff analysieren.
- Verbesserungen aus den 3en in NEOTH einbauen, angepasst auf Funktionsweise + Logik + Systeme.
- Neue Features übernehmen wenn NEOTH sie noch nicht hat aber haben sollte.
- Security-Konzepte spiegeln wenn relevant.

## AC — n8n integration smarts

- n8n workflows + usage klug implementieren: wann NEOTH n8n nutzt für welche Tasks + Crons + Routinen damit Tokens gespart werden.

## AD — README + docs + comparison

- README muss alle Features enthalten.
- n8n integration + Obsidian + paperless + alles andere = gesamtes Öko-System.
- Agenten researchen lassen + dann für die README SVGs bauen in NEOTH-CI + Vergleichstabellen + README erweitern mit neuen unique selling points.
- Doc muss verbessert + ausgebaut + auf aktuellen Stand + mehr Features enthalten + listen.
- Die besten Features hervorheben + die die andere nicht haben.

## AE — Implementation-status audit + Plan 1.1 reconciliation

- Schicke Agenten los die schauen wieviel des Plans wir schon umgesetzt / superseded / besser eingebaut haben + was noch fehlt.
- Analysiere wo es Logik-Probleme gibt oder Dinge schlau aufgelöst werden müssen.
- Check ob Framework 4.1 noch bessere Implementierung braucht + ob Dinge aus Plan 1.1 oder Specs oder superseded plan files vergessen / noch nicht eingebaut wurden.

## AF — End-to-end testing

- Am Ende: Check ob alle Funktionen + Logiken + Features + Skills + Plugins alle zusammen arbeiten.
- Schritt für Schritt testen, nachprüfen, debuggen.
- Edge + smoke tests.

## AG — Credentials import

- Credentials aus Chrome / Firefox / Edge / Bitwarden / Vaultwarden / anderen gängigen Password-Managern importieren können — CLI + GUI.
- Beim Onboarding nach Import fragen.
- Konstant verfügbar machen (nicht nur Onboarding) — auch in Settings + im Wizard.
- Hübsch in GUI.
- Headstart für den Operator.

---

## Triage status

5 senior-dev research agents deployed 2026-05-24:

| Agent | Scope | Output target |
| :-- | :-- | :-- |
| A1 — implementation-status | Walk every item above; classify SHIPPED / PARTIAL / MISSING / SUPERSEDED with file:line evidence | feeds ROAD_TO_1.0.md sections |
| A2 — QUELLEN diff | Inventory hermes/openhuman/openclaw mirrors; flag features NEOTH lacks; security patterns to mirror | feeds the AB triage row |
| A3 — new repos | claude-plugins-official / codegraph / Understand-Anything / book-of-secret-knowledge / chrome-devtools-mcp / oh-my-pi / OMI — integration shape per source | feeds Z triage row |
| A4 — wizard architect | v0.3 wizard expansion design — auto-detect contract + install pipeline + cross-distro package managers + credentials import + CLI↔GUI parity | feeds A + AG triage rows |
| A5 — logic + integration audit | Memory/brain logic verify + cross-feature integration + edge cases + framework 4.1 vs reality + spec↔code deltas + logic anti-patterns | feeds E + AE + AF triage rows |

Once all 5 land, ROAD_TO_1.0.md gets built as the bucketed multi-
release roadmap (v0.3 / v0.4 / v0.5 / v0.9 / v1.0 lanes).
