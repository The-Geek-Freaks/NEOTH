---
id: gstack-ai-software-factory
title: gstack - Virtual Engineering Team via AI
description: Garry Tans gstack verwandelt Claude Code in ein komplettes virtuelles Entwicklerteam bestehend aus verschiedenen AI-Agenten-Rollen.
tags: [pkm, rag, gstack, ai-agents, claude-code, openclaw, productivity]
source: sources/gstack_readme.md
---
# gstack: Virtual AI Engineering Team

[INTENT: Konzept und Architektur von gstack als AI-gestütztes Software-Factory-System vermitteln]

## Paradigma & Konzept
[INTENT: Den Paradigmenwechsel durch gstack in der AI-Entwicklung verstehen]
gstack (entwickelt von Garry Tan) nutzt Claude Code, um ein virtuelles Entwicklungsteam zu simulieren. Ein einzelner Entwickler kann mithilfe dieses Setups Produktivitätssteigerungen vom bis zu 810-fachen Output erzielen. Das System liefert 23 Spezialisten-Rollen und 8 Power-Tools via Slash-Commands. Es strukturiert den gesamten "Sprint"-Prozess.

## Chunk 1: Installation, System-Integration & Agent-Routing
[INTENT: Exakte Installationsbefehle, CLI-Flags, Auto-Update-Mechanismen und Prompt-Snippets für die gstack Integration bereitstellen]

**Single-User Installation (Claude Code):**
Installation via Git-Clone mit `--single-branch --depth 1` nach `~/.claude/skills/gstack`, gefolgt von `./setup`.
Zusätzlich in `CLAUDE.md` definieren: `... use the /browse skill from gstack for all web browsing, never use mcp__claude-in-chrome__* tools ...`

**Team-Modus (Empfohlen für Shared Repos):**
Bootstrappt das Repository mit Auto-Update-Check (throttled auf 1x/Stunde, network-failure-safe, silent).
```bash
(cd ~/.claude/skills/gstack && ./setup --team) && ~/.claude/skills/gstack/bin/gstack-team-init required && git add .claude/ CLAUDE.md && git commit -m "require gstack for AI-assisted work"
```

**OpenClaw Integration (via ACP):**
In der Datei `AGENTS.md` muss zwingend hinterlegt werden:
`when spawning Claude Code sessions for coding work, tell the session to use gstack skills. Include these examples — security audit: "Load gstack. Run /cso", code review: "Load gstack. Run /review", QA test a URL: "Load gstack. Run /qa https://...", build a feature end-to-end: "Load gstack. Run /autoplan, implement the plan, then run /ship", plan before building: "Load gstack. Run /office-hours then /autoplan. Save the plan, don't implement."`

**Unterstützte Host-Agenten (via `--host` Flag):**
Manuell oder automatisch injizierbar in: `--host codex`, `--host opencode`, `--host cursor`, `--host factory`, `--host slate`, `--host kiro`, `--host hermes`, `--host gbrain`.


## Chunk 2: Der "Sprint"-Prozess und Architectural Pipelines
[INTENT: Spezifische Funktionsweisen, Metriken, Thresholds und Framework-Constraints der Agenten-Pipelines im Detail dokumentieren]

**Planung & Architektur (Pre-Code):**
- `/office-hours`: 6 "forcing questions", generiert das zentrale Design-Doc.
- `/plan-ceo-review`: 10-Sektionen-Review mit 4 Enforcement-Modi: Expansion, Selective Expansion, Hold Scope, Reduction.
- `/plan-eng-review`: Generiert ASCII-Diagramme für Datenfluss/State-Machines; verlangt Test-Matrices und Security-Failure-Modes.
- `/autoplan`: Führt CEO → Design → Eng Review nacheinander aus; pausiert nur für "Taste Decisions".
- `/spec`: Transformiert Intent in auszuführende Spec. **Thresholds:** Codex Quality Gate (blockt bei Score < 7/10). Führt "fail-closed" Secret Redaction durch, archiviert in `$GSTACK_STATE_ROOT/projects/$SLUG/specs/`. Flag `--execute` spawnt `claude -p` in frischem Worktree.

**Design & User/Developer Experience:**
- `/plan-design-review` / `/design-review`: Bewertet Design-Dimensionen (0-10) inkl. "AI Slop Detection". `/design-review` setzt Fixes via atomaren Commits um.
- `/plan-devex-review` / `/devex-review`: DX-Audit. Benchmark gegen Konkurrenz-TTHW (Time To Hello World). 3 Modi: DX EXPANSION, DX POLISH, DX TRIAGE.
- `/design-html`: Generiert 30KB große, zero-deps HTML/React/Svelte/Vue-Implementierungen. Nutzt "Pretext computed layout".
- `/design-shotgun`: Generiert 4-6 AI Mockups im Browser Comparison Board, nutzt persistentes "Taste Memory".

**Engineering, Debugging & QA:**
- `/investigate`: Analytischer Debugger. **Iron Law:** Keine Fixes ohne Root-Cause-Analyse. Hard-Stop nach exakt 3 fehlgeschlagenen Fix-Versuchen.
- `/review`: Identifiziert Produktions-Bugs, führt auto-fixes durch und markiert Completeness-Gaps im PR.
- `/qa` / `/qa-only`: Headless-Browser Zugriff. `/qa` Fixes erzeugen zwingend neue Regression-Tests.
- `/pair-agent`: Multi-Agent-Koordinator. Startet bei Remote-Agenten automatisch einen `ngrok`-Tunnel. Bietet Tab-Isolation, Scoped Tokens, Rate Limiting und Activity Attribution im Headed-Browser.

**Security & DevSecOps:**
- `/cso`: OWASP Top 10 + STRIDE. Extrem rauscharm: **17 False-Positive-Exclusions**, ein **8/10+ Confidence Gate** und verlangt zwingend Exploit-Szenarien.
- `/ship` / `/land-and-deploy`: Sync, Test, Coverage Audit und PR-Erstellung. Bootstrappt Test-Frameworks.
- `/canary` & `/benchmark`: SRE-Post-Deploy Loop und Performance-Monitoring (Page Load, Core Web Vitals, Payload Size).

**Dokumentation & Metriken:**
- `/document-release` / `/document-generate`: Generiert Doku strikt nach dem **Diataxis Framework**. Baut interne "Coverage Map", um in PRs fehlende Doku als Gap zu kennzeichnen.
- `/learn`: Extrahierbares "Memory-System". Lernt Projekt-Patterns über Sessions hinweg.
- `/retro global`: Aggregiert wöchentliche Entwickler-Analysen über alle verknüpften Tools (Claude, Codex, Gemini) hinweg.
