---
title: "Claude Code Best Practices"
description: "Architektur, Workflows und Best Practices für Agentic Engineering mit Claude Code"
tags: ["claude-code", "agentic-engineering", "orchestration", "workflows", "llm"]
source: "sources/claude_code_best_practice_readme.md"
---

# [INTENT: CLAUDE_AGENTIC_ENGINEERING] Claude Code & Agentic Workflows (Pedantic Setup Guide)

## Chunk 1: Core Configuration, Settings & Memory Architecture
Detaillierte Pfade und Konfigurationsobjekte für Claude Code Setups:
- **Project Settings (`.claude/settings.json`):** Verwaltet und steuert explizit Permissions, Model Config, Output Styles, Sandboxing, Keybindings, Auto Mode Config und das Status Line Setup.
- **MCP Servers & Integration:** Werden strikt in `.claude/settings.json` und `.mcp.json` definiert. (Computer Use Beta läuft als eigener MCP Server).
- **Memory & Context Hierarchy:**
  - Workspace-weit: `.claude/rules/`, `CLAUDE.md`.
  - Globales Gedächtnis (Systemweit): `~/.claude/rules/`, `~/.claude/tasks/`, `~/.claude/projects/<project>/memory/`.
- **Dateistruktur für Automation:** Agenten-Prompts (`.claude/agents/<name>.md`), Slash-Commands (`.claude/commands/<name>.md`), Skills (`.claude/skills/<name>/SKILL.md`), Hooks (`.claude/hooks/`).

## Chunk 2: CLI Flags, Beta Features & Slash Commands
Vollständiges Register der Steuerungsbefehle zur Laufzeit:
- **Automatisierung & Performance:** `--permission-mode auto` oder `Shift+Tab` für Auto Mode. `/fast` oder `"fastMode": true` in Settings für schnelles Ausführen. `/advisor` (`advisorModel` in Config / `--advisor` als Flag) für strategische Model-Ratschläge.
- **Review & Planung:** `/code-review ultra` oder `claude ultrareview [target]` für tiefes Task-Tracking. `/ultraplan` für Architekturplanung, `/tasks` für das Management im `.claude/tasks/` Verzeichnis.
- **Umgebung & Isolation:** Flag `--worktree` (`-w`) inkl. `.worktreeinclude` Datei für Git Worktrees. Isolation steuerbar über Hooks (`WorktreeCreate`/`WorktreeRemove`).
- **UI & Remote:** `/tui fullscreen` oder Env-Var `CLAUDE_CODE_NO_FLICKER=1` für No Flicker Mode. `/remote-control` (`/rc`) für Headless Mode. `--chrome` für DevTools-Integration in Chrome.

## Chunk 3: Orchestration Workflows & Community Pipelines
Der Orchestration Workflow erzwingt das Architektur-Pattern: **Command -> Agent -> Skill**.
Spezifische Community-Pipelines mit exakten Phasen:
- **Superpowers:** Nutzt Git Worktrees, TDD und subagent-driven Development mit paralleler Agenten-Ausführung (Dispatching).
- **Everything Claude Code:** Strikter Flow: PRD-Planung -> PRP-Implementierung -> Code Review -> E2E Testing -> Build Fix.
- **Matt Pocock Skills:** Basiert auf `/grill-with-docs`, `/grill-me`, `/to-prd` und gezielten Codebase-Architecture Verbesserungen.
- **Spec Kit:** Strenge Befehlshierarchie via `/speckit.constitution`, gefolgt von `.specify`, `.plan`, `.implement` und `.converge`.
- **gstack:** Management-Prozess via `/plan-ceo-review`, `/plan-eng-review`, `/plan-design-review`, gefolgt von `/qa` und `/land-and-deploy`.
