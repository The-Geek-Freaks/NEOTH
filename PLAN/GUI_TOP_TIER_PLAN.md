# GUI TOP-TIER PLAN — Design Lane (Claude)

> Erstellt 2026-07-16 aus 6-Agenten-Research-Wave (`wf_8618f46f-1a0`).
> Lane-Abgrenzung: Codex/GPT arbeitet an GOLD-Rollup-Contracts (CI, packaging,
> integrity). Diese Lane = GUI/Design. Codex' Commit `7e53c9b5` fasste
> main.rs / panel_logic.rs / main.slint / settings.slint an → vor jedem Push
> `git pull --rebase`, atomare Commits, selektives `git add`.
> Deckt die offenen GOLD-Rollups **GOLD-R4-04/05/06/09** aus ROAD_TO_1_0_GOLD.md ab.

## Research-Basis (verifiziert am Code, HEAD 7e53c9b5)

- GUI: 24 Slint-Files (~41k LOC gesamt, main.rs 16k), Token-System in
  `theme.slint` komplett (light/dark, density, tweaks-overrides, motion).
- Buddy: prozeduraler Orb, 26 Moods, animierte Hue-Transitions — visuell stark,
  aber **kein Daemon→GUI-Event-Bus**: GuiActivity-Varianten sind dead code.
- Kanban ("Code Sessions"): 5-Spalten-Board + Feed + Comments existieren in GUI,
  aber **Kommentare werden dem LLM-Worker NICHT injiziert** (Dispatcher ignoriert sie).
- Parity: ~130 CLI-Subcommands / 24 Slash-Commands / 20 freedom.yaml-Sections
  vs. GUI → P0-Lücken: WAL-Browser, Permissions-Matrix, MCP-Panel, Operator-Identity,
  undo, 7 Slash-Commands ohne Trigger.
- `agents`-Tab = roher ProbeView-Dump; cluster/config/privacy etc. = Settings-Family.
- Glyph-Kollisionen in Sidebar (n8n=Plugins `⧉`, Calendar=Resources `▦`).

## Wellen (Reihenfolge = Impact)

### Wave A — Kanban: LLM-lesbare Notizen (Operator-Wunsch, P0)
- [x] A1 Daemon: Task-Comments in den Worker-Prompt injizieren (Dispatcher liest
      Comments beim Task-Start; Format: `## Operator notes` Block). KEIN neuer
      WAL-Opcode (Space erschöpft) — Comments reiten existierendes Payload.
- [x] A2 GUI: Note-Composer am Task-Detail — Author-Tag `operator-note` vs. Chat-Comment;
      dynamisch anhängbar, Anzeige als eigene Sektion auf der Karte.
- [ ] A3 Kanban-Write-Ops komplettieren (GAP-03): move/status, archive, blocked-Toggle,
      Session-Selector (Board zeigt bisher nur letzte Session).
- [x] A4 Rechtsklick-Kontextmenü auf Kanban-Karten (move to column, archive, block, copy id).

### Wave B — Buddy lebendig (GOLD-R4-06)
- [x] B1 Daemon→GUI-Event-Bus: GuiActivity an WAL-Events verdrahten —
      Dreaming 0xF4, Council 0x60–0x64, Self-Improve 0xBE/0xBF + 0x1C–0x1E,
      Self-Reprog ExtendedSubtype 0x01/0x02/0x05, Channel-Ingress 0x32,
      Loops 0x7C–0x7F, Cron 0x40–0x46.
- [x] B2 Overlay: Drag + Position-Persist (Stub ersetzen), Click-through-Option.
- [x] B3 Human-Captions statt Mood-Keys ("thinking…" statt "thinking") +
      Speech-Bubble/Callout für Kurztext.
- [x] B4 Click auf BuddyDock → Quick-Action-Menü (Chat öffnen, DND, letzte Aktivität).
- [x] B5 DND / Quiet-Hours GUI (verknüpft mit proactive.quiet_hours_utc, DES-09 G37).

### Wave C — CLI↔GUI-Parity P0s (GOLD-R4-05)
- [x] C1 WAL-Inspector-Tab: Events pagen, Opcode-Filter, verify-Button (audit-cyan).
- [x] C2 Permissions-Matrix in Privacy (custom_autonomy.overrides, ~20 Action-Keys,
      aus `neoth permissions show --output json`).
- [x] C3 Operator-Identity in Config (operator_id, language_primary/code, role, role_custom).
- [ ] C4 MCP-Panel (`neoth mcp` list/add/remove/toggle).
- [ ] C5 Undo-Trigger + Slash-Command-Lücken: /quit (Daemon-Stop-Button Doctor),
      /critic + /background (Chat-Composer-Buttons), /tour //recipe //glossary (Chat).
- [ ] C6 Cluster-Config editierbar (master switch, transport, peers, trusted_ssids).
- [x] C7 Usage/Cost-Analytics-View (`neoth cost/usage`) im Overview.

### Wave D — Interaction-Grammar (Best-in-Class-Transfer)
- [x] D1 Command-Palette Ctrl+K: Navigation + Aktionen (doctor, new task, theme,
      DND, session switch) — Raycast/Linear-Pattern.
- [ ] D2 Rechtsklick-Kontextmenü-Primitive in components.slint; Rollout auf
      Listen (Sessions, Channels, Cron, Plugins, Memory).
- [ ] D3 Einheitliche hover/focus/active-Grammar + Focus-Rings überall (ein Muster).
- [ ] D4 Filter-as-you-type in jeder Listen-View.
- [x] D5 Keyboard-Shortcuts (Ctrl+1..9 Tabs, Ctrl+Enter send, Esc close) +
      Shortcut-Cheatsheet (? oder Ctrl+/).

### Wave E — Homogenität & Polish (GOLD-R4-09)
- [x] E1 Glyph-Dedup + eine Icon-Familie (Sidebar-Kollisionen fixen).
- [~] E2 Skeleton-States: ProbeView (Agents/Automation) + AgentsView ✅; weitere Panels bei Bedarf.
- [ ] E3 Optimistic UI auf allen Toggles/Mutationen (nie Spinner auf cron-toggle).
- [x] E4 About/Version/Copyright-Panel + In-App-Changelog ("What's new" nach Update).
- [x] E5 `agents`-ProbeView → strukturierte View (Cards statt Text-Dump).
- [ ] E6 Density-Mode-Rollout auf alle Tabs (bisher nur chat).

### Wave G — GUI-Inventar-P0/P1 (aus gui-inventory Agent)
- [x] G1 P0: ToastStack click-to-dismiss (`callback toast-dismissed(int)` + Rust-Drain).
- [x] G2 P0: Daemon-offline-Banner statt Blank-Screen (shared `daemon-reachable` bool,
      InlineErrorBanner + Retry auf Doctor/Resources/Cluster/Channels).
- [x] G3 P1: Chat-Bubble Hover-Action-Bar (Copy/Retry/Delete) — größte Chat-Lücke.
- [~] G4 P1: Tooltip-Primitive (Primitive ✅, NavBtn-Rollout offen) 
- [~] G5 P1: ConfirmDialog-Primitive (Primitive ✅, Rollout offen) (ersetzt one-off PopupWindows, gated destructive ops).
- [x] G6 P1: Version-Binding (`env!("CARGO_PKG_VERSION")` → StatusFooter) +
      update-available Badge.
- [ ] G7 P1: Accessibility-Pass (accessible-label auf Icon-Elemente, ~25 → flächendeckend).

### Wave F — Cluster/Mesh-Dashboard
- [x] F1 Per-Peer-Ressourcen aus SwarmTable in Mesh-Tab (CPU/RAM/VRAM je Node).
- [ ] F2 WAL-Sync-Status je Peer (Vector-Clock-Delta), Gossip-Event-Stream.
- [ ] F3 Per-Node-Aktionen (request sync, kick peer), Node-Rollen.

## Wave H — 12/10 KILLER-BACKLOG (Research-Wave 2, `wf_c9f1360d-bda`, web-grounded)

GUI-only Superpowers (Rangfolge nach wow×feasibility):
- [x] H1 **WAL-Timeline-Scrubber** — 255 Opcodes in semantischen Bändern = vor-gefärbte
      Timeline; scrubben durch die Audit-History statt grep-Dump. (Killer, eigener Tab/WAL-Inspector-Erweiterung)
- [x] H2 **Memory Force-Directed Graph** — Obsidian-style Graph-View über Memory-Tiers/Hebbian-Links. (Killer)
- [~] H3 **System-Tray** ✅ (Windows-Toasts + Jump-List offen) — App lebt im Tray, native Notifications. (Killer)
- [x] H4 **Drag-Drop-Ingestion** — Files in Chat/Memory ziehen. (Killer)
- [x] H5 Overview: Time-Series-Charts (7-Tage-Sparkline) (Token/Cost/Activity Sparklines). (Killer)
- [ ] H6 Live-Theme-Editor mit Instant-Preview (tweaks.toml GUI). (High)

Buddy (Companion-Research):
- [x] H7 **Speech-Bubble-Quick-Entry am Orb** (ChatGPT Option+Space-Pattern, am Buddy verankert). (Killer)
- [ ] H8 **Edge-Snapping mit Spring-Gravity** beim Drag. (Killer — Drag-Basis ✅ gebaut)
- [x] H9 **Daemon-Event-Mood-Reactions** (Event-Bus, Spec-Agent läuft). (Killer)
- [x] H10 State-Ring (listening/thinking/speaking-Visualisierung). (Killer)
- [ ] H11 Click-through default + hover-to-activate; Quiet-Hours/Attention-Budget. (High)
- [x] H12 Rechtsklick auf Orb → Quick-Command-Palette. (High)

Kanban (Linear/Height/GH-Projects):
- [ ] H13 **Space-Peek-Panel** (Karte nicht-disruptiv previewen). (Killer)
- [x] H14 **AI-Agent als First-Class-Assignee** auf Karten (Linear-Agents-Modell — Hemisphere-Zuordnung sichtbar/steuerbar). (Killer)
- [ ] H15 Inline-Diffs in Karten (syntax-highlighted). (High)
- [ ] H16 Batch-Select + Bulk-Actions, WIP-Limits, Saved-Filter-Views, Swimlanes. (High)

Chat (Claude/ChatGPT/Perplexity-Research):
- [ ] H17 **Edit-and-Branch mit Variant-Navigator**. (Killer)
- [ ] H18 **Regenerate mit Model-Picker**. (Killer) — VERIFIZIERT: `neoth chat --model` existiert
      (Priority CLI > tweaks > freedom). FEHLT: Provider-Catalog-Dump im CLI (`models list` = nur
      lokale Managed-Models). Schritt 1: `neoth models catalog --output json` (live catalog,
      model-version-agnostic). Schritt 2: Picker am Retry-Button (ContextMenu-Primitive),
      Auswahl → chat --model <m>, Antwort als Sibling (→ H17-Branch-Modell).
- [x] H19 Code-Block-Affordances (Copy/Run/Collapse) + Always-Visible-Stop. (Killer)
- [ ] H20 Prompt-Library mit Template-Variablen; Multi-Model-Split-View (Council-Compare!); Volltext-Suche. (High)

Mesh/Fleet (Grafana/Netdata/k9s):
- [x] H21 Netdata-Node-Cards mit Color-Ring-Health (Basis ✅ Build-Agent). (Killer)
- [ ] H22 Health-Heatmap (Zeit × Peer), Topology-Graph mit RTT, Composite-Cluster-Bar. (High)

## Gates (BSOD-Regeln beachten)
- Slint: `SRC/_gui_check.bat` (mit `-j` VOR `--`).
- Rust: `cargo check -j1 --tests` — NIE lokal test-linken; Tests → CI.
- Nach Edits: `py -m graphify update` für neothd-Änderungen.
- Jede Welle = eigener Commit-Block, sofort pushen (Codex-Kollisionsfenster klein halten).
