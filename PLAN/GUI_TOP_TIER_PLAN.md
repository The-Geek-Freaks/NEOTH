# GUI TOP-TIER PLAN — Design Lane (Claude)

> Erstellt 2026-07-16 aus 6-Agenten-Research-Wave (`wf_8618f46f-1a0`).
> **Vollstaendige Research-Evidenz:** PLAN/RESEARCH_GUI_2026_07_16.md — die
> unveraenderten Agent-Outputs beider Wellen (Parity-Audit, GUI-Inventar,
> Buddy-Audit, Best-in-Class-Prinzipien, Killer-Features, Synthese).
> Lane-Abgrenzung: Codex/GPT arbeitet an GOLD-Rollup-Contracts (CI, packaging,
> integrity). Diese Lane = GUI/Design. Codex' Commit `7e53c9b5` fasste
> main.rs / panel_logic.rs / main.slint / settings.slint an → vor jedem Push
> `git pull --rebase`, atomare Commits, selektives `git add`.
> Deckt die offenen GOLD-Rollups **GOLD-R4-04/05/06/09** aus ROAD_TO_1_0_GOLD.md ab.

## ERFÜLLUNGSSTAND (Operator-Auftrag 2026-07-16, Stand HEAD 07cdb326)

Der Auftrag "maximales Research → Plan → Implementierung" ist wie folgt durchlaufen:

1. **Systematisches GUI-Research** ✅ — Wave 1 `wf_8618f46f-1a0` (6 Agenten, 600k Tokens):
   GUI-Komplettinventar (24 Slint-Files, alle Tabs/Callbacks/Lücken), CLI↔GUI-Parity-Audit
   (~130 Subcommands / 24 Slash-Commands / 20 Config-Sections → P0-Lückenliste),
   Tracker/Codex-Kollisionsanalyse, Buddy-Audit (26 Moods, toter Event-Bus),
   Kanban/Cluster-Tiefenanalyse (Comments-nicht-injiziert als P0 bestätigt).
2. **Best-in-Class-Analyse** ✅ — Wave 1 + Wave 2 `wf_c9f1360d-bda` (12 Agenten, 1.67M Tokens,
   web-grounded): Claude Desktop, ChatGPT Desktop + Codex, Cursor/Composer, Linear, Raycast,
   Notion/Obsidian, Perplexity, TypingMind, LibreChat, Msty, Grafana/Netdata/k9s/Tailscale,
   Desktop-Pets/Dynamic-Island — je 3–8 konkrete Mechaniken + NEOTH-Transfer, gerankt
   killer/high/nice. Ökosystem-Homogenität (ein Icon-Set, eine Interaction-Grammar,
   Spacing-Grid, Footer/About/Changelog) als eigene Dimension.
3. **Plan aus dem Research** ✅ — dieses Dokument: Wellen A–G aus dem Parity/Inventar-Audit,
   Wave H (Killer-Backlog) aus der Web-Research-Synthese.
4. **Implementierung** ✅ laufend — 21 Commits `67e968c5`→`07cdb326` am 2026-07-16, jede Welle
   mit Ownership-Agenten gebaut, von Hand verdrahtet, Gates grün, gepusht. Bilanz unten
   an den [x]-Items ablesbar (A+B komplett, C 6/7, H 14/22).
5. **Codex-Abgleich** ✅ — durchgehend `pull --rebase` vor jedem Push; Codex merged die
   GUI-Commits aktiv in `codex/gold-integrate` (+fmt-normalize); 0 Konflikte über 21 Commits.

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
- [x] A3 Kanban-Write-Ops: move/status/block/finish/assign via Kontextmenü ✅;
      **Session-Selector** ✅ (`Latest (live)` als expliziter Warm-Sentinel,
      `list --all` für Historie, konkrete Pins via Cold-Show, leere/stale
      Kataloge kohärent und Async-Snapshots generationsgebunden).
- [x] A4 Rechtsklick-Kontextmenü auf Kanban-Karten (move to column, archive, block, copy id).
      Move, Finish, Block, Archive, Hemisphere-Assign und Copy-ID sind über
      typisierte Mutationsbelege verdrahtet; Erfolg und Refresh folgen erst
      nach exakter Bestätigung von Aktion, Task-ID und Zielstatus.

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
- [~] C6 Cluster-Config editierbar: ein expliziter Apply-Vorgang überträgt
      Master-Switch, Name, den in Desktop-Releases vollständig enthaltenen
      Peeroxide/Iroh-Carrier, Bootstrap-Peers, mDNS, Announce-Policy, exakte
      Trusted-SSID-Zeilen, Listen-Port und ein write-only Shared Secret in eine
      typisierte, prozessübergreifend gesperrte und PREPARED-journalisierte
      Zwei-Datei-Transaktion. GUI und CLI verlangen den vollständigen
      JSON-Receipt und prüfen Pfad plus jedes Zielfeld; die GUI serialisiert
      diesen CLI-Commit zusätzlich mit ihren älteren Autosave-Workern. Direkte
      Cluster-Einzelwrites, Lost Updates und optimistische Erfolgstoasts sind
      entfernt. Ein privater exakter Runtime-Marker hält echte Pending-Zustände
      über identische Retries; nur der Daemon darf ihn nach erfolgreichem
      Carrier-Start für exakten öffentlichen Snapshot, nicht reversibles
      privates Identity-Binding und PID-Lock bestätigen. Disabled plus stopped
      ist bereits inert und liefert korrekt `restart_required=false`.
      **Residual:** aktivierte Lifecycle-Änderungen werden noch nicht live
      umgeschaltet. C6 bleibt partiell, bis ein gemeinsamer Transport/mDNS/
      Gossip-Supervisor Start, Teardown und Carrier-Wechsel kontrolliert.
- [x] C7 Usage/Cost-Analytics-View (`neoth cost/usage`) im Overview.

### Wave D — Interaction-Grammar (Best-in-Class-Transfer)
- [~] D1 Command-Palette Ctrl+K: Navigation + Aktionen (doctor, new task, theme,
      DND, session switch) — Raycast/Linear-Pattern.
      **Residual:** Der aktuelle `PaletteItem`-Vertrag enthält nur Tab-Ziele;
      echte Aktionen für Doctor-Run, New Task, Theme, DND und Session-Wechsel
      samt typisiertem Dispatch fehlen.
- [ ] D2 Rechtsklick-Kontextmenü-Primitive in components.slint; Rollout auf
      Listen (Sessions, Channels, Cron, Plugins, Memory).
- [ ] D3 Einheitliche hover/focus/active-Grammar + Focus-Rings überall (ein Muster).
      `accessible-action-default` alone is not keyboard wiring: NavBtn,
      Complexity-Segmente und Theme-Toggle brauchen `FocusScope`/`forward-focus`,
      Enter/Space, sichtbaren Fokus sowie passende tab/radio/switch-Rollen und
      selected/checked state.
- [ ] D4 Filter-as-you-type in jeder Listen-View.
- [x] D5 Keyboard-Shortcuts (Ctrl+1..9 Tabs, Ctrl+Enter send, Esc close) +
      Shortcut-Cheatsheet (? oder Ctrl+/).
      **Closed 2026-07-18 (`d455efc5`):** Ctrl+6..9 = agents · automation ·
      mesh · doctor, Ctrl+B = Sidebar-Toggle, Cheatsheet geführt. Vorher
      geblockt durch Slint-Codegen-Stack-Ceiling — build.rs kompiliert jetzt
      auf 256-MiB-Stack-Thread (BUILD_LOG_2026_07_18 W0), Ceiling ist weg.

### Wave E — Homogenität & Polish (GOLD-R4-09)
- [x] E1 Glyph-Dedup + eine Icon-Familie (Sidebar-Kollisionen fixen).
- [~] E2 Skeleton-States: ProbeView (Agents/Automation) + AgentsView ✅; weitere Panels bei Bedarf.
- [ ] E3 Optimistic UI auf allen Toggles/Mutationen (nie Spinner auf cron-toggle).
- [x] E4 About/Version/Copyright-Panel + In-App-Changelog ("What's new" nach Update)
      + offizielles `AboutSlint`-Attributionswidget.
- [x] E5 `agents`-ProbeView → strukturierte View (Cards statt Text-Dump).
- [ ] E6 Density-Mode-Rollout auf alle Tabs (bisher nur chat).
- [x] E7 Reduced-/No-Motion-Vertrag für jede tick-getriebene Animation ✅
      (2026-07-16): jede `animation-tick()`-getriebene Phase im Buddy-Orb
      (orbit/pulse/breathe/pop/ring-t/blink + die transienten Overlays
      listen-ph/wobble/memory-t/thinking-raw/scan-sweep) kollabiert bei
      `Theme.animation-mode == 0` auf einen statischen Neutralwert. Damit
      frieren Idle-Breath, Ringe, Glow, Blink, Speaking-Ring UND der
      Consent-Badge-Throb (hing an `breathe`) ein. Nicht-invisible Freeze-Werte
      gewählt (sweep→0.5, memory-t→0.5) damit kein Overlay unsichtbar wird.
      `animate`-Blöcke honorierten den Mode schon über die Duration-Tokens.
      **App-weit erweitert** (2026-07-16b): auch die tick-getriebenen
      Animationen außerhalb des Orbs — NeothButton-Spinner (`◐`), Led-Puls,
      Skeleton-Shimmer (components.slint) und der Activity-Row-Aktiv-Puls
      (activity.slint) — frieren bei mode 0. Nebenbei 3 latente 0ms-Divisionen
      gefixt (die Spinner/Led/Puls teilten durch `Theme.duration-*`, das bei
      mode 0 `0ms` ist). wal_timeline nutzt nur `animate{}` → schon safe.
      Gate GATE_EXIT=0.

### Wave G — GUI-Inventar-P0/P1 (aus gui-inventory Agent)
- [x] G1 P0: ToastStack click-to-dismiss (`callback toast-dismissed(int)` + Rust-Drain).
- [x] G2 P0: Daemon-offline-Banner statt Blank-Screen (shared `daemon-reachable` bool,
      InlineErrorBanner + Retry auf Doctor/Resources/Cluster/Channels).
- [x] G3 P1: Chat-Bubble Hover-Action-Bar (Copy/Retry/Delete) — größte Chat-Lücke.
- [~] G4 P1: Tooltip-Primitive (Primitive ✅, NavBtn-Rollout offen) 
- [~] G5 P1: ConfirmDialog-Primitive (Primitive ✅, Rollout offen) (ersetzt one-off PopupWindows, gated destructive ops).
- [x] G6 P1: Version-Binding (`env!("CARGO_PKG_VERSION")` → StatusFooter) +
      update-available Badge.
- [ ] G7 P1: Accessibility-Pass (Labels flächendeckend plus Fokusreihenfolge,
      Tastaturaktivierung, Rollen/States und Modal-Focus-Trap; `ConfirmDialog`
      hat wegen fehlender Slint-Dialogrolle derzeit nur Text-Fallback-Semantik).

### Wave F — Cluster/Mesh-Dashboard
- [x] F1 Per-Peer-Ressourcen aus SwarmTable in Mesh-Tab (CPU/RAM/VRAM je Node).
- [x] F2 (2026-07-18): SYNC-STATE-Card im Mesh-Tab — per-Peer ACK-Highwater,
      Pending(+Attempts), Inbound-Next, Cursor (Segment:Offset), Request-State
      + Last-Error (consent-rot) aus `cluster sync-state --output json`
      (durable_sync::MeshPeerStatus). Card versteckt sich ohne Daten.
      Gossip-Event-Stream war schon da (Session #13).
- [ ] F3 Per-Node-Aktionen (request sync, kick peer), Node-Rollen.

## Wave H — 12/10 KILLER-BACKLOG (Research-Wave 2, `wf_c9f1360d-bda`, web-grounded)

GUI-only Superpowers (Rangfolge nach wow×feasibility):
- [x] H1 **WAL-Timeline-Scrubber** — 255 Opcodes in semantischen Bändern = vor-gefärbte
      Timeline; scrubben durch die Audit-History statt grep-Dump. (Killer, eigener Tab/WAL-Inspector-Erweiterung)
- [x] H2 **Memory Force-Directed Graph** — Obsidian-style Graph-View über Memory-Tiers/Hebbian-Links. (Killer)
- [~] H3 **System-Tray** ✅ (Windows-Toasts + Jump-List offen) — Windows/macOS
      nativ, Linux via GTK-freiem StatusNotifierItem; Start erst im laufenden
      GUI-Event-Loop. (Killer)
- [~] H4 **Drag-Drop-Ingestion** — Files in Chat/Memory ziehen. (Killer)
      **Residual:** `DroppedFile` legt Dateien ausschließlich im
      Chat-Attachment-Strip ab. Memory-Ingestion und eine sichtbare
      Zielauswahl/Statusanzeige fehlen.
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
- [x] H18 **Regenerate mit Model-Picker**. (Killer) — SHIPPED: `neoth models
      catalog --output json` liefert den live, modellversionsunabhängigen
      Provider-Katalog; der Retry-Picker bietet Same model plus den Live-Katalog
      des Providers an und übergibt die Auswahl als einmaligen `--model`-
      Override in den Send-Pfad. Das ursprüngliche `neoth chat --model`-
      Fundament und die Priorität CLI > tweaks > freedom bleiben erhalten.
      Antwort-Branching/Variant-Navigation ist bewusst weiter H17, nicht Teil
      des geschlossenen H18-Vertrags.
- [~] H19 Code-Block-Affordances (Copy/Run/Collapse) + Always-Visible-Stop. (Killer)
      **Residual:** Copy, Collapse und Stop sind vorhanden; ein sicherer,
      permission-gated Code-Run-Pfad mit sichtbarem Lifecycle fehlt.
- [ ] H20 Prompt-Library mit Template-Variablen; Multi-Model-Split-View (Council-Compare!); Volltext-Suche. (High)

Mesh/Fleet (Grafana/Netdata/k9s):
- [x] H21 Netdata-Node-Cards mit Color-Ring-Health (Basis ✅ Build-Agent). (Killer)
- [ ] H22 Health-Heatmap (Zeit × Peer), Topology-Graph mit RTT, Composite-Cluster-Bar. (High)

## Wave I — Research-Refresh 2026-07-18 (5-Agenten: Inventar, Plan-State, Parity 134 Verben, Backend-Scan, UX-Research)

Neue verifizierte Gaps, nicht von A–H abgedeckt. Reihenfolge = Impact.
Codex-Zone bleibt tabu (credential panel, moral-core editor, inline-tool-approval,
request-sync-real, task-priority/label, message-branch-nav, artifact-canvas,
inline-patch-diff (Chat), rollback-apply).

Dead-Ends / Bugs (kleine Diffs, hoher Wert):
- [x] I1 ~~Chat-Channel-Kontextmenü~~ **FEHLBEFUND** (verified 2026-07-18):
      on_channel_copy_name main.rs:6630 + on_channel_remove :7045 existieren,
      ConfirmDialog gated. Agent-Report war falsch.
- [x] I2 ~~Self-Reprog Apply~~ **FEHLBEFUND**: on_sd_apply_source_clicked
      main.rs:5356, volle Kette inkl. Confirm-Popup verdrahtet.
- [x] I3 ~~WAL Sidebar/Timeline~~ **FEHLBEFUND**: NavBtn "WAL" app_shell.slint:289;
      WalTimelineStrip importiert main.slint:32, instanziert :3939, Rust füllt
      Buckets main.rs:6297. (NAV_PANELS = Deep-Link-Chip-Allowlist, nicht Sidebar.)
- [x] I4 ~~memgraph/groundtruth unsichtbar~~ **FEHLBEFUND**: Sidebar-Einträge
      app_shell.slint:264/265.
- [x] I5 ~~Dreaming kein Refresh~~ **FEHLBEFUND**: refresh_dreaming läuft nach
      Dream Now (main.rs:5608).
      ⚠ LEHRE: Inventory-Agent-TOP-15 war 5/6 falsch — JEDES Wave-I-Item vor
      Build am Code verifizieren (bekannte Regel, erneut bestätigt).
- [x] I6 Cron-Run-Button gated: disabled + TooltipArea "Managed by the live
      daemon" solange `daemon-state == "live"` (cron.slint CronJobCard,
      main.slint Instanziierung). 2026-07-18.

Buddy lebendig — Restausbau (GOLD-R4-06):
- [x] I7 Forward-Infra-Moods verdrahtet (2026-07-18): 0x25→ProviderFallback,
      0x65/0xDC→ConsentGate, 0x9F→MemoryRecall, 0xAE/0xAF→AuditVerify,
      0xD9/0xDB/0xF2→Secured, 0xF0→QuotaBreached (neue Variante, mood
      "problem"). Provider-Hot-Lane 0x20..0x23 bewusst NICHT subscribed.
      Test `every_followed_type_maps` pinnt Subscription⊆Mapping.
- [x] I8 Idle-Variety (2026-07-18): 20s-Phasen-Zyklus (breathe → look-around
      ±2.5u → double-blink 1.6s-Subzyklus → yawn/squash x+2%/y-4% → breathe),
      deterministisch aus animation-tick, amp 0.45 bei mode 1, komplett statisch
      bei mode 0. Einschlafen/Celebration weiter über Mood-Bus (I7).
- [x] I9 (2026-07-18): working/analyzing-Overlay-Fade nachgezogen (Rest war
      schon gefadet — VERIFIED-DONE), Caption-Crossfade VERIFIED-DONE, Orb hat
      jetzt FocusScope (Enter/Space=click, Menu=ctx) + zirkulären Fokus-Ring
      in dock-hue.

Kanban TOP (Backend-Felder existieren, GUI rendert sie nicht):
- [x] I10 (2026-07-18): KanbanTaskRow +7 Felder (type-chip/worker/tests/
      tests-failing/eta/parent-ref/has-patch), Chip-Zeile auf der Karte, warm-
      UND cold-path identisch befüllt (GuiBoardTask +9 serde-default-Felder —
      wire-kompatibel mit alten Daemons). eta_ns = DURATION ab started_ns
      (store.rs-Test belegt), Helper format_eta_at clock-injectable, 13 Tests.
- [x] I11 (2026-07-18): proportionale Summary-Bar (14px, horizontal-stretch je
      Spalten-Count, Spalten-Akzentfarben, versteckt bei leerem Board).
- [x] I12 = H13 Space-Peek (2026-07-18): hover-move-Callback-Kette Card→Column→
      Board, board-lokaler FocusScope (Space öffnet, Esc schließt, reject für
      LineEdits), Overlay 520px mit id/Titel/Hemisphere/Spalte/I10-Chips.
      Pure Slint, 0 Rust-Wiring.

Parity-Lücken (aus 134-Verb-Audit):
- [x] I13 (2026-07-18): neue ui/bgjobs.slint — strukturierte Job-Cards
      (Led running/exit-0/exit-n) + Run-Form (command+label) via
      `jobs --run --output json` typed BgRunAck (neuer JSON-Ack in
      cli/jobs.rs run_bg_job, fail-closed, auto-refresh danach).
      Chat-Prompt-Pfad /background lief schon über Slash-Chips (G16).
- [x] I14 (2026-07-18): SlashCmdsView in tabs.slint — Cards mit Led on/off,
      source-Chip (builtin/operator hervorgehoben), Description; ersetzt den
      ProbeView-Dump im slash-Tab. Read-only by design (keine add/remove-Verben
      → keine Dead-Buttons). parse_slash_cmds + 2 Tests.
- [ ] I15 Channel-Pairing-Wizard (`connect`-Verb CLI-only) — größte tägliche
      Reibung, aber R4-07-Territorium → mit R4-07-Welle bündeln.

Homogenität (UX-Research "aus einem Guss"-Checkliste):
- [x] I16 (2026-07-18): ConfirmDialog ×4 (Chat-Delete idx-armed, Cron-Remove,
      Mesh Prefer-A/B mit Seiten-Label, SelfImprove-Rollback); Streaming-Caret
      blinkt ▋↔▏ (Block-Glyphen = gleiche Advance-Width, kein Reflow; statisch
      bei mode 0); Palette-Legend-Footer "↑↓ ↵ esc" (↵-Chip war schon da);
      app_shell Font-Token-Sweep (7 Literale → 2xs/xl); EntranceFade-Kontrakt
      inline auf ChatView/AgentsView/MemoryGraphView/LoopPanel/Resources/
      Probe/DoctorView.
- [~] I17 Toast: Countdown-Hairline ✅ + max-3-Stack ✅ (push_toast kappt,
      ältester fliegt) 2026-07-18. Format-Sweep der 141 Sites geprüft: nach G18
      schon spezifisch (Titel+Fehlerbody) → kein Churn-Sweep. **Residual:**
      Undo-Toast (`neoth undo`).
- [~] I18 (2026-07-18): Empty-State-Familie ✅ (loop ∞ / dreaming ☽ / n8n ⇶ /
      calendar ◷ → EmptyState; Transient-Loader bewusst belassen). Focus-Ring
      konstante-Border-Regel jetzt auf NavBtn/CheckBox/NeothButton/Complexity-
      Segmente/Theme-Toggle (+ Toggle hat jetzt FocusScope+Enter/Space).
      **Residual:** restliche Views systematisch (= D3).
      ⚠ D4-Erkenntnis: Slint-Strings haben KEIN contains/starts-with →
      Filter-as-you-type MUSS Rust-seitig filtern (Modell filtern, nicht View).

## Gates (BSOD-Regeln beachten)
- Slint: `SRC/_gui_check.bat` (mit `-j` VOR `--`).
- Rust: `cargo check -j1 --tests` — NIE lokal test-linken; Tests → CI.
- Nach Edits: `py -m graphify update` für neothd-Änderungen.
- Jede Welle = eigener Commit-Block, sofort pushen (Codex-Kollisionsfenster klein halten).
