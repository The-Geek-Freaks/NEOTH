# DESIGN OVERHAUL PLAN — NEOTH GUI (2026-07-05)

Ziel: die NEOTH-GUI auf Apple-Design-Niveau bringen; Design-Mockup
("Neoth Design Overhaul", dark neon-on-ink) nach Slint portieren; GUI
feature-parity mit CLI; neue Tabs; das minimierte Companion-Overlay;
Buddy zum Leben erwecken.

Quelle: `QUELLEN/design_overhaul_2026-07-04/` (Mockup + ds_*.css Tokens +
support.js — via Chrome-`GetFile`-API gezogen, MCP brauchte OAuth).
Referenz: `SRC/neothd-gui/ui/COMPONENT_API.md` (autoritative Prop-Namen —
Slint-Prop-Raten war Fehlerquelle #1).

## Geliefert (Session 2026-07-04/05, Commits de3d9ce6..cb34a491)

| Wave | Commit | Inhalt |
|---|---|---|
| 1 | 5f82c5ab | Motion-Tokens (entrance/side-in/toast), Toast-System (glass, draining bar), Nav-Gruppen CORE/WORK/SYSTEM, Wordmark-Sublabel |
| 2 | 6198e9ce | **Agent-Activity-Sidecar** (Claude-Code-Style): rechts einfahrend, collapsible, kind-farbige breathing Leds; Feeds: chat plan/metric, deep-link-chips, kanban board, loop start/stop, preset apply |
| 3 | feae6a7a | **Mission-Control Overview**: 7 Cards (Status, Tokens, Hemispheres, Agents, Skills&Plugins, Calendar, Consent), 8 tolerant JSON-Probes |
| 4a | 02d5f933 | Tabs: n8n, Babel (Observer+Windows), Calendar (+Add), Evolve (Self-Improve Accept/Rollback) |
| CLI | de3d9ce6 | Backing: `babel …--output json`, `dream list/show`, `obsidian status` |
| CLI | 057ecb14 | `neoth buddy status/self-activation/proactive` (Aggregator; sovereign+smart-approve read-only, keine Ceremony-Bypass) |
| 4b | b2af367e | Tabs: Obsidian, Dreaming, Wiki (Suche/Filter), Buddy-Config, Companion, Mesh (ehrliche Failover-Karte) |
| 5 | 9a8dc137 | **Living Buddy** (idle-breathing, organische Orbiter, animierte Mood-Farben, State-Pop, Glow) + Steve-Jobs-Polish (Kicker/InfoRow/RefreshFooter zentralisiert, Refresh→NeothButton, Token-Sweep, Overview-Hero, Card-Glow, Sidecar-Motion) |
| 6 | 57b3f1ed | **Consent-Strip im Chat-Tab** (Mode-Pill + Gated/Full-Auto-Toggle via Ceremony + Consent-Popover mit Revoke) |
| 7 | 88ac4af0 | **Minimized Companion-Overlay** (frameless, always-on-top via winit-Accessor, semi-transparent, Buddy + Compact-Chat; TopBar-Minimize ⊟) |
| fix | cb34a491 | overview binding-loop entfernt (Slint-1.16 Panic-Risiko) → 0 Loops GUI-weit |

**Nav jetzt:** 25 Panels. **GUI-Tests: 219 grün, clippy 0.**

## Nicht headless-verifizierbar (Screen-Access vom Operator denied — Gates+Tests = Evidenz, B8-Präzedenz)
Overlay: echte Per-Pixel-Transparenz (near-opaque dark bg degradiert sauber),
tatsächliche always-on-top-Durchsetzung, Taskbar-Verhalten, Bottom-right bei
non-96-DPI. Buddy-Animationen visuell. → **Device-Test durch Operator nötig.**

## Offen — Rest-Waves (priorisiert)

### P1 — Reichweite/Parität
- **DES-08 Plugins/Skills add+remove in GUI** — enable/disable existiert (Settings-Tabs). Fehlt: ADD (Plugin=.wasm-Pfad / Skill=skill.yaml), REMOVE, und **via Chat** ("bau mir Skill X" → NEOTH generiert → erscheint). Daemon: `neoth plugin`/`neoth skills` haben kein add/remove-from-path; Skill-Creator existiert (advanced_skill_creator). M/L.
- **DES-09 Alle Settings GUI-editierbar** — Audit welche freedom.yaml-Felder NICHT im Settings-Panel editierbar sind (GAP-06/10 Rest: language/role, cost-caps, provider-advanced, persona_mode, models_aliases, obsidian-Pfade …) + Editoren nachrüsten. M.
- **DES-10 Channel-Watch live** — Channels-Tab soll eingehenden Chat live sehen. Daemon: kein `channel_stream`/WAL-tail (gui-stream = nur Board). Braucht neuen `neoth channel tail --follow` oder gui-stream `channel_stream`-Methode. M (daemon).

### P2 — Features die Daemon-Arbeit brauchen
- **DES-11 Self-Reprogramming-Tab** — FEAT-05 = v1.1, im Daemon NICHT gebaut (nur Research-Doc). Tab erst nach FEAT-05. L (daemon).
- **DES-12 Plugin-provided Tabs** — WASM-Manifest hat kein `ui_surface`-Feld; braucht Manifest-Erweiterung + GUI-Dispatch. M.
- **DES-13 Mesh Full-Failover** — Redundanz ist PARTIAL (foreign_events geschrieben, kein Indexer). Tab sagt's ehrlich. Volle Daten-Redundanz = foreign-indexer + conflict-resolution. L (daemon, = G02-CLUSTER-02b).

### P3 — Polish-Long-Tail (Steve-Jobs-Review Rest)
- Card ambient-glow ist drin; verbleibende P2/P3 aus dem Review: sidecar-Breite 300→220px (DAU-Fenster), `duration-micro/fast` Namens-Swap, `⟳`-Glyph→SVG-Asset, Nav-Neon-Disziplin verifiziert-ok.
- Header/Footer-Info-Optimierung, Density-Toggle in freedom.yaml persistieren.

## Gotchas (durable)
- **Slint-Binding-Loop**: `EntranceFade { height: parent.height }` + `ScrollView { height: parent.height - Npx }` in einer content-getriebenen Layout = layoutinfo-v-Zyklus (Slint 1.16: „may cause panic"). Fix: beide parent.height-Bindings raus, ScrollView sized natürlich. (Traf Wave-4b + overview.)
- **Reserviert**: `row`/`col` sind GridLayout-Props → nicht als eigene Property nutzen (`cap` statt `row`).
- **Struct-Export**: view-Struct muss aus dem view-File UND aus main.slint re-exportiert werden, sonst kein Rust-Struct. Komponenten (z.B. MiniOverlay) ebenso re-exportieren, sonst `cannot find type`.
- **winit always-on-top**: `slint::winit_030::{WinitWindowAccessor, winit}` (Feature `unstable-winit-030`); `window().with_winit_window(|w| w.set_window_level(AlwaysOnTop))` NACH `.show()` (Event-Loop muss aktiv sein). Slint-1.16 Window hat KEINE DSL-always-on-top-Property.
- **Prop-Namen**: SegBar `fraction` (nicht value), NeothButton `label` (nicht text), NeothLineEdit `placeholder-text`, Led `state` = live/connecting/error/off (nicht active/idle), kein `vertical-alignment` auf Rectangle/Led. → COMPONENT_API.md.
- **Parallele Agents dürfen KEINE Shared-Files editieren** (main.rs/main.slint/app_shell/panel_logic) → Konflikt-Chaos. Muster: Agents bauen self-contained view-Files + liefern Wiring-Spec; Integration zentral.
