# ZERO-FRICTION PLAN — NEOTH (2026-07-04)

Ziel: Ein DAU ("Alex' Mom auf frischem Win11") kommt ohne Handbuch von
Installer zu funktionierendem NEOTH — und ein Power-User schaltet ALLES
mit EINER Wahl frei, statt ~75 default-OFF-Flags einzeln zu togglen.
Per-Flag-Kontrolle bleibt vollständig erhalten (CLI `neoth config` /
freedom.yaml / GUI Settings).

## 1. Geliefert (diese Session, Commits b0ae6fe5..5b3cd857)

| Item | Was |
|---|---|
| ZF-01 Built-in-Presets | `full-auto` / `balanced` / `essentials` / `local-sovereign` als kompilierte Bundles (config/preset_builtins.rs). Generic `overrides`-Map (dotted-path → freedom.yaml) mit Denylist (autonomy/sovereign/self_activation/security/secrets/hook_chain), Typo-Pfade failen LAUT (FreedomConfig-Round-Trip), Consent-Diff für Kosten/Privacy-Pfade (PRESET_WARN_PATHS), `autonomy: full` läuft IMMER durch die full-auto-Ceremony (nie Raw-Write). |
| ZF-01 Wizard-Picker | `neoth init` fragt „How should NEOTH work?" (4 Presets + custom, Default balanced); `--zero-friction` = full-auto. Overrides mergen direkt nach write_config. |
| ZF-01 GUI | Config-Tab PRESETS: BUILT-IN/YOURS-Sektionen mit Beschreibung, Apply mit Dry-Run-Consent-Panel, full-auto via Daemon-Token, Delete für eigene Presets. |
| GAP-09 | GUI autonomy=full → mint-token + `autonomy full-auto --gui-confirmed` (Ceremony-Bypass geschlossen). |
| Parity-Wins | Memory-Suche (Settings), Doctor: Status- + Security-Audit-Probes, Maintenance: Backup/Rollback-Preview, tmux-Text-Fix im GUI-Wizard. |
| ULTRA-Reste | Doctor advisable-hints (groundtruth_injection, consolidation_sweep); smart MCP loader (N-04) verdrahtet (Prompt-gezielte Tool-Kataloge, `mcp_servers.yaml smart_loading: false` = alter Pfad). |
| Bugfix | `CouncilConfig::default()` nullte serde-Field-Defaults: fehlender `council:`-Block ⇒ groundtruth_injection=false trotz Default-ON-Contract. Jetzt serde-geroutet. |
| fix(rmas) | complete() stdin/stdout-Race → EIN io-Mutex über den ganzen Turn. |

## 2. Offene Zero-Friction-Items (Backlog, priorisiert)

### P1 — Onboarding-Kern
- **ZF-02 Wizard-Express-Pfad (M)**: Preset-Picker von Step „letzter" an
  Position 2 (nach Lizenz) ziehen; bei Nicht-custom die Steps
  identity-Detail (BCP-47 → OS-Autodetect), topology, autonomy,
  auto-update, wasm, supervisor SKIPPEN (Preset setzt sie). Channels /
  Keet / Obsidian / n8n / tududi / mobile-mcp aus dem Pflichtpfad in
  Post-Setup-Tipps („Add a messenger" Karte) verschieben. Ziel: ≤5
  Fragen (Mode, Lizenz, Preset, Provider, Key). Custom-Pfad = heutiger
  Flow. Datei: cli/init.rs Step-Kette + steps_identity/steps_topology.
- **ZF-03 Live-Key-Verify im Wizard (S/M)**: steps_provider macht heute
  KEINEN Test-Call; Fehler erscheint erst beim ersten Chat. Ein 1-Token
  Ping mit grün/rot + Retry im Wizard. (Provider-complete existiert;
  timeout 10s, skip-bar.)
- **ZF-04 `neoth rmas consent --acknowledge` (S)**: manueller
  `touch ~/.neoth/rmas_consent_acknowledged` ist DAU-feindlich und
  plattform-abhängig dokumentiert. CLI-Subcommand mit Anzeige des
  Upstream-Lizenz-Status + expliziter Bestätigung (Wizard erstellt den
  Marker NIE automatisch — Security-Floor).
- **ZF-05 GUI-Wizard-Parity (M/L)**: GUI-Wizard (10 Screens) fehlt:
  HMAC-Backup, Keet, Obsidian, n8n, Bitwarden-Import, WASM. Express-GUI:
  Preset-Picker als Screen 2 (wie CLI), Rest in Settings-Tipps. Der
  heutige Welcome/Migrate-Card-Pfad bleibt.

### P2 — Laufzeit-Reibung
- **ZF-06 Cron-Hot-Spawn (M)**: enabled-Gates sind SPAWN-TIME
  (serve_tasks spawn_* → return None). Preset-Flip + reload startet
  Crons NICHT (heute: Hinweis „nächster Daemon-Start"). Fix-Muster
  existiert: adapter-fleet respawnt auf generation-bump (serve.rs
  719-771) — gleiches Supervisor-Muster für Cron-Fleet. Bis dahin ist
  der Post-Apply-Hinweis der Contract.
- **ZF-07 Boot-Stagger (S)**: full-auto startet ~28 Crons gleichzeitig;
  First-Tick-Burst (9+ LLM-Crons) auf Low-End-Box. Minimal: shared
  Semaphore(3) um die First-Tick-LLM-Calls ODER deterministischer
  5s-Slot-Stagger pro Task. Erst NACH Messung bauen (YAGNI-Gate:
  Full-Auto-Feldbericht abwarten).
- **ZF-08 Doctor als Discovery-Hub (S, wiederkehrend)**: advisable-Hint
  pro sinnvoller default-OFF-Feature-Gruppe (dreaming, proactive,
  loop_config, media.dictation …) mit 1-Zeilen-Nutzen + Preset-Verweis.
  Muster steht (checks/config.rs advisable-Checks).

### P3 — GUI-Parity Long-Tail (aus Parity-Audit 2026-07-04)
Reihenfolge nach DAU-Wert; Transport-Muster (ProbeView / worker +
`--output json`) steht überall:
1. **GAP-01 Cron-CRUD im Automation-Panel (L)** — heute read-only Dump.
2. **GAP-19 Channel-Add-Formular (M)** — Token-Eingabe → credentials.yaml.
3. **GAP-03 Kanban-Write-Ops (M)** — move/assign/comment/archive.
4. **GAP-02 Loop-Definition-Form (M)** + fehlendes `/loop` Slash-Builtin.
5. **GAP-10 Kosten-Caps editierbar (M)** — daily_usd_cap/per-message im COUNCIL-Expander.
6. **GAP-06 Profil-Edit (S/M)** — language/role; Preset-Save/Delete GUI ✅ (Delete geliefert; Save-current existiert).
7. **Privacy-AUDIT-Panel (S)** — `neoth privacy audit --last 30d` (ULTRA nannte es highest-value).
8. GAP-11 n8n-Trigger, GAP-12 Agent-Run-Button, GAP-15 Hooks (+ `/hooks`), TTS/Dictate-Buttons, Glossary/Recipe-Sektionen, cluster trusted_ssids-Edit, persona_mode-Toggle.

### P4 — Cluster/Sonstiges
- **G02-CLUSTER-02 Foreign-Indexer (M, PARTIAL)**: persist-then-dedup
  liegt; idx_foreign_events wird geschrieben, aber kein Indexer
  konsumiert (wal_sync.rs:22-24). Cron nach serve_tasks-Muster.

## 3. Nicht bauen (bewusst)
- Presets, die `sovereign_buddy` / `self_activation` / `security.*` /
  Secrets setzen — Denylist, eigene Ceremonies. Babel `federate` bleibt
  default-OFF + Runtime-Consent (einziger Egress-Pfad).
- Auto-Anlegen des RMAS-Markers durch Wizard/Preset — nie.
- Kein automatisches `autonomy: full` ohne Ceremony — Preset meldet,
  Ceremony entscheidet.

## 4. Definition of Done (Zero-Friction v1)
- [x] 1-Wahl-Preset statt 75 Toggles (CLI+Wizard+GUI, Consent-Diff)
- [ ] Wizard ≤5 Fragen im Express-Pfad (ZF-02)
- [ ] Key-Fehler sichtbar IM Wizard, nicht beim ersten Chat (ZF-03)
- [ ] Kein manuelles Marker-/YAML-Editing für irgendein Feature nötig
      (ZF-04 + ZF-08 decken die Reste)
- [ ] Preset-Flip wirkt ohne Restart (ZF-06)
