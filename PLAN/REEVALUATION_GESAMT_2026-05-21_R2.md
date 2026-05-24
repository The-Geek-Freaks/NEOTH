# NEOTH - Re-Evaluation Gesamt R2 (2026-05-21)

**Anlass:** erneutes "nochmal evaluieren bitte" nach der ersten Re-Evaluation.  
**Scope:** aktueller Worktree, Fokus auf `SRC/` statt README-/Roadmap-Claims.  
**Wichtig:** bestehende untracked Reports wurden nicht ueberschrieben. Diese Datei ist bewusst separat.

---

## 1) Urteil in einem Satz

NEOTH ist technisch deutlich staerker als die letzte Re-Evaluation es belegt hat, aber es ist noch kein rundes DAU-Produkt: die Kernmodule haben Substanz und viele Tests, waehrend GUI-Chat, Channel-Live-Wiring, Produktwahrheit in der Doku und einige "Scaffold wird als fertig wahrgenommen"-Flaechen die Produktreife bremsen.

---

## 2) Was sich gegenueber der letzten Bewertung aendert

Die letzte Bewertung war zu pauschal bei "fehlender Evidenz". Das stimmt so nicht mehr.

Verifizierte Fakten:

- `SRC/neothd/src/channels/webhook_verify.rs` hat echte Edge-/Anti-Fragility-Tests fuer Meta/Slack Signaturen, Query-Parser, Timestamp-Skew, malformed Hex und Duplicate-Key-Semantik.
- `SRC/neothd/src/channels/webhook_router.rs` und `webhook_listener.rs` sind nicht nur Konzept: sie haben End-to-End-Tests auf GET/POST, Slack URL verification, Body-Cap und Shutdown.
- `SRC/neothd/src/mcp/gate.rs` und `SRC/neothd/src/permissions/gate.rs` sind substanzielle Safety-Gates mit Audit-Pfaden.
- `SRC/neothd/src/wasm_plugin/*` ist mit Feature `wasm-plugin-host` erstaunlich weit: Fuel, Memory-Limiter, Manifest-Caps, Discovery, Compile-Preflight, Hostcall-Katalog und Dispatcher sind getestet.
- `SRC/neothd/src/providers/local_qwen.rs` enthaelt jetzt eine Disk-Space-Preflight-Erweiterung; die Tests dafuer laufen.
- Testmarker im Kernbereich: 260 Dateien mit insgesamt 2667 `#[test]` / `#[tokio::test]` Treffern.

Die neue Kritik ist deshalb nicht mehr "zu wenig Tests", sondern:

1. Es gibt noch zu viele Produktversprechen, die nur als Scaffold, outbound-only, CLI-only oder feature-gated real sind.
2. Die GUI zeigt an manchen Stellen eine Produktoberflaeche, deren Backend noch Stub ist.
3. Einige sichere Defaults sind korrekt fail-closed, aber fuer Normalnutzer nicht als klare UX gefuehrt.
4. Die README ist stellenweise optimistischer als der Live-Daemon-Wiring-Stand.

---

## 3) Re-Scoring R2 (0-10)

| Kategorie | Score | Begruendung |
|---|---:|---|
| Security / Safety | 8.3 | Gute Crypto-Primitives, MCP-Allowlist default-deny, Permission-Gate, WAL-Audit, WASM-Limits. Abzug fuer Plugin-Hook "degrades to Allow" ohne Invoker und fehlendes Channel-Confirm. |
| Reliability | 7.6 | Viele kleine deterministische Tests und robuste WAL-/Gate-Pfade. Abzug fuer unbounded webhook connection spawning, Feature-/Scaffold-Flanken und begrenzte Runtime-E2E-Abdeckung. |
| Code-Qualitaet | 8.0 | Rust-Struktur ist modular, explizite Fehler, klare Tests. Abzug fuer veraltete Kommentare/Scaffold-Text, grosse Module, GUI-Subprocess-Kopplung. |
| Testtiefe | 7.9 | 260/2667 Testmarker plus gezielte Gruenlaeufe. Abzug fuer fehlende Full-suite-Verifikation in dieser Runde, kaum GUI-Visual/E2E, Qwen-forward ignored ohne lokale Gewichte. |
| UX / GUI | 6.2 | Wizard und Settings sind real, aber GUI-Chat ist aktuell nur Stub-Bubble. Code Sessions ist maechig, aber dicht und pro-orientiert. |
| DAU-Readiness | 6.5 | Installation/Wizard/Telegram/CLI besser als MVP, aber Chat-GUI und Multi-Channel-Erwartung sind noch nicht idiotensicher. |
| Pro-Operator-Readiness | 8.2 | CLI, WAL, Gates, hooks, code sessions, tests und config surfaces sind stark fuer Power User. |
| Produktwahrheit / Claim-Disziplin | 6.4 | README/Status kommuniziert manche "ships" Aussagen staerker als der Daemon-Wiring-Stand hergibt. |
| Gesamt | 7.5 | Starkes Fundament mit echten Sicherheits- und Testbelegen; noch kein "12/10 Produkt". |

### 3.1 Prozentuale Achsenbewertung

Umrechnung: `Score / 10 * 100`. Die Prozentwerte sind keine Marketing-Reifegrade, sondern aktuelle Ist-Bewertung pro Achse gegen den Anspruch "sicheres, alltagstaugliches, pro-faehiges Personal-AI-Produkt".

| Achse | Prozent | Ampel | Kurzurteil |
|---|---:|---|---|
| Security / Safety | 83% | gruen | Starke Gates, HMAC-Pfade, MCP default-deny, WAL-Audit, WASM-Limits; Plugin-Hook fail-open und Channel-Confirm bleiben offen. |
| Reliability / Betriebsfestigkeit | 76% | gelb-gruen | Viele robuste Kernpfade; Overload-/Drain-/Runtime-E2E-Vertraege noch nicht hart genug. |
| Code-Qualitaet / Wartbarkeit | 80% | gruen | Modularer Rust-Kern, explizite Fehler, viele Tests; Abzug fuer grosse Module und teils veraltete Scaffold-Kommentare. |
| Testtiefe / Evidenz | 79% | gelb-gruen | Starke Unit-/Edge-Testbasis; Full-suite, GUI-E2E, visuelle Tests und echter Qwen-Forward-Pass fehlen in dieser Runde. |
| UX / GUI-Kohaerenz | 62% | gelb | Wizard/Settings real, aber GUI-Chat ist nicht end-to-end; Code Sessions ist pro-stark, fuer DAUs dicht. |
| DAU-Readiness | 65% | gelb | Einstieg besser als Roh-CLI, aber sichtbare Primaerflows und Multi-Channel-Erwartung sind noch zu bruechig. |
| Pro-Operator-Readiness | 82% | gruen | CLI, WAL, Kanban, Gates, Hooks, Provider-Topologie und Diagnostik sind stark fuer Power User. |
| Produktwahrheit / Claim-Disziplin | 64% | gelb | README/Status muss strenger zwischen live, outbound-only, feature-gated und scaffold unterscheiden. |
| Gesamtprodukt aktuell | 75% | gelb-gruen | Sehr gutes Fundament; noch nicht die konsistente Produktreife, die die README teilweise suggeriert. |

Verdichtung nach Oberachsen:

| Oberachse | Prozent | Gewichtung / Lesart |
|---|---:|---|
| Technischer Kern | 81% | Mittel aus Security, Code-Qualitaet, Pro-Operator-Readiness. |
| Nachweisbarkeit | 78% | Mittel aus Reliability und Testtiefe. |
| Nutzerprodukt | 64% | Mittel aus UX, DAU-Readiness und Produktwahrheit. |
| Release-Readiness fuer Power User | 80% | Nutzbar fuer technische Operatoren mit CLI-Komfort und Fehlertoleranz. |
| Release-Readiness fuer normale Nutzer | 63% | Noch nicht gut genug, solange GUI-Chat und Channel-Wiring nicht echt end-to-end sind. |

---

## 4) Harte Findings

### P0-1: GUI-Chat ist nicht end-to-end

Beleg:

- `SRC/neothd-gui/ui/main.slint` deklariert `chat-send-clicked` mit Kommentar, dass Rust durch `cli::chat::run_chat_with` dispatcht.
- `SRC/neothd-gui/src/main.rs` macht aktuell nur: trimmen, loggen, operator bubble in die Scrollback pushen, composer leeren.
- Der Kommentar im Rust-Code sagt explizit: "The full provider dispatch lands in the next Chat-wiring pick".

Impact:

- Fuer DAUs sieht die GUI wie ein Chat aus, aber Send erreicht keinen Provider.
- Das ist keine kleine Polish-Luecke, sondern der zentrale erste Nutzermoment.

Done-Kriterium:

- GUI Send muss denselben Provider-/WAL-/Permission-/Cost-Pfad nutzen wie `neothd chat`.
- Fehler muessen in der Bubble landen, nicht nur im Log.
- Test: GUI callback -> mock provider -> assistant bubble + WAL/provider frames.

### P0-2: Daemon startet real nur Telegram als Channel-Task

Beleg:

- `SRC/neothd/src/cli/serve.rs` importiert und spawnt im Channel-Abschnitt nur `TelegramChannel`.
- `WebhookListenerConfig` / `webhook_listener::serve` existieren und sind getestet, werden im `serve`-Pfad aber nicht gebootstrapped.
- `WhatsAppChannel::run()` bails weiterhin mit "webhook receiver deferred".
- `KeetChannel::run()` bails weiterhin mit "receive loop is deferred".
- Discord hat inzwischen Gateway-Code im Adapter, aber der Daemon-Wiring-Abschnitt startet ihn nicht.

Impact:

- "Channels on deck" ist als Adapter-Code teilweise richtig, als Produktwahrnehmung aber riskant.
- Operatoren koennen konfigurieren, aber Live-Inbound ist nicht konsistent.

Done-Kriterium:

- `serve` muss pro konfiguriertem Channel explizit spawn/skip mit Health-Status machen.
- `neoth doctor channels` muss "live inbound", "outbound-only", "configured but not started", "scaffold" sauber trennen.
- README darf nur das behaupten, was `serve` tatsaechlich bootet.

### P0-3: HookAction::Plugin kann sicherheitsrelevant fail-open wirken

Beleg:

- `SRC/neothd/src/hooks/dispatcher.rs` setzt `Plugin`-Actions ohne Invoker auf "degrades to Allow".
- `bootstrap_plugin_invoker()` loggt Compile-/Discovery-Probleme und registriert bei null kompilierten Plugins keinen Invoker.

Impact:

- Wenn ein Operator einen Plugin-Hook als Policy-/Safety-Hook versteht, kann ein slim build, Compile-Fehler oder fehlende Registrierung den Hook faktisch ueberspringen.
- Das ist fuer optionale Telemetrie okay, fuer Safety-Hooks nicht.

Done-Kriterium:

- Hook-Schema braucht `required: true/false` oder getrennte Actions `PluginOptional` / `PluginRequired`.
- Required Plugin failure muss `Block` ergeben.
- Doctor muss fehlende Invoker als rote Policy-Luecke markieren, wenn required hooks existieren.

### P1-1: Webhook-Listener ist security-sauber, aber operativ noch nicht belastbar

Beleg:

- Body-Cap ist korrekt vor dem Vollbuffern (`Limited`).
- Signaturpfade sind gut getestet.
- Pro TCP-Connection wird aber unbounded `tokio::spawn` erzeugt.
- Over-cap Body wird im Test nur als "non-success" akzeptiert; praktisch faellt das aktuell ueber Handler-Error auf 500 statt klarer 413/429.
- Kommentar sagt selbst: Caller ist fuer Drain in-flight connections verantwortlich.

Impact:

- Fuer localhost hinter Reverse Proxy ist das vertretbar.
- Fuer "best-in-class" fehlt ein expliziter Overload-Contract.

Done-Kriterium:

- Semaphore-bounded accept/serve.
- 413 fuer Body cap, 429 fuer concurrency cap.
- In-flight counter in `/metrics`.
- Shutdown wartet bounded auf aktive Requests.

### P1-2: Permission-Gate ist sicher, aber Channel-Confirm ist noch nicht Produkt

Beleg:

- `ConfirmStrategy::Channel` deny-t aktuell "channel-confirm not wired".
- Tests pinnen dieses fail-closed Verhalten.

Impact:

- Safety ist korrekt.
- User Experience bei Standard/Strict-Autonomie ist fuer nicht-interaktive Channels noch hart.

Done-Kriterium:

- Channel-confirm mit Timeout, auditierbarem Request/Decision-Frame und replay-sicherer Decision-ID.
- UI/CLI erklaert, warum eine Aktion nicht lief und wie man sie freigibt.

### P1-3: Coding workflow ist stark fuer Pros, aber nicht "autonom fertig"

Beleg:

- `neoth code` hat Decomposition, Kanban, Dispatcher und optional `--dispatch`.
- Patch-Apply existiert mit `--apply <repo_root>` und task-spezifischem Worktree.
- Trotzdem bleiben Ambiguous Tasks heuristisch unassigned; LLM second opinion ist noch Pick #9.
- Worker-Prompt hat noch "repo context placeholder" und fordert unified diff, statt lokale Dateien wirklich kontrolliert bereitzustellen.

Impact:

- Als Operator-Workflow stark.
- Als vollautonomer Coding-Agent noch nicht auf Codex-/Claude-Code-Niveau.

Done-Kriterium:

- Repo-context selection integriert.
- Ambiguous classifier -> LLM second opinion live.
- Apply/Test result in GUI und WAL sichtbar.
- Worktree cleanup policy vorhanden.

### P2-1: Cloud ist "local mirror live", nicht direkte Cloud-Integration

Beleg:

- `connector_for()` ist live, wenn `connector_options.local_root` gesetzt ist.
- Ohne `local_root` faellt er auf `StubConnector`.
- `modified_unix` ist im LocalFsConnector aktuell immer 0.
- Direkte Dropbox/OneDrive/GDrive/GCS/iCloud/Gmail APIs sind nicht umgesetzt.

Impact:

- Fuer Operatoren mit Desktop-Sync praktisch brauchbar.
- Als "Cloud connectors" ohne Qualifier missverstaendlich.

Done-Kriterium:

- README/Doctor: "local mirror mode" klar benennen.
- `modified_unix` korrekt befuellen.
- Direkte API-Connectoren erst als live labeln, wenn OAuth/Transport existiert.

### P2-2: Local Qwen Preflight ist gut, aber Forward-Pass-Evidenz ist noch optional

Beleg:

- `local_qwen` Tests: 23 passed, 1 ignored.
- Ignored Test: `local_qwen_forward_pass_against_cached_weights`, braucht `NEOTH_QWEN_TEST_REPO_PATH`.

Impact:

- Download-/Prompt-/Sampling-/Preflight-Pfade sind testbar.
- Reale lokale Inferenzqualitaet und Hardware-Performance sind in dieser Runde nicht belegt.

Done-Kriterium:

- CI/manual smoke mit kleinem lokalen Fixture oder dokumentiertem nightly hardware lane.
- Metrics: cold start, tokens/s CPU, tokens/s CUDA, Speicherverbrauch, failure mode bei fehlenden Gewichten.

### P2-3: GUI-Testabdeckung ist funktional, nicht visuell

Beleg:

- `neothd-gui` Tests: 8 passed.
- Tests decken Autonomy-Validation, License-Gate und YAML writes ab.
- Keine Screenshot-/layout-/keyboard-/a11y-Verifikation in dieser Runde.

Impact:

- Wizard-Serialization ist gut.
- 12/10 GUI-Qualitaet kann so nicht nachgewiesen werden.

Done-Kriterium:

- Slint UI smoke: render start, navigate wizard, settings tabs, chat send mock.
- Screenshot regression oder wenigstens layout sanity fuer 820x600 und 1100x720.
- Keyboard order und focus states testen.

---

## 5) Positive Befunde

### Security

- Meta/Slack HMAC-Verifikation ist sauber getrennt und gut getestet.
- Slack replay window ist gepinnt.
- Query parser hat Edge-Tests fuer leere Queries, malformed percent escapes, duplicate keys und unknown keys.
- MCP gate ist secure-by-default: kein `allow_tools` und kein `trust_all_tools` bedeutet deny.
- Tool descriptions und JSON schema descriptions werden sanitisiert.
- Permission decisions werden in WAL geschrieben.
- WASM host hat Fuel und Memory cap wirklich an Wasmtime angebunden.

### Reliability

- WAL-/Store-/Gate-Design nutzt explizite Events und Tests.
- Webhook body-limit ist vor dem Vollbuffern platziert.
- Local Qwen disk-space preflight verhindert halbkaputte Downloads.
- Daemon hat PID lock, clock rollback guard, quota guard, panic log.

### Pro-Operator Surface

- CLI ist breit und tief.
- Kanban / coding workflow hat echte Datenmodelle, DB-CRUD, Dispatcher, GUI Board und Activity Feed.
- Feature Flags sind bewusst eingesetzt, nicht zufaellig.
- Viele Stubs bailen mit actionable error statt silent no-op.

---

## 6) Verification in dieser Runde

Ausgefuehrt:

- `git status --short`
  - Worktree war bereits dirty: mehrere untracked PLAN/docs Reports.
- Testmarker-Sichtung:
  - 260 Dateien mit `#[test]` / `#[tokio::test]`
  - Summe Treffer: 2667
- `& .\scripts\cargo-msvc.ps1 test '-p' neoth-plugin-sdk --offline`
  - 5 passed, 0 failed
  - 1 doctest ignored
- `& .\scripts\cargo-msvc.ps1 test '-p' neothd webhook_verify --offline`
  - 29 passed, 0 failed
- `& .\scripts\cargo-msvc.ps1 test '-p' neothd webhook_router --offline`
  - 16 passed, 0 failed
- `& .\scripts\cargo-msvc.ps1 test '-p' neothd webhook_listener --offline`
  - 6 passed, 0 failed
- `& .\scripts\cargo-msvc.ps1 test '-p' neothd mcp::gate --offline`
  - 13 passed, 0 failed
- `& .\scripts\cargo-msvc.ps1 test '-p' neothd permissions::gate --offline`
  - 14 passed, 0 failed
- `& .\scripts\cargo-msvc.ps1 test '-p' neothd cloud:: --offline`
  - 15 passed, 0 failed
- `& .\scripts\cargo-msvc.ps1 test '-p' neothd wasm_plugin --features wasm-plugin-host --offline`
  - 67 passed, 0 failed
- `& .\scripts\cargo-msvc.ps1 test '-p' neothd local_qwen --offline`
  - 23 passed, 0 failed, 1 ignored
- `& .\scripts\cargo-msvc.ps1 test '-p' neothd-gui --offline`
  - 8 passed, 0 failed

Initialer Fehlstart:

- Direkte `cargo test -p neothd ... --offline` Aufrufe aus der normalen PowerShell scheiterten an fehlendem MSVC Environment (`cl.exe` / `ml64.exe` nicht gefunden).
- Der projektinterne Wrapper `scripts/cargo-msvc.ps1` loest das, wenn `-p` als Argument gequotet wird: `'-p'`.

Nicht ausgefuehrt:

- Keine volle `test --workspace` Suite.
- Kein `clippy --workspace --all-targets -- -D warnings`.
- Kein realer GUI-Screenshot-/Interaction-Test.
- Kein realer Qwen Forward Pass mit lokalen Gewichten.
- Keine echten externen Channel/API Calls.

---

## 7) Naechste Umsetzung nach Prioritaet

### P0

1. GUI Chat wirklich an `run_chat_with` / Provider / WAL / Error-Bubbles anbinden.
2. Daemon Channel-Wiring ehrlich machen: Telegram, Slack, Discord, WhatsApp webhook listener, Keet jeweils explizit live/outbound-only/scaffold.
3. Plugin hooks required-vs-optional einfuehren; required plugin failure muss blocken.

### P1

4. Webhook overload contract: semaphore, 413/429, in-flight metrics, bounded shutdown drain.
5. Channel-confirm implementieren oder UI/Doctor auf "unwired fail-closed" hochstufen.
6. Coding workflow: repo-context, second-opinion classifier, apply/test visibility, worktree cleanup.

### P2

7. Cloud local-mirror wording fix + `modified_unix` korrekt befuellen.
8. GUI visual/e2e smoke fuer Wizard, Settings, Chat, Code Sessions.
9. Local Qwen hardware smoke lane dokumentieren/automatisieren.

---

## 8) Schlussurteil

Die harte Korrektur: NEOTH ist kein Blender. Unter der Haube gibt es viel echte Substanz, und mehrere Sicherheitsflaechen sind besser getestet als die letzte Re-Evaluation unterstellt hat.

Die ebenso harte Gegenposition: NEOTH darf sich noch nicht als fertig integriertes Alltagsprodukt verkaufen. Die groessten Luecken sind nicht kryptographisch oder architektonisch, sondern in Live-Wiring, Claim-Disziplin und dem ersten Nutzererlebnis in der GUI.

Kurz: Pro-Operator-Basis stark. DAU-Produkt noch nicht. Naechster Qualitaetssprung ist nicht "mehr Ideen", sondern weniger Scaffolds in sichtbaren Primaerflows.
