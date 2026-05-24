# NEOTH Re-Evaluation R4 - Snapshot 2026-05-22

Stand: 2026-05-22  
HEAD: `bf58c01`  
Modus: nicht-destruktiver Snapshot nach R3; keine Code-Aenderungen durch diese Evaluation  
Scope: aktueller HEAD plus paralleler Live-Delta im Arbeitsbaum

## 1. Kurzurteil

R3 ist ueberholt. Die damals offene P0-Luecke "Skill-Assets liegen im Repo, wirken aber nicht zur Runtime" ist im aktuellen HEAD geschlossen: `skills::loader::load_all` startet jetzt immer mit gebundelten `include_str!`-Skills aus `SRC/neothd/assets/skills`, danach werden User-Skills aus `~/.neoth/skills` als Override gemerged.

Dadurch steigt NEOTH von **76% Arbeitsbaum / 75% Runtime-Wirkung** auf **82% aktuelle Produktreife** im committed HEAD. Streng als warning-clean Release-Gate gerechnet liegt es aber nur bei **78%**, weil `clippy -D warnings` aktuell faellt.

Waehrend dieser R4-Erstellung kam parallel ein weiterer Arbeitsbaum-Delta dazu: `SRC/neothd/src/recall/` mit offline `citation_check` plus `mod recall;` in `SRC/neothd/src/main.rs`. Dieser Delta ist untracked/modifiziert, aber bereits targeted getestet: **14 passed, 0 failed** fuer `recall::citation_check`. Wenn dieser Delta bleibt und sauber verdrahtet wird, hebt er die Live-Arbeitsbaum-Perspektive auf **83% Potential**, aber nicht den committed-HEAD-Score.

Die groeßte Verbesserung seit R3 ist nicht ein einzelnes Feature, sondern Produktwahrheit: gebundelte Skills, Mode-/Slash-/Skills-CLI, Glossary, Privacy Audit, Tour und GUI-Chat-Wiring sind jetzt belegbar im Code und durch Tests grob abgesichert.

## 2. Prozentuale Achsenbewertung

| Achse | R3 | R4 aktuell | Tendenz | Begruendung |
| --- | ---: | ---: | --- | --- |
| Security / Safety | 83% | **86%** | hoch | Privacy Audit, no-network Konstruktionstest, gebundelte Skills ohne Installationspfad-Drift, WAL/Channel-Sicherheitsregressionen gruen. Noch nicht 90+, weil Channel-/Webhook-End-to-End und Privacy-Enforcement nicht voll release-belegt sind. |
| Reliability / Betriebsfestigkeit | 76% | **82%** | hoch | Frischer Skill-Start ohne `~/.neoth/skills` funktioniert, User-Overrides sind getestet, `neothd`-Pakettests sind breit gruen. Channel-Bootstrap bleibt der Hauptabzug. |
| Code-Qualitaet / Wartbarkeit | 81% | **80%** | leicht runter | Architektur besser, aber `clippy -D warnings` faellt mit 19 Fehlern. Viel davon ist Doc-/Style-Lint, trotzdem kein warning-clean Stand. |
| Testtiefe / Evidenz | 82% | **88%** | hoch | `neothd`: 2850 passed, 2 ignored; Integration: 7 passed; no-network: 1 passed; GUI: 8 passed. Dazu Bundled-Skill-Invarianten und Loader-Override-Tests. |
| UX / GUI-Kohaerenz | 62% | **74%** | stark hoch | GUI-Chat ist nicht mehr nur Bubble-Stub, sondern ruft `neothd chat` via Subprocess. CLI-UX mit glossary/privacy/tour ist deutlich besser. Abzug: GUI-Chat ist nicht als echtes UI-E2E getestet. |
| DAU-Readiness | 65% | **74%** | hoch | `neoth glossary`, `neoth tour`, `neoth privacy audit`, Slash-Parity und bessere GUI senken Einstiegsschmerz. Noch kein rundes Consumer-Produkt. |
| Pro-Operator-Readiness | 84% | **90%** | hoch | 22 gebundelte Skills, Mode Registry, Skills install/uninstall, Slash-Oberflaeche, Coding-Workflow, Privacy/Glossary/Tour: fuer Power User jetzt stark. |
| Produktwahrheit / Claim-Disziplin | 64% | **80%** | stark hoch | Die R3-Asset-vs-Runtime-Luecke ist geschlossen. Abzug bleibt fuer Channel-Claims und warning-clean Release-Wahrheit. |
| Gesamtprodukt aktuell | 76% | **82% HEAD / 83% live-potential** | hoch | Operator-/Runtime-Fundament hat die 80%-Schwelle genommen. Der neue untracked Citation-Check bringt Potential, ist aber noch nicht CLI-verdrahtet. |
| Strict Release Gate | n/a | **78%** | neu | Wegen `clippy -D warnings` nicht release-clean. Tests sind gruen, Lint nicht. |

## 3. Oberachsen

| Oberachse | R4 | Kommentar |
| --- | ---: | --- |
| Technischer Kern | **85%** | Skill-Runtime, WAL, CLI, Provider-/Mode-/Slash-Flaechen sind jetzt belastbar. |
| Nachweisbarkeit | **87%** | Testmenge ist stark. Clippy-Gate verhindert 90+. |
| Nutzerprodukt | **74%** | CLI-Onboarding klar besser, GUI brauchbarer, aber noch nicht rund. |
| Release-Readiness Power User | **88%** | Fuer Operatoren ist das jetzt ein ernsthaft nutzbares System. |
| Release-Readiness normale Nutzer | **72%** | Tour/Glossary helfen, aber Setup, Channels und Fehlerflaechen bleiben technisch. |
| Multichannel Runtime | **71%** | Adapter/Testsubstanz existiert, aber `serve` bootstrapped im belegten Pfad weiterhin nur Telegram als echte Channel-Task. |

## 4. Was sich gegen R3 real geaendert hat

### 4.1 R3-P0 ist geschlossen: Bundled Skills wirken zur Runtime

`SRC/neothd/src/skills/bundled.rs` bindet aktuell 22 Skill-YAMLs per `include_str!` ein. `SRC/neothd/src/skills/loader.rs` baut daraus zuerst den gebundelten Skill-Satz und merged danach `~/.neoth/skills/<id>/skill.yaml` als User-Override.

Das ist die richtige Loesung:

- Kein Installer-Race.
- Kein frischer Start mit leerer Skill-Library.
- User-Override bleibt moeglich.
- `Skill::path` nutzt `<bundled>/...` als ehrlichen Marker.
- Tests pinnen leeres/missing User-Dir, Override-Verhalten, Count gegen Assets-Directory und Parse-Invarianten.

Bewertung: Dieser Punkt hebt Runtime-Wahrheit und Operator-Readiness deutlich.

### 4.2 Skill-/Mode-/Slash-Oberflaeche ist jetzt produktnaeher

Relevant gefunden:

- `neoth skills --list/--test/--install/--uninstall`
- `neoth mode list/show/match`
- `neoth slash` Sicht auf Slash-Kommandos
- Slash-Builtins fuer `/glossary`, `/privacy`, `/tour`
- 22 gebundelte Skills unter `SRC/neothd/assets/skills`

Das ist nicht mehr nur Architektur-Fundament. Das ist eine reale Operator-Oberflaeche.

### 4.3 NOOB-UX ist sichtbar besser

Neu bzw. relevant im aktuellen HEAD:

- `SRC/neothd/src/cli/glossary.rs`
- `SRC/neothd/src/cli/privacy.rs`
- `SRC/neothd/src/cli/tour.rs`

Diese drei Flächen heben DAU-Readiness, weil sie Fachbegriffe, Datenschutzlage und Einstiegspfad erklaeren, ohne dass der Nutzer den Plan-Ordner lesen muss.

Abzug: Alles ist noch stark CLI-zentriert. Fuer echte DAU-Reife muss das in GUI/First-Run sichtbar werden.

### 4.4 GUI-Chat ist nicht mehr Stub-only

`SRC/neothd-gui/src/main.rs` bindet `chat_send_clicked` jetzt an `chat_via_subprocess`, das `neothd chat <message>` startet und stdout als Assistant-Bubble rendert. Das schliesst die alte R2-P0-Luecke weitgehend.

Abzug:

- Der Pfad ist Subprocess-basiert, nicht in-process.
- Die GUI-Tests decken Wizard/Config ab, aber keinen echten `chat_via_subprocess`-Happy-Path mit Fake-`neothd`.
- Eine Kommentarstelle um `format_now_hms` spricht noch von stub-send/provider dispatch future; das ist stale und sollte bereinigt werden.

### 4.5 Channels bleiben der Runtime-Bremsklotz

`SRC/neothd/src/cli/serve.rs` bootstrapped im belegten Hauptpfad weiterhin Telegram als echte Channel-Task. Slack/WhatsApp/Discord/Keet haben Adapter, Formatter, Tests und Kommentare, aber nicht denselben sichtbaren Startpfad wie Telegram.

Das ist jetzt der groesste Unterschied zwischen "technisch viel vorhanden" und "Produkt kann breit raus".

### 4.6 Live-Delta: offline Citation-Check fuer Recall

Parallel zur Evaluation kam ein neuer untracked Recall-Block dazu:

- `SRC/neothd/src/recall/mod.rs`
- `SRC/neothd/src/recall/citation_check.rs`
- `SRC/neothd/src/main.rs` mit `mod recall;`

Inhaltlich ist das stark fuer Research-/Provenance-Qualitaet:

- erkennt DOI, arXiv, ISBN und Publisher-URLs;
- normalisiert IDs fuer spaetere Dedupe-/Lookup-Pfade;
- auditierter Offline-Heuristikpfad fuer unanchored narrative citations;
- suspicious-future-year Signal;
- JSON-stabile Report-Shape;
- keine Netzwerkanfrage, daher passend zur bestehenden no-outbound-network-Haltung.

Targeted Test:

- `.\scripts\cargo-msvc.ps1 test '-p' neothd recall::citation_check --offline`
- Ergebnis: **14 passed, 0 failed**

Abzug:

- Noch keine CLI-Verdrahtung wie `neoth recall citation-check`.
- Live Crossref/OpenAlex/Semantic-Scholar Lookup ist bewusst deferred.
- Als untracked Arbeitsbaum-Delta ist es noch nicht committed/release-wahr.

## 5. Harte Befunde

### Tests

Ausgefuehrt:

- `.\scripts\cargo-msvc.ps1 test '-p' neothd --offline`
- `.\scripts\cargo-msvc.ps1 test '-p' neothd-gui --offline`
- `.\scripts\cargo-msvc.ps1 test '-p' neothd recall::citation_check --offline`

Ergebnis:

- `neothd`: **2850 passed, 0 failed, 2 ignored**
- `neothd` Integration: **7 passed, 0 failed**
- `no_network_construction_outside_providers`: **1 passed**
- `neothd-gui`: **8 passed, 0 failed**
- `recall::citation_check` Live-Delta: **14 passed, 0 failed**

Das ist fuer einen bewegten Arbeitsbaum stark.

### Lint

Ausgefuehrt:

- `.\scripts\cargo-msvc.ps1 clippy '-p' neothd --offline -- -D warnings`

Ergebnis:

- **failed**
- 19 Fehler unter `-D warnings`

Relevante Klassen:

- `unused import: FailureItem` in `SRC/neothd/src/sub_agents/parallel.rs`
- mehrere `clippy::doc_lazy_continuation`
- `clippy::empty_line_after_doc_comments`
- `clippy::derivable_impls`
- `clippy::manual_pattern_char_comparison`

Das sind ueberwiegend wartungsnahe Probleme, keine offensichtlichen Runtime-Bugs. Trotzdem: warning-clean ist aktuell falsch behauptet.

## 6. Priorisierte naechste Arbeit

### P0 - Clippy-Gate wieder gruen machen

Wenn `-D warnings` als Release- oder CI-Gate gilt, ist das jetzt P0. Die Fixes wirken klein und mechanisch.

Done-Kriterium:

- `.\scripts\cargo-msvc.ps1 clippy '-p' neothd --offline -- -D warnings` ist gruen.

### P1 - Channel-Bootstrap ehrlich fertigziehen

Telegram startet. Die anderen Channel muessen aus dem Adapter-/Testzustand in den `serve`-Startpfad.

Done-Kriterium:

- Slack/WhatsApp/Discord/Keet haben explizite enable/config checks.
- Jeder startbare Channel bekommt eine `tokio::spawn`-Task oder einen klaren "configured but disabled/not supported"-Status.
- `neoth doctor`/`neoth status` sagt ehrlich, was live ist.

### P1 - GUI-Chat-E2E testbar machen

Der Subprocess-Ansatz ist pragmatisch. Jetzt braucht er einen Test-Haken.

Done-Kriterium:

- `chat_via_subprocess` kann mit fake binary/path getestet werden.
- Happy path, non-zero exit, empty stdout und missing binary sind abgedeckt.
- Stale Stub-Kommentare sind entfernt.

### P1 - Routing-Konflikte fuer 22 Skills pinnen

Mit 22 gebundelten Skills ist Keyword-Routing nicht mehr trivial.

Done-Kriterium:

- Prompt-Matrix fuer typische deutsche/englische Operator-Prompts.
- Erwartete Skill-ID pro Prompt.
- Tests fuer Konflikte wie `diagnose` vs `systematic_debugging`, `writing_plans` vs `to_prd`, `requesting_code_review` vs `receiving_code_review`.

### P2 - DAU-Onboarding in GUI spiegeln

Glossary/Tour/Privacy sind CLI-stark. Der naechste Sprung fuer normale Nutzer entsteht erst, wenn diese Flaechen im ersten GUI-Flow auftauchen.

## 7. Neues Gesamturteil

NEOTH hat die 80%-Schwelle im aktuellen HEAD genommen.

Streng formuliert:

- Aktuelle Produktreife: **82%**
- Live-Arbeitsbaum-Potential mit `recall::citation_check`: **83%**
- Operator-/Power-User-Reife: **88-90%**
- Normale-Nutzer-Reife: **72-74%**
- Strict warning-clean Release-Reife: **78%**

Die neue Hauptluecke ist nicht mehr Skill-Runtime. Die ist geloest. Die neue Hauptluecke ist Release-Hygiene plus Channel-/GUI-End-to-End-Beweis.

Naechster effektivster Schritt: **Clippy-Gate fixen, danach Channel-Bootstrap und GUI-Chat-E2E.**
