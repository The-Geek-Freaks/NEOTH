# NEOTH Re-Evaluation R3 - Snapshot 2026-05-22

Stand: 2026-05-22  
Modus: nicht-destruktiver Snapshot, waehrend parallel weiter am Projekt gearbeitet wird  
Scope: Delta gegen R2, Fokus auf neue Skill-Assets, Loader-Test und aktuelle Runtime-Wahrheit

## 1. Kurzurteil

Die technische Gesamtbewertung liegt im aktuellen Arbeitsbaum bei **76% Produktreife**, aber weiterhin nur bei **75% belegter Runtime-Wirksamkeit**. Es gibt neue, sinnvolle Skill-Assets fuer Arbeitsdisziplin und Review-Prozesse, und `SRC/neothd/src/skills/loader.rs` enthaelt jetzt einen Smoke-Test, der die gebundelten YAMLs aus `SRC/neothd/assets/skills/...` parst.

Das hebt die Evidenz, aber noch nicht die Runtime-Wahrheit: Die Chat-/CLI-Ladestrecke zeigt weiterhin auf `~/.neoth/skills`. Die Assets sind damit als Paketbestandteil und Testfixture sichtbar, aber ihre automatische Aktivierung im frischen Runtime-Home ist noch nicht bewiesen. Sobald ein sauberer Installer/Bundled-Skill-Merge existiert und Routing-Konflikte getestet sind, steigt die Bewertung realistisch auf **78%**.

## 2. Prozentuale Achsenbewertung

| Achse | R2 | R3 aktuell | Tendenz | Begruendung |
| --- | ---: | ---: | --- | --- |
| Security / Safety | 83% | **83%** | stabil | Keine neuen Security-relevanten Runtime-Aenderungen. Die neuen Skills verbessern Prozesssicherheit nur nach Aktivierung. |
| Reliability / Betriebsfestigkeit | 76% | **76%** | stabil | Keine neue Bootstrap-/Runtime-Verdrahtung gefunden. Bestehende Zuverlaessigkeitsluecken bleiben. |
| Code-Qualitaet / Wartbarkeit | 80% | **81%** | leicht hoch | Der neue Loader-Smoke-Test ist fokussiert und passt zum bestehenden Modul. Runtime-Bundling bleibt offen. |
| Testtiefe / Evidenz | 79% | **82%** | hoch | `neothd skills::` laeuft mit 38 Passing Tests inklusive Parse-Smoke-Test fuer gebundelte Skills. Routing-/Installations-Tests fehlen noch. |
| UX / GUI-Kohaerenz | 62% | **62%** | stabil | Kein neuer belegter GUI-End-to-End-Fortschritt in diesem Snapshot. |
| DAU-Readiness | 65% | **65%** | stabil | Normale Nutzer profitieren erst, wenn Skills installiert/aktiviert und sichtbar erklaert werden. |
| Pro-Operator-Readiness | 82% | **84%** | hoch | Die neuen Skills plus `writing_skills` staerken professionelle Operator-Workflows deutlich, sobald sie aktiviert sind. |
| Produktwahrheit / Claim-Disziplin | 64% | **64%** | stabil | Der neue Test macht Asset-Existenz ehrlicher, aber automatische Runtime-Aktivierung ist weiter offen. |
| Gesamtprodukt aktuell | 75% | **76%** | leicht hoch | Der Arbeitsbaum hat bessere Evidenz. Die Runtime-Wirkung bleibt bei 75%, bis Bundling/Installation belegt ist. |

## 3. Oberachsen

| Oberachse | R3 | Kommentar |
| --- | ---: | --- |
| Technischer Kern | **82%** | Loader und Skill-Core bleiben solide; der neue Test verbessert die Absicherung. |
| Nachweisbarkeit | **81%** | Asset-Parse ist jetzt belegt. Routing- und Installations-Evidenz fehlen noch. |
| Nutzerprodukt | **64%** | Keine neue GUI-/DAU-Wirksamkeit im Snapshot. |
| Release-Readiness Power User | **81%** | Fuer Operatoren attraktiver durch Review-/TDD-/Debugging-/Skill-Authoring-Disziplin. |
| Release-Readiness normale Nutzer | **63%** | Unveraendert zu schwach fuer breitere Produktreife. |

## 4. Neue Beobachtungen seit R2

### 4.1 Neue Skill-Assets sind fachlich sinnvoll

Neu bzw. untracked gefunden:

- `SRC/neothd/assets/skills/systematic_debugging/skill.yaml`
- `SRC/neothd/assets/skills/test_driven_development/skill.yaml`
- `SRC/neothd/assets/skills/requesting_code_review/skill.yaml`
- `SRC/neothd/assets/skills/receiving_code_review/skill.yaml`
- `SRC/neothd/assets/skills/writing_skills/skill.yaml`

Bereits als erwarteter gebundelter Skill im Loader-Test enthalten:

- `SRC/neothd/assets/skills/verification_before_completion/skill.yaml`

Inhaltlich ist das eine gute Richtung:

- `systematic_debugging` erzwingt Root-Cause-Arbeit statt Symptompatching.
- `test_driven_development` beschreibt RED/GREEN/REFACTOR konsequent.
- `requesting_code_review` macht Pre-Review-Evidenz explizit.
- `receiving_code_review` verhindert halb erledigte Review-Kommentare.
- `writing_skills` erzwingt RED/GREEN/REFACTOR-Disziplin beim Schreiben neuer Skill-Manifeste.

Das passt sehr gut zum bestehenden `verification_before_completion`-Gedanken und hebt die Operator-Qualitaet, sobald es wirklich aktiv ist.

### 4.2 Neuer Pluspunkt: Asset-Parse-Smoke-Test existiert

`SRC/neothd/src/skills/loader.rs` enthaelt jetzt `qm_21_ported_superpowers_skills_all_parse_clean`. Der Test laedt `assets/skills`, erwartet sechs Skill-IDs und prueft, dass jeder Skill Trigger und einen nicht-leeren `system_prompt` hat.

Das ist genau die richtige Richtung und hebt die Test-/Evidenzachse spuerbar. Eine Einschraenkung bleibt: Der Test parst Assets im Source Tree, beweist aber noch nicht, dass ein frisches Runtime-Home diese Skills automatisch bekommt.

### 4.3 Kritische Runtime-Luecke: Assets werden offenbar nicht automatisch aktiviert

Gefundene Codepfade:

- `SRC/neothd/src/cli/chat.rs` baut den Skill-Pfad aus `FreedomConfig::default_neoth_home()` und `skills`.
- `SRC/neothd/src/cli/skills.rs` nutzt ebenfalls `FreedomConfig::default_neoth_home().join("skills")`.
- Die neue Loader-Teststrecke liest `assets/skills` fuer Tests, ersetzt aber keine Runtime-Installation.

Damit gilt aktuell:

> Die neuen YAMLs sind im Repository sichtbar und parse-getestet, aber nach jetzigem Befund nicht automatisch Teil des laufenden Chat-/Skill-Routings.

Das ist die wichtigste R3-Korrektur. Nicht die Skill-Idee ist schwach, sondern die Produktintegration ist noch unvollstaendig.

### 4.4 Trigger-Breite braucht Regressionstests

Einige Trigger sind breit:

- `test_driven_development` mit Begriffen wie `implement`, `add`, `refactor`, `write the`.
- `systematic_debugging` mit generischen Fehlerwoertern wie `fails`, `failing`, `broken`.
- `writing_skills` ist spezifischer, sollte aber gegen normale Dokumentationsprompts abgegrenzt werden.

Das kann gewollt sein, aber sobald die Skills wirklich aktiv sind, muss das Routing mit allen gebundelten Skills gemeinsam getestet werden. Sonst kann ein breiter Skill spezifischere Skills ueberdecken.

## 5. Priorisierte Bewertung

### P0 - Bundled-Skill-Installation oder Loader-Merge klaeren

Die neuen Assets brauchen einen echten Runtime-Pfad. Zwei saubere Varianten:

1. `neoth init` kopiert gebundelte Default-Skills nach `~/.neoth/skills`, ohne User-Dateien blind zu ueberschreiben.
2. Der Loader merged gebundelte Skills plus User-Skills, wobei User-Skills Vorrang haben.

Done-Kriterium:

- Frischer NEOTH-Home ohne manuelle Kopie aktiviert die gebundelten Skills nachweisbar.
- Konflikte sind deterministisch geloest.
- Test beweist, dass mindestens einer der neuen Skills aus dem frischen Runtime-Pfad geladen wird.

### P1 - Asset-Fixture-Tests fuer alle gebundelten YAMLs

Teilweise erledigt: `qm_21_ported_superpowers_skills_all_parse_clean` parst die gebundelten YAMLs im Source Tree und prueft Basisinvarianten.

Offenes Done-Kriterium:

- Test deckt nicht nur Parse, sondern erwartetes Routing ab.
- Routing-Erwartungen fuer typische deutsche und englische Prompts sind festgelegt.
- CI/Packaging unterscheidet bewusst zwischen "Assets fehlen im Publish-Shape" und "Assets muessen im Source Tree vorhanden sein". Aktuell skippt der Test, wenn `assets/skills` fehlt; fuer Packaging-Wahrheit braucht es einen strengeren Pfad.

### P1 - Routing-Konflikte sichtbar machen

Gerade `test_driven_development` kann sehr viel fangen. Das ist nur akzeptabel, wenn die Rangfolge transparent ist.

Done-Kriterium:

- Regressionstabelle mit Beispielprompts:
  - Bug/Failure -> `systematic_debugging`
  - Feature mit explizitem TDD -> `test_driven_development`
  - Review anfordern -> `requesting_code_review`
  - Review-Kommentare abarbeiten -> `receiving_code_review`
  - Abschluss melden -> `verification_before_completion`
- Keine unerwarteten Ueberdeckungen.

### P2 - UX/Operator-Sicht herstellen

Wenn Skills aktiv sind, braucht der Operator eine einfache Sicht:

- Welche Skills sind installiert?
- Welche sind enabled?
- Warum wurde dieser Skill fuer diesen Prompt gewaehlt?

Ohne diese Sicht bleibt das Feature fuer Power User gut, fuer DAU aber undurchsichtig.

## 6. Delta gegen R2

Positiv:

- Neuer Fortschritt in Richtung professioneller Agenten-Arbeitsablaeufe.
- Skill-Core-Testbereich ist gruen.
- Asset-Parse-Smoke-Test fuer gebundelte Skills ist vorhanden.
- `writing_skills` schliesst die Methodik-Luecke beim Erstellen neuer Skills.
- Die neuen Skills ergaenzen bestehende Verification-Ideen sinnvoll.

Negativ bzw. offen:

- Keine belegte automatische Aktivierung der neuen Assets im frischen Runtime-Home.
- Asset-Fixture-Test deckt Parse ab, aber noch nicht Routing-Entscheidungen oder Installation.
- Routing-Konflikte durch breite Trigger noch nicht abgesichert.
- Keine Verbesserung der GUI-/Channel-/DAU-Luecken aus R2.

## 7. Verifikation in diesem Snapshot

Ausgefuehrt:

- `git status --short`
- `git diff --stat`
- `git ls-files --others --exclude-standard SRC/neothd/assets/skills`
- `git grep` nach Skill-Ladepfaden und `assets/skills`
- `.\scripts\cargo-msvc.ps1 test '-p' neothd skills:: --offline`

Ergebnis:

- Tracked Arbeitsbaum hat eine Aenderung in `SRC/neothd/src/skills/loader.rs`.
- Neue untracked Skill-Asset-Verzeichnisse vorhanden, inklusive `writing_skills`.
- Skill-Core-Testbereich: **38 passed, 0 failed**.
- Parse der gebundelten Skill-Assets ist getestet.
- Kein belastbarer Runtime-Pfad gefunden, der `SRC/neothd/assets/skills` automatisch in `~/.neoth/skills` installiert oder als Bundled-Skills merged.

## 8. Neues Gesamturteil

NEOTH liegt im aktuellen Arbeitsbaum bei **76% aktueller Produktreife**. Die reine belegte Runtime-Wirksamkeit bleibt bei **75%**, weil der neue Asset-Parse-Test noch keine automatische Aktivierung beweist.

Streng formuliert:

- Als Engineering-Basis: **gut und wachsend**.
- Als aktiv nutzbares Skill-System out of the box: **noch nicht voll bewiesen**.
- Als Power-User-Werkzeug: **ueber 80% im Arbeitsbaum, wenn Bundling/Installer geloest ist**.
- Als normales Nutzerprodukt: **weiter klar unter 70%**.

Naechster effektivster Schritt: **Bundled-Skill-Loader oder Installer plus Asset-Fixture-Tests**. Das ist der kleinste Hebel, der den heutigen Fortschritt von "liegt im Repo" zu "wirkt im Produkt" macht.
