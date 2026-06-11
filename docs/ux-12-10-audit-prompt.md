# UX 12/10 Audit Prompt

Ziel: Bestehende Web-Apps, Apps, Desktop-GUIs und Programme so prüfen und verbessern, dass sie klarer, schneller, vertrauenswürdiger, professioneller und begehrenswerter werden. Dieses Sheet ist als Arbeitsblatt, Code-Review-Prompt und Umsetzungsplan für Codex/Claude/GPT gedacht.

Leitidee: 12/10 UX heißt nicht "mehr Effekte". Es heißt: Der Nutzer erkennt sofort den Wert, versteht ohne Nachdenken den nächsten Schritt, erreicht das Hauptziel mit minimaler Reibung, vertraut dem System auch bei Fehlern, und erinnert sich an die Experience als präzise, hochwertig und unvermeidlich.

## 0. Quellenbasis

Dieses Raster kombiniert:

- NN/g 10 Usability Heuristics: Sichtbarkeit von Systemstatus, Realwelt-Sprache, Kontrolle, Konsistenz, Fehlerprävention, Wiedererkennen statt Erinnern, Effizienz, Minimalismus, Fehler-Recovery, Hilfe im Kontext.
- Apple Human Interface Guidelines: klare Hierarchie, Harmonie mit Plattform/Device, Konsistenz, lesbare Inhalte, ausreichende Hit Targets, gute Organisation, Accessibility.
- Laws of UX: Hick's Law, Fitts's Law, Jakob's Law, Cognitive Load, Chunking, Goal-Gradient, Peak-End Rule, Von Restorff, Serial Position, Zeigarnik, Aesthetic-Usability Effect.
- Fogg Behavior Model: Verhalten passiert, wenn Motivation, Ability und Prompt gleichzeitig zusammenkommen. Erhöhe zuerst Ability durch weniger Reibung, bevor du mit Motivation/Copy nachlegst.
- Baymard Checkout/Flow Research: Drop-off entsteht oft durch lange/unklare Flows, versteckte Kosten, erzwungene Registrierung, schlechte Formular-Recovery, generische Fehler und unklare Payment-/Trust-Signale.

Primäre Referenzen:

- https://www.nngroup.com/articles/ten-usability-heuristics/
- https://developer.apple.com/design/human-interface-guidelines
- https://developer.apple.com/design/tips/
- https://lawsofux.com/
- https://www.behaviormodel.org/home
- https://baymard.com/learn/checkout-flow-ux-optimization

## 1. Agenten-Prompt

Kopiere diesen Block in einen Coding-Agenten, wenn er eine bestehende App prüfen und verbessern soll.

```text
Du bist ein kompromissloser Senior Product Designer, UX-Researcher und Frontend/GUI Engineer.

Aufgabe:
Prüfe die bestehende App/Website/Desktop-GUI im Code und optimiere UX, UI, Microcopy, Flow-Logik und Conversion-/Retention-Mechaniken auf 12/10-Niveau. Arbeite am Code, nicht nur am Screenshot. Lies Routen, Screens, Komponenten, State-Logik, Validierung, Error States, Loading States, Accessibility und Texte.

Design-Philosophie:
- Steve-Jobs-Prinzip: Design ist, wie es funktioniert. Schönheit zählt nur, wenn sie Klarheit, Vertrauen und Handlungskraft erhöht.
- Fokus: Eine Hauptaufgabe pro Screen. Alles andere wird sekundär, verschoben oder entfernt.
- Simplicity: Komplexität wird im System gelöst, nicht dem Nutzer aufgeladen.
- End-to-end Craft: Copy, Layout, State, Animation, Latenz, Fehlerverhalten und Datenmodell müssen zusammenpassen.
- Taste by subtraction: Jedes UI-Element muss seinen Platz verdienen.

Prüfe gegen:
- NN/g Heuristics
- Apple HIG / Plattformkonventionen
- Laws of UX
- Fogg B=MAP
- Ethical persuasion: echte Social Proofs, echte Knappheit, echte Authority, keine Dark Patterns
- Absprungpunkte: lange Texte, forced signup, versteckte Kosten, verlorene Eingaben, generic errors, fehlende Undo/Cancel/Back-Wege, unklare CTAs, zu viele Optionen, mobile Tastatur verdeckt CTA, leerer Loading State, onboarding wall, disabled button ohne Grund

Arbeitsweise:
1. Mappe alle relevanten Screens, Routen, Dialoge, Formulare, Hauptflows und kritischen States.
2. Extrahiere alle sichtbaren Texte, CTAs, Placeholder, Empty States, Errors, Tooltips und Toasts.
3. Identifiziere primäre Nutzerziele und den schnellsten Weg zum ersten echten Erfolg.
4. Bewerte jeden Screen nach dem 12-Dimensionen-Score unten.
5. Finde Code-Stellen, die UX-Friktion erzeugen: bedingte Disabled-States, lange Formulare, harte Validierung, unklare Error-Branches, fehlende a11y, schlechte Loading-/Empty-States.
6. Liefere konkrete Patches. Keine reinen Empfehlungen, wenn Codeänderungen möglich sind.
7. Verifiziere mit Build, Lint, Typecheck, Tests und wenn möglich Browser-/Simulator-Screenshot.

Output:
- Kurzfazit mit Gesamtscore.
- Tabelle je Screen/Flow: Score, stärkster Drop-off, betroffene Codepfade, konkrete Änderung.
- P0/P1/P2 Backlog.
- Copy-Rewrite-Tabelle: vorher, nachher, Begründung.
- Umgesetzte Patches.
- Verifikationsergebnis.
```

## 2. 12/10 Scorecard

Bewerte jede relevante Ansicht von 0 bis 10. 12/10 entsteht nicht durch einen einzelnen Wow-Effekt, sondern durch starke Werte ohne Gate-Fails.

| Dimension | Frage | 10/10-Kriterium | Harte Fail-Signale |
|---|---|---|---|
| 1. Intent Clarity | Weiß der Nutzer in 3 Sekunden, was diese Ansicht macht? | Headline, Layout und CTA zeigen Aufgabe + Ergebnis. | Vage Hero-Copy, "Learn more" als Primäraktion, kein sichtbarer nächster Schritt. |
| 2. Value Immediacy | Erlebt der Nutzer schnell echten Nutzen? | Erster sinnvoller Erfolg in unter 30s oder klarer Fortschritt. | Onboarding-Wand, erst Account/API-Key/Setup vor Wert. |
| 3. Focus | Hat der Screen genau eine Primärhandlung? | Ein Primary CTA, sekundäre Aktionen visuell tiefer. | Mehrere gleich starke Buttons, konkurrierende Cards, Navigation lenkt vom Flow ab. |
| 4. Cognitive Load | Muss der Nutzer zu viel lesen/merken/entscheiden? | Chunking, progressive Disclosure, sichtbare Labels, kurze Texte. | Lange Absätze, 7+ gleichwertige Optionen, versteckte Regeln. |
| 5. Friction | Wie viele Schritte, Felder und Zweifel liegen zwischen Nutzer und Ziel? | Jedes Feld/Step verdient seinen Platz; Defaults und Autofill helfen. | Pflichtfelder ohne Grund, forced signup, manuelle Re-Eingabe, Captcha früh. |
| 6. Feedback | Reagiert das System sichtbar und schnell? | Immediate feedback, Skeleton/Progress, klare Statewechsel. | Spinner ohne Kontext, Button wirkt tot, optimistic UI ohne Recovery. |
| 7. Error Recovery | Sind Fehler spezifisch, reparierbar und nicht beschämend? | Inline, konkret, Daten bleiben erhalten, direkte Reparatur. | "Invalid input", gelöschte Eingaben, Fehler erst am Ende, kein Retry. |
| 8. Trust | Wirkt das Produkt kompetent und ehrlich? | Kosten, Risiken, Datenschutz, Status und Grenzen sind sichtbar. | Überraschungskosten, Fake-Social-Proof, unklare Berechtigungen, dunkle Muster. |
| 9. Accessibility | Können Menschen und Assistive Tech die UI bedienen? | Keyboard, Fokus, Kontrast, Labels, Hit Targets, reduced motion. | Icon-only ohne Label, schlechte Kontraste, kein Fokus, Textüberlauf. |
| 10. Platform Fit | Fühlt es sich auf Device/OS/Web nativ und erwartet an? | Konventionen werden genutzt, Reach Zones und Layout passen. | Custom Controls brechen Standards, mobile CTA verdeckt, Desktop ohne Tastaturpfade. |
| 11. Delight/Craft | Gibt es präzise Details, die Qualität spürbar machen? | Motion, Spacing, Typografie, Empty States und Microcopy wirken absichtlich. | Einheitslayout, inkonsistente Abstände, billig wirkende Gradients, Layout-Jumps. |
| 12. Growth Loop | Gibt es natürlichen Share-/Return-Wert? | Ergebnis ist speicherbar, teilbar, wiederholbar oder habit-bildend. | Referral vor Wert, Share-Button ohne sharewürdiges Ergebnis, keine Erinnerung an Fortschritt. |

Gate-Fails, die den Gesamtscore deckeln:

- Keine sichtbare Primäraktion: max. 6/10.
- Nutzer verliert eingegebene Daten bei Fehler/Back: max. 5/10.
- Primärer Flow ist mit Keyboard oder Mobile nicht bedienbar: max. 6/10.
- Überraschungskosten, versteckte Registrierung oder Fake-Trust-Signale: max. 4/10.
- Kritische Aktion ohne Confirmation/Undo: max. 6/10.
- Kritischer Screen ohne Error-/Loading-/Empty-State: max. 7/10.

## 3. Steve-Jobs-Prinzipien als Review-Fragen

Nutze diese Fragen brutal. Wenn die Antwort schwach ist, ändern.

1. Was ist die eine Sache, die dieser Screen perfekt tun muss?
2. Welche guten Ideen müssen gelöscht werden, damit die beste Idee sichtbar wird?
3. Kann ein Erstnutzer das Ergebnis fühlen, bevor er die Architektur verstehen muss?
4. Ist die UI das Produkt oder nur Dekoration über dem Produkt?
5. Wurde Komplexität wirklich entfernt oder nur in einem Menü versteckt?
6. Wird der Nutzer geführt, ohne bevormundet zu werden?
7. Sind die wichtigsten Dinge physisch leicht erreichbar: Blick, Maus, Touch, Keyboard?
8. Ist jeder Zustand gestaltet: initial, hover, focus, loading, empty, success, error, disabled, offline?
9. Würde ein Screenshot professionell wirken, wenn alle Texte entfernt wären?
10. Würde der Flow noch funktionieren, wenn alle visuellen Effekte deaktiviert wären?

## 4. Psychologische Mechanismen

### 4.1 Fogg B=MAP

Für jede Zielhandlung prüfen:

- Motivation: Will der Nutzer das Ergebnis wirklich? Ist der Nutzen konkret?
- Ability: Ist die Handlung leicht genug? Felder, Schritte, Kosten, Risiko, Zeit, Wissen.
- Prompt: Gibt es zum richtigen Zeitpunkt einen klaren, sichtbaren Auslöser?

Optimierungsregel:

1. Ability erhöhen: weniger Schritte, bessere Defaults, Autofill, Beispiele, inline Hilfe.
2. Prompt schärfen: CTA sichtbar, konkret, verbbasiert, an der richtigen Stelle.
3. Motivation nur dann erhöhen: Social Proof, Nutzen, Status, Belohnung, Fortschritt.

Schlechter Fix: lauterer CTA auf schlechtem Flow.
Guter Fix: Flow so einfach machen, dass der CTA leise sein darf.

### 4.2 Hick's Law

Wenn Entscheidungen langsam werden, reduziere Anzahl und Komplexität der Optionen.

Check:

- Gibt es mehr als 5 gleichwertige Optionen?
- Sind Unterschiede zwischen Optionen sofort klar?
- Gibt es eine empfohlene Default-Option?
- Kann Advanced Stuff hinter "Advanced", "More", "Customize" oder einem sekundären Panel liegen?

Fix:

- Eine empfohlene Option markieren.
- Seltene Optionen einklappen.
- Optionen nach Nutzerziel gruppieren, nicht nach interner Architektur.
- Vergleichstabelle nur, wenn Unterschiede wirklich verglichen werden müssen.

### 4.3 Fitts's Law

Wichtige Ziele müssen groß, nah und leicht erreichbar sein.

Check:

- Mobile Tap Targets mindestens ca. 44x44 px/pt.
- Primary CTA im natürlichen Scan-/Reach-Bereich.
- Destructive Actions nicht direkt neben Primary Actions.
- Kleine Icon-Buttons haben Label/Tooltip und klaren Fokuszustand.
- Häufige Aktionen sind nicht in Menüs vergraben.

### 4.4 Jakob's Law

Nutzer bringen Erwartungen aus anderen Produkten mit.

Check:

- Suche sieht aus und funktioniert wie Suche.
- Back/Cancel/Undo verhalten sich erwartbar.
- Links sehen wie Links aus; Buttons wie Buttons.
- Platform-Konventionen werden nicht aus Branding-Eitelkeit gebrochen.
- Eigene Metaphern erklären sich sofort.

### 4.5 Cognitive Load, Chunking, Recall

Das Interface soll Wiedererkennen ermöglichen, nicht Erinnern erzwingen.

Check:

- Labels bleiben sichtbar, auch wenn der Nutzer tippt. Placeholder ersetzt kein Label.
- Regeln stehen neben dem Feld, nicht in einer weit entfernten Anleitung.
- Multi-Step-Flow zeigt aktuellen Schritt, erledigte Schritte und nächsten Schritt.
- Informationen werden in sinnvolle Gruppen geteilt.
- Wichtige Daten müssen nicht aus vorherigen Screens erinnert werden.

### 4.6 Goal-Gradient, Zeigarnik, Progress

Menschen bleiben eher dran, wenn Fortschritt sichtbar und unvollständige Aufgaben greifbar sind.

Check:

- Fortschritt wird wahr und nicht künstlich angezeigt.
- Der nächste kleinste Schritt ist klar.
- Teilweise erledigte Arbeit bleibt gespeichert.
- Rückkehr in einen Flow setzt dort fort, wo der Nutzer aufgehört hat.
- Completion States zeigen konkret, was erreicht wurde.

### 4.7 Peak-End Rule

Nutzer erinnern die stärkste Stelle und das Ende.

Check:

- Gibt es einen starken Moment, in dem Wert sichtbar wird?
- Ist der Abschluss mehr als "Done"?
- Werden Fehler am Ende vermieden?
- Gibt es einen guten finalen Zustand: Ergebnis, Kopieren, Teilen, nächster Schritt?

### 4.8 Von Restorff und Serial Position

Das wichtigste Element darf auffallen. Nicht alles darf auffallen.

Check:

- Genau ein Element pro Ansicht ist visuell dominant.
- Erste und letzte Elemente in Listen/Flows sind bewusst gewählt.
- Badges, Farben und Animationen werden sparsam eingesetzt.
- Warnfarben sind für echte Warnungen reserviert.

### 4.9 Social Proof, Authority, Reciprocity, Scarcity

Nur ethisch und wahr einsetzen. Fake-Signale sind kurzfristiger Conversion-Schrott und langfristiger Vertrauensverlust.

Check:

- Social Proof: echte Zahlen, echte Reviews, echte Logos, konkrete Quelle.
- Authority: Zertifizierungen, Sicherheitsdetails, Benchmarks oder Expertise belegen.
- Reciprocity: erst Wert geben, dann Account/Share/Payment fragen.
- Scarcity: nur anzeigen, wenn sie real, aktuell und relevant ist.
- Commitment: kleine, freiwillige Schritte nutzen; keine versteckten Verpflichtungen.

## 5. Absprungpunkt-Katalog

Diese Muster sind Drop-off-Kandidaten. Im Code suchen, im Flow verifizieren, dann patchen.

| Absprungpunkt | Typischer Code-/UI-Geruch | Besser |
|---|---|---|
| Forced signup | Account muss vor Wert erstellt werden. | Guest/Trial/Preview zuerst; Account nach erstem Erfolg. |
| Onboarding wall | Mehrere Slides vor Nutzung. | Inline Onboarding, progressive Hilfe, Skip. |
| Zu lange Texte | Mehrere Absätze im Tool-/App-Screen. | Headline + 1 Satz + konkrete Aktion. |
| Unklare CTA | "Continue", "Submit", "Next" ohne Kontext. | "Create backup", "Start scan", "Send invite". |
| Zu viele Optionen | Cards/Buttons mit gleicher Priorität. | Default, Gruppierung, progressive Disclosure. |
| Versteckte Kosten | Preis/Usage erst spät sichtbar. | Kosten vor Commit, klare Limits, Preview. |
| Datenverlust | Form reset bei Fehler, Back oder Reload. | State persistieren, Draft, Retry ohne Re-Entry. |
| Generische Fehler | "Something went wrong". | Ursache + konkrete Reparatur + Retry/Undo. |
| Aggressive Validation | Fehler während des Tippens. | Nach Blur oder Submit; während Tippen nur sanfte Hinweise. |
| Disabled Button ohne Erklärung | Button deaktiviert, Nutzer weiß nicht warum. | Inline Checklist oder Error direkt daneben. |
| Spinner ohne Kontext | Endlos-Loading. | Skeleton, Status, ETA/Step, Cancel falls lang. |
| Fehlender Exit | Modal/Wizard ohne Back/Cancel. | Back, Cancel, Undo, Escape, Close. |
| Mobile Keyboard verdeckt CTA | Autofocus + CTA unten. | Kein aggressiver Autofocus; CTA sichtbar; safe-area beachten. |
| Icon-only Mystery | Icons ohne Label/Tooltip. | Labels für unklare Icons; aria-label immer. |
| Layout Shift | Inhalte springen bei Loading/Error. | Stable dimensions, skeleton placeholders. |
| Marketing vor Produkt | Landing-Seite statt nutzbarem Tool. | Hauptnutzen im ersten View direkt ausführbar. |

## 6. Copy- und Text-Regeln

### 6.1 Text-Budgets

Richtwerte, nicht Dogma:

| Element | Budget | Regel |
|---|---:|---|
| Button | 1-3 Wörter | Verb + Objekt, keine cleveren Labels. |
| Nav Item | 1-2 Wörter | Erwartbare Begriffe. |
| Screen Heading | 3-7 Wörter | Was passiert hier? |
| Helper Text | 1 Zeile | Nur Regel, Risiko oder nächster Schritt. |
| Error | 1-2 Sätze | Problem + Fix. |
| Empty State | 1 Heading, 1 Satz, 1 CTA | Kein Essay. |
| Toast | 3-8 Wörter | Ergebnis, nicht Erklärung. |
| Onboarding | Max. 3 Bullets | Jede Bullet unter 8 Wörter. |
| Modal | Max. 1 kurzer Absatz | Bei Destructive: Konsequenz + Aktion. |

### 6.2 Copy-Formel

Gute UX-Copy beantwortet:

1. Was ist passiert?
2. Warum ist es relevant?
3. Was kann ich jetzt tun?

Beispiele:

| Schlecht | Besser |
|---|---|
| "Invalid input" | "Email needs an @ sign." |
| "Submit" | "Create workspace" |
| "Error while processing request" | "Scan failed because the server is offline. Retry when it is reachable." |
| "You must complete all required fields" | "Add a project name to continue." |
| "Continue" | "Continue to payment" |
| "Learn more" als Primary CTA | "Start free scan" |

### 6.3 Wörter, die oft UX verschlechtern

Prüfen und meist ersetzen:

- "Maybe", "might", "probably": schwächt Vertrauen.
- "Advanced" für Dinge, die jeder braucht: falsche Hierarchie.
- "Magic", "AI-powered" ohne konkretes Ergebnis: Marketing-Lärm.
- "Submit": technisch statt nutzerorientiert.
- "Optional" bei Feldern, die nicht wirklich gebraucht werden: Feld löschen.
- "Required" ohne Grund: begründen oder entfernen.
- Interne Begriffe: nur verwenden, wenn Zielgruppe sie wirklich nutzt.

### 6.4 Platzhalter sind keine Labels

Pflicht:

- Jedes Input-Feld hat ein persistentes Label.
- Placeholder zeigt Beispiel, nicht Regelwerk.
- Validierungsregel steht neben dem Feld oder erscheint kontextuell.
- Error-Meldung steht nah am betroffenen Feld.

## 7. Flow-Logik

### 7.1 Primary Flow Audit

Für den wichtigsten Flow:

1. Was ist der erste Wertmoment?
2. Wie viele Klicks/Taps bis dahin?
3. Wie viele Pflichtfelder bis dahin?
4. Welche Entscheidungen sind vor Wert nötig?
5. Welche Daten kann das System selbst ableiten?
6. Was passiert bei Back, Refresh, Offline, Timeout?
7. Wo kann der Nutzer abbrechen?
8. Wo kann der Nutzer ohne Datenverlust zurück?

12/10-Ziel:

- Erstes sinnvolles Ergebnis vor Konfiguration.
- Konfiguration wird aus Nutzungsdaten abgeleitet, nicht abgefragt.
- Fortgeschrittene Optionen sind da, aber nicht im Weg.

### 7.2 Formulare

Regeln:

- Nur Felder, die jetzt gebraucht werden.
- Gute Defaults.
- Browser Autofill unterstützen.
- Mobile Keyboard-Typen korrekt setzen.
- Eingaben nie löschen, außer der Nutzer löscht bewusst.
- Inline-Fehler nah am Feld.
- Submit-Fehler scrollt zum ersten Fehler.
- Langes Formular in sinnvolle Abschnitte splitten.
- Optionales nicht als Pflicht tarnen.

Code-Indikatoren:

```bash
rg -n "placeholder|aria-label|aria-describedby|disabled|required|validate|error|invalid|toast|spinner|loading|modal|dialog|input|textarea|select|form|submit|checkout|signup|register|onboarding" .
```

### 7.3 Buttons und CTAs

Regeln:

- Pro Screen genau ein visueller Primary CTA.
- CTA sagt Ergebnis, nicht technische Aktion.
- Disabled CTA erklärt, was fehlt.
- Destructive CTA ist visuell getrennt und bestätigt.
- Secondary Actions sind erreichbar, aber nicht dominant.
- Icon Buttons brauchen Tooltip/Accessible Name.

Code-Indikatoren:

```bash
rg -n "Button|button|IconButton|disabled|onClick|onPress|submit|primary|secondary|danger|destructive|aria-label|title=" .
```

### 7.4 Loading, Empty, Error, Success

Jeder relevante State braucht Design.

| State | Muss enthalten |
|---|---|
| Loading | Was passiert gerade, stabile Fläche, ggf. Schritt/ETA, Cancel bei langer Aktion. |
| Empty | Warum leer, wie starten, ein CTA. |
| Error | Konkretes Problem, Ursache wenn bekannt, Fix, Retry/Undo, keine Daten verlieren. |
| Success | Was wurde erreicht, wo ist das Ergebnis, sinnvoller nächster Schritt. |
| Offline | Was funktioniert noch, was wird synchronisiert, wann wird retried. |
| Disabled | Warum nicht verfügbar, was fehlt, wie aktivieren. |

Code-Indikatoren:

```bash
rg -n "isLoading|loading|pending|suspense|skeleton|empty|error|catch|toast|success|retry|offline|disabled" .
```

## 8. UI Craft Check

### 8.1 Layout

Prüfen:

- Kein Textüberlauf auf Mobile/Desktop.
- Keine Cards in Cards, wenn es nur Layout-Deko ist.
- Stable dimensions für Boards, Grids, Toolbars, Inputs, Buttons.
- Keine Layout-Shifts bei Hover, Loading, Validation.
- Primärinhalt ist im ersten View sichtbar.
- Navigation konkurriert nicht mit kritischen Flows.
- Scrollposition bleibt bei Statewechseln sinnvoll.

### 8.2 Typografie

Prüfen:

- Headings sind nicht hero-groß in Tool-Panels.
- Line length grob 45-75 Zeichen bei Lesetext.
- Body-Text nicht zu dünn, nicht zu klein.
- Keine negative Letter-Spacing.
- Keine viewport-basierte Font-Size-Spielerei für normalen Text.
- Labels, Meta und Errors sind lesbar.

### 8.3 Farbe

Prüfen:

- Farben haben semantische Rollen.
- Warnung, Erfolg, Info, Gefahr sind unterscheidbar.
- Kontrast für Text und Controls ausreichend.
- Palette wirkt nicht wie ein einfarbiges Theme ohne Hierarchie.
- Primary Color wird nicht für alles benutzt.

### 8.4 Motion

Prüfen:

- Motion erklärt Zustand oder Beziehung, nicht nur Deko.
- Microinteractions ca. 150-250ms.
- Screen transitions nur länger, wenn sie Orientierung stiften.
- `prefers-reduced-motion` wird respektiert.
- Animation verursacht keine Layout-Sprünge.

### 8.5 Accessibility

Minimum:

- Keyboard vollständig bedienbar.
- Sichtbarer Fokus.
- Semantische Buttons/Links/Form Fields.
- Accessible Names für Icon Buttons.
- Labels für Inputs.
- Kontrast ausreichend.
- Hit Targets groß genug.
- Dialoge trap/focus korrekt.
- Errors sind für Screenreader verbunden.

Code-Indikatoren:

```bash
rg -n "aria-|role=|tabIndex|autofocus|focus|label|htmlFor|alt=|title=|dialog|modal|tooltip|prefers-reduced-motion" .
```

## 9. Internet-Konsens- und Viralitäts-Mechaniken

"Viralität" entsteht selten durch Share-Buttons. Sie entsteht, wenn ein Ergebnis so nützlich, neu, statusrelevant oder erleichternd ist, dass Teilen rational wirkt.

### 9.1 Sharewürdiger Output

Prüfen:

- Erzeugt die App ein Artefakt, Ergebnis, Report, Bild, Link, Score, Dashboard oder Vorher/Nachher?
- Ist dieses Ergebnis ohne Login anschaubar, wenn Sharing Ziel ist?
- Gibt es gutes Open Graph / Preview-Material?
- Ist die Share-Copy konkret und nicht cringe?
- Kann der Nutzer vor dem Teilen bearbeiten, anonymisieren oder kontrollieren?

### 9.2 Retention

Prüfen:

- Gibt es einen natürlichen Grund zurückzukehren?
- Speichert die App Fortschritt oder Historie sichtbar?
- Wird der nächste sinnvolle Schritt angeboten?
- Gibt es Reminder nur nach echtem User Intent?
- Gibt es persönliche Verbesserung, Monitoring, Watchlist, Inbox, Feed, Habit oder Workflow-Fortsetzung?

### 9.3 Social Proof

Prüfen:

- Sind Nutzerzahlen, Logos, Reviews oder Testimonials echt und nachvollziehbar?
- Ist Social Proof nah an der Entscheidung, die er stützen soll?
- Wird Qualität gezeigt statt nur Menge?
- Für B2B: Case, ROI, Sicherheits-/Compliance-Signale.
- Für Developer Tools: Stars, issues, releases, docs quality, examples, benchmarks.

### 9.4 Trust Before Ask

Regel:

- Erst Ergebnis, dann Account.
- Erst Nutzen, dann Newsletter.
- Erst Klarheit, dann Payment.
- Erst Permission-Rationale, dann Permission Prompt.
- Erst Preview, dann Commitment.

## 10. Review-Ausgabeformat

Jeder Audit soll so enden:

```markdown
## UX Verdict

Gesamtscore: X/10
Deckelnder Gate-Fail: falls vorhanden
Stärkster Hebel: eine konkrete Änderung

## Screen/Flow Score

| Screen/Flow | Score | Hauptproblem | Codepfad | Fix |
|---|---:|---|---|---|
| ... | ... | ... | ... | ... |

## P0/P1/P2

- P0: Muss vor Release, sonst Drop-off/Trust/A11y kaputt.
- P1: Hoher UX-/Conversion-Hebel.
- P2: Polish, Craft, Delight.

## Copy Rewrites

| Ort | Vorher | Nachher | Warum |
|---|---|---|---|
| ... | ... | ... | ... |

## Implementierte Änderungen

- Datei + kurze Änderung.

## Verifikation

- Build/Lint/Typecheck/Test/Screenshot Ergebnis.
```

Severity-Regeln:

- P0: Blockiert Hauptflow, zerstört Vertrauen, verliert Daten, bricht Accessibility, versteckt Kosten/Risiko.
- P1: Erhöht Drop-off messbar, erzeugt Verwirrung, verlängert Flow, schwächt Conversion/Activation.
- P2: Polish, Konsistenz, Delight, professioneller Eindruck.

## 11. Code-Review-Prozedur

1. Repo scannen.
   ```bash
   rg --files
   ```

2. App-Struktur finden.
   ```bash
   rg -n "route|router|screen|page|layout|component|view|window|dialog|modal|form|wizard" .
   ```

3. Texte extrahieren.
   ```bash
   rg -n "\"[^\"]{12,}\"|'[^']{12,}'|placeholder|title|label|description|helper|error|toast" .
   ```

4. UX-Risiken suchen.
   ```bash
   rg -n "disabled|isLoading|loading|error|invalid|required|submit|signup|register|checkout|payment|delete|remove|danger|confirm|undo|cancel|back" .
   ```

5. A11y suchen.
   ```bash
   rg -n "aria-|role=|tabIndex|htmlFor|label|alt=|dialog|modal|focus|autofocus|keyboard|shortcut" .
   ```

6. Styling/Responsive suchen.
   ```bash
   rg -n "overflow|white-space|text-overflow|line-clamp|height:|width:|min-width|max-width|font-size|letter-spacing|z-index|position: fixed|position: absolute" .
   ```

7. Hauptflow manuell oder mit Playwright/Simulator durchlaufen.

8. Patches umsetzen.

9. Verifizieren:
   ```bash
   pnpm test
   pnpm exec tsc --noEmit
   pnpm exec playwright test
   ```
   Passe Befehle an das Projekt an. Wenn keine Tests existieren: mindestens Build/Typecheck/Lint oder App-Start plus Screenshot.

## 12. Optimierungsrezepte

### 12.1 "Zu langer Text"

Vorher:

- Erklärung, warum Feature existiert.
- Interne Begriffe.
- Mehrere Nebensätze.
- CTA ohne Ergebnis.

Nachher:

- Heading: Ergebnis.
- Satz: Was passiert als Nächstes.
- CTA: konkrete Handlung.

Template:

```text
[Ergebnisorientierte Heading]
[Ein Satz: was das System jetzt macht oder was der Nutzer bekommt.]
[Verb + Objekt CTA]
```

### 12.2 "Zu viele Optionen"

Fix:

- Top 1 Default vorselektieren.
- Top 3 sichtbar lassen.
- Rest unter "More options".
- Unterschiede in 1 Zeile je Option.
- Recommendation erklären, nicht nur badge draufkleben.

### 12.3 "Formular fühlt sich schwer an"

Fix:

- Felder löschen, die später erhoben werden können.
- Beispiele in Placeholder, Labels persistent.
- Input Masks nur verzeihend.
- Validierung nach Blur.
- Autofill und passende Keyboard Types.
- Progress und Draft speichern.

### 12.4 "User vertraut nicht"

Fix:

- Kosten, Datenverwendung, Risiken und Dauer vor Commit zeigen.
- Status und Logs sichtbar machen, wenn relevant.
- Security/Privacy-Signale konkret statt generisch.
- Keine Fake-Zähler.
- Support/Undo/Cancel klar sichtbar.

### 12.5 "UI wirkt nicht premium"

Fix:

- Weniger visuelle Ideen.
- Präzise Spacing-Skala.
- Konsistente Radius-/Shadow-/Color-Tokens.
- Ein primärer Akzent.
- Bessere Empty/Error/Success States.
- Kein Textüberlauf.
- Keine generischen Stock-Bilder.
- Icons nur mit klarer Funktion.
- Motion für Ursache-Wirkung, nicht für Lärm.

### 12.6 "Kein Wachstum"

Fix:

- Ergebnis exportierbar/teilbar machen.
- Vorher/Nachher zeigen.
- Nutzerfortschritt sichtbar machen.
- Return Hook aus echtem Workflow bauen: Monitoring, Inbox, Watchlist, Report, Memory, Saved Views.
- Share nach Wertmoment anbieten, nicht davor.

## 13. Finaler 12/10 Release-Gate

Vor Release muss der Reviewer diese Fragen mit "ja" beantworten:

- Kann ein Erstnutzer den Hauptwert ohne Erklärung starten?
- Gibt es genau eine dominante Primäraktion pro Screen?
- Sind alle Texte kürzer als nötig, aber nicht unklar?
- Sind Fehler spezifisch, reparierbar und datenverlustfrei?
- Sind Loading, Empty, Success, Error, Disabled und Offline gestaltet?
- Funktioniert der Hauptflow auf Mobile/Desktop/Keyboard?
- Werden Plattformkonventionen respektiert?
- Ist Trust vor Commitment hergestellt?
- Gibt es keinen Fake-Social-Proof, keine versteckte Knappheit, keine Dark Patterns?
- Gibt es einen starken Wertmoment und einen guten Abschluss?
- Ist das Ergebnis speicherbar, fortsetzbar oder teilbar?
- Wurde der Code verifiziert: Build, Lint, Typecheck, Tests oder App-Start/Screenshot?

Wenn eine Frage "nein" ist, ist es kein 12/10.
