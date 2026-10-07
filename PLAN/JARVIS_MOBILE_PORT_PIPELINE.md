# Jarvis-Funktionen in NEOTH Mobile — verbindliche Gold-Pipeline

Auftrag vom 7. Oktober 2026: Die selbst gebaute Jarvis-App und die eigenen
WhatsApp-Funktionen einschließlich sichtbarer Tool-Aufrufe für NEOTH übernehmen,
für Android und iOS anpassen und mit dem NEOTH-GUI-Design vereinheitlichen.
Dieser Auftrag erweitert Road to 1.0 Gold. Er ersetzt keine offene Gold-Abnahme.

## Nachweis und bestehende Grenzen

Referenz ist der Chat **Alexa mit Jarvis verbinden**
(`01a0f174-3180-7820-848b-5a90983da860`). Der untersuchte Android-Checkout hat
Basis `03619565f017820a090f3fbf9b6571b3c8a3d3da` und enthält lokale eigene Änderungen.
Die Dateihashes des tatsächlichen Inhalts sind deshalb maßgeblich; der Commit
allein beschreibt die neuen Jarvis-Funktionen nicht. Die Root-Lizenz des
OpenClaw-Checkouts ist MIT (2026 OpenClaw Foundation). Eine spätere konkrete
Code-/Asset-Übernahme behält die jeweilige Attribution; Drittanbieter-Assets
haben ihre eigenen Bedingungen.

Der zusätzlich angefragte eigene WhatsApp-Toolstatus ist inzwischen als konkreter
Archivcode wiedergefunden: `live-status-aba.js`, SHA-256
`6E879EB352D051BC938F49083D2F74CE8DEFB3444C339B5DDB6A6785DDE35A71`,
und zugehöriger Integrationspatch. Die ergänzende Quellinventur
`work/gold-20260906/wave2485-jarvis-mobile-source/WHATSAPP_SOURCE_RECOVERY.md`
belegt Turn-Start, Teilantwort, Tool-Start, Compaction, Finalize und sichtbare
Endantwort als Eingänge einer editierbaren Statusblase. Dazu gehören lesbare
Schritte, Todo-Checkliste/Fortschritt, Aktivitätsanzeige, begrenzte Edits/Rollover
und Abschluss-, Fehler-, Limit- und Stale-Zustände. Dies ist Quellnachweis,
kein aktueller WhatsApp-Installations- oder Zustellnachweis. Die ursprüngliche
Quelllücke unter JM-01/JM-06 ist damit behoben; der NEOTH-Port bleibt offen.

Lokale Eingangsnachweise liegen unter
`work/gold-20260906/wave2485-jarvis-mobile-source/` (Inventar und Hashmanifest)
und `work/gold-20260906/wave2485-neoth-mobile-port-map/` (NEOTH-Zielkarte).
Die Untersuchung ist statisch. Historische Jarvis-Geräteberichte sind keine
NEOTH-Tests. In diesem Schritt wurden keine App-Quellen aus Jarvis importiert.

NEOTH-Ausgangsstand ist `8f0d1306573fe27cfabd7ac3f70227ece2f21e33`:
Flutter V3 besitzt Pairing, Status, einen laufenden Chat-Auftrag, lokale
Cancellation und begrenzte Endergebnisse. Es besitzt noch keinen mobilen
Tool-Ereignisstrom, keine dauerhafte mobile Chat-Historie und keinen
WhatsApp-Inbox-Vertrag. Desktop-Chatereignisse, Tool-Records, kanonische
Transkripte und WhatsApp-Serveradapter sind bereits vorhanden und werden genutzt.

Die aktuelle WhatsApp-Baileys-Route kann neue Text-/Mediennachrichten mit dauerhaftem
Idempotenzschutz senden, besitzt aber noch keine Edit-/Unsend-/Status-API.
JM-06 benötigt dafür zusätzlich eine an Konto, ursprünglichen Chat und Inbound-Turn
gebundene Status-Operation. Unklare Zustellausgänge bleiben ungeklärt und dürfen
nicht durch erneutes Senden verdeckt werden; der bestehende Schlüssel der
Endantwort bleibt getrennt. Ohne Edit-Fähigkeit entstehen keine zusätzlichen
Fortschrittsnachrichten. Der Quellabgleich dazu liegt unter
`work/gold-20260906/wave2486-whatsapp-owner-map/WHATSAPP_OWNER_MAP.md`.

Der aktuelle Mobile-Produktfehler bleibt eine eigene offene Abnahme. Der letzte
CLI-Vertrag auf diesem Stand ist mit 59 Fällen unabhängig aufgenommen; dies
belegt weder Mobile Pair/Status/Chat/Revoke noch den hier geplanten Port.

## Verbindliche Arbeitspakete

Alle folgenden Pakete bleiben offen, bis ihre konkrete Abnahme vorliegt.
Eine Vorlage, ein statischer Review oder ein registrierter Test schließt sie
nicht. Zusätzliche beim Port gefundene eigene Jarvis-Funktionen erhalten vor
Gold-Abschluss einen eigenen Eintrag; fehlende Quellen werden nicht still
als entbehrlich behandelt.

| ID | Funktionsumfang und belegte Vorlage | NEOTH-Ziel und erforderliche Abnahme |
|---|---|---|
| JM-01 | Vollständiger Abgleich der eigenen App- und WhatsApp-Erweiterungen. Die App enthält tatsächlich Tool-Statuszeilen, Gesprächsvorschau, transiente Nachrichtenkarten und responsive Zustände. | Quellen mit Inhalts-Hash, bestehende NEOTH-Funktion, Anpassung, Test und Restabhängigkeit pro Funktion zuordnen. Der eigene WhatsApp-Statusmanager ist separat wiedergefunden und wird als eigener Quellstand erfasst; die App-Nachrichtenvorschau ersetzt ihn nicht. |
| JM-02 | NEOTH-Design und mobile Darstellung. Jarvis liefert kompakte lesbare Zeilen, Statuskarten und anpassbare Panels. | `apps/neoth_companion/lib/main.dart` und vorhandene Flutter-Komponenten an die semantischen Rollen aus `SRC/neothd-gui/ui/theme.slint`, `design-system/PRODUCT.md` und `DESIGN.md` angleichen. Erste isolierte Umsetzung zeigt die bereits vorhandenen V3-Endergebnisse. Keine simulierten Tool-Aufrufe. Abnahme: reale Zustände, schmale/breite Ansichten, Textskalierung, Accessibility-Labels und erhaltene Bedienaktionen. |
| JM-03 | Sichtbare Tool-Aufrufe mit laufend, erfolgreich, fehlgeschlagen und unbestätigt. Vorlage: `TalkModeManager.kt`, `JarvisToolDetail.kt`, `JarvisScreen.kt`, `HorizonSnapshotFactory.kt`. | Echte Start-/Ergebnisereignisse am Aufrufpfad `mcp/dispatch_loop.rs` erzeugen und über den tatsächlichen Adapter in `cli/chat.rs` durchreichen; die bisherigen Records in `cli/chat_turn_pipeline.rs` entstehen erst nach der Antwort. Die begrenzte Fortschrittsprojektion darf Tool-Ausführung, Audit und finale Antwort auch bei einem langsamen Empfänger nicht blockieren. Anschließend berechtigter Transport durch Companion-Protokoll, Rust-Bridge und Dart. Keine stdout-Auswertung als Tool-Wahrheit und kein zweites Tool-Ledger. Abnahme: echte Aufrufe, Reihenfolge, Korrelation, verspätete/duplizierte Ereignisse, Abschluss, Abbruch, Reconnect und fehlendes Ergebnis. |
| JM-04 | Sichere Tool-Details und begrenzte Anzeige. Jarvis zeigt kontrollierte Namen und nur ausgewählte Dateinamen/Hosts/Aktionen; keine rohen Argumente, Outputs, Fehler oder IDs. Laufende Karten bleiben sichtbar, abgeschlossene erhalten einen einmaligen kurzen Ablauf. | NEOTH-eigene Auswahlregeln vor der Darstellung, begrenzte Zeilen, monotone Fristen und textlich erkennbare Zustände. Bestehende Rechte und Audit-Belege bleiben maßgeblich. Abnahme mit sensiblen Canaries, unbekannten Tools, langen Daten, Clock/TTL, Turn-Wechsel und fehlenden Resultaten; ein unbekanntes Ende darf nicht als Erfolg erscheinen. |
| JM-05 | Gesprächsdarstellung und Streaming. Vorlage: typisierte User/Assistant-Einträge und begrenztes Panel in `JarvisConversationPresentation.kt`; bewusstes Scrollen/Folgen. | Bestehenden NEOTH-Session-/Transcript-Owner und echte Deltas verwenden. Mobile-Protokoll und native ABI explizit versionieren, V3-Terminal nicht heimlich erweitern. Abnahme: Zuordnung zum richtigen Gespräch, Delta/Final-Zusammenführung, Scrollverhalten, Abbruch, Reconnect, History-Bounds und keine doppelte Antwort. |
| JM-06 | Eigene WhatsApp-Statusblase aus dem wiedergefundenen `live-status-aba.js`: Turn-Start, Teilantwort, Tool-Schritte, Todo-Checkliste/Fortschritt, Compaction, Aktivität/Dauer und Done/Error/Limit/Stale; begrenztes Editieren/Rollover und getrennte Endantwort. | An `channels/whatsapp_api.rs`, `channels/whatsapp_baileys.rs` und den bestehenden Account-/Turn-/Delivery-Owner anbinden. Dieselbe typisierte Tool-Projektion wie Mobile verwenden, soweit die Kanal-Semantik es erlaubt. Abnahme: korrekter Account/Empfänger/Turn, echte Tool-/Planereignisse, Reihenfolge, begrenzte Aktivitätsupdates/Edits, Transport ohne Edit-Fähigkeit, Compaction-/Limit-/Stale-Enden, Zustellbeleg, Wiederanlauf, keine doppelte Status- oder Endnachricht und keine sensiblen Tool-Details. Ein neuer WhatsApp-Inbox-Client ist dadurch nicht impliziert. |
| JM-07 | Belegte App-Nachrichtenvorschau: WhatsApp, WhatsApp Business und Telegram; explizite Freigabe, Paket-Allowlist, Ruhezeiten, 512-Zeichen-Grenze, Deduplikation und 30-Sekunden-Karte. Vorlage: `IncomingMessageNotice.kt` und `NodeRuntime.kt`. | Als opt-in, rein lesende NEOTH-Vorschau über einen eigenen autorisierten Kanal-/Benachrichtigungs-Owner anpassen. Keine Notification-Actions, Read-Receipts oder Antworten aus dem Preview ableiten. Plattformunterschiede Android/iOS explizit behandeln. Abnahme: fehlende Freigabe, Ruhezeiten, veraltete/replayed Events, doppelte Quelle, Ablauf, Widerruf und getrennte Kanalzuständigkeit. |
| JM-08 | Voice-/Medienzustände: zuhören, verarbeiten, sprechen, still, abgebrochen; begrenzte Gesprächs- und Mikrofon-Lebensdauer. Vorlage: `JarvisConversationLifecycle.kt` und Talk-Session-Zustände. | Mit NEOTHs bestehendem Voice-/Session-/Medien-Owner verbinden. Gerätespezifische Wake-Modelle, Echo-Sonderfälle oder OpenClaw-Realtime-APIs nicht als NEOTH-Vertrag übernehmen. Abnahme: tatsächlicher Audio-/Session-Lebenszyklus, Unterbrechung, Hintergrund/Vordergrund, Berechtigung, Cleanup und Android/iOS-spezifische Grenzen. Weitere Jarvis-Kamera-/Timer-/Home-Ansichten in JM-01 aufnehmen, bevor über ihre NEOTH-Anpassung entschieden wird. |
| JM-09 | Einheitliche NEOTH-Bedienung über Mobile und bestehende Desktop-Oberflächen. | Gemeinsame Bedeutung für Ready/Working/Waiting/Needs-confirmation/Failed/Complete; nahe schwarze Flächen, grüne Live-/Primärrollen, cyanfarbene Nachweise, rosa Grenzen/Fehler und gelbe Arbeit/Warnung. Bestehende NEOTH-Typografie und skalierbare Abstände nutzen. Desktop-`.slint` bleibt gemäß geltender Vorgabe unverändert; dessen Tokens dienen als Referenz. Mobile-Parität nicht mit Desktop-Renderabnahme verwechseln. |
| JM-10 | Vollständige App-/Produkt-/Release-Abnahme des Ports. | Vorhandene `mobile-companion.yml`-Kette erweitern: Flutter-Analyse/Widget-/Controllerfälle, Rust-Protokoll/Bridge, Android-ABIs und iOS-Slices, Originalartefakte und Quellenbindungen, tatsächliche Pair/Chat/Tool/Cancel/Reconnect/Revoke-Reisen, Geräte-UX und signierte Distribution. Keine Gold-Freigabe aus Screenshots, Mocks oder Testzahlen ableiten. |

## Reihenfolge und Parallelisierung

1. Aktuellen V3-Fehler mit klarer Readiness-/Cleanup-Diagnostik eingrenzen,
   eng reparieren und Pair/Status/Chat/Revoke auf dem gebundenen Producer abnehmen.
2. Parallel dazu JM-01 vervollständigen und JM-02 als isolierten Flutter-Kandidaten
   vorbereiten. Bestehende Fehler-, Consent-, Cancel- und Revoke-Zustände bleiben
   unverfälscht. Der Port wird nicht in einen laufenden Test-Producer hineineditiert.
3. Same-enrollment Restart separat aufnehmen; vorhandenen V4-Kandidaten gezielt
   rebasen und prüfen. V4 ist kein Ersatz für einen Tool-/Transcript-Ereignisvertrag.
4. JM-03/JM-04 als vollständigen vertikalen Tool-Pfad umsetzen: echter Producer,
   typisierte Projektion, berechtigter Transport, native Bridge, Dart-Zustand,
   Darstellung und Fehler-/Abbruchnachweis. UI und Producer nach einem vereinbarten
   Vertrag parallel bearbeiten, anschließend gemeinsam integrieren.
5. JM-05/JM-06/JM-07 mit ihren tatsächlichen Session-, Kanal- und Consent-Ownern
   bearbeiten. Vorhandene Transkripte und Tool-Records wiederverwenden. Voice,
   Medien und weitere belegte App-Funktionen unter JM-08 folgen mit eigenen
   End-to-End-Kriterien; sie verschwinden nicht aus dem Gold-Backlog.
6. Jede angenommene Änderung in die bestehende kanonische Source-/Test-Auswahl
   aufnehmen. Root bündelt unabhängige überprüfte Änderungen in einen Producer
   und behält genau einen CI-Dispatch-Strom. Gute bestehende Nachweise behalten
   ihre ursprüngliche Source-Bindung; bei geänderten Quellen werden sie nicht
   fälschlich als aktuelle Produktabnahme übernommen.
7. JM-09/JM-10 mit der gesamten Gold-Abnahme zusammenführen: Full CI, native
   Pakete, echte Gerätewege, vorhandene Plattformgrenzen und Signing-Eingaben.

## Schutz vor Auslassungen und ungeprüften Übernahmen

- Verbindliche Traceability: Anforderung -> konkreter Jarvis-Quellstand ->
  bestehender NEOTH-Owner -> Änderung -> ausführbarer Akzeptanzfall -> Originalbeleg.
- Jeder Port-Status nennt vorbereitet, importiert, hosted geprüft, Gerät geprüft
  oder Release akzeptiert. Eine blockierte Quelle/Plattformabhängigkeit bleibt
  ausdrücklich offen; sie wird weder umbenannt noch als erledigt gezählt.
- Persönliche Endpoints, Accounts, Haushaltszuordnungen, Tokens, Konfigurationen,
  Signierschlüssel, Modelle und Aufnahmen werden nicht mitkopiert. Die erlaubten
  NEOTH-Konfigurations- und Credential-Pfade bleiben zuständig.
- Native Assets/Fonts/Modelle nur bei tatsächlichem Bedarf und mit belegter
  Lizenz/Attribution übernehmen. Die erste Darstellung nutzt vorhandene
  NEOTH-Mittel; Jarvis-HUD-Artwork und WebView-Shell werden nicht pauschal kopiert.
- Lokaler BSOD-Hold bleibt absolut. Compiler, Formatter, Code-/XML-Parser,
  Flutter/Dart/Node/Python, Tests und App-/GUI-/Modell-Runtimes laufen hier nicht.
  Ausführbare Validierung erfolgt in den bestehenden Hosted-Lanes.

## Einbindung in Road to 1.0 Gold

JM-01..JM-10 ergänzen `GOLD-R4-12` / `GOLD-LF-002-12` (Mobile),
`GOLD-R4-07`, `GOLD-LF-P1-16`, `GOLD-LF-001-03`, `GOLD-LF-001-08`
(Kanäle/Voice/Account), `GOLD-LF-003-12..14` (Session/Transcript/Parität) und
`GOLD-LF-002-19`, `GOLD-LF-003-23` (Qualität/Release). Diese Zuordnung schließt
keinen vorhandenen Punkt. Die ursprünglichen Gold-Backlog-Zeilen bleiben erhalten.

## W2488 Umsetzungsstand

JM-02: Passive Terminalkarten und NEOTH-Theme sind veröffentlicht; tatsächliche Flutter-/App-Abnahme bleibt offen. Der schmale Widgetfall wurde auf eine nachgemessene 240-dp-Ansicht und wirksame 2x-Skalierung korrigiert. Frühere statische Annahmen sind kein Rendernachweis.

JM-03/JM-04: Der echte ToolActivity-Producer ist als geprüfter Quell-Slice integriert. Seine Start-/Ergebnis-/Abbruchfakten kommen aus dem realen MCP-Pfad, nicht aus Textinterpretation. Der begrenzte Sink bleibt von Ausführung und Audit unabhängig. Der nachfolgende vertikale Pfad führt vom autorisierten Companion-Request über separat versionierte Activity-Snapshots auf derselben Verbindung zur vorhandenen nativen Operation und deren Dart-Controller. Terminal V3 bleibt getrennte finale Autorität. Dieser Protokoll-/Bridge-/UI-Pfad ist noch in Arbeit; seine Existenz wird nicht aus dem Producer oder dem Layout abgeleitet.

JM-06: Eigene WhatsApp-Vorlage und NEOTH-Kanalzuständigkeit sind zugeordnet. Die erforderliche editierbare, Account-/Chat-/Turn-gebundene Statusoperation bleibt umzusetzen; ein normaler Finalsend ersetzt sie nicht. JM-05/JM-07/JM-08 sowie native Geräte- und signierte Release-Nachweise bleiben ebenfalls offen.

## W2490 vertikaler Quellstand

JM-03/JM-04 sind im Quellstand vom tatsächlichen MCP-Producer über die autorisierte, kompatibel ausgehandelte Activity-Projektion und additive native v2-ABI bis zum Flutter-Controller und zur passiven Anzeige integriert. Der bisherige Terminalvertrag bleibt maßgeblich. Die Anzeige verdichtet Ereignisse je Tool-Ordinal auf den letzten Zustand, zeigt die öffentliche Phase als Text und nennt ungewisse Ausgänge ausdrücklich Outcome unknown. Private Daten werden nicht angezeigt; Schema v1 erlaubt nur Read file, Write file, List files, Search code und Tool call.

Die drei unabhängigen statischen Reviews sind abgeschlossen; neue ausführbare Regressionen betreffen Stream-Fehler/Cleanup, Capability-/Legacy-Verträglichkeit, tatsächliche native Poll-/Cancel-/Free-Pfade, Größenproben-Rennen und Flutter-Stale-/Loss-/Darstellungszustände. Sie sind bis zum Hosted-Lauf Testquellen, keine bestandenen Tests. Der bestehende V1-Interop-Canary beweist keine Live-Toolanzeige; deren vollständige Produktreise sowie native Geräte-/Release-Abnahme bleiben explizit offen. JM-06 WhatsApp-Status und JM-05/JM-07/JM-08 sind durch diesen Slice nicht abgeschlossen.

### W2491 — echte mobile Tool-Aktivität zur Hosted-Abnahme vorbereitet

Der neue Hosted-Durchlauf verwendet einen tatsächlichen, im isolierten NEOTH-Home konfigurierten MCP-Aufruf. Das Tool bleibt gehalten, bis die native v2-Bridge den gestarteten Tool-Schritt über den verschlüsselten Companion-Pfad empfangen hat. Erst dann darf das Tool antworten; Abschluss und Aktivität müssen dieselbe Anfrage betreffen. Tool-Zähler, zwei Provider-Runden, Gerätewiderruf und bestehendes Cleanup werden geprüft. Die vorherige V1-Reise bleibt erhalten. Die kanonische Auswahl umfasst 90 Rust- und 22 Collector-Fälle sowie 50 Quellen; das ist eine registrierte Auswahl, kein bestandener Lauf.

Der zuvor fehlgeschlagene Hosted-Typcheck 37607345253 wird durch zwei eng begrenzte Korrekturen adressiert: Move/Borrow im Activity-Fehlerzweig und das fehlende optionale Sink-Argument eines vorhandenen Tests. Quellen und Testtreiber sind unabhängig statisch geprüft; neue Hosted-, Flutter-/Native-, Geräte- und Release-Abnahme bleiben offen. Nachweis und Grenzen: `docs/verification/gold-wave2491-live-tool-activity.json`. Der getrennte WhatsApp-Status-Transportkandidat ist wegen einer gefundenen Duplikatgrenze bei der Datenaufbewahrung noch nicht übernommen. Keine neue Gold-/JM-Anforderung wird allein durch diese Vorbereitung abgeschlossen.

### W2495 — native Poll-Korrektur und konkret gebundene Vorabnahme

Auf `52aa2a9d43b7b32dc02bb67588aac89da49b804a` ist Lauf `37610072562` unabhängig mit 40 Owner-/Updater- und 42 Companion-Fällen, drei Originalarchiven/98 Einträgen, Produktions-Clippy, Testziel-Typcheck, öffentlicher CLI und bytegleicher Referenz aufgenommen. Der folgende Mobile-Lauf `37613199073` bestand 39 exakt zugeordnete Transport- und 22 Collector-Fälle, stoppte aber beim nativen Bridge-Build mit E0308. Die tatsächliche Pair/Chat/Tool/Revoke-Reise wurde dort nicht gestartet.

Der Poll-Helfer erhält nun eine Referenz auf den bereits gehaltenen Mutex-Guard. Auswahl, Terminalvorrang und die getrennte Größen-/Verbrauchslogik bleiben unverändert. Die Korrektur benötigt neue Hosted-Abnahme; weder die vorherigen 82 Fälle noch Teilbelege des fehlgeschlagenen Mobile-Laufs gelten als aktuelle vollständige Mobile-/Native-/Geräte-/Release-Freigabe. Einzelheiten: `docs/verification/gold-wave2495-bridge-poll-typecheck.json`. Die WhatsApp-Transportprüfung ist statisch abgeschlossen; der Transport und seine echte Lifecycle-Anbindung sind weiterhin isolierte Kandidaten. Keine JM- oder Gold-Anforderung wird allein dadurch geschlossen.

### W2497 — mobiler Chat-Abbruch eingegrenzt, Ursache noch offen

Lauf `37614438523` auf `b29ba382c4e951d934d57fe5a8dba2deaa4b28d4` kompiliert die native Bridge und erreicht reales Pairing sowie Status. Der V1-Chat endet als `indeterminate`; der Zähler für den erwarteten Chat-Completions-Pfad bleibt unverändert. Das beweist keine generelle Netzwerkfreiheit. Die V2-Reise mit gehaltenem Tool wird nicht erreicht. Der WAL wird beim Cleanup geleert; der Serve-Prozess endet dennoch mit Code 1. Vollständige Mobile-Abnahme bleibt offen.

Die optionale Diagnose bewahrt nun ausschließlich feste Fehlerstufen und typisierte Fehlerklassen. Der Hosted-Collector speichert höchstens die erste vollständige erlaubte Meldung; private Fehlertexte, Pfade und Tokens werden nicht übernommen. Öffentliche Fehlerantworten, Timeout-Erkennung und bestehende Autoritäts-/Cleanup-Grenzen bleiben erhalten. Zwei Rust-Testquellen und ein Collector-Testfall erweitern die registrierte Auswahl auf 92 Rust-/23 Collector-Fälle und weiterhin 50 Quellen. Das ist Diagnosevorbereitung, kein Nachweis einer reparierten Chat-Reise. Quellenprüfung und Grenzen: `docs/verification/gold-wave2497-chat-failure-diagnostics.json`.

Nach dem erneuten BSOD bleibt lokale Arbeit seriell auf Text/JSON/Git/GitHub beschränkt, mit Idle-Priorität und Affinität zu einem logischen CPU-Kern. Keine lokalen Builds, Tests, Parser oder Produkt-Runtimes; keine parallelen Subagenten. WhatsApp-, Verlauf-, Geräte- und Release-Abnahmen bleiben offen. Bestehende Backlog-Zeilen bleiben erhalten.

### W2499 — Chat-Engine als Fehlerbereich belegt

Der Originalnachweis von Lauf `37617894011` auf `897fd11f2a67802939789119f2c8837555cebad0` ist per API-/ZIP-SHA256 geprüft. Die 23 Collector-Fälle sowie CLI-/Bridge-Build sind bestanden. Pairing und Status funktionieren; der Chat scheitert im Engine-Pfad mit noch unklassifizierter Ursache. Die neue Diagnose markiert acht konkrete Engine-Grenzen, erhält bestehende Fehlermeldungen und typisierte Ursachen und erkennt Provider-Autorisierung separat. Registriert bleiben 92 Mobile-Rust-/23 Collector-Fälle und 50 Quellen. Keine Chat-Reparatur oder vollständige Mobile-/Native-/Release-Abnahme wird daraus behauptet. Details: `docs/verification/gold-wave2499-chat-engine-boundaries.json`.

Im getrennten WhatsApp-Kandidaten W2498 sind die verpasste erste Tool-Meldung und ein abtrennbarer Publisher adressiert; acht Status-Testquellen und der separate Hosted-Workflow W2496 sind vorbereitet. Diese Kandidaten sind nicht übernommen oder ausgeführt. Lokaler BSOD-Hold und serielle Idle-/Ein-Kern-Begrenzung gelten unverändert; ursprüngliche Backlog-Zeilen bleiben erhalten.

### W2500 — isolierte Kostenfreigabe für den mobilen Hosted-Test

Lauf `37620382915` auf `e4270cb1aaaf8a8305cb95d3cfef9eb1bd6ae97e` belegt den Chat-Abbruch im Provider-Pfad. 23 Collector-Fälle sowie CLI-/Bridge-Build bestehen, Pairing und Status funktionieren; V1-Chat und damit V2-Toolreise bleiben offen. Das Originalarchiv ist gegen den API-SHA256 geprüft. Die ursprüngliche Fehlerklasse wurde durch die bestehende Quarantäne absichtlich entfernt; die optionale Diagnose erfasst sie künftig unmittelbar davor ausschließlich als feste Kategorie.

Die isolierte Testkonfiguration verwendet einen Provider unbekannter Kosten mit Standard-Autonomie und startet ohne interaktive Eingabe. Sie erhält nun genau die ausdrückliche Freigabe für diesen lokalen Modell-Stub. Eine strikte URL-Prüfung begrenzt diese Konfiguration auf numerisches `127.0.0.1` mit gültigem Port und `/v1`. Alle übrigen Aktionen behalten den Standard; Produktionsberechtigungen, Pricing, MCP-Freigaben, Geräteautorisierung und Widerruf werden nicht gelockert. Ein neuer Collector-Test prüft die Einzelregel und zwölf ungültige Routen vor jedem Datei-Write. Registriert sind 92 Mobile-Rust-/24 Collector-Fälle und 50 Quellen; frische Hosted-Abnahme ist erforderlich. Der Quellbefund ist noch kein Nachweis der alleinigen Fehlerursache oder einer reparierten Produktreise. Report: `docs/verification/gold-wave2500-loopback-cost-fixture.json`. Lokaler BSOD-Hold, serielle Idle-/Ein-Kern-Arbeit und offene Geräte-/Release-/JM-Ziele bleiben bestehen.

### W2502 — mobiler Chat belegt, Widerruf mit behaltenem Listener-Owner

Lauf `37622611780` auf `25443bd93f1bae402458d635c9149de271b2c050` bestätigt erstmals die V1-Reise bis zur akzeptierten echten Chat-Antwort: exakt eine Anfrage am isolierten Provider, erwarteter Antworttext, sauberes Serve-Ende mit Exit 0 und geleertem WAL. 24 Collector-Fälle und CLI-/Bridge-Build bestehen. Das gegen API-SHA256 geprüfte Originalarchiv ist `11482947826`. Der Lauf scheitert anschließend beim Gerätewiderruf mit CLI-Exit 1; dessen genaue RPC-Ursache ist noch nicht belegt. V2-Toolreise und vollständige Mobile-Abnahme bleiben offen.

Die statische Untersuchung zeigt zwei konkrete Lifecycle-Fehler: Ein angeforderter Stopp während der erneuten Listener-Bereitschaft wurde als Fehler behandelt; ein abbrechender RPC konnte beim Join einen bereits aus der Map entfernten Listener-Handle verlieren. Der Stopp verlangt weiterhin erfolgreich geprüftes Rendezvous-Cleanup. Der Handle verbleibt nun bis zum tatsächlichen Join-Ergebnis beim Daemon, auch wenn der RPC-Warter wegfällt. Drei neue Rust-Regressionen prüfen Abbruch nach tatsächlich begonnenem Warten, fehlerhafte Terminalzustände und Bereitschaft versus Stopp. Der Hosted-Collector übernimmt für Geräte-RPCs nur vorhandene feste Fehlerklassen. Auswahl: 95 Mobile-Rust-/25 Collector-Fälle/50 Quellen, insgesamt 2829 portable Registrierungen. Dies ist eine Quellkorrektur mit frischer Hosted-Abnahme ausstehend, kein bestätigter Widerruf. Report: `docs/verification/gold-wave2502-companion-revoke-owner.json`.

Der unübernommene WhatsApp-Kandidat W2501 ergänzt eine dauerhafte Sperre gegen Statusmeldungen nach finaler Antwort, exakte Account-/Chat-/Inbound-/Reply-Key-Bindung und unterschiedliche Anzeigen für abgelehnte sowie ungewisse Tools. Sieben zusätzliche Sidecar-Testquellen und insgesamt neun Status-Rust-Testquellen sind vorbereitet, aber nicht ausgeführt. Geräte-, WhatsApp-, Native- und Release-Abnahme bleiben offen; der lokale BSOD-Hold gilt unverändert.

### W2503 — unabhängige Regressionen auch bei fehlgeschlagener Produktreise

Lauf `37625585308` auf `071451dbc87a2b9056e7c99d9a37a131cbc8c461` erreicht den Widerruf nicht: Schon beim ersten Pairing läuft die Bereitschaftsfrist ab. Der feste Nachweis zeigt `readiness_owner_deadline`, angeforderten Stopp und abgeschlossenes Pairing-Teardown; der Daemon endet mit Exit 0 und geleertem WAL. Das Originalarchiv `11483524445` ist gegen den API-SHA256 geprüft. Dieser Lauf bestätigt oder widerlegt den W2502-Widerrufsfix nicht.

Der Workflow führt künftig nach erfolgreicher Quellenzulassung, Transportprüfung, CLI-/Bridge-Build und bestätigter Overlay-Wiederherstellung die unabhängigen No-Cluster-, Core- und Bridge-Regressionen auch dann aus, wenn die echte Produktreise fehlschlägt. Der Produktfehler bleibt ein fehlgeschlagener Job; keine Aussage, Frist, Testauswahl oder Cache-Abnahme wird gelockert. Dadurch gehen bei einem frühen Bereitschaftsfehler nicht erneut alle übrigen Testnachweise verloren. Kein zusätzlicher paralleler Job oder Dispatch; kein gemessener Laufzeitgewinn behauptet. Auswahl bleibt 95 Rust-/25 Collector-Fälle/50 Quellen. Neue vollständige Hosted-Abnahme ist ausstehend. Details: `docs/verification/gold-wave2503-mobile-failure-coverage.json`.

### W2507/W2508 — echte mobile Toolreise abgenommen, Flutter-Abnahme läuft weiter

Lauf 37641280086 auf c4a04fb5b57d3ec05f2c6ee5e0a5bc611009fd29 ist einschließlich Originalarchiv und 50 Quellbindungen unabhängig geprüft: 99 Rust-Fälle, 25 Collector-Fälle, V1-Chat und tatsächlich beobachtete V2-Toolaktivität vor Freigabe des gehaltenen MCP-Tools. Derselbe Request erreicht den Terminalzustand, das Tool wird genau einmal ausgeführt; beide Widerrufe und sauberes Herunterfahren mit geleertem WAL bestehen. Dies belegt den Hosted-Pfad von JM-03/JM-04, noch keine native Geräteanzeige oder vollständige Gold-Abnahme.

Der anschließende Android-/iOS-Workflow 37642719422 stoppt bereits bei Flutter-Analyse: In main.dart wurde die boolesche Pending-Bedingung falsch mit dem nullable Pattern kombiniert. W2508 trennt diese Bedingungen, ohne Anzeige- oder Berechtigungsregeln zu ändern. Flutter-Widget-/Controllerprüfung und native Builds bleiben frisch nachzuweisen; die mobilen Runtime-Nachweise behalten ihren ursprünglichen Producer und dürfen nur bei bewiesener Quellgleichheit übernommen werden.

JM-06: Zwölf geprüfte WhatsApp-Kandidatdateien mit dauerhafter Sperre gegen verspätete Statusupdates nach der Endantwort, zehn Rust-Statusregressionen und acht neuen Sidecar-Fällen sind vorbereitet. Die kombinierte Hosted-Validierung ist ein neuer Workflow-Kandidat. Noch kein Import, keine Ausführung und keine echte WhatsApp-Zustellung. JM-05/JM-07/JM-08 sowie Native-/Geräte-/Release-Ziele bleiben offen.

### W2510 — Mobile-Hosted-Abnahme und WhatsApp-Übernahme

Mobile-Lauf 37646594648 auf 848fe3adf7db266368e7478b20a91265f579353c ist unabhängig aufgenommen: 35 Flutter-Fälle und Analyse, drei Android-ABIs, iOS-XCFramework, tatsächliche Flutter-Builds, zehn definierte FFI-Exporte, Kotlin-Prüfung samt hochgeladenen bytegleichen Kotlin-Quellen sowie vier Originalarchive/155 Einträge und 57 Quellbindungen. Die zuvor auf c4a04fb5b57d3ec05f2c6ee5e0a5bc611009fd29 aufgenommene V1/V2-Produktreise ist für 848 durch unveränderte Runtime-Quellen gebunden. Das ist Hosted-Abnahme dieser Producer, keine Geräte- oder signierte Release-Freigabe.

JM-06 WhatsApp übernimmt den geprüften Status-/Owner-/Abschluss-Slice und eine gezielte Hosted-Prüfung. Zehn Rust- und acht Node-Regressionsquellen sind neu registriert; ihre Ausführung ist noch offen. Die echte MCP-bis-Sidecar-Reise und verknüpfte WhatsApp-Zustellung bleiben separate Nachweise. JM-05 Verlauf/Streaming, JM-07 Vorschauen und JM-08 Voice werden dadurch nicht geschlossen. Der ursprüngliche Backlog bleibt erhalten.

W2510 Prüfabschluss: Die integrierte WhatsApp-Brücke besteht auf b625b606 im Hosted-Lauf 37651077395 sämtliche 37 Node- und 19 Rust-Adapterfälle. Die tatsächliche Kanal-Owner-/HTTP-Anbindung und ihre Freigabe-, Status-, Abschluss- und Abbruchfälle sind damit aufgenommen; Originalartefakt und 24 Quellen sind hashgebunden. Der Nachweis bleibt auf kontrollierte Gegenstellen begrenzt. JM-06 ist bis zur vollständigen MCP-bis-Sidecar-Reise und Konto-/Geräteabnahme weiterhin offen.
