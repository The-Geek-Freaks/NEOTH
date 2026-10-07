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
