# NEOTH Reevaluation Gesamt 2026-05-22 R6

Stand: 2026-05-22, erneute Bewertung nach weiterer aktiver Arbeit.

Basis:
- HEAD: `0b9baa3` (`feat(providers): QM-10 Phase 1 - circuit-breaker primitive`)
- Live-Tree: HEAD plus in-progress QM-9 Usage-Log-Arbeit:
  - `SRC/neothd/src/cli/mod.rs`
  - `SRC/neothd/src/daemon/mod.rs`
  - `SRC/neothd/src/cli/usage.rs`
  - `SRC/neothd/src/daemon/usage_log.rs`
- Kein Commit/Stage durch diese Evaluation.

## Urteil

R6 HEAD ist deutlich besser als R5 Live.

Der vorherige harte Build-Blocker ist weg: `neothd` kompiliert, Clippy ist
gruen, und der committed HEAD steht bei 88%. Der aktuelle Live-Tree ist aber
wieder in Arbeit: die neue QM-9 Usage-Log-Schicht kompiliert und besteht
Clippy, laesst aber die `neothd`-Tests rot werden. Live faellt deshalb auf
80%.

Trotzdem ist das Projekt noch nicht "strict green", weil eine Product-Truth-
Luecke bleibt: WhatsApp wird als `LIVE` mit "send + receive both real"
ausgegeben, aber der Webhook-Listener droppt Pipeline-Outbound weiterhin.
Empfang ist real, Antwortversand aus dem Inbound-WebHook-Pfad ist noch nicht
belegt.

## Prozentuale Bewertung der Achsen

| Achse | R5 HEAD | R5 Live | R6 HEAD | R6 Live |
|---|---:|---:|---:|---:|
| Security / Safety | 88% | 82% | 89% | 88% |
| Reliability | 86% | 62% | 89% | 72% |
| Code Quality / Maintainability | 86% | 64% | 89% | 82% |
| Test / Evidence | 91% | 76% | 94% | 68% |
| UX / GUI / Operator Guidance | 79% | 79% | 82% | 83% |
| DAU-Nutzbarkeit | 78% | 75% | 81% | 78% |
| Pro-Operator / Automation | 93% | 87% | 95% | 94% |
| Product Truth / Claim Accuracy | 85% | 64% | 83% | 76% |
| Gesamt | 86% | 73% | 88% | 80% |
| Strict Release Gate | 86% | 0% blocked | 85% blocked | 0% blocked |

Interpretation:
- R6 HEAD ist stabiler als R5 HEAD, weil Slack/WhatsApp inbound bootstrap,
  OnSessionStart hooks, Doctor Node/tmux probes und der Circuit Breaker
  inzwischen committed sind.
- R6 Live ist nicht mehr identisch zu HEAD: QM-9 Usage ist gerade halb
  integriert und hat einen roten Unit-Test.
- Product Truth faellt gegenueber der technischen Basis ab, weil WhatsApp
  weiterhin mehr behauptet als der aktuelle Runtime-Pfad beweist und die
  Usage-Log-Moduldoku "Every provider call" behauptet, obwohl Provider-Calls
  noch nicht in `record_now`/`append` verdrahtet sind.

## Was sich seit R5 verbessert hat

### 1. Build-Gesundheit wiederhergestellt

Der R5-Live-Blocker `whatsapp_app_secret` in `Credentials::is_empty` ist in
HEAD nicht mehr offen. `cargo check`, `clippy -D warnings` und Tests laufen
durch.

Bewertung: P0 erledigt.

### 2. Slack inbound ist jetzt plausibel live

`serve` spawned Slack Socket Mode bei `slack_bot_token + slack_app_token +
provider`. Die Slack-Dispatch-Tests decken Reply-Posting im Handler ab.

Bewertung: grosser R4/R5-Fortschritt. Was noch fehlt, ist ein lokaler Fake-
Socket-Mode-E2E-Test, der Boot -> Frame -> Handler -> Reply schliesst.

### 3. WhatsApp inbound bootstrap ist da

`serve` baut `WebhookListenerConfig` mit Meta Verify Token, App Secret und
Pipeline Handler und spawned den Listener auf `127.0.0.1:<port>`.

Bewertung: inbound ist nicht mehr nur Papier. Aber der Antwortpfad ist noch
nicht ehrlich geschlossen.

### 4. OnSessionStart hooks sind in `serve`

Nach Subsystem-Bootstrap wird `HookStage::OnSessionStart` ausgefuehrt und
`HOOK_FIRED` in den WAL geschrieben. Block-Result wird geloggt und ignoriert.

Bewertung: gut fuer Pro-Operator/Automation. Semantik "Block wird ignoriert"
ist akzeptabel, solange es bewusst so bleibt und im Operator-Modell klar ist.

### 5. Doctor ist fuer Noob-UX realistischer

Node/npm und tmux werden in `run_all_checks` sichtbar. Das reduziert die
klassische "Claude CLI ist kaputt, aber eigentlich fehlt Toolchain"-Falle.

Bewertung: UX/DAU klar besser.

### 6. Circuit Breaker Primitive ist sauber gelandet

HEAD enthaelt ein neues Provider-Circuit-Breaker-Modul:

- `BreakerConfig`
- `BreakerState`
- `BreakerError`
- `CircuitBreaker`
- `Permit`
- `BreakerRegistry`
- 12 fokussierte Unit Tests

Die State Machine ist verstaendlich und testbar: Closed -> Open ->
HalfOpen -> Closed/Open. `HalfOpen` erlaubt nur einen Probe-Call. Drop ohne
Settlement zaehlt konservativ als Failure.

Bewertung: gute Phase-1-Basis. Noch kein Runtime-Gewinn, solange Provider-
Calls nicht durch `try_acquire()` / `record_*()` laufen.

### 7. QM-9 Usage Log ist als Live-Delta sichtbar, aber noch nicht releasefaehig

Der Live-Tree enthaelt jetzt `daemon::usage_log` plus `cli::usage`.
Die Richtung ist sinnvoll: JSONL pro Tag, Aggregation, CLI-Ausgabe als
Tabelle/JSON. Check und Clippy sind gruen.

Aber:
- `neothd` Tests schlagen in `format_date_utc_matches_known_epochs` fehl.
- `usage_log.rs` behauptet "Every provider call appends", aber es gibt im
  aktuellen Source-Tree keinen Provider-Call-Wire-in auf `record_now` oder
  `append`.

Bewertung: gute QM-9-Basis, aktuell P0 wegen rotem Test und P1 wegen
ueberzogener Product-Truth.

## Findings

### P0: Live-Tree hat roten `neothd` Unit-Test

Code-Evidenz:
- `SRC/neothd/src/daemon/usage_log.rs:249`
- Test: `daemon::usage_log::tests::format_date_utc_matches_known_epochs`
- Erwartet: `2026-05-22`
- Tatsaechlich: `2026-05-23`

Ursache:
- `1_779_494_400` ist `2026-05-23 00:00:00 UTC`, nicht `2026-05-22`.
- Korrekt fuer `2026-05-22 00:00:00 UTC` ist `1_779_408_000`.

Done-Kriterium:
- Timestamp-Konstante korrigieren oder Kommentar/Expectation auf
  `2026-05-23` aendern.
- Danach `.\scripts\cargo-msvc.ps1 test '-p' neothd --offline` wieder gruen.

### P0: WhatsApp `LIVE` ist weiterhin zu stark formuliert

Code-Evidenz:
- `SRC/neothd/src/cli/doctor.rs:1500` beschreibt live channel wiring mit
  "send + receive both real".
- `SRC/neothd/src/cli/doctor.rs:1978` testet `whatsapp: LIVE`.
- `SRC/neothd/src/cli/serve.rs:608` baut zwar `WebhookListenerConfig`.
- `SRC/neothd/src/channels/webhook_listener.rs:395` loggt aber weiterhin:
  `pipeline produced outbound (drop here; adapter owns send)`.

Das ist der zentrale Truth-Abzug. Es gibt einen WhatsApp Graph API Send-
Helper, aber der Inbound-WebHook-Pfad haelt keinen WhatsApp-Sender und
verwirft die Pipeline-Antwort.

Fix-Optionen:
1. Ehrlich umbenennen: `WEBHOOK-LIVE` / `INBOUND-LIVE`, Detail "receive real,
   reply send not wired in listener path".
2. Oder richtig schliessen: Listener/Handler erhaelt WhatsApp-Sender und
   versendet `OutboundMessage` ueber Graph API.

Done-Kriterium:
- Fake Meta POST -> Pipeline returns outbound -> fake WhatsApp send endpoint
  bekommt Reply.
- Danach darf Doctor "send + receive both real" sagen.

### P1: Circuit Breaker ist nur Primitive, noch kein Provider-Schutz

Code-Evidenz:
- `SRC/neothd/src/providers/circuit_breaker.rs:169` hat `try_acquire`.
- `SRC/neothd/src/providers/circuit_breaker.rs:310` hat `BreakerRegistry`.
- `SRC/neothd/src/providers/mod.rs:18` exportiert das Modul.

Es gibt aber noch kein Wire-in um `Provider::complete` / `Provider::stream`.
Damit verbessert es Codebasis und Testbarkeit, aber noch nicht reale
Provider-Reliability.

Done-Kriterium:
- Provider-Aufrufe gehen durch Breaker-Gate.
- Provider-Errors zaehlen als Failure.
- Success resetet Failure-Zaehler.
- Open Breaker liefert klare Operator-Fehlermeldung oder Failover.
- Test: Provider mock fails N-mal -> breaker opens -> call rejected ->
  cooldown -> half-open probe -> close/open.

### P1: Slack/WhatsApp brauchen lokale Boot-E2E-Gates

Die Unit-Tests sind gut, aber der entscheidende Release-Beweis ist Boot-
Integration:

- Slack: `serve` mit Fake Socket Mode -> Message Frame -> Handler -> fake
  postMessage.
- WhatsApp: `serve`/listener mit Fake Meta POST -> signature verify -> decode
  -> handler -> reply send or explicit no-reply truth.

Ohne diese Tests bleibt "LIVE" stark, aber nicht maximal belastbar.

### P1: Usage Log ist nicht an Provider-Aufrufe verdrahtet

Code-Evidenz:
- `SRC/neothd/src/daemon/usage_log.rs:3` behauptet, jeder Provider-Call
  appende ein `UsageEvent`.
- Im aktuellen Source-Tree findet sich kein Callsite-Wire-in von Provider-
  Completion/Stream auf `record_now` oder `append`.

Damit ist `neoth usage` als Viewer/Aggregator gut, aber die Datenquelle ist
noch nicht produktiv befuellt.

Done-Kriterium:
- `Provider::complete`/`stream` Callsites oder ein gemeinsamer Wrapper
  schreiben Success und Error in `usage_log`.
- Test: Mock-Provider call -> JSONL-Zeile entsteht; Error-Provider call ->
  `ok=false` Zeile entsteht.

### P2: OnSessionStart Block-Semantik dokumentieren

`OnSessionStart` kann `Block` liefern, wird aber nach Boot ignoriert. Das ist
pragmatisch, aber Operatoren duerfen daraus nicht "Boot wurde verhindert"
ableiten.

Done-Kriterium:
- Doctor/help/docs sagen knapp: OnSessionStart Block wird geloggt, stoppt den
  Daemon nicht.

## Verification

Durchgefuehrt in R6:

```text
.\scripts\cargo-msvc.ps1 check '-p' neothd --offline
Result: PASS

.\scripts\cargo-msvc.ps1 clippy '-p' neothd --offline -- -D warnings
Result: PASS

.\scripts\cargo-msvc.ps1 test '-p' neothd --offline
Result: FAIL
- unit: 2898 passed, 1 failed, 2 ignored
- failed: daemon::usage_log::tests::format_date_utc_matches_known_epochs
- root cause: timestamp `1_779_494_400` maps to 2026-05-23, not 2026-05-22

.\scripts\cargo-msvc.ps1 test '-p' neothd-gui --offline
Result: PASS
- 17 passed, 0 failed
```

## Schlussbewertung

R6 HEAD ist nicht "fast da, aber kaputt" mehr. HEAD ist technisch wieder
stabiler. Der aktuelle Live-Tree ist aber wieder ein aktiver Arbeitsstand:
Usage-Log ist sinnvoll, aber Tests sind rot und Provider-Wire-in fehlt.

Aktuelle strenge Gesamtwertung:

- HEAD: 88%
- Live-Tree: 80%
- Release-Gate: blocked, bis der Usage-Test wieder gruen ist und WhatsApp-
  Truth und/oder Reply-Sendpfad sauber geloest ist.

## Naechste Reihenfolge

1. Usage-Test fixen: `1_779_408_000` fuer 2026-05-22 oder Erwartung auf
   2026-05-23 aendern.
2. WhatsApp-Truth fixen: Status ehrlich machen oder Reply-Sendpfad wirklich
   verdrahten.
3. Usage-Log in Provider-Aufrufe wire-innen oder die Doku auf "append helper"
   statt "every provider call" zuruecknehmen.
4. Circuit Breaker in Provider-Aufrufe wire-innen, nicht nur exportieren.
5. Slack und WhatsApp Boot-E2E mit lokalen Fakes absichern.
6. Danach nochmal Score: realistisch 90-91%, wenn die Gates gruen bleiben.
