# NEOTH Reevaluation Gesamt 2026-05-22 R7

Stand: 2026-05-22, erneute Bewertung nach weiterer aktiver Arbeit.

Basis:
- HEAD: `4ddf1b6` (`feat(doctor): channel-flapping detection over last 24h of usage_log`)
- Live-Tree: kein dirty tracked Code; nur untracked Plan-/Review-Dokumente.
- Kein Commit/Stage durch diese Evaluation.

## Urteil

R7 ist funktional deutlich weiter als R6: Usage-Logging ist nicht mehr nur
Viewer/Aggregator, sondern in Chat, Streaming, Council-Debate und MCP-loop
sichtbar verdrahtet. Circuit-Breaker-State wird persistiert. Die GUI hat
Usage-Refresh, Preset-Tile und einen Apply-active-Handler.

Aber: R7 ist kein Release-Green. Der harte Gate-Blocker ist nicht mehr ein
kaputter Unit-Test, sondern `clippy -D warnings`. `neothd` Tests laufen
durch, GUI Tests laufen durch, aber der Lint-Gate ist rot.

## Prozentuale Bewertung der Achsen

| Achse | R6 HEAD | R6 Live | R7 HEAD | R7 Live |
|---|---:|---:|---:|---:|
| Security / Safety | 89% | 88% | 90% | 90% |
| Reliability | 89% | 72% | 88% | 88% |
| Code Quality / Maintainability | 89% | 82% | 84% | 84% |
| Test / Evidence | 94% | 68% | 93% | 93% |
| UX / GUI / Operator Guidance | 82% | 83% | 86% | 87% |
| DAU-Nutzbarkeit | 81% | 78% | 84% | 85% |
| Pro-Operator / Automation | 95% | 94% | 96% | 96% |
| Product Truth / Claim Accuracy | 83% | 76% | 81% | 80% |
| Gesamt | 88% | 80% | 87% | 87% |
| Strict Release Gate | 85% blocked | 0% blocked | 0% blocked | 0% blocked |

Interpretation:
- R7 hat mehr echte Produktfunktion als R6.
- R7 verliert trotzdem Release-Score, weil `clippy -D warnings` rot ist.
- R7 verbessert Operator-Diagnostik durch `channel flapping`, bleibt aber
  wegen Clippy blocked.

## Was seit R6 besser ist

### 1. Usage-Log ist jetzt in echten Provider-Pfaden

HEAD zeigt `record_now` in:

- normalem Chat-Providerpfad
- Streaming-Chatpfad
- Council-Debate / HemisphereProvider
- MCP dispatch loop

Damit ist die R6-P1-Luecke "Viewer ohne Datenquelle" weitgehend geschlossen.

Restluecke: nicht jeder moegliche Provider-Call im ganzen System ist bewiesen,
aber die zentralen Operator-Pfade sind jetzt abgedeckt.

### 2. Circuit Breaker ist nicht mehr nur volatile State Machine

Der Breaker hat:

- globale Registry
- `acquire_for(provider_id)`
- persisted snapshot/restore in `serve`
- Doctor-Visibility
- Hot-path Wire-in in Chat, Council und MCP

Das ist ein echter Reliability-Sprung. Noch offen: harte Failover-Policy
zwischen Providern statt nur Reject/Record.

### 3. GUI Dashboard ist operativer geworden

Die GUI hat jetzt:

- Usage-Tile mit 60s Auto-Refresh
- Saved-Presets-Tile
- Apply-active Button mit Rust-Handler
- 29 GUI Tests statt 17 in R6

Das schiebt UX/DAU merklich hoch. Die GUI ist nicht mehr nur Wizard + Chat,
sondern wird langsam ein Operator-Dashboard.

### 4. Channel-Flapping Doctor-Check

`SRC/neothd/src/cli/doctor.rs` fuegt einen neuen Check hinzu:

- liest 24h Usage-Log
- warnt ab >=5 Samples und >=20% Error-Rate
- integriert CheckDoc/Explain
- erhoeht `run_all_checks` auf 24 Checks
- Tests laufen inzwischen durch

Das ist konzeptionell gut. Die Heuristik ist aber noch unscharf, weil
`usage_log` aktuell Provider-Labels, aber keine Channel-Labels speichert.
Der Check nennt "channel flapping", misst aber faktisch Provider-Error-Rate.

## Findings

### P0: `clippy -D warnings` ist rot

Aktuelle Fehler:

- `SRC/neothd/src/cli/chat.rs:1914`
  - `let result = match raw { ... }; result`
  - Clippy `let_and_return`; trivial zu fixen.

- `SRC/neothd/src/cli/doctor.rs:738`
  - `if any_open { Warn } else if any_half_open { Warn } else { Pass }`
  - Clippy `if_same_then_else`; zusammenziehen zu `if any_open || any_half_open`.

- `SRC/neothd/src/cli/doctor.rs:798`
  - `cap exceeded` und `>=80% cap` liefern beide `Warn`.
  - Clippy `if_same_then_else`; zusammenziehen zu einem bool.

- `SRC/neothd/src/daemon/dreaming.rs:198`
  - `sort_by` kann `sort_by_key(Reverse(...))` sein.

Done-Kriterium:
- `.\scripts\cargo-msvc.ps1 clippy '-p' neothd --offline -- -D warnings`
  muss wieder gruen sein.

### P0: WhatsApp `LIVE` ist weiterhin zu stark

Weiterhin unveraendert:

- Doctor beschreibt WhatsApp als `LIVE` mit "send + receive both real".
- `WebhookListenerConfig` wird gebaut.
- `webhook_listener.rs` droppt aber Pipeline-Outbound weiterhin:
  `pipeline produced outbound (drop here; adapter owns send)`.

Das bleibt der zentrale Product-Truth-Abzug.

Done-Kriterium:
- Entweder Status ehrlicher machen: `INBOUND-LIVE` / `WEBHOOK-LIVE`.
- Oder echten Reply-Sendpfad bauen: Meta POST -> Pipeline outbound -> WhatsApp
  Graph API send.

### P1: Channel-Flapping misst Provider-Rate, nicht Channel-Rate

Der neue Live-Check ist nuetzlich, aber sein Name ist zu spezifisch fuer die
Datenbasis. `usage_log` hat `provider`, aber keine `channel`/`route`/`egress`
Dimension. Damit kann der Check OpenAI/Gemini/Claude-Fehler erkennen, aber
nicht sauber Slack-vs-WhatsApp-vs-Chat unterscheiden.

Fix-Optionen:
- kurzfristig: Check umbenennen zu `provider flapping` oder Detailtext
  ehrlicher machen.
- richtig: `UsageEvent` um `channel`/`surface`/`route` erweitern und
  Channel-Flapping darauf auswerten.

### P1: Usage-Logging kann doppelt oder uneinheitlich werden

Die neuen Instrumentierungen sind verteilt:

- Chat sync
- Chat stream
- Council hemisphere
- MCP loop

Das ist pragmatisch, aber mittelfristig dupliziert es Record-Logik:
`cost`, `elapsed_ms`, `ok`, `unknown` model fallback, permit settlement.

Fix:
- gemeinsamer helper/wrapper fuer "provider call with breaker + usage".
- Tests fuer success/error auf jedem Surface.

### P2: GUI Apply-active braucht E2E, nicht nur shaping tests

GUI Tests pruefen Summary/Parser gut. Es fehlt noch ein Test, der den Apply-
Flow mit Fake-`neothd` validiert:

- fake `preset list` liefert `* active`
- click/handler ruft `preset apply active`
- status-line aktualisiert
- preset summary refresh passiert

Aktuell ist die Codebasis plausibel, aber der Button ist nicht E2E-gepinnt.

## Verification

Durchgefuehrt in R7:

```text
.\scripts\cargo-msvc.ps1 check '-p' neothd --offline
Result: PASS

.\scripts\cargo-msvc.ps1 clippy '-p' neothd --offline -- -D warnings
Result: FAIL
- cli/chat.rs:1914 let_and_return
- cli/doctor.rs:738 if_same_then_else
- cli/doctor.rs:798 if_same_then_else
- daemon/dreaming.rs:198 unnecessary_sort_by

.\scripts\cargo-msvc.ps1 test '-p' neothd --offline
Result: PASS
- unit: 2986 passed, 0 failed, 2 ignored
- integration: 7 passed, 0 failed
- no-network: 1 passed, 0 failed

.\scripts\cargo-msvc.ps1 test '-p' neothd-gui --offline
Result: PASS
- 29 passed, 0 failed
```

## Schlussbewertung

R7 ist produktiv reifer als R6, aber release-technisch gerade schlechter als
ein sauberer HEAD, weil Lint rot ist. Die Richtung ist richtig: Usage,
Breaker, Presets und Doctor werden echter. Der aktuelle Arbeitsbaum muss aber
erst wieder strict-clean werden.

Aktuelle strenge Gesamtwertung:

- HEAD: 87%
- Live-Tree: 87%
- Release-Gate: 0% / blocked wegen `clippy -D warnings`

## Naechste Reihenfolge

1. Clippy-P0s fixen: `let_and_return`, beide Doctor-`if_same_then_else`,
   `dreaming::sort_by_key`.
2. WhatsApp-Truth fixen: Status ehrlich machen oder echten Reply-Sendpfad.
3. Channel-Flapping entweder ehrlicher als Provider-Flapping benennen oder
   `UsageEvent` um Channel/Surface erweitern.
4. Gemeinsamen Provider-call wrapper fuer breaker + usage bauen.
5. GUI Apply-active E2E mit Fake-`neothd` pinnen.
