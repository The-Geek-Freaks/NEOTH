# W2555 — Vergleich zweier vorhandener Workflow-Replays

Dieser Vergleich ist der erste umgesetzte R01-Baustein. Er bewertet zwei
behaltene Berichte des vorhandenen NEOTH-Replay-Befehls mit demselben Corpus,
Provider, expliziten Modell und konfigurierten Request-Limit. Verglichen werden
zwei Textversionen desselben ausdruecklich ausgewaehlten Skills.

Der Comparator startet weder Modell noch Provider, Tool, Training, Scheduler
oder Self-Improve-Accept. Der bestehende Release-Witness-Pruefer bleibt
unveraendert und verlangt weiterhin ausschliesslich bestandene Episoden.

## Ausfuehrung auf einem zugelassenen Remote-Runner

Die folgenden Schritte sind ein Bedienvertrag. Unter dem lokalen BSOD-Hold
werden diese Python-/Replay-Befehle auf der Workstation nicht ausgefuehrt.

1. Oeffentlichen oder synthetischen Corpus kuratieren. Jede Episode bekommt
   eine stabile ID und explizit denselben Skillnamen. Private Chats, WAL,
   Gedaechtnis, Nutzungslogs und Aufnahmen sind keine automatisch zugelassenen
   Trainings- oder Vergleichsdaten.
2. Vor Versuchen das Protokoll und seinen SHA-256 separat festhalten. Ganze
   Aufgabenfamilien fuer Held-out-Daten zurueckhalten; Kandidat vor deren
   Nutzung einfrieren. Ein vom Tool verglichener Hash beweist allein keine
   historische Vorregistrierung.
3. Baseline und Kandidat mit dem vorhandenen Workflow-Replay-Owner erzeugen.
   Model, Provider, Konfiguration, Request-Cap und Corpus muessen gleich
   bleiben. Vorhandene Kostenfreigabe bleibt der alleinige Ausfuehrungs-Owner.
4. Auf demselben freigegebenen Runner lokal behaltene Daten vergleichen:

~~~text
python3 packaging/workflow_compare_gate.py \
  --protocol protocol.json --expected-protocol-sha256 <retained-sha256> \
  --expected-source-revision <exact-producer> \
  --corpus corpus.json --baseline baseline-report.json \
  --candidate candidate-report.json --out comparison-witness.json
~~~

Die Outputdatei muss neu sein. Private Berichte/Corpus werden nicht vom
Comparator hochgeladen. Hosted Preflight fuehrt ausschliesslich synthetische
Vertragstests aus, keine bezahlten Modellversuche.

## Protokollvertrag v1

Exakt folgende Felder sind erforderlich; unerwartete Felder werden abgewiesen:

- schema_version: ganzzahlig 1.
- kind: workflow-replay-comparison-protocol-v1.
- source_revision: exakte Git-Revision, gleich dem separaten CLI-Argument.
- corpus_sha256: Hash der unveraenderten Corpusdatei.
- episode_ids: 1..64 eindeutige IDs, exakt in Corpus- und Reportreihenfolge.
- hard_case_ids: nichtleere vorab bestimmte Teilmenge der Episode-IDs.
- scorer: contains-v1, genau wie im vorhandenen Reporter.
- config: unveraenderte Replay-Projektion mit provider, model,
  max_per_request, fingerprint_sha256, effective_public_config_sha256.
  provider_default gilt nicht als fest ausgewaehltes Modell.
- baseline und candidate: jeweils id, skill_id, skill_content_sha256.
  Varianten-ID und Content-Hash unterscheiden sich; Skill-ID bleibt gleich.

Jede Episode muss auch tatsaechlich den deklarierten Provider und das Modell
ausweisen. Ein frueher Fehler kann laut Rust-Reporter ohne Skillbeobachtung
auftreten: er bleibt als Fehler im Nenner, mit unbekannter Variantenbeobachtung.
Ein halbes Hash-/Skillpaar, beobachteter fremder Skill oder fehlender Antwort-Hash
bei pass/fail sind keine zulaessigen Vergleichsdaten.

## Ergebnis und Grenzen

Der Witness enthaelt nur Quell-/Input-Hashes, Summen und nullbasierte
Episode-Indizes fuer Regressionen und Hard-Case-Fehler. Keine Prompts, Antworten,
Fehlergruende oder Episode-Namen werden ausgegeben. Alle Fail/Error-Episoden
bleiben erhalten; fehlende Episoden oder eine falsche globale Pass-Aussage
werden abgewiesen.

cost_status, token_usage_status und provider_attempt_count_status bleiben
unknown: Replay v1 misst diese Groessen nicht. Das gemeinsame max_per_request
beweist nur dasselbe konfigurierte NEOTH-Limit. Es beweist weder gleiche Kosten
noch gleiche Sampling-Parameter oder genau einen Provider-Aufruf ohne
providerinterne Wiederholung.

contains-v1 prueft eine erwartete Zeichenfolge. Es beweist keine allgemeine
Antwortqualitaet, gelernte Faehigkeit, sichere Toolausfuehrung, Council-Qualitaet
oder Verbesserung unter anderen Aufgaben. Darum bleibt jedes Ergebnis
measurement_only und automatic_promotion=false, auch bei hoeherem Score.
Berichte sind vom Operator bereitgestellte Belege; dieser Validator ersetzt
keine unabhaengige Herkunfts-/Laufabnahme.

Ein sinnvoller spaeterer Pilot kann acht zurueckgehaltene Faelle mit je drei
Wiederholungen pro Variante verwenden. Das sind 48 geplante Episoden, keine
Garantie von 48 Provider-Aufrufen. Modell, Remote-Ressource und Kostenlimit
muessen vor dem tatsaechlichen Lauf festgelegt werden. SFT/LoRA ist ein
getrennter weiterer Versuch mit lizenziertem Modell, unabhaengiger Auswertung,
klaren Datenrechten und Rueckweg. Kein MASS-Code wurde kopiert.

## Validierung

Dreizehn neue synthetische CLI-Vertragstests pruefen den wirklichen Comparator,
Fehlererhalt, Drift, Variantenbindung, Nullbeobachtungen, Early Errors,
Protocol-Hash, Begrenzung und verweigertes Ueberschreiben. Sie sind in die
bestehende einzelne Preflight-Kette aufgenommen. Lokale Runtime-Ausfuehrung
unter dem BSOD-Hold: keine. Hosted-Abnahme wird separat dokumentiert.

Fehlende Variantenbeobachtung setzt comparison_complete=false und inconclusive=true. Die rohe Pass-Differenz bleibt sichtbar, ist dann aber kein vollstaendiger Variantenvergleich. reported_containment_matches_contract bezeichnet nur die passenden Reportangaben. Historische Vorregistrierung und Reportauthentizitaet werden nicht unabhaengig verifiziert. Ein weiterer Test startet den CLI-Pruefer in einem frischen Hosted-Pythonprozess.
