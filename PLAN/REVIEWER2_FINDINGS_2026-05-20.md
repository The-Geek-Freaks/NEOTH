# Reviewer 2 Audit (Code-Qualität/Architektur/Bugs)

## P0 — Falsche Re-Klassifizierung autorisierter Redactions möglich
- **Datei/Zeile:** `SRC/neothd/src/cli/verify.rs` (`window_overlaps_authorised`, Segmentvergleich über `Path::display().to_string()`).
- **Problem:** Der Match zwischen verifiziertem Segment und `REDACTION_MARKER`-Payload hängt an einer String-Repräsentation von Pfaden. Absolute vs. relative Pfade, Symlinks oder OS-spezifische Darstellung können dazu führen, dass ein tatsächlich autorisierter Rewrite nicht erkannt wird.
- **Risiko:** False Negative im Audit (unerwartete FAILs trotz autorisierter Redaction) oder inkonsistentes Verhalten zwischen Umgebungen.
- **ToDo:** Segment-ID kanonisieren (z. B. `canonicalize` + robustes fallback), oder stabile Segment-Identität in Marker schreiben (z. B. Segment-Seq + inode/UUID).

## P1 — Hohe Komplexität / Verantwortungsmischung in `run_verify`
- **Datei/Zeile:** `SRC/neothd/src/cli/verify.rs` (`run_verify`).
- **Problem:** `run_verify` kapselt Key-Handling, Segment-Auswahl, Marker-Extraktion, Authorisation-Extraktion, Verifikation, Re-Klassifizierung und Rendering in einem Block.
- **Risiko:** Schwer testbar, größere Change-Surface bei kleinen Anforderungen, höhere Regressionswahrscheinlichkeit.
- **ToDo:** Zerlegen in pure Funktionen (`collect_segments`, `collect_authorisations`, `verify_segment`, `render_output`) und gezielt Unit-Tests je Schritt.

## P1 — Querystring-Parser für Meta-Handshake ist fragil bei Sonderfällen
- **Datei/Zeile:** `SRC/neothd/src/channels/webhook_verify.rs` (`meta_challenge_response`, `url_decode`).
- **Problem:** Handgerolltes Parsing via `split('&')` und `split_once('=')` + permissive Fehlerbehandlung bei `%`-Escapes.
- **Risiko:** Edge Cases (mehrfache Keys, unerwartete Encodings, malformed Inputs) sind schwer vollständig abzudecken; Sicherheitslogik lebt auf Parser-Annahmen.
- **ToDo:** Auf etablierte URL-Parsing-Utilities (`url::form_urlencoded`) umstellen, Fehlermodi explizit machen, zusätzliche Negativtests.

## P2 — Smoke/Integration-Abdeckung ist teils dokumentiert statt executable
- **Datei/Zeile:** `SRC/neothd/src/cli/verify.rs` (Kommentarblock zu „layered coverage“ statt End-to-End-Test).
- **Problem:** Kritischer Verifikationspfad wird argumentativ begründet, aber nicht durch einen dedizierten E2E-Test gegen echte WAL-Artefakte abgesichert.
- **Risiko:** Änderungen an Writer-/Segment-Semantik können die Annahmen brechen, ohne dass die gewünschte Benutzerwirkung getestet wird.
- **ToDo:** Minimalen deterministischen E2E-Test hinzufügen (fixture-basierter WAL-Ausschnitt + gezielte Tamper-Mutation + erwarteter non-zero Exit).

## P2 — Segment-Sortierung implizit von Dateinamen-Konvention abhängig
- **Datei/Zeile:** `SRC/neothd/src/cli/verify.rs` (`list_segments` nutzt `out.sort()`).
- **Problem:** Lexikografische Sortierung funktioniert nur robust bei strikt zero-padded Namen.
- **Risiko:** Bei Abweichungen falsche Verifikationsreihenfolge / schwer nachvollziehbare Audit-Ausgaben.
- **ToDo:** Sequenznummer explizit aus Dateinamen parsen und numerisch sortieren; bei Parse-Fehlern warnen.
