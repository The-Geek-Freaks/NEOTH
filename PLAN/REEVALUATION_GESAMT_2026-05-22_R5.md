# NEOTH Re-Evaluation R5 - Snapshot 2026-05-22

Stand: 2026-05-22  
HEAD: `501738a`  
Modus: nicht-destruktiver Snapshot; keine Code-Aenderungen durch diese Evaluation  
Scope: committed HEAD plus aktueller dirty Live-Arbeitsbaum

## 1. Kurzurteil

R5 ist gegen R4 ein echter Sprung nach oben, aber zweigeteilt:

- **Committed HEAD (`501738a`)**: ca. **86% Produktreife**.
- **Aktueller Live-Arbeitsbaum**: ca. **73% strict**, weil er gerade nicht kompiliert.
- **Live-Potential nach Fix des Compile-Blockers und WhatsApp-Truth-Fix**: **88%**.

Die R4-P0/P1-Liste wurde weitgehend abgearbeitet:

- Clippy-Fix wurde committed (`29d13ef`).
- `neoth recall --citation-check` ist verdrahtet (`3804a95`).
- GUI-Chat-Subprocess ist testbar (`30a6047`).
- Channel-Bootstrap-Statuslogging wurde ehrlicher (`a652ce1`).
- Skill-Router hat Hyphen-/Dotted-Keyword-Fix plus Routing-Matrix fuer gebundelte Skills (`501738a`).

Der neue Live-Delta geht in die richtige Richtung: Slack/WhatsApp sollen von Status-only zu echter Runtime-Startlogik wachsen. Aber dieser Delta ist aktuell noch nicht fertig.

## 2. Prozentuale Achsenbewertung

| Achse | R4 | R5 HEAD | R5 Live aktuell | Tendenz | Begruendung |
| --- | ---: | ---: | ---: | --- | --- |
| Security / Safety | 86% | **88%** | **82%** | hoch, live gebremst | Citation-Check bleibt offline/no-network, Skill-Routing sicherer, channel status ehrlicher. Live-Delta fuegt Meta-App-Secret hinzu, kompiliert aber nicht und behauptet WhatsApp-LIVE zu frueh. |
| Reliability / Betriebsfestigkeit | 82% | **86%** | **62%** | HEAD hoch, live rot | HEAD hat mehr Tests und bessere Routing-/GUI-/Recall-Flaechen. Live-Arbeitsbaum faellt `cargo check` wegen `whatsapp_app_secret` in `Credentials::is_empty`. |
| Code-Qualitaet / Wartbarkeit | 80% | **86%** | **64%** | HEAD hoch, live runter | R4-Clippy-Gate wurde committed. Live-Delta fuehrt einen compile-time Feld-Drift ein. |
| Testtiefe / Evidenz | 88% | **91%** | **76%** | hoch, live stale | `neothd` 2868 passed, Integration 7, no-network 1, GUI 17. Aber aktuelle Live-Config-Aenderung wurde nach den gruenen Tests nicht mehr build-clean. |
| UX / GUI-Kohaerenz | 74% | **79%** | **79%** | hoch | GUI-Chat-Fehlerpfade sind testbar; GUI-Tests steigen von 8 auf 17. |
| DAU-Readiness | 74% | **78%** | **75%** | hoch | Glossary/Tour/Privacy plus GUI-Chat-Testbarkeit und citation-check CLI. Live-Compile-Blocker verhindert Release-Wert. |
| Pro-Operator-Readiness | 90% | **93%** | **87%** | hoch, live gebremst | 22 Skills, Routing-Matrix, Skills/Mode/Slash/Recall-CLI. Live-Channel-Work geht in richtige Richtung, ist aber unfertig. |
| Produktwahrheit / Claim-Disziplin | 80% | **85%** | **64%** | HEAD hoch, live kritisch | HEAD ist ehrlicher als R4. Live-Delta klassifiziert WhatsApp als `LIVE`, obwohl `webhook_listener::dispatch_messages` Outbound weiterhin loggt und droppt. |
| Gesamtprodukt | 82% | **86%** | **73%** | HEAD stark, live blockiert | HEAD hat die naechste Stufe genommen. Der aktuelle Arbeitsbaum ist ein Zwischenzustand und nicht releasefaehig. |
| Strict Release Gate | 78% | **86%** | **0% pass / blocked** | HEAD gruen, live rot | Live: `cargo check -p neothd` und `clippy -D warnings` failen mit E0027. |

## 3. Was seit R4 besser wurde

### 3.1 Clippy-Gate wurde im committed Verlauf wieder geschlossen

Commit `29d13ef chore(clippy): R4-P0 — clippy -D warnings green again` adressiert die R4-Lint-Luecke. Das hebt Code-Qualitaet und Strict-Release-Bewertung im HEAD deutlich.

Live-Einschraenkung: der spaetere dirty Arbeitsbaum hat wieder einen Compile-Blocker eingefuehrt.

### 3.2 Citation-Check ist jetzt Produktflaeche

R4 hatte `recall::citation_check` nur als Live-Potential. In R5 ist es committed und per CLI angebunden:

- `SRC/neothd/src/recall/citation_check.rs`
- `SRC/neothd/src/cli/recall.rs`
- `neoth recall --citation-check <TEXT>`
- `neoth recall --citation-check -` fuer stdin

Das ist ein echter Sprung fuer Research-/Provenance-Qualitaet. Es bleibt bewusst offline und verletzt die no-network-Haltung nicht.

### 3.3 GUI-Chat ist testbar statt nur verdrahtet

`SRC/neothd-gui/src/main.rs` hat jetzt:

- `chat_via_subprocess_with`
- `shape_chat_output`
- `BINARY_MISSING_MESSAGE`
- Tests fuer happy path, empty stdout, non-zero stderr, no-stderr, UTF-8 truncation, missing binary

GUI-Testzahl steigt von 8 auf **17 passed**. Das schliesst einen wichtigen Teil der R4-P1-Luecke.

### 3.4 Skill-Routing ist robuster

`SRC/neothd/src/skills/router.rs` behebt einen echten Router-Fehler:

- hyphenated Keywords wie `fact-check` matchen jetzt via substring;
- dotted Keywords wie `node.js` ebenfalls;
- eine R4-P1-Routing-Matrix pinnt Konfliktfaelle fuer gebundelte Skills.

Das ist wichtig, weil 22 gebundelte Skills sonst schnell durch broad triggers driftig werden.

### 3.5 Channel-Status wurde ehrlicher, aber noch nicht voll geloest

HEAD `a652ce1` verbessert Statuslogging: Telegram live, Slack/WhatsApp nicht mehr stillschweigend als magisch fertig verkauft. Das ist Produktwahrheit.

Der aktuelle dirty Live-Delta geht weiter und versucht Slack/WhatsApp wirklich in `serve` zu starten. Das ist die richtige Richtung, aber aktuell unfertig.

## 4. Live-Blocker im aktuellen Arbeitsbaum

### P0 - `Credentials::is_empty` ist nicht mit `whatsapp_app_secret` synchron

Aktueller dirty diff fuegt in `SRC/neothd/src/config/credentials.rs` hinzu:

- `whatsapp_app_secret: Option<SecretString>`

Aber `Credentials::is_empty` destructured `Self` absichtlich exhaustiv und nennt das neue Feld nicht.

Verifikation:

- `.\scripts\cargo-msvc.ps1 check '-p' neothd --offline`
- `.\scripts\cargo-msvc.ps1 clippy '-p' neothd --offline -- -D warnings`

Beide failen mit:

```text
error[E0027]: pattern does not mention field `whatsapp_app_secret`
```

Das ist ein guter Compile-Guard. Genau dafuer wurde die exhaustive destructure offenbar gebaut.

Done-Kriterium:

- `whatsapp_app_secret` in `Credentials::is_empty` aufnehmen.
- Danach `cargo check`, `cargo test`, `clippy -D warnings` erneut laufen lassen.

### P0 - WhatsApp `LIVE` ist im Live-Delta noch zu stark behauptet

Der dirty Delta in `SRC/neothd/src/cli/doctor.rs` klassifiziert WhatsApp als `LIVE`, wenn Token, Phone-ID, Verify-Token und App-Secret vorhanden sind. `SRC/neothd/src/cli/serve.rs` startet dann den Meta webhook listener.

Das Problem: `SRC/neothd/src/channels/webhook_listener.rs::dispatch_messages` ruft die Pipeline auf, aber bei `Ok(Some(outbound))` wird der Outbound nur geloggt und gedroppt:

```text
pipeline produced outbound (drop here; adapter owns send)
```

Damit ist Receive echt, aber Reply-Pfad nicht. Doctor-Text "send + receive both real" ist fuer WhatsApp im dirty Delta noch falsch.

Saubere Optionen:

1. Doctor/serve nur `INBOUND-LIVE / OUTBOUND-SEPARATE` oder `WEBHOOK-LIVE` nennen.
2. Oder `webhook_listener` bekommt einen echten WhatsApp send path / adapter reference und sendet replies ueber Graph API.

Erst Option 2 verdient `LIVE` im Sinne "bidirectional channel".

### P1 - Slack ist plausibler live, braucht aber weiterhin End-to-End-Evidenz

Slack wirkt im Live-Delta reifer als WhatsApp:

- `SlackChannel::run` existiert;
- `serve` spawnt es mit Bot- und App-Token;
- Doctor unterscheidet partial token vs both tokens.

Abzug bleibt: Ohne echte tokenlose Simulation/Fake socket-mode test bleibt das eher Integrationsvertrauen als voll lokaler E2E-Beweis.

## 5. Verifikation

Ausgefuehrt:

- `git status --short`
- `git log --oneline -n 12`
- `git show --stat --oneline -n 8`
- `.\scripts\cargo-msvc.ps1 test '-p' neothd --offline`
- `.\scripts\cargo-msvc.ps1 test '-p' neothd-gui --offline`
- `.\scripts\cargo-msvc.ps1 clippy '-p' neothd --offline -- -D warnings`
- `.\scripts\cargo-msvc.ps1 check '-p' neothd --offline`

Ergebnisse:

- `neothd` Tests: **2868 passed, 0 failed, 2 ignored**
- `neothd` Integration: **7 passed, 0 failed**
- `no_network_construction_outside_providers`: **1 passed**
- `neothd-gui`: **17 passed, 0 failed**
- Current live `cargo check`: **failed**
- Current live `clippy -D warnings`: **failed**

Aktueller dirty Arbeitsbaum:

- `SRC/neothd/src/cli/doctor.rs`
- `SRC/neothd/src/cli/serve.rs`
- `SRC/neothd/src/config/credentials.rs`
- `SRC/neothd/src/config/mod.rs`

## 6. Neues Gesamturteil

Committed HEAD ist stark: **86%**. Die R4-Hauptabzuege wurden sichtbar abgearbeitet.

Der aktuelle Live-Arbeitsbaum ist aber gerade ein Zwischenzustand: **73% strict**, weil er nicht kompiliert und weil WhatsApp-LIVE zu optimistisch ist.

Wenn du den Compile-Blocker fixst und WhatsApp entweder ehrlich klassifizierst oder den Reply-Pfad wirklich sendest, ist **88%** realistisch. Ab dann bleiben als groesste Bremsen:

1. echte Multichannel-E2E-Evidenz;
2. GUI-first Onboarding statt CLI-first;
3. live Citation Lookup nur mit sauberem outbound allowlist model;
4. Release-/Packaging-Beweis fuer beide Binaries und gebundelte Skills.
