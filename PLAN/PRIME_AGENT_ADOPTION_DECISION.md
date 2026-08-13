# Entscheidung — Prime Agent als Referenz, nicht als NEOTH-Runtime

> **Status:** abgeschlossene Adoptionsentscheidung (`GOLD-ADOPT-PRIME-01`);
> keine Produktfunktion und kein Abschluss eines Implementierungs- oder
> Release-Items.
>
> **Entscheidung:** **Kein Runtime-, Vendor- oder Quellcode-Adopt von Prime
> Agent.** NEOTH übernimmt selektiv und eigenständig überprüfbare *Semantik* in
> nativen Rust-Modulen. Der einzige unmittelbar sinnvolle Arbeitsschritt ist der
> bereits offene, verhaltensneutrale Baseline-Slice `GOLD-NCT-01`.
>
> **Geprüfter Upstream-Snapshot:**
> [`a18809e00ea30638584d87b3afea7285a9d7296c`](https://github.com/PrimeIntellect-ai/prime-agent/tree/a18809e00ea30638584d87b3afea7285a9d7296c)
> (Stand der Prüfung: 2026-08-07; vollständiger 40-stelliger Pin, kein beweglicher
> Branch-Name). Alle Aussagen über Prime Agent in diesem Dokument beziehen sich
> ausschließlich auf diesen Snapshot, sofern nicht ausdrücklich anders markiert.
>
> **Verbindliche Quellenhierarchie:** Die aktuelle
> [`ROAD_TO_1_0_GOLD.md`](ROAD_TO_1_0_GOLD.md) ist der Release-Vertrag. Die
> 3.285-zeilige, kanonische
> [`NEOTH_COGNITIVE_TRANSPORT.md`](NEOTH_COGNITIVE_TRANSPORT.md) ist die
> ausführliche NCT/NIR-Spezifikation. Sie ist die erweiterte, reconciled Fassung
> des 2.481-zeiligen NCT-Eingabedokuments; historische `post-Gold`-/`v1.1`-
> Aussagen darin sind als `DOC_DRIFT` reconciliert: sie beschreiben nur
> Reihenfolge, nicht einen Aufschub aus Gold. Die Road führt `GOLD-NCT-00` als
> Spezifikationsbindung erledigt und `GOLD-NCT-01..27` plus
> `GOLD-ADOPT-BUZZ-01` weiter offen. Dieses Dokument kann keine Checkbox
> schließen.

## 1. Kurzentscheidung

Prime Agent ist für NEOTH **relevant als Produkt- und Architekturstudie**, nicht
als einzubettende Agentenplattform. Es bestätigt, dass langlebige Arbeit von
einem expliziten Session-/Run-Modell, echten Kind-Sessions, Zielen,
Fortsetzungsmechanismen und begrenzter Autonomie profitiert. Es löst aber genau
nicht die Sicherheits- und Autoritätsprobleme, die NEOTH als lokaler,
auditierbarer Agent erfüllen muss.

Die falschen Alternativen sind daher:

| Alternative | Urteil | Grund |
|---|---|---|
| Prime Agent neben `neothd` ausführen oder als Backend ausliefern | **REJECT** | zwei Run-/Session-Autoritäten, Python/Node/ZeroMQ-Lebenszyklus und kein gemeinsamer Cost/Consent/WAL-Gate |
| Prime-TypeScript, IPython-Kernel oder Python-Skills vendoren | **REJECT** | modellgenerierter Code erhielte Ambient-OS-Rechte; zusätzlicher Liefer-, Patch- und Lizenz-Supply-Chain-Radius |
| Prime-Protokolle unverändert als NEOTH-Transport übernehmen | **REJECT** | ACP/JSON/RPC sind Integrationsflächen, aber kein NIR/1-, Subject-, Capability-, Budget- oder Fencing-Authority-Modell |
| Prime-Semantik als Anforderung lesen und in Rust nachbauen | **ADOPT SELECTIVELY** | passt in NCT, hält NEOTH als einzige Autorität und erlaubt eigenständige negative/adversariale Tests |
| zuerst „autonomen Prime-ähnlichen Agenten“ bauen | **DEFER** | ohne reproduzierbare Baseline, typed Run-Authority und action/cost-gates wäre dies eine unmessbare Parallel-Runtime |

**Direkt jetzt:** `GOLD-NCT-01` beginnt mit einer reinen Instrumentierung des
bestehenden NEXUS-Primary-/QA-/Single-Correction-Pfads. Das ist *kein*
Prime-Runtime-Adopt, speichert im Baseline-Feld keine rohen Prompts und verändert
keine Route, Providerwahl, Action oder Ausführung. Direct, Council, Fallback,
Streaming, weitere Sub-Agent- und Cluster-Worker-Pfade bleiben ausdrücklich
offene Baseline-Arbeit unter derselben Roadmap-Karte.

**Danach:** Nur die durch Baseline belegten Lücken im vorhandenen NCT-Plan
schrittweise schließen. Eine spätere „durable run/session authority“ ist eine
NEOTH-eigene Konsequenz aus `GOLD-NCT-02..07`, `14..17`, `23..26` und
`GOLD-R4-13a..l` — nicht die Einbindung von Prime Agent.

## 2. Nachweisbasis zum Upstream

### 2.1 Identität, Lizenz und Reifegrad

* Das offizielle Repository bezeichnet sich im gepinnten
  [`README`](https://github.com/PrimeIntellect-ai/prime-agent/blob/a18809e00ea30638584d87b3afea7285a9d7296c/README.md)
  als „self-improving RLM agent“ für Coding sowie lang laufende Arbeit. Der
  geprüfte Baum enthält u. a. `packages/`, `prime-agent-runtime/`,
  `package.json`, `package-lock.json`, `install.sh` und `test.sh`; es ist kein
  einzelnes Rust-Crate.
* Die Root-[`LICENSE`](https://github.com/PrimeIntellect-ai/prime-agent/blob/a18809e00ea30638584d87b3afea7285a9d7296c/LICENSE)
  ist MIT. Das erlaubt grundsätzlich Kopien unter Einhaltung von Copyright- und
  Lizenztext, ist aber **keine** technische oder Sicherheitsfreigabe.
* Der Snapshot ist sichtbar aktiv und substanziell (GitHub zeigte bei der
  Quellensichtung 4.480 Commits sowie viele offene Issues/PRs). Das ist ein
  Reifeindikator für ein sich schnell bewegendes Projekt, kein NEOTH-
  Produktionsnachweis, keine stabile API-Zusage und keine Plattformqualifikation.
* Die offizielle Installationsanleitung nennt macOS oder Linux; daraus darf
  gerade keine Windows-Release-Parität abgeleitet werden. NEOTH benötigt seine
  eigene unterstützte Plattform-/Installer-/Doctor-Matrix (`GOLD-NCT-24/27`).

### 2.2 Tatsächliche Prime-Architektur — und was daran nützlich ist

| Prime-Agent-Baustein (am Pin) | Beobachteter Zweck | Für NEOTH nutzbare Lehre | Nicht übernehmbar |
|---|---|---|---|
| lokaler Daemon, Worker und Session-Supervisor | Sessions arbeiten nach Terminal-Detach weiter und lassen sich erneut anhängen | eine eindeutige, dauerhafte Run-/Lifecycle-Authority ist wertvoll | Daemon/Worker/Kernellaufzeit, deren Dateiformat oder Prozessmodell |
| ein Session-Baum pro Worker | Eltern-/Kind-Arbeit bleibt als tatsächliche Session-Struktur erhalten | explizite Parent/Child-, Attempt-, Cancel- und Terminal-Semantik | in-memory Ownership oder nebenläufige zweite Task-Authority |
| persistentes IPython als Modellwerkzeug | Kontext, Dateien, Shell, Tools und Unteragenten werden programmatisch aus einer Python-REPL gesteuert | Programmatic Workflows brauchen klar begrenzte, beobachtbare Effects | IPython, Python-Kernel, `dill`, Python-Interpreter, ZeroMQ oder modellgenerierte Python-Ausführung |
| typed Host Requests und reale `AgentSession`-Kinder | `rlm(...)` startet echte Child Agents statt Text zu simulieren | nur typisierte Delegate/Result/Cancel-Verträge und echte Lebenszyklen sind belastbar | freie Text-Steuerung, ungebundene Child-Authority oder eine Prime-SDK-Abhängigkeit |
| Compaction, Goals, Heartbeats, Schedules und bounded autonomy | lang laufende Aufgaben können innerhalb von Turn-/Token-/Zeitbudgets weitergehen | Budgets, fortsetzbare Zustände und klare Terminalzustände sind notwendige Run-Semantik | Erfolg aus „Budget erreicht“ ableiten; der Upstream warnt selbst davor |
| Continual Harness | zusätzliche Prompts, Memory, Skills und Subagent-Spezifikationen werden versioniert/refined | kleine, reviewbare, rollbackfähige Verbesserungen sind ein brauchbares Produktmuster | persistente Prompt-/Skill-Mutation ohne NEOTH-Approval, Provenance und nicht-executable Datenmodell |
| ACP, JSON und RPC | TUI-freie Automatisierung und Integrationsflächen | externe Adapter brauchen versionierte, eng begrenzte Verträge | diese Protokolle als interne NIR- oder Authority-Abkürzung behandeln |

Die README bestätigt dabei ausdrücklich die persistenten Python- und
Harness-/Subagent-Konzepte, die Hintergrundsessions, Compaction, Goals,
Heartbeats, Schedules, bounded autonomy sowie JSON/RPC. Sie stellt ebenfalls
klar, dass die Worker-/Kernel-Isolation **keine Sicherheits-Sandbox** ist. Diese
Selbsteinordnung ist für die Entscheidung maßgeblich.

### 2.3 Sicherheits- und Zuverlässigkeitsbefund

Prime Agent ist für einen vertrauenswürdigen lokalen Coding-Workspace gedacht;
NEOTH muss dagegen seine Authority auch über Provider, lokale Tools, Mesh und
persistente Autonomie nachweisbar begrenzen. Folgende Differenzen sind
Blocker, nicht bloße Implementierungsdetails:

| Befund am geprüften Prime-Modell | Risiko für eine Übernahme | NEOTH-Entscheidung |
|---|---|---|
| Modell-generiertes Python und Projektkommandos laufen mit den Rechten des angemeldeten Users; Upstream sagt ausdrücklich „not a security sandbox“. | Prompt-/Skill-/Repo-Injection wird unmittelbar zu Host-Datei-, Prozess-, Netzwerk- oder Credential-Zugriff. | **REJECT Runtime.** Effects bleiben hinter NEOTHs Capability-, Consent-, Paid-Provider-, Egress- und WAL-Gates. |
| ausführbare Python-Skills, Extensions, Konfiguration und Secret-Resolver | Code-/Konfigurationssupply-chain erhält Execution und Secret-Zugriff. | **REJECT.** Keine Python-Skill- oder Extension-Compatibility-Schicht. |
| `dill`-basierte, ausführbare Deserialisierung im Kernel-/Session-Umfeld | Persistenz ist potentiell Code-Ausführung, nicht nur Daten-Recovery. | **REJECT.** NEOTH verwendet versionierte, strikt limitierte Datenformate; keine Pickle-/`dill`-Klasse. |
| plain, nicht gelockte bzw. nicht atomar committe Harness-JSON-Dateien | Crash, Parallelzugriff oder Manipulation können Run-/Skill-/Memory-State verlieren oder verfälschen. | **REJECT storage.** NCT benötigt Revision, Idempotency, atomare Commit-/Recovery-Beweise (`GOLD-NCT-04`, `14/15`). |
| Telemetrie ist standardmäßig aktiv; optional ist ein vollständiger Trace-Upload vorgesehen | Prompts, Pfade, Tool-/Sessionmetadaten können lokalen Privacy-Scope verlassen. | **REJECT default.** NCT-Telemetrie ist inhaltsfrei, bounded und WAL/auditierbar (`GOLD-NCT-07`, `22`). |
| Node + Python + IPython + ZeroMQ statt eines NEOTH-nativen Runtime-Owners | mehr Updater, Lockfiles, Interpreter/Kernel, IPC, Prozesse, CVEs und schwerer Windows-Support. | **REJECT vendor/runtime.** Ein Rust-Owner in `neothd` (`GOLD-NCT-23/27`). |
| Remote-MCP-Funktionalität deckt keine NEOTH-Transport-/Fencing-/Budget-Authority ab | Tool-Erreichbarkeit würde fälschlich als Delegations- oder Action-Autorität gelten. | **REJECT authority mapping.** MCP bleibt begrenzte Tool-/Resource-Grenze (`GOLD-NCT-19`). |

Das ist bewusst strenger als „Prime ist unsicher“: Prime dokumentiert sein
Trust-Modell ehrlich. Es passt nur nicht zum NEOTH-Vertrag, in dem eine
empfangene Nachricht, ein Child, ein Signaturbeweis oder ein Tool niemals
selbst Execution-, Provider- oder Budget-Autorität minten darf.

## 3. NEOTH-Ausgangslage und eigentliche Lücke

NCT ist bereits als Evolution des NEXUS-/Sub-Agent-Handoff definiert, nicht als
zweites Framework. Der bestehende Unterbau umfasst insbesondere:

* `AuthorizedProvider` mit Cost- und Consent-Authorizer,
* private Run-Records und inhaltsarme WAL-Ereignisse,
* `sub_agents` mit typisierten Requests/Results, begrenztem Fan-out und echten
  Provider-/QA-/Retry-Pfaden,
* Cluster-`TaskDelegate`/`TaskResult`, Membership- und Carrier-Arbeit,
* lokale Memory-/Self-improve-Pfade, Code Map/Graphify sowie GUI und Buddy.

Der konkrete Mangel ist daher **nicht** „es fehlt ein Agentenruntime“. Es fehlt
ein einziger, durchgängig persistierter und typisierter **Task/Run/Session-
Authority-Kern**: Run-ID und Subject, Parent/Child, Correlation, Attempt/Fence,
Revision, Route, Cancel, Provider-Permit, Result-/Dead-Letter-Übergang und
Recovery müssen in einer konsistenten Authority zusammenkommen. Heute existieren
mehrere gute Teilpfade; Prime illustriert das Produktmuster, darf aber keines
davon ersetzen.

```text
Prime-Beobachtung: daemon -> worker -> session tree -> IPython / harness
                                      |
                                      |  nicht übernehmen
                                      v
NEOTH-Ziel: one durable typed task/run/session authority
  Direct / NEXUS / Council / Cluster / Cron / Channel / Buddy
                          |
             NIR/1 + revision + capability + permit + fence
                          |
  existing Cost/Consent/WAL + local action gate + recovery/Doctor surfaces
```

## 4. Zuordnung zu verbindlichen Roadmap-Karten

Die Matrix ist eine Abhängigkeitskarte; ein Eintrag ist **nicht** der Nachweis,
dass die jeweilige Karte erledigt ist.

| Prime-Impuls | NEOTH-native Konkretisierung | Primäre Gold-Karten | Entscheidung |
|---|---|---|---|
| wiederholte Kontextkopien sichtbar machen | datensparsame Messung des Ist-Pfads, Fixtures sowie Train/Holdout ohne Routenänderung | `GOLD-NCT-01`, später `07`, `26` | **NOW: baseline only** |
| typed Host Request / echte Child Session | kanonischer NIR-Request/Result, Parent/Child-/Correlation-/Attempt-Felder, V1→V2-Adapter | `GOLD-NCT-02`, `05`, `06`, `12`, `25` | **ROADMAP** |
| durable Session-Baum / detach-resume | ein generation-bound Lifecycle-Owner; persistente, fencesichere Cluster-Delegation und Recovery | `GOLD-NCT-04`, `14`, `15`, `23`, `24`, `26`; `GOLD-R4-13b,d,f,i,l` | **ROADMAP, native** |
| Goals, heartbeats, schedules, bounded autonomy | explizite Zeit-/Token-/Kosten-/Turn-Budgets, cancel/retry und sichtbare Terminal-/Dead-Letter-Zustände | `GOLD-NCT-09`, `10`, `14`, `17`, `23`, `24`, `26`; `GOLD-R4-13b,f,h,i,l` | **ROADMAP, erst nach Authority** |
| retained subagents / direct messaging | NIR-gebundene Übergabe mit Subject, Capability, Revision, Manifest und Action-Firewall | `GOLD-NCT-03`, `04`, `11`, `12`, `13`, `15`; `GOLD-R4-13a,d,e` | **ROADMAP** |
| kompakter Continual Harness | nur bereits vorhandene NEOTH-Memory-/Self-improve-Mechanismen verbessern; jede Mutation reviewbar, provenance-gebunden und nicht selbst ausführbar | außerhalb eines Prime-Adopts; berührt bei tatsächlicher Consumer-Wiring `GOLD-NCT-23..26` | **DEFER / no compatibility layer** |
| ACP/JSON/RPC | externe, versionierte Adapter nach Admission, nie interne Runtime- oder Task-Authority | `GOLD-NCT-18`, `19`, `23`, `24`, `26`; `GOLD-R4-13d,g,h` | **ROADMAP, bounded** |
| Supervisor-/Queue-Muster | nur belegte Invarianten nachbauen: eindeutiger Terminal-CAS, Deadline, cancel, recovery, durable backpressure | `GOLD-NCT-14`, `15`, `17`, `26`; `GOLD-R4-13b,c,f,i,l` | **ROADMAP, native** |

### 4.1 Cluster-Abgrenzung zu `GOLD-R4-13a..l`

Prime liefert keine Abkürzung für die offenen Cluster-Verträge. Im Gegenteil:

* `GOLD-R4-13a` (Membership/Revoke), `13c` (Cost authority), `13e`
  (Capability/Capacity/Locality) und `13g` (Carrier/config truth) bleiben
  **NEOTH-Authorities**; Prime-Sessionzustand darf keine davon vertreten.
* `GOLD-R4-13b`, `13d`, `13f`, `13i` und `13l` teilen das Thema einer
  dauerhaften Task-/Result-/Scheduler-/Observability-Authority mit NCT, müssen
  aber über WAL/SQLite, typed `TaskDelegate`/`TaskResult`, fencingsichere
  Recovery und echte Mehrprozess-Tests geschlossen werden — nicht über eine
  Prozess- oder JSON-Queue.
* `GOLD-R4-13h` verlangt GUI, CLI, Buddy und Channel-Parität. Prime-TUI oder
  RPC darf keine alternative Steuerfläche schaffen.
* `GOLD-R4-13j`/`13k` (Upgrade und Backup-vs-Recall) erfordern formale
  Artefaktfähigkeit und klare Herkunft. Prime-Harness-Dateien sind weder
  autoritative Backups noch Recall-Material.

## 5. Strikte Übernahme-/Nichtübernahme-Regeln

### 5.1 Erlaubte, neu zu implementierende Semantik

1. **Dauerhafte Task-Graph-Semantik:** Ein Run hat genau eine lokale,
   durable Authority; Child-/Cluster-Attempts sind ID-, Subject-, Revision-,
   Deadline- und Fence-gebunden.
2. **Explizite Weiterarbeit:** Goal, Heartbeat und Schedule sind nur
   autorisierte, budgetierte Re-Entry-Ereignisse. Ein Limit oder ein
   bestandener Teil-Gate ist kein Success.
3. **Typisierte Übergabe:** Request, Result, Evidence, Warning, Usage,
   ActionIntent und Failure sind kanonische, größenbegrenzte Datenobjekte;
   keine freie Prompt-/Python-/Shell-Steuerung.
4. **Reviewbare Verbesserung:** Eine spätere Verbesserung kann einen
   versionierten Vorschlag mit Herkunft, Diff, Testbeleg, Approval und
   Rollback erzeugen. Sie darf weder Base Prompt noch ausführbaren Skill-State
   autonom umschreiben.
5. **Lifecycle-Disziplin:** detach, resume, cancel, timeout, crash und
   shutdown führen zu genau einem sichtbaren, recoverbaren Zustand.

### 5.2 Nichtübernahme (verbindlich)

* keine Prime-Binaries, keine npm- oder Python-/IPython-/ZeroMQ-Abhängigkeit,
  kein `prime-agent-runtime` und kein Source-Transplant;
* keine Executable-Skill-/Extension-/Config-Kompatibilität, kein `dill` oder
  anderes Pickle-/Code-Deserialisieren;
* keine ambient Shell-, Datei-, Netz-, Prozess-, GPU- oder Secret-Autorität
  aus einem Modell, einer Session, einem Child oder einer Nachricht;
* keine plain/unlocked/non-atomic JSON als Authority oder Recovery-Quelle;
* keine standardmäßige Prompt-/Trace-Exfiltration und kein optionaler Full-
  Trace-Upload ohne eine separate, explizite NEOTH-Entscheidung;
* keine Prime-ACP/RPC/MCP-Identität als Ersatz für NIR, Admission, Fence,
  Capability, Consent, Provider-Permit, Cost oder WAL;
* keine Aussage „Prime-kompatibel“, solange kein eigener, begrenzter Adapter
  spezifiziert, threat-modeled und qualifiziert ist.

## 6. Invarianten für jede spätere native Umsetzung

Die folgenden Regeln sind vor der ersten aktiven Route bindend:

1. **Eine Authority:** Es gibt pro Run/Task genau einen durablen,
   revisionierten Owner. Prozesslokaler Zustand oder eine zweite Daemon-Runtime
   ist kein Owner.
2. **Fail closed:** fehlendes/defektes Persistenz-, Manifest-, Replay-,
   Membership-, Permit- oder Fence-Material blockiert Provider-, Memory- und
   Action-Effekte.
3. **Keine Authority-Vererbung:** Child, Cluster-Resultat, A2A-Card,
   MCP-Tool, Signatur oder Route Receipt kann keine lokale Action oder
   Provider-Ausgabe autorisieren. `GOLD-NCT-13` baut die konkrete Aktion lokal
   neu und führt die bestehenden Gates erneut aus.
4. **Kosten sind final:** jedes konkrete Provider-Leaf benötigt seine eigene
   Cost-/Consent-/WAL-Autorisierung; bei distributed execution einen
   single-use, expiry- und fence-gebundenen Permit (`GOLD-NCT-17`,
   `GOLD-R4-13c`).
5. **Datensparsam messen:** Telemetrie/WAL enthält nur content-free,
   bounded-cardinality Metadaten und Hashes. Rohe Nutzerprompts, private
   Records, Secrets, Ref-Inhalte, IPython-Snapshots oder vollständige Traces
   werden weder für NCT-01 noch für einen späteren Route-Entscheid persistiert
   oder hochgeladen.
6. **Deterministische Enden:** Cancel, Deadline, Retry, Redelegation und
   Crash resultieren in genau einem terminalen Commit oder einer sichtbaren,
   durable Dead-Letter-Transition; nie stiller Verlust oder doppelter Effekt.
7. **MCP bleibt begrenzt:** Remote MCP ist Tool-/Resource-Zugang unter
   `GOLD-NCT-19`, nicht Delegation, Transport oder Session-/Task-Authority.
8. **Release ist vollständige Parität:** CLI, API, GUI, Buddy, Doctor,
   Channels, Packaging, Update/Repair/Uninstall und Windows-/Plattformbeweis
   gehören zum DoD; ein funktionierender Entwickler-Worker genügt nicht.

## 7. Der einzige direkte Slice: `GOLD-NCT-01`

### Ziel und enger Umfang

Instrumentiere den bestehenden Ausführungspfad so, dass er pro Run/Edge
reproduzierbar erfassen kann:

* Pfadklasse: Direct, NEXUS/Sub-Agent, Council, QA, Retry, Fallback,
  Streaming oder Cluster-Worker;
* Route-/Provider-/Modell-ID, konkrete Leaf-Zahl und begrenzte
  Parent/Child-/Correlation-Referenz;
* **wiederholte** Kontextbytes/tokens (nicht den Kontext selbst), native vs.
  geschätzte Usage, Cache-Usage soweit der Provider sie autoritativ liefert;
* TTFT, Queue-, Provider-, QA-/Repair- und Gesamtlatenz, Kosten sowie eine
  explizit getrennte Failure-/Repair-/Final-Outcome-Klasse;
* fixture-/dataset-ID, Code-/Config-/Policy-Hash und train/holdout-Markierung.

### Unantastbare Nichtziele

* kein Prime-Install, Vendor, Daemon, Kernel, ACP-/RPC-Adapter oder Python;
* keine Änderung an Prompt-Text, Provider-, Retry-, Council-, Fan-out-,
  Action-, Cost-/Consent- oder Scheduling-Entscheidungen;
* keine neue aktive Route, keine automatisch fortgesetzte Aufgabe und kein
  neuer Persistenz-Owner;
* die NCT-01-Baseline persistiert keine rohen Prompts, Outputs, Secrets, Dateien
  oder Full Traces und fügt keine solche Persistenz hinzu. Bereits bestehende
  private Sub-Agent-Run-Records sind keine Baseline-Ausgabe und bleiben
  außerhalb dieses Slice. Fixtures sind separat kontrollierte, minimale
  Testdaten und keine Kopie realer Nutzersessions;
* kein „NCT/Prime integriert“-Claim. Der Slice liefert nur die
  Vergleichsgrundlage für die nächsten Karten.

### Akzeptanzkriterien

1. Jeder genannte Ist-Pfad produziert für eine gefrorene Fixture einen
   versionierten, content-free Baseline-Datensatz; fehlende native
   Providerusage bleibt als `unknown`/`estimated` sichtbar, nie erfunden.
2. Derselbe Fixture-/Config-/Code-Snapshot ergibt stabile Pfadklassifikation
   und eine nachvollziehbare Wiederholungsmetrik. Messrauschen wird als Range
   ausgewiesen, nicht als Effizienzgewinn verkauft.
3. Train- und Holdout-Corpus sind getrennt; keine Route wird anhand von Daten
   aktiviert, die später als unabhängiger Erfolg ausgegeben werden.
4. Das vorhandene Laufzeitverhalten ist mit/ohne Instrumentierung
   funktionsgleich; der Instrumentierungsfehler degradiert beobachtbar und
   darf keine Provider-/Action-/WAL-Autorisierung öffnen.
5. Unit-/Fixture-Tests beweisen Redaction/No-Raw-Prompt-Persistenz und
   Edge-Korrelation; ein Diff-/source-to-sink-Audit zeigt die abgedeckten und
   bewusst noch nicht abgedeckten Production Consumers.

### Kill-/Stop-Kriterien

Den Slice stoppen, zurückrollen oder als negative Evidenz dokumentieren, wenn
eine der folgenden Bedingungen eintritt:

* die Metrik kann Kontextwiederholung nicht ohne Persistenz von Prompt- oder
  Ref-Inhalt bestimmen;
* sie verändert Providerusage, Timing, Reihenfolge, Retry oder Resultat mehr
  als die dokumentierte reine Beobachtung zulässt;
* ihre WAL-/Telemetry-Schreibungen die Cost-/Consent-/Action-Gates verdecken,
  ausfallen lassen oder unbounded wachsen;
* die Abdeckung zeigt, dass es keinen stabilen gemeinsamen Ist-Pfad gibt.
  Dann ist die korrekte Folge eine explizite Lückenkarte, nicht ein künstlicher
  „Prime supervisor“-Shim;
* der Upstream-Pin oder dessen Lizenz/Trust-Modell sich nicht mehr verifizieren
  lässt. Dann bleibt die NEOTH-Arbeit nur durch eigene Anforderungen und Tests
  begründbar, nicht durch den Primäreindruck.

## 8. Voraussetzungen für spätere Phasen und Re-Audit

Vor einer Ausweitung von `GOLD-NCT-01` müssen mindestens folgende Tore erfüllt
sein:

1. `GOLD-NCT-01` liefert eine belastbare Baseline samt negativer Ergebnisse.
2. `GOLD-NCT-02..05` liefern kanonische Daten, Limits, refs/revisions und einen
   einzigen Kontextprojektor; danach erst `GOLD-NCT-06/07` für echte NEXUS-
   Migration/Usage.
3. `GOLD-NCT-09` läuft zunächst ausschließlich im Shadow-Mode; `10` darf nur
   nach gehaltenen Nichtunterlegenheits-, Kosten- und Latenzbelegen aktivieren.
4. Jeder remote-/clusterfähige Pfad wartet auf `GOLD-NCT-11..17` und die
   korrespondierenden `GOLD-R4-13a..l`-Beweise. Eine lokale Session-Tree-Demo
   ist kein Cluster-Completion-Beweis.
5. `GOLD-NCT-18/19` behandeln A2A/MCP erst nach dem internen Authority-Kern.
   Eine Prime-Remote-MCP-Integration ändert diese Reihenfolge nicht.

Ein erneutes, dateiweises Upstream-Audit ist zwingend bei:

* einem Wunsch nach Source-Copy, SDK/Runtime-Einbettung oder
  „Prime-Kompatibilität“;
* neuem Prime-Release, neuem Commit-Pin, Lizenz-/Notice-Änderung oder Änderung
  von Python/Node/Kernel/IPC/Telemetry/Secrets/Skill-/Extension-Verhalten;
* jeder behaupteten Windows-Unterstützung oder neuen Remote-MCP-/ACP-/RPC-
  Authority;
* jeder Erweiterung der NEOTH-Semantik über die obigen, eigenständig
  implementierten Daten-/Lifecycle-Invarianten hinaus.

Das Re-Audit muss den neuen Commit vollständig pinnen, die geänderten Dateien
gegen den alten Pin diffen, Trust-/Threat-/License-/SBOM-Folgen bewerten und
jedes weiterverwendete Konzept einer aktuellen NCT- und R4-Karte mit eigenen
Tests zuordnen. Ein Stern-, Issue- oder Benchmark-Status ersetzt diesen Schritt
nicht.

## 9. Provenance- und Lizenzpflichten

Die vorliegende Entscheidung übernimmt **keinen Prime-Code**. Für die
eigenständige Rust-Implementierung sind daher die Ideen/Verhaltensanforderungen
zu dokumentieren, aber keine Prime-Quellteile in NEOTH zu kopieren.

Falls später ausnahmsweise Code kopiert werden soll, gilt vor Merge zwingend:

1. exakter Source-Pfad, Commit und Zweck in einem Adoption Ledger;
2. Prüfung, dass die konkrete Datei tatsächlich unter MIT steht und keine
   abweichende Drittanbieter-Lizenz/Notice mitbringt;
3. Erhalt der Copyright- und MIT-Lizenztexte, Kennzeichnung der Änderungen,
   Eintrag in `THIRD_PARTY_LICENSES` und SBOM/Release Notices;
4. Security-, Plattform-, Lifecycle-, Authority- und Testreview der Kopie;
5. explizite Freigabe durch die Roadmap-Karte. Kein Copy/Paste in einen
   generischen „vendor“-Ordner und keine Ableitung von Support durch die Lizenz.

Da der Beschluss ausdrücklich nur native Neuentwicklung zulässt, ist der
Normalfall besser: **keine** Quellkopie, keine Prime-Laufzeitabhängigkeit, aber
eine kurze Provenance-Notiz mit URL, Pin, beobachteter Semantik und der
zugehörigen eigenen NEOTH-Tests.

## 10. Abschlussformel für Roadmap und Produktkommunikation

> Prime Agent gehört zu NEOTH als überprüfte externe Referenz für langlebige
> Agentenarbeit. Er gehört **nicht** in den NEOTH-Prozess, die Release-Artefakte
> oder die Authority-Kette. NEOTH baut die verwertbaren Semantiken nativ auf
> NIR/1, ContentRefs, Revisionen, Admission, Cost/Consent/WAL und Fencing auf.
> Bis `GOLD-NCT-01` eine datensparsame Baseline liefert und die nachfolgenden
> Karten die Authority-Beweise schließen, bleibt „Prime-inspiriert“ eine
> Designentscheidung — keine ausgelieferte Capability und kein Gold-Abschluss.
