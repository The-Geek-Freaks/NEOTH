# GUI, CLI, Buddy, and capability parity for v1.0

- Status: **Proposed — v1.0 release blocker**
- Scope owner: **WS-R4-04, WS-R4-05, WS-R4-06, WS-R4-09**, with integration obligations into WS-R4-08 and WS-R4-10
- Committed audit baseline: **`19f74b228cc6d43fc2542922bbc28e324ba52ac6`**
- Depends on: **[Plan 001](001-openclaw-channel-migration-parity.md)** for channel/account/import behavior and **[Plan 002](002-zero-friction-adoption-coupling.md)** for the canonical capability catalog, adoption adapters, durable jobs, packaging, and clean-machine proof
Release rule: this plan is complete only when the resulting behavior is present in the exact release artifacts, not merely in source or a dirty worktree.

> Audit note: the shared worktree contained uncommitted release-self-knowledge work while this plan was written, including a provisional `neoth self-knowledge` CLI and release snapshot code. It is useful design evidence, but it is not committed-baseline functionality and must not be counted as complete until it passes the same exact-head and artifact gates as every other release capability.

## 1. Outcome

NEOTH v1.0 must expose one coherent product through CLI, full GUI, Buddy/overlay, onboarding, Wiki/Obsidian self-knowledge, and release documentation. A user must never have to know which internal binary, installer, daemon, provider, skill, channel adapter, or model downloader implements a capability. The same operation must have the same prerequisites, policy gates, state, progress, result, error, repair path, and audit receipt on every surface.

This plan closes the current split-product problem:

- CLI has the broadest real capability surface, but much of it is not discoverable or executable from GUI/Buddy.
- GUI contains useful panels and correctly typed mutation bridges, but also visible controls whose behavior is cosmetic, partial, stale, or weaker than their copy implies.
- Buddy receives real live activity moods, yet is not an actionable companion and runs a separate, weaker chat path.
- CLI and GUI onboarding are different task graphs with different validation and checkpoint behavior.
- long-running installs, imports, downloads, model loads, migrations, and repairs do not share a durable user-visible task state.
- the existing self-Wiki catalogs names, not executable product capabilities and live availability.
- the in-flight Graphify release snapshot is CLI-oriented and is not yet a shared GUI/Buddy/Wiki/Obsidian product contract.

The target is not one GUI panel per CLI subcommand. The target is **complete classified parity**: every public operation is directly executable, guided, or handed off without losing context; every intentionally internal or unavailable operation is explicitly classified and never advertised as functional.

## 2. Coordination boundaries

### 2.1 Plan 001 owns channel truth

Plan 001 owns the canonical channel/account model, OpenClaw-compatible importer, per-account behavior, capability probes, inbound/outbound semantics, attachments, threading, reactions, auth lifecycle, routing, and Keet/WhatsApp/other adapter contracts.

This plan only owns how that truth appears and is operated in:

- onboarding and repair;
- GUI channel/account settings;
- chat session routing and channel switcher;
- CLI discovery and typed status;
- Buddy quick actions, status, and handoff;
- progress, disabled reasons, and test evidence.

No channel-specific registry, auth state machine, or migration parser may be reimplemented here.

### 2.2 Plan 002 owns installable capability truth

Plan 002 owns the canonical `CapabilityDescriptor`, capability lock, release asset ownership, native download/install/configure/probe/update/uninstall adapters, durable integration jobs, clean-machine packaging, and common Wizard/CLI/GUI/Buddy job API.

This plan consumes those objects. It adds a **surface projection**, not a second capability catalog. It does not invent a parallel downloader, model manager, installer queue, readiness probe, or adoption manifest.

### 2.3 This plan owns product-surface parity

This plan owns:

- classification and projection of every public operation;
- CLI/GUI/Buddy interaction parity and discoverability;
- a shared onboarding/reconfigure/repair task graph;
- real chat session/channel switching and immediate cancellation;
- Buddy as an actionable companion using the same sessions and task controllers;
- rendering Plan 002 jobs with phase, byte/step progress, retry, cancel, and resume;
- projecting signed release Graphify/self-knowledge into GUI, Buddy, Wiki, and Obsidian;
- generated copy and documentation links that cannot outlive the capability state they describe;
- DAU-friendly keyboard, accessibility, scale, recovery, and notification behavior.

### 2.4 Explicit non-goals

- Do not duplicate OpenClaw migration research from Plan 001.
- Do not define another adoption lifecycle or job database beside Plan 002.
- Do not make every nested CLI operation a permanent sidebar panel.
- Do not expose internal maintenance/debug operations merely to inflate parity counts.
- Do not implement GUI actions by assembling human-oriented CLI output and guessing success from text.
- Do not claim a feature is ready because a control, enum value, README sentence, or catalog entry exists.

## 3. Release invariants

These are non-negotiable contracts, not aspirations.

1. **One capability identity.** Every public operation is addressed by stable `capability_id + operation_id` from Plan 002 and keeps that identity across surfaces, docs, telemetry/audit, tasks, Graphify, and migrations.
2. **One state source.** CLI, GUI, Buddy, Wiki, and docs may format state differently, but must read the same revisioned runtime truth.
3. **One executor.** Every mutation reaches the same typed operation implementation and policy gates. Surface adapters must not contain shadow business logic.
4. **One durable task.** Every operation that can outlive an interaction frame returns a task/job ID and survives UI closure, process restart, or GUI-to-CLI switching.
5. **No false affordances.** Every visible enabled control has a real consumer, typed result, failure behavior, and test. A decorative control must look decorative; unavailable functionality must explain why.
6. **No false readiness.** `Ready` requires all declared prerequisites and probes for the selected setup. Failure leaves onboarding or repair active and preserves the last safe checkpoint.
7. **No manual dependency scavenger hunt.** User-selected capabilities may download managed components, models, or sidecars, but NEOTH owns discovery, verification, progress, configuration, and rollback. The only acceptable unavoidable user actions are explicit third-party sign-in/QR and OS permission prompts.
8. **Policy parity.** Permission, cost, secret, autonomy, sandbox, and audit/WAL gates are identical on all surfaces, including Buddy shortcuts and GUI restore actions.
9. **Release truth.** Generated surface bindings, capability lock, signed Graphify snapshot, packaged binaries/assets, Wiki/Obsidian export, and documentation describe the same exact release commit and digest.
10. **Interface switching preserves work.** Existing GUI-ready-token preference semantics remain intact, and active sessions/tasks can be resumed after switching.
11. **Fail closed on drift.** Unknown operation IDs, schema mismatches, stale capability digests, missing receipts, and incompatible checkpoints disable mutations with an actionable repair message.
12. **Public parity is generated and measured.** Counts are derived at build/test time; hard-coded counts in this plan are audit snapshots, not future truth.

## 4. Evidence-backed current-state audit

### 4.1 Inventory and positive foundations

- The committed CLI exposes roughly 135 top-level command variants in `SRC/neothd/src/cli/mod.rs`; the observed dirty self-knowledge wave raises that snapshot to roughly 136. Nested operations make the real public surface much larger.
- Generated CLI documentation already derives command structure from Clap in `SRC/neothd/src/cli/docgen.rs`. This is the correct anti-drift foundation and should feed the projection compiler instead of being replaced.
- The full GUI has 26 sidebar panels in `SRC/neothd-gui/ui/app_shell.slint`. Panel count is not a parity metric; an action palette and generated forms can cover long-tail operations.
- All 151 root Slint callbacks observed during the audit have Rust references when macro-generated handlers are included. This is a useful syntactic wiring floor, but a callback that only logs or changes a marker is not functional wiring.
- `SRC/neothd-gui/src/gui_action.rs` provides a strong fail-closed typed JSON subprocess boundary. Its mutation ACKs reject unknown fields, and tests pin a meaningful subset of checked actions. This should become a generated/exhaustive surface adapter, not be discarded.
- Existing GUI switching uses a private ready token and commits the interface preference only after the GUI proves readiness (`cli/gui.rs`, `cli/interface.rs`). WS-R4-03 is genuinely strong and must be preserved.
- Buddy activity is not a pure mock: daemon GUI streaming maps recent WAL events to mood, and the GUI polls the shared warm stream. This is a real base for contextual status.
- Main chat already supports streamed responses and attachments. The work is to unify it with sessions, routing, cancellation, Buddy, and typed errors, not replace it wholesale.
- The existing model manager and `neoth models` command provide lifecycle foundations that Plan 002 will expose as managed jobs.

### 4.2 Existing self-Wiki is a catalog, not a capability registry

`SRC/neothd/src/memory/self_wiki.rs` currently indexes four broad kinds: skill, cron, top-level CLI command, and slash command. It does not represent nested CLI operations, input/output schemas, runtime availability, prerequisites, permissions, cost/consent class, task state, GUI routes, Buddy actions, repair operations, or release asset ownership. Bundled skill descriptions are generic, so presence in the Wiki is not proof of utility or wiring.

`neoth capabilities` and the GUI Wiki consume this catalog. They are good discovery shells, but cannot answer the release-critical questions:

- Can I execute this here?
- Is it installed, authenticated, healthy, degraded, busy, or unavailable?
- What will it download or cost?
- What is the active task and can I cancel/resume it?
- What permission is required?
- Which exact release code and documentation implement it?
- What changed, and how do I repair or roll it back?

The observed uncommitted `neoth self-knowledge status|verify|query` work is a substantial native CLI foundation: it verifies and queries the release-bound Graphify snapshot (`SRC/neothd/src/cli/self_knowledge.rs`; `SRC/neothd/src/wiki/release_snapshot.rs`). No GUI or Buddy consumer was found. The current self-improve proposal schema is still skill-file-oriented and has no Graphify node IDs, capability/surface-lock diff, affected release assets, or migration projection (`SRC/neothd/src/self_improve.rs:247-309`). The feature therefore remains incomplete across surfaces even though the CLI foundation is real; implementation must project that foundation rather than rebuilding it.

### 4.3 CLI and GUI onboarding are different products

The CLI initializer contains a long, checkpointed sequence covering environment detection, experience/migration choice, identity, preset, provider/topology/local-model setup, channels, OMI, Keet, Obsidian, n8n, imports, companion/mobile, recommended installs, autonomy, updates, WASM, supervisor, and summary.

The GUI wizard owns a much smaller field snapshot and a different sequence. Its validation covers only a subset of the resulting runtime contract. Several built-in preset buttons jump directly to Done, although the UI copy says a preset configures autonomy, provider, and channel in one click. The underlying preset definitions primarily set autonomy, budget/caps, and feature flags; `local-sovereign` does not itself select and prove a local provider, while the GUI default remains `claude_cli`.

The GUI finish callback performs synchronous child-process work on the UI event path. More critically, the Slint Finish control calls `finish-clicked()` and then unconditionally navigates to Chat. Rust may report failure and return, but the UI still leaves onboarding. This creates a false-ready state.

`SRC/neothd/src/wizard/ipc.rs` defines step/progress messages but states that the MPSC wiring is missing, and no active consumer was found. It is an unwired protocol, not shared onboarding.

### 4.4 Chat contains confirmed false affordances

- The visible channel list is hard-coded to CLI, Telegram, and WhatsApp.
- Selecting a channel only logs the selection; it does not switch account, routing, transcript, or send behavior.
- Sending still invokes the same `neoth chat --stream` path without the selected channel.
- Session-card selection changes only the active marker/status; it does not load or resume the selected canonical session transcript.
- Slash-command autocomplete is advertised and a slash-active property exists, but the visible interaction is only a badge. No canonical picker is wired, despite the real slash dispatch/list already existing in CLI chat.
- A product-tour claim says every slash command has a panel twin. That is not proven and should be generated or removed.
- The user can only stop after a long stall threshold, not immediately while a normal request is running.
- child stderr is discarded in important chat paths, weakening diagnosability.

These are P0 because the UI implies that user intent has changed when runtime behavior has not.

### 4.5 Buddy is reactive, not yet a product companion

The CLI Buddy aggregates state and exposes only a small number of toggles. The GUI Buddy panel mainly configures behavior. The overlay exposes restore/hide/send and a one-line composer, but:

- it starts a separate minimal child process instead of attaching to the canonical conversation/task controller;
- it buffers the response instead of providing the same streaming experience;
- it discards stderr and lacks robust exit-status handling;
- it has no immediate cancel, attachment, voice/dictation, screenshot, approval queue, job view, or exact handoff;
- concurrent sends are not coherently controlled;
- it retains only a tiny local snippet history instead of canonical session history;
- its drag zone is explicitly not implemented;
- placement uses approximate dimensions and can clip under high DPI;
- no complete global-hotkey, tray, position persistence, or completion-notification contract was found.

The live mood/event stream should be kept and expanded. It is not evidence that Buddy can execute or supervise the underlying work.

### 4.6 Long-running progress is not a shared product primitive

GUI search found no common structured rendering for byte/step progress, phase, ETA/confidence, retry, cancel, pause/resume, logs, or repair. Existing installer/model paths mostly log to tracing or stderr. Some local-model paths rely on external tooling or implicit Hugging Face downloads, which Plan 002 correctly replaces with native managed jobs.

The GUI can show cached models but does not provide the complete pull/prune/repair/job lifecycle. This plan must render Plan 002 jobs consistently rather than add another downloader.

### 4.7 Public lifecycle operations are partial or surface-specific

- n8n is explicitly read-only in GUI and primarily status/list oriented in CLI.
- Mesh warns that auto-merge restore is incomplete.
- Companion reports that pairing status is not queryable.
- rollback restore is intentionally CLI-only even though GUI copy exposes the limitation.
- several panels represent configuration but not installation, authentication, readiness probing, repair, update, or uninstall.

Plan 002 owns completing those backend lifecycles. This plan owns making every resulting operation discoverable and safely executable on the required surfaces.

### 4.8 Accessibility and DAU gaps are release behavior

- Main GUI minimum width is approximately 820 pixels, which constrains small screens and split layouts.
- Overlay sizing/placement admits high-DPI clipping.
- keyboard-only navigation, focus restoration, screen-reader names/state, reduced motion, contrast, scalable text, and task notifications need exact tests rather than general claims.
- asynchronous operations currently risk freezing the event loop or silently running without visible state.

DAU-friendly means a non-technical user can install, choose a mode, understand waits, recover failures, switch surfaces, and finish a task without reading logs.

## 5. Findings and required dispositions

| ID | Severity | Confirmed gap | Impact | Required disposition | Confidence |
|---|---|---|---|---|---|
| SURF-01 | P0 | No actionable canonical projection maps public nested operations to CLI, GUI, Buddy, onboarding, state, gates, and docs. Existing self-Wiki is name-oriented. | Drift, partial adoption, untestable parity, stale claims. | Generate a surface-binding lock from Plan 002 descriptors plus Clap/config metadata; classify every public operation. | High |
| SURF-02 | P0 | CLI and GUI onboarding use different task graphs; wizard IPC is declared but unwired. | Setup results differ by chosen interface; resume/repair is unreliable. | One daemon-owned, versioned onboarding session/task graph with CLI and GUI renderers. | High |
| SURF-03 | P0 | GUI Finish navigates to Chat even if persistence/application fails. Presets can imply provider/channel readiness they did not prove. | False-ready and potentially unsafe/incomplete setup. | Transition only on a typed `Ready` receipt after probes; keep failed step active with repair. | High |
| SURF-04 | P0 | Chat channel tabs are hard-coded; switching only logs; sends ignore selection. | Messages can go through the wrong route while UI says otherwise. | Consume Plan 001 account/session routing; disable until real; test route/account binding on every send. | High |
| SURF-05 | P0 | No shared durable UI for installs/downloads/imports/model pulls/repairs and no immediate cancel contract. | Zero-friction fails; users cannot distinguish progress from a hang or recover safely. | Render Plan 002 `JobId` state everywhere; immediate cancel/attach/retry/resume. | High |
| SURF-06 | P1 | Session cards and slash discovery are cosmetic/partial. | History and commands appear available but do not perform claimed actions. | Load canonical sessions; generate slash picker from the real registry; delete unsupported claims. | High |
| SURF-07 | P1 | Buddy has live moods but is a separate weaker chat process with little actionability. | Companion cannot supervise or complete real work and diverges from main chat. | Attach Buddy to canonical sessions/tasks/approvals/jobs; provide exact GUI/CLI handoff. | High |
| SURF-08 | P1 | Lifecycle/configuration parity is incomplete; some operations are read-only or CLI-only. | GUI users cannot install, repair, restore, authenticate, or update features they can see. | Project all Plan 002 operations; apply equal confirmation/gate ceremony. | High |
| SURF-09 | P1 | Signed release Graphify/self-knowledge is provisional CLI-only work; GUI/Buddy/Wiki/Obsidian projection and self-improve review are missing. | NEOTH cannot reliably explain or safely modify itself across surfaces. | Bind exact-release knowledge to the surface lock, publish verified exports, and gate proposal/apply/undo. | High |
| SURF-10 | P1 | Accessibility, high-DPI overlay behavior, completion notifications, and responsive layouts lack release gates. | DAU experience fails on common desktop configurations and assistive input. | Add explicit accessibility/scale/keyboard/notification contracts and artifact-level tests. | Medium-high |

No roadmap item may be closed by replacing a false affordance with a disclaimer. Either wire the behavior, classify it as unavailable and disable it, or remove the public control/copy.

## 6. Canonical surface-projection design

### 6.1 Consume `CapabilityDescriptor`; do not fork it

Plan 002's `CapabilityDescriptor` remains authoritative for identity, lifecycle, prerequisites, install assets, availability, health, jobs, and adoption ownership. Plan 003 adds a versioned `SurfaceProjectionDescriptor` keyed by the same stable identity:

```text
SurfaceProjectionDescriptor
  schema_version
  capability_id
  operation_id
  visibility                 public | advanced | internal | unavailable
  interaction_class          instant | form | stream | durable_job | session | handoff
  cli                        route, aliases, input schema, output schema
  gui                        route, panel/form/palette action, focus target
  buddy                      inline action | quick action | exact handoff | hidden
  onboarding                 phase, condition, checkpoint ownership
  state_source               typed query + revision semantics
  task_binding               optional JobId/SessionId controller
  gate_contract              permission, consent, cost, secret, confirmation
  disabled_reason            machine code + localized copy key + repair operation
  success_receipt            typed schema and postcondition probe
  docs                       canonical page/anchor and copy keys
  accessibility              label, role, focus order, announcements
```

The descriptor must not duplicate secrets or dynamic runtime values. It states how a surface reaches and renders canonical behavior.

### 6.2 Required classifications

Every discovered operation receives exactly one release disposition:

- **Direct:** executable on that surface with the same typed inputs/results.
- **Guided:** the surface opens a generated form or multi-step flow, then executes the same operation.
- **Exact handoff:** Buddy or a compact surface opens the full GUI route or emits the exact CLI invocation while preserving task/session/capability context. Handoff is acceptable for complex operations; a dead-end instruction is not.
- **Internal/hidden:** not a user capability and omitted from marketing/discovery. It remains testable as internal code.
- **Explicitly unavailable:** a release/platform capability that cannot operate, with probe-derived reason and repair/alternative. It must be disabled, never simulated.

Public CLI and full GUI require execution parity through Direct or Guided mappings. Buddy requires inline parity for common/urgent actions and exact context-preserving handoff for advanced operations. A Buddy-only explanatory sentence is not parity.

### 6.3 Generated `surface-bindings-v1.json`

Build a deterministic release artifact from:

- Plan 002 capability lock/descriptors;
- recursive Clap command metadata, including nested operations and aliases;
- canonical configuration schema/metadata;
- GUI route/action declarations;
- Buddy quick-action/handoff declarations;
- slash-command registry;
- onboarding phase graph;
- signed release Graphify node IDs and docs anchors.

The generated artifact records:

- exact source commit and release version;
- capability-lock digest;
- Graphify snapshot digest;
- public/internal/unavailable disposition for every operation;
- surface coverage and test IDs;
- docs/copy ownership;
- platform restrictions.

Release CI fails on unclassified operations, orphaned visible controls, duplicated IDs, missing state sources, missing gate contracts, stale docs anchors, or digest mismatch. The artifact is packaged for runtime query and exported into Wiki/Obsidian.

### 6.4 One typed operation boundary

CLI, GUI, and Buddy should call the same Rust operation layer. Preserve the current typed JSON GUI action boundary as a compatibility adapter, but stop treating human CLI text as a machine protocol.

Preferred shape:

```text
surface input
  -> generated typed request
  -> CapabilityExecutor
  -> permission/cost/secret/confirmation gates
  -> instant receipt OR durable JobId/SessionId
  -> canonical state revision + WAL/audit receipt
  -> surface-specific rendering
```

If a subprocess boundary remains necessary, use a hidden versioned machine protocol with strict schemas, explicit exit status, structured stderr/error codes, request IDs, and capability-lock compatibility. Do not parse success from prose.

### 6.5 State and mutation semantics

- Queries return `{schema_version, capability_id, revision, observed_at, state, health, reason_codes}`.
- Mutations include the expected revision where race-sensitive and return a typed receipt.
- Receipts include operation ID, result/postcondition, resulting revision, audit/WAL correlation, task/session ID if applicable, and rollback/repair affordance.
- GUI and Buddy subscribe to state/task updates; polling is an explicit degraded fallback with freshness shown.
- A stale state never appears as current without a visible stale/offline marker.
- dangerous operations such as restore, credential replacement, channel reset, uninstall, self-modification, and destructive pruning use the same confirmation and recovery ceremony on GUI and CLI.

### 6.6 Discovery without 500 panels

Keep stable task-oriented panels for high-frequency workflows. Add a generated command/action palette for the complete public long tail:

- search by capability, operation, alias, symptom, or docs term;
- show availability, prerequisites, platform support, risk/gates, estimated download/cost, and current task;
- open the canonical form/panel or run an eligible instant operation;
- expose the exact CLI equivalent and docs/self-knowledge link;
- let Buddy invoke the same palette or hand off with context;
- never list internal commands as product functionality.

CLI receives symmetric discovery: `neoth capabilities`/self-knowledge should show the GUI path, Buddy availability, runtime status, required setup, and machine-readable operation schema.

## 7. Wiring and adoption ledger

This ledger is a release checklist. `Backend owner` prevents Plan 003 from duplicating Plans 001/002; `surface acceptance` is Plan 003's responsibility.

| Surface/capability | Current evidence | Backend owner | Required CLI projection | Required GUI projection | Required Buddy projection | Release acceptance |
|---|---|---|---|---|---|---|
| Capability discovery | Top-level self-Wiki/catalog; generated Clap docs | 002 + 003 projection | Recursive operations, live state, schemas, GUI/Buddy paths | Searchable action palette plus Wiki state | Search/quick action/exact handoff | Zero unclassified public operations |
| First run | Rich checkpointed CLI; smaller divergent GUI | 003 using 002 jobs | Render shared phases/checkpoints | Render same session and repair state | Show progress/approval; open exact step | Same result/probes regardless of surface |
| Reconfigure/repair | Scattered commands/panels | 002 lifecycle + 003 flow | `configure/status/repair` by capability | Installed-capability health and repair center | Alert, explain, retry/handoff | No reinstall needed for recoverable faults |
| Presets | Copy overstates provider/channel effects | 002 descriptors + config | Dry-run plan and explicit prerequisites | Preview exact changes/downloads/auth/probes | Recommend and open preview | No Ready until declared prerequisites pass |
| Provider/auth | CLI wizard broader than GUI | 002 | Typed provider/auth setup and probe | Provider picker, sign-in/secret ref, probe | Auth-needed alert/handoff | Secret-safe, tested provider call/probe |
| Local models/Hugging Face | CLI model lifecycle; GUI cached list only | 002 | Pull/list/prune/repair with JobId | Size/license/disk plan; progress/cancel/resume | Job progress, completion, retry | No external CLI prerequisite; verified assets |
| Chat streaming | Main GUI streams; overlay buffers | 003 | Canonical session stream/cancel | Same controller and transcript | Attach to same stream, immediate cancel | One request ID/session across surfaces |
| Chat sessions | Cards only mark active selection | 003 | List/open/resume/export canonical session | Load full transcript and routing context | Continue same session; new chat | Restart and cross-surface resume proof |
| Slash commands | Real CLI registry; cosmetic GUI affordance | 003 | Canonical list/execute/help | Generated picker with input forms | Search/invoke eligible commands | No advertised command without real dispatch |
| Channel/account routing | Hard-coded tabs; selection only logs | 001 | Account-aware status/select/send | Dynamic accounts, capabilities, transcript route | Status/quick reply/handoff | Send receipt proves selected account/route |
| WhatsApp/other migration | Needs OpenClaw parity | 001 | Import preview/apply/status/repair | Guided import, QR/auth, diff, progress | Notify required action and completion | Fixture parity and live probe per Plan 001 |
| Keet | Roadmap/backend work and stale GUI copy disagree | 001/002 | Probe/setup/status/send per real adapter | Registry-generated availability/copy | Status and exact action/handoff | No stale “unsupported” copy if artifact supports it |
| Obsidian/L6 preload | Existing setup/bootstrap surfaces | 002 | Install/config/status/update/uninstall | Vault picker, managed bootstrap/job, status | Search/open indexed note; job progress | Fresh-vault and existing-vault clean-machine tests |
| n8n | Read-only status/list surfaces | 002 | Full declared lifecycle from descriptor | Install/connect/auth/probe/workflow controls | Health/failure alert and open operation | No visible “integration” without operational path |
| Companion/mobile/OMI | Pairing status incomplete | 002 | Pair/status/revoke/repair | QR/pairing, permissions, live status | Pairing alert/handoff | Pair/restart/revoke state verified |
| Skills/plugins/presets | Catalog presence is not wiring proof | 002 | Install/config/enable/test/update/remove | Marketplace/library with managed jobs | Recommend/enable common; exact handoff | Every bundled/adopted item has probe and owner |
| Cron/automations | Typed GUI actions cover subset | 002 runtime + 003 projection | Full CRUD/test/pause/history | Full forms/status/history with policy state | Due/failure alert; pause/retry/inspect | Custom/autonomy semantics identical; fail closed |
| Security/permissions/cost | Strong backend gates exist in areas | Runtime + 003 | Typed prompt/receipt and audit link | Native confirmation/consent, no bypass | Approval queue and exact context | Same decision and audit correlation everywhere |
| Restore/rollback | Restore intentionally CLI-only | Runtime + 003 | Existing guarded ceremony | Same guarded operation and recovery preview | Alert/handoff; never silent execute | Equivalent safety; artifact restore test |
| Release self-knowledge | Provisional CLI status/verify/query | 003 + release pipeline | Verify/query/open/export exact snapshot | Search graph, route to code/docs/status | Explain current operation and open source/docs | Digest-bound Graph/Wiki/Obsidian parity |
| Self-improve/self-dev | Typed GUI mutations exist; knowledge review incomplete | Runtime + 003 | Propose/review/apply/verify/undo | Visual diff, tests/gates, approval, rollback | Propose/explain; approval/handoff | No autonomous apply without gates and reversible receipt |
| Job center | No shared complete renderer | 002 state machine + 003 renderer | `jobs list/watch/cancel/retry/resume/logs` | Global task center and inline progress | Current jobs, cancel/retry, notifications | Crash/restart and surface-switch continuity |
| Updates/installers | Release work in progress | 002 | Check/plan/apply/rollback with JobId | Native update UX and release notes/progress | Notify/open/update-later | Signed exact artifact; no external manual verifier |
| Accessibility/notifications | No complete gate | 003 | Accessible text/status and noninteractive modes | Keyboard, screen reader, scale, reduced motion | Hotkey, focus, position, private notifications | Automated + manual matrix on release artifacts |
| Docs/copy | Several stale/overbroad claims | 003 + 010 | Generated help links | Generated labels/availability/help | Generated explanation/handoff | Copy build fails when descriptor/route disappears |

## 8. Zero-friction user flows

### 8.1 Fresh install and first launch

1. Installer completes without asking the user to install a verifier, language runtime, package manager, or model CLI.
2. First launch creates one onboarding session with a versioned checkpoint ID.
3. If no interface preference exists, the release-level chooser asks GUI or CLI once. It explains that switching remains available at any time. Existing R4-03 ready-token semantics commit the choice only after the selected surface is healthy.
4. Environment detection records OS/architecture, GPU/CPU/RAM/disk, existing NEOTH/OpenClaw config, supported provider credentials by presence (never value), existing Obsidian vaults, local runtimes/services, and import candidates.
5. Offer three honest paths:
   - **Recommended:** safest low-friction setup for detected hardware and credentials.
   - **Local:** chooses and proves a genuinely local provider/model, including asset size/license/disk plan.
   - **Custom:** exposes all choices and consequences without weakening fail-closed policy.
6. Before mutation, show a generated plan: configuration changes, downloads, approximate sizes, sign-ins/QR/OS permissions, estimated time range, services, and rollback point.
7. Execute through Plan 002 jobs. GUI/CLI/Buddy show the same phase, progress, required action, and errors. Closing the UI does not abort unless the user explicitly cancels.
8. Perform real provider/model, channel/account, integration, and self-knowledge probes declared by selected capabilities.
9. Write the initialized/Ready marker only after the typed aggregate readiness receipt. A partially configured setup enters `Needs action` or `Degraded`, not `Ready`.
10. Show a concise completion page with working actions, pending optional capabilities, how to switch GUI/CLI, and how to open Buddy. Every link is executable.

### 8.2 Optional capability selected later

1. User clicks a capability in GUI, chooses it in CLI, or asks Buddy.
2. Surface reads the same descriptor and runtime state.
3. Show prerequisites, platform limits, disk/download/cost/permission implications, and whether external authentication is unavoidable.
4. User confirms once at the correct policy boundary.
5. Plan 002 creates a durable job and returns `JobId`.
6. Inline progress and global Job Center display phases such as download, verify, unpack, configure, start, authenticate, probe, and ready. Byte progress is used where measurable; step progress where not. Do not fabricate ETA.
7. User may cancel immediately. Safe cancellation rolls back incomplete staging; unsafe interruption explains the boundary and finishes/repairs atomically.
8. Restart or interface switch reattaches to the same job.
9. Success appears only after the postcondition probe and state revision. Failure shows exact reason, safe retry/repair, logs with secrets redacted, and rollback state.

### 8.3 GUI to CLI and CLI to GUI handoff

- `Open in CLI` copies/displays an exact invocation containing stable operation/task/session IDs, not secrets. If a terminal launcher is available, user explicitly launches it.
- `Open in GUI` resolves the canonical GUI route and focus target after the ready-token handshake.
- active chat session, selected channel/account, onboarding checkpoint, capability operation, and JobId survive the handoff.
- the receiving surface verifies capability/surface lock compatibility before mutation.
- if the other surface cannot start, preference and current work remain intact; the original surface shows repair guidance.

### 8.4 Reconfigure and repair

- Settings is generated from the same config metadata used by CLI, with secret references and policy-owned fields treated specially.
- Changing a setting produces a preview, validates cross-field requirements, and identifies affected capabilities.
- NEOTH applies atomically where possible, probes the result, and rolls back or enters explicit Degraded state on failure.
- Repair Center groups failures by actionable root cause, not by subsystem log source.
- `doctor`, GUI repair, and Buddy diagnosis use the same checks and receipts.

### 8.5 Self-knowledge and self-improve

1. Every real release contains the full signed Graphify snapshot, source map, surface binding lock, Wiki export, and Obsidian-ready export for the same commit/digests.
2. CLI, GUI, and Buddy verify those digests before presenting knowledge as exact-release truth.
3. User can ask what a capability does, where it is implemented, which operations call it, what gates protect it, its live status, and how to change it.
4. Answers link to exact Graphify nodes, local release docs/Wiki/Obsidian notes, GUI routes, and CLI operations.
5. Self-improve uses knowledge to create a proposal, never to silently edit the installed release. Proposal contains scope, affected graph nodes, risk, tests, capability/surface lock diff, migration/rollback, and expected new behavior.
6. Apply requires existing permission/autonomy gates and a visible diff/review. Build/tests and exact postcondition checks run before activation.
7. Failed verification restores the last working state. Successful activation emits a signed/auditable receipt and supports undo.
8. Generated self-knowledge is rebuilt after accepted changes; stale snapshots are visibly marked and cannot authorize further automated changes.

## 9. Buddy product contract

Buddy should match the useful desktop-companion expectations users already understand while staying local-first, policy-bound, and more operationally transparent. Current official ChatGPT desktop behaviors provide a practical benchmark: quick global access, file/screenshot context, continuation into the main app/history, remembered placement, streaming interruption, and background completion notifications. NEOTH should meet those interaction basics and exceed them with durable jobs, local integrations, explicit permissions, repair, and exact self-knowledge.

Benchmark sources, used only for interaction expectations rather than as NEOTH implementation authority:

- [Using the ChatGPT Windows app](https://help.openai.com/en/articles/9982051-using-the-chatgpt-windows-app): companion shortcut, files, conversation continuation, and window position.
- [Work with Apps on macOS](https://help.openai.com/en/articles/10119604): application context and review/apply/undo interaction.
- [Desktop app release notes](https://help.openai.com/en/articles/9703738-desktop-app-release-notes): background completion notifications, streaming interruption, screenshots, and sharing shortcuts.
- [Launching the Chat Bar](https://help.openai.com/en/articles/9295241-how-to-launch-the-chat-bar): compact access, movement, files, photos, and screenshots.

### 9.1 Required Buddy capabilities

- configurable global hotkey with conflict detection and an accessible alternative;
- tray/menu presence where supported, with clear running/privacy state;
- remembers monitor, position, size, and expanded/collapsed state safely across DPI/layout changes;
- uses the same canonical conversation/session store as main GUI and CLI;
- new chat, recent sessions, search, and exact `Open in full GUI`/`Continue in CLI` handoff;
- true streaming with immediate stop/interrupt and clear queued/running state;
- drag/drop, clipboard paste, file picker, and screenshot attachment through the same attachment policy as main chat;
- voice/dictation only where the descriptor reports installed/available, with download/setup progress if needed;
- selected channel/account and routing shown before a send; compact mode may hand off complex channel configuration;
- approval/consent/cost queue with enough context to decide safely and a link to full details;
- active integration/model/install/import/update jobs with progress, retry, cancel, and completion/error notifications;
- proactive alerts grounded in canonical runtime state, never invented recommendations or repeated nagging;
- quick actions generated from the surface projection, including status, pause automation, retry failed job, open repair, and inspect audit;
- current operation explanation from verified release self-knowledge, including exact code/docs links;
- self-improve proposal explanation and diff review handoff, but no weaker approval path;
- privacy-safe notifications that redact prompt, filename, contact, secret, and sensitive result content by default;
- offline/degraded/stale-state indicators and recovery rather than silent failure.

### 9.2 Buddy architecture rule

Remove the separate weak overlay chat implementation as an execution path. The overlay becomes a compact renderer/controller attached to the same conversation stream, child/task ownership, error channel, attachments, and cancellation as the main GUI. Daemon-owned work continues if the overlay closes. Reopening Buddy or switching surfaces attaches by session/task ID.

Keep and enrich the existing activity mood stream, but treat mood as presentation derived from typed events. It must never be the only representation of a failure, approval, or long-running job.

## 10. Ordered implementation slices

Each slice ends with tests and a shippable rollback boundary. Do not start downstream UI wiring on unstable upstream schemas.

### Slice 0 — freeze truth and remove false claims

1. Inventory recursive Clap operations, slash commands, config fields, GUI routes/callbacks/controls, Buddy actions, onboarding steps, and current Wiki nodes.
2. Mark each as public, advanced, internal, or unavailable; identify its canonical capability/operation owner.
3. Immediately disable or remove controls whose only effect is logging/marker changes, including fake channel switching and fake session loading, until their real wiring lands.
4. Correct preset, Keet, slash-panel, Ready, and lifecycle copy from descriptor-backed truth.
5. Add an orphan-control and stale-copy CI report before changing architecture.

Exit: no enabled control knowingly lies about its effect; the complete gap set is machine-readable.

### Slice 1 — surface binding compiler and release lock

1. Extend Plan 002's generation pipeline with `SurfaceProjectionDescriptor` and deterministic `surface-bindings-v1.json`.
2. Recursively extract Clap operations and aliases; bind canonical input/output metadata.
3. Register GUI routes/actions/forms and Buddy inline/handoff mappings.
4. Register state source, gate contract, task binding, success receipt, docs anchor, and accessibility metadata.
5. Fail generation for duplicate/unclassified/unowned operations or visible orphan controls.
6. Include commit/version/capability-lock/Graphify digests and package the result.

Exit: all committed-baseline public operations are classified; counts are generated; internal commands cannot leak into marketing.

### Slice 2 — shared typed executor and state subscriptions

1. Introduce/finish the common typed operation layer beneath CLI/GUI/Buddy.
2. Preserve `gui_action` as a strict adapter; migrate handlers from handwritten arg assembly to generated typed requests.
3. Add versioned machine transport only where an in-process call is impossible.
4. Standardize state revisions, receipts, error codes, audit correlations, and redaction.
5. Provide subscription with freshness and bounded reconnect; polling remains an explicit fallback.
6. Generate tests that invoke each mutation through every declared surface adapter and compare gates/postconditions.

Exit: no GUI/Buddy mutation depends on human stdout or bypasses production gates.

### Slice 3 — Plan 002 Job Center and progress everywhere

1. Add a shared task controller/client over Plan 002 durable jobs.
2. Implement CLI `jobs` watch/list/cancel/retry/resume/logs with machine and human output.
3. Add GUI global Job Center plus inline progress components.
4. Add Buddy current-job cards, completion/failure notifications, and exact handoff.
5. Handle app close/restart, daemon restart, network loss, stale job leases, cancellation boundaries, and secret-redacted logs.
6. Convert model pulls, optional downloads, installers, imports, updates, migrations, Obsidian preload, and repairs as Plan 002 exposes them.

Exit: every operation classified `durable_job` is visible, cancellable where safe, resumable/retriable as declared, and never represented only by a spinner/log.

### Slice 4 — one onboarding/reconfigure/repair graph

1. Replace divergent wizard control flow with one versioned daemon-owned onboarding session.
2. Reuse/replace the unwired wizard IPC with the canonical task/event protocol; remove dead declarations once migrated.
3. Define conditional phases from selected capability prerequisites and detected environment.
4. Make CLI and GUI renderers consume identical phase schemas, validation, checkpoints, jobs, required user actions, and aggregate readiness.
5. Make presets produce an explicit plan; ensure Local selects and proves local execution rather than inheriting `claude_cli`.
6. Transition to Chat/Home only after a typed Ready receipt; failure remains on the exact step.
7. Implement reconfigure and Repair Center on the same graph.

Exit: a fixture matrix produces identical final configuration/state from CLI and GUI; kill/resume works at every phase; no false Ready.

### Slice 5 — canonical conversations, sessions, slash actions, and channels

1. Introduce one conversation task/session controller for CLI, main GUI, and Buddy.
2. Wire session selection to load/resume the actual transcript, attachments, model/provider context, and route.
3. Generate slash discovery/forms from the real registry.
4. Add immediate cancel/interrupt and structured errors without discarding stderr evidence.
5. Replace hard-coded channel tabs with Plan 001 dynamic account/session projections.
6. Bind each send to selected account/route and show the resulting receipt; unavailable capabilities are disabled with probe-derived reasons.
7. Preserve channel/session/task context across GUI/CLI/Buddy handoff.

Exit: no cosmetic chat/session/channel control remains; route-binding tests prove sends use the displayed selection.

### Slice 6 — full GUI parity without sidebar explosion

1. Keep high-frequency task panels; add generated global action palette and typed forms for the long tail.
2. Project every public lifecycle operation from Plan 002: install, configure, authenticate, probe, start/stop, status, update, repair, and uninstall as applicable.
3. Close read-only/CLI-only gaps or classify genuine platform limitations explicitly.
4. Give dangerous operations equal preview, confirmation, audit, and rollback ceremony.
5. Generate CLI equivalents and docs/self-knowledge links in every form.
6. Add per-capability health and repair entry points.

Exit: every public CLI operation has a Direct/Guided full-GUI mapping and identical postcondition, or is reclassified internal/unavailable with release evidence.

### Slice 7 — Buddy as a first-class companion

1. Rebuild overlay execution on the canonical conversation/task controller.
2. Implement hotkey, placement persistence, multi-monitor/DPI clamping, tray/menu, focus restoration, and immediate cancel.
3. Add sessions, attachments, screenshot, optional voice/dictation, approvals, job cards, channel state, quick actions, and privacy-safe notifications.
4. Generate actions and disabled reasons from surface bindings.
5. Implement exact handoff to full GUI/CLI for advanced flows without losing context.
6. Keep mood/activity as an accessible secondary signal backed by typed events.

Exit: Buddy completes the common-task benchmark and never uses a weaker policy, chat, error, or task path.

### Slice 8 — signed release self-knowledge across all surfaces

1. Complete exact-release Graphify snapshot generation and verification.
2. Bind Graphify nodes to capability/operation IDs, GUI routes, CLI commands, config schema, tests, ownership, gates, and docs.
3. Generate and package Wiki plus Obsidian-ready exports from the same digests.
4. Add GUI graph/search/status/progress/open actions and Buddy query/explain/handoff.
5. Show verification/staleness state on every surface.
6. Wire self-improve proposal/review/test/apply/verify/undo to existing safety gates and surface-lock diffs.
7. Fail release if packaged Graphify/Wiki/Obsidian/surface bindings do not match exact commit/artifacts.

Exit: NEOTH can accurately explain its own exact installed release everywhere; self-modification is reviewed, tested, auditable, and reversible.

### Slice 9 — DAU, accessibility, packaging, and truth sweep

1. Run keyboard-only, screen-reader, contrast, reduced-motion, text-scale, 100–300% DPI, small-window, multi-monitor, offline, proxy, slow-network, disk-full, interrupted-download, and reboot matrices.
2. Ensure asynchronous work never blocks the UI event loop.
3. Generate/update README, CLI docs, screenshots/SVGs, Wiki, launch copy, and help from verified release truth.
4. Execute Plan 002 clean-machine artifact tests and Plan 001 channel fixtures.
5. Verify exact-head CI, security, CodeQL, release archive/installers, first run, update, rollback, uninstall, and self-knowledge digests.

Exit: release candidate is install-and-go on supported platforms and all public copy matches observable behavior.

## 11. Test and release gates

### 11.1 Registry/projection completeness

- recursively enumerate every Clap operation, alias, slash command, public config operation, GUI action/control, Buddy action, and onboarding phase;
- assert exactly one capability/operation identity and disposition;
- assert every public CLI operation has Direct/Guided GUI execution mapping;
- assert every Buddy operation is inline or exact handoff;
- assert internal/unavailable items are not advertised as ready;
- assert no visible enabled control lacks a state source, consumer, typed receipt, and test ID;
- assert no copy key references a removed/unavailable operation without disabled wording;
- snapshot generated counts, but compare sets/digests rather than preserving today's 135/136 command number.

### 11.2 Cross-surface contract tests

For each mutation class, execute equivalent requests through CLI, GUI adapter, and Buddy adapter where declared and assert:

- identical permission/cost/secret/confirmation decision;
- identical request binding and effective inputs;
- identical postcondition probe and resulting state revision;
- identical typed error code for invalid/unavailable operations;
- audit/WAL receipt correlation;
- no secrets in process args, logs, notifications, or generated handoff command;
- stale schema/digest fails closed.

### 11.3 Onboarding matrix

At minimum:

- clean Windows GUI and CLI;
- clean Linux GUI and CLI where GUI artifact supported;
- macOS GUI and CLI where supported;
- recommended cloud-provider setup;
- local CPU-only and supported GPU setup;
- existing OpenClaw import;
- existing NEOTH reconfigure/repair;
- offline/temporarily unavailable download;
- auth/QR canceled and resumed;
- disk-full, checksum failure, process crash, reboot, and rollback;
- express preset and custom setup;
- `local-sovereign` proves no unintended cloud egress;
- Finish failure stays in wizard and does not write Ready/initialized.

Each CLI/GUI pair must converge to the same canonical state and probe receipts.

### 11.4 Chat/channel/session tests

- dynamic channels/accounts come only from Plan 001 registry;
- selecting a channel changes canonical route/account and transcript context;
- every send receipt proves displayed route/account binding;
- unavailable/reauth/degraded states disable or gate sending correctly;
- selecting a session loads and resumes the canonical transcript across process restart;
- slash picker exactly matches the canonical registry and dispatches typed operations;
- immediate cancel works during normal streaming, not only after a timeout;
- main GUI, CLI, and Buddy attach to the same session/request stream;
- attachments follow capability limits and redaction policy;
- stderr/transport errors become typed user-visible failures.

### 11.5 Durable-job tests

- known byte length: byte progress is monotonic and reaches verified completion;
- unknown length: honest phase/step progress without fake percentage/ETA;
- cancel at every phase leaves a documented safe state;
- kill GUI/CLI/Buddy and reattach by JobId;
- reboot/daemon restart recovers leases and never duplicates side effects;
- retry is idempotent or requires explicit repair where not;
- success requires postcondition probe; failure never becomes Ready;
- logs and notifications are secret-safe;
- multiple concurrent jobs render and arbitrate resource conflicts correctly.

### 11.6 Buddy acceptance

- global hotkey conflict, invocation, focus, and accessible fallback;
- window position/size persistence and clamping at 100%, 150%, 200%, and 300% DPI across monitor changes;
- canonical new/recent/resume session behavior;
- streaming, immediate cancel, attachments, clipboard, screenshot, and optional voice availability;
- approval/consent/cost decision equality with full surfaces;
- active-job progress, retry, cancel, and private completion notification;
- channel/account visibility and correct send routing;
- exact full-GUI/CLI handoff preserving session/task/operation;
- crash of Buddy does not kill daemon-owned task or corrupt session;
- no notification leaks sensitive content by default.

### 11.7 Accessibility and interaction gates

- every interactive control has name, role, state, keyboard path, and visible focus;
- focus returns predictably after dialogs, handoffs, errors, and task completion;
- progress and state changes are announced without flooding;
- color is never the only state signal;
- text remains usable under OS scaling and large fonts;
- reduced motion is honored;
- small window/split screen reflows rather than clipping critical controls;
- confirmation dialogs state scope, consequence, and rollback in plain language;
- long-running work does not block event processing.

### 11.8 Release-artifact truth gates

- exact tag/version/commit across binaries and manifests;
- capability lock, surface binding lock, Graphify snapshot, Wiki export, Obsidian export, docs, and packaged assets share recorded digests;
- every packaged binary can verify/query the installed locks offline;
- installer exposes the same first-run path on a clean machine;
- no external manual verifier/runtime/package-manager/model-CLI prerequisite;
- update and rollback preserve compatible sessions/jobs/config or migrate them transactionally;
- exact-head CI, Security, CodeQL, clean-machine installers, channel fixtures, surface parity, and self-knowledge verification are visibly green before tag.

## 12. STOP conditions

Stop the affected release slice and do not mark roadmap completion when any condition holds:

1. Plan 002's capability/job identity or state contract is still changing incompatibly; stabilize it before generating surface bindings.
2. Plan 001's account/channel/route model is absent; keep channel controls disabled instead of wiring a second model.
3. Any public operation has no capability/operation owner or surface disposition.
4. Any visible enabled control only logs, toggles local appearance, updates a marker, or claims success without runtime postcondition.
5. Any GUI/Buddy mutation bypasses a CLI/runtime gate, parses free-form success text, or cannot produce a typed receipt.
6. Any long-running operation lacks honest progress/state plus declared cancel/retry/resume semantics.
7. Onboarding can write Ready/initialized or navigate to the normal product without required probes.
8. A preset name/copy promises a provider, channel, privacy mode, or capability it does not configure and verify.
9. Chat can display one channel/account/session while sending or loading another.
10. Buddy uses a separate weaker execution, policy, session, error, or task path.
11. Release Graphify/Wiki/Obsidian/surface lock digest does not match the exact packaged source/artifact.
12. Self-improve can apply without reviewable diff, gates, tests, postcondition verification, audit receipt, and undo.
13. Required clean-machine work depends on undocumented/manual external tooling.
14. Accessibility/high-DPI tests reveal unreachable approval, cancel, repair, or setup controls.
15. README/docs/tour/Wiki claim functionality not demonstrated by artifact tests.
16. Exact-head CI, Security, CodeQL, installer, migration, parity, or artifact verification is red or unavailable.
17. Evidence exists only in the dirty worktree. Dirty WIP is never enough to close R4 checkboxes or cut a tag.

## 13. Rollout and rollback

### 13.1 Safe rollout

1. Generate the surface manifest in shadow mode and diff it against the legacy CLI/GUI/Buddy inventory.
2. Add completeness reports without initially changing execution.
3. Migrate read-only queries first, then low-risk instant mutations, then durable jobs, onboarding, chat/channels, dangerous restore/self-improve operations.
4. Gate new rendering with a temporary `surface_registry_v1` compatibility flag during development only.
5. Run legacy and new adapters against the same fixtures and compare state/gates/receipts.
6. Remove legacy paths and the flag before Gold; v1.0 must not ship two divergent product contracts.

### 13.2 Runtime rollback rules

- On surface-lock mismatch, read-only diagnostics may fall back with a prominent stale state; mutations fail closed.
- Existing R4-03 interface preference/ready-token behavior remains the rollback boundary for GUI startup.
- On Buddy/GUI crash, daemon-owned tasks and sessions continue and can be attached from CLI.
- Wizard checkpoints are schema-versioned. Migration failure preserves the previous checkpoint/config and opens repair; it never silently restarts or marks Ready.
- Plan 002 owns atomic adoption/config/job rollback. Surfaces display its actual rollback result, not an optimistic local message.
- A failed self-improve activation restores the last verified code/config/locks and marks the proposal failed with evidence.
- A failed update preserves the previous exact release including matching Graphify/Wiki/Obsidian/surface locks.

## 14. Principal risks and mitigations

| Risk | Why it matters | Mitigation |
|---|---|---|
| Registry becomes a second source of truth | Creates the drift this plan is meant to remove. | Projection references Plan 002 identities and generated source metadata; it does not redefine lifecycle/business rules. |
| “Parity” causes 500 bespoke screens | Unmaintainable GUI and poor navigation. | Stable high-frequency panels plus generated palette/forms and explicit internal classifications. |
| Machine protocol remains CLI text | Localization/copy changes break runtime wiring. | Strict versioned typed requests/receipts and common executor. |
| UI migration breaks strong existing gates | Security regression hidden by polish. | Cross-surface gate/receipt differential tests; preserve typed `gui_action` semantics while migrating. |
| Durable task framework expands scope | Large cross-cutting change. | Plan 002 owns it; Plan 003 only consumes/renders it and sequences UI after schema stability. |
| Buddy becomes a second app/runtime | Sessions, policies, and failures diverge. | Compact renderer attached to canonical controller; exact handoff for complex work. |
| Generated copy feels generic | DAU quality suffers. | Descriptor-backed state plus curated localized copy keys; generation enforces ownership, not prose quality. |
| Self-knowledge is trusted when stale | Wrong self-modification or support guidance. | Exact digest verification, visible staleness, fail-closed mutation, signed/auditable proposal lifecycle. |
| Hidden platform limitations surface late | “Works everywhere” release claim fails. | Platform dispositions and clean-machine artifact matrices before docs/launch. |
| Concurrent dirty work is mistaken for completion | Roadmap becomes dishonest again. | Exact committed baseline, artifact gates, and no completion checkbox without remote exact-head evidence. |

## 15. Definition of Done

This plan is done only when all conditions are evidenced on the exact release candidate:

- [ ] A deterministic `surface-bindings-v1.json` is generated, packaged, and digest-bound to the exact capability lock, Graphify snapshot, version, and commit.
- [ ] Every recursive public CLI operation, slash command, public config/lifecycle operation, GUI action/control, Buddy action, and onboarding phase has exactly one stable capability/operation identity and disposition.
- [ ] There are zero unclassified public operations and zero visible enabled orphan controls.
- [ ] Every public CLI operation has full-GUI Direct/Guided execution parity; internal/unavailable exceptions are explicit, evidence-backed, and absent from misleading marketing.
- [ ] Buddy completes common actions inline and hands advanced actions off exactly with preserved session/task/operation context.
- [ ] CLI, GUI, and Buddy mutations use the same typed executor, gates, postcondition, state revision, and audit receipt.
- [ ] No machine path parses human stdout as proof of success; errors are typed and stderr evidence is not silently discarded.
- [ ] One versioned onboarding session/task graph serves CLI and GUI, supports checkpoint/resume/repair, and converges to the same state.
- [ ] Presets preview exact effects/prerequisites; Local proves local execution; failure never navigates away or writes Ready.
- [ ] Plan 002 jobs render honest phase/byte/step progress, required action, cancel, retry, resume, logs, and postcondition state in CLI, GUI, and Buddy.
- [ ] Chat channel/account tabs are dynamic from Plan 001 and every send receipt proves the displayed route binding.
- [ ] Session selection loads/resumes canonical transcript and context; slash picker is generated from the real registry; cancellation is immediate during normal streaming.
- [ ] Main GUI, CLI, and Buddy use the same conversation/session/task controller and attachments policy.
- [ ] Buddy has tested hotkey, focus, placement/DPI persistence, sessions, attachments/screenshot, immediate cancel, approvals, jobs, private notifications, channel state, and exact handoff.
- [ ] All Plan 002-installed/adopted capabilities expose their declared install/config/auth/probe/status/update/repair/uninstall lifecycle on required surfaces.
- [ ] Dangerous restore, credential, uninstall, prune, and self-improve operations have equal confirmation, permission, audit, and rollback ceremony across surfaces.
- [ ] Every real release contains complete verified Graphify, source map, surface lock, Wiki export, and Obsidian-ready export for the same exact commit.
- [ ] CLI, GUI, and Buddy can status/verify/query/open that self-knowledge and clearly mark stale/unverified states.
- [ ] Self-improve is proposal-first, reviewable, gated, tested, postcondition-verified, auditable, and reversible; it cannot silently mutate a release.
- [ ] Accessibility, keyboard, screen-reader, reduced-motion, large-text, small-window, 100–300% DPI, multi-monitor, offline, slow-network, interrupted-job, and reboot matrices pass.
- [ ] Clean Windows/macOS/Linux release artifacts install and reach their selected Ready state without manual external dependency installation, subject only to explicit sign-in/QR/OS permission actions.
- [ ] README, generated CLI docs, GUI tour/copy, Wiki, Obsidian export, screenshots/SVGs, and launch material are regenerated from and agree with the verified release truth.
- [ ] Exact-head CI, tests, Security, CodeQL, Plan 001 channel fixtures, Plan 002 clean-machine/adoption tests, parity tests, and self-knowledge artifact verification are visibly green.
- [ ] No WS-R4 completion claim relies solely on local dirty work, an unpushed commit, a source-only implementation, or an environment-limited test result.

Only after every checkbox is proven may WS-R4-04, WS-R4-05, WS-R4-06, and WS-R4-09 be marked complete and the v1.0.0 tag proceed.
