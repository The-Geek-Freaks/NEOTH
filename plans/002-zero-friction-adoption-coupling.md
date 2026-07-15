# Plan 002: Make every public NEOTH adoption installable, coupled, observable, and reversible in v1.0

> **Executor instructions**: Read this whole plan before editing. Execute the
> phases in order and run every verification gate. This is a v1.0 release
> blocker, not a future-feature list. A feature is not complete when a parser,
> installer hint, downloaded file, config field, or process exists; it is
> complete only after the exact released artifact can discover, acquire,
> verify, materialize, configure, start, authenticate/probe, report, repair,
> update, and safely uninstall it through the same runtime contract.
>
> Do not invent success. A capability with a missing binary, mutable upstream,
> failed probe, unavailable account/device prerequisite, or incomplete binding
> must remain visibly unavailable or failed. Do not silently degrade to a
> different product or weaken a permission/security boundary.
>
> The reviewer who dispatched this plan maintains the plans index. Do not
> create or edit plans/README.md.
>
> **Drift check (run first)**:
>
>     git diff --stat 19f74b228cc6d43fc2542922bbc28e324ba52ac6..HEAD -- SRC/neothd SRC/neothd-gui SRC/neoth-migrate bridges L6_Vault_Template packaging .github/workflows README.md docs PLAN
>
> The plan was written while the worktree also contained an uncommitted
> release/self-knowledge integration wave. Compare every cited current-state
> seam with live source. If a cited gap was independently closed, retain its
> contract and tests but do not duplicate the implementation. If the canonical
> registry, release layout, or security boundary has materially changed, STOP
> and ask the integrator to rebase this plan.

## Status

- **Priority**: P1 / v1.0.0 tag blocker
- **Effort**: L (multi-wave; commit and verify each phase)
- **Risk**: HIGH (installation, third-party supply chain, config, subprocesses,
  mobile distribution, and cross-platform packaging)
- **Depends on**: the in-flight release self-knowledge and clean-machine
  foundation; plan 003 consumes this plan's capability/job API for full
  GUI/CLI/Buddy parity
- **Category**: direction, security, migration, dx, tests, docs
- **Planned at**: commit 19f74b228cc6d43fc2542922bbc28e324ba52ac6,
  2026-07-15
- **Scope milestone**: v1.0.0 GOLD; no historical v1.1/post-Gold label may defer
  a retained public adoption

## Why this matters

NEOTH already contains substantial runtime implementations, but its public
adoptions do not share an end-to-end installation and coupling contract. Some
wizard flags record intent, some installers print an external command, some
sidecars fetch on first process spawn, some assets exist only in the source
tree, and several GUI/Buddy paths cannot show the only progress or error
stream. This makes a feature-rich source checkout look complete while a normal
release user still has to discover and repair hidden prerequisites.

This plan turns every retained public capability into one truthful product
contract. Small resources ship in the release; large or license-constrained
resources download on demand from a release-locked manifest. Every surface
observes one durable job, every mutation uses the same permissions and audit
rails, every config write is lossless and atomic, and Ready means an
authenticated capability-specific probe succeeded.

## Non-negotiable product contract

The authoritative Road-to-Gold document states at
PLAN/ROAD_TO_1_0_GOLD.md:13 that every implementation/adoption task in the
document is v1.0 GOLD scope. It defines the completion sequence at
PLAN/ROAD_TO_1_0_GOLD.md:156-161 as:

    install/download
      -> verify
      -> materialize bundled assets
      -> persist lossless config/presets
      -> start/supervise
      -> authenticated readiness probe

The durable user-visible states are:

    queued
    downloading or running with byte/step progress
    validating
    configuring
    ready
    failed
    cancelled
    resumable retry

Apply that lifecycle to every row in the adoption matrix below. A provider
login, channel QR scan, mobile OS permission, or external account credential
can remain an unavoidable human action, but NEOTH must install all software it
claims to manage, explain the one remaining human action, verify it, and
continue automatically. No user-facing instruction may merely say to install
Docker, Node, Python, pip, npm, npx, minisign, cosign, an AppImage, or a sidecar
manually.

## Current state

### Foundations to reuse, not replace

- SRC/neothd/src/wizard/install_step.rs:32-48 defines typed installer outcomes.
  Lines 89-344 implement Winget, Chocolatey, apt, dnf, pacman, and Homebrew
  adapters. Lines 348-393 centralize subprocess execution and stderr capture.
  Lines 440-520 provide the fallback chain and InstallerRanPayload audit shape.
  Extend this substrate with progress/cancellation and managed-artifact
  providers; do not create another unrelated package-manager layer.
- SRC/neothd/src/wizard/ipc.rs:36-91 defines the shared wizard step registry and
  progress model, including Install. Lines 159-189 already model cancellation
  and state mutation. The integration job API must be the durable backend for
  both CLI and GUI wizard presentations.
- SRC/neothd/src/media/model_manager.rs:198-244 and 279-525 already implement
  a fail-closed ModelDownloadAttempt, pending-state binding, audit-before-
  network behavior, validation, and recovery. Its module header states that
  hf-hub is the sole model downloader with range resume. Generalize its
  observer/receipt behavior; do not reintroduce huggingface-cli.
- SRC/neothd/Cargo.toml:529 and :577 already include reqwest and hf-hub with
  rustls. Native model acquisition needs no Python or Hugging Face CLI.
- SRC/neothd/src/cli/obsidian.rs:1731-1957 implements manifest-driven,
  hash-idempotent, contained, transactional Obsidian/L6 preload and optional
  ingest. Lines 3014-3155 and 3409-4394 contain strong copy, provenance,
  idempotency, reconciliation, restricted-scope, and escape tests. Preserve
  this implementation and add packaging/application/plugin coupling around it.
- L6_Vault_Template/preload_manifest.yaml:1-119 is the operator-curated
  manifest. It is a release resource candidate, not a path the installed
  product may assume exists on the developer machine.
- SRC/neothd/src/channels/mod.rs:205-267 defines ChannelKind, but
  SRC/neothd/src/channels/probe.rs:218-233, SRC/neothd-gui/src/panel_logic.rs,
  and SRC/neothd-gui/ui/settings.slint independently enumerate the same public
  adapters and aliases. Treat this as drift evidence: the Plan 001
  ChannelDescriptor/capability catalog must generate probes and all surface
  pickers/forms instead of preserving several handwritten registries.
- SRC/neothd/Cargo.toml:46-55 defines release-server and release-desktop
  feature bundles. The current dirty worktree adds Matrix, IRC, Nostr, Google
  Chat, clipboard, and the WASM host to those bundles. Final artifact tests
  must prove, rather than assume, that each target uses the right bundle.
- SRC/neothd/src/wal/events.rs:20-68 says the top-level WAL byte space is full
  and new events must use ExtendedSubtype. EVENT_TYPE_INSTALLER_RAN already
  exists at :410. Reuse InstallerRanPayload for package-manager terminal
  receipts and allocate an append-only extended integration-job subtype only
  for lifecycle transitions that do not fit it.
- SRC/neothd/src/daemon/kanban_sse.rs:72-249 and
  SRC/neothd/src/cli/serve_tasks.rs:3610-3649 demonstrate the existing
  broadcast/SSE pattern. Reuse the bounded broadcast-plus-durable-snapshot
  shape for integration progress instead of polling child stderr from each UI.
- SRC/neothd/src/config/preset_builtins.rs:32 pins four freedom presets, while
  SRC/neothd/src/profile/presets.rs:27-207 pins five behavioral presets.
  SRC/neothd/src/cli/preset.rs and GUI callbacks around
  SRC/neothd-gui/src/main.rs:10115-10380 already apply them. Presets need
  capability prerequisites and transactional rollback, not a third preset
  implementation.

### Confirmed gaps

#### [DIRECTION-01] Establish one adoption lifecycle

- **Evidence**: there is no CapabilityDescriptor, IntegrationJob, or equivalent
  shared lifecycle registry in SRC/neothd. The Road-to-Gold correction at
  PLAN/ROAD_TO_1_0_GOLD.md:156-193 explicitly requires one completion sequence
  and progress/cancel/retry parity.
- **Impact**: each installer, GUI callback, Buddy action, model path, and
  sidecar independently decides what complete means. A download or config write
  can be mistaken for readiness and failures disappear between surfaces.
- **Effort**: L.
- **Risk**: HIGH; it becomes the release installation control plane.
- **Confidence**: HIGH; searched the source registry and all installer modules.
- **Fix sketch**: add one typed capability catalog, durable job store, state
  machine, artifact ownership ledger, orchestrator, and read-only event/status
  API. Adapt existing installers incrementally.

#### [BUG-01] Replace intent-only wizard choices with real jobs

- **Evidence**: SRC/neothd/src/cli/init/steps_topology.rs:965-1072 records or
  prints the Qwen download path, including an external huggingface-cli/pip
  instruction. SRC/neothd/src/cli/init/steps_channel.rs:87-150 does not execute
  Obsidian installation, while :266-300 prints n8n prerequisites/commands.
  Tests at SRC/neothd/src/cli/init.rs:2530-2690 assert recorded intent rather
  than installed readiness.
- **Impact**: --download-qwen-weights, --install-obsidian, and --install-n8n
  can exit successfully without the selected capability existing.
- **Effort**: M after the shared lifecycle exists.
- **Risk**: MED; non-interactive scripts depend on exit semantics.
- **Confidence**: HIGH.
- **Fix sketch**: enqueue the real capability job, wait by default, return a
  job id only with an explicit --background flag, and exit non-zero unless the
  job is Ready.

#### [BUG-02] Preserve model progress and failures in all surfaces

- **Evidence**: SRC/neothd/src/cli/models.rs:34-82 exposes pull for CLIP and
  Whisper but intentionally excludes Qwen. SRC/neothd/src/installers/
  qwen_weights.rs:1-18 shells out conceptually to Hugging Face CLI even though
  the native runtime already uses hf-hub. The current GUI has model selection
  but no model pull/prune/job panel. Buddy/companion subprocess creation around
  SRC/neothd-gui/src/main.rs:7239-7300 sends stderr to Stdio::null and retains
  no cancellable child/job handle.
- **Impact**: large model downloads look frozen, cannot be cancelled or resumed
  from GUI/Buddy, and their only diagnostic stream may be discarded.
- **Effort**: M.
- **Risk**: MED; partial-cache correctness and concurrent first-use races.
- **Confidence**: HIGH.
- **Fix sketch**: route Qwen, Ouro, CLIP, Whisper, Faster-Whisper, Piper, and
  managed Ollama models through ModelDownloadAttempt plus the shared job
  observer. Make every first-use consumer attach to the same job.

#### [DX-01] Turn Obsidian preload and plugin claims into a release capability

- **Evidence**: SRC/neothd/src/installers/obsidian_vault.rs:46-85 contains only
  a five-entry plugin descriptor list. The custom neoth-archive-bridge has no
  plugin source anywhere else in the repository. SRC/neothd/src/cli/
  obsidian.rs:386-425 scaffolds community plugin state but does not install the
  five plugins. The robust L6 preload exists only in L6_Vault_Template and is
  not in current portable/native package support lists.
- **Impact**: a source checkout can preload L6, but a clean installed release
  cannot discover the template and the advertised curated plugin setup is only
  a list.
- **Effort**: L.
- **Risk**: MED; Obsidian vault ownership and third-party plugin supply chain.
- **Confidence**: HIGH.
- **Fix sketch**: ship L6 and the repository-owned bridge as verified resources,
  acquire pinned community plugin releases, create/select a vault, write
  config atomically, and prove app/vault/plugin/reader/preload probes.

#### [DX-02] Finish n8n and Paperless after process installation

- **Evidence**: SRC/neothd/src/cli/n8n.rs:1-33 explicitly defines a read-only
  Status/Workflows command; it does not install, import, or start n8n.
  SRC/neothd/src/installers/n8n.rs:34-94 selects an unpinned Docker or global
  npm command. SRC/neothd/src/installers/n8n_starter_workflows.rs:248-291
  contains ten generated starter workflows and the assets directory contains
  three bootstrap JSON files, but users are told to import/configure them.
  SRC/neothd/src/installers/paperless.rs:41-43 fetches a compose file from
  branch main, :139-168 checks Docker, and :172-205 explicitly uses a TCP probe
  that cannot identify Paperless.
- **Impact**: neither adoption reaches configured/authenticated Ready on a clean
  machine; Paperless can report an unrelated service on the port.
- **Effort**: L.
- **Risk**: HIGH; local service lifecycle, credentials, data volumes, upgrades.
- **Confidence**: HIGH.
- **Fix sketch**: pin runtimes/images/assets, own a local instance directory,
  generate credentials, import workflows idempotently, use authenticated
  product probes, supervise, and preserve user data on normal uninstall.

#### [SECURITY-01] Remove mutable and first-spawn acquisition

- **Evidence**: SRC/neothd/src/installers/cbm.rs:24-37 uses main, releases/latest,
  and an explicitly unverified Winget id. Paperless uses main as above.
  SRC/neothd/src/installers/ollama.rs uses mutable vendor installer URLs.
  SRC/neothd/src/installers/obsidian.rs:71-92 returns an unpinned download page
  on Linux. SRC/neothd/src/installers/mobile_mcp.rs:1-18 and
  SRC/neothd/src/installers/hex_graph.rs:1-5 rely on npx fetching on first use.
- **Impact**: the bits run after user approval are not bound to the reviewed
  release, and offline first use fails after configuration claimed success.
- **Effort**: M for the lock/verification substrate, then S per capability.
- **Risk**: HIGH; supply-chain and rollback behavior.
- **Confidence**: HIGH.
- **Fix sketch**: generate a target-specific capability lock with exact
  version, source revision, URL, size, SHA-256, optional upstream signature,
  license, and expected runtime probe. Download to staging, verify before
  execution, and bind the receipt to the job and release manifest.

#### [DX-03] Package runtime assets, not source-only sidecars

- **Evidence**: .github/workflows/release.yml:1982-1989 archives only source,
  tests, package manifests, README, and a service file for WhatsApp Baileys.
  bridges/whatsapp-baileys/package.json requires Node >=22.16.0 and pnpm
  10.32.1. packaging/windows/build-installer.ps1:371-417 accepts a flat required
  file list plus only self-knowledge as a nested directory; Linux/macOS support
  lists at packaging/linux/build-packages.sh:9-11 and
  packaging/macos/build-packages.sh:9-11 likewise omit integration assets.
- **Impact**: WhatsApp Web, L6, workflows, and full skill packages cannot be
  install-and-go from the release contract.
- **Effort**: L.
- **Risk**: HIGH; artifact layout and signed closed-file-set verification.
- **Confidence**: HIGH.
- **Fix sketch**: replace ad-hoc flat allowlists with a recursively verified
  capability resource manifest and ship standalone sidecars or managed runtime
  bundles, never a package-manager homework archive.

#### [DIRECTION-02] Ship a real companion client

- **Evidence**: the daemon and pairing QR exist, but no Android or iOS client
  project/distributable is present. The roadmap states this directly at
  PLAN/ROAD_TO_1_0_GOLD.md:178-183. SRC/neothd/src/installers/mobile_mcp.rs is
  device automation through ADB/WebDriverAgent, not the NEOTH companion app.
- **Impact**: the QR encodes a protocol with no normal-user consumer.
- **Effort**: L.
- **Risk**: HIGH; mobile transport, signing, permissions, store distribution.
- **Confidence**: HIGH.
- **Fix sketch**: extract a shared Rust companion protocol core, build thin
  Android/iOS clients, consume the existing single-use pairing invite, and
  publish installable artifacts with connection/cancel/update status.

#### [BUG-03] Materialize complete skill packages and prerequisites

- **Evidence**: 181 directories exist under SRC/neothd/assets/skills.
  SRC/neothd/src/skills/bundled.rs:1407-1452 explicitly skips sibling asset
  assertions in packaging-stripped builds. The drawio_diagram skill requires
  scripts/data at SRC/neothd/assets/skills/drawio_diagram/skill.yaml:55-250.
  graphify/skill.yaml:5-105 tells the user to pip install Graphify,
  ppt_master/skill.yaml:2-32 tells the user to pip install python-pptx, and
  officecli skills tell the user to install an external binary.
- **Impact**: bundled YAML can advertise a skill whose executable payload or
  runtime is absent from the installed release.
- **Effort**: L.
- **Risk**: MED; package size, licenses, sandbox permissions, platform support.
- **Confidence**: HIGH.
- **Fix sketch**: package each skill as a capability with its complete resource
  tree and declared runtime dependencies. Materialize managed prerequisites or
  keep the skill disabled with an actionable typed reason.

#### [MIGRATION-01] Make OpenClaw channel migration executable and lossless

- **Evidence**: SRC/neoth-migrate/src/openclaw_channels.rs:1-7 describes an
  inspection plan, not target activation. Lines 957-1115 block known gaps;
  :996 identifies multi-account flattening and :1044 requires WhatsApp relink.
- **Impact**: a user cannot migrate channel configuration/behavior to NEOTH
  without manually rebuilding it, and an eager apply would lose accounts or
  semantics.
- **Effort**: L.
- **Risk**: HIGH; credentials, account identity, sender policy, and behavior
  drift.
- **Confidence**: HIGH.
- **Fix sketch**: produce a hash-bound reviewed apply plan, map all accounts and
  policies transactionally, quarantine unsupported fields, launch the same
  integration jobs/probes, and require re-auth only where upstream sessions
  cannot be safely transferred.

## Source and version ledger

These are the local, read-only adoption baselines observed during planning.
They are evidence inputs, not permission to fetch a moving head during a
release. Before implementation, record each selected upstream in the
capability source lock and include its license/provenance.

| Source or package | Observed baseline | Role / required treatment |
|---|---:|---|
| The-Geek-Freaks/NEOTH | 19f74b228cc6d43fc2542922bbc28e324ba52ac6 | Plan baseline; current worktree contains later uncommitted integration work |
| openclaw/openclaw | 4c667aac8859114bd8f0a589ac6cd1de8bfe1474 | Channel/config migration and parity oracle; never import unknown fields lossily |
| tinyhumansai/openhuman | 15c744296dcb2bbbf394526d255755a361f88188, described locally as v0.53.30-staging | Existing migration source; route imported integrations through the same review/job contract |
| colbymchenry/codegraph | c41559a9d022c47a8c316eae31fac493a2da866f, v0.9.2 | Code-graph source comparison; do not conflate it with CBM or Graphify |
| addyosmani/agent-skills | d187883b7d761265309cdcc0f202cc76b4b3fb06, 0.6.2 | Bundled skill provenance and full-package coverage |
| Imbad0202/academic-research-skills | 2236bed19f95ad72f7ecd6e2c80123e60e0374c6 | Bundled academic skill provenance |
| msitarzewski/agency-agents | 783f6a72bfd7f3135700ac273c619d92821b419a | Bundled/adopted agent content provenance |
| chopratejas/headroom | 34dafe69d907c9a2971abc0d801ff9bfa498b3a8 | Native code adoption provenance; no runtime installer should be implied |
| Andyyyy64/whichllm | e78d6b0303924e207440c6403693b35328e6eef4 | Provider recommendation provenance |
| mattpocock/skills | f304057d61d3df3c9fd992ac2b6e3833cb9325fb | Skill provenance |
| phuryn/pm-skills | d384f0c9eb81fe74656a4f6da168587836939edb | Product skill provenance |
| @levnikolaevich/hex-graph-mcp | 0.21.1 at SRC/neothd/src/mcp/config.rs:595-596 | Exact package pin exists; remove npx first-run network by prefetching a verified package/runtime |
| @mobilenext/mobile-mcp | 0.0.62 at SRC/neothd/src/mcp/config.rs:888-908 | Exact package pin exists; bundle/prefetch managed Node package and verify ADB/WDA separately |
| WhatsApp Baileys bridge | bridge 1.0.0; Node >=22.16.0; pnpm 10.32.1; baileys 7.0.0-rc13 | Build a standalone/managed-runtime deliverable; source archive is not Ready |
| Keet bridge | bridge 1.0.0; pnpm 10.32.1; hyperswarm 4.17.0; keet-identity-key 3.2.0; bare-runtime 1.29.4 | Existing standalone build is the pattern for a zero-dependency sidecar |
| Qwen profile model | Qwen/Qwen2.5-3B-Instruct at SRC/neothd/src/providers/local_qwen.rs:79 | Add immutable HF revision and artifact hashes to the release capability lock |
| Ouro thinking model | ByteDance/Ouro-1.4B-Thinking at SRC/neothd/src/providers/ouro/adapter.rs:43 | Same native model lifecycle as Qwen |
| CBM | main install script, releases/latest, unverified Winget id at cbm.rs:24-37 | BLOCKED from Ready until an exact version/source/hash/package id is reviewed |
| Paperless | compose source from branch main at paperless.rs:41-43 | BLOCKED from Ready until exact image digests/config schema are locked |
| n8n | global npm/container command without a version at n8n.rs:34-94 | Select one supported version and lock package/image plus migration policy |
| Obsidian Linux installer | generic download page at obsidian.rs:71-92 | Resolve a versioned vendor asset per target and verify vendor signature/hash |
| Ollama | mutable vendor installer URLs in ollama.rs | Resolve a versioned artifact and verify installed version before Ready |
| Tududi | operator-supplied server.js and token; no managed source pin | Pick a reviewed tag/image/package, install it, then retain the existing secure token/config upsert |

If a local checkout is newer than a public comparison document, the exact
checkout SHA wins for code archaeology, but the released compatibility claim
must name the actually tested upstream version. Do not label a moving branch or
latest URL as a version.

## Target architecture

### 1. Capability catalog

Add a single checked-in catalog under packaging/capabilities/catalog.json.
Include it in the neoth binary and copy the same bytes into every release.
Generate a target-specific capabilities.lock.json in the release workflow.
Each CapabilityDescriptor must contain:

- stable id, display name, category, v1 support tier, supported targets;
- source provenance, version/revision, license, redistribution posture;
- compile-time feature requirements and expected released binaries/resources;
- prerequisites represented as other capability ids, never prose;
- artifact list with URL/source, byte size, SHA-256, optional upstream
  signature/key id, archive format, executable bit, and final relative path;
- required config fields and credential slot names, never credential values;
- lifecycle adapter id and probe id;
- user-data paths versus NEOTH-owned paths;
- GUI/CLI/Buddy/wizard/Doctor surface flags;
- update strategy, rollback strategy, uninstall behavior, and whether purge is
  separately confirmable;
- explicit UnavailableReason for unsupported platform/account/device/license
  combinations.

The release lock is closed: sorted unique entries, canonical JSON, hash bound
to release version, git SHA, Rust target, source archive hash, and self-
knowledge manifest. Unexpected files or capabilities fail packaging.

### 2. Durable integration job state machine

Create SRC/neothd/src/integrations with:

- catalog.rs: parse/validate the embedded catalog and installed release lock;
- jobs.rs: SQLite store at NEOTH_HOME/setup.db;
- state.rs: exhaustive state and legal-transition validation;
- artifacts.rs: staged download, verification, extraction, ownership receipts;
- orchestrator.rs: dependency DAG, permission gate, lifecycle execution,
  cancellation, retry, rollback, and terminal receipts;
- probe.rs: typed authenticated probe results;
- supervisor.rs: install-owned child/service registration and readiness;
- adapters/: one adapter per capability family, wrapping existing modules.

Minimum durable schema:

    integration_jobs(
      job_id, capability_id, operation, release_version, manifest_sha256,
      state, state_revision, current_step, completed_steps, total_steps,
      bytes_done, bytes_total, started_at, updated_at, terminal_at,
      error_code, redacted_error, retry_of, requested_by, cancel_requested
    )

    integration_artifacts(
      capability_id, release_version, artifact_id, expected_sha256,
      installed_sha256, owned_path, source_kind, installed_at
    )

    integration_services(
      capability_id, service_id, ownership, endpoint, pid_or_service_ref,
      last_probe_status, last_probe_at
    )

No secrets, prompts, QR payloads, API tokens, phone numbers, or raw subprocess
output enter setup.db. Store only bounded redacted tails. Use immediate
transactions and monotonically increasing state_revision. On restart:

- queued/running/downloading/validating/configuring jobs become resumable only
  after staging and manifest hashes are revalidated;
- a changed release lock invalidates the old job and creates a retry;
- completed Ready jobs are re-probed, not blindly trusted;
- cancellation kills the owned process tree, flushes progress, preserves
  verified resumable partials, and rolls back config/service changes;
- only one mutating job per capability can run; read-only status is concurrent.

Legal terminal states are Ready, Failed, and Cancelled. Failure carries a stable
machine code and localized/operator-readable remediation. Retry creates a new
job linked by retry_of; history is immutable and bounded by retention policy.

### 3. One API, four consumers

Expose:

    neoth integrations list [--json]
    neoth integrations show CAPABILITY [--json]
    neoth integrations install CAPABILITY [--background] [--json]
    neoth integrations repair CAPABILITY [--background] [--json]
    neoth integrations update CAPABILITY [--background] [--json]
    neoth integrations uninstall CAPABILITY [--purge-data] [--json]
    neoth integrations jobs [--active] [--json]
    neoth integrations cancel JOB_ID [--json]
    neoth integrations retry JOB_ID [--background] [--json]

The daemon exposes the same typed service over authenticated loopback IPC and a
read-only progress event stream. GUI, Buddy, wizard, Doctor, first-use model
paths, and channel setup call the service; none shell a second implementation.
CLI may execute in-process when the daemon is absent, using the same
orchestrator and cross-process lock.

### 4. Permissions and audit

Add one explicit ManageSoftware/ManageIntegration ActionKind instead of
misusing ExternalTaskWrite. It must carry capability id, operation, target,
source/version, download bytes, executable/process effect, data-retention
effect, and whether elevation/restart is required. Map it through all autonomy
levels and custom policy without weakening the existing Full hard floor.

Order:

    build immutable plan
      -> display/record exact effects
      -> required audit intent
      -> permission/consent decision
      -> network/process/config mutation
      -> terminal audit receipt

Reuse EVENT_TYPE_INSTALLER_RAN for package-manager execution. Add one
ExtendedSubtype::IntegrationLifecycle for non-package transitions, append-only
and default DoNotGossip. A missing WAL writer blocks mutating production jobs.
Read-only discovery/status/probe remains available.

### 5. Artifact and config safety

- Download only HTTPS release-lock URLs after existing outbound/SSRF checks.
- Stage under NEOTH_HOME/staging/CAPABILITY/JOB; reject links, devices, path
  traversal, case-collisions, duplicate names, unbounded files, and target
  architecture mismatch.
- Verify size/hash/signature before making any file executable or starting it.
- Commit versioned capability directories first and update a small current
  pointer/launcher last. Roll back that pointer on failed start/probe.
- Persist config through the canonical typed/lossless atomic updater. Preserve
  comments/unknown fields where the existing format promises it.
- Write credential values only through credentials.yaml/keychain helpers and
  bounded stdin; never argv, URL, environment dump, logs, setup.db, or WAL.
- The ownership ledger may delete only paths whose current hash and owner match
  its receipt. Normal uninstall preserves vaults, model caches selected as user
  data, Paperless/n8n volumes, imported workflows, mobile pairing history, and
  channel sessions. Purge is a distinct typed confirmation.

## Complete adoption lifecycle matrix

Every row below must receive a CapabilityDescriptor and a lifecycle adapter or
an explicit, tested UnavailableReason. Grouped rows still require per-member
catalog entries and coverage tests.

| Capability | Discover/acquire/verify | Materialize/configure/start/probe | Update/uninstall | Required surfaces | Current evidence / gap |
|---|---|---|---|---|---|
| Release self-knowledge / Graphify snapshot | Discover adjacent signed snapshot; verify release/git/source/payload manifest | Materialize immutable release Wiki/Obsidian baseline plus stable user overlay; native graph query probe | New release installs new baseline; preserve overlay; remove only owned baseline | CLI, GUI, Buddy, wiki, Obsidian, Doctor | In-flight release foundation at roadmap :195-235; register it as a capability/job consumer, do not fork its builder |
| Obsidian desktop | Detect installed version or acquire target-locked vendor artifact | Install app, launch once when necessary, confirm executable/product/version | Versioned update/rollback; app removal never deletes vault | Wizard, CLI, GUI, Buddy, Doctor | obsidian.rs offers package-manager/download hints, Linux is not self-contained |
| Obsidian vault binding | Discover existing vaults; select or create default | Scaffold contained folders/config, persist canonical obsidian_vault, start reader/writers, prove write/read/status | Repair binding; detach without deleting vault; purge only NEOTH-owned scaffold on explicit request | All four surfaces | Strong CLI runtime exists; clean-machine coupling and GUI job flow missing |
| L6 preload | Ship exact template and manifest in capabilities resources | Copy/hash/normalize/ingest via existing preload_template; prove expected scopes and generated-dir exclusions | Per-file hash update/revoke; uninstall removes only owned mirror, never user edits | Wizard, CLI, GUI, Buddy, Doctor | Source template exists and runtime is robust; release assets absent |
| Obsidian community plugins | Resolve reviewed exact versions/hashes/licenses for Dataview, Smart Connections, Templater, Periodic Notes | Install into .obsidian/plugins, update community-plugins.json losslessly, launch/probe plugin manifests | Versioned rollback; remove only NEOTH-installed unchanged plugin dirs | Wizard, CLI, GUI, Buddy, Doctor | BOOTSTRAP_PLUGINS is descriptor-only |
| neoth-archive-bridge | Build repository-owned plugin with manifest/main/styles and deterministic bundle | Install file-only bridge/dashboard, bind NEOTH-owned archive folders/state, prove commands/readiness without secrets | Ship with release; atomic update; ownership-safe removal | Obsidian, CLI, GUI, Buddy | Identifier exists but no plugin implementation/source |
| n8n runtime | Detect existing compatible instance or acquire pinned managed Node+n8n package; existing Docker is optional, never required homework | Create NEOTH-owned instance/data dirs and auth, start under supervisor, authenticated /health/version probe | Schema-aware backup/update/rollback; preserve user data and credentials; purge separate | Wizard, CLI, GUI, Buddy, Doctor | Unpinned Docker/npm command and read-only CLI |
| n8n workflows | Ship/verify all 3 asset workflows plus 10 generated starters | Bind NEOTH base URL/scoped token placeholders, import idempotently by stable id/hash, leave dangerous workflows inactive until reviewed, authenticated list probe | Three-way update without overwriting user edits; detach/remove owned unchanged workflows | CLI, GUI, Buddy, n8n UI, Doctor | Shapes exist but manual import/config remains |
| Paperless-ngx | Acquire pinned OCI image digests plus managed rootless runtime when no compatible engine exists | Create secrets/volumes, start, obtain/store API token, authenticated product/version probe, bind webhook/ingest/Obsidian paths | Database/media backup, digest migration, rollback; preserve volumes by default | Wizard, CLI, GUI, Buddy, Doctor | main compose URL, external Docker prerequisite, TCP-only probe |
| CalDAV | Discover endpoint/account and validate TLS | Bounded-stdin/keychain credential binding; authenticated calendar list/read/write capability probe according to policy | Rotate credentials; detach only | Wizard, CLI, GUI, Buddy, Doctor | Public README capability; include in parity inventory even though no software download |
| Optional IMAP source build | Confirm artifact compile feature and server/account | Secure credential flow and authenticated read-only mailbox probe; never imply SMTP | Rotate/detach; no message deletion | CLI, GUI, Buddy, Doctor; source-build UnavailableReason in stock artifact if intentionally omitted | README calls it source-build opt-in; release feature truth must stay exact |
| Shared managed Node runtime | Acquire one target-locked, checksum/signature-verified Node distribution; never use ambient npm/npx as the stock path | Materialize one versioned NEOTH-owned runtime and package cache; prove version, target, permissions, and supervisor launch | Side-by-side update/rollback; delete only owned runtime after dependent-capability reference count reaches zero | Wizard, CLI, GUI, Buddy, Doctor | n8n, Hex Graph, mobile-mcp, WhatsApp Baileys, and some skills otherwise create divergent hidden Node prerequisites |
| SSH tunnel transport | Compile into the supported server/desktop bundle or provide a signed artifact variant selected by the installer | Lossless tunnel/jump-host config, host-key/TOFU review, bounded connection and data-path probe | Atomic artifact/config update; stop/detach without deleting unrelated SSH material | CLI, GUI, Buddy, Doctor | `ssh-tunnel` is currently source-build-only despite a public config/runtime surface |
| Iroh cluster transport | Publish a target-matched signed cluster transport variant/add-on and select it through capability setup | Bind NodeId/relay policy and prove direct or relayed authenticated peer roundtrip | Versioned update/rollback; preserve cluster identity unless purge | CLI, GUI, Buddy, cluster panel, Doctor | `cluster-iroh` is compile-gated and absent from stock artifacts |
| Qwen CUDA/Metal acceleration | Detect hardware first, then acquire the matching signed accelerator artifact variant; CPU remains the safe fallback | Verify compiled backend and driver/toolchain compatibility, then run a bounded inference/device probe | Side-by-side artifact update/rollback; never replace a working CPU build until the accelerator probe passes | Wizard, models CLI, GUI, Buddy, Doctor | `qwen-cuda`/`qwen-metal` are source-build-only, so current GPU detection cannot make shipped Qwen acceleration installable |
| PTY provider subprocess | Include the supported desktop implementation or a signed target variant and declare platform availability | Run a bounded interactive provider-CLI fixture with terminal cleanup and cancellation | Atomic update/rollback; no persisted terminal secrets | CLI, GUI, Buddy, Doctor | `pty-subprocess` is source-build-only and Windows otherwise loses the documented interactive fallback |
| Browser credential import helper | Keep the stock core unable to read browser stores; if retained as public functionality, acquire a separately signed one-shot helper only after explicit high-risk consent | Bind request to browser/profile/credential class, import through SecretRefs without plaintext logs/WAL, then destroy transient state and probe the target credential | Helper updates are isolated; uninstall removes only helper bytes and never browser data or imported credentials | Wizard, CLI, GUI, Buddy, Doctor | `browser-import` is intentionally absent from releases for attack-surface reasons; a manual source build is not a zero-friction public contract |
| RecursiveMAS sidecar | Acquire an exact reviewed sidecar plus managed runtime/model lock; no operator-installed checkout or Python | Start under supervisor, apply VRAM/policy gate, and prove bounded JSON-over-stdio council roundtrip | Atomic runtime/model update/rollback; preserve reviewed configuration | CLI, GUI, Buddy, council panel, Doctor | `recursive-mas` is compile-gated and currently expects an operator-installed Python sidecar |
| Qwen local profile model | Native hf-hub, immutable revision/artifact lock, disk/accelerator preflight, resumable progress | Validate JSON/tokenizer/safetensors, materialize cache, load one bounded inference probe | Side-by-side model revision, rollback, prune with active-use guard | Wizard, models CLI, GUI, Buddy, Doctor | Native runtime exists; wizard/CLI parity and progress missing |
| Ouro local thinking model | Same shared model lifecycle | Validate/load one bounded inference probe | Same | CLI, GUI, Buddy, Doctor | DEFAULT_OURO_REPO exists; fold into catalog |
| CLIP | Same shared model lifecycle | Validate and run one fixture embedding/dimension probe | Same | models CLI, GUI, Buddy, media panel, Doctor | Pull exists in CLI; no full surface/job parity |
| Candle Whisper tiny/base/small/medium/large | Same shared model lifecycle per reviewed model id | Validate and transcribe a bundled short fixture | Same | models CLI, GUI, Buddy voice, Doctor | Runtime and cache validation exist; unify progress |
| Faster-Whisper variants | Acquire model plus a managed, target-locked runtime or remove stock-release claim; no user pip | Validate runtime/model pair and transcribe fixture | Atomic runtime/model updates; remove owned environment only | CLI, GUI, Buddy voice, Doctor | Current provider probes Python; user-installed Python must not be a stock-release prerequisite |
| Piper/local TTS voices | Acquire exact engine/voice/model/config lock | Validate voice files and synthesize bounded fixture | Side-by-side voice updates/prune | CLI, GUI, Buddy voice, Doctor | Runtime surface exists; add it to model/resource inventory |
| Ollama runtime and models | Acquire target-locked Ollama installer/binary; model pulls are individual jobs with digest/size | Start managed/existing service, authenticated/local API version/model probe, bind selected model | Runtime and model update/prune; preserve external instance | Wizard, CLI, GUI, Buddy, Doctor | Installer is partly automatic but URLs/model commands are mutable and status is fragmented |
| FFmpeg / OCR / fontconfig | Prefer release-bundled target-locked tools where license permits; otherwise managed verified artifact/package | Materialize PATH-local tool dir, version/capability probes, use exact path rather than ambient executable | Atomic update; remove owned files only | CLI, GUI media, Buddy, Doctor | Installer modules mostly recommend package-manager commands |
| OBS Studio / virtual camera | Acquire compatible signed vendor package without requiring user package manager | Install, launch/configure plugin/virtual camera where permitted, version and virtual-camera probe | Update app/plugin; preserve scenes/profiles | Wizard, CLI, GUI, Buddy, Doctor | obs.rs and faccam_family.rs are install hints |
| FadCam Android | Deep-link/store install is unavoidable; verify package/version and pairing | Guided Android permission/pairing, authenticated media-source probe | Store update; disconnect only | GUI, Buddy, mobile setup, Doctor | URL descriptor only; never claim NEOTH installed it without device acknowledgement |
| CBM | Resolve exact upstream version/revision/hash and verified package identity | Install binary, retain existing atomic MCP upsert, start stdio handshake/list-tools probe | Versioned update/rollback; unregister and remove owned binary | Wizard, CLI, GUI, Buddy, MCP/Doctor | auto_register exists, sources are mutable/unverified |
| Hex Graph MCP | Prefetch exact 0.21.1 npm tarball and managed Node runtime into release/cache | Register exact managed executable path, stdio initialize/list-tools probe | Package/runtime update as reviewed lock; unregister/remove owned cache | Wizard, CLI, GUI, Buddy, MCP/Doctor | Exact pin exists but npx fetches on first use |
| Tududi | Pin reviewed server release/container and install local instance, or mark connection-only with explicit reason until managed mode lands | Generate/store token, start server, retain secure MCP upsert, API plus stdio/list-tools probe | Data backup/migration/update; unregister; preserve tasks by default | Wizard, CLI, GUI, Buddy, MCP/Doctor | Current wizard requires an existing path/server/token |
| mobile-mcp | Prefetch exact 0.0.62 package and managed Node; discover ADB/WDA capabilities | Register managed launcher; device enumeration and harmless screenshot/tree probe after OS permission | Package/runtime update; unregister; preserve device tooling | Wizard, CLI, GUI, Buddy, MCP/Doctor | npx first-run fetch and manual Node/ADB/Xcode prerequisites |
| Claude Code / Codex / Antigravity CLIs | Resolve exact supported versions and signed/hash-locked packages/scripts | Install into NEOTH-managed tool dir, login handoff, version/auth probe | Update/rollback/remove owned CLI; preserve vendor login unless purge | Wizard, CLI, GUI, Buddy, Doctor | installers/mod.rs uses npm and a curl-to-shell installer |
| Keet bridge | Ship existing standalone per target and verify version/hash | Create identity/topic, bind exact sender policy, supervise, prove full-duplex authenticated roundtrip | Release-bound update/rollback; stop/remove owned binary; preserve identity unless purge | Channel CLI/GUI, Buddy, Doctor | Standalone pattern exists; ensure every desktop artifact includes it and musl omission is explicit |
| WhatsApp Baileys bridge | Build standalone or bundle managed Node+resolved lock; no source-only homework | Start supervised bridge, show QR progress, persist session privately, exact account/group policy, bidirectional text/media/reply probe | Atomic sidecar update; reconnect; preserve session unless purge | Channel CLI/GUI, Buddy, Doctor | release workflow packages source only |
| WhatsApp Business | No local runtime; guide Meta app/token/webhook fields | Secure credentials, webhook challenge, send/receive/media/reply authenticated probes and exact account identity | Rotate/detach; no cloud resource deletion without separate consent | Channel CLI/GUI, Buddy, Doctor | Config exists; behavior parity/migration proof required |
| Signal | Acquire target-locked signal-cli/JRE or a reviewed standalone runtime | Link/register device, supervise RPC, sender/group/media/reply probe | Update runtime; unlink/remove only with explicit confirmation | Channel CLI/GUI, Buddy, Doctor | Current probe depends on external signal-cli endpoint |
| BlueBubbles | Detect required macOS server/device; automate signed server app installation where license permits | Guided iMessage/Full Disk Access setup, authenticated API/websocket probe | App update; detach without deleting iMessage data | Channel CLI/GUI, Buddy, Doctor | External server prerequisite; must be explicit and guided |
| Telegram, Slack, Discord, LINE, IRC, Mattermost, Google Chat, Matrix, Twitch, Nostr | Catalog fields/account prerequisites; no hidden local binary except compile feature | Keychain/bounded-stdin config, exact sender/room/relay policy, authenticated vendor handshake plus supported text/media/reply/stream behavior probe | Credential rotation, reconnect, detach, preserve remote data | Channel CLI/GUI, Buddy, Doctor | 15-kind config registry exists; many current probes check presence/compile flag rather than live behavior |
| Tailscale | Acquire signed/versioned client if absent | Install, login handoff, status/account/tailnet probe, bind mesh transport | Update client; disconnect/remove only with explicit effect text | Wizard, CLI, GUI, Buddy, Doctor | installer command exists; clean-machine install/login lifecycle incomplete |
| Hysteria2 | Acquire exact signed/hash-locked binary; never get.hy2.sh at runtime | Configure NEOTH-owned profile, supervise, authenticated tunnel/readiness probe | Atomic binary/config update; stop/remove owned profile | Wizard, CLI, GUI, Buddy, Doctor | mutable install script and package hints |
| tmux warm sessions | Install through managed package job only on supported Unix | Version >= required minimum, create/attach harmless probe | Package update; remove only if NEOTH-owned and unused | CLI, GUI status, Buddy, Doctor | distro command selection exists but no common lifecycle |
| All 181 bundled skills | Catalog generator walks every directory and includes YAML plus all sibling files | Materialize immutable bundled package set and writable user overlay; dependency and permission probes before enable | Release replaces baseline; custom/user packages update/uninstall independently | skills CLI/GUI, Buddy, Doctor | YAML embedding can omit sibling assets |
| Graphify skill | Use release-bundled self-knowledge reader for NEOTH self-map; acquire a managed Graphify runtime only for general external-repo graph generation if retained | Exact version/backend probe; deterministic fixture graph/export | Update managed runtime; preserve user graphs | CLI, GUI, Buddy, skills/Doctor | skill currently instructs pip install; release snapshot work must not be confused with general Graphify execution |
| Draw.io skill | Ship scripts/data and resolve managed renderer/browser dependency | Run deterministic fixture diagram and verify output | Replace baseline; remove owned runtime only | CLI, GUI, Buddy, skills/Doctor | sibling resources are not guaranteed in package |
| Office/PPT skills | Prefer native/release-managed implementation; otherwise acquire exact officecli/python runtime and wheels with hashes | Run one small DOCX/XLSX/PPTX/PDF fixture per advertised operation | Locked environment update/rollback; remove owned environment | CLI, GUI, Buddy, skills/Doctor | skills currently instruct manual officecli or pip install |
| WASM plugins | Verify stock artifact was compiled with wasm-plugin-host; local package provenance/capability scan | Install/enable through existing sandbox and run bounded fixture probe | Versioned plugin update/rollback; disable/uninstall; preserve config | plugins CLI/GUI, Buddy, Doctor | desktop release feature bundle is in-flight; add artifact/runtime proof and progress |
| Built-in freedom/profile presets and hook assets | Catalog prerequisite capability ids and one shipped hook asset | Plan/dry-run, consent, atomic config apply, then enqueue required capability jobs; rollback config if mandatory job fails | Reapply/undo; deleting custom preset never removes shared integrations | Wizard, CLI, GUI, Buddy, Doctor | core preset application works; integration prerequisites are not coupled |
| Custom skills/plugins | Local and catalog source discovery with provenance/security scan | Stage, verify, install complete package, dependency jobs, enable/probe | Update diff/review, rollback, uninstall owned package | CLI, GUI, Buddy, Doctor | local-dir flows exist; no shared download/update/progress contract |
| OMI developer/native ingest | No local app is implied; discover OMI account/device and endpoint mode | Secure credential setup, listener/API config, authenticated import/export or native-ingest probe, privacy/retention confirmation | Rotate/detach/purge through existing OMI lifecycle | Wizard, CLI, GUI, Buddy, Doctor | runtime/privacy controls are strong; installer module only probes endpoint |
| NEOTH companion Android/iOS | Publish signed Android APK/AAB and iOS IPA/TestFlight-ready build plus store/deep links | Scan existing single-use QR, Noise/P2P handshake, scoped token receipt, chat/approval/job status probe | In-app update/store flow, revoke device, uninstall leaves server data until revoked | Mobile app, GUI, Buddy, CLI pair-phone, Doctor | server/QR exists; no client distributable |
| OpenClaw migration | Detect exact version/config includes/accounts; hash-bound review plan | Transactionally map all channel accounts/policies/skills/cron/runtime refs, store secrets only by reference/re-auth, then run capability jobs and probes | Resume/idempotent reapply; rollback target config; source remains untouched | migrate CLI, GUI, Buddy migration status, Doctor | inspect-only channel ledger and blockers remain |
| OpenHuman/Hermes/Veronica migration | Existing source detection/apply remains source of truth | Route imported integration/skill/runtime artifacts into non-activated review plus capability jobs | Resume/idempotent; rollback target only | migrate CLI/GUI/Buddy/Doctor | OpenHuman memory migration is strong; integration activation must not bypass the common lifecycle |

## Commands you will need

Run Rust commands from SRC unless a command says otherwise. Rust MSRV is 1.91
at SRC/Cargo.toml:31 and SRC/neothd/Cargo.toml:5.

| Purpose | Command | Expected on success |
|---|---|---|
| Format | cargo fmt --all -- --check | exit 0 |
| Core lint | cargo clippy --workspace --all-targets --features "wizard wasm-plugin-host release-desktop" -- -D warnings | exit 0, no warnings |
| Core tests | cargo test --workspace -- --test-threads=1 | exit 0, all tests pass |
| Integration lifecycle | cargo test -p neoth --lib integrations:: | exit 0, all new state/catalog/artifact tests pass |
| Wizard | cargo test -p neoth --lib cli::init:: | exit 0 |
| Models | cargo test -p neoth --lib media::model_manager | exit 0 |
| Obsidian | cargo test -p neoth --lib cli::obsidian | exit 0 |
| Channels | cargo test -p neoth --lib channels:: | exit 0 |
| Migrations | cargo test -p neoth-migrate | exit 0 |
| GUI compile | cargo check -p neothd-gui | exit 0 |
| Keet dependencies | pnpm --dir bridges/keet install --frozen-lockfile | exit 0 |
| Keet tests | pnpm --dir bridges/keet test | exit 0 |
| WhatsApp dependencies | pnpm --dir bridges/whatsapp-baileys install --frozen-lockfile | exit 0 |
| WhatsApp tests | pnpm --dir bridges/whatsapp-baileys test | exit 0 |
| Bootstrap verifier | python packaging/test_bootstrap_verifier.py | exit 0 |
| Release isolation | python .github/release-tools/test-release-isolation.py | exit 0 |
| Linux package contract | bash packaging/linux/test-contracts.sh | exit 0 |
| macOS package contract | bash packaging/macos/test-contracts.sh | exit 0 on macOS |
| Windows package contract | powershell -NoProfile -File packaging/windows/test-packaging.ps1 | exit 0 on Windows |
| Diff hygiene | git diff --check | no output, exit 0 |

The pnpm commands are for repository tests/build input only. Released users
must not need Node or pnpm for a capability advertised as installable.

## Suggested executor toolkit

- Use Graphify against the final source graph when changing registries or
  release layouts; regenerate the release self-knowledge only through its
  canonical builder.
- Use the accessibility audit for all new Slint progress, modal, keyboard,
  screen-reader, scaling, and error states.
- Keep Ponytail/YAGNI pressure: one catalog, one job state machine, one
  downloader/verification boundary, one config path, one service supervisor.
  Do not create per-surface installer logic.
- Model new transactional writes after
  SRC/neothd/src/cluster/durable_sync.rs:379-418 and
  SRC/neothd/src/cli/obsidian.rs:1867-1911.

## Scope

### In scope

- New SRC/neothd/src/integrations/ modules described above.
- packaging/capabilities/catalog.json and generated per-target lock/fixtures.
- SRC/neothd/src/cli/integrations.rs and command registration/docs generation.
- SRC/neothd/src/wizard/install_step.rs, ipc.rs, shared_state.rs, init.rs, and
  init step modules.
- SRC/neothd/src/media/model_manager.rs, model consumers, models CLI, local
  Qwen/Ouro/Whisper/CLIP/Piper/Ollama paths.
- Existing installer modules under SRC/neothd/src/installers/.
- Obsidian/L6 assets, the new repository-owned archive-bridge plugin, n8n
  workflows, Paperless, OMI, sidecars, MCP registrations, skills/plugins,
  presets/hooks, channels/probes, service supervision, Doctor.
- SRC/neoth-migrate channel/integration apply paths.
- bridges/keet and bridges/whatsapp-baileys deliverables.
- A new shared mobile protocol crate and Android/iOS companion clients under a
  clearly named clients/ or companion/ root, plus their release workflows.
- SRC/neothd-gui Rust/Slint surfaces required to consume integration jobs.
- Packaging, installer, updater, CI/security/release workflows and layout
  fixtures for all supported targets.
- README, generated CLI docs, install/getting-started/upgrade/release notes,
  privacy/security/runbooks, feature matrix, and Road-to-Gold truth updates
  after exact artifact proof.

### Out of scope

- Rewriting working provider inference, memory, council, or channel protocol
  algorithms merely to fit this lifecycle.
- Hosting a NEOTH cloud control plane.
- Creating vendor accounts, accepting third-party terms, buying hardware, or
  bypassing mobile/desktop OS security prompts. NEOTH must guide and verify
  these unavoidable steps.
- Publishing to app stores, package registries, crates.io, or tagging v1.0
  before the operator supplies signing/publisher authority and all gates pass.
- Auto-deleting external accounts, remote channel data, Obsidian vaults,
  Paperless/n8n volumes, or mobile data on normal uninstall.
- Falling back to unverified latest/main artifacts to keep a capability green.

## Git workflow

- Work on the current integration branch after reconciling the dirty worktree.
- Conventional commits match current history, for example:
  feat(gold): wire adoption lifecycle and progress
  fix(packaging): ship verified integration resources
  feat(mobile): ship companion pairing clients
- Commit each completed phase only after its focused gates pass. Push each
  verified commit to the configured remote branch because the operator
  explicitly requested frequent pushes.
- Never tag v1.0.0 or publish artifacts as part of an intermediate phase.
- Never amend/revert another agent's changes or use destructive git commands.

## Steps

### Step 0: Reconcile the live baseline and freeze the inventory

1. Run the drift check.
2. Enumerate all of:
   - every installer module under SRC/neothd/src/installers;
   - all 181 SRC/neothd/assets/skills directories and every sibling file;
   - all 15 ChannelKind values and compile features;
   - both bridge projects;
   - all local model repositories/artifact manifests;
   - all n8n workflow providers (3 asset workflows plus 10 generated);
   - all built-in freedom/profile presets and hook assets;
   - every README/docs public capability noun;
   - every release binary/resource on every target.
3. Add a temporary/generated audit report test fixture, not a hand-maintained
   prose list, that fails for an uncatalogued item.
4. Reconcile the in-flight release self-knowledge/packaging work. Do not alter
   its manifest semantics from this plan; register it as a capability.

**Verify**:

    cargo test -p neoth --lib integrations::catalog::tests::source_inventory_is_exhaustive

Expected: exit 0; output identifies 181 skill packages, 15 channels, every
installer module, both bridges, all model families, presets/hooks, and all
workflow providers, with zero uncatalogued public entries.

### Step 1: Add and validate the canonical capability catalog

1. Create packaging/capabilities/catalog.json with one entry per matrix row and
   one child entry per grouped capability.
2. Implement strict parsing in integrations/catalog.rs:
   - reject unknown schema version, duplicate id/path, unsorted entries,
     unknown dependency, dependency cycles, missing source/license, mutable
     version tokens, target without artifacts/probe/unavailable reason;
   - reject secrets or credential-looking literal values;
   - prove every compile feature and release binary maps to a capability;
   - prove every public capability is exposed on required surfaces.
3. Include the catalog bytes in neoth. Source builds may use the embedded
   catalog; production releases must also load and byte-compare the adjacent
   signed copy/lock.
4. Add a deterministic lock generator in packaging/capabilities that consumes
   only explicit versioned inputs. Do not resolve latest/main at runtime.
5. Add source/provenance notices and redistribution decisions. If an upstream
   may not be redistributed, record download-at-install with exact hash rather
   than copying it into the release.

**Verify**:

    cargo test -p neoth --lib integrations::catalog
    python packaging/capabilities/test_catalog.py

Expected: all positive/negative fixtures pass; running the generator twice
produces byte-identical canonical JSON; every catalog source is immutable.

### Step 2: Build the durable job engine, permission gate, and API

1. Add the setup.db schema and migrations. Use one cross-process lock per
   capability mutation and immediate SQLite transactions.
2. Implement exhaustive states/transitions, progress counters, cancellation,
   retry, restart recovery, retention, and redacted error codes.
3. Wrap the existing PkgManagerChain and ModelDownloadAttempt as adapters.
   Extend run_argv to:
   - stream bounded structured progress without discarding stdout;
   - hold a child process-tree handle;
   - honor cancellation and deadlines;
   - redact secrets before persistence/broadcast;
   - distinguish elevation-required, restart-required, offline, checksum,
     incompatible-version, configuration, start, and probe failures.
4. Add ManageIntegration to permissions and custom policy. Add exact
   intent/result auditing and fail closed without a writer.
5. Implement neoth integrations commands and loopback IPC/event stream.
6. Add crash/restart/concurrency tests with injected executors and fixture
   artifacts. Never use the real network in unit tests.

**Verify**:

    cargo test -p neoth --lib integrations::
    cargo test -p neoth --lib wizard::install_step
    cargo test -p neoth --lib permissions::

Expected: all transition-table, duplicate-job, crash-recovery,
cancel/process-tree, retry/hash-binding, audit failure, redaction, and
cross-process locking tests pass.

### Step 3: Implement verified acquisition, materialization, supervision, and ownership

1. Add a native artifact fetcher that reuses reqwest/rustls, SSRF policy,
   resumable staging, size limits, SHA-256, signature verification, and secure
   archive extraction.
2. Add platform materializers for:
   - release-bundled files;
   - direct versioned vendor artifacts;
   - package-manager operations through existing adapters;
   - managed portable Node/runtime packages;
   - OCI runtime/images for Paperless only when required;
   - mobile/store deep links as explicit AwaitingUser steps represented within
     Configuring, not fake Ready.
3. Add an ownership ledger and versioned current-pointer commit.
4. Extend the existing service supervisor so owned services expose start/stop,
   log tail, restart policy, authenticated readiness, and graceful rollback.
5. Retire or derive SRC/neothd/src/installers/zero_install.rs from the real
   release inventory so it cannot emit a stale partial installer.

**Verify**:

    cargo test -p neoth --lib integrations::artifacts
    cargo test -p neoth --lib integrations::supervisor
    python packaging/capabilities/test_materializer.py

Expected: malicious archives/links/case collisions/hash mismatches are rejected;
cancel and failed probe leave the previous version active; uninstall never
deletes an unowned or locally modified path.

### Step 4: Unify every local model and media prerequisite

1. Replace qwen_weights external CLI rendering with the native model adapter.
2. Extend models CLI to enumerate/pull/status/prune Qwen, Ouro, CLIP, Candle
   Whisper sizes, Faster-Whisper sizes/runtime, Piper voices, Ollama runtime,
   and Ollama model digests.
3. Add immutable HF revision/artifact entries and disk/RAM/VRAM estimates.
4. Make implicit first use attach to or create the same durable job. Chat/voice/
   media waits while surfacing progress and continues only after the exact
   verified cache generation is Ready.
5. Add safe cancellation, resume, concurrent-consumer fan-out, cache validation,
   active-use prune guard, and failed-download retry.
6. Eliminate user pip/huggingface-cli prerequisites from stock-release paths.
   If Faster-Whisper cannot be shipped with a managed runtime on a target,
   mark that backend unavailable there while Candle Whisper remains Ready.
7. Add GUI/Buddy integration job controls; do not parse stderr.

**Verify**:

    cargo test -p neoth --lib media::model_manager
    cargo test -p neoth --lib providers::local_qwen
    cargo test -p neoth --lib providers::ouro
    cargo test -p neoth --lib media::stt_provider
    cargo test -p neoth --lib cli::models

Expected: fixture downloads show deterministic byte progress, cancel/resume,
hash-bound Ready, one shared job under concurrency, and no external CLI spawn.

### Step 5: Ship Obsidian, vault/L6, and all five plugins as one coupled adoption

1. Add L6_Vault_Template and its manifest to the capability resource tree.
   Release builds must use repository bytes, never the developer absolute path.
2. Implement Obsidian app acquisition per target with exact version/signature/
   hash and installed-version probe.
3. Build vault discovery/selection/creation. On first install:
   - select an existing vault or create the documented default;
   - scaffold required folders and .obsidian config without overwriting user
     data;
   - persist obsidian_vault and reader/preload config atomically;
   - materialize L6 through existing preload_template;
   - start/reload the vault reader/writers;
   - prove file write/read, preload scopes, wiki query, and reader status.
4. Resolve and lock the four community plugin releases. Validate archive
   manifests and licenses; install exact files and update community-plugins.json
   losslessly.
5. Implement neoth-archive-bridge as a deterministic repository-owned,
   file-based Obsidian plugin. It must expose NEOTH archive folders/status and
   safe deep links/commands without storing provider/channel secrets.
6. Detect plugin user modifications. Update with backup/three-way policy;
   normal uninstall removes only unchanged NEOTH-owned plugin files and never
   the vault.
7. Add one integration card/job across wizard, CLI, GUI, Buddy, and Doctor.

**Verify**:

    cargo test -p neoth --lib cli::obsidian
    cargo test -p neoth --lib installers::obsidian
    cargo test -p neoth --lib integrations::adapters::obsidian
    node --test integrations/obsidian/neoth-archive-bridge/test/*.test.mjs

Expected: a clean temp home produces a bound vault with L6, five enabled plugin
directories, verified reader/write/preload/wiki probes, idempotent rerun, safe
repair, and ownership-safe uninstall.

### Step 6: Make n8n, Paperless, calendar, and mail operational

1. Select and lock one supported n8n release. Prefer a NEOTH-managed portable
   Node+n8n installation over global npm. Existing compatible n8n remains
   adoptable but must be explicitly marked external ownership.
2. Generate a local n8n instance, scoped NEOTH API token, encrypted credentials,
   and service definition. Bind only loopback/private endpoints.
3. Import all 13 workflows idempotently:
   - stable ids and content hashes;
   - substitute NEOTH base URL and credential references;
   - preserve user edits;
   - keep effectful templates inactive until review;
   - prove authenticated list/read and one harmless fixture execution.
4. Select exact Paperless image digests and a supported managed rootless
   container runtime. Install the runtime automatically if absent and resume
   after elevation/restart.
5. Generate Paperless secrets/volumes, start, create/store an API token, bind
   webhook/ingest/Obsidian folders, and use an authenticated version/API probe.
6. Add backup-before-migration, rollback, repair, and data-preserving uninstall.
7. Add CalDAV and optional IMAP credential/test cards to the same inventory.
   They need authenticated behavior probes, not a software-download fiction.

**Verify**:

    cargo test -p neoth --lib installers::n8n
    cargo test -p neoth --lib n8n_api
    cargo test -p neoth --lib installers::paperless
    cargo test -p neoth --lib paperless
    cargo test -p neoth --lib integrations::adapters::n8n
    cargo test -p neoth --lib integrations::adapters::paperless

Expected: fixture services prove install/config/start/authenticated probe,
workflow idempotency/user-edit preservation, upgrade rollback, and
data-preserving uninstall without ambient Docker/npm.

### Step 7: Finish sidecars, channels, mesh, and provider CLI prerequisites

1. Convert CBM, Hex Graph, Tududi, mobile-mcp, Signal, Hysteria2, Tailscale,
   tmux, FFmpeg/OCR/fontconfig, OBS/FadCam, and provider CLIs to capability
   adapters. Reuse their current probes/upserts where sound.
2. Replace every mutable script/latest/main/npx-first-run source with a release
   lock. A capability stays Failed/Unavailable until pin, license, and checksum
   are reviewable.
3. Build WhatsApp Baileys as a standalone artifact or managed Node runtime
   bundle per target. The public release asset must be directly runnable.
4. Preserve Keet's standalone release path and add an end-to-end local
   full-duplex readiness fixture.
5. For all 15 channel kinds:
   - prove compile-time availability matches artifact feature bundle;
   - use one lossless config schema in CLI/GUI/migration;
   - secure credentials and exact allowlists/account identity;
   - implement authenticated health and supported behavior probes;
   - test add/edit/test/remove/rotate/reconnect;
   - expose sidecar installation jobs and QR/login progress where needed.
6. Deep-diff the pinned OpenClaw source for multi-account, reply/media,
   streaming/edit, group, mention, thread, sender, reconnect, and health
   semantics. Record evidence-based skips for channels NEOTH intentionally does
   not support; no silent omission.

**Verify**:

    cargo test -p neoth --lib installers::
    cargo test -p neoth --lib channels::
    cargo test -p neoth --lib cli::channel
    pnpm --dir bridges/keet test
    pnpm --dir bridges/whatsapp-baileys test

Expected: the canonical 15-row registry is identical across CLI/GUI/catalog/
release features; managed sidecars start offline after install; live fixture
probes distinguish configured, reachable, authenticated, degraded, and failed.

### Step 8: Ship the OMI and NEOTH mobile experiences

1. Keep OMI as a privacy-sensitive external device/service integration:
   configure Developer API/native ingest modes, credentials, retention, and
   probes through the common job surface. Do not pretend the OMI app is the
   NEOTH companion.
2. Extract the existing companion invitation, Noise/P2P framing, scoped token,
   revocation, and message/job schemas into a no-UI Rust crate usable by daemon,
   Android, and iOS. Preserve single-use/TTL/PSK/Noise boundaries.
3. Build:
   - Android application with QR/deep-link pairing, background connection,
     chat, approvals, capability job progress/cancel/retry, channel/automation
     status, media/share intent, notifications, revoke/logout;
   - iOS application with the same product contract and platform-appropriate
     background/notification/share behavior.
4. Use thin Kotlin/Swift shells over the shared core unless a written,
   tested platform constraint proves another implementation safer. Do not
   replace private P2P pairing with an unauthenticated LAN socket.
5. Add accessibility, permission rationale, offline/reconnect, token expiry,
   device revocation, and upgrade migrations.
6. Build signed-ready APK/AAB and IPA/TestFlight artifacts. CI may use
   non-production test signing; final public signing remains an operator step.
7. Distinguish mobile-mcp device automation from the companion app in all UI
   and docs.

**Verify**:

    cargo test -p neoth-companion-core
    ./gradlew :app:test :app:lint assembleRelease
    xcodebuild test -scheme NEOTHCompanion -destination "platform=iOS Simulator,name=iPhone 16"

Expected: shared protocol vectors pass on daemon/Android/iOS; QR pairs once,
wrong PSK/expired/replayed invite fails, reconnect works, revoke disconnects,
and integration-job updates/cancel/retry render identically.

### Step 9: Materialize every skill, plugin, preset, and hook dependency

1. Generate skill package manifests from all 181 source directories, including
   every sibling script/data/template/resource and provenance/license.
2. Change bundled skill loading so the release baseline is a complete immutable
   package tree, not YAML-only include strings. Materialize it atomically on
   first run/version change while preserving user overlays.
3. Add typed dependency declarations: executable/runtime capability ids,
   platform, network, permission/action kinds, required assets, and probe.
4. Wire Graphify, Draw.io, Office/PPT, browser, and other dependency-bearing
   skills through managed capability jobs. Remove manual pip/install prose from
   enabled stock-release paths.
5. Keep a skill disabled with a visible reason until every mandatory dependency
   is Ready. Enabling triggers the exact plan/consent/job flow.
6. Add catalog install/update/review/rollback/uninstall for custom skills and
   WASM plugins, reusing security review/capability sandboxing.
7. Make freedom/profile presets compute prerequisite jobs before config commit.
   Mandatory failure rolls back; optional failure is explicit. Preserve undo.
8. Package the hook asset and prove catalog coverage.

**Verify**:

    cargo test -p neoth --lib skills::
    cargo test -p neoth --lib plugins::
    cargo test -p neoth --lib cli::preset
    cargo test -p neoth --lib profile::presets

Expected: every one of 181 source packages has identical released resource
coverage; no packaging-stripped skip remains; dependency-bearing skills cannot
run until their exact dependency probe is Ready; preset rollback is atomic.

### Step 10: Make OpenClaw and other migration activation transactional

1. Extend openclaw_channels from inspection to a deterministic target plan:
   preserve every known account, channel field, sender/group/thread/reply/media/
   streaming/reconnect policy, and source location hash.
2. Never flatten multi-account configuration. Add typed target accounts or
   block with an exact unsupported record until the runtime can represent them.
3. Do not copy secret values into plan/report/WAL. Import secure references only
   where technically portable; otherwise create a re-auth step (for example
   WhatsApp QR) linked to the capability job.
4. Apply all target config/credential-reference changes in one transaction,
   leaving imported integrations disabled until their job and authenticated
   probe are Ready.
5. Route OpenHuman/Hermes/Veronica imported integrations/skills/runtime
   artifacts through the same review/job path.
6. Add a behavior-parity fixture corpus derived from the pinned upstream
   versions and verify normalized source-to-target semantics.

**Verify**:

    cargo test -p neoth-migrate
    cargo test -p neoth-migrate openclaw_channels

Expected: multi-account fixtures remain multi-account, unknown/lossy fields
block apply, source mutation invalidates plan, apply is atomic/idempotent,
re-auth resumes, and every activated channel has a successful behavior probe.

### Step 11: Wire wizard, CLI, GUI, Buddy, Doctor, and first-use continuations

1. Replace the three intent-only wizard flags with actual jobs. Non-interactive
   default waits; --background returns job id. Wizard checkpoints persist job
   ids and resume after restart.
2. Add an Integrations GUI page generated from the catalog: availability,
   installed/current version, download size, dependencies, permissions,
   progress, logs, cancel/retry/repair/update/uninstall, data-preservation text.
3. Make Buddy a thin consumer of the same API:
   - show current install/download/config/probe job;
   - allow safe cancel/retry;
   - notify terminal state;
   - open the full GUI or exact CLI command;
   - never discard stderr or spawn its own installer.
4. When a GUI/Buddy action needs a missing capability, show the plan and start
   the job after consent. Auto-resume only idempotent/pure reads after Ready;
   mutating actions require an explicit retry to prevent duplicate side effects.
5. Make Doctor render the same catalog/probe/job truth and actionable failure
   codes. Repair starts the same job.
6. Generate a capability parity fixture consumed by plan 003. The parity plan
   owns broader GUI/Buddy feature completeness; this plan owns adoption and
   progress semantics.
7. Add keyboard/screen-reader labels, live-region progress, high-DPI/long-text
   layout, no terminal window flashes, and bounded friendly errors.

**Verify**:

    cargo test -p neoth --lib cli::init::
    cargo test -p neoth --lib cli::doctor::
    cargo test -p neoth --lib cli::integrations::
    cargo check -p neothd-gui

Expected: one injected job produces byte-identical JSON/state revisions in CLI,
GUI adapter, Buddy adapter, wizard resume, and Doctor; no surface shells an
integration installer or parses free-form progress.

### Step 12: Put the complete capability payload in every real release

1. Extend portable archives, Windows installer, macOS app/pkg/dmg, Linux
   deb/rpm, updater staging, and uninstallers with:
   - catalog.json and target capabilities.lock.json;
   - L6/Obsidian/plugin resources;
   - n8n workflow resources;
   - complete bundled skill packages and hook assets;
   - target standalone sidecars and managed runtime packages selected for
     redistribution;
   - self-knowledge snapshot;
   - licenses/provenance/third-party notices.
2. Replace the Windows single-special-directory rule at
   packaging/windows/build-installer.ps1:410-417 and equivalent flat lists with
   recursive manifest verification. Retain a closed file set.
3. Bind artifact manifest, updater, installer receipts, installed resource
   manifest, and runtime catalog to the same release version/git SHA/target.
4. Verify normal uninstall stops owned services and removes owned program files
   while preserving user data; explicit purge is separately tested.
5. Make WhatsApp/Keet and other sidecars first-class target artifacts, not
   detached homework archives.
6. Include stock release feature probes that actually start/load representative
   Matrix/IRC/Nostr/Google Chat, clipboard, WASM host, GUI, each sidecar, and
   native self-knowledge.

**Verify**:

    python .github/release-tools/test-release-isolation.py
    python packaging/test_bootstrap_verifier.py
    powershell -NoProfile -File packaging/windows/test-packaging.ps1
    bash packaging/linux/test-contracts.sh
    bash packaging/macos/test-contracts.sh

Expected: every extracted/installed artifact has exactly the manifest-declared
files, no unexpected paths/symlinks, matching hashes/features/version/target,
and can run all stock capabilities without build tools.

### Step 13: Qualify clean machines, update/repair/uninstall, and publish truth

1. Add fresh VM/runner tests for every supported Windows, macOS, and Linux
   target, including standard user, path with spaces/non-ASCII, offline core
   setup, interrupted download, failed auth/provider, reboot/elevation resume,
   upgrade from previous release, rollback, repair, normal uninstall, purge.
2. Run a representative adoption suite:
   - cloud provider plus one channel;
   - fully local Qwen/Whisper;
   - Obsidian app/vault/L6/five plugins;
   - n8n and workflows;
   - Paperless;
   - Keet and WhatsApp Baileys;
   - one MCP sidecar;
   - one complete skill with sibling assets;
   - companion pairing on Android and iOS.
3. Prove no external developer tool is required at runtime: no Rust, cargo,
   Node, npm, pnpm, Python, pip, Hugging Face CLI, minisign, cosign, Docker, or
   package manager unless the capability manifest says NEOTH itself installed
   and owns the managed runtime.
4. Generate README feature/install tables, CLI docs, wiki/self-knowledge,
   diagrams, release notes, comparison claims, install/getting-started/upgrade/
   uninstall docs from the verified catalog and test receipts.
5. Update Road-to-Gold only with exact-head evidence. Do not mark R4 boxes
   complete from unit tests alone.
6. Require exact-head CI, Security, CodeQL, release packaging, clean-machine,
   and mobile artifact jobs green before the v1.0.0 tag.

**Verify**:

    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets --features "wizard wasm-plugin-host release-desktop" -- -D warnings
    cargo test --workspace -- --test-threads=1
    git diff --check

Expected: all local gates exit 0 and the exact pushed HEAD has green CI,
Security, CodeQL, packaging, clean-machine, and mobile runs. Public docs contain
no capability state not derivable from the catalog/receipts.

## Test plan

### State/catalog unit tests

- Every legal transition and every illegal transition.
- Two concurrent installs of the same capability coalesce; different
  capabilities may run subject to resource limits.
- Crash at every step boundary recovers or rolls back deterministically.
- Cancel before download, mid-download, during validation, during config, and
  during probe.
- Retry binds exact old job/release manifest but creates a new immutable job.
- Manifest/source/artifact mutation invalidates staging.
- Error/log redaction removes every credential fixture.
- Catalog dependency DAG detects missing ids/cycles and remains sorted.
- Source inventory proves all installers, 181 skills, 15 channels, two bridges,
  models, workflows, presets/hooks, and release resources are covered.

### Artifact/config/security tests

- HTTPS/SSRF policy, size cap, timeout, range resume.
- Hash/signature/architecture mismatch and revoked key.
- Archive traversal, absolute path, symlink/hardlink, device, case collision,
  duplicate path, Unicode normalization collision, decompression bomb.
- Config unknown-field/comment preservation where promised.
- Credential values absent from argv/env dump/log/setup.db/WAL/JSON output.
- Missing audit writer and denied permission fail before network/process/write.
- Ownership-safe rollback/update/uninstall with locally modified files.

### Integration family tests

- Each matrix row has discover, install/acquire, verify, materialize, config,
  start, authenticated probe, status, repair, update, rollback, uninstall.
- Each target adapter runs against a local fixture server/process. Real network
  tests are opt-in release jobs with immutable endpoints/artifacts.
- Models use tiny fixture artifacts for normal tests and separate release-candidate
  real-model smoke tests.
- n8n/Paperless test user-data preservation and schema migration rollback.
- Obsidian tests an existing non-empty vault and plugin user modification.
- Channels test account identity and behavior, not credential presence alone.
- Migration tests all pinned upstream fixtures and unknown-field fail-closed.

### Surface parity and accessibility tests

- Snapshot the same job revisions through CLI JSON, GUI model, Buddy model,
  wizard checkpoint, and Doctor.
- Progress is announced, keyboard reachable, cancellable, and remains readable
  at high DPI and long localization strings.
- GUI/Buddy spawn no terminal window and discard no sole diagnostic stream.
- Closing/reopening GUI does not cancel a background job; daemon restart
  recovers it.

### Release/clean-machine tests

- Exact contents/version/feature/architecture/signature on every archive/native
  package.
- First run with no build tools or package managers.
- Online optional acquisition and offline core behavior.
- Interrupted network, elevation/reboot, disk-full, auth failure, port conflict.
- Update/repair/rollback/uninstall/purge.
- Android/iOS install, pairing, revoke, reconnect, update.

## Done criteria

All must hold:

- [ ] One validated capability catalog covers every public adoption, all 181
  skill packages, all 15 channels, both bridges, every installer module, all
  model families, all workflows, presets/hooks, and every released resource.
- [ ] Every catalog capability implements the complete lifecycle or has a
  tested explicit UnavailableReason for that target.
- [ ] CLI, GUI, Buddy, wizard, Doctor, first-use consumers, and migrations use
  one durable job API and expose the same state revision/progress/error.
- [ ] queued, byte/step progress, validating, configuring, ready, failed,
  cancelled, and retry are durable and restart-safe.
- [ ] Ready is reachable only after exact artifact/config binding and an
  authenticated capability-specific probe.
- [ ] The three intent-only wizard flags execute real jobs and fail scripts
  when readiness fails.
- [ ] Qwen/Ouro/CLIP/Whisper/Faster-Whisper/Piper/Ollama have GUI/CLI/Buddy
  progress, cancel, retry, validation, status, update, and safe prune.
- [ ] Obsidian installs/binds app, vault, L6, reader/writers, four pinned
  community plugins, and the real neoth-archive-bridge; normal uninstall
  preserves the vault.
- [ ] n8n installs/starts/authenticates and idempotently imports all 13
  workflows; Paperless installs/starts/authenticates without manual Docker.
- [ ] Keet and WhatsApp Baileys are directly runnable released sidecars;
  WhatsApp QR/session progress is visible and resumable.
- [ ] All 15 channels have lossless CLI/GUI config and typed authenticated
  health/behavior probes; OpenClaw multi-account/policy migration is lossless
  or blocks before apply.
- [ ] Android and iOS companion distributables consume the real pairing
  protocol and expose chat/approval/integration-job parity.
- [ ] Every bundled skill materializes all sibling resources; dependency-bearing
  skills cannot enable until exact prerequisites are Ready.
- [ ] No stock-release feature requires the user to manually install Node/npm/
  pnpm, Python/pip, Hugging Face CLI, Docker, minisign/cosign, build tools, or a
  hidden sidecar.
- [ ] Target release locks contain no latest/main/unversioned executable source.
- [ ] No mutating job runs before required audit and permission; no secret enters
  argv, logs, setup.db, WAL, manifests, or public status JSON.
- [ ] Normal uninstall removes only owned program files/services and preserves
  operator data; purge is separate and confirmed.
- [ ] Windows installer, macOS app/pkg/dmg, Linux deb/rpm, portable archives,
  updater, and uninstallers all verify the same closed recursive capability
  manifest.
- [ ] Clean-machine, update, repair, rollback, uninstall, accessibility, mobile,
  CI, Security, and CodeQL gates are green on the exact pushed HEAD.
- [ ] README/docs/wiki/diagrams/release notes/roadmap claims are generated or
  reconciled against verified shipped capability truth.
- [ ] git diff --check, Rust fmt, workspace clippy, and workspace tests exit 0.
- [ ] No v1.0.0 tag or publication occurs before every criterion above and the
  operator-owned signing/publisher step.

## STOP conditions

Stop and report; do not improvise if:

- Any current-state seam no longer matches and the replacement has different
  security, ownership, release-layout, or state semantics.
- A third-party executable/model/plugin/image lacks an exact immutable version,
  source revision, license/redistribution decision, and verifiable hash or
  signature. Keep it unavailable; never substitute latest/main.
- Implementing zero-friction would require bypassing an OS permission, vendor
  account approval, mobile signing rule, or third-party terms.
- An install/config/upgrade/uninstall path cannot distinguish NEOTH-owned files
  from operator data.
- A credential would need to enter argv, URL, logs, setup.db, WAL, release
  manifest, migration report, or test fixture.
- OpenClaw or another migration source contains a field/account/behavior that
  the target cannot represent losslessly. Block apply and add typed support;
  never flatten or drop it.
- The mobile P2P/Noise core cannot compile or pass protocol vectors on Android
  or iOS. Do not fall back to an unauthenticated/public LAN service.
- A capability probe can only test an open port or credential presence rather
  than product identity/authenticated behavior. It cannot become Ready.
- A release target omits a public compile feature/resource without an explicit
  catalog UnavailableReason and matching docs.
- A focused verification gate fails twice after a reasonable correction.
- Exact-head remote CI/Security/CodeQL or clean-machine jobs are unavailable;
  leave GOLD/tag status open.

## Maintenance notes

- The capability catalog and target release lock become the source of truth for
  public feature matrices, docs, packaging, updater, installer, Doctor, GUI,
  Buddy, and release self-knowledge. Adding a public adoption means adding its
  complete lifecycle and tests in the same change.
- Never add a new per-feature downloader or progress enum. Extend the shared
  artifact/job interfaces.
- Keep upstream pins and notices reviewable. An automated dependency update may
  propose a lock change, but must not activate it without artifact, license,
  behavior, rollback, and clean-machine tests.
- Treat integration job schemas and capability ids as public migration
  contracts. Additive schema migrations and stable ids only.
- Reviewers should scrutinize Ready transitions, permission/audit order,
  secrets, archive extraction, ownership-safe uninstall, mutable URLs,
  authenticated probe quality, migration losslessness, mobile protocol reuse,
  and documentation generated before proof.
- Plan 003 may add broader GUI/CLI/Buddy product parity, but it must consume the
  CapabilityDescriptor and integration job contracts from this plan rather
  than duplicating capability/progress state.
