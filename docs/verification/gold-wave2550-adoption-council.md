# W2550 — NEOTH adoption council, 2026-10-12

Reviewed baseline: `11f890affa65c3abeaae65ff7069f8fcac3c6a10`. This is a source-backed research and build-plan decision, **not implementation, installed-tool, model-training, device or Gold acceptance**.

The council accounted for **51 user inputs**. It inspected code samples at **50 pinned repository revisions**; the exact Jay article remains unresolved. Nine remote-only research agents supplied domain reports, followed by a cross-domain critique. Root alone inspected NEOTH and wrote files, using serial Idle-priority, one-core PowerShell text/JSON/hash/Git operations. No local product, parser, compiler, browser, model or test runtime was started.

The complete machine-readable ledger is [gold-wave2550-adoption-council.json](gold-wave2550-adoption-council.json). Each source entry records its current pin, actual implementation links, release/change evidence, license boundary, finding and disposition. Two sampled files do not constitute an exhaustive repository audit; upstream feature lists and reported tests are not proof of working NEOTH behavior.

## Decisions for Anatomy and MASS

**Anatomy: useful optional tooling.** Its [pinned kit](https://github.com/wheresryan22/anatomy/tree/689dcf966e63d92be10a5d593c6e19e10acd4422) produces technical SVG/interactive illustrations. The inspected geometry audit and Chrome capture pipeline check rendering properties, not whether the explanation is true. The MIT code can be considered with its notices. Root may select it for architecture/explanation work only when a visual adds value, after supplying canonical facts and choosing an allowed remote renderer. Nothing is installed or run here. NEOTH receives a proposed optional ExplanationArtifact seam (A06), not a new production runtime dependency.

**MASS: useful workflow research and a conditional training path.** The [official publication](https://pub.sakana.ai/mass/) studies both workflow search with fixed weights and distillation of team trajectories into model weights. This can improve a trainable model used by NEOTH; it does not automatically improve application correctness, memory or tool authority. Reported transfer is uneven: research score per output token improves, while the same metric is below baseline on two coding benchmarks. These are research results, not an estimate of improvement for NEOTH.

The [running guide](https://github.com/SakanaAI/mass/blob/fb403581bed2c974b3f99e7236224169da643079/docs/running.md) reports six H100 GPUs and about 19 hours for first-cycle SFT alone, excluding workflow search and data collection. That describes the published experiment, **not a minimum for every smaller pilot**. The supplied task executor has no sandbox; it is unsuitable for this workstation. The [NOTICE](https://github.com/SakanaAI/mass/blob/fb403581bed2c974b3f99e7236224169da643079/NOTICE.md) assigns no public open-source license to MASS-specific code. No code is copied or adapted.

The user's training question changes the decision from a categorical rejection to **R01: a separate NEOTH-domain evaluation and optional training experiment**. First measure a fixed-model baseline against task-specific contracts. If worthwhile, select a licensed trainable model and independently implemented/permitted training stack, allocate a bounded isolated remote environment, and compare against held-out NEOTH tasks. API access to a proprietary model does not itself provide editable model weights. No training, GPU rental, model replacement or production dispatch is authorized by this research result.

## Existing NEOTH owners and inspected overlap

- `SRC/neothd/src/recipes/schema.rs`: Typed input parameters, subrecipes, retry success_check already exist; no general artifact-verifier contract in the inspected schema.
- `SRC/neothd/src/cli/workflow_replay.rs`: Curated prompt corpus with contains-v1, config/skill/source hashes and empty MCP scope; not a general correctness grader.
- `SRC/neothd/src/council/types.rs`: Typed responses/refusals/verdicts and metadata-only agreement; preserve absent/not-evaluated evidence.
- `SRC/neothd/src/providers/cost_authorization.rs`: Existing budget reservation and council precharge ownership.
- `SRC/neothd/src/cron/scheduler.rs`: Generation-aware reload/completion, rejected config and durable checkpoints already exist.
- `SRC/neothd/src/wal/context_evidence_receipts.rs`: Bounded authenticated receipt ledger, generation anchors and predecessor retention already exist.
- `SRC/neothd/src/wal/scan.rs`: Retained authenticated history constrains HMAC key rotation/retention.
- `SRC/neothd/src/memory/document_claims.rs`: Source+claim+scope applied-once ledger shares savepoint with fact mutation; document text remains untrusted BulkText.
- `SRC/neothd/src/daemon/email_ingest_cron.rs`: Seen-item ledger, quarantine and local-before-external sink order already present; proposed unit recovery requires a demonstrated missing case, not an assumption of absent durability.
- `SRC/neothd/src/cli/todo.rs`: Canonical external task write admission already implemented.
- `SRC/neothd/src/cli/calendar.rs`: Read grant and payload-bound write admission already exist.
- `SRC/neothd/src/security/injection_tracker.rs`: Existing deterministic canary/sender/turn-signal handling must not be replaced by an uncalibrated classifier.
- `apps/neoth_companion/lib/companion_controller.dart`: Authority epoch, offline state and pending request recovery already present; no new mobile queue owner.
- `apps/neoth_companion/lib/conversation_models.dart`: Pending request/conversation identity invariants already enforced.
- `SRC/neothd/src/recall/parity_batch_plan.rs`: Immutable redacted plan and canonical digest can anchor comparison provenance; extend existing evidence, no second evaluator authority.

These are bounded static observations. A proposed gap must first produce an exact missing behavior/acceptance case. Existing functionality should be mapped to its existing proof, not reimplemented because an upstream repository describes the same pattern.

## Council decisions and bounded work

### A04 — Connector outcomes and outbound draft revisions

- State: **planned-gap-validation**; order: first.
- Owner: Root / existing connector and effect owners.
- Sources: SRC-01, SRC-02, SRC-13, SRC-14, SRC-15, SRC-36.

Begin with a gap case in email sink recovery, then extend the existing receipt/cursor owner. Unit key includes connector/account/item/revision/input hash. States committed, retryable, terminal_failure, unknown_outcome remain distinct. Explicit per-tool atomic-or-partial batch policy. Optional publication drafts bind destination rendition, payload revision and existing approval.

Acceptance:

- Prove a currently missing case before changing existing admission; no duplicate canonical owner.
- Crash after external success/before receipt never blindly retries an indeterminate effect; reconcile provider evidence or require replan.
- One failed unit cannot erase successful receipts or mark the whole scan complete.
- Same idempotency key/different destination, content or grant conflicts; changed rendition requires current approval.
- Reserved connector/daemon metadata cannot be overridden by model payload.

### A01 — Evidence-bound workflow handoffs and comparable trials

- State: **planned-gap-validation**; order: second.
- Owner: Root / existing council, recipe and replay owners.
- Sources: SRC-17, SRC-21, SRC-37, SRC-40, SRC-42, SRC-44, SRC-51.

An immutable contract sidecar binds workflow/version, inputs/config/corpus/skill hashes, declared effects, output schema and versioned verifier. Existing effect/WAL/replay paths own state. Compare curated run artifacts using existing parity provenance; do not equate contains-v1 with product correctness.

Acceptance:

- Verifier outcome is verified/failed/inconclusive/not-run; missing, stale or foreign verifier evidence cannot admit dependent effect.
- Only declared dependencies block, not unrelated work; artifact without independent verification is not fact.
- Selective recovery lists preserved/rerun units and requires terminal source, exact contract/plan/input bindings plus effect receipts; otherwise needs_manual_replan.
- Unknown external outcome never reruns automatically. Same reservation/budget owner persists through retry/cancel.
- Comparable reports preserve both candidates, evaluator identity/version, criteria and config mismatches; no self-voted automatic policy/model promotion.

### A02 — Prompt-component cost attribution

- State: **planned-gap-validation**; order: third.
- Owner: Root / prompt assembly and existing cost owner.
- Sources: SRC-22, SRC-38.

Attach component identity/count metadata to existing reservation: system, workflow, skill, retrieval, tool result, user, unattributed. Retain provider/model/tokenizer/rate versions; capture at assembly, not MITM.

Acceptance:

- No second precharge or billing owner.
- Observed provider totals reconcile with attributed plus unattributed usage; estimates stay distinct and need not equal provider billing.
- Missing usage remains unknown, including timeout after send; no raw prompt or secret leakage.
- Repeated/reused prompt components are accounted under explicit cached/uncached rules where provider evidence exists.

### A03 — Structure-preserving source projections and document lineage

- State: **planned-gap-validation**; order: fourth.
- Owner: Root / current document staging, recall and lifecycle owners.
- Sources: SRC-07, SRC-09, SRC-10, SRC-25, SRC-27.

Add bounded source projections for headings/tables/lists/code and original ranges; logical document/revision/rename lineage follows the existing staging and source/claim/scope owner. Purge lineage includes derived projections; payload erasure and minimum audit metadata remain distinct.

Acceptance:

- Same source and parser version yields deterministic bounded projection; oversized blocks follow explicit overflow policy instead of unbounded whole-table retention.
- Every citation resolves to the exact source revision/range; moved/repeated equal blocks are not silently the same identity.
- Cancellation never publishes a partial index as complete; rename does not replace content history.
- Derived data deletion failures remain visible/retryable and cannot be declared erased prematurely.
- Existing applied-once document claims and source/scope authority remain unchanged.

### A05 — Extend W2485 Jarvis/WhatsApp tool-call mobile port only where current companion lacks projection

- State: **merge-existing-Jarvis-mobile-port**; order: parallel-product-track-not-same-patch.
- Owner: Root / canonical companion daemon and Flutter projection.
- Sources: SRC-06, SRC-17, SRC-18, SRC-26, SRC-31, SRC-34, SRC-35.

Extend W2485 Jarvis/WhatsApp tool-call mobile port only where current companion lacks projection. Single daemon delivery/effect owner; client ID correlates to canonical event ID. Display pending/unknown/failed/confirmed faithfully, typed approvals/action cards and endpoint/environment rebind.

Acceptance:

- Provider echo joins only proven message identity; identical text alone never deduplicates messages.
- Disconnected mobile never labels unacknowledged mutation sent or resends an unknown outcome automatically.
- Offline queue is a bounded projection/submission buffer with no independent effect/retry authority; reconnect revalidates canonical state.
- Approval binds current tool/destination/payload revision; session/incognito/subject switches cannot leak previous state.
- Endpoint/environment switch rejects stale credential binding; owner-authorized revocation remains possible.
- Hosted contract/UI evidence then actual device acceptance separately; no .slint edits under current hold.

### A06 — ExplanationArtifact for selected verified activity/architecture/source facts

- State: **planned-no-install**; order: optional-product-and-tooling.
- Owner: Root / artifact export owner and optional approved remote renderer.
- Sources: SRC-44, SRC-46, SRC-50.

ExplanationArtifact for selected verified activity/architecture/source facts. Inert HTML/SVG export is default; interactive Anatomy rendering is a separately declared active-content mode. Preserve input/source hashes, model/renderer revision and illustrative/observed/derived labels. No renderer dependency for daemon startup.

Acceptance:

- Export exactly selected approved facts; no illustrative geometry promoted to verification.
- No external requests or arbitrary embedded input HTML/script in inert mode; redact before export.
- Active renderer has explicit allowlisted assets, resource/deadline caps and isolated approved host; failure cannot mark artifact verified.
- Output digest/source revisions retained before publication; accessible static fallback, keyboard/reduced motion where interactive.
- BSOD hold: no local Node, browser or rendering. Current research is not installed-tool or rendered-artifact acceptance.

### A07 — Visible reversible explicit session/device presentation override, with preference precedence and compaction restoration inside the existing profile engine

- State: **merge-GOLD-R4-11**; order: merge-existing-profile-work.
- Owner: Root / communication profile and presentation owners.
- Sources: SRC-45.

Visible reversible explicit session/device presentation override, with preference precedence and compaction restoration inside the existing profile engine. Complements existing default-on adaptation; no second profile store.

Acceptance:

- Explicit selection outranks inferred preference; off/reset is durable and visible.
- Compaction/reconnect preserve declared scope without leaking across users/incognito.
- Never infer ADHD/medical labels or change permissions/tool effects from presentation preference.
- No arbitrary response-length cap copied from an upstream skill.

### A08 — Compare current Responses/provider adapter against explicit capability descriptors

- State: **planned-gap-validation**; order: merge-existing-provider-contracts.
- Owner: Root / provider adapter owner.
- Sources: SRC-48.

Compare current Responses/provider adapter against explicit capability descriptors. Unsupported hosted tools, store:false, tool arguments/results, reasoning/redaction and cancellation must be represented honestly; no Strata engine dependency.

Acceptance:

- Unsupported tool cannot silently drop and report success.
- Store:false cannot be upgraded to durable remote storage.
- Queue/cancel/unknown-terminal state remains typed; authority and source policies enforced by existing owner.
- Only add regression for a demonstrated gap; no second inference server.

### R01 — NEOTH-domain multi-agent trajectory training

- State: **experiment-design-only**; order: conditional-research-not-1.0-release-gate.
- Owner: Root / model evaluation research; no current compute dispatch.
- Sources: SRC-51.

Potentially improve a trainable model used by NEOTH. First compare fixed-model task-specific handoff workflows against baseline. Only then a separately budgeted remote SFT/LoRA pilot using permitted model/data/training tools. No MASS-specific code copy without grant; no automatic model replacement.

Acceptance:

- Preregister disjoint train/development/heldout task families, corpus hashes, objective checks, independent blinded judgments and quality/cost/latency thresholds before optimization.
- Equal total inference/evaluation budget for workflow-only comparisons; report all trials, failures, confidence intervals and retained baseline, not only champions.
- Training corpus consists of licensed/authorized curated or synthetic successful and failure/recovery trajectories; no automatic private WAL/chat harvesting or hidden reasoning extraction.
- Measure task completion, tool/permission/side-effect correctness, recovery, retention of coding skills, total tokens/latency/cost including search/data generation/training.
- New model wins defined NEOTH target tasks without violating effect authority or regressing required functions; otherwise retain baseline.
- Record model/adapter/data/optimizer/evaluator provenance, checkpoint rollback and cancellation; isolated compute with fixed resource cap. No local workload under BSOD hold.
- Question about benefit does not authorize paid GPU rental, production deployment or training run. Concrete compute/model selection and cost cap remain prerequisites.

## Conditional connectors and excluded scope

These ideas are retained with entry conditions; they are not silently added as required 1.0 product suites. An optional adapter is not a license exemption. Before actual implementation, verify the exact file/API/asset terms and integration boundary.

- **C01 — Recurring task templates and work-order instances** (SRC-03, SRC-04): After core task delivery; reuse current scheduler; revision/timezone/instance idempotency, no maintenance-suite clone.
- **C02 — Remote device-test adapter** (SRC-05): Only bounded approved remote devices; session ownership, disconnect/cancel/reap and resource budget; no local emulator.
- **C03 — Read-only structured data/Zotero connectors** (SRC-08, SRC-36): Concrete connector demand, documented API/license, snapshot/source/row identity; no database or library engine embedding.
- **C04 — Ephemeral shared artifact** (SRC-11): Separate payload expiry, revocation, share authority and retained minimal audit; no in-process presence as truth.
- **C05 — Federated search descriptors** (SRC-16): Registry overlap check, per-provider source/destination permission, bounded fan-out/timeout, result provenance, explicit unavailable state.
- **C06 — Backup catalog** (SRC-23): No new scheduler; verify new generation before retention deletes old; backup identity separate from Recall evidence.
- **C07 — Optional location/trail context** (SRC-27, SRC-28): Explicit chosen source, raw/derived separation, time-range scope and retention, manual import first; no default location collection.
- **C08 — Optional pantry/recipe or service-launcher connector** (SRC-29, SRC-30): Existing credential/permission owners; read/write/destructive distinct; no replacement apps.
- **C09 — Optional visual sensor** (SRC-32): Prove useful bounded observed-state task before camera/model pipeline; accuracy/resource/retention limits; no inference acceptance from code inspection.
- **C10 — Advisory injection classifier** (SRC-41): Resolve exact article; model license and independent multilingual corpus/calibration; deterministic untrusted framing stays authoritative; classifier never grants permission.
- **C11 — Canvas recovery / animation / CAD** (SRC-43, SRC-47): No current product requirement for embedded CAD/solver/animation engine. Separate optional future artifact worker; owner-bound recovery and asset licenses.
- **C12 — User-initiated network diagnostics** (SRC-49): No GhostTrack source import; stale/no license/weak HTTP-hit heuristic. If useful, design bounded HTTPS/source-labeled diagnostics independently with minimal retention.

## Source coverage ledger

Every resolved repository below has at least two reviewed source bodies or, for instruction-only skills, the actual instruction asset plus its executable helper. Links use the captured commit. Releases and head changes are stated independently; an old release is not represented as current code.

### SRC-01 — [LosaLosSantos/aurelio-finance](https://github.com/LosaLosSantos/aurelio-finance)

Pin: `29727d84416b4f8d6c57381c4a8f27a08fbd78d4`; commit date: 2026-10-11. License: MIT.

Change evidence: Recent b6a03ac adds persisted before/after changes to chat context; upstream test claims not rerun.

Inspected: [backend/app/chat.py](https://github.com/LosaLosSantos/aurelio-finance/blob/29727d84416b4f8d6c57381c4a8f27a08fbd78d4/backend/app/chat.py); [backend/app/chain.py](https://github.com/LosaLosSantos/aurelio-finance/blob/29727d84416b4f8d6c57381c4a8f27a08fbd78d4/backend/app/chain.py).

Finding: Chat separates proposed changes from confirmed CRUD/UoW effects; bounded analyst/confidant calls and per-step costs.

Decision: Reuse existing NEOTH approval/effect owner; add user-visible verified before/after receipts where absent. Mapping: **A04**.

### SRC-02 — [Cloeille/picsou-finance](https://github.com/Cloeille/picsou-finance)

Pin: `b0a038ffd83100f98cd8b1e50cf52a87e5e23aae`; commit date: not established. License: Apache-2.0 plus Commons Clause/custom additional conditions; concrete reuse compatibility unresolved.

Change evidence: Bank-sync docs distinguish active EnableBanking and disabled/unvalidated Powens; release not established.

Inspected: [backend/src/main/java/com/picsou/port/BankConnectorPort.java](https://github.com/Cloeille/picsou-finance/blob/b0a038ffd83100f98cd8b1e50cf52a87e5e23aae/backend/src/main/java/com/picsou/port/BankConnectorPort.java); [backend/src/main/java/com/picsou/service/SyncService.java](https://github.com/Cloeille/picsou-finance/blob/b0a038ffd83100f98cd8b1e50cf52a87e5e23aae/backend/src/main/java/com/picsou/service/SyncService.java).

Finding: OAuth state binds member and nonce; a consumed-session checkpoint precedes fallible balance updates; retries and reconnect preserve external identity.

Decision: Use connector state/checkpoint requirements only; no banking product or source import. Mapping: **A04**.

### SRC-03 — [Worklenz/worklenz](https://github.com/Worklenz/worklenz)

Pin: `98a874697806dec810600755cc7c4e6c33cb40a8`; commit date: 2026-10-09. License: AGPL-3.0.

Change evidence: Current commit is dependency maintenance, not proof of a newly shipped recurrence feature.

Inspected: [worklenz-backend/src/controllers/task-recurring-controller.ts](https://github.com/Worklenz/worklenz/blob/98a874697806dec810600755cc7c4e6c33cb40a8/worklenz-backend/src/controllers/task-recurring-controller.ts); [worklenz-backend/src/cron_jobs/recurring-tasks.ts](https://github.com/Worklenz/worklenz/blob/98a874697806dec810600755cc7c4e6c33cb40a8/worklenz-backend/src/cron_jobs/recurring-tasks.ts).

Finding: Recurring task configuration and scheduled instance creation are separate responsibilities.

Decision: Optional recurring task templates on existing scheduler; combine with CMMS, not a second project manager. Mapping: **C01**.

### SRC-04 — [Grashjs/cmms](https://github.com/Grashjs/cmms)

Pin: `347c0e24995c0205d926c1f2f6851665283d73a8`; commit date: 2026-10-05. License: AGPL-3.0.

Change evidence: Current change fixes translated placeholders; root README unavailable in council retrieval.

Inspected: [api/src/main/java/com/grash/model/WorkOrder.java](https://github.com/Grashjs/cmms/blob/347c0e24995c0205d926c1f2f6851665283d73a8/api/src/main/java/com/grash/model/WorkOrder.java); [api/src/main/java/com/grash/model/PreventiveMaintenance.java](https://github.com/Grashjs/cmms/blob/347c0e24995c0205d926c1f2f6851665283d73a8/api/src/main/java/com/grash/model/PreventiveMaintenance.java).

Finding: Work-order status/ownership and preventive-maintenance schedule are distinct model concepts.

Decision: Optional accountable recurring task instances; no separate maintenance suite. Mapping: **C01**.

### SRC-05 — [jo-duchan/tapflow](https://github.com/jo-duchan/tapflow)

Pin: `72c761d59e08309122c6ce7f4691058cc350e003`; commit date: 2026-10-11. License: MIT.

Change evidence: Latest stores flow video during upload; iOS changelog describes bounded reconnect/teardown; roadmap action timeline remains unimplemented.

Inspected: [packages/cli/src/lib/approval-prompt.ts](https://github.com/jo-duchan/tapflow/blob/72c761d59e08309122c6ce7f4691058cc350e003/packages/cli/src/lib/approval-prompt.ts); [packages/android-agent/src/emulator/EmulatorVideo.ts](https://github.com/jo-duchan/tapflow/blob/72c761d59e08309122c6ce7f4691058cc350e003/packages/android-agent/src/emulator/EmulatorVideo.ts).

Finding: Explicit approval UI; emulator frames use bounded backpressure and teardown handles EPIPE/late frames. Protocol docs bind sessions to authenticated user/client identity.

Decision: Keep as optional remote device-test adapter reference; no local emulators or runtime under hold. Mapping: **C02**.

### SRC-06 — [prasadpatil25/MindSpark](https://github.com/prasadpatil25/MindSpark)

Pin: `f2fd2f551bb4fc240b83f72162ae2c5ca26613ef`; commit date: 2026-09-29. License: MIT.

Change evidence: cd97615 hardens legacy map claim, metadata and relay event authority.

Inspected: [worker/auth-core.js](https://github.com/prasadpatil25/MindSpark/blob/f2fd2f551bb4fc240b83f72162ae2c5ca26613ef/worker/auth-core.js); [worker/collab-do.js](https://github.com/prasadpatil25/MindSpark/blob/f2fd2f551bb4fc240b83f72162ae2c5ca26613ef/worker/collab-do.js).

Finding: Owner/editor/viewer capabilities and protected-resource claims; relay must not accept server-owned event types from clients.

Decision: Map to existing NEOTH companion authority and regressions; do not create a second collaboration service. Mapping: **A05**.

### SRC-07 — [MODSetter/SurfSense](https://github.com/MODSetter/SurfSense)

Pin: `552e05631c7df9b6252c21aa94cd0302fd00e7ce`; commit date: 2026-10-09. License: Apache-2.0 except proprietary subtree under BSL-1.1.

Change evidence: Desktop v2.2.0; no changelog found by council.

Inspected: [surfsense_backend/app/indexing_pipeline/document_chunker.py](https://github.com/MODSetter/SurfSense/blob/552e05631c7df9b6252c21aa94cd0302fd00e7ce/surfsense_backend/app/indexing_pipeline/document_chunker.py); [surfsense_backend/app/indexing_pipeline/document_embedder.py](https://github.com/MODSetter/SurfSense/blob/552e05631c7df9b6252c21aa94cd0302fd00e7ce/surfsense_backend/app/indexing_pipeline/document_embedder.py).

Finding: Markdown table-aware chunks retain table structure and line spans; embeddings follow indexing chunks.

Decision: Native bounded table/section chunks and stable citation anchors, following NEOTH staging authority. Mapping: **A03**.

### SRC-08 — [baserow/baserow](https://github.com/baserow/baserow)

Pin: `ae95e512e1675db6cb1b73e8ac2266b9369b4061`; commit date: 2026-10-09. License: OSE/client MIT; docs CC-BY-SA; premium/enterprise have separate terms.

Change evidence: 2.4.0 September 30: row action sequences, field permissions, workspace providers and workflow cancellation.

Inspected: [backend/src/baserow/contrib/database/table/handler.py](https://github.com/baserow/baserow/blob/ae95e512e1675db6cb1b73e8ac2266b9369b4061/backend/src/baserow/contrib/database/table/handler.py); [backend/src/baserow/contrib/database/rows/handler.py](https://github.com/baserow/baserow/blob/ae95e512e1675db6cb1b73e8ac2266b9369b4061/backend/src/baserow/contrib/database/rows/handler.py).

Finding: Dynamic table/row mutations include transaction, dependency-cache and search maintenance.

Decision: Optional read-only view snapshot connector with stable row/revision/source identity; no dynamic database engine import. Mapping: **C03**.

### SRC-09 — [Systaro/DocuVault](https://github.com/Systaro/DocuVault)

Pin: `d82c07944df7013303abf1539df625fc04dfa8e0`; commit date: 2026-10-03. License: BSL-1.1 with competitive-service restriction and future Apache conversion.

Change evidence: v0.8.5 commit; v0.8.4 September 30 includes AI-created separate documents.

Inspected: [backend/src/main/kotlin/com/docuvault/service/DocumentPersistService.kt](https://github.com/Systaro/DocuVault/blob/d82c07944df7013303abf1539df625fc04dfa8e0/backend/src/main/kotlin/com/docuvault/service/DocumentPersistService.kt); [backend/src/main/kotlin/com/docuvault/service/DocumentLineageService.kt](https://github.com/Systaro/DocuVault/blob/d82c07944df7013303abf1539df625fc04dfa8e0/backend/src/main/kotlin/com/docuvault/service/DocumentLineageService.kt).

Finding: Persistence spans file/Git, database and embeddings; lineage traces moves and original authorship.

Decision: Native logical-document lineage; preserve revisions and citation identity across rename, do not conflate content equality with identity. Mapping: **A03**.

### SRC-10 — [gyaaniguy/personal-drive](https://github.com/gyaaniguy/personal-drive)

Pin: `3ce0d278a4511e64035a45522329c3997572e796`; commit date: 2026-10-02. License: Apache-2.0.

Change evidence: v2.0 September 13; changelog includes queued-upload cancellation, encrypted ZIPs and viewer/path handling.

Inspected: [app/Http/Controllers/DriveControllers/FileManagerController.php](https://github.com/gyaaniguy/personal-drive/blob/3ce0d278a4511e64035a45522329c3997572e796/app/Http/Controllers/DriveControllers/FileManagerController.php); [app/Http/Controllers/ShareControllers/ShareFilesGenController.php](https://github.com/gyaaniguy/personal-drive/blob/3ce0d278a4511e64035a45522329c3997572e796/app/Http/Controllers/ShareControllers/ShareFilesGenController.php).

Finding: File staging/share controls, including direct shares restricted to a single file.

Decision: Add cancel/staging proof only if absent in current document route; do not build a duplicate drive. Mapping: **A03**.

### SRC-11 — [sorathiya903/pastedb](https://github.com/sorathiya903/pastedb)

Pin: `be621edb655fa3d5f6a6c2fb3b8cb4c813feaa95`; commit date: 2026-10-09. License: MIT.

Change evidence: No release/changelog found.

Inspected: [backend/main.py](https://github.com/sorathiya903/pastedb/blob/be621edb655fa3d5f6a6c2fb3b8cb4c813feaa95/backend/main.py); [backend/collab.py](https://github.com/sorathiya903/pastedb/blob/be621edb655fa3d5f6a6c2fb3b8cb4c813feaa95/backend/collab.py).

Finding: Mongo TTL/search with raw API-key lookup and in-process collaborative presence; advertised expiry is not durable audit proof.

Decision: Defer paste/collaboration service; any ephemeral export must separate payload expiry from retained audit metadata. Mapping: **C04**.

### SRC-12 — [AnanthaRajuC/QueryAPIGate](https://github.com/AnanthaRajuC/QueryAPIGate)

Pin: `087e9419348658bded66f7551c9ab405516fa976`; commit date: 2026-10-12. License: FSL-1.1-MIT; present noncompeting terms, later MIT.

Change evidence: Current Helm upgrade tests; changelog labels several MCP/OAuth/quota/audit features experimental.

Inspected: [queryapigate/auditchain.py](https://github.com/AnanthaRajuC/QueryAPIGate/blob/087e9419348658bded66f7551c9ab405516fa976/queryapigate/auditchain.py); [queryapigate/services/audit.py](https://github.com/AnanthaRajuC/QueryAPIGate/blob/087e9419348658bded66f7551c9ab405516fa976/queryapigate/services/audit.py).

Finding: Transactional audit hash chain, HMAC rotation and retained anchors.

Decision: NEOTH already has authenticated WAL/receipt anchors and history-bound key retention. Evidence/reference only; no new audit engine. Mapping: **covered**.

### SRC-13 — [getopenpost/openpost](https://github.com/getopenpost/openpost)

Pin: `2b81d9d983a2f9701238ea9500c6bb7d030017fa`; commit date: 2026-10-11. License: AGPL-3.0.

Change evidence: v7.17.5 October 11.

Inspected: [apps/cli/internal/commands/publication.go](https://github.com/getopenpost/openpost/blob/2b81d9d983a2f9701238ea9500c6bb7d030017fa/apps/cli/internal/commands/publication.go); [apps/cli/internal/commands/schedule.go](https://github.com/getopenpost/openpost/blob/2b81d9d983a2f9701238ea9500c6bb7d030017fa/apps/cli/internal/commands/schedule.go).

Finding: Distinct draft/rendition/validation/publish/retry operations; expected revision guards updates; weekly schedules validated separately.

Decision: Add provider-specific draft/rendition binding through current canonical effect authority, optional self-hosted API adapter later. Mapping: **A04**.

### SRC-14 — [Maildun/maildun](https://github.com/Maildun/maildun)

Pin: `9077877c8d0c307c99dc41cf5dccbcdde41c109f`; commit date: 2026-10-11. License: AGPL-3.0 plus stated section-7 attribution/origin/trademark terms; root license inspected, compatibility not resolved.

Change evidence: v0.1.0-beta.1 October 2; 9068aab makes unsubscribe/system merge fields server-owned.

Inspected: [app/Actions/Transactional/QueueTransactionalEmail.php](https://github.com/Maildun/maildun/blob/9077877c8d0c307c99dc41cf5dccbcdde41c109f/app/Actions/Transactional/QueueTransactionalEmail.php); [app/Actions/Automations/AdvanceAutomationRun.php](https://github.com/Maildun/maildun/blob/9077877c8d0c307c99dc41cf5dccbcdde41c109f/app/Actions/Automations/AdvanceAutomationRun.php).

Finding: Idempotency key bound to canonical template/recipient/data fingerprint; mismatches conflict; duplicate insert races recover prior record.

Decision: Use as cross-adapter regression requirements; existing canonical admission remains owner. No bulk-mail platform. Mapping: **A04**.

### SRC-15 — [karatektus/pl_mail](https://github.com/karatektus/pl_mail)

Pin: `f19818fa5098385e5e233a6673f4105a44006da1`; commit date: 2026-10-11. License: AGPL-3.0.

Change evidence: No releases; current delete-forever operation defaults off per user.

Inspected: [src/Service/Imap/ImapAccountSyncer.php](https://github.com/karatektus/pl_mail/blob/f19818fa5098385e5e233a6673f4105a44006da1/src/Service/Imap/ImapAccountSyncer.php); [src/Service/Rule/MailRuleEngine.php](https://github.com/karatektus/pl_mail/blob/f19818fa5098385e5e233a6673f4105a44006da1/src/Service/Rule/MailRuleEngine.php).

Finding: Mailbox structure sync first, vanished folders skipped, individual failure cleanup; ordered rules with explicit stop behavior.

Decision: Inspect NEOTH email per-unit recovery gap; preserve prior successful sink effects and explicit unknown outcomes. Mapping: **A04**.

### SRC-16 — [degoog-org/degoog](https://github.com/degoog-org/degoog)

Pin: `5cd67cec74d38944792db498b604790624a1cbbe`; commit date: 2026-10-10. License: AGPL-3.0.

Change evidence: 1.1.0 October 10.

Inspected: [src/server/search/engine-selection.ts](https://github.com/degoog-org/degoog/blob/5cd67cec74d38944792db498b604790624a1cbbe/src/server/search/engine-selection.ts); [src/server/search/engine-timeout.ts](https://github.com/degoog-org/degoog/blob/5cd67cec74d38944792db498b604790624a1cbbe/src/server/search/engine-timeout.ts).

Finding: Input/capability engine selection, stable masked config fingerprint, bounded provider timeout.

Decision: Optional bounded federated-search adapter descriptors after registry overlap check; no arbitrary executable plugin framework. Mapping: **C05**.

### SRC-17 — [helpin-ai/helpin](https://github.com/helpin-ai/helpin)

Pin: `7d50197435c797ad329f71888173f8bdecc8dd88`; commit date: 2026-10-11. License: Community AGPL-3.0-only; any ee directory enterprise; listed SDK/widget directories Apache-2.0; root scope confirmed.

Change evidence: server-v0.95.474; recent reversible conversation merging and edge-case correction.

Inspected: [server/internal/agentcontract/interaction_contracts.go](https://github.com/helpin-ai/helpin/blob/7d50197435c797ad329f71888173f8bdecc8dd88/server/internal/agentcontract/interaction_contracts.go); [server/internal/decision/policy.go](https://github.com/helpin-ai/helpin/blob/7d50197435c797ad329f71888173f8bdecc8dd88/server/internal/decision/policy.go).

Finding: Typed ask/approval/checkpoint contracts; explicit off/shadow/primary semantic routing and limits.

Decision: Reuse existing consent owner; extend typed mobile projection/handoff only for demonstrated gaps. Shadow cannot dispatch. Mapping: **A01,A05**.

### SRC-18 — [zackb/tether](https://github.com/zackb/tether)

Pin: `62b4670b50ce5422e4ceeb510849790a512ee10d`; commit date: 2026-10-10. License: MIT.

Change evidence: v0.2.37 October 10.

Inspected: [src/core/src/bluetooth/messages.cpp](https://github.com/zackb/tether/blob/62b4670b50ce5422e4ceeb510849790a512ee10d/src/core/src/bluetooth/messages.cpp); [src/core/src/otp.cpp](https://github.com/zackb/tether/blob/62b4670b50ce5422e4ceeb510849790a512ee10d/src/core/src/otp.cpp).

Finding: Deterministic local/provider echo reconciliation and bounded retention; OTP TTL and registrable-domain binding.

Decision: Apply proven-ID echo semantics to Jarvis/WhatsApp mobile port; Apple/MAP stack and OTP automation deferred. Mapping: **A05**.

### SRC-19 — [harshalgajjar/Reminal](https://github.com/harshalgajjar/Reminal)

Pin: `06da92d4b7f26f9248546067b3059c9953d049c5`; commit date: 2026-10-11. License: AGPL-3.0-or-later.

Change evidence: v3.16.4; latest changelog-format checks.

Inspected: [internal/session/restore.go](https://github.com/harshalgajjar/Reminal/blob/06da92d4b7f26f9248546067b3059c9953d049c5/internal/session/restore.go); [internal/atrest/atrest.go](https://github.com/harshalgajjar/Reminal/blob/06da92d4b7f26f9248546067b3059c9953d049c5/internal/atrest/atrest.go).

Finding: Sealed restore uses locks/atomic publication before legacy deletion; keystore transient lock distinguished from lost key; corrupt state quarantined.

Decision: Reference existing NEOTH restore/authority tests; no terminal manager import. Mapping: **covered**.

### SRC-20 — [flohoss/gocron](https://github.com/flohoss/gocron)

Pin: `1d4629f282eec3510e1b041f5d22b8a626ee62f8`; commit date: 2026-10-05. License: MIT.

Change evidence: v0.13.2 warns about timezone configuration.

Inspected: [internal/scheduler/scheduler.go](https://github.com/flohoss/gocron/blob/1d4629f282eec3510e1b041f5d22b8a626ee62f8/internal/scheduler/scheduler.go); [services/jobs.go](https://github.com/flohoss/gocron/blob/1d4629f282eec3510e1b041f5d22b8a626ee62f8/services/jobs.go).

Finding: Stop context, persisted jobs, boot recovery and rejected config preserving prior schedule.

Decision: Current NEOTH scheduler already has generation-scoped completion and rejected reload. Map proof, no new scheduler. Mapping: **covered**.

### SRC-21 — [ptweezy/cronstable](https://github.com/ptweezy/cronstable)

Pin: `1e32c6cdbe3491b90b58f928ba0fb1facf528fad`; commit date: 2026-10-12. License: MIT software; brand assets reserved separately.

Change evidence: 1.2.63 October 11; current dependency bump.

Inspected: [cronstable/cron.py](https://github.com/ptweezy/cronstable/blob/1e32c6cdbe3491b90b58f928ba0fb1facf528fad/cronstable/cron.py); [cronstable/recovery.py](https://github.com/ptweezy/cronstable/blob/1e32c6cdbe3491b90b58f928ba0fb1facf528fad/cronstable/recovery.py).

Finding: Leases, retry/timeout pools; content-bound DAG recovery refuses changed config/nonterminal state and preserves completed nodes.

Decision: Selective replay only behind plan/version/effect receipts and no automatic retry of unknown external effects. Mapping: **A01**.

### SRC-22 — [rustrak/rustrak](https://github.com/rustrak/rustrak)

Pin: `ad995239537ac72e916f7a0bed20df151622d751`; commit date: 2026-10-09. License: GPL-3.0.

Change evidence: v0.16.2 unhandled sessions.

Inspected: [packages/client/src/result.ts](https://github.com/rustrak/rustrak/blob/ad995239537ac72e916f7a0bed20df151622d751/packages/client/src/result.ts); [packages/mcp/src/tools/agents.ts](https://github.com/rustrak/rustrak/blob/ad995239537ac72e916f7a0bed20df151622d751/packages/mcp/src/tools/agents.ts).

Finding: Typed failure distinct from absent data; bounded trace, latency, token and tool-call queries.

Decision: Add explicit unknown/cost-attribution views using NEOTH telemetry; no observability server import. Mapping: **A02**.

### SRC-23 — [TimWitzdam/GitSave](https://github.com/TimWitzdam/GitSave)

Pin: `1f01edc3d586fb7ab9fce7169a4cd75284168a9b`; commit date: 2026-09-26. License: Apache-2.0.

Change evidence: v1.4.0 secret generator replacement.

Inspected: [backend/services/schedule.service.ts](https://github.com/TimWitzdam/GitSave/blob/1f01edc3d586fb7ab9fce7169a4cd75284168a9b/backend/services/schedule.service.ts); [backend/server.ts](https://github.com/TimWitzdam/GitSave/blob/1f01edc3d586fb7ab9fce7169a4cd75284168a9b/backend/server.ts).

Finding: Scheduled mirror clone, history/snapshots, retention and timeouts.

Decision: Optional backup catalog after core acceptance; same existing scheduler and owner, preserve last verified generation. Mapping: **C06**.

### SRC-24 — [mvschwarz/openrig](https://github.com/mvschwarz/openrig)

Pin: `3001cc436656c435e54425443e708e3e2d8c7d68`; commit date: 2026-10-11. License: Apache-2.0.

Change evidence: v0.6.9 restore guidance.

Inspected: [packages/cli/src/atomic-text-write.ts](https://github.com/mvschwarz/openrig/blob/3001cc436656c435e54425443e708e3e2d8c7d68/packages/cli/src/atomic-text-write.ts); [packages/cli/src/commands/reconcile-session.ts](https://github.com/mvschwarz/openrig/blob/3001cc436656c435e54425443e708e3e2d8c7d68/packages/cli/src/commands/reconcile-session.ts).

Finding: Private temporary-file publication; reconciliation can observe/rebind session without launching or sending input; unknown continuity remains unknown.

Decision: Recovery regression reference for existing owner-bound NEOTH state; no new agent manager. Mapping: **covered**.

### SRC-25 — [ancsemi/Haven](https://github.com/ancsemi/Haven)

Pin: `0c0e8af1c8d2805b7870a29c5143725529fdb1bf`; commit date: 2026-10-12. License: AGPL-3.0.

Change evidence: Current DM GIF button change; not a privacy semantic change.

Inspected: [src/auth.js](https://github.com/ancsemi/Haven/blob/0c0e8af1c8d2805b7870a29c5143725529fdb1bf/src/auth.js); [src/deletedAttachments.js](https://github.com/ancsemi/Haven/blob/0c0e8af1c8d2805b7870a29c5143725529fdb1bf/src/deletedAttachments.js).

Finding: Purpose-bound TOTP/session tokens; two-stage attachment retention sweeper with retry on locked files. Does not establish derived-data erasure completeness.

Decision: Use retention retry visibility as extension of current lifecycle; no chat server import. Mapping: **A03**.

### SRC-26 — [yuzicapp/yuzic](https://github.com/yuzicapp/yuzic)

Pin: `4305d585cc47a5d1eb853ad3851a6c7a5c9c2f24`; commit date: 2026-09-30. License: GPL-3.0.

Change evidence: Current merge Release 2.17.0 supersedes earlier 2.1.1 search result.

Inspected: [src/features/offline/offlineMutations.ts](https://github.com/yuzicapp/yuzic/blob/4305d585cc47a5d1eb853ad3851a6c7a5c9c2f24/src/features/offline/offlineMutations.ts); [src/features/offline/networkPolicy.ts](https://github.com/yuzicapp/yuzic/blob/4305d585cc47a5d1eb853ad3851a6c7a5c9c2f24/src/features/offline/networkPolicy.ts).

Finding: Typed persisted destination-bound queue; target-specific collapse; original scrobble time/expiry; disconnect drops. Unknown network is allowed in its Wi-Fi policy.

Decision: Reuse queue/expiry requirements through NEOTH canonical owner. Explicit per-capability unknown-network policy; do not inherit permissive music-download policy. Mapping: **A05**.

### SRC-27 — [open-wanderer/wanderer](https://github.com/open-wanderer/wanderer)

Pin: `e343edf761a35d8c543a9c99e4599ded15556d6f`; commit date: 2026-10-11. License: AGPL-3.0.

Change evidence: v0.21.0 September 28; current dockerignore maintenance.

Inspected: [db/hooks/api_tokens.go](https://github.com/open-wanderer/wanderer/blob/e343edf761a35d8c543a9c99e4599ded15556d6f/db/hooks/api_tokens.go); [db/federation/delete.go](https://github.com/open-wanderer/wanderer/blob/e343edf761a35d8c543a9c99e4599ded15556d6f/db/federation/delete.go).

Finding: Raw-once API token with hashed storage; deletes activity snapshots and propagates deletion to recorded audiences.

Decision: Reference derived/replicated erasure receipts; optional GPX read adapter remains separate. Mapping: **A03,C07**.

### SRC-28 — [dedicatedcode/reitti](https://github.com/dedicatedcode/reitti)

Pin: `3fcd4db2871954db1e4ca7cf2e2a702fb4510dae`; commit date: 2026-10-10. License: AGPL-3.0.

Change evidence: Older v5.1.0 release is not current behavior proof; current source/date checked, full semantic diff not established.

Inspected: [src/main/java/com/dedicatedcode/reitti/controller/api/v2/LocationApiController.java](https://github.com/dedicatedcode/reitti/blob/3fcd4db2871954db1e4ca7cf2e2a702fb4510dae/src/main/java/com/dedicatedcode/reitti/controller/api/v2/LocationApiController.java); [src/main/java/com/dedicatedcode/reitti/controller/api/ProcessedVisitApiController.java](https://github.com/dedicatedcode/reitti/blob/3fcd4db2871954db1e4ca7cf2e2a702fb4510dae/src/main/java/com/dedicatedcode/reitti/controller/api/ProcessedVisitApiController.java).

Finding: Separate raw location streams and zone-aware processed visit summaries; time/access-level guards. Full guard-chain behavior not audited.

Decision: Optional location context with independently specified raw/derived retention and time-range scopes; no default tracking. Mapping: **C07**.

### SRC-29 — [TraceApps/cooktrace](https://github.com/TraceApps/cooktrace)

Pin: `870bdc51257776f68250091f4177db3383b81c13`; commit date: 2026-10-11. License: AGPL-3.0.

Change evidence: 1.4.0 October 2; latest README Unraid update.

Inspected: [server/lib/api-tokens.js](https://github.com/TraceApps/cooktrace/blob/870bdc51257776f68250091f4177db3383b81c13/server/lib/api-tokens.js); [server/lib/mcp/server.js](https://github.com/TraceApps/cooktrace/blob/870bdc51257776f68250091f4177db3383b81c13/server/lib/mcp/server.js).

Finding: Hashed expiring/revocable PATs, read/write/destroy scopes, separate destructive gate; stateless per-request MCP relies on router authorization.

Decision: Optional recipe/pantry connector only through existing NEOTH permissions; no duplicate cooking app. Mapping: **C08**.

### SRC-30 — [man15h/holm](https://github.com/man15h/holm)

Pin: `59da72c6fcdcbe22e1581a6c52b51b21c3dd2ace`; commit date: 2026-10-09. License: MIT.

Change evidence: v0.5.0 merge; unreviewed UI feature delta not inferred.

Inspected: [src/lib/server/session.js](https://github.com/man15h/holm/blob/59da72c6fcdcbe22e1581a6c52b51b21c3dd2ace/src/lib/server/session.js); [src/lib/server/sessionToken.js](https://github.com/man15h/holm/blob/59da72c6fcdcbe22e1581a6c52b51b21c3dd2ace/src/lib/server/sessionToken.js).

Finding: Master-key-context-derived session signing, expiry and constant-time signature verification. App visibility rules not established by these files.

Decision: Per-user service launcher optional later; session primitives already exist, no launcher server import. Mapping: **C08**.

### SRC-31 — [screentinker/screentinker](https://github.com/screentinker/screentinker)

Pin: `104ef0db4ad5ec31b570f3e5d1b0c1780fda0cd4`; commit date: 2026-10-11. License: MIT.

Change evidence: v2.5.1 October 9.

Inspected: [server/lib/device-identity.js](https://github.com/screentinker/screentinker/blob/104ef0db4ad5ec31b570f3e5d1b0c1780fda0cd4/server/lib/device-identity.js); [server/lib/unpair-gate.js](https://github.com/screentinker/screentinker/blob/104ef0db4ad5ec31b570f3e5d1b0c1780fda0cd4/server/lib/unpair-gate.js).

Finding: Persistent device ID preferred, weaker fallback identifiers also exist; local PIN gate for unpairing.

Decision: Reference lifecycle UI only. Never infer proven identity from fallback fingerprint or make on-device PIN mandatory for already-authorized owner revocation. Mapping: **A05**.

### SRC-32 — [oleost/VisionState](https://github.com/oleost/VisionState)

Pin: `859722fc21d65b6cb2da224d53c1e457e96dc06f`; commit date: 2026-10-10. License: Apache-2.0.

Change evidence: v0.8.0.

Inspected: [visionstate/backend/visionstate/engine/state.py](https://github.com/oleost/VisionState/blob/859722fc21d65b6cb2da224d53c1e457e96dc06f/visionstate/backend/visionstate/engine/state.py); [visionstate/backend/visionstate/engine/training.py](https://github.com/oleost/VisionState/blob/859722fc21d65b6cb2da224d53c1e457e96dc06f/visionstate/backend/visionstate/engine/training.py).

Finding: Settings snapshot, debounce/object tracking and per-sensor classifiers from labeled examples.

Decision: Optional observed-state sensor adapter after separate data/model/resource assessment; no default camera inference. Mapping: **C09**.

### SRC-33 — [crivion/laranode](https://github.com/crivion/laranode)

Pin: `8a0a4b27051771be87bfc5c8fe0f283783a55e6f`; commit date: 2026-09-23. License: MIT.

Change evidence: No release confirmed.

Inspected: [app/Jobs/RunBackupJob.php](https://github.com/crivion/laranode/blob/8a0a4b27051771be87bfc5c8fe0f283783a55e6f/app/Jobs/RunBackupJob.php); [app/Filesystem/SafeFileProcess.php](https://github.com/crivion/laranode/blob/8a0a4b27051771be87bfc5c8fe0f283783a55e6f/app/Filesystem/SafeFileProcess.php).

Finding: Persisted backup job status and privileged process facade.

Decision: Existing NEOTH job outcomes cover generic idea; no VPS control panel or privileged facade import. Mapping: **covered**.

### SRC-34 — [Nethera-io/nethera](https://github.com/Nethera-io/nethera)

Pin: `f056cf0792aa912d60eafced257f99a851c634b3`; commit date: 2026-08-10. License: MIT.

Change evidence: No release confirmed.

Inspected: [agent/enroll.go](https://github.com/Nethera-io/nethera/blob/f056cf0792aa912d60eafced257f99a851c634b3/agent/enroll.go); [agent/jobs.go](https://github.com/Nethera-io/nethera/blob/f056cf0792aa912d60eafced257f99a851c634b3/agent/jobs.go).

Finding: Credential reuse binds endpoint/environment; bounded job command/output/timeout handling.

Decision: Add endpoint/environment change cases to companion pairing acceptance; canonical authority remains daemon. Mapping: **A05**.

### SRC-35 — [ar3ac/lucius](https://github.com/ar3ac/lucius)

Pin: `c454e7614d2d36fac362cae724be46e6c2dad5bf`; commit date: 2026-09-26. License: MIT.

Change evidence: v1.0.0.

Inspected: [main.py](https://github.com/ar3ac/lucius/blob/c454e7614d2d36fac362cae724be46e6c2dad5bf/main.py); [static/sw.js](https://github.com/ar3ac/lucius/blob/c454e7614d2d36fac362cae724be46e6c2dad5bf/static/sw.js).

Finding: PIN-gated named commands with execution/output bounds and PWA caching.

Decision: Typed approved mobile action cards if missing in current companion; no unrestricted shell/PWA engine import. Mapping: **A05**.

### SRC-36 — [eseifert/altero](https://github.com/eseifert/altero)

Pin: `0a258e1b86b3f82e40ccbcb0990cea4712cfc143`; commit date: 2026-10-09. License: AGPL-3.0.

Change evidence: Current master source inspected; release not confirmed.

Inspected: [src/altero/api/batch.py](https://github.com/eseifert/altero/blob/0a258e1b86b3f82e40ccbcb0990cea4712cfc143/src/altero/api/batch.py); [src/altero/db.py](https://github.com/eseifert/altero/blob/0a258e1b86b3f82e40ccbcb0990cea4712cfc143/src/altero/db.py).

Finding: Library/revision/idempotency locking, object savepoints, successful subset with structured failures and atomic activity; SQLite WAL/FKs.

Decision: Explicit per-tool partial-batch policy using existing transactions; optional Zotero adapter separately scoped. Mapping: **A04,C03**.

### SRC-37 — [tigerless-labs/autoharness](https://github.com/tigerless-labs/autoharness)

Pin: `9eec6232587ff2c4deeded00ac467de19532d763`; commit date: 2026-10-09. License: MIT.

Change evidence: No changelog/release; latest redaction respects validators.

Inspected: [src/autoharness/lib/validate.py](https://github.com/tigerless-labs/autoharness/blob/9eec6232587ff2c4deeded00ac467de19532d763/src/autoharness/lib/validate.py); [src/autoharness/hook/promoter.py](https://github.com/tigerless-labs/autoharness/blob/9eec6232587ff2c4deeded00ac467de19532d763/src/autoharness/hook/promoter.py).

Finding: Proposer/promoter distinction, path/schema/self-authored gate checks, materialized evidence and atomic skill publication.

Decision: Current installed-skill authority stays owner; verify admission receipt coverage rather than adding autonomous promotion. Mapping: **A01**.

### SRC-38 — [tigerless-labs/cost-xray](https://github.com/tigerless-labs/cost-xray)

Pin: `069733fabdc1416f2535148c0652cdfbb5bb7bee`; commit date: 2026-09-29. License: MIT.

Change evidence: Latest UTF-8/ASCII locale capture test.

Inspected: [cost_xray/addon.py](https://github.com/tigerless-labs/cost-xray/blob/069733fabdc1416f2535148c0652cdfbb5bb7bee/cost_xray/addon.py); [cost_xray/cost.py](https://github.com/tigerless-labs/cost-xray/blob/069733fabdc1416f2535148c0652cdfbb5bb7bee/cost_xray/cost.py); [cost_xray/detectors.py](https://github.com/tigerless-labs/cost-xray/blob/069733fabdc1416f2535148c0652cdfbb5bb7bee/cost_xray/detectors.py).

Finding: Proxy captures sessions; heuristic skill-detection patterns can miss or misattribute usage.

Decision: Native prompt-component attribution at NEOTH assembly boundary; no MITM raw-secret capture proxy. Mapping: **A02**.

### SRC-39 — [Jakeschincariol/replica-skill](https://github.com/Jakeschincariol/replica-skill)

Pin: `77c9436fb3d18c3d58169efb8caf4fe906b0dc51`; commit date: 2026-10-03. License: MIT.

Change evidence: v1.0 only observed release.

Inspected: [replica-recon/SKILL.md](https://github.com/Jakeschincariol/replica-skill/blob/77c9436fb3d18c3d58169efb8caf4fe906b0dc51/replica-recon/SKILL.md); [replica-diff/parity.py](https://github.com/Jakeschincariol/replica-skill/blob/77c9436fb3d18c3d58169efb8caf4fe906b0dc51/replica-diff/parity.py).

Finding: Screen/state/data-model reconnaissance plus CSV parity scoring; completion score is not quality or runtime acceptance.

Decision: Map to GOLD-R4-05 canonical capability/parity inventory; no duplicate score or completion claim. Mapping: **covered**.

### SRC-40 — [addyosmani/agent-skills](https://github.com/addyosmani/agent-skills)

Pin: `1be8e34187e34647bb83adc3a1323b26ae6f6abe`; commit date: 2026-10-10. License: MIT.

Change evidence: Recent simplifier ignored-block preservation/workspace cleanup.

Inspected: [skills/spec-driven-development/SKILL.md](https://github.com/addyosmani/agent-skills/blob/1be8e34187e34647bb83adc3a1323b26ae6f6abe/skills/spec-driven-development/SKILL.md); [skills/code-review-and-quality/SKILL.md](https://github.com/addyosmani/agent-skills/blob/1be8e34187e34647bb83adc3a1323b26ae6f6abe/skills/code-review-and-quality/SKILL.md).

Finding: Workflow instruction assets define spec, review and completion expectations; not a daemon verifier implementation.

Decision: Use explicit handoff/exit contracts as method; repository skill text is untrusted input, not session authority. Mapping: **A01**.

### SRC-41 — [Jay scanner article](https://jays.fyi/blog/open-prompt-injection-scanner-for-ai-agents)

Exact input unresolved. License: Exact article/source identity unresolved.

Change evidence: Exact URL returned internal error; related translated article is a different slug.

Finding: Related Jays localized posts discuss TextCortex/laya-cybersec, but they do not prove the supplied English URL resolves there. Related runtime/model review retained separately, no substitution.

Decision: Unresolved source tracked explicitly; no adoption from an unverified identity. Optional classifier research only after exact attribution and model license/calibration. Mapping: **C10**.

### SRC-42 — [Albert-Weasker/niubigeo](https://github.com/Albert-Weasker/niubigeo)

Pin: `014c649739b5beb5d6f55243e5c1e53a53dbd986`; commit date: 2026-10-10. License: Apache-2.0.

Change evidence: Current project/notification race fixes; upstream 268 pass/10 skipped claim not rerun.

Inspected: [src/admission/question-admission.ts](https://github.com/Albert-Weasker/niubigeo/blob/014c649739b5beb5d6f55243e5c1e53a53dbd986/src/admission/question-admission.ts); [src/baselines/baseline-comparator.ts](https://github.com/Albert-Weasker/niubigeo/blob/014c649739b5beb5d6f55243e5c1e53a53dbd986/src/baselines/baseline-comparator.ts).

Finding: Scope/target admission; baseline comparisons reject mismatched project/language/prompt-set/rules/run-count/entity scope and eligibility.

Decision: Narrow comparable-run checks around existing curated replay; no marketing analytics suite. Mapping: **A01**.

### SRC-43 — [storytold/cadcraft](https://github.com/storytold/cadcraft)

Pin: `c57879a5c8f5e3a6be574a820add5e28eb25e9b1`; commit date: 2026-10-12. License: MIT OR Apache-2.0.

Change evidence: v0.5.0 October 11; current GPU-loss autosave repair.

Inspected: [crates/engine/src/autosave.rs](https://github.com/storytold/cadcraft/blob/c57879a5c8f5e3a6be574a820add5e28eb25e9b1/crates/engine/src/autosave.rs); [crates/constraints/src/lm.rs](https://github.com/storytold/cadcraft/blob/c57879a5c8f5e3a6be574a820add5e28eb25e9b1/crates/constraints/src/lm.rs).

Finding: Pure autosave plan separated from I/O with instance-bound recovery filenames; bounded damped solver with finite/singular checks.

Decision: Defer CAD engine; recovery-plan reference only if NEOTH canvas feature requires it. Mapping: **C11**.

### SRC-44 — [morluto/rea](https://github.com/morluto/rea)

Pin: `98d8470d36cfbf7cd25820a4ed430aebae20c0c5`; commit date: 2026-10-12. License: MIT.

Change evidence: Current managed-snapshot/cleanup fix; rea-agents 4.1.0 documentation.

Inspected: [src/domain/evidence.ts](https://github.com/morluto/rea/blob/98d8470d36cfbf7cd25820a4ed430aebae20c0c5/src/domain/evidence.ts); [src/application/investigation/EvidenceLedger.ts](https://github.com/morluto/rea/blob/98d8470d36cfbf7cd25820a4ed430aebae20c0c5/src/application/investigation/EvidenceLedger.ts).

Finding: Typed subject/provider/environment evidence, observed/derived/inferred distinction, canonical ID validation and immutable idempotent imports.

Decision: Use distinctions in workflow/evidence projections; NEOTH existing ledger remains source of truth, no binary-analysis engine import. Mapping: **A01,A06**.

### SRC-45 — [ayghri/i-have-adhd](https://github.com/ayghri/i-have-adhd)

Pin: `1ecea1993b7fce257ffbd686c070948b5e07eda6`; commit date: 2026-10-11. License: MIT.

Change evidence: Current French README merge; does not establish runtime delta.

Inspected: [extensions/i-have-adhd.ts](https://github.com/ayghri/i-have-adhd/blob/1ecea1993b7fce257ffbd686c070948b5e07eda6/extensions/i-have-adhd.ts); [hooks/always-on.mjs](https://github.com/ayghri/i-have-adhd/blob/1ecea1993b7fce257ffbd686c070948b5e07eda6/hooks/always-on.mjs).

Finding: Opt-in session state, one-time context insertion, visible indicator and restore after compaction; hook intentionally ignores operational failures.

Decision: Merge reversible explicit presentation override into GOLD-R4-11; no diagnostic/medical inference, no authority change. Mapping: **A07**.

### SRC-46 — [QingYunA/answer-me-with-html](https://github.com/QingYunA/answer-me-with-html)

Pin: `5d5b86ddbeea500b7fec6b3e80ad273ad875b005`; commit date: 2026-10-12. License: MIT.

Change evidence: v0.4.9; current DSH update-path fix.

Inspected: [src/render.js](https://github.com/QingYunA/answer-me-with-html/blob/5d5b86ddbeea500b7fec6b3e80ad273ad875b005/src/render.js); [src/cli.js](https://github.com/QingYunA/answer-me-with-html/blob/5d5b86ddbeea500b7fec6b3e80ad273ad875b005/src/cli.js).

Finding: Parse/lint/panel/template pipeline with embedded assets and source; loopback preview default with explicit LAN option.

Decision: Optional deterministic sanitized single-file explanation export; separate inert default from declared active renderer. Mapping: **A06**.

### SRC-47 — [alchaincyf/huashu-art-motion](https://github.com/alchaincyf/huashu-art-motion)

Pin: `9ff59339f934e08483ba0a5b1db20f4c2c421b35`; commit date: 2026-10-10. License: MIT code; separate font and demo asset terms.

Change evidence: v1 October 6; current showcase asset correction.

Inspected: [scripts/engine/render.py](https://github.com/alchaincyf/huashu-art-motion/blob/9ff59339f934e08483ba0a5b1db20f4c2c421b35/scripts/engine/render.py); [scripts/engine/lib/render.js](https://github.com/alchaincyf/huashu-art-motion/blob/9ff59339f934e08483ba0a5b1db20f4c2c421b35/scripts/engine/lib/render.js).

Finding: Loopback allowlisted asset server renders Chromium frames to ffmpeg; failures propagate; substantive Canvas renderer.

Decision: Defer animation engine/assets, optional future export worker with separate license/resource gate. Mapping: **C11**.

### SRC-48 — [Niko1221/Strata](https://github.com/Niko1221/Strata)

Pin: `7695859aa13afb248bdb4d36f9b2e95707db079d`; commit date: 2026-10-11. License: MIT.

Change evidence: v0.1.39 October 4; current canonical Q2_0 pack.

Inspected: [serve/responses.py](https://github.com/Niko1221/Strata/blob/7695859aa13afb248bdb4d36f9b2e95707db079d/serve/responses.py); [serve/server.py](https://github.com/Niko1221/Strata/blob/7695859aa13afb248bdb4d36f9b2e95707db079d/serve/server.py).

Finding: Responses compatibility maps instructions/input/function tools/events and drops hosted tools; queue/cancellation are server concerns.

Decision: Provider contract regression reference: explicit unsupported features, store:false and content preservation. No new model engine. Mapping: **A08**.

### SRC-49 — [HunxByts/GhostTrack](https://github.com/HunxByts/GhostTrack)

Pin: `a5cb8ad4c08acd803f166fb067b7dac724d6cb3d`; commit date: 2024-01-11. License: No repository license found in inspected complete tree.

Change evidence: Last observed requirements update 2024; no release found.

Inspected: [GhostTR.py](https://github.com/HunxByts/GhostTrack/blob/a5cb8ad4c08acd803f166fb067b7dac724d6cb3d/GhostTR.py); [requirements.txt](https://github.com/HunxByts/GhostTrack/blob/a5cb8ad4c08acd803f166fb067b7dac724d6cb3d/requirements.txt).

Finding: Plain HTTP ipwho.is lookup, coarse IP metadata, offline phone metadata, username HTTP-status heuristic; missing timeout/schema checks and weak match evidence.

Decision: Do not import stale/unlicensed source. User-initiated network diagnostics may be designed independently; not a prohibition on legitimate OSINT. Mapping: **C12**.

### SRC-50 — [wheresryan22/anatomy](https://github.com/wheresryan22/anatomy)

Pin: `689dcf966e63d92be10a5d593c6e19e10acd4422`; commit date: 2026-10-12. License: MIT.

Change evidence: Current merge; WebGL/3D remains beta per README.

Inspected: [kit/audit.mjs](https://github.com/wheresryan22/anatomy/blob/689dcf966e63d92be10a5d593c6e19e10acd4422/kit/audit.mjs); [scripts/capture.mjs](https://github.com/wheresryan22/anatomy/blob/689dcf966e63d92be10a5d593c6e19e10acd4422/scripts/capture.mjs).

Finding: Agent skill and Node isometric SVG/WebGL kit; geometry/motion audit and headless Chrome capture check illustration geometry, not factual truth. Runtime Node >=20.10, install CLI >=22.20 per README.

Decision: Useful optional proactive Codex renderer on permitted remote host after supplied facts; NEOTH optional ExplanationArtifact seam. Not installed/run under BSOD hold. Mapping: **A06**.

### SRC-51 — [SakanaAI/mass](https://pub.sakana.ai/mass/)

Pin: `fb403581bed2c974b3f99e7236224169da643079`; commit date: 2026-10-09. License: NOTICE explicitly assigns no public open-source license to MASS-specific code; no code reuse granted.

Change evidence: October 2026 publication; README notes driver differs from paper and some ablations not shipped.

Inspected: [harness_improvement/iterate_multi_agent_prompt.py](https://github.com/SakanaAI/mass/blob/fb403581bed2c974b3f99e7236224169da643079/harness_improvement/iterate_multi_agent_prompt.py); [mass/pipeline.py](https://github.com/SakanaAI/mass/blob/fb403581bed2c974b3f99e7236224169da643079/mass/pipeline.py); [docs/running.md](https://github.com/SakanaAI/mass/blob/fb403581bed2c974b3f99e7236224169da643079/docs/running.md); [NOTICE.md](https://github.com/SakanaAI/mass/blob/fb403581bed2c974b3f99e7236224169da643079/NOTICE.md).

Finding: Research implementation searches workflows, ranks trajectories and performs LoRA. Evidence can motivate model-specific training but is not NEOTH product acceptance. Full reported training used 6 H100/about19h SFT alone; data/search/evaluation extra.

Decision: Use bounded handoff contracts now; preserve conditional NEOTH-domain training research after workflow-only baseline and heldout evaluation. No local run, autonomous self-promotion or code import. Mapping: **A01,R01**.

## Review corrections and remaining uncertainty

- Replace generic proposed new audit/consent/scheduler/skill systems with mapping to existing owners.
- WorkflowContract is immutable sidecar plus existing admission; version/hash verifier, preserve inconclusive and unknown outcomes.
- Connector unit semantics before broader adoption. Mobile remains its existing separate Jarvis adapter track, not a combined backend rewrite.
- Stable document identity cannot be inferred from equal content alone; oversized tables need explicit bound.
- Maildun license resolved from actual root text; Helpin community/enterprise/SDK scopes resolved. NOASSERTION did not mean no license.
- Exact Jay URL unresolved; related Laya material is not substituted for the requested article.
- User followup: model training may improve NEOTH's model, so preserve conditional research R01 rather than categorically rejecting training. No resource expenditure initiated.

The cross-review required changes: make workflow contracts sidecars rather than new run truth, specify verifier provenance/outcomes, put connector unit recovery before wider adapters, and keep the mobile/Jarvis delivery work in its own slice. Root accepted those limits. A universal P0 rating for every useful pattern was rejected. The external source findings are not unanimous proof that each feature is missing in NEOTH.

Copyleft does not categorically prohibit reuse. Actual linking/distribution/service and file-specific terms matter. A source-informed rewrite is not described as clean-room; a genuine clean-room would require a neutral behavior specification and an independent implementation path. This batch imports no upstream code or assets.

The related localized Jays articles and TextCortex/Laya model/runtime are recorded separately in the JSON. They do not prove the exact supplied article's identity. The optional classifier remains a research idea, with unresolved model license/calibration and no authority to approve tool effects.

## Operational use now

For this council, each delegated task had bounded source ownership and requested pinned sources, actual code, change evidence, limitations and a decision. Root rejects an unsupported claim, preserves disagreement and records the exact source/gap before scheduling a product change. This is a working method applied to this research; no new NEOTH daemon contract implementation is claimed.

Future proactive tool selection: prefer an existing text/table/diagram when sufficient; select Anatomy only for a substantive explanation requiring illustration, on an explicitly permitted remote runtime under the hold. Record facts and artifact provenance before publishing. Use MASS-inspired contracts and bounded comparison as planning aids; model training remains R01 with its own budget and acceptance.
