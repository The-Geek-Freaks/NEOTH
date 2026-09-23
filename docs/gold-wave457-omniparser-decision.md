# W457 — Omniparser v1.0 adoption decision

**Decision: SKIP_FOR_V1_0_REOPEN_ON_EVIDENCE (2026-09-23).** The current delivery and benefit evidence does not justify bundling OmniParser in v1.0. This closes the requested adopt/skip decision; it does not claim a shipped parser or complete computer-use implementation.

## What the product needs today

PC-01 has an implemented but incompletely accepted native OS-control integration surface: it has deny-by-default file read/write, exact executable allowlisting, autonomous-policy gates, and WAL auditing. The existing `cua-driver` MCP configuration declares `screenshot`, pointer, keyboard, scroll, window-list and wait tools on Windows and macOS. Those declarations establish an existing capture-and-act integration surface; this decision does not claim a fresh installed-driver or live desktop acceptance.

OmniParser adds a different capability: it converts a screenshot into labeled/grounded UI elements. That can improve action grounding, particularly in dense or icon-heavy interfaces, but it is not required for the current computer-use path to capture a screen or execute an operator-approved action. It is therefore an enhancement to an existing integration, not a missing prerequisite for PC-01's shipped slices.

The prerequisite cited by the original reopen condition is not fully met. PC-01 still lists window management and system audio as open slices. PC-02, the optional Chrome DevTools MCP, remains unchecked and has a pre-merge privacy environment-variable and licence-confirmation blocker. The use case therefore lacks both a demonstrated screenshot-grounding failure rate and accepted lifecycle evidence for the optional browser-control surface. PC-02 is not inherently required by a desktop parser: the existing desktop integration could also be its consumer.

## Candidate comparison

| Question | OmniParser v2 | Existing NEOTH path | Decision impact |
| --- | --- | --- | --- |
| User benefit | Structured regions and icon descriptions can reduce ambiguity in visual GUI action selection. | `cua-driver` configuration already declares screenshots plus desktop input/window tools through an allowlisted, autonomy-gated and WAL-audited MCP server. | Benefit is real but unquantified for the current product tasks. |
| Delivery shape | Upstream documents a Python 3.12 Conda/pip environment, Torch, vision/OCR/model packages and Hugging Face model acquisition. | External MCP process is the established extension boundary; NEOTH has no built-in model-tool dispatch table. | Do not add a new Rust vision subsystem. An eventual adoption must be a pinned MCP-sidecar contract. |
| Provenance | GitHub latest release is `v.2.0.1` (2025-09-12) with no release assets. Current master documents an automatic first-use detector download while a Hugging Face PR is unmerged. | Managed artifacts in NEOTH use reviewed version/digest/length and explicit operator activation. | The current upstream shape does not provide a directly pin-able, release-asset-only install path. |
| Resource footprint | The prior repository decision recorded an approximately 600 MB ONNX checkpoint. The upstream requirements also pull a broad Python/ML/OCR/GUI stack. | Current host has 255.84 GiB physical RAM and 214,438 MiB free at this read, so host RAM alone is not a reason to reject it. | Fresh-Windows installation/storage, cold-start, CPU/GPU compatibility and support burden remain unmeasured; the old 600 MB concern is still material for product delivery. |
| Licence | GitHub API declares the repository `CC-BY-4.0`; the upstream README displays an MIT badge and separately says the new YOLOv9 detector is MIT-based while older Ultralytics detectors retain AGPL and caption models are MIT. | No approved NEOTH manifest exists for code plus every selected model/weight. | This conflict is an adoption blocker until an exact commit, package set, and model-weight licences are independently reconciled. |

## Why SKIP is the stronger current verdict

The recommendation is not based on the task being large. OmniParser can supply useful visual grounding. It is skipped because the product does not currently establish that its incremental accuracy is needed, while adoption would add an unpinned Python/ML/OCR delivery chain, an unresolved code/model licence matrix, and a model lifecycle that the current managed-artifact system has not accepted.

The host’s available RAM removes one weak argument against a future trial, but it does not solve a fresh Windows user's download/disk/runtime budget, the need to pin every artifact, or the absence of a model-specific user benefit measurement. Installing it merely because PC-01 exists would also bypass the stated MCP-only extension boundary and invite a `media/vision.rs` subsystem with no demonstrated internal consumer.

## Binding scope

The decision binds the following v1.0 scope:

1. No OmniParser code, Python environment, model, or dependency is added to the core product for v1.0.
2. Computer-use remains the approved `cua-driver` MCP integration; screenshot parsing is an optional external MCP concern, never an ambient in-process model.
3. The decision does not claim that visual grounding is unhelpful. It states that current product evidence does not justify the delivery, provenance, and licence cost.
4. A future adoption must start with a new decision record and a pinned sidecar proposal, before implementation or a model download.

## Measurable reopen conditions

Reopen P2-17 when all applicable conditions below have evidence, rather than merely when time passes:

1. **Need:** at least one reproducible, operator-approved Windows task demonstrates a grounding failure in the existing screenshot path, and a bounded comparison shows that the candidate resolves it. Retain only the consented inputs, action and observed result needed to reproduce that benefit; policy denials or unavailable applications do not count as grounding failures.
2. **Surface:** An actual desktop or browser MCP consumer is accepted with its relevant privacy and licence conditions verified; PC-02 is one possible consumer, not a mandatory dependency. This establishes an actual consumer for structured screen elements beyond raw screenshot inspection.
3. **Provenance:** one exact upstream commit/tag, every code dependency, and every model artifact have recorded source URL, immutable revision, byte length, SHA-256, and a no-automatic-download installation path. The official release currently has no binary assets, so a future proposal must close that gap instead of treating a mutable branch or first-use download as provenance.
4. **Licensing:** the repository `CC-BY-4.0` API result, README MIT badge, selected detector licence, caption-model licence, and all shipped dependencies are reconciled by exact artifact. No AGPL detector or unreviewed weight may enter by transitive/default selection.
5. **Fresh-Windows budget:** a clean supported Windows machine records baseline disk/RAM, installation footprint, idle memory, and one bounded inference latency with the exact pinned sidecar. The result must fit a product-approved budget set before implementation; this decision does not infer that budget from the developer workstation's 256 GiB RAM.
6. **MCP lifecycle:** the proposal defines default-off operator activation; privilege/credential isolation; screenshot data retention; cancellation and timeouts; update/repair/uninstall; status/doctor; CLI/GUI parity; and a clean-machine acceptance suite.

## Evidence consulted

- `PLAN/ROAD_TO_1_0_GOLD.md` current P2-17 row: binding adopt/skip decision required; an undocumented limbo cannot close the item.
- `PLAN/PROGRESS_v1_0.md` PC-01/PC-02 status: PC-01 has shipped slices but open window-management/audio work; PC-02 remains unchecked with `CHROME_DEVTOOLS_MCP_NO_USAGE_STATISTICS=1` and licence confirmation requirements.
- `SRC/neothd/src/computer_use.rs`: current `cua-driver` MCP allowlist includes screenshot, mouse, keyboard, scroll, windows and wait; it is autonomy-gated and WAL-audited.
- `QUELLEN/DO_NOT_ADOPT.md`: original reopen rationale, MCP boundary, and approximately 600 MB ONNX concern.
- [Microsoft OmniParser repository](https://github.com/microsoft/OmniParser), queried through GitHub API on 2026-09-23: repository metadata, latest release, README, requirements, licence file, and master commit. No model was downloaded and no runtime was probed.

## Scope and verification

This decision was prepared from source head `5bace4f059f8179eee89cdce3050701107ba3f7f`. The sole host read was Windows system/RAM metadata. No model download, model execution, browser action, compiler, parser, test, formatter, benchmark, occurred during evidence collection. The decision is bound to the recorded source head and the accompanying decision-inputs evidence.
