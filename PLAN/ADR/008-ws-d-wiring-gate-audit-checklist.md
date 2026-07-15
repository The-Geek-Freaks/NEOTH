# ADR-008 — WS-D wiring gate/audit checklist: six mandatory elements for every live-path wiring

- **Status:** Accepted (2026-06-08, Session 45)
- **Relates to:** GOLD plan `PLAN/ROAD_TO_1_0_GOLD.md`; operator directive 2026-06-08

## Context

WS-D ("feature wiring") commits wire already-built, already-tested modules into the daemon's live execution path. Unlike WS-A (security hardening) or WS-C (correctness), wiring commits activate previously-inert code — from that moment the operator's runtime is affected, costs may be incurred, and wrong-shaped effects can reach external systems (channels, providers, the OS). NEOTH already ships orthogonal mechanisms that together form a complete safety envelope for any new live-path effect:

1. **Status surface** — `neoth status` (cli/status.rs:34) reads a `Snapshot` from `daemon::observability::snapshot()` (daemon/observability.rs:42). `neoth doctor` (cli/doctor.rs:766 `run_all_checks`) exposes per-check `CheckOutcome { name, status: CheckStatus, detail }` (doctor.rs:631–634). Together these are the operator's truth surfaces: they must not lie about what is on or off.

2. **Permission/gate** — `permissions::evaluate(action, &policy_snapshot)` maps every `Action` variant to `Decision::Allow | Confirm(reason) | Deny(reason)` under an immutable `AutonomyPolicySnapshot`. The exhaustive 27-entry `ActionKind` wire vocabulary and explicit matches make a newly added action fail compilation until its stable name, representative, and policy arms are defined. Production code cannot pass a raw `AutonomyLevel`; it obtains snapshots from `FreedomConfig` or the live `ReloadController`, while `Gate::for_level` is test-only. `LeaseScope`-backed capability leases let the operator pre-authorise bounded subjects; `lease_scope_for(action)` maps each action to its coverable scope or `None`. The SDK's `PermissionToken<L>` catches level mismatches only in native Rust APIs that opt into that typed interface; `_host` is consumer-selectable and the zero-sized marker is not runtime authority. WASM plugins are instead gated by an operator activation bound to the manifest/WASM hashes and an approval-derived `HostcallPermission` check on every hostcall. Neither mechanism replaces the daemon's `Action`/`Gate` decision for external effects.

3. **Audit event** — `wal/events.rs` is the single-source-of-truth event registry. Every event type occupies a declared band (0x01..=0xFF) and each `pub const EVENT_TYPE_*: u8` constant has an inline doc with the exact payload schema. Canonical permissions events are `0xA0 PERMISSION_GRANTED` / `0xA1 PERMISSION_DENIED` (events.rs:891–893); channel effects emit `0x33 CHANNEL_EGRESS` (events.rs:315); provider calls emit `0x20 PROVIDER_REQUEST` / `0x21 PROVIDER_RESPONSE` (events.rs:169–173). The WAL writer is the only process that appends frames; one-shot CLIs forward via the `0xAE AUDIT_RPC_ACCEPT` path (events.rs:960–966).

4. **Safe default** — `freedom.yaml.example` and `FreedomConfig::default()` document the baseline. Opt-in features carry an `enabled: bool` field that defaults to `false` (e.g. `ProactiveConfig { enabled: false }` at config/mod.rs:876–881; `DreamingConfig { enabled: false }` at config/mod.rs:1379; `VectorIndexConfig { backend: VectorBackend::BruteForce }` at config/mod.rs:498–504; `AuditRpcConfig { enabled: false }` at config/mod.rs:514). The pattern is: a `#[derive(Default)]` on the outer struct (with `#[serde(default)]`) means a missing key in freedom.yaml gives the safe fallback automatically — no config = least-privilege.

5. **CLI/GUI truth** — `neoth doctor` checks must not lie. GOLD-HON-* commits (Sessions 40–43) were exclusively about closing lying surfaces. The GOLD-WIRE-07 doctor check (`check_vector_index_snapshot`, doctor.rs:1534) is a concrete example: it reads `freedom.yaml::memory.vector_index.backend` live and flags a WARN when HNSW is selected but the snapshot is absent or stale, so the operator cannot believe they have fast ANN recall when they do not. `neoth status` exposes `autonomy`, `provider_kind`, `channels` from the live config (observability.rs:27–51); `neoth cluster status` similarly reads live config rather than hardcoded values (`status_mode_policy`, cluster.rs:862 — enforced by test `status_mode_policy_derives_from_config_not_hardcoded`, cluster.rs:1554).

6. **Tests** — the project's test convention is `#[cfg(test)] mod tests` co-located in the same file (`src/X.rs`). The permissions module alone has 30+ inline tests (permissions/mod.rs:719–1435) covering every autonomy-level ladder, NaN cost-estimate paths, and lease-scope exhaustion. WIRE-07 added a real 200-vector HNSW graph test above the brute-force ceiling (`find_similar_dispatch_real_hnsw_graph_above_hnsw_m`, embeddings.rs:1042). WIRE-11 added 4 tests including an empty-input guard (fact_check.rs:61–117). CI green is the gate before merge.

The absence of any one element creates a specific failure mode: no status label → the operator cannot tell if the feature activated; no gate → an effect fires at all autonomy levels including Strict; no audit event → the WAL is unaware of the effect, forensics are impossible; no safe default → a fresh install triggers the feature without consent; no CLI truth → `neoth doctor` or `neoth status` lies about the current posture; no tests → a silent regression in any of the above goes undetected.

WS-D has 12 items (WIRE-01 through WIRE-12). Not all of them carry all six elements (see Compliance Audit). This checklist formalises the requirement so future wiring commits are held to a single consistent bar.

## Decision

Every WS-D style feature-wiring commit — and any future commit that wires a previously-inert module into the daemon's live execution path — MUST satisfy all six of the following elements before merge. A failing item is a hard blocker, not a TODO.

**Element 1 — Status label.** The feature's on/off state must be readable by the operator without inspecting source code. Acceptable surfaces: a field in `daemon::observability::Snapshot` (read by `neoth status`); a `CheckOutcome` entry in `cli::doctor::run_all_checks` (read by `neoth doctor`); a subcommand output that reads the live `FreedomConfig` field rather than a hardcoded string. The check must read the live config, not a compile-time constant. Pinned by test.

**Element 2 — Permission/gate.** Every new effect that reaches outside the daemon's read-only path (provider call, channel send, OS file access, cluster action, autonomous outbound) must have a corresponding `Action` variant in `permissions/mod.rs` and an arm in all four `evaluate_*` functions. The arms must be explicit — no `_ => Allow` wildcard at `Full` level (GOLD-COR-05). Where the action is delegatable, `lease_scope_for(action)` must return `Some(scope)` and the `LeaseScope` variant must exist in `permissions/lease.rs`. Where it is not delegatable (blast radius too high), `lease_scope_for` must return `None` and the doc must state why.

**Element 3 — Audit event.** At least one WAL event from `wal/events.rs` must be emitted at the effect site. New event type constants must claim a declared band in the range-allocation table (events.rs:18–35) and carry an inline-doc payload schema. Audit frames must be emitted BEFORE the effect when order matters (e.g. `0xA0 PERMISSION_GRANTED` before the action, not after). For one-shot CLIs where the daemon owns the WAL writer, use the `0xAE AUDIT_RPC_ACCEPT` forwarding path.

**Element 4 — Safe default.** The feature must default to OFF (or least-privilege) in `FreedomConfig::default()`. The mechanism is an `enabled: bool` field (defaulting `false`) or an enum variant that is the safe fallback (e.g. `VectorBackend::BruteForce`). The field must carry `#[serde(default)]` so a `freedom.yaml` that omits the key activates the safe value. Document the on/off consequence and any cost implication in `freedom.yaml.example`.

**Element 5 — CLI/GUI truth.** `neoth doctor` and `neoth status` must not misrepresent the new feature's state. If the feature has an on/off config gate, add a `CheckOutcome` in `run_all_checks` that reads the live `freedom.yaml` via `FreedomConfig::load_from_path` (not a cached or compile-time value) and emits WARN when the feature is on but a prerequisite is missing, or PASS/silent when the feature is off. The check must be pinned by at least one test that asserts the WARN fires when expected and PASS fires when expected.

**Element 6 — Tests.** Every wiring commit must add tests in the co-located `#[cfg(test)] mod tests` block covering: (a) the config gate — feature is off when the freedom.yaml field is absent or set to its default; (b) the gate ladder — at least one `evaluate` call per autonomy level that the new `Action` variant is expected to hit; (c) the primary effect path — a unit or integration test that proves the newly-wired module is actually reached. Tests must pass under `cargo test` without requiring a live daemon, live provider, or live channel.

## Consequences

**Positive:**
- Every wired feature is operator-observable from day zero — no "silent activations" that only surface in WAL forensics months later.
- The exhaustive-match rule in `evaluate_full` (GOLD-COR-05) already catches missing gate arms at compile time; this ADR extends that discipline to the other five elements and makes it explicit policy.
- `neoth doctor` becomes a reliable single entry point for "is anything misconfigured?" — operators and CI both run it; a failing check in CI blocks the release.
- The WAL audit chain stays complete: every new live-path effect has a `wal::events` constant and a named emit site, making post-incident forensics possible.
- Freedom.yaml safe defaults mean a fresh install is always least-privilege; operators cannot accidentally activate a paid-provider or OS-tool feature by forgetting to configure something.
- The six-point checklist is small enough to apply at PR review time without a multi-hour audit.

**Negative / trade-offs:**
- Small pure-logic wirings (e.g. WIRE-11 `fact-check` — a stateless heuristic classifier with no provider call, no channel send, no OS access, no cost) are over-specified by Elements 2 and 3. The gate requirement for such wirings is satisfied by documenting that no `Action` variant is needed (the effect is read-only and purely local), not by creating a spurious `Action::FactCheck` variant. This exception must be stated explicitly in the commit message.
- Element 5 (CLI/GUI truth) adds a `run_all_checks` entry even for features most operators will never enable. The convention in `doctor.rs` is to return `CheckStatus::Pass` with `"feature is off — nothing to check"` when the gate is closed (see `check_vector_index_snapshot`, doctor.rs:1536–1541), which keeps the output noise-free.
- Adding a new `Action` variant forces updating all four `evaluate_*` functions, `lease_scope_for`, and the exhaustive test `full_explicit_enumeration_preserves_wildcard_allow_behaviour` (permissions/mod.rs:1075). This is intentional friction — a new effect that nobody reviewed for all five autonomy levels is a security gap.
- The test requirement (Element 6c, primary effect path) may require a mock `Provider` or an in-memory channel adapter. The project already has counting mock providers in the coding test suite; reuse, do not introduce new test frameworks.

## Alternatives considered

**Alternative A — Gate-only (no status/audit/default/test requirements).** Keep the current ad-hoc approach: reviewers catch missing elements by eye. Rejected: the WS-D compliance audit (below) shows that even careful reviewers missed Elements 1, 3, and 5 on several WIRE-0x commits. A documented checklist is a forcing function; reviewer eyeballs are not.

**Alternative B — Require an ADR per wiring commit.** Each wiring writes its own ADR documenting the six elements. Rejected: an ADR is appropriate for irreversible architectural choices (see PLAN/ADR/README.md — "hard to reverse", "choice between two viable approaches"). A wiring commit is not an architectural choice — it is the mechanical application of a pre-decided design. One checklist ADR (this document) is sufficient; individual wirings reference it in their commit message rather than generating their own ADRs.

**Alternative C — Encode the checklist as a pre-commit hook script.** A shell script inspects the diff for missing WAL event constants, missing `evaluate` arms, etc. Rejected: the Rust compiler already enforces Element 2 (exhaustive match) at compile time. Elements 1, 3, 4, 5, and 6 require semantic understanding that a grep-based hook would approximate poorly, producing false positives on correctly-structured wirings (e.g. a pure-local wiring legitimately has no new WAL event). The checklist is better enforced at PR review with this ADR as the reference.

**Alternative D — Merge Elements 1 and 5** (status label == CLI truth). They appear to be the same thing. Kept separate because they address different failure modes: Element 1 is "can the operator observe the feature's state at all?"; Element 5 is "when the feature is on but misconfigured, does the operator get an actionable warning?". An observability snapshot may show `vector_index: hnsw` (Element 1 satisfied) while `neoth doctor` silently passes on a missing snapshot (Element 5 violated). Both must be independent checks.

## Compliance audit

Audit of three recently-shipped WS-D wirings against the six-point checklist:

**WIRE-07 — `recall`: dispatch similarity recall to HNSW EmbeddingIndex behind a config gate (commit 32dd0db)**

1. Status label — PASS. `check_vector_index_snapshot` added to `run_all_checks` (doctor.rs:790), reads `freedom.yaml::memory.vector_index.backend` live via `freedom_vector_backend_is_hnsw` (doctor.rs:1514–1526), emits WARN when backend=hnsw but snapshot absent or stale (doctor.rs:1544–1553). Pinned by tests `vector_index_passes_when_brute_force` and `vector_index_warns_when_hnsw_and_no_snapshot` (doctor.rs:2712–2725).
2. Permission/gate — NOT APPLICABLE (documented). `neoth recall --similar-to*` is a read-only local operation. No external provider call, no channel send, no OS mutation. No new `Action` variant is needed; the corpus-ceiling gate and the backend enum itself act as the runtime gate.
3. Audit event — PARTIAL MISS. No new WAL event was added for the HNSW dispatch path. The operator can observe the feature via `neoth doctor` (Element 1) but there is no `neoth wal show` trail of "HNSW was used for this query" vs "brute-force fallback was used". A `0x2F`-adjacent recall-backend event would close this gap; deferred to WIRE-07b.
4. Safe default — PASS. `VectorBackend::BruteForce` is the `#[default]`-annotated variant (config/mod.rs:498–504); `MemoryConfig::default().vector_index.backend` is asserted to be `BruteForce` in test at config/mod.rs:2918–2924. Missing key in freedom.yaml = brute-force, zero behaviour change.
5. CLI/GUI truth — PASS (see Element 1).
6. Tests — PASS. `find_similar_dispatch_brute_force_when_hnsw_path_none`, `find_similar_dispatch_uses_hnsw_snapshot_not_the_conn`, `find_similar_dispatch_kind_filter_skips_hnsw`, `find_similar_dispatch_missing_snapshot_falls_back_to_brute_force`, `find_similar_dispatch_corrupt_snapshot_falls_back_without_error`, `find_similar_dispatch_real_hnsw_graph_above_hnsw_m` (memory/embeddings.rs:922–1042). **Score: 5/6 (Element 3 partial).**

**WIRE-10 — `domain-events`: wire EventBus end-to-end with a council producer + UsageMeter consumer (commit 6838dc4)**

1. Status label — PARTIAL. `EventBus::receiver_count()` noted as useful for "the upcoming `neoth status` dashboard line" (domain_events/mod.rs:187). `global_meter_snapshot()` (domain_events/mod.rs:318) is available for `neoth gui-stream` and future `neoth doctor` display, but as of this commit no `CheckOutcome` in `run_all_checks` exposes EventBus health. Commit note: "GUI display is WIRE-10b".
2. Permission/gate — NOT APPLICABLE (documented). The EventBus is a process-internal pub-sub channel; it carries no external effect itself. The producer-side effects (provider calls) already pass through `0x20 PROVIDER_REQUEST` / permission gates independently.
3. Audit event — PARTIAL. The bus itself emits no WAL event on bus-level operations (by design per the module doc: "This is NOT a WAL replacement", domain_events/mod.rs:32–39). `ProviderResponded` events are consumed by `UsageMeter` which exposes `global_meter_snapshot()` — the meter data reaches `neoth gui-stream` as a pull surface. A WAL event documenting "EventBus installed at daemon startup" was not added; a startup-wiring frame would close the audit gap.
4. Safe default — PASS. The `OnceLock<(EventBus, UsageMeter)>` singleton only initialises when `init_global()` is called from `serve.rs`; a daemon that never calls `serve::run` (e.g. a one-shot CLI) carries no bus overhead. `UsageMeter` initialises with all-zero atomics (domain_events/mod.rs:195–200).
5. CLI/GUI truth — MISS (same as Element 1 — no `neoth doctor` check for bus health or lagged-event count).
6. Tests — PASS. Snapshot serde round-trip, meter accumulation, lagged-event counter, receiver-count behaviour, and overflow-clamp all covered (domain_events/mod.rs:540–605). **Score: 3/6 (Elements 1/3/5 partial or absent).**

**WIRE-11 — `cli`: expose `fact_check::assess` as the `neoth fact-check` subcommand (commit 7c9df23)**

1. Status label — NOT APPLICABLE (documented). `fact-check` is a stateless, pure-local proposition classifier (no config gate, always available as a CLI command). The only relevant status surface is "the subcommand exists and is listed in `neoth --help`", which is structural. No `neoth doctor` check is appropriate.
2. Permission/gate — NOT APPLICABLE (documented). No provider call, no channel send, no OS mutation, no network. The entire pipeline is deterministic heuristics over the input string (fact_check.rs:28 calls `assess(&args.claim)`, which is a pure fn in `profile::fact_check`). No `Action` variant needed.
3. Audit event — NOT APPLICABLE (documented). No effect that needs a WAL audit record: no external resource is touched, no operator state changes, no cost is incurred. The operator's input is not persisted.
4. Safe default — NOT APPLICABLE. No config gate; the command is always available once installed. Defaulting to OFF would break the UX premise.
5. CLI/GUI truth — NOT APPLICABLE. No on/off state to surface. The command's existence IS its status.
6. Tests — PASS. `run_fact_check_assesses_a_simple_verifiable_claim`, `render_table_shows_verdict_counts_and_each_proposition`, `render_json_roundtrips_to_the_same_report`, `render_table_handles_empty_input_without_panicking` (fact_check.rs:61–117). **Score: 6/6 (four elements documented as N/A with explicit rationale; Element 6 fully satisfied).**

**Summary:** WIRE-07 satisfies 5/6 (Element 3 partial — no per-query backend WAL event). WIRE-10 satisfies 3/6 (Elements 1/3/5 partial — no doctor check for bus health, no startup WAL frame). WIRE-11 satisfies 6/6, with four elements explicitly documented as N/A due to the pure-local, stateless nature of the wiring. The checklist is realistic: a pure-local wiring like WIRE-11 documents N/A with rationale; a side-effecting wiring like WIRE-10 must close the open items in a follow-up commit (WIRE-10b).

## References

- neothd/src/permissions/mod.rs:385 (permissions::evaluate)
- neothd/src/permissions/mod.rs:330 (lease_scope_for)
- neothd/src/permissions/lease.rs:34 (LeaseScope enum)
- neothd/src/wal/events.rs:18-35 (range-allocation table)
- neothd/src/wal/events.rs:891-893 (0xA0/0xA1 PERMISSION_GRANTED/DENIED)
- neothd/src/cli/doctor.rs:766 (run_all_checks)
- neothd/src/cli/doctor.rs:1534 (check_vector_index_snapshot)
- neothd/src/cli/status.rs:34 (run_status)
- neothd/src/daemon/observability.rs:27 (Snapshot struct)
- neothd/src/config/mod.rs:498-504 (VectorBackend default)
- neothd/src/config/mod.rs:876-881 (ProactiveConfig default OFF)
- neothd/src/config/mod.rs:514 (AuditRpcConfig enabled:false default)
- freedom.yaml.example (operator config reference)
- neothd/src/domain_events/mod.rs:67-74 (WIRE-10 producer status doc)
- neothd/src/domain_events/mod.rs:187 (receiver_count neoth status note)
- neothd/src/coding/provider_worker.rs:44 (WIRE-01 ProviderWorker)
- neothd/src/cli/recall.rs:618-630 (WIRE-07 configured_hnsw_path)
- neothd/src/memory/embeddings.rs:219 (find_similar_dispatch)
- neothd/src/cli/fact_check.rs:27 (WIRE-11 run_fact_check)
- PLAN/ADR/007-chat-turn-pipeline-module-boundary.md
- PLAN/ADR/006-ho08-ecology-council-adaptation-hook.md
- ADR-005 (episodes-only privacy boundary)
- GOLD-COR-05 (evaluate_full exhaustive-match refactor)
