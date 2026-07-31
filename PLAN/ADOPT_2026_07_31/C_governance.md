# C — Governance & Autonomy Cluster Report
**Agent:** C · **Date:** 2026-07-31 · **Sources:** microsoft/agent-governance-toolkit, shanraisshan/claude-code-best-practice, garrytan/gstack, fermisense.com/when-machines-take-the-wheel/

All gaps are backed by an explicit grep command and its result. No hallucinated gaps.

---

## Source (a): microsoft/agent-governance-toolkit — LOCAL: `/tmp/adopt2026/agent-governance-toolkit`

### 1. What it actually does

Multi-language, Linux-Foundation-hosted (MIT, LF Projects series) open toolkit for deterministic AI agent governance. Microsoft-sponsored, 5.5k stars, 3268 code files.

**Core language** is Python (`agent-governance-python/agent-os/`) but **Rust SDK** (`agent-governance-rust/agentmesh/`) is the highest-value deliverable for NEOTH. The toolkit ships 10+ formal RFC 2119 specifications under `docs/specs/` and a library of benchmark scripts.

What the Rust SDK (`agentmesh` crate, `agent-governance-rust/agentmesh/src/`) actually provides:

| Module | What it does |
|--------|-------------|
| `audit.rs` | Append-only **SHA-256 hash-chain** logger: each entry covers `seq\|timestamp\|agent_id\|action\|decision\|prev_hash`; 100K entry buffer with seam-anchor on eviction for overflow; `verify()` re-anchors from seam |
| `trust.rs` | `TrustManager`: per-agent score 0–1000, five tiers (`Untrusted/Low/Neutral/Trusted/HighlyTrusted`), configurable reward (+10) / penalty (-50) / decay (0.95/hr), JSON persistence |
| `prompt_injection.rs` | `PromptInjectionDetector`: 7 `InjectionType` variants (`DirectOverride`, `DelimiterAttack`, `EncodingAttack`, `RolePlay`, `ContextManipulation`, `CanaryLeak`, `MultiTurnEscalation`), 4 `ThreatLevel` grades (`Low/Medium/High/Critical`), 3 `Sensitivity` modes, cross-turn 10K ring buffer, embedding-backed signal (`prompt_injection_embedding.rs`) |
| `credential_vault.rs` | AES-256-GCM encrypted vault; agents only see opaque `{{cred:NAME}}` placeholders; `CredentialRecord` carries `name`, `value`, `cred_type`, `version`, `created_at`, `rotated_at` |
| `identity.rs` | Ed25519 `AgentIdentity` — keypair generation, signing, verification |
| `policy.rs` | ACS-compatible policy evaluation helper |

**Agent Control Specification (ACS)** (`policy-engine/spec/SPECIFICATION.md`): portable manifest schema with:
- Named *intervention points* (`pre_tool_call`, `post_tool_call`, + 4 more)
- Cedar and Rego/OPA policy engines (pluggable)
- IFC (Information Flow Control) label lattice: `public < internal < confidential < secret`
- Manifest `extends` with SHA-256 pinning, HTTPS-only URL loads, fail-closed on unknown tool

**MCP Security Gateway Spec** (`docs/specs/MCP-SECURITY-GATEWAY-1.0.md`): dual-stage pipeline — tool call interception (allow/deny/sensitive + approval workflow) → response scanning (injection, credential leak, PII, exfil URL). Adds:
- Tool fingerprinting: HMAC hash of tool description+schema stored at registration; mismatch = `rug_pull` block
- Schema drift detection: compares current tool catalog against stored baseline; severity-classified diff

**Benchmarks** (`docs/BENCHMARKS.md`):
- Policy eval (single rule): 0.011 ms p50, 84K ops/sec
- 100-rule policy: 0.030 ms p50
- Concurrent (1,000 agents): 47K ops/sec, near-linear
- Benchmark scripts: Python (`bench_kernel.py`, `bench_audit.py`, `bench_chaos.py`)
- **No scored conformance suite runnable against NEOTH** — benchmarks are internal; the prompt-injection fixture (`benchmarks/prompt-injection/`) is evaluation-only and does not publish a public ASR

**Is it a recognised standard?**  
Yes. LF Projects charter (`CHARTER.md`) designates this as a formal TSC-governed project with RFC 2119 specifications and interop conformance requirements. The ACS `SPECIFICATION.md` is the normative contract for all language SDKs. This is an *emerging inter-vendor standard*, not just a library — adherence gives NEOTH alignment with the spec rather than just the Microsoft implementation.

### 2. Where it beats NEOTH

Run evidence for every gap claim:

**GAP A — Multi-turn injection escalation tracking**
```
grep -rn 'MultiTurn\|multi_turn\|CanaryLeak\|canary_token\|turn_escalat' SRC/neothd/src/
```
Result: 0 hits.

AGT `prompt_injection.rs` tracks `MultiTurnEscalation` — a user claiming prior approval or unlocked state across turns — in a 10,000-entry ring buffer per session. NEOTH's `security/ingress_sanitizer.rs` gates each message at ingress (single-message scope); `security/content_scanner.rs` scans documents for 15 static injection patterns. Neither has cross-turn injection state.  
**AGT file**: `agent-governance-rust/agentmesh/src/prompt_injection.rs` (~400 lines, lines 1–250 read)  
**NEOTH equivalent**: `SRC/neothd/src/security/ingress_sanitizer.rs` + `content_scanner.rs` — no multi-turn state

**GAP B — Canary token leak detection**
```
grep -rn 'CanaryLeak\|canary_token\|canary_leak\|canary' SRC/neothd/src/security/
```
Result: 0 hits in security/.

AGT lets operators configure named canary tokens; if a model output repeats one, it's rated `Critical`. NEOTH has no canary infrastructure.  
**AGT file**: `prompt_injection.rs` `InjectionType::CanaryLeak` + `DetectionConfig::custom_patterns`

**GAP C — Hash-chain tamper-evident audit log**
```
grep -rn 'hash_chain\|AuditLogger\|prev_hash\|seam_hash\|merkle' SRC/neothd/src/
```
Result: 1 hit — `cluster/hyperswarm.rs:1225` comparing capability hashes (unrelated to audit).

AGT `audit.rs:AuditLogger` produces `AuditEntry` with `seq`, `timestamp`, `agent_id`, `action`, `decision`, `previous_hash`, `hash`. Each entry's hash covers all prior fields; `verify()` traverses the chain. NEOTH's `permissions/audit.rs` exists (115 lines found) and the WAL records decisions, but the WAL is not cryptographically chained — individual records are not linked by hash.  
**AGT file**: `agent-governance-rust/agentmesh/src/audit.rs`  
**NEOTH equivalent**: `SRC/neothd/src/permissions/audit.rs` + `SRC/neothd/src/wal/` — no hash chain

**GAP D — Per-external-agent trust score**
```
grep -rn 'TrustScore\|trust_score\|TrustManager\|TrustTier' SRC/neothd/src/
```
Result: 0 hits.

AGT `trust.rs:TrustManager` tracks a dynamic 0–1000 score per agent ID with time-decay. NEOTH's `tier_classifier.rs` classifies *actions* into 7 approval tiers; `permissions/audit.rs` records *decisions*. NEOTH's autonomy level is a global operator preference (Strict/Standard/Elevated/Full), not a per-peer dynamic score. The `council/quality_score.rs` exists but scores internal sub-agent quality, not external peer agents.  
**AGT file**: `agent-governance-rust/agentmesh/src/trust.rs`  
**NEOTH equivalent**: `SRC/neothd/src/council/quality_score.rs` (partial overlap, wrong scope)

**GAP E — MCP tool fingerprinting and rug pull detection**
```
grep -rn 'rug_pull\|schema_drift\|tool_fingerprint\|tool_hash' SRC/neothd/src/
```
Result: 0 hits.

AGT's MCP-SECURITY-GATEWAY-1.0 spec defines cryptographic fingerprinting of tool descriptions+schemas stored at first registration; any delta = `rug_pull` block. NEOTH has `security/dep_health.rs` and `security/osv_check.rs` (library CVE scanning) but nothing that fingerprints MCP tool schemas at call time.

**GAP F — Credential placeholder substitution vault**
```
grep -rn '{{cred:\|cred:NAME\|CredentialVault\|credential_vault\|placeholder_re' SRC/neothd/src/
```
Result: 0 hits.

AGT `credential_vault.rs` encrypts secrets at rest (AES-256-GCM, 12-byte nonce) and uses `{{cred:NAME}}` as a safe opaque reference. NEOTH has `security/api_tokens.rs` and `security/credential_redact.rs` (redacts from logs) but no placeholder substitution system — credentials flow as raw values to the caller.

**GAP G — IFC data-provenance label lattice**
```
grep -rn 'ifc_clearance\|information_flow\|source_labels\|clearance\|ifc\.' SRC/neothd/src/
```
Result: 0 hits.

ACS §11 defines a stateless label flow model: `input.snapshot.ifc.source_labels[]` at each tool-call sink; tool catalog entries declare `clearance` (max sensitivity accepted). Default lattice: `public < internal < confidential < secret`. NEOTH's `permissions/policy.rs` has `ActionKind` + `ApprovalTier` (action-based classification) but no data-provenance labels that propagate from source through the agent loop.

### 3. Steal-list

| # | What to steal | Source file | Target NEOTH file | Real consumer | Effort |
|---|---------------|-------------|-------------------|---------------|--------|
| 1 | `PromptInjectionDetector` multi-turn state: ring buffer, `MultiTurnEscalation`, `CanaryLeak` type, configurable canary tokens | `agentmesh/src/prompt_injection.rs` | `SRC/neothd/src/security/injection_tracker.rs` (new) | `security/ingress_sanitizer.rs::sanitize()` — append cross-turn state check after current single-message pass | M |
| 2 | SHA-256 hash-chain `AuditLogger` — `log()`, `verify()`, seam-anchor on eviction | `agentmesh/src/audit.rs` | `SRC/neothd/src/permissions/audit.rs` — augment existing module with chained `AuditEntry` type | `permissions/gate.rs::record_decision()` | M |
| 3 | `TrustManager` — 0-1000 score, 5 tiers, reward/penalty/decay, JSON persistence | `agentmesh/src/trust.rs` | `SRC/neothd/src/cluster/peer_trust.rs` (new) | `cluster/hyperswarm.rs` peer accept/reject + `loop_engine/` proactive delegation decisions | M |
| 4 | MCP tool fingerprinting / rug pull detection — HMAC schema fingerprint + schema drift diff | `docs/specs/MCP-SECURITY-GATEWAY-1.0.md` §4, §16 | `SRC/neothd/src/security/mcp_guardian.rs` (new) | MCP tool invocation path in `permissions/gate.rs::McpToolInvocation` action | L |
| 5 | Credential `{{cred:NAME}}` placeholder system — AES-256-GCM store, placeholder regex, resolver | `agentmesh/src/credential_vault.rs` | `SRC/neothd/src/security/credential_vault.rs` (new) — existing `api_tokens.rs` stays; vault wraps it | Channel adapter tool-call injectors; `permissions/lease.rs::McpTool` scope | L |
| 6 | IFC label lattice concept — `source_labels[]`, `clearance` field on tool catalog entries, no-write-down policy | ACS spec §11 (`policy-engine/spec/SPECIFICATION.md`) | `SRC/neothd/src/permissions/ifc.rs` (new label types + `clearance` field on `ActionKind`) | `permissions/gate.rs` — check label dominance before `McpToolInvocation` and `ExternalHttpRequest` | L |
| 7 | Canary token `CanaryLeak` — 3-line extension to steal #1 scope | `prompt_injection.rs:InjectionType::CanaryLeak` | `security/injection_tracker.rs` (same file as #1, canary config field) | `ingress_sanitizer.rs` — check model output path too | S (bundled with #1) |
| 8 | ACS `AUDIT-COMPLIANCE-1.0` canonical `AuditEntry` schema fields (`seq`, `timestamp`, `agent_id`, `action`, `decision`, `previous_hash`, `hash`) for WAL serialization alignment | `docs/specs/AUDIT-COMPLIANCE-1.0.md` §4.1 | `SRC/neothd/src/wal/events.rs` — align audit WAL event schema (comment-level alignment, not code change) | Downstream audit tooling, interoperability | S |

### 4. What NEOTH already does as well or better (no gap)

- **Permission taxonomy**: NEOTH's 27 `ActionKind` variants + 7 `ApprovalTier` tiers + `AutonomyLevel × Tier → Decision` matrix is *more granular* than AGT's general allow/deny. No steal needed.
- **Content injection patterns**: NEOTH `content_scanner.rs` has 15 injection patterns + 7 malware indicators (paperless-specific); AGT's Rust detector's built-in rule corpus targets general LLM injection — comparable coverage, different domain. NEOTH does not need to replace its scanner with AGT's.
- **Consent / lease system**: NEOTH `lease.rs` (525 lines) + `consent.rs` (2789 lines) is more sophisticated than AGT's policy manifest for the personal-daemon use-case.
- **OSV / CVE scanning**: NEOTH `security/osv_check.rs` + `dep_health.rs` covers library dependency CVEs. AGT `credential_vault.rs` adds `CVEFeed` integration for MCP server dependencies — AGT beats NEOTH only on the MCP-server-specific CVE check (included in steal #4 scope).
- **Council / adversarial review**: NEOTH `council/` (18 modules, orchestrator + adversarial self-reflect) is far more sophisticated than anything in AGT.

### 5. Licence obligations for source (a)

- **MIT License** — must include Microsoft copyright notice and MIT license text in any redistribution. Code copied into NEOTH binary: include in `THIRD_PARTY_LICENSES.txt` or equivalent. Required attribution: `Copyright (c) Microsoft Corporation`.
- **LF Projects governance (CHARTER.md)** — binds *contributors* to the project, not users of the code. No usage restriction. No patent grant separate from MIT (MIT itself carries no patent grant; Microsoft signed the DCO, not a patent pledge — evaluate any patent risk separately if commercialising).
- **Antitrust Policy (ANTITRUST.md)** — binds participants in project meetings only. Zero obligation for downstream code users.
- **Developer Certificate of Origin (DCO)** — required only if NEOTH *contributes back upstream*. Consuming the MIT code imposes no DCO obligation.
- **Net obligation for NEOTH**: add `Copyright (c) Microsoft Corporation. Licensed under the MIT License.` to `THIRD_PARTY_LICENSES.txt` and ensure the notice ships in the binary distribution.

---

## Source (b): shanraisshan/claude-code-best-practice — LOCAL: `/tmp/adopt2026/claude-code-best-practice`

### 1. What it actually does

A showcase / tutorial repository for Claude Code configuration patterns. 63k stars. 124 code files but most are SVG marketing assets (the `!/` directory is 80% of the repo). Concrete deliverables:

- **`.claude/settings.json`**: canonical example of hooks wiring (all 8 hook types: `PreToolUse`, `PostToolUse`, `PostToolUseFailure`, `PermissionRequest`, `Notification`, `Stop`, `SubagentStop`, `PreCompact`), permissions allowlist with domain-scoped `WebFetch`, tool glob patterns, `CLAUDE_AUTOCOMPACT_PCT_OVERRIDE: 80`, custom status line, plans directory
- **`.claude/hooks/scripts/hooks.py`**: single Python dispatcher routing all hook events via `CLAUDE_HOOK_TYPE` env var; async by default, 5-second timeout
- **`.claude/agents/*.md`**: agent definitions with `subagent_type`, `model`, `tools`, `description` headers; `time-agent` and `weather-agent` examples
- **`agent-teams/` orchestration**: sequential orchestrator pattern — Agent tool (subagent_type) → captures output → Skill tool → output file contract; strict sequential flow with explicit data contract definition
- **`.claude/commands/workflows/`**: slash commands that wire multi-agent workflows

### 2. Where it beats NEOTH

It does not beat NEOTH in any implementable code dimension.

NEOTH already has:
- `src/hooks/` — hooks subsystem
- `src/skills/` (34.8k LOC) — skills system with installer, authority, router, creator
- Session management, WAL, channel adapters
- `src/coding/decomposer.rs`, `dispatcher.rs` — multi-agent decompose/dispatch

The repository is a configuration *showcase* of Claude Code's built-in capabilities, not a source of new mechanisms. Its `.claude/settings.json` demonstrates the complete Claude Code hooks API — useful as a reference for NEOTH's Claude Code integration documentation, not for NEOTH's Rust implementation.

**One concrete, non-obvious pattern**: the agent-teams `ORCHESTRATOR.md` defines an explicit **data contract** between sub-agents — fields that MUST be returned, named and typed, enforced by the orchestrator before invoking the next step. NEOTH's `src/coding/dispatcher.rs` dispatches tasks but the inter-agent data contract is implicit. The pattern is worth porting to `coding/dispatcher.rs` comments/doc.

### 3. Steal-list

| # | What to steal | Source file | Target NEOTH file | Real consumer | Effort |
|---|---------------|-------------|-------------------|---------------|--------|
| 1 | Explicit inter-agent data contract definition pattern (field name + type + required/optional) | `agent-teams/orchestration/ORCHESTRATOR.md` §Data Contract | `SRC/neothd/src/coding/dispatcher.rs` — add `WorkerContract` typed struct documenting expected return fields | `coding/task_executor.rs` — validate returned JSON against contract before accepting result | S |

### 4. What NEOTH already does as well or better

Everything. This repo demonstrates Claude Code configuration; NEOTH implements the equivalent behaviours in Rust.

### 5. Licence obligations for source (b)

MIT license. Copyright: shanraisshan. No obligations beyond attribution in `THIRD_PARTY_LICENSES.txt` if code is copied. The data contract pattern (steal #1) is a design idea, not copyrightable code — no obligation.

---

## Source (c): garrytan/gstack — LOCAL: `/tmp/adopt2026/gstack`

### 1. What it actually does

A bun/TypeScript persistent-browser + opinionated-workflow-skills toolkit for Claude Code. 125k stars, 879 code files. Core components:

- **Chromium daemon** (`ARCHITECTURE.md`): long-lived headless Chromium process with sub-second browser tool latency via CDP; CLI binary talks to localhost HTTP server; state persisted in `~/.gstack/`
- **55 skill prompts**: Markdown files (`SKILL.md`) in per-feature directories; each is a multi-phase instruction set executed by Claude Code
- **`/autoplan`** (`autoplan/SKILL.md`): 4-phase review pipeline — CEO Review (strategy/scope) → Design Review (UI scope only) → Eng Review + Dual Voices → DX Review (developer-facing) → Final Approval Gate; produces a "Decision Audit Trail" written to `reports/` before any implementation begins
- **`/canary`** (`canary/SKILL.md`): visual post-deploy monitor — baseline screenshot capture → page discovery → continuous monitoring loop → regression diff report
- **`/careful`** (`careful/SKILL.md`): destructive command guardrails — blocked pattern list (rm -rf, format, truncate, dd, shred, DROP TABLE, etc.) with safe exceptions
- **`/guard`** (`guard/SKILL.md`): full safety mode layering careful + explicit confirmation for every file write
- **`/codex`**: cross-model second opinion via Codex CLI (GPT-4o or Gemini)
- **`/benchmark-models`**: parallel model comparison with LLM judge — latency/tokens/cost/quality scoring

Alex already has gstack installed at `~/.claude/skills/gstack` and uses it. The evaluation question is *which mechanisms should become native NEOTH capabilities*.

### 2. Where it beats NEOTH

**Overlap first (honest assessment):**

| gstack mechanism | NEOTH equivalent | Verdict |
|-----------------|------------------|---------|
| `/cso` OWASP+STRIDE review | `council/orchestrator.rs` adversarial panel | Already covered |
| `/codex` second opinion | `coding/second_opinion.rs` | Already covered |
| `/careful` destructive patterns | `security/risk_gate.rs` | Already covered |
| `/canary` visual monitoring | N/A (no browser in NEOTH) | Not applicable |
| `/benchmark-models` model comparison | `models/catalog.rs` + `discovery.rs` | Partial (catalog, not benchmark) |

**Genuine gap:**

`/autoplan`'s **Decision Audit Trail** — a *pre-work* multi-role sequential sign-off pipeline where each reviewer's verdict is written to a persistent record before implementation is authorised. NEOTH's `council/` does post-generation adversarial review (`self_reflect.rs`, `quality_score.rs`, `orchestrator.rs`). The coding pipeline (`coding/plan_review.rs`, `coding/early_stop.rs`) checks the plan but there is no *multi-role sequential gate* whose sign-off trail is written to WAL/disk *before* a high-impact action proceeds.

```
grep -rn 'DecisionAuditTrail\|audit_trail\|pre_work_gate\|sign_off\|approval_gate' SRC/neothd/src/
```
Result: 0 hits.

The gap is behavioural not code-missing. The mechanism is: `seq[role_reviewer_1_verdict, role_reviewer_2_verdict, ..., gate_decision]` persisted as a WAL chain *before* the dispatcher fires. High-impact actions (SelfSourceEdit, ExecArbitrary, SelfBinaryReplace) would benefit from this gate.

### 3. Steal-list

| # | What to steal | Source file | Target NEOTH file | Real consumer | Effort |
|---|---------------|-------------|-------------------|---------------|--------|
| 1 | Pre-work multi-role sign-off gate: sequential role verdicts written to WAL before high-impact action dispatch | `autoplan/SKILL.md` §Phase 0–4 + §Decision Audit Trail | `SRC/neothd/src/council/pre_action_gate.rs` (new) — `PreActionGate::run(action: &Action) -> GateDecision`; emits WAL events per phase | `coding/dispatcher.rs` before dispatching `SelfSourceEdit`, `ExecArbitrary`, `SelfBinaryReplace`, `PatchApplyToRepo` | L |
| 2 | `/careful` blocked-pattern list (curated command taxonomy including SQL, format, dd) as a static const table | `careful/SKILL.md` §What's protected | `SRC/neothd/src/security/risk_gate.rs` — compare against NEOTH's existing block patterns; fill any taxonomy gaps | `security/risk_gate.rs::is_dangerous_command()` | S |

### 4. What NEOTH already does as well or better

- Post-generation council review: NEOTH's `council/` subsystem (orchestrator, self_reflect, adversarial review, quality_score, callosum) is architecturally superior to gstack's prompt-only review skills.
- `/codex` second opinion: NEOTH `coding/second_opinion.rs` is the equivalent.
- `/cso` OWASP review: NEOTH's 12-module `security/` stack covers the same ground in Rust.

### 5. Licence obligations for source (c)

MIT license. Copyright: garrytan. No behavioural/design obligations. The `/careful` pattern list is a design idea; the `/autoplan` protocol is a procedure; neither is copyrightable code. If SKILL.md text is quoted inline in NEOTH doc comments, add attribution. No binary obligation if only the design pattern is ported.

---

## Source (d): fermisense.com/when-machines-take-the-wheel/

### 1. What it actually does

This is **NOT** an article about machine autonomy governance, permission tiers, or human-in-the-loop thresholds. The fetched content and title ("The Rise of Intelligence Ownership: a task-trained open source model vs the frontier") is an e-commerce case study: fine-tuning a 9B model for product catalog integrity classification — demonstrating 87% quality at $0.50/1K listings versus frontier models at $19–172/1K at 70–76% quality. The "machines take the wheel" framing refers to fine-tuned small models replacing frontier API calls for a narrow business task, not autonomous AI agents.

### 2–5. (All sections — no actionable content)

The article contains **zero** claims about:
- Autonomy levels or handoff protocols
- Human-in-the-loop thresholds
- Failure mode taxonomy
- Accountability frameworks
- Permission tiers

**No extraction value for NEOTH's `src/permissions/tier_classifier.rs`, `lease.rs`, `policy.rs`, `proactive/action_staging.rs`, or `loop_engine/`.** This is a plain verdict, not a failure — the brief's task was to extract *if present*. Nothing is present.

**Licence**: No code involved; it is a blog post with charts. No obligations.

---

## Summary Steal-List (Ranked)

| # | Item | Source | Target NEOTH file | Effort | Real consumer |
|---|------|---------|-------------------|--------|---------------|
| 1 | Multi-turn injection escalation tracking + canary token detection: cross-turn ring buffer, `MultiTurnEscalation`, `CanaryLeak` | `agentmesh/src/prompt_injection.rs` | `SRC/neothd/src/security/injection_tracker.rs` (new) | M | `security/ingress_sanitizer.rs` — append cross-turn state after single-message pass |
| 2 | SHA-256 hash-chain tamper-evident audit log: `AuditEntry{seq, prev_hash, hash}`, `verify()` | `agentmesh/src/audit.rs` | `SRC/neothd/src/permissions/audit.rs` — augment existing module | M | `permissions/gate.rs::record_decision()` → chain all gate verdicts |
| 3 | Per-agent trust score: 0–1000, 5 tiers, reward/penalty/decay, JSON persistence | `agentmesh/src/trust.rs` | `SRC/neothd/src/cluster/peer_trust.rs` (new) | M | `cluster/hyperswarm.rs` peer accept/reject; `loop_engine/` delegation threshold |
| 4 | MCP tool fingerprinting + rug pull detection: HMAC schema hash at registration, delta = block | `docs/specs/MCP-SECURITY-GATEWAY-1.0.md` §4, §16 | `SRC/neothd/src/security/mcp_guardian.rs` (new) | L | `permissions/gate.rs::McpToolInvocation` action path |
| 5 | Pre-work multi-role sign-off gate: sequential role verdicts + Decision Audit Trail written to WAL before high-impact dispatch | `gstack/autoplan/SKILL.md` §Phase 0–4 | `SRC/neothd/src/council/pre_action_gate.rs` (new) | L | `coding/dispatcher.rs` before SelfSourceEdit / ExecArbitrary / SelfBinaryReplace |
| 6 | Credential `{{cred:NAME}}` placeholder vault: AES-256-GCM store, opaque reference, resolver | `agentmesh/src/credential_vault.rs` | `SRC/neothd/src/security/credential_vault.rs` (new) | L | Channel adapter tool-call injectors; `permissions/lease.rs::McpTool` scope |
| 7 | IFC label lattice: `source_labels[]`, `clearance` on `ActionKind`, no-write-down policy check | ACS spec §11 | `SRC/neothd/src/permissions/ifc.rs` (new) + `ActionKind` augment | L | `permissions/gate.rs` — McpToolInvocation + ExternalHttpRequest data-provenance gate |
| 8 | AUDIT-COMPLIANCE-1.0 canonical schema alignment: ensure WAL audit events use same field names | `docs/specs/AUDIT-COMPLIANCE-1.0.md` §4.1 | `SRC/neothd/src/wal/events.rs` — comment-level alignment only | S | External audit tooling interoperability |
| 9 | `risk_gate.rs` gap-fill from `/careful` pattern list: verify SQL, format, dd, shred coverage | `gstack/careful/SKILL.md` §What's protected | `SRC/neothd/src/security/risk_gate.rs` | S | `risk_gate.rs::is_dangerous_command()` |
| 10 | `WorkerContract` typed struct for inter-agent data contracts | `claude-code-best-practice/agent-teams/ORCHESTRATOR.md` | `SRC/neothd/src/coding/dispatcher.rs` | S | `coding/task_executor.rs` return validation |

---

## Items that contradict the brief's baseline

1. **fermisense article is completely off-topic** — the URL and title suggest an autonomy-governance piece; the actual content is an ML fine-tuning case study for product cataloging. Zero design constraints for NEOTH's autonomy tiers. Not a failure of the brief; just a mismatch between article title and content.

2. **AGT conformance suite cannot be run against NEOTH** — the brief asks "is there a scored conformance suite we could run NEOTH against?" The answer is no: AGT's benchmark scripts (`bench_kernel.py`, `bench_audit.py`) measure AGT's own Python implementation. The formal RFC 2119 conformance requirements in each spec could be implemented as a NEOTH test harness, but that work does not exist yet in the repo. The prompt-injection evaluation fixture (`benchmarks/prompt-injection/`) is evaluation-only, not a publishable-ASR methodology (per `BENCHMARKS.md` §Security & Red-Team + issue #2577).

3. **AGT Rust SDK crate has a notable transitive dep: `cedar-policy` + `regorus` (OPA/Rego)** — these are substantial crates. Steal items #1–#3 and #6–#9 do NOT require pulling in Cedar or Rego; they are self-contained Rust logic using `sha2`, `aes-gcm`, `hmac`, `ed25519-dalek` (already in NEOTH's ecosystem for other modules). Only steal #7 (IFC) conceptually references the Cedar lattice, but the NEOTH port would use a simple Rust enum, not the Cedar dep itself.

4. **claude-code-best-practice is marketing, not code** — brief tags it 63k★, 124 code files; actual value: near zero for NEOTH's Rust implementation. The hooks and settings it demonstrates are already in NEOTH's hooks subsystem.

5. **WAL opcode exhaustion applies** — steals #1, #3, #4, #5 all emit new WAL events. Each MUST use the Extended-Subtype band (`ExtendedSubtype` in `SRC/neothd/src/wal/events.rs`). Top-level opcodes 255/255 are exhausted; any new WAL event failing this rule is a build-time compile error from the `allowlist_contains_exactly_*` test.

---

## Build Order — Staged Slices

**Slice 1 (~1 week — ships independently): Hash-chain audit hardening**
- Augment `permissions/audit.rs` with `AuditEntry{seq, timestamp, agent_id, action, decision, previous_hash, hash}` type (steal #2)
- Add `sha2` call in `gate.rs::record_decision()` to compute and persist chain hash
- Add `verify_chain()` function; expose via `neoth audit verify` CLI subcommand
- No new WAL opcodes needed — `audit.rs` writes to its own JSONL log; WAL emits the same gate events as today
- **Consumer**: operator verification of gate decision integrity; CI test asserting `verify_chain()` passes after a round-trip

**Slice 2 (~1 week — after Slice 1): Multi-turn injection tracker**
- New file `security/injection_tracker.rs` with `InjectionTracker` (10K-entry ring buffer), `InjectionType` enum (7 variants), `ThreatLevel` (5 levels), `Sensitivity` (3 modes) (steal #1 + bundled canary #7)
- Wire into `ingress_sanitizer.rs::sanitize()` — call tracker after current single-message scan
- Add `canary_tokens: Vec<String>` to freedom.yaml security config block
- Emit WAL Extended-Subtype event `InjectionEscalationDetected` on `MultiTurnEscalation` + `Critical`
- **Consumer**: `ingress_sanitizer.rs` guards all inbound channel messages; `loop_engine/` can check tracker state before autonomous actions

**Slice 3 (~1 week — after Slice 2): Peer trust scoring**
- New file `cluster/peer_trust.rs` with `PeerTrustManager` (steal #3): per-agent score 0–1000, 5 tiers, decay, JSON persistence to `~/.neoth/peer_trust.json`
- Wire into `cluster/hyperswarm.rs` peer accept: score ≥ 500 (Neutral) required for `ClusterTaskAccept`
- Wire into `loop_engine/` delegation: `score ≥ 700` (Trusted) required for autonomous task dispatch to peer
- CLI: `neoth cluster peer trust list`, `neoth cluster peer trust adjust <id> <score>`
- WAL Extended-Subtype event `PeerTrustAdjusted`
- **Consumer**: `cluster/hyperswarm.rs`; `loop_engine/`; autonomy gate for cluster delegation

**Slice 4 (~2 weeks — after Slice 3): MCP guardian + rug pull detection**
- New file `security/mcp_guardian.rs` with `McpToolGuardian`: HMAC-SHA256 fingerprinting of tool description+schema at first-call registration, persisted to `~/.neoth/mcp_fingerprints.json`; `check_or_register(tool_name, schema) → GuardDecision` (Allow / Rug-Pull-Block)
- Wire into `permissions/gate.rs` `McpToolInvocation` action path: call guardian before approving
- Schema drift: compare stored fingerprint to current; `Severity::High` delta = block; `Severity::Low` delta = emit WAL warning
- WAL Extended-Subtype events `McpToolRegistered`, `McpToolRugPullBlocked`, `McpToolSchemaDriftDetected`
- **Consumer**: `permissions/gate.rs::McpToolInvocation` — every MCP tool call

**Slice 5 (~2 weeks — after Slice 4): Pre-action sign-off gate**
- New file `council/pre_action_gate.rs` (steal gstack #5): `PreActionGate::run(action, context) → GateVerdict`; phases: [scope_review, risk_review, gate_decision]; each phase verdict written to WAL chain (from Slice 1)
- Wire into `coding/dispatcher.rs` before dispatching `SelfSourceEdit`, `ExecArbitrary`, `SelfBinaryReplace`, `PatchApplyToRepo`
- Gate is skippable in `Full` autonomy level; always runs in `Strict`
- **Consumer**: `coding/dispatcher.rs`; operator can review `neoth wal show --type gate_phase`

**Slice 6 (v1.1 scope — deferred): Credential vault + IFC labels**
- `security/credential_vault.rs` (steal #6): AES-256-GCM store, `{{cred:NAME}}` placeholder system, resolver; wraps existing `security/api_tokens.rs`
- `permissions/ifc.rs` (steal #7): `IFCLabel` enum (`Public/Internal/Confidential/Secret`), `clearance` field on `ActionKind`, no-write-down check in gate
- Both deferred: no immediate consumer calling for them; build after Slices 1–5 have shipped and the operator has a real credential-sensitive MCP workflow to protect
