# QUELLEN Adoption Analysis: agency-agents → NEOTH
Date: 2026-05-21

---

## 1. What Kind of Agency Is This?

**Model: One orchestrator → many parallel specialists (NEXUS pipeline)**

agency-agents ("The Agency") is a **prompt-definition library** — 100+ Markdown persona files
organized into divisions. There is no runtime, no message bus, no RPC. Agents are activated by
copy-pasting a persona into an LLM context. Coordination happens through a documented protocol
called **NEXUS** (`strategy/nexus-strategy.md`).

Architecture classification:
- **NOT** peer-to-peer. Agents never message each other directly.
- **NOT** hierarchical CEO→manager→worker in the organizational sense.
- **IS** a single orchestrator (AgentsOrchestrator) that dispatches tasks to specialists and
  manages a Dev↔QA loop. That orchestrator is itself a persona — it delegates, tracks state,
  enforces quality gates, and handles retry/escalation.

Comparison to NEOTH:
- NEOTH's `council/orchestrator.rs` is the functional equivalent of AgentsOrchestrator.
- NEOTH's `sub_agents/` (builtins + loader + review) is the execution layer that
  agency-agents only describes as persona files.
- The NEXUS Dev↔QA loop (Developer→Evidence Collector→PASS/FAIL→retry≤3→escalate) is
  architecturally identical to NEOTH's coding-workflow dispatcher→reviewer flow already in
  council/orchestrator.rs and council/quality_score.rs.

---

## 2. Architecture of NEOTH Relevant Layers

| NEOTH module | Role |
|---|---|
| `council/orchestrator.rs` | dispatch, retry policy, quality gate |
| `council/quality_score.rs` | pass/fail scoring |
| `council/callosum.rs` | synthesis (= NEXUS phase-gate integration) |
| `council/types.rs` | CouncilVoice enum, hemisphere config |
| `sub_agents/builtins.rs` | built-in persona definitions |
| `sub_agents/review.rs` | reviewer sub-agent execution |

---

## 3. Full Agent Enumeration and Classification

### 3.1 Engineering Division

| Agent file | Classification | Rationale |
|---|---|---|
| engineering-ai-engineer.md | **ADOPT-AS-HEMISPHERE-ROLE** | Maps to Right hemisphere (deep reasoning, model tasks). Promote as a preset in `HemisphereRole::Deep`. |
| engineering-backend-architect.md | **ADOPT-AS-AGENT** | Port to `sub_agents/builtins.rs` as `BackendArchitect` persona. Used in coding-workflow dispatch for API/schema tasks. |
| engineering-code-reviewer.md | **ADOPT-AS-AGENT** | Merge with existing `sub_agents/review.rs`. The persona adds "minimal-change" and "evidence over claims" instructions missing from current reviewer. |
| engineering-security-engineer.md | **ADOPT-AS-COUNCIL-VOICE** | Security perspective fits as a `CouncilVoice` in `council/types.rs`. Fires on consent gates and permission-token evaluation. |
| engineering-threat-detection-engineer.md | **ADOPT-AS-COUNCIL-VOICE** | Pair with security-engineer voice. Activated when WAL event codes 0xA0–0xA3 (autonomy gates) trigger. |
| engineering-incident-response-commander.md | **ADOPT-AS-AGENT** | Port as `IncidentResponder` sub-agent. Relevant for NEOTH daemon crash/recovery path. |
| engineering-minimal-change-engineer.md | **ADOPT-AS-AGENT** | Valuable diff discipline. Add as `MinimalChangeReviewer` in `sub_agents/builtins.rs` — runs before any worktree-apply commit. |
| engineering-autonomous-optimization-architect.md | **ADOPT-AS-COUNCIL-VOICE** | Performance perspective for council. Activated on resource-heavy dispatch cycles. |
| engineering-database-optimizer.md | **ADOPT-AS-AGENT** | Port as `DbOptimizer` sub-agent for SQLite/views.db query advice. |
| engineering-codebase-onboarding-engineer.md | **ADOPT-AS-AGENT** | Port as `OnboardingGuide` sub-agent — fire during `neoth init` wizard to explain project structure. |
| engineering-sre.md | **ADOPT-AS-AGENT** | Port as `SreMonitor` sub-agent for daemon health + WAL diagnostics. |
| engineering-devops-automator.md | **SKIP-DUPLICATE** | NEOTH has no CI/CD layer; overlap with `neoth update` auto-update is thin. |
| engineering-frontend-developer.md | **SKIP-OUT-OF-SCOPE** | GUI is Slint/Tauri-native; web frontend specialization does not apply. |
| engineering-rapid-prototyper.md | **SKIP-DUPLICATE** | Covered by Left hemisphere fast-path dispatch. |
| engineering-software-architect.md | **SKIP-DUPLICATE** | Covered by Cerebellum orchestrator role. |
| engineering-senior-developer.md | **SKIP-DUPLICATE** | Absorbed by code-reviewer + backend-architect. |
| engineering-embedded-firmware-engineer.md | **SKIP-OUT-OF-SCOPE** | No hardware target. |
| engineering-mobile-app-builder.md | **SKIP-OUT-OF-SCOPE** | FadCam is separate project. |
| engineering-data-engineer.md | **SKIP-OUT-OF-SCOPE** | No ETL pipeline. |
| engineering-ai-data-remediation-engineer.md | **SKIP-OUT-OF-SCOPE** | Data-quality niche not in scope. |
| engineering-git-workflow-master.md | **SKIP-DUPLICATE** | NEOTH has `neoth code` + kanban WAL; this adds nothing structural. |
| engineering-cms-developer.md | **SKIP-OUT-OF-SCOPE** | No CMS. |
| engineering-email-intelligence-engineer.md | **SKIP-OUT-OF-SCOPE** | No email pipeline in core. |
| engineering-feishu-integration-developer.md | **SKIP-OUT-OF-SCOPE** | Feishu not a target messenger. |
| engineering-filament-optimization-specialist.md | **SKIP-OUT-OF-SCOPE** | 3D printing domain. |
| engineering-wechat-mini-program-developer.md | **SKIP-OUT-OF-SCOPE** | Not a target channel. |
| engineering-voice-ai-integration-engineer.md | **SKIP-OUT-OF-SCOPE** | whisper-rs/piper-rs are pinned tech; no new integration needed now. |
| engineering-solidity-smart-contract-engineer.md | **SKIP-OUT-OF-SCOPE** | Blockchain out of scope. |

### 3.2 Testing Division

| Agent file | Classification | Rationale |
|---|---|---|
| testing-evidence-collector.md | **ADOPT-AS-AGENT** | This is the missing QA reviewer in NEOTH's coding-workflow. Port as `EvidenceCollector` sub-agent: runs after worker applies patch, returns structured PASS/FAIL verdict to `council/quality_score.rs`. |
| testing-reality-checker.md | **ADOPT-AS-AGENT** | Final integration verifier. Port as `RealityChecker` — fires at Phase 4 (worktree-apply gate) before merging to main. |
| testing-api-tester.md | **ADOPT-AS-AGENT** | Port as `ApiTester` sub-agent for provider-endpoint smoke-test on `neoth provider test`. |
| testing-performance-benchmarker.md | **ADOPT-AS-COUNCIL-VOICE** | Add as performance voice in council — fires when task classification is "perf" or dispatch hits retry budget. |
| testing-accessibility-auditor.md | **ADOPT-AS-COUNCIL-VOICE** | A11y perspective for GUI council debate (NOOB-UX items). |
| testing-test-results-analyzer.md | **ADOPT-AS-AGENT** | Port as `TestResultsAnalyzer` — consumes `cargo test` stdout, emits structured quality deltas to views.db kanban. |
| testing-tool-evaluator.md | **SKIP-OUT-OF-SCOPE** | Tool-selection advisor; NEOTH tech stack is already pinned. |

### 3.3 Specialized Division (selected)

| Agent file | Classification | Rationale |
|---|---|---|
| specialized/agents-orchestrator.md | **SKIP-DUPLICATE** | NEOTH's `council/orchestrator.rs` is the production implementation of this. The persona doc is reference-only; port specific retry/escalation language into inline comments. |
| specialized/agentic-identity-trust.md | **ADOPT-AS-COUNCIL-VOICE** | Trust-scoring model (delegation chains, zero-trust for agents, fail-closed auth) maps to NEOTH's `permissions::evaluate` + `PermissionToken<L>` gates. Add as `CouncilVoice::TrustAuditor`. |
| specialized/identity-graph-operator.md | **ADOPT-AS-AGENT** | Entity deduplication for ground-truth import (R-24). Port `IdentityGraphOperator` as sub-agent firing during `neoth memory import`. |
| specialized/mcp-builder.md | **ADOPT-AS-AGENT** | Port as `McpServerBuilder` sub-agent for NEOTH's plugin-wasm runtime toggle (NOOB-UX-3). |
| specialized/automation-governance-architect.md | **ADOPT-AS-COUNCIL-VOICE** | Governance/compliance voice — activate when `freedom.yaml` feature flags change at runtime. |
| specialized/blockchain-security-auditor.md | **SKIP-OUT-OF-SCOPE** | Solidity-specific domain. |
| specialized/zk-steward.md | **SKIP-OUT-OF-SCOPE** | Zettelkasten knowledge management — NEOTH handles memory via SQLite tiers, not ZK. |
| specialized/document-generator.md | **SKIP-OUT-OF-SCOPE** | PDF/PPTX export not in NEOTH scope. |
| specialized/sales-data-extraction-agent.md | **SKIP-OUT-OF-SCOPE** | Sales domain. |
| specialized/data-consolidation-agent.md | **SKIP-OUT-OF-SCOPE** | Sales domain. |
| specialized/report-distribution-agent.md | **SKIP-OUT-OF-SCOPE** | Sales domain. |
| specialized/lsp-index-engineer.md | **SKIP-OUT-OF-SCOPE** | LSP integration not in current NEOTH scope. |

### 3.4 Project Management Division

| Agent file | Classification | Rationale |
|---|---|---|
| project-management-studio-producer.md | **SKIP-DUPLICATE** | Cerebellum hemisphere already owns high-level orchestration. |
| project-manager-senior.md | **ADOPT-AS-AGENT** | Spec-to-task conversion logic maps to `neoth code` kanban population. Port as `TaskDecomposer` sub-agent firing at Cerebellum orchestration step. |
| project-management-jira-workflow-steward.md | **SKIP-OUT-OF-SCOPE** | NEOTH uses internal kanban (views.db), not Jira. |
| project-management-experiment-tracker.md | **SKIP-OUT-OF-SCOPE** | A/B testing infrastructure not in scope. |
| project-management-project-shepherd.md | **SKIP-DUPLICATE** | Covered by Cerebellum + coding-workflow dispatcher. |
| project-management-studio-operations.md | **SKIP-DUPLICATE** | Covered by NEOTH daemon operational loop. |

### 3.5 Support Division

| Agent file | Classification | Rationale |
|---|---|---|
| support-executive-summary-generator.md | **ADOPT-AS-AGENT** | Port as `SessionSummarizer` sub-agent — fires at session end (Stop hook) to populate `PLAN/PROGRESS.md` entries. Addresses HARD RULE: PROGRESS.md update. |
| support-analytics-reporter.md | **SKIP-OUT-OF-SCOPE** | Web analytics domain. |
| support-legal-compliance-checker.md | **SKIP-OUT-OF-SCOPE** | Legal domain. |
| support-finance-tracker.md | **SKIP-OUT-OF-SCOPE** | Finance domain. |
| support-infrastructure-maintainer.md | **SKIP-DUPLICATE** | Covered by SreMonitor above. |
| support-support-responder.md | **SKIP-OUT-OF-SCOPE** | Customer support domain. |

### 3.6 All Other Divisions

| Division | Verdict | Reason |
|---|---|---|
| Design (7 agents) | **SKIP-OUT-OF-SCOPE** | Slint UI is code-driven; brand/visual roles do not apply to a CLI+TUI product. Exception: UX-Architect accessibility notes are absorbed via testing-accessibility-auditor council voice above. |
| Marketing (17 agents) | **SKIP-OUT-OF-SCOPE** | Social media, SEO, China e-commerce — entirely out of NEOTH domain. |
| Paid Media (4 agents) | **SKIP-OUT-OF-SCOPE** | Ad buying domain. |
| Sales (5 agents) | **SKIP-OUT-OF-SCOPE** | CRM/sales domain. |
| Product (3 agents) | **SKIP-OUT-OF-SCOPE** | B2C product analytics; NEOTH is operator-tooling. |
| Finance (5 agents) | **SKIP-OUT-OF-SCOPE** | Accounting domain. |
| Game Dev (15 agents) | **SKIP-OUT-OF-SCOPE** | Unity/Unreal/Godot domain. |
| Academic (4 agents) | **SKIP-OUT-OF-SCOPE** | Research writing domain. |
| Spatial Computing (4 agents) | **SKIP-OUT-OF-SCOPE** | XR/AR domain. |

---

## 4. Handoff Pattern — Key Inspiration

The NEXUS handoff format is the most portable artifact in this repo. Every agent-to-agent
transfer uses a structured Markdown block:

```
FROM / TO / Phase / Task-ID / Priority / Timestamp
Context: current state + relevant files + dependencies
Deliverable: what is needed + acceptance criteria + constraints
Quality: must-pass criteria + evidence required + next receiver
```

**NEOTH mapping:**

NEOTH's coding-workflow already passes tasks through `views.db::idx_kanban_*` rows, but the
handoff payload between Cerebellum→Left/Right and back is currently implicit (just the task
text + WAL frame). The NEXUS handoff schema should be adopted as the `SubAgentRequest` and
`SubAgentResult` struct fields in `sub_agents/schema.rs`:

| NEXUS field | NEOTH field to add/rename |
|---|---|
| `current_state` | `SubAgentRequest::context` (exists) |
| `acceptance_criteria` | `SubAgentRequest::success_criteria` (new field) |
| `evidence_required` | `SubAgentResult::evidence` (new field, replaces free-form output) |
| `handoff_to_next` | `SubAgentResult::next_agent` (new field, currently implicit) |

The Dev↔QA loop (3 retries, then escalate) is already present in NEOTH's dispatcher. The
contribution is **formalizing the FAIL payload**: NEXUS Evidence Collector returns a structured
verdict (`PASS`, `FAIL`, `BLOCKED`) with specific failure items. NEOTH should adopt this enum
in `council/quality_score.rs` (`QaVerdict { Pass, Fail(Vec<FailureItem>), Blocked(String) }`).

---

## 5. Adoption Summary

### ADOPT-AS-AGENT (port to `sub_agents/builtins.rs` or new files)
1. `BackendArchitect` — coding-workflow API/schema tasks
2. `CodeReviewer` — merge with existing `sub_agents/review.rs`, add evidence-based diff
3. `IncidentResponder` — daemon crash/recovery path
4. `MinimalChangeReviewer` — pre-worktree-apply commit gate
5. `DbOptimizer` — SQLite/views.db advisor
6. `OnboardingGuide` — fires during `neoth init` wizard
7. `SreMonitor` — daemon health + WAL diagnostics
8. `EvidenceCollector` — **highest priority**: QA verdict after worker patch apply
9. `RealityChecker` — Phase 4 integration verifier before main merge
10. `ApiTester` — `neoth provider test` smoke-test
11. `TestResultsAnalyzer` — `cargo test` output → kanban delta
12. `IdentityGraphOperator` — ground-truth entity dedup (R-24)
13. `McpServerBuilder` — plugin-wasm runtime (NOOB-UX-3)
14. `TaskDecomposer` — spec → kanban task decomposition
15. `SessionSummarizer` — Stop-hook PROGRESS.md updater (HARD RULE compliance)

### ADOPT-AS-HEMISPHERE-ROLE (preset in hemisphere config)
1. `engineering-ai-engineer` → `HemisphereRole::Deep` preset (Right hemisphere default persona)

### ADOPT-AS-COUNCIL-VOICE (add to `council/types.rs` CouncilVoice enum)
1. `SecurityEngineer` — fires on consent gates, autonomy gates (0xA0–0xA3)
2. `ThreatDetectionEngineer` — pair with SecurityEngineer on WAL cluster events (0xE0–0xE7)
3. `PerformanceBenchmarker` — fires on retry-budget approach or "perf" task type
4. `AccessibilityAuditor` — fires on GUI council debate (NOOB-UX items)
5. `TrustAuditor` (from agentic-identity-trust) — fires on `permissions::evaluate` calls
6. `AutomationGovernanceArchitect` — fires on `freedom.yaml` runtime feature-flag changes

### SKIP-DUPLICATE (7 agents already covered by NEOTH internals)
AgentsOrchestrator persona, StudioProducer, ProjectShepherd, RapidPrototyper, SoftwareArchitect,
SeniorDeveloper, StudioOperations.

### SKIP-OUT-OF-SCOPE (80+ agents — design, marketing, sales, finance, game, academic, media)
All domain-specific agents outside engineering/testing/specialized core.

---

## 6. Implementation Order

Priority order based on current coding-workflow gaps:

| Priority | Item | Unlocks |
|---|---|---|
| 1 | `EvidenceCollector` sub-agent + `QaVerdict` enum | Closes missing structured PASS/FAIL in dispatcher loop |
| 2 | `RealityChecker` sub-agent | Hardens Phase 4 worktree-apply gate |
| 3 | `SubAgentRequest::success_criteria` + `SubAgentResult::evidence` fields | Formalizes NEXUS handoff in schema.rs |
| 4 | `SessionSummarizer` Stop-hook sub-agent | Enforces PROGRESS.md HARD RULE automatically |
| 5 | `SecurityEngineer` + `ThreatDetectionEngineer` council voices | Closes council gap on autonomy/permission gates |
| 6 | Remaining ADOPT-AS-AGENT entries (8–15 above) | Expand sub-agent library incrementally |
