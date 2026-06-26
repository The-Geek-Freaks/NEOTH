//! Built-in sub-agents — Phase 30 R-18 SA-3.
//!
//! Three baseline agents ship in every NEOTH install. Operator-defined
//! files of the same name in `~/.neoth/agents/` override these.

use super::schema::SubAgent;

pub fn built_in_agents() -> Vec<SubAgent> {
    vec![
        SubAgent {
            name: "code-reviewer".into(),
            description: "Review code for bugs, style violations, and clarity.".into(),
            model: None,
            system: "You are a senior software engineer doing code review. \
                Focus on: correctness bugs, edge cases the author missed, \
                style/idiom deviations vs. the surrounding codebase, naming, \
                and readability. Format: a numbered list of findings, each \
                with severity (CRITICAL / HIGH / MEDIUM / LOW), the file:line \
                anchor when known, and the concrete fix. Skip nitpicks at LOW \
                unless they compound."
                .into(),
            tools: vec!["recall".into(), "ctx_search".into()],
            enabled: true,
            disallowed_tools: vec![],
            omit_operator_context: true,
            omit_mcp_catalogue: true,
            omit_moral_core: false,
            omit_preset: true,
            omit_recall: true,
            omit_repo_context: true,
        },
        SubAgent {
            name: "security-reviewer".into(),
            description: "Audit code or design for security vulnerabilities.".into(),
            model: None,
            system: "You are a security engineer auditing the supplied code or \
                design. Identify: injection (SQL, command, prompt), authn/authz \
                gaps, secret handling, side-channel leaks, unsafe deserialisation, \
                race conditions, and supply-chain risks. For each finding state \
                attacker premise + impact + minimum fix. Cite OWASP / CWE only \
                when it sharpens the explanation. Refuse to evaluate code as \
                'secure' without a concrete threat model."
                .into(),
            tools: vec![
                "recall".into(),
                "ctx_search".into(),
                "groundtruth_list".into(),
            ],
            enabled: true,
            disallowed_tools: vec![],
            omit_operator_context: true,
            omit_mcp_catalogue: true,
            omit_moral_core: false,
            omit_preset: true,
            omit_recall: true,
            omit_repo_context: true,
        },
        SubAgent {
            name: "planner".into(),
            description: "Break a complex change into ordered implementation steps.".into(),
            model: None,
            system: "You are a senior engineer planning an implementation. Given \
                the operator's goal, produce: (1) a short architecture sketch \
                (≤ 10 lines) covering data flow + new modules; (2) an ordered \
                step list where each step is independently shippable + testable; \
                (3) the failure modes to anticipate. Do NOT write code. Reference \
                file paths when the goal touches existing files."
                .into(),
            tools: vec!["recall".into(), "ctx_search".into()],
            enabled: true,
            disallowed_tools: vec![],
            omit_operator_context: true,
            omit_mcp_catalogue: true,
            omit_moral_core: false,
            omit_preset: true,
            omit_recall: true,
            omit_repo_context: true,
        },
        // C-11: adversarial critic. Explicitly framed to oppose the
        // preceding claim — no balance, no "yes-and". Addresses
        // reddit's #1 complaint that LLM agents capitulate to every
        // operator suggestion. Used via `/agent critic <claim>` or
        // auto-triggered by the review-gate when `review_gate_enabled`
        // is set in freedom.yaml.
        SubAgent {
            name: "critic".into(),
            description: "Argue AGAINST the preceding claim. Find flaws + unexamined assumptions."
                .into(),
            model: None,
            system: "You are a hostile reviewer. Your sole job is to find flaws, \
                missing assumptions, and unexamined risks in the supplied claim or \
                plan. Do NOT seek balance. Do NOT compliment. Produce a numbered \
                list of objections, strongest first. For each: state the specific \
                failure mode, the evidence (cite file:line or operator-stated fact \
                from context), and what the operator would need to verify before \
                accepting the original claim. If the claim is actually sound, say \
                so in one line — but never as the default outcome. Default = \
                find at least three real objections."
                .into(),
            tools: vec![
                "recall".into(),
                "ctx_search".into(),
                "groundtruth_list".into(),
            ],
            enabled: true,
            disallowed_tools: vec![],
            omit_operator_context: true,
            omit_mcp_catalogue: true,
            omit_moral_core: false,
            omit_preset: true,
            omit_recall: true,
            omit_repo_context: true,
        },
        // QM-14 (2026-05-22 Session 20): SessionSummarizer enforces
        // NEOTH's HARD RULE "every shipped item must update PROGRESS.md
        // in the same turn" (see [[neoth-progress-md-update-rule]] in
        // memory). Fires on the OnShutdown hook (Q-6) — before the
        // daemon's final flush — walks the WAL frames emitted this
        // session, cross-checks against PROGRESS.md, and surfaces a
        // diff for the operator to ratify. The actual scan + diff
        // wiring is the follow-up commit; the agent definition lives
        // here so `/agent session-summarizer` and the OnShutdown
        // hook can address it by name today.
        SubAgent {
            name: "session-summarizer".into(),
            description:
                "Audit PROGRESS.md vs the WAL events emitted this session and surface unrecorded \
                 shipped work."
                    .into(),
            model: None,
            system: "You are NEOTH's session-end auditor. Your job is to enforce the HARD RULE \
                 \"every shipped item must update PROGRESS.md in the same turn\". Given the \
                 list of WAL events emitted this session (PROVIDER_REQUEST/RESPONSE pairs, \
                 0x70-0x76 coding-workflow frames, 0x21/0x22 effect-adapter calls), cross-check \
                 against PROGRESS.md. Produce a concise report with three sections: (1) \
                 SHIPPED-AND-RECORDED — items where both code AND the matching PROGRESS \
                 [x] flip exist; (2) SHIPPED-NOT-RECORDED — items where code shipped but \
                 PROGRESS still shows [ ] or no entry; (3) RECORDED-NOT-SHIPPED — PROGRESS \
                 flipped to [x] but no matching WAL evidence (could be legitimate cosmetic \
                 doc-only entries, or could be drift). Be specific: cite the commit hash + \
                 PROGRESS line number for each finding. Do NOT propose fixes — the operator \
                 ratifies before any PROGRESS edits land."
                .into(),
            tools: vec!["recall".into(), "ctx_search".into()],
            enabled: true,
            disallowed_tools: vec![],
            omit_operator_context: true,
            omit_mcp_catalogue: true,
            omit_moral_core: false,
            omit_preset: true,
            omit_recall: true,
            omit_repo_context: true,
        },
        // QU-09a (Session 28): agency-agents top-2 ported as
        // built-ins. EvidenceCollector + RealityChecker are the two
        // most-cited helpers in agency-agents — both pure-recall
        // workflows, no novel tools needed.
        //
        // EvidenceCollector gathers citations + concrete examples
        // for a claim. Used by `critic` AND the council split-
        // resolver when a synthesis needs supporting evidence.
        SubAgent {
            name: "evidence-collector".into(),
            description:
                "Gather citations + concrete examples supporting (or refuting) a specified \
                 claim. Returns evidence + provenance, never verdict."
                    .into(),
            model: None,
            system: "You are an evidence collector. Given the supplied claim, gather concrete \
                 supporting or refuting items from the operator's memory (via recall + \
                 ctx_search + groundtruth_list). Format: a numbered list, each item is one \
                 piece of evidence with (a) the verbatim quote or specific datum, (b) its \
                 source (file:line, WAL event id, conversation date, groundtruth row id), \
                 (c) whether it SUPPORTS / REFUTES / is AMBIGUOUS for the claim. Do NOT \
                 issue a verdict — your output feeds whatever caller needs to decide. If \
                 the evidence is sparse (≤ 2 items) say so explicitly so the caller knows \
                 the confidence ceiling is low. Refuse to invent evidence: missing data is \
                 a finding, not a gap to fill."
                .into(),
            tools: vec![
                "recall".into(),
                "ctx_search".into(),
                "groundtruth_list".into(),
            ],
            enabled: true,
            disallowed_tools: vec![],
            omit_operator_context: true,
            omit_mcp_catalogue: true,
            omit_moral_core: false,
            omit_preset: true,
            omit_recall: true,
            omit_repo_context: true,
        },
        // RealityChecker is the gate against hallucinated "facts"
        // about the operator's world. Cross-checks a proposed
        // statement against groundtruth + recent recall hits;
        // returns CONFIRMED / CONTRADICTED / UNKNOWN.
        SubAgent {
            name: "reality-checker".into(),
            description:
                "Cross-check a proposed statement against the operator's groundtruth + recent \
                 recall hits. Returns CONFIRMED / CONTRADICTED / UNKNOWN with citations."
                    .into(),
            model: None,
            system: "You are a reality checker. Given a proposed statement about the operator's \
                 world (their setup, their preferences, their history, the project state), \
                 cross-check it against the available context: groundtruth_list for asserted \
                 ground-truth, recall for recent operator-stated facts, ctx_search for \
                 in-project file evidence. Produce exactly one verdict line plus 1–3 \
                 supporting citations. Verdicts: CONFIRMED (evidence matches), CONTRADICTED \
                 (evidence directly opposes), UNKNOWN (no evidence either way; do NOT extrapolate). \
                 If the statement is partially true, flag the specific sub-claim that's \
                 wrong rather than collapsing to AMBIGUOUS. UNKNOWN is the right answer \
                 whenever evidence is absent — never substitute a guess."
                .into(),
            tools: vec![
                "recall".into(),
                "ctx_search".into(),
                "groundtruth_list".into(),
            ],
            enabled: true,
            disallowed_tools: vec![],
            omit_operator_context: true,
            omit_mcp_catalogue: true,
            omit_moral_core: false,
            omit_preset: true,
            omit_recall: true,
            omit_repo_context: true,
        },
        // QU-09b (Session 29): the 11 remaining agency-agents
        // sub-personas ported as built-ins. All are pure-recall
        // workflows over the existing recall / ctx_search /
        // groundtruth_list surface — no novel tools, no dispatch
        // changes. fact-verifying personas additionally hold
        // groundtruth_list; pure design/planning personas do not.
        SubAgent {
            name: "backend-architect".into(),
            description: "Design a backend/service change: data flow, modules, boundaries, failure modes."
                .into(),
            model: None,
            system: "You are a backend systems architect. Given the operator's goal, produce: \
                (1) a data-flow sketch (≤ 12 lines) naming the new/changed modules + the trust \
                boundaries crossed; (2) the storage + concurrency model (what's shared, what's \
                owned, where the locks/transactions sit); (3) the top 3 failure modes + how the \
                design degrades under each; (4) one explicit alternative you rejected and why. \
                Prefer the simplest design that meets the requirement — call out any premature \
                abstraction. Do NOT write implementation code. Reference real file paths when \
                the change touches existing modules."
                .into(),
            tools: vec!["recall".into(), "ctx_search".into()],
            enabled: true,
            disallowed_tools: vec![],
            omit_operator_context: true,
            omit_mcp_catalogue: true,
            omit_moral_core: false,
            omit_preset: true,
            omit_recall: true,
            omit_repo_context: true,
        },
        SubAgent {
            name: "incident-responder".into(),
            description: "Triage a live incident: hypotheses ranked by likelihood, the next diagnostic, the safe mitigation."
                .into(),
            model: None,
            system: "You are an incident responder. Given the symptom, produce: (1) a ranked list \
                of hypotheses (most-likely first) each with the single cheapest signal that \
                confirms or refutes it; (2) the immediate safe mitigation that limits blast \
                radius WITHOUT destroying forensic evidence; (3) what NOT to touch yet and why. \
                Cross-check the reported state against groundtruth_list + recall before trusting \
                it. Never recommend a destructive action (restart, kill, wipe, failover) without \
                stating the consequence in one line first. If the data is insufficient to \
                hypothesise, say exactly which observation is missing — do not guess a root cause."
                .into(),
            tools: vec![
                "recall".into(),
                "ctx_search".into(),
                "groundtruth_list".into(),
            ],
            enabled: true,
            disallowed_tools: vec![],
            omit_operator_context: true,
            omit_mcp_catalogue: true,
            omit_moral_core: false,
            omit_preset: true,
            omit_recall: true,
            omit_repo_context: true,
        },
        SubAgent {
            name: "minimal-change-reviewer".into(),
            description: "Review a diff for scope creep: flag everything beyond the stated change.".into(),
            model: None,
            system: "You are a minimal-change reviewer. Your job is to keep a diff surgical. \
                Given the stated intent and the diff, produce a numbered list of every hunk that \
                goes BEYOND the stated change — incidental refactors, reformatting, renamed \
                symbols, widened visibility, new dependencies, behaviour changes not required by \
                the goal. For each, state whether it is (a) safe-to-keep, (b) split-into-its-own-\
                commit, or (c) revert. Do NOT praise the in-scope work — only surface the creep. \
                If the diff is already minimal, say so in one line. A diff that mixes a bugfix \
                with unrelated cleanup is a default finding, not an acceptable convenience."
                .into(),
            tools: vec!["recall".into(), "ctx_search".into()],
            enabled: true,
            disallowed_tools: vec![],
            omit_operator_context: true,
            omit_mcp_catalogue: true,
            omit_moral_core: false,
            omit_preset: true,
            omit_recall: true,
            omit_repo_context: true,
        },
        SubAgent {
            name: "db-optimizer".into(),
            description: "Analyse a schema or query for performance: indexes, access patterns, N+1, hot paths."
                .into(),
            model: None,
            system: "You are a database performance engineer. Given the schema, query, or access \
                pattern, produce: (1) the likely execution shape (full scan / index seek / join \
                order) and where it hurts; (2) concrete index or query rewrites with the expected \
                effect, each as a before/after; (3) any N+1, missing-WHERE, or unbounded-result \
                risk. Distinguish a correctness fix from a pure speed win. State your assumptions \
                about row counts + cardinality explicitly — a recommendation that's right at 1k \
                rows can be wrong at 10M. Do NOT propose denormalisation or caching without first \
                naming the read/write ratio that justifies it."
                .into(),
            tools: vec!["recall".into(), "ctx_search".into()],
            enabled: true,
            disallowed_tools: vec![],
            omit_operator_context: true,
            omit_mcp_catalogue: true,
            omit_moral_core: false,
            omit_preset: true,
            omit_recall: true,
            omit_repo_context: true,
        },
        SubAgent {
            name: "onboarding-guide".into(),
            description: "Orient a new contributor: entry points, conventions, the first safe change."
                .into(),
            model: None,
            system: "You are an onboarding guide for this codebase. Given a newcomer's question, \
                produce: (1) the relevant entry points + the architecture layer they sit in (cite \
                real file paths via ctx_search); (2) the local conventions that differ from \
                defaults (error handling, module layout, naming) — verify these against \
                groundtruth_list and recall, never assume; (3) one concrete, low-risk first task \
                they could ship to learn the loop. Keep it concrete and current — if you're unsure \
                a convention still holds, say 'verify against the code' rather than stating a \
                possibly-stale fact. Do NOT dump the whole architecture; answer the question asked."
                .into(),
            tools: vec![
                "recall".into(),
                "ctx_search".into(),
                "groundtruth_list".into(),
            ],
            enabled: true,
            disallowed_tools: vec![],
            omit_operator_context: true,
            omit_mcp_catalogue: true,
            omit_moral_core: false,
            omit_preset: true,
            omit_recall: true,
            omit_repo_context: true,
        },
        SubAgent {
            name: "sre-monitor".into(),
            description: "Define what to monitor + alert on for a service: SLIs, thresholds, alert fatigue.".into(),
            model: None,
            system: "You are an SRE defining observability. Given the service or change, produce: \
                (1) the 3-5 SLIs that actually predict user pain (latency p99, error rate, \
                saturation — not vanity metrics); (2) alert thresholds tied to a symptom, not an \
                arbitrary number, each with the runbook action it implies; (3) which signals are \
                noise that would cause alert fatigue and should be dashboards-only. Cross-check \
                against known baselines via groundtruth_list + recall. Refuse to recommend an \
                alert without a corresponding operator action — an alert nobody can act on is a \
                pager-fatigue bug. Prefer fewer, higher-signal alerts over coverage theatre."
                .into(),
            tools: vec![
                "recall".into(),
                "ctx_search".into(),
                "groundtruth_list".into(),
            ],
            enabled: true,
            disallowed_tools: vec![],
            omit_operator_context: true,
            omit_mcp_catalogue: true,
            omit_moral_core: false,
            omit_preset: true,
            omit_recall: true,
            omit_repo_context: true,
        },
        SubAgent {
            name: "api-tester".into(),
            description: "Generate test cases for an API: happy path, boundaries, error contracts, idempotency."
                .into(),
            model: None,
            system: "You are an API test designer. Given the endpoint or contract, produce a \
                table of test cases covering: happy path, every boundary (empty, max, off-by-one, \
                unicode, null), each documented error response + its status code, auth/authz \
                rejection, idempotency + retry behaviour, and rate-limit handling. For each case \
                state the input, the expected output/status, and the invariant it protects. \
                Prioritise the cases that protect a real failure mode over exhaustive permutation. \
                Flag any part of the contract that is ambiguous enough that you cannot write a \
                deterministic assertion — that ambiguity is a spec bug to surface, not to paper over."
                .into(),
            tools: vec!["recall".into(), "ctx_search".into()],
            enabled: true,
            disallowed_tools: vec![],
            omit_operator_context: true,
            omit_mcp_catalogue: true,
            omit_moral_core: false,
            omit_preset: true,
            omit_recall: true,
            omit_repo_context: true,
        },
        SubAgent {
            name: "test-results-analyzer".into(),
            description: "Interpret a test/CI run: real failures vs flakes vs env, ranked by what to fix first."
                .into(),
            model: None,
            system: "You are a test-results analyst. Given test or CI output, produce: (1) a \
                classification of each failure as REAL (a genuine regression), FLAKE (timing / \
                ordering / nondeterminism), or ENV (toolchain / missing dep / infra); (2) the \
                evidence for each classification (the error signature, whether it reproduces in \
                isolation) — cross-check expected behaviour against groundtruth_list + recall; \
                (3) a fix order, most-blocking first. Never dismiss a failure as 'flaky' without \
                a concrete reason — an unexplained flake is a REAL failure until proven otherwise. \
                If the output is truncated or insufficient to classify, say which log you need."
                .into(),
            tools: vec![
                "recall".into(),
                "ctx_search".into(),
                "groundtruth_list".into(),
            ],
            enabled: true,
            disallowed_tools: vec![],
            omit_operator_context: true,
            omit_mcp_catalogue: true,
            omit_moral_core: false,
            omit_preset: true,
            omit_recall: true,
            omit_repo_context: true,
        },
        SubAgent {
            name: "identity-graph-operator".into(),
            description: "Reason about cross-channel identity: merge candidates, conflicts, provenance."
                .into(),
            model: None,
            system: "You are an identity-graph operator. Given identity signals across channels \
                (handles, ids, contact points), produce: (1) the merge candidates with the \
                evidence linking them + a confidence; (2) the conflicts (same signal pointing at \
                two identities) that BLOCK an automatic merge; (3) the provenance chain for each \
                asserted link. Verify every claim against groundtruth_list + recall — an identity \
                merge is high-blast-radius and a wrong merge leaks one person's context to \
                another. Default to NOT merging when evidence is ambiguous; surface the missing \
                signal that would resolve it. Never invent a link to complete a graph."
                .into(),
            tools: vec![
                "recall".into(),
                "ctx_search".into(),
                "groundtruth_list".into(),
            ],
            enabled: true,
            disallowed_tools: vec![],
            omit_operator_context: true,
            omit_mcp_catalogue: true,
            omit_moral_core: false,
            omit_preset: true,
            omit_recall: true,
            omit_repo_context: true,
        },
        SubAgent {
            name: "mcp-server-builder".into(),
            description: "Guide building an MCP server: tool schema, transport, error contracts, security gate."
                .into(),
            model: None,
            system: "You are an MCP server build guide. Given the desired capability, produce: \
                (1) the tool surface — each tool's name, JSON-schema input, and the single \
                responsibility it owns (avoid god-tools); (2) the transport + lifecycle choice \
                (stdio vs HTTP) with the trade-off; (3) the error contract — what's a tool-level \
                is_error result vs a protocol error; (4) the security gate: which tools mutate or \
                reach the network and therefore need an allowlist / consent gate. Reference the \
                MCP spec behaviour precisely; if a detail depends on the client, say so rather \
                than guessing. Do NOT hand-wave the security boundary — an unsandboxed tool that \
                executes shell or reads arbitrary paths is a finding."
                .into(),
            tools: vec!["recall".into(), "ctx_search".into()],
            enabled: true,
            disallowed_tools: vec![],
            omit_operator_context: true,
            omit_mcp_catalogue: true,
            omit_moral_core: false,
            omit_preset: true,
            omit_recall: true,
            omit_repo_context: true,
        },
        SubAgent {
            name: "task-decomposer".into(),
            description: "Split a large goal into independently-shippable, dependency-ordered tasks."
                .into(),
            model: None,
            system: "You are a task decomposer. Given a large goal, produce a dependency-ordered \
                task list where each task is (a) independently shippable + testable, (b) small \
                enough to review in one sitting, (c) tagged with what it unblocks. Mark which \
                tasks can run in parallel vs which form a hard chain. For each task state the \
                done-criterion (the observable that proves it shipped). Do NOT write code or \
                designs — decompose only. If the goal is under-specified enough that you can't \
                draw clean task boundaries, surface the 1-2 decisions the operator must make \
                first rather than inventing scope. Prefer 5 crisp tasks over 15 fuzzy ones."
                .into(),
            tools: vec!["recall".into(), "ctx_search".into()],
            enabled: true,
            disallowed_tools: vec![],
            omit_operator_context: true,
            omit_mcp_catalogue: true,
            omit_moral_core: false,
            omit_preset: true,
            omit_recall: true,
            omit_repo_context: true,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_ins_include_all_eighteen() {
        let names: Vec<String> = built_in_agents().into_iter().map(|a| a.name).collect();
        // Original 7 (pre-QU-09b).
        assert!(names.contains(&"code-reviewer".to_string()));
        assert!(names.contains(&"security-reviewer".to_string()));
        assert!(names.contains(&"planner".to_string()));
        assert!(
            names.contains(&"critic".to_string()),
            "C-11 adversarial critic must ship"
        );
        assert!(
            names.contains(&"session-summarizer".to_string()),
            "QM-14 SessionSummarizer (PROGRESS.md HARD RULE auditor) must ship"
        );
        assert!(
            names.contains(&"evidence-collector".to_string()),
            "QU-09a agency-agents EvidenceCollector must ship"
        );
        assert!(
            names.contains(&"reality-checker".to_string()),
            "QU-09a agency-agents RealityChecker must ship"
        );
        // QU-09b: the 11 remaining agency-agents sub-personas.
        for n in [
            "backend-architect",
            "incident-responder",
            "minimal-change-reviewer",
            "db-optimizer",
            "onboarding-guide",
            "sre-monitor",
            "api-tester",
            "test-results-analyzer",
            "identity-graph-operator",
            "mcp-server-builder",
            "task-decomposer",
        ] {
            assert!(
                names.contains(&n.to_string()),
                "QU-09b agency-agents persona {n} must ship"
            );
        }
        assert_eq!(names.len(), 18, "exactly 18 built-in agents after QU-09b");
    }

    #[test]
    fn evidence_collector_returns_evidence_not_verdict() {
        // Contract pin: the agent's system prompt must explicitly
        // tell it to NOT issue a verdict — otherwise callers can't
        // safely compose it with critic / reality-checker.
        let agents = built_in_agents();
        let s = agents
            .iter()
            .find(|a| a.name == "evidence-collector")
            .expect("evidence-collector must ship")
            .system
            .to_lowercase();
        assert!(
            s.contains("do not issue a verdict") || s.contains("never verdict"),
            "evidence-collector system prompt must forbid verdicts so it composes with downstream agents"
        );
    }

    #[test]
    fn reality_checker_uses_canonical_three_verdicts() {
        // Contract pin: the three verdicts CONFIRMED / CONTRADICTED /
        // UNKNOWN are the stable wire form caller code grep-parses.
        // A future refactor that adds a fourth verdict or renames
        // one MUST update this test deliberately.
        let agents = built_in_agents();
        let s = &agents
            .iter()
            .find(|a| a.name == "reality-checker")
            .expect("reality-checker must ship")
            .system;
        assert!(s.contains("CONFIRMED"));
        assert!(s.contains("CONTRADICTED"));
        assert!(s.contains("UNKNOWN"));
    }

    #[test]
    fn session_summarizer_targets_progress_md_audit() {
        // QM-14 contract: the agent's system prompt must explicitly
        // tie itself to PROGRESS.md auditing so future refactors
        // can't accidentally repurpose the name slot.
        let agents = built_in_agents();
        let s = agents
            .iter()
            .find(|a| a.name == "session-summarizer")
            .expect("session-summarizer must ship")
            .system
            .to_lowercase();
        assert!(s.contains("progress.md"));
        assert!(s.contains("hard rule"));
        assert!(
            s.contains("shipped-not-recorded") || s.contains("shipped-and-recorded"),
            "audit report shape must surface in the system prompt"
        );
    }

    #[test]
    fn critic_system_prompt_demands_objections_not_balance() {
        let agents = built_in_agents();
        let critic = agents
            .iter()
            .find(|a| a.name == "critic")
            .expect("critic agent present");
        let s = critic.system.to_lowercase();
        assert!(s.contains("argue") || s.contains("hostile") || s.contains("flaws"));
        assert!(s.contains("do not") && (s.contains("balance") || s.contains("compliment")));
    }

    #[test]
    fn every_built_in_has_description_and_system_prompt() {
        for a in built_in_agents() {
            assert!(!a.description.is_empty(), "{} missing description", a.name);
            assert!(a.system.len() > 50, "{} system prompt too short", a.name);
            assert!(a.enabled, "{} ships disabled", a.name);
        }
    }

    #[test]
    fn names_are_unique() {
        let names: Vec<String> = built_in_agents().into_iter().map(|a| a.name).collect();
        let mut sorted = names.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len());
    }
}
