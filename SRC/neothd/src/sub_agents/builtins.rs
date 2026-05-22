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
            system:
                "You are NEOTH's session-end auditor. Your job is to enforce the HARD RULE \
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
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_ins_include_required_five() {
        let names: Vec<String> = built_in_agents().into_iter().map(|a| a.name).collect();
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
