//! Skill-testing harness — ported from obra/superpowers Item #3.
//!
//! Implements the RED / GREEN / REFACTOR cycle for skill authoring:
//!
//!   - **RED.** Run the agent against the scenario prompt **without** the
//!     skill loaded. The reply should exhibit the violation the skill is
//!     designed to prevent.
//!   - **GREEN.** Run the same prompt again, this time prepending the
//!     skill's `system_prompt`. The reply should NOT exhibit the violation
//!     and SHOULD contain the compliance marker if the scenario defines
//!     one.
//!   - **REFACTOR.** Operator iterates on the skill's prompt until both
//!     RED + GREEN expectations hold.
//!
//! A scenario is YAML: `~/.neoth/skills/<id>/tests/<name>.yaml`. Multiple
//! scenarios per skill — each one targets a different failure mode.
//!
//! v0.1 ships the module + types + dispatcher; CLI subcommand
//! `neoth skills test <skill_id>` wires in as the next follow-up.

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::providers::{Provider, Request};
use crate::skills::schema::Skill;

/// One operator-authored test scenario for a skill.
///
/// At least one of `expect_violation_substring` / `forbid_violation_substring`
/// must be set so RED has something to assert against. Same for GREEN —
/// at least one of `require_compliance_substring` / `forbid_violation_substring`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct TestScenario {
    /// Stable identifier used in CLI output + WAL audit.
    pub id: String,
    /// The prompt to send to the provider. Should NOT contain the skill's
    /// own system prompt — the harness handles that.
    pub prompt: String,
    /// RED-path assertion: substring the no-skill reply MUST contain to
    /// prove the skill is needed. `None` skips the RED-violation check.
    #[serde(default)]
    pub expect_violation_substring: Option<String>,
    /// GREEN-path assertion: substring the with-skill reply MUST contain
    /// to prove the skill produced the intended behaviour. `None` skips.
    #[serde(default)]
    pub require_compliance_substring: Option<String>,
    /// Anti-pattern: substring that MUST NOT appear in either reply when
    /// the skill is active. Use for "do not invent facts", "do not omit
    /// caveats", etc. Empty by default.
    #[serde(default)]
    pub forbid_substring: Option<String>,
}

impl TestScenario {
    /// Load a scenario from disk. Errors on parse failure.
    pub fn load(path: &Path) -> Result<Self> {
        let body = std::fs::read_to_string(path)
            .with_context(|| format!("read scenario {}", path.display()))?;
        let scen: TestScenario = serde_yaml::from_str(&body)
            .with_context(|| format!("parse scenario YAML {}", path.display()))?;
        Ok(scen)
    }
}

/// Outcome of one scenario run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScenarioOutcome {
    pub scenario_id: String,
    /// True if the RED run produced a violation per the scenario's rule.
    /// `None` when no RED assertion was configured.
    pub red_violated: Option<bool>,
    /// True if the GREEN run satisfied the compliance rule.
    pub green_complied: Option<bool>,
    /// True if the forbid rule was respected in both runs.
    pub forbid_respected: Option<bool>,
    /// Raw reply texts (kept for diagnosis output).
    pub red_response: String,
    pub green_response: String,
}

impl ScenarioOutcome {
    /// Aggregate pass/fail. All configured assertions must hold; unset
    /// assertions are ignored. Returns false if anything fails.
    pub fn passed(&self) -> bool {
        let red = self.red_violated.unwrap_or(true); // RED unset = no requirement
        let green = self.green_complied.unwrap_or(true);
        let forbid = self.forbid_respected.unwrap_or(true);
        red && green && forbid
    }
}

/// Run one scenario against a provider, comparing skill-on vs skill-off
/// behaviour.
pub async fn run_scenario(
    provider: &dyn Provider,
    skill: &Skill,
    scenario: &TestScenario,
) -> Result<ScenarioOutcome> {
    // RED: no skill system prompt — bare provider call.
    let red_req = Request {
        prompt: scenario.prompt.clone(),
        system: None,
        model: None,
        ..Default::default()
    };
    let red = provider.complete(red_req).await?;

    // GREEN: skill's system_prompt becomes the system.
    let green_req = Request {
        prompt: scenario.prompt.clone(),
        system: Some(skill.system_prompt().to_string()),
        model: None,
        ..Default::default()
    };
    let green = provider.complete(green_req).await?;

    let red_violated = scenario
        .expect_violation_substring
        .as_ref()
        .map(|needle| red.text.contains(needle));
    let green_complied = scenario
        .require_compliance_substring
        .as_ref()
        .map(|needle| green.text.contains(needle));
    let forbid_respected = scenario
        .forbid_substring
        .as_ref()
        .map(|needle| !red.text.contains(needle) && !green.text.contains(needle));

    Ok(ScenarioOutcome {
        scenario_id: scenario.id.clone(),
        red_violated,
        green_complied,
        forbid_respected,
        red_response: red.text,
        green_response: green.text,
    })
}

/// Run every scenario under `<skill_dir>/tests/*.yaml`. Returns one
/// outcome per scenario file. Missing tests dir → empty vec, not an
/// error — operators may run `neoth skills test` before writing any
/// scenarios.
pub async fn run_all_scenarios_for(
    provider: &dyn Provider,
    skill: &Skill,
) -> Result<Vec<ScenarioOutcome>> {
    let mut tests_dir = skill.path.clone();
    tests_dir.pop(); // strip "skill.yaml"
    let tests_dir = tests_dir.join("tests");
    if !tests_dir.exists() {
        return Ok(vec![]);
    }
    let mut outcomes = Vec::new();
    let entries = std::fs::read_dir(&tests_dir)
        .with_context(|| format!("read tests dir {}", tests_dir.display()))?;
    let mut paths: Vec<_> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.extension()
                    .and_then(|s| s.to_str())
                    .map(|s| s == "yaml" || s == "yml")
                    .unwrap_or(false)
        })
        .collect();
    paths.sort();
    for p in paths {
        let scenario = TestScenario::load(&p)?;
        let outcome = run_scenario(provider, skill, &scenario).await?;
        outcomes.push(outcome);
    }
    Ok(outcomes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::Completion;
    use crate::skills::schema::{Skill, SkillManifest};
    use async_trait::async_trait;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn fixture_skill(system: &str) -> Skill {
        Skill {
            manifest: SkillManifest {
                id: "test-skill".into(),
                description: "test".into(),
                version: "1.0.0".into(),
                trigger_keywords: vec![],
                system_prompt: system.into(),
                tool_allowlist: vec![],
                author: None,
                tags: vec![],
                homepage: None,
                source: None,
                modes: vec![],
                enabled: true,
            },
            path: PathBuf::from("/tmp/test-skill/skill.yaml"),
        }
    }

    /// Provider that returns different canned replies depending on whether
    /// the request carries a `system` prompt. RED (no system) → red_reply;
    /// GREEN (with system) → green_reply. Mirrors the harness's two paths.
    struct ScriptedProvider {
        red_reply: String,
        green_reply: String,
    }

    #[async_trait]
    impl Provider for ScriptedProvider {
        fn name(&self) -> &'static str {
            "scripted"
        }
        async fn complete(&self, req: Request) -> Result<Completion> {
            let text = if req.system.is_some() {
                self.green_reply.clone()
            } else {
                self.red_reply.clone()
            };
            Ok(Completion {
                text,
                model: "scripted".into(),
                latency: std::time::Duration::from_millis(1),
                input_tokens: Some(1),
                output_tokens: Some(1),
            })
        }
    }

    #[tokio::test]
    async fn red_violates_green_complies_full_pass() {
        let skill = fixture_skill("Always include a VERIFICATION line.");
        let scenario = TestScenario {
            id: "verify".into(),
            prompt: "Tell me the test status".into(),
            expect_violation_substring: Some("should be fine".into()),
            require_compliance_substring: Some("VERIFICATION".into()),
            forbid_substring: None,
        };
        let provider = ScriptedProvider {
            red_reply: "It should be fine.".into(),
            green_reply: "Test status: VERIFICATION via cargo test passed.".into(),
        };
        let outcome = run_scenario(&provider, &skill, &scenario).await.unwrap();
        assert_eq!(outcome.red_violated, Some(true));
        assert_eq!(outcome.green_complied, Some(true));
        assert!(outcome.passed(), "all configured assertions must hold");
    }

    #[tokio::test]
    async fn red_does_not_violate_marks_fail() {
        let skill = fixture_skill("Always verify");
        let scenario = TestScenario {
            id: "verify".into(),
            prompt: "Status".into(),
            expect_violation_substring: Some("MISSING".into()),
            require_compliance_substring: None,
            forbid_substring: None,
        };
        // Both replies omit MISSING → RED expectation unmet → fail.
        let provider = ScriptedProvider {
            red_reply: "all good".into(),
            green_reply: "all good".into(),
        };
        let outcome = run_scenario(&provider, &skill, &scenario).await.unwrap();
        assert_eq!(outcome.red_violated, Some(false));
        assert!(!outcome.passed());
    }

    #[tokio::test]
    async fn green_does_not_comply_marks_fail() {
        let skill = fixture_skill("Be precise");
        let scenario = TestScenario {
            id: "precise".into(),
            prompt: "respond".into(),
            expect_violation_substring: None,
            require_compliance_substring: Some("PRECISE".into()),
            forbid_substring: None,
        };
        let provider = ScriptedProvider {
            red_reply: "ok".into(),
            green_reply: "still ok".into(),
        };
        let outcome = run_scenario(&provider, &skill, &scenario).await.unwrap();
        assert_eq!(outcome.green_complied, Some(false));
        assert!(!outcome.passed());
    }

    #[tokio::test]
    async fn forbid_substring_fails_when_present_in_green() {
        let skill = fixture_skill("Don't speculate");
        let scenario = TestScenario {
            id: "no-speculation".into(),
            prompt: "x".into(),
            expect_violation_substring: None,
            require_compliance_substring: None,
            forbid_substring: Some("probably".into()),
        };
        let provider = ScriptedProvider {
            red_reply: "no speculation here".into(),
            green_reply: "this is probably true".into(),
        };
        let outcome = run_scenario(&provider, &skill, &scenario).await.unwrap();
        assert_eq!(outcome.forbid_respected, Some(false));
        assert!(!outcome.passed());
    }

    #[tokio::test]
    async fn scenario_with_no_assertions_is_a_smoke_test() {
        let skill = fixture_skill("anything");
        let scenario = TestScenario {
            id: "smoke".into(),
            prompt: "hi".into(),
            expect_violation_substring: None,
            require_compliance_substring: None,
            forbid_substring: None,
        };
        let provider = ScriptedProvider {
            red_reply: "hi".into(),
            green_reply: "hi".into(),
        };
        let outcome = run_scenario(&provider, &skill, &scenario).await.unwrap();
        assert!(outcome.passed(), "no assertions = pass by default");
    }

    #[test]
    fn load_scenario_round_trips_through_yaml() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("s.yaml");
        let body = "id: verify\nprompt: \"Test\"\nexpect_violation_substring: \"should\"\nrequire_compliance_substring: \"VERIFY\"\n";
        std::fs::write(&path, body).unwrap();
        let s = TestScenario::load(&path).unwrap();
        assert_eq!(s.id, "verify");
        assert_eq!(s.prompt, "Test");
        assert_eq!(s.expect_violation_substring.as_deref(), Some("should"));
        assert_eq!(s.require_compliance_substring.as_deref(), Some("VERIFY"));
        assert!(s.forbid_substring.is_none());
    }

    #[tokio::test]
    async fn run_all_scenarios_for_returns_empty_when_no_tests_dir() {
        let dir = tempdir().unwrap();
        let skill_path = dir.path().join("skill.yaml");
        std::fs::write(&skill_path, "id: x\n").unwrap();
        let mut skill = fixture_skill("x");
        skill.path = skill_path;
        let provider = ScriptedProvider {
            red_reply: "x".into(),
            green_reply: "x".into(),
        };
        let outcomes = run_all_scenarios_for(&provider, &skill).await.unwrap();
        assert!(outcomes.is_empty());
    }

    #[tokio::test]
    async fn run_all_scenarios_loads_yaml_files_in_sorted_order() {
        let dir = tempdir().unwrap();
        let skill_path = dir.path().join("skill.yaml");
        std::fs::write(&skill_path, "id: x\n").unwrap();
        let tests_dir = dir.path().join("tests");
        std::fs::create_dir_all(&tests_dir).unwrap();
        std::fs::write(
            tests_dir.join("a.yaml"),
            "id: a\nprompt: \"p\"\nrequire_compliance_substring: \"OK\"\n",
        )
        .unwrap();
        std::fs::write(
            tests_dir.join("b.yaml"),
            "id: b\nprompt: \"q\"\nrequire_compliance_substring: \"OK\"\n",
        )
        .unwrap();
        std::fs::write(tests_dir.join("ignore.txt"), "skip me").unwrap();

        let mut skill = fixture_skill("y");
        skill.path = skill_path;
        let provider = ScriptedProvider {
            red_reply: "x".into(),
            green_reply: "OK from green".into(),
        };
        let outcomes = run_all_scenarios_for(&provider, &skill).await.unwrap();
        assert_eq!(outcomes.len(), 2);
        assert_eq!(outcomes[0].scenario_id, "a");
        assert_eq!(outcomes[1].scenario_id, "b");
        assert!(outcomes.iter().all(|o| o.passed()));
    }
}
