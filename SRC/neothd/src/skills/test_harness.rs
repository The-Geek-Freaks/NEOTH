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

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::providers::{Provider, Request};
use crate::skills::schema::Skill;
use crate::skills::store::{
    cap_metadata_is_link_like, open_bound_directory, open_real_child_dir, read_regular_file_bounded,
};

const MAX_SKILL_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_SCENARIO_FILES: usize = 128;
const MAX_TEST_DIRECTORY_ENTRIES: usize = 256;
const MAX_SCENARIO_FILE_BYTES: usize = 256 * 1024;
const MAX_SCENARIO_TOTAL_BYTES: usize = 2 * 1024 * 1024;
// The contract is intentionally flat: `<skill>/tests/<scenario>.yaml`.
// Rejecting nested directories makes the traversal depth exactly one.
const MAX_SCENARIO_DEPTH: usize = 1;
const MAX_TEST_DISCOVERY_WORK: usize = 1 + MAX_TEST_DIRECTORY_ENTRIES + MAX_SCENARIO_FILES;

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
    /// Load one direct scenario file through a no-follow directory capability.
    /// Errors on linked/special files, size overflow, invalid UTF-8, or YAML.
    pub fn load(path: &Path) -> Result<Self> {
        let parent_path = path
            .parent()
            .context("scenario path has no parent directory")?;
        let name = path.file_name().context("scenario path has no file name")?;
        let parent = open_bound_directory(parent_path, false, "skill scenario directory")?
            .with_context(|| {
                format!("scenario directory disappeared: {}", parent_path.display())
            })?;
        let raw = read_regular_file_bounded(&parent.dir, name, path, MAX_SCENARIO_FILE_BYTES)?;
        parse_scenario_yaml(&raw, path)
    }
}

fn parse_scenario_yaml(raw: &[u8], display_path: &Path) -> Result<TestScenario> {
    let body = std::str::from_utf8(raw)
        .with_context(|| format!("scenario is not UTF-8: {}", display_path.display()))?;
    serde_yaml::from_str(body)
        .with_context(|| format!("parse scenario YAML {}", display_path.display()))
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
    let scenarios = load_all_scenarios(skill)?;
    let mut outcomes = Vec::with_capacity(scenarios.len());
    for scenario in scenarios {
        let outcome = run_scenario(provider, skill, &scenario).await?;
        outcomes.push(outcome);
    }
    Ok(outcomes)
}

/// Load and validate the complete scenario set before the first provider call.
/// No traversal or parse error can therefore produce a partial paid run.
fn load_all_scenarios(skill: &Skill) -> Result<Vec<TestScenario>> {
    if skill.path.starts_with(Path::new("<bundled>")) {
        return Ok(Vec::new());
    }
    if skill.path.file_name() != Some(OsStr::new("skill.yaml")) {
        anyhow::bail!(
            "skill test path must end in skill.yaml: {}",
            skill.path.display()
        );
    }

    let skill_dir_path = skill
        .path
        .parent()
        .context("skill manifest path has no parent directory")?;
    let skill_dir =
        open_bound_directory(skill_dir_path, false, "skill test root")?.with_context(|| {
            format!(
                "loaded skill directory disappeared: {}",
                skill_dir_path.display()
            )
        })?;

    // Bind the opened namespace generation to the exact Skill that was loaded.
    // A directory swap or manifest edit after load fails before any provider call.
    let manifest_raw = read_regular_file_bounded(
        &skill_dir.dir,
        OsStr::new("skill.yaml"),
        &skill.path,
        MAX_SKILL_MANIFEST_BYTES,
    )?;
    let manifest_yaml = std::str::from_utf8(&manifest_raw)
        .with_context(|| format!("skill manifest is not UTF-8: {}", skill.path.display()))?;
    if !skill.content_hash.is_empty() {
        let observed_hash =
            crate::skills::versioning::skill_content_hash_hex(manifest_yaml, skill.system_prompt());
        if observed_hash != skill.content_hash {
            anyhow::bail!(
                "loaded skill namespace changed before test discovery at {}",
                skill.path.display()
            );
        }
    }

    let tests_display = skill_dir_path.join("tests");
    let tests_dir = match open_real_child_dir(&skill_dir.dir, OsStr::new("tests"), &tests_display) {
        Ok(directory) => directory,
        Err(error) if error_is_not_found(&error) => return Ok(Vec::new()),
        Err(error) => return Err(error).context("open skill tests directory"),
    };

    let mut entry_count = 0usize;
    let mut scenario_count = 0usize;
    let mut total_bytes = 0usize;
    let mut work = 1usize; // opening/enumerating the direct tests directory
    let mut scenario_files: Vec<(OsString, PathBuf)> = Vec::new();
    let entries = tests_dir.entries().with_context(|| {
        format!(
            "enumerate skill tests directory {}",
            tests_display.display()
        )
    })?;
    for entry in entries {
        entry_count = entry_count
            .checked_add(1)
            .context("skill test directory entry count overflow")?;
        if entry_count > MAX_TEST_DIRECTORY_ENTRIES {
            anyhow::bail!(
                "skill test directory exceeds the {MAX_TEST_DIRECTORY_ENTRIES}-entry limit at {}",
                tests_display.display()
            );
        }
        work = charge_discovery_work(work, &tests_display)?;
        let entry = entry
            .with_context(|| format!("read skill tests directory {}", tests_display.display()))?;
        let name = entry.file_name();
        let display_path = tests_display.join(&name);
        let metadata = tests_dir
            .symlink_metadata(&name)
            .with_context(|| format!("inspect skill test entry {}", display_path.display()))?;
        if cap_metadata_is_link_like(&metadata) {
            anyhow::bail!(
                "skill test entry must not be a symlink or reparse point: {}",
                display_path.display()
            );
        }
        if !metadata.is_file() {
            anyhow::bail!(
                "skill test directory depth exceeds {MAX_SCENARIO_DEPTH} or contains a special entry: {}",
                display_path.display()
            );
        }

        let is_scenario = Path::new(&name)
            .extension()
            .and_then(OsStr::to_str)
            .map(|extension| extension == "yaml" || extension == "yml")
            .unwrap_or(false);
        if !is_scenario {
            continue;
        }
        scenario_count = scenario_count
            .checked_add(1)
            .context("skill scenario count overflow")?;
        if scenario_count > MAX_SCENARIO_FILES {
            anyhow::bail!(
                "skill test suite exceeds the {MAX_SCENARIO_FILES}-scenario limit at {}",
                tests_display.display()
            );
        }
        scenario_files.push((name, display_path));
    }

    scenario_files.sort_by(|left, right| left.0.cmp(&right.0));
    let mut scenarios = Vec::with_capacity(scenario_files.len());
    for (name, display_path) in scenario_files {
        work = charge_discovery_work(work, &display_path)?;
        let raw =
            read_regular_file_bounded(&tests_dir, &name, &display_path, MAX_SCENARIO_FILE_BYTES)?;
        total_bytes = total_bytes
            .checked_add(raw.len())
            .context("skill scenario aggregate byte count overflow")?;
        if total_bytes > MAX_SCENARIO_TOTAL_BYTES {
            anyhow::bail!(
                "skill test suite exceeds the {MAX_SCENARIO_TOTAL_BYTES}-byte aggregate limit at {}",
                display_path.display()
            );
        }
        scenarios.push(parse_scenario_yaml(&raw, &display_path)?);
    }
    Ok(scenarios)
}

fn charge_discovery_work(current: usize, display_path: &Path) -> Result<usize> {
    let next = current
        .checked_add(1)
        .context("skill test discovery work counter overflow")?;
    if next > MAX_TEST_DISCOVERY_WORK {
        anyhow::bail!(
            "skill test discovery exceeds the {MAX_TEST_DISCOVERY_WORK}-unit work limit at {}",
            display_path.display()
        );
    }
    Ok(next)
}

fn error_is_not_found(error: &anyhow::Error) -> bool {
    error.chain().any(|source| {
        source
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io_error| io_error.kind() == std::io::ErrorKind::NotFound)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::Completion;
    use crate::skills::schema::{Skill, SkillManifest};
    use async_trait::async_trait;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
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
                delegate_to: None,
                model: None,
                paths: vec![],
                effort: None,
                loop_trigger: false,
                visibility: Default::default(),
            },
            path: PathBuf::from("/tmp/test-skill/skill.yaml"),
            content_hash: String::new(),
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
                identity: Default::default(),
                model: "scripted".into(),
                latency: std::time::Duration::from_millis(1),
                input_tokens: Some(1),
                output_tokens: Some(1),
                cache_creation_tokens: None,
                cache_read_tokens: None,
            })
        }
    }

    struct CountingProvider {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl Provider for CountingProvider {
        fn name(&self) -> &'static str {
            "counting"
        }

        async fn complete(&self, _req: Request) -> Result<Completion> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Completion {
                text: "unexpected provider call".into(),
                identity: Default::default(),
                model: "counting".into(),
                latency: std::time::Duration::from_millis(1),
                input_tokens: Some(1),
                output_tokens: Some(1),
                cache_creation_tokens: None,
                cache_read_tokens: None,
            })
        }
    }

    fn skill_at(path: PathBuf, system_prompt: &str) -> Skill {
        let mut skill = fixture_skill(system_prompt);
        skill.path = path;
        skill
    }

    fn counting_provider() -> (CountingProvider, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        (
            CountingProvider {
                calls: Arc::clone(&calls),
            },
            calls,
        )
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

    #[tokio::test]
    async fn oversized_scenario_aborts_before_provider_dispatch() {
        let dir = tempdir().unwrap();
        let skill_path = dir.path().join("skill.yaml");
        std::fs::write(&skill_path, "id: test-skill\n").unwrap();
        let tests_dir = dir.path().join("tests");
        std::fs::create_dir(&tests_dir).unwrap();
        std::fs::write(
            tests_dir.join("oversized.yaml"),
            vec![b'x'; MAX_SCENARIO_FILE_BYTES + 1],
        )
        .unwrap();
        let skill = skill_at(skill_path, "x");
        let (provider, calls) = counting_provider();

        let error = run_all_scenarios_for(&provider, &skill).await.unwrap_err();

        assert!(format!("{error:#}").contains("exceeds the 262144-byte"));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn too_many_scenarios_abort_before_provider_dispatch() {
        let dir = tempdir().unwrap();
        let skill_path = dir.path().join("skill.yaml");
        std::fs::write(&skill_path, "id: test-skill\n").unwrap();
        let tests_dir = dir.path().join("tests");
        std::fs::create_dir(&tests_dir).unwrap();
        for index in 0..=MAX_SCENARIO_FILES {
            std::fs::write(
                tests_dir.join(format!("scenario-{index:03}.yaml")),
                format!("id: s-{index}\nprompt: p\n"),
            )
            .unwrap();
        }
        let skill = skill_at(skill_path, "x");
        let (provider, calls) = counting_provider();

        let error = run_all_scenarios_for(&provider, &skill).await.unwrap_err();

        assert!(format!("{error:#}").contains("exceeds the 128-scenario limit"));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn aggregate_scenario_bytes_abort_before_provider_dispatch() {
        let dir = tempdir().unwrap();
        let skill_path = dir.path().join("skill.yaml");
        std::fs::write(&skill_path, "id: test-skill\n").unwrap();
        let tests_dir = dir.path().join("tests");
        std::fs::create_dir(&tests_dir).unwrap();
        let prompt = "x".repeat(240 * 1024);
        for index in 0..9 {
            std::fs::write(
                tests_dir.join(format!("scenario-{index}.yaml")),
                format!("id: s-{index}\nprompt: {prompt}\n"),
            )
            .unwrap();
        }
        let skill = skill_at(skill_path, "x");
        let (provider, calls) = counting_provider();

        let error = run_all_scenarios_for(&provider, &skill).await.unwrap_err();

        assert!(format!("{error:#}").contains("2097152-byte aggregate limit"));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn changed_skill_namespace_aborts_before_provider_dispatch() {
        let dir = tempdir().unwrap();
        let skill_path = dir.path().join("skill.yaml");
        let initial_manifest = "id: test-skill\nsystem_prompt: x\n";
        std::fs::write(&skill_path, initial_manifest).unwrap();
        let tests_dir = dir.path().join("tests");
        std::fs::create_dir(&tests_dir).unwrap();
        std::fs::write(tests_dir.join("scenario.yaml"), "id: s\nprompt: p\n").unwrap();
        let mut skill = skill_at(skill_path, "x");
        skill.content_hash = crate::skills::versioning::skill_content_hash_hex(
            initial_manifest,
            skill.system_prompt(),
        );
        std::fs::write(&skill.path, "id: replacement\nsystem_prompt: x\n").unwrap();
        let (provider, calls) = counting_provider();

        let error = run_all_scenarios_for(&provider, &skill).await.unwrap_err();

        assert!(format!("{error:#}").contains("namespace changed"));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn linked_scenario_aborts_before_provider_dispatch() {
        let dir = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let skill_path = dir.path().join("skill.yaml");
        std::fs::write(&skill_path, "id: test-skill\n").unwrap();
        let tests_dir = dir.path().join("tests");
        std::fs::create_dir(&tests_dir).unwrap();
        let outside_scenario = outside.path().join("outside.yaml");
        std::fs::write(&outside_scenario, "id: outside\nprompt: p\n").unwrap();
        let linked_scenario = tests_dir.join("linked.yaml");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside_scenario, &linked_scenario).unwrap();
        #[cfg(windows)]
        if std::os::windows::fs::symlink_file(&outside_scenario, &linked_scenario).is_err() {
            return;
        }
        let skill = skill_at(skill_path, "x");
        let (provider, calls) = counting_provider();

        let error = run_all_scenarios_for(&provider, &skill).await.unwrap_err();

        assert!(format!("{error:#}").contains("symlink or reparse point"));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(outside_scenario.is_file());
    }
}
