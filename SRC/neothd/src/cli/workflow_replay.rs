//! ADOPT31-D5 — contained, operator-curated workflow replay.
//!
//! This module intentionally has no relationship to the legacy offline
//! `EvalCase` verifier. A corpus contains only an operator-curated prompt and
//! a fixed `contains-v1` expectation; a run enters the current chat preparation
//! and provider path once, under an empty MCP agent scope.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Args;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const CORPUS_KIND: &str = "workflow-replay-corpus-v1";
const REPORT_KIND: &str = "workflow-replay-report-v1";
const SCORER: &str = "contains-v1";
const MAX_EPISODES: usize = 64;
const MAX_FIELD_BYTES: usize = 32 * 1024;
const MAX_CORPUS_BYTES: usize = 2 * 1024 * 1024;

#[derive(Args, Debug, Clone)]
pub struct WorkflowReplayCaptureArgs {
    /// One explicit operator-selected capture input. WAL and history are never read.
    pub input: PathBuf,
    /// New corpus destination. Existing paths are refused.
    #[arg(long)]
    pub out: PathBuf,
}

#[derive(Args, Debug, Clone)]
pub struct WorkflowReplayRunArgs {
    /// Versioned operator-curated workflow replay corpus.
    pub corpus: PathBuf,
    /// Persist reports here. Without it, reports remain in the contained temp root.
    #[arg(long)]
    pub out_dir: Option<PathBuf>,
    /// Print the machine report to stdout as JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaptureInputV1 {
    schema_version: u32,
    episode_id: String,
    prompt: String,
    expected_contains: String,
    #[serde(default)]
    skill: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkflowEpisodeV1 {
    episode_id: String,
    prompt: String,
    expected_contains: String,
    #[serde(default)]
    skill: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusProvenanceV1 {
    label: String,
    input_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkflowCorpusV1 {
    schema_version: u32,
    kind: String,
    provenance: CorpusProvenanceV1,
    episodes: Vec<WorkflowEpisodeV1>,
}

#[derive(Debug, Clone, Serialize)]
struct ReplayConfigProjectionV1 {
    provider: String,
    model: String,
    max_per_request: u32,
    fingerprint_sha256: String,
    effective_public_config_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
struct ReplayContainmentV1 {
    transient_home: bool,
    transient_workspace: bool,
    actual_home_effects: Vec<&'static str>,
    external_tools: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct EpisodeReportV1 {
    episode_id: String,
    outcome: &'static str,
    reason: Option<String>,
    provider: String,
    model: String,
    selected_skill: Option<String>,
    selected_skill_content_sha256: Option<String>,
    response_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct WorkflowReplayReportV1 {
    schema_version: u32,
    kind: &'static str,
    corpus_sha256: String,
    source_revision: String,
    scorer: &'static str,
    config: ReplayConfigProjectionV1,
    containment: ReplayContainmentV1,
    episodes: Vec<EpisodeReportV1>,
    passed: bool,
}

#[derive(Default)]
struct ReplaySink {
    provider_response: String,
    terminal_provider: Option<String>,
    terminal_model: Option<String>,
}

impl crate::cli::chat_turn_pipeline::ChatTurnEventSink for ReplaySink {
    fn emit(&mut self, event: crate::cli::chat_turn_pipeline::ChatTurnEvent) -> Result<()> {
        use crate::cli::chat_turn_pipeline::{ChatOutput, ChatTurnEvent, ChatTurnTerminal};
        match event {
            ChatTurnEvent::Output(ChatOutput::ReplayCompletedBody { text }) => {
                self.provider_response.push_str(&text);
            }
            ChatTurnEvent::Terminal(ChatTurnTerminal::Complete {
                provider, model, ..
            }) => {
                self.terminal_provider = Some(provider);
                self.terminal_model = Some(model);
            }
            _ => {}
        }
        Ok(())
    }
}

impl ReplaySink {
    fn terminal_completed(&self) -> bool {
        self.terminal_provider.is_some() && self.terminal_model.is_some()
    }
}

pub async fn run_capture_cmd(args: WorkflowReplayCaptureArgs) -> Result<()> {
    anyhow::ensure!(
        !args.out.exists(),
        "workflow replay corpus already exists: {}",
        args.out.display()
    );
    let raw = read_bounded(&args.input, "capture input")?;
    let input: CaptureInputV1 = serde_json::from_slice(&raw).with_context(|| {
        format!(
            "parse workflow replay capture input {}",
            args.input.display()
        )
    })?;
    validate_capture(&input)?;
    let corpus = WorkflowCorpusV1 {
        schema_version: 1,
        kind: CORPUS_KIND.to_owned(),
        provenance: CorpusProvenanceV1 {
            label: "operator-curated+inputhash".to_owned(),
            input_sha256: sha256(&raw),
        },
        episodes: vec![WorkflowEpisodeV1 {
            episode_id: input.episode_id,
            prompt: input.prompt,
            expected_contains: input.expected_contains,
            skill: input.skill,
        }],
    };
    write_new_json(&args.out, &corpus)?;
    println!("workflow replay corpus written: {}", args.out.display());
    println!("corpus_sha256: {}", sha256(&std::fs::read(&args.out)?));
    Ok(())
}

pub async fn run_workflow_replay_cmd(args: WorkflowReplayRunArgs) -> Result<()> {
    let raw = read_bounded(&args.corpus, "workflow replay corpus")?;
    let corpus: WorkflowCorpusV1 = serde_json::from_slice(&raw)
        .with_context(|| format!("parse workflow replay corpus {}", args.corpus.display()))?;
    validate_corpus(&corpus)?;

    // Validation ends before consent, provider construction, a transient home,
    // or any provider effect. Invalid corpus data can therefore never egress.
    let config = crate::config::FreedomConfig::load_from_default_path()?;
    let config_path = crate::config::FreedomConfig::default_path();
    let actual_home = config_path
        .parent()
        .map(Path::to_path_buf)
        .context("workflow replay default config has no parent home")?;
    let ephemeral = crate::cli::consent::ensure_all_granted_or_prompt_at(
        &actual_home,
        &config,
        crate::cli::consent::ConsentMutationSource::Tty,
    )
    .await?;
    let provider = crate::providers::fallback_chain_from_config_interactive(
        &config,
        &actual_home,
        None,
        &ephemeral,
    )
    .await?;

    let replay_root = replay_root()?;
    let replay_home = replay_root.join("home");
    let workspace = replay_root.join("workspace");
    std::fs::create_dir_all(&replay_home)?;
    std::fs::create_dir_all(&workspace)?;
    let provider_name = provider.name().to_owned();
    let model = config
        .provider_model
        .clone()
        .unwrap_or_else(|| "provider_default".to_owned());
    let config_projection = ReplayConfigProjectionV1 {
        provider: provider_name.clone(),
        model: model.clone(),
        max_per_request: config.tokens.max_per_request,
        fingerprint_sha256: config_fingerprint(
            &provider_name,
            &model,
            config.tokens.max_per_request,
        ),
        effective_public_config_sha256: public_config_fingerprint(&config)?,
    };

    let mut episodes = Vec::with_capacity(corpus.episodes.len());
    for episode in &corpus.episodes {
        let mut sink = ReplaySink::default();
        let result = crate::cli::chat::run_workflow_replay_turn(
            config.clone(),
            provider.as_ref(),
            replay_home.clone(),
            actual_home.clone(),
            ephemeral.clone(),
            episode.prompt.clone(),
            episode.skill.clone(),
            &mut sink,
        )
        .await;
        let response = sink.provider_response.clone();
        let resolved_provider = sink
            .terminal_provider
            .clone()
            .unwrap_or_else(|| provider_name.clone());
        let resolved_model = sink.terminal_model.clone().unwrap_or_else(|| model.clone());
        let selected_skill = result
            .as_ref()
            .ok()
            .and_then(|observation| observation.selected_skill.as_ref());
        let (outcome, reason) = score_replay_turn(&result, &sink, &episode.expected_contains);
        episodes.push(EpisodeReportV1 {
            episode_id: episode.episode_id.clone(),
            outcome,
            reason,
            provider: resolved_provider,
            model: resolved_model,
            selected_skill: selected_skill.map(|skill| skill.id.clone()),
            selected_skill_content_sha256: selected_skill.map(|skill| skill.content_sha256.clone()),
            response_sha256: (!response.is_empty()).then(|| sha256(response.as_bytes())),
        });
    }
    let passed = episodes.iter().all(|episode| episode.outcome == "pass");
    let report = WorkflowReplayReportV1 {
        schema_version: 1,
        kind: REPORT_KIND,
        corpus_sha256: sha256(&raw),
        source_revision: option_env!("NEOTH_SOURCE_HEAD")
            .or(option_env!("GITHUB_SHA"))
            .or(option_env!("VERGEN_GIT_SHA"))
            .unwrap_or("unknown")
            .to_owned(),
        scorer: SCORER,
        config: config_projection,
        containment: ReplayContainmentV1 {
            transient_home: replay_home.starts_with(&replay_root),
            transient_workspace: workspace.starts_with(&replay_root),
            actual_home_effects: vec!["provider_consent_and_cost_usage_audit"],
            external_tools: "deny_all",
        },
        episodes,
        passed,
    };
    let out_dir = args.out_dir.unwrap_or_else(|| replay_root.join("output"));
    std::fs::create_dir_all(&out_dir)
        .with_context(|| format!("create replay report directory {}", out_dir.display()))?;
    let json = serde_json::to_string_pretty(&report)?;
    std::fs::write(out_dir.join("workflow-replay-report-v1.json"), &json)?;
    std::fs::write(
        out_dir.join("workflow-replay-report-v1.md"),
        render_markdown(&report),
    )?;
    if args.json {
        println!("{json}");
    } else {
        println!("workflow replay report written: {}", out_dir.display());
        println!(
            "workflow replay: {}",
            if report.passed { "PASS" } else { "FAIL" }
        );
    }
    anyhow::ensure!(
        report.passed,
        "workflow replay contains failed or errored episodes"
    );
    Ok(())
}

fn validate_capture(input: &CaptureInputV1) -> Result<()> {
    anyhow::ensure!(
        input.schema_version == 1,
        "unsupported capture schema_version"
    );
    validate_episode(&WorkflowEpisodeV1 {
        episode_id: input.episode_id.clone(),
        prompt: input.prompt.clone(),
        expected_contains: input.expected_contains.clone(),
        skill: input.skill.clone(),
    })
}

fn validate_corpus(corpus: &WorkflowCorpusV1) -> Result<()> {
    anyhow::ensure!(
        corpus.schema_version == 1 && corpus.kind == CORPUS_KIND,
        "unsupported workflow replay corpus schema"
    );
    anyhow::ensure!(
        corpus.provenance.label == "operator-curated+inputhash",
        "workflow replay corpus has invalid provenance label"
    );
    anyhow::ensure!(
        valid_sha256(&corpus.provenance.input_sha256),
        "workflow replay corpus has invalid input hash"
    );
    anyhow::ensure!(
        !corpus.episodes.is_empty() && corpus.episodes.len() <= MAX_EPISODES,
        "workflow replay corpus episode count is outside bounds"
    );
    let mut ids = std::collections::BTreeSet::new();
    for episode in &corpus.episodes {
        validate_episode(episode)?;
        anyhow::ensure!(
            ids.insert(&episode.episode_id),
            "workflow replay corpus has duplicate episode_id"
        );
    }
    Ok(())
}

fn validate_episode(episode: &WorkflowEpisodeV1) -> Result<()> {
    for (name, value) in [
        ("episode_id", episode.episode_id.as_str()),
        ("prompt", episode.prompt.as_str()),
        ("expected_contains", episode.expected_contains.as_str()),
    ] {
        anyhow::ensure!(
            !value.trim().is_empty() && value.len() <= MAX_FIELD_BYTES,
            "workflow replay {name} is empty or too large"
        );
    }
    anyhow::ensure!(
        !episode.prompt.trim_start().starts_with('/'),
        "workflow replay rejects slash-command prompts"
    );
    if let Some(skill) = &episode.skill {
        anyhow::ensure!(
            !skill.trim().is_empty() && skill.len() <= 256,
            "workflow replay skill is empty or too large"
        );
    }
    Ok(())
}

fn contains_v1(actual: &str, expected: &str) -> bool {
    actual.to_lowercase().contains(&expected.to_lowercase())
}

fn score_replay_turn(
    result: &Result<crate::cli::chat::WorkflowReplayTurnObservation>,
    sink: &ReplaySink,
    expected_contains: &str,
) -> (&'static str, Option<String>) {
    match result {
        Err(error) => ("error", Some(sanitize_reason(&error.to_string()))),
        Ok(_) if !sink.terminal_completed() => (
            "error",
            Some("missing terminal provider completion".to_owned()),
        ),
        Ok(_) if sink.provider_response.trim().is_empty() => {
            ("error", Some("missing terminal reply".to_owned()))
        }
        Ok(_) if contains_v1(&sink.provider_response, expected_contains) => ("pass", None),
        Ok(_) => (
            "fail",
            Some("contains-v1 expectation was not found".to_owned()),
        ),
    }
}

fn public_config_fingerprint(config: &crate::config::FreedomConfig) -> Result<String> {
    Ok(sha256(config.public_yaml()?.as_bytes()))
}

fn replay_root() -> Result<PathBuf> {
    let root = std::env::temp_dir().join(format!("neoth-workflow-replay-{}", uuid::Uuid::new_v4()));
    std::fs::DirBuilder::new()
        .recursive(false)
        .create(&root)
        .with_context(|| format!("create contained replay root {}", root.display()))?;
    Ok(root)
}

fn read_bounded(path: &Path, name: &str) -> Result<Vec<u8>> {
    use std::io::Read as _;

    let file =
        std::fs::File::open(path).with_context(|| format!("open {name} {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("read {name} metadata {}", path.display()))?;
    anyhow::ensure!(
        metadata.is_file() && metadata.len() <= MAX_CORPUS_BYTES as u64,
        "{name} is not a bounded regular file"
    );
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take((MAX_CORPUS_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {name} {}", path.display()))?;
    anyhow::ensure!(
        bytes.len() <= MAX_CORPUS_BYTES,
        "{name} grew beyond bounded size while reading"
    );
    Ok(bytes)
}

fn write_new_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path
        .parent()
        .context("workflow replay output has no parent directory")?;
    std::fs::create_dir_all(parent)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    use std::io::Write as _;
    let mut file = options
        .open(path)
        .with_context(|| format!("create workflow replay corpus {}", path.display()))?;
    file.write_all(serde_json::to_string_pretty(value)?.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

fn config_fingerprint(provider: &str, model: &str, max_per_request: u32) -> String {
    sha256(
        format!(
            "workflow-replay-config-v1\0{provider}\0{model}\0{max_per_request}\0{SCORER}\0deny_all"
        )
        .as_bytes(),
    )
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
fn sanitize_reason(reason: &str) -> String {
    reason.chars().take(240).collect()
}

fn render_markdown(report: &WorkflowReplayReportV1) -> String {
    let mut markdown = format!(
        "# Workflow replay report\n\n- Corpus SHA-256: `{}`\n- Source revision: `{}`\n- Scorer: `{}`\n- Result: **{}**\n\n| Episode | Outcome | Reason |\n| --- | --- | --- |\n",
        report.corpus_sha256,
        report.source_revision,
        report.scorer,
        if report.passed { "PASS" } else { "FAIL" },
    );
    for episode in &report.episodes {
        markdown.push_str(&format!(
            "| {} | {} | {} |\n",
            markdown_table_cell(&episode.episode_id),
            markdown_table_cell(episode.outcome),
            markdown_table_cell(episode.reason.as_deref().unwrap_or("")),
        ));
    }
    markdown
}

fn markdown_table_cell(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace(['\r', '\n'], " ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use crate::providers::{Completion, Provider, Request};
    use async_trait::async_trait;

    #[derive(Default)]
    struct RecordingReplayProvider {
        calls: AtomicUsize,
        requests: Mutex<Vec<Request>>,
    }

    #[async_trait]
    impl Provider for RecordingReplayProvider {
        fn name(&self) -> &'static str {
            "local_qwen"
        }

        fn default_model(&self) -> Option<&str> {
            Some("workflow-replay-test-model")
        }

        fn output_token_ceiling(&self, _request: &Request) -> Option<u32> {
            Some(64)
        }

        async fn complete(&self, request: Request) -> Result<Completion> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let prompt = request.prompt.clone();
            let model = request
                .model
                .clone()
                .unwrap_or_else(|| "workflow-replay-test-model".to_owned());
            self.requests
                .lock()
                .expect("record workflow replay provider request")
                .push(request);
            Ok(Completion {
                text: format!("recorded terminal reply for {prompt}"),
                model,
                latency: std::time::Duration::ZERO,
                ..Completion::default()
            })
        }
    }

    #[derive(Default)]
    struct FailingReplayProvider {
        calls: AtomicUsize,
        requests: Mutex<Vec<Request>>,
    }

    #[async_trait]
    impl Provider for FailingReplayProvider {
        fn name(&self) -> &'static str {
            "local_qwen"
        }

        fn default_model(&self) -> Option<&str> {
            Some("workflow-replay-test-model")
        }

        async fn complete(&self, request: Request) -> Result<Completion> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.requests
                .lock()
                .expect("record failing workflow replay provider request")
                .push(request);
            anyhow::bail!("recorded workflow replay provider failure")
        }
    }

    #[test]
    fn contains_v1_is_case_insensitive_and_rejects_missing_expectation() {
        assert!(contains_v1("Current workflow completed", "WORKFLOW"));
        assert!(!contains_v1(
            "Current workflow completed",
            "provider failure"
        ));
    }

    #[test]
    fn corpus_rejection_happens_before_any_runtime_setup() {
        let corpus = WorkflowCorpusV1 {
            schema_version: 1,
            kind: CORPUS_KIND.to_owned(),
            provenance: CorpusProvenanceV1 {
                label: "operator-curated+inputhash".to_owned(),
                input_sha256: "0".repeat(64),
            },
            episodes: vec![WorkflowEpisodeV1 {
                episode_id: "one".to_owned(),
                prompt: "/effectful".to_owned(),
                expected_contains: "done".to_owned(),
                skill: None,
            }],
        };
        assert!(validate_corpus(&corpus).is_err());
    }

    #[test]
    fn scoring_requires_an_authenticated_provider_terminal_and_never_passes_errors() {
        let mut sink = ReplaySink {
            provider_response: "workflow completed".to_owned(),
            ..ReplaySink::default()
        };
        assert_eq!(
            score_replay_turn(
                &Ok(crate::cli::chat::WorkflowReplayTurnObservation::default()),
                &sink,
                "completed"
            )
            .0,
            "error",
            "stdout-like bytes without a terminal completion cannot pass"
        );
        sink.terminal_provider = Some("recording-provider".to_owned());
        sink.terminal_model = Some("recording-model".to_owned());
        assert_eq!(
            score_replay_turn(
                &Ok(crate::cli::chat::WorkflowReplayTurnObservation::default()),
                &sink,
                "COMPLETED"
            )
            .0,
            "pass"
        );
        assert_eq!(
            score_replay_turn(&Err(anyhow::anyhow!("provider failed")), &sink, "completed").0,
            "error"
        );
    }

    #[test]
    fn replay_scoring_ignores_human_stdout_and_requires_typed_completed_body() {
        use crate::cli::chat_turn_pipeline::{
            ChatOutput, ChatTurnEvent, ChatTurnEventSink, ChatTurnTerminal,
        };

        let mut sink = ReplaySink::default();
        sink.emit(ChatTurnEvent::Output(ChatOutput::HumanStdout {
            text: "status: terminal reply".to_owned(),
        }))
        .expect("record status output");
        sink.emit(ChatTurnEvent::Terminal(ChatTurnTerminal::Complete {
            provider: "recording-provider".to_owned(),
            model: "recording-model".to_owned(),
            session_id: None,
            response_feedback: None,
            response_feedback_unavailable: true,
        }))
        .expect("record terminal");
        assert_eq!(
            score_replay_turn(
                &Ok(crate::cli::chat::WorkflowReplayTurnObservation::default()),
                &sink,
                "terminal reply",
            )
            .0,
            "error",
            "ordinary status output must not satisfy the replay scorer",
        );

        sink.emit(ChatTurnEvent::Output(ChatOutput::ReplayCompletedBody {
            text: "terminal reply".to_owned(),
        }))
        .expect("record typed replay body");
        assert_eq!(
            score_replay_turn(
                &Ok(crate::cli::chat::WorkflowReplayTurnObservation::default()),
                &sink,
                "terminal reply",
            )
            .0,
            "pass",
        );
    }

    #[test]
    fn public_config_fingerprint_covers_the_effective_secret_free_config() {
        let baseline = crate::config::FreedomConfig::default();
        let mut changed = baseline.clone();
        changed.provider_model = Some("workflow-replay-digest-test".to_owned());
        let baseline_digest =
            public_config_fingerprint(&baseline).expect("digest baseline public config");
        let changed_digest =
            public_config_fingerprint(&changed).expect("digest changed public config");
        assert!(valid_sha256(&baseline_digest));
        assert!(valid_sha256(&changed_digest));
        assert_ne!(baseline_digest, changed_digest);
    }

    #[test]
    fn config_fingerprint_uses_actual_nul_field_separators() {
        let expected =
            sha256(b"workflow-replay-config-v1\0provider\0model\042\0contains-v1\0deny_all");
        assert_eq!(config_fingerprint("provider", "model", 42), expected);
    }

    fn install_authorized_replay_skill(
        home: &Path,
        config: &crate::config::FreedomConfig,
        config_path: &Path,
        id: &str,
        prompt: &str,
    ) {
        let skill_dir = home.join("skills").join(id);
        std::fs::create_dir_all(&skill_dir).expect("create installed replay skill");
        std::fs::write(
            skill_dir.join("skill.yaml"),
            format!(
                "id: {id}\ndescription: Workflow replay fixture\ntrigger_keywords: [workflow-replay-fixture]\nsystem_prompt: {prompt:?}\nenabled: true\n"
            ),
        )
        .expect("write installed replay skill");
        let wal_dir = home.join("wal");
        std::fs::create_dir_all(&wal_dir).expect("create replay skill authority WAL directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&wal_dir, std::fs::Permissions::from_mode(0o700))
                .expect("restrict replay skill authority WAL directory");
        }
        #[cfg(windows)]
        crate::wal::win_native::set_private_current_user_directory_dacl(&wal_dir)
            .expect("restrict replay skill authority WAL directory");
        crate::wal::compaction::load_or_init_key(&wal_dir.join("hmac.key"))
            .expect("create replay skill authority key");
        let current = crate::skills::installer::inspect_current_install(&home.join("skills"), id)
            .expect("inspect installed replay skill");
        crate::skills::mutation_lifecycle::record_committed_install_incarnation_for_test(
            home,
            id,
            &current.generation_sha256,
            crate::skills::installer::SkillMutationOrigin::CliInstall,
        )
        .expect("record replay skill installation incarnation");
        let reload =
            crate::config::reload::ReloadController::new(config.clone(), config_path.to_path_buf());
        let decision = crate::skills::authority::SkillAuthorityDecision::new(
            crate::skills::authority::SkillAuthorityDecisionSource::OperatorCli,
            crate::skills::authority::SkillAuthorityState::Active,
            None,
        )
        .expect("construct active replay skill authority");
        crate::skills::authority::publish_installed_authority_decision(home, id, &reload, decision)
            .expect("publish active replay skill authority");
    }

    #[tokio::test]
    async fn actual_replay_turn_records_provider_terminal_and_scores_its_reply() {
        let actual = tempfile::tempdir().expect("actual operator home");
        let replay = tempfile::tempdir().expect("contained replay home");
        let mut config = crate::config::FreedomConfig::default();
        config.autonomy = crate::permissions::AutonomyLevel::Full;
        config.provider_model = Some("workflow-replay-test-model".to_owned());
        config.council.disabled = Some(true);
        config.memory.recall_shortcut = false;
        config.chat_onboarding_completed = true;
        let actual_config = actual.path().join("freedom.yaml");
        std::fs::write(
            &actual_config,
            serde_yaml::to_string(&config).expect("serialize actual config"),
        )
        .expect("write actual config");
        std::fs::write(
            replay.path().join("freedom.yaml"),
            serde_yaml::to_string(&config).expect("serialize replay config"),
        )
        .expect("write replay config");

        let provider = RecordingReplayProvider::default();
        let mut sink = ReplaySink::default();
        let observation = crate::cli::chat::run_workflow_replay_turn_at(
            config,
            &provider,
            replay.path().to_path_buf(),
            actual.path().to_path_buf(),
            actual_config,
            crate::consent::EphemeralConsent::default(),
            "replay prompt".to_owned(),
            None,
            &mut sink,
        )
        .await
        .expect("contained replay must complete its one provider turn");

        assert!(observation.selected_skill.is_none());
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        assert!(
            sink.terminal_completed(),
            "only a provider terminal completes replay"
        );
        assert_eq!(
            score_replay_turn(&Ok(observation), &sink, "terminal reply").0,
            "pass"
        );
    }

    #[tokio::test]
    async fn actual_replay_provider_failure_emits_no_terminal_or_accepted_body() {
        let actual = tempfile::tempdir().expect("actual operator home");
        let replay = tempfile::tempdir().expect("contained replay home");
        let mut config = crate::config::FreedomConfig::default();
        config.autonomy = crate::permissions::AutonomyLevel::Full;
        config.provider_model = Some("workflow-replay-test-model".to_owned());
        config.council.disabled = Some(true);
        config.memory.recall_shortcut = false;
        config.chat_onboarding_completed = true;
        let actual_config = actual.path().join("freedom.yaml");
        std::fs::write(
            &actual_config,
            serde_yaml::to_string(&config).expect("serialize actual config"),
        )
        .expect("write actual config");
        std::fs::write(
            replay.path().join("freedom.yaml"),
            serde_yaml::to_string(&config).expect("serialize replay config"),
        )
        .expect("write replay config");

        let provider = FailingReplayProvider::default();
        let mut sink = ReplaySink::default();
        let error = crate::cli::chat::run_workflow_replay_turn_at(
            config,
            &provider,
            replay.path().to_path_buf(),
            actual.path().to_path_buf(),
            actual_config,
            crate::consent::EphemeralConsent::default(),
            "replay provider failure".to_owned(),
            None,
            &mut sink,
        )
        .await
        .expect_err("provider failure must fail the contained replay");

        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            provider
                .requests
                .lock()
                .expect("read failing replay request")
                .len(),
            1
        );
        assert!(
            sink.provider_response.is_empty(),
            "failed provider must not produce accepted replay body"
        );
        assert!(
            !sink.terminal_completed(),
            "failed provider must not emit a terminal completion"
        );
        assert_eq!(
            score_replay_turn(&Err(error), &sink, "replay provider failure").0,
            "error",
            "a failed replay provider turn cannot pass",
        );
    }

    #[tokio::test]
    async fn actual_replay_reports_the_authority_bound_selected_skill_snapshot() {
        let actual = tempfile::tempdir().expect("actual operator home");
        let replay = tempfile::tempdir().expect("contained replay home");
        let skill_id = "workflow-replay-fixture";
        let actual_skill_body = "WORKFLOW-REPLAY-ACTUAL-SKILL-BODY";
        let replay_skill_body = "WORKFLOW-REPLAY-REPLAY-HOME-SKILL-BODY";
        let mut config = crate::config::FreedomConfig::default();
        config.autonomy = crate::permissions::AutonomyLevel::Full;
        config.provider_model = Some("workflow-replay-test-model".to_owned());
        config.council.disabled = Some(true);
        config.memory.recall_shortcut = false;
        config.chat_onboarding_completed = true;
        let actual_config = actual.path().join("freedom.yaml");
        std::fs::write(
            &actual_config,
            serde_yaml::to_string(&config).expect("serialize actual config"),
        )
        .expect("write actual config");
        install_authorized_replay_skill(
            actual.path(),
            &config,
            &actual_config,
            skill_id,
            actual_skill_body,
        );
        let replay_skill_dir = replay.path().join("skills").join(skill_id);
        std::fs::create_dir_all(&replay_skill_dir).expect("create replay-home shadow skill");
        std::fs::write(
            replay_skill_dir.join("skill.yaml"),
            format!("id: {skill_id}\ndescription: Shadow skill\nsystem_prompt: {replay_skill_body}\nenabled: true\n"),
        )
        .expect("write replay-home shadow skill");
        std::fs::write(
            replay.path().join("freedom.yaml"),
            serde_yaml::to_string(&config).expect("serialize replay config"),
        )
        .expect("write replay config");

        let registry = crate::skills::SkillRegistry::load_from_config_path(
            actual.path().join("skills"),
            &actual_config,
        )
        .await
        .expect("load authority-bound actual skill registry");
        let expected_skill = registry
            .snapshot_owned()
            .iter()
            .find(|candidate| candidate.as_skill().id() == skill_id)
            .expect("actual authority-bound skill is routable");
        let expected_content_sha256 = expected_skill.as_skill().content_hash.clone();

        let provider = RecordingReplayProvider::default();
        let mut sink = ReplaySink::default();
        let observation = crate::cli::chat::run_workflow_replay_turn_at(
            config,
            &provider,
            replay.path().to_path_buf(),
            actual.path().to_path_buf(),
            actual_config,
            crate::consent::EphemeralConsent::default(),
            "replay selected installed skill".to_owned(),
            Some(skill_id.to_owned()),
            &mut sink,
        )
        .await
        .expect("selected installed skill replay completes");

        let selected_skill = observation
            .selected_skill
            .expect("selected skill observation");
        assert_eq!(selected_skill.id, skill_id);
        assert_eq!(selected_skill.content_sha256, expected_content_sha256);
        let requests = provider
            .requests
            .lock()
            .expect("read recorded replay requests");
        assert_eq!(requests.len(), 1);
        let system = requests[0]
            .system
            .as_deref()
            .expect("selected skill request system");
        assert!(system.contains(actual_skill_body));
        assert!(!system.contains(replay_skill_body));
    }
}
