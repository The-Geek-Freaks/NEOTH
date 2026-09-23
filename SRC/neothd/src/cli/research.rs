//! `neoth research` — explicit, durable operator lifecycle for deep research.
//!
//! `create` only snapshots bounded intent. `approve` is deliberately separate
//! from `run`; no provider or HTTP authorizer is constructed before `run`.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::daemon::research_runs::{self, ResearchRun, ResearchRunBudget};

/// Reserves every producer `complete` call before invoking the wrapped provider.
/// The wrapped provider retains its ordinary cost authorization boundary.
/// Bound: plan + at most one extraction/provider call per fetched page + one
/// continue check between rounds + final synthesis.
struct RunCallBudget<'a> {
    inner: &'a dyn crate::providers::Provider,
    home: &'a std::path::Path,
    id: &'a str,
    attempt: &'a str,
}
#[async_trait::async_trait]
impl crate::providers::Provider for RunCallBudget<'_> {
    fn name(&self) -> &'static str {
        self.inner.name()
    }
    fn default_model(&self) -> Option<&str> {
        self.inner.default_model()
    }
    async fn complete(
        &self,
        req: crate::providers::Request,
    ) -> Result<crate::providers::Completion> {
        research_runs::reserve_provider_call(self.home, self.id, self.attempt)?;
        self.inner.complete(req).await
    }
}

struct DurableControl<'a> {
    home: &'a std::path::Path,
    id: &'a str,
    attempt: &'a str,
}
impl crate::tools::deep_research::ResearchRunControl for DurableControl<'_> {
    fn checkpoint(&self, phase: &'static str) -> Result<()> {
        match research_runs::observe_control(self.home, self.id, self.attempt)? {
            research_runs::ResearchControl::Cancelled => {
                anyhow::bail!("research run cancelled before {phase}")
            }
            // Pause is intentionally cooperative: preserve the current bounded
            // round, checkpoint it, then consume the request at that boundary.
            research_runs::ResearchControl::PauseRequested
                if matches!(phase, "continue_check" | "synthesis") =>
            {
                research_runs::pause_at_boundary(self.home, self.id, self.attempt)?;
                anyhow::bail!("research run paused at completed-round boundary before {phase}")
            }
            research_runs::ResearchControl::Continue
            | research_runs::ResearchControl::PauseRequested => {
                research_runs::begin_effect(self.home, self.id, self.attempt)
                    .context("persist research effect boundary")
            }
        }
    }
    fn resume_checkpoint(&self) -> Result<Option<crate::tools::deep_research::ResearchCheckpoint>> {
        Ok(Some(research_runs::load(self.home, self.id)?.checkpoint))
    }
    fn persist_checkpoint(
        &self,
        checkpoint: &crate::tools::deep_research::ResearchCheckpoint,
    ) -> Result<()> {
        research_runs::checkpoint(self.home, self.id, self.attempt, checkpoint.clone())
    }
    fn round_completed(&self) -> Result<()> {
        if matches!(
            research_runs::observe_control(self.home, self.id, self.attempt)?,
            research_runs::ResearchControl::PauseRequested
        ) {
            research_runs::pause_at_boundary(self.home, self.id, self.attempt)?;
            anyhow::bail!("research run paused after durable round checkpoint")
        }
        Ok(())
    }
}

#[derive(Args, Debug, Clone)]
pub struct ResearchArgs {
    #[command(subcommand)]
    pub action: ResearchAction,
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ResearchAction {
    Create {
        topic: String,
        #[arg(long, default_value = "operator-requested bounded web research")]
        scope: String,
    },
    Show {
        id: String,
    },
    List,
    Approve {
        id: String,
        #[arg(long)]
        revision: u64,
    },
    Run {
        id: String,
        #[arg(long)]
        revision: u64,
    },
    Pause {
        id: String,
        #[arg(long)]
        revision: u64,
    },
    Resume {
        id: String,
        #[arg(long)]
        revision: u64,
    },
    Cancel {
        id: String,
        #[arg(long)]
        revision: u64,
    },
}

pub async fn run_research(args: ResearchArgs) -> Result<()> {
    let home = crate::config::FreedomConfig::default_neoth_home();
    run_research_at(&home, args, None).await
}

/// The public command always resolves its provider from the current config.
/// Tests may supply an already-resolved provider, but still traverse the same
/// revision, authorization, WAL and deep-research execution path.
async fn run_research_at(
    home: &std::path::Path,
    args: ResearchArgs,
    provider_override: Option<&dyn crate::providers::Provider>,
) -> Result<()> {
    match args.action {
        ResearchAction::Create { topic, scope } => {
            // Configuration is read exactly once and the resolved caps are stored
            // immutably; later freedom.yaml changes cannot widen this run.
            let cfg = crate::config::FreedomConfig::load_from_path_or_default(
                &home.join("freedom.yaml"),
            )?;
            let mut budget = ResearchRunBudget::from_config(&cfg.deep_research);
            budget.max_provider_tokens = cfg.tokens.max_per_request;
            budget.max_wall_secs = 900;
            render(
                &research_runs::create(home, topic, scope, budget)?,
                &args.output,
            )
        }
        ResearchAction::Show { id } => render(&research_runs::load(home, &id)?, &args.output),
        ResearchAction::List => render_list(&research_runs::list(home)?, &args.output),
        ResearchAction::Approve { id, revision } => {
            render(&research_runs::approve(home, &id, revision)?, &args.output)
        }
        ResearchAction::Pause { id, revision } => render(
            &research_runs::request_control(home, &id, revision, "pause")?,
            &args.output,
        ),
        ResearchAction::Cancel { id, revision } => render(
            &research_runs::request_control(home, &id, revision, "cancel")?,
            &args.output,
        ),
        ResearchAction::Resume { id, revision } | ResearchAction::Run { id, revision } => {
            run(home, &id, revision, &args.output, provider_override).await
        }
    }
}

async fn run(
    home: &std::path::Path,
    id: &str,
    revision: u64,
    output: &OutputFormat,
    provider_override: Option<&dyn crate::providers::Provider>,
) -> Result<()> {
    let claimed = research_runs::claim_run(home, id, revision)?;
    if matches!(claimed.state, research_runs::ResearchRunState::Cancelled) {
        return render(&claimed, output);
    }
    let attempt = claimed
        .attempt_token
        .as_deref()
        .context("claimed research run missing executor attempt token")?;
    // Resolve current provider credentials only after the durable approval/claim.
    // The immutable run budget is reconstituted into a local config copy so the
    // existing engine receives its normal bounded producer, without reading
    // mutable operator caps again.
    let mut cfg =
        match crate::config::FreedomConfig::load_from_path_or_default(&home.join("freedom.yaml")) {
            Ok(value) => value,
            Err(error) => return Err(pre_effect_failure(home, id, attempt, error)),
        };
    cfg.deep_research.max_rounds = Some(claimed.budget.max_rounds);
    cfg.deep_research.results_per_query = Some(claimed.budget.results_per_query);
    cfg.deep_research.pages_per_round = Some(claimed.budget.pages_per_round);
    let resolved_provider;
    let provider: &dyn crate::providers::Provider = match provider_override {
        Some(provider) => provider,
        None => {
            resolved_provider = match crate::providers::from_config_for_utility_at(&cfg, home).await
            {
                Ok(value) => value,
                Err(error) => {
                    return Err(pre_effect_failure(
                        home,
                        id,
                        attempt,
                        error.context("resolve approved research provider"),
                    ));
                }
            };
            resolved_provider.as_ref()
        }
    };
    let search_provider = crate::tools::deep_research::resolve_search_provider();
    let search_key = match crate::tools::deep_research::resolve_search_key(search_provider) {
        Ok(value) => value,
        Err(error) => return Err(pre_effect_failure(home, id, attempt, error)),
    };
    let wal_dir = home.join("wal");
    if let Err(error) = std::fs::create_dir_all(&wal_dir) {
        return Err(pre_effect_failure(home, id, attempt, error.into()));
    }
    let segment = crate::wal::writer::unique_standalone_segment_path(&wal_dir, "research-run");
    let (writer, join) = match crate::wal::writer::spawn_for_home(segment, home.to_path_buf()) {
        Ok(value) => value,
        Err(error) => return Err(pre_effect_failure(home, id, attempt, error.into())),
    };
    let provider_auth = crate::providers::cost_authorization::ProviderCallAuthorizer::interactive(
        cfg.autonomy_policy(),
        Some(writer.clone()),
        claimed.budget.max_provider_tokens,
    )
    .with_usage_home(home.to_path_buf());
    let wrapped = crate::providers::cost_authorization::CostAuthorizingProvider::new(
        provider,
        provider_auth,
        crate::providers::utility_model_for_config(&cfg),
        "deep_research_run",
    );
    let budgeted = RunCallBudget {
        inner: &wrapped,
        home,
        id,
        attempt,
    };
    let http = match crate::tools::external_http::ExternalHttpAuthorizer::interactive(
        cfg.autonomy_policy(),
    ) {
        Ok(value) => value,
        Err(error) => {
            drop(wrapped);
            drop(writer);
            let wal = join.await.context("join research lifecycle WAL writer");
            return match wal {
                Ok(()) => Err(pre_effect_failure(home, id, attempt, error)),
                Err(wal_error) => Err(pre_effect_failure(
                    home,
                    id,
                    attempt,
                    anyhow::anyhow!(
                        "research setup failed: {error:#}; WAL finalization failed: {wal_error:#}"
                    ),
                )),
            };
        }
    };
    // `run_deep_research` is the existing real producer: this CLI never
    // substitutes a proposal/ledger for a network execution.
    // Account setup time as active time too. The fresh read also fences a stale
    // executor before any controlled producer can begin.
    let refreshed = research_runs::load(home, id).and_then(|run| {
        anyhow::ensure!(
            run.state == research_runs::ResearchRunState::Running
                && run.attempt_token.as_deref() == Some(attempt),
            "research attempt changed before controlled dispatch"
        );
        Ok(run)
    });
    let remaining_wall_ms = match refreshed {
        Ok(run) => {
            let live_elapsed_ms = run
                .attempt_started_unix_ms
                .map(|started| {
                    crate::time::now_unix_ns_i64()
                        .saturating_div(1_000_000)
                        .saturating_sub(started) as u64
                })
                .unwrap_or(0);
            match run
                .budget
                .max_wall_secs
                .saturating_mul(1000)
                .checked_sub(run.wall_elapsed_ms.saturating_add(live_elapsed_ms))
                .filter(|milliseconds| *milliseconds > 0)
            {
                Some(milliseconds) => milliseconds,
                None if run.effect_started => {
                    drop(http);
                    drop(wrapped);
                    drop(writer);
                    let wal = join.await.context("join research lifecycle WAL writer");
                    return match wal {
                        Ok(()) => Err(interrupted_failure(
                            home,
                            id,
                            attempt,
                            anyhow::anyhow!(
                                "immutable research wall-time budget exhausted before resume"
                            ),
                        )),
                        Err(wal_error) => Err(interrupted_failure(
                            home,
                            id,
                            attempt,
                            anyhow::anyhow!(
                                "research budget exhausted before resume; WAL finalization failed: {wal_error:#}"
                            ),
                        )),
                    };
                }
                None => {
                    drop(http);
                    drop(wrapped);
                    drop(writer);
                    let wal = join.await.context("join research lifecycle WAL writer");
                    return match wal {
                        Ok(()) => Err(pre_effect_failure(
                            home,
                            id,
                            attempt,
                            anyhow::anyhow!(
                                "immutable research wall-time budget exhausted before first effect"
                            ),
                        )),
                        Err(wal_error) => Err(pre_effect_failure(
                            home,
                            id,
                            attempt,
                            anyhow::anyhow!(
                                "research budget exhausted before first effect; WAL finalization failed: {wal_error:#}"
                            ),
                        )),
                    };
                }
            }
        }
        Err(error) => {
            drop(http);
            drop(wrapped);
            drop(writer);
            let wal = join.await.context("join research lifecycle WAL writer");
            return match wal {
                Ok(()) => Err(error),
                Err(wal_error) => Err(anyhow::anyhow!(
                    "research setup failed: {error:#}; WAL finalization failed: {wal_error:#}"
                )),
            };
        }
    };
    let control = DurableControl { home, id, attempt };
    let result = match tokio::time::timeout(
        std::time::Duration::from_millis(remaining_wall_ms),
        crate::tools::deep_research::run_deep_research_controlled(
            &claimed.topic,
            &budgeted,
            &search_key,
            search_provider,
            &cfg.deep_research,
            &writer,
            &http,
            Some(&control),
        ),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(anyhow::anyhow!(
            "immutable research wall-time budget exhausted"
        )),
    };
    drop(wrapped);
    drop(http);
    drop(writer);
    let wal_result = join.await.context("join research lifecycle WAL writer");
    match result {
        Ok(report) => {
            if let Err(wal) = wal_result {
                return Err(interrupted_failure(
                    home,
                    id,
                    attempt,
                    anyhow::anyhow!("research completed but WAL finalization failed: {wal:#}"),
                ));
            }
            let finished = match research_runs::complete(
                home,
                id,
                attempt,
                &report.article,
                &report.citations,
            ) {
                Ok(value) => value,
                Err(error) => {
                    return Err(interrupted_failure(
                        home,
                        id,
                        attempt,
                        error.context("persist completed research report"),
                    ));
                }
            };
            render(&finished, output)?;
            Ok(())
        }
        Err(error) => {
            // A provider/search/fetch may already have crossed the network
            // boundary. Persist an explicit unknown-interruption state and do
            // not silently replay it on another `run` invocation.
            let wal_error = wal_result.err();
            let current = research_runs::load(home, id)?;
            if controlled_terminal_wal_result(&current, wal_error.as_ref())? {
                return render(&current, output);
            }
            if !current.effect_started {
                return Err(pre_effect_failure(home, id, attempt, error));
            }
            let terminal = research_runs::fail_interrupted(home, id, attempt);
            match (terminal,wal_error) { (Ok(_),None)=>Err(error).context("approved research run interrupted; reissue refused pending operator inspection"), (Err(persist),None)=>Err(anyhow::anyhow!("research failure: {error:#}; terminal persistence failed: {persist:#}")), (Ok(_),Some(wal))=>Err(anyhow::anyhow!("research failure: {error:#}; WAL finalization failed: {wal:#}")), (Err(persist),Some(wal))=>Err(anyhow::anyhow!("research failure: {error:#}; WAL finalization failed: {wal:#}; terminal persistence failed: {persist:#}")) }
        }
    }
}

fn pre_effect_failure(
    home: &std::path::Path,
    id: &str,
    attempt: &str,
    error: anyhow::Error,
) -> anyhow::Error {
    match research_runs::fail_pre_effect(home, id, attempt) {
        Ok(()) => error,
        Err(persist) => anyhow::anyhow!(
            "research setup failed: {error:#}; pre-effect terminal persistence failed: {persist:#}"
        ),
    }
}
fn interrupted_failure(
    home: &std::path::Path,
    id: &str,
    attempt: &str,
    error: anyhow::Error,
) -> anyhow::Error {
    match research_runs::fail_interrupted(home, id, attempt) {
        Ok(_) => error,
        Err(persist) => anyhow::anyhow!(
            "research terminal transition failed: {error:#}; interrupted persistence failed: {persist:#}"
        ),
    }
}

fn controlled_terminal_wal_result(
    run: &ResearchRun,
    wal_error: Option<&anyhow::Error>,
) -> Result<bool> {
    if matches!(
        &run.state,
        research_runs::ResearchRunState::Paused | research_runs::ResearchRunState::Cancelled
    ) {
        if let Some(wal) = wal_error {
            anyhow::bail!(
                "research run reached {:?}, but lifecycle WAL finalization failed: {wal:#}",
                run.state
            );
        }
        return Ok(true);
    }
    Ok(false)
}

fn render(run: &ResearchRun, output: &OutputFormat) -> Result<()> {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!("{}", serde_json::to_string(run)?),
        OutputFormat::Table => {
            println!(
                "{}  rev={}  state={:?}  rounds={}/{}",
                run.id, run.revision, run.state, run.completed_rounds, run.budget.max_rounds
            );
            if let Some(report) = &run.report {
                println!("\n{report}");
                for (index, citation) in run.citations.iter().enumerate() {
                    println!("[{}] {} — {}", index + 1, citation.title, citation.url);
                }
            }
        }
    };
    Ok(())
}
fn render_list(runs: &[ResearchRun], output: &OutputFormat) -> Result<()> {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!("{}", serde_json::to_string(runs)?),
        OutputFormat::Table => {
            for run in runs {
                println!(
                    "{}  rev={}  state={:?}  {}",
                    run.id, run.revision, run.state, run.topic
                );
            }
        }
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::Provider as _;
    use clap::Parser;
    use std::ffi::OsString;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct RestoreNeothHome(Option<OsString>);

    impl Drop for RestoreNeothHome {
        fn drop(&mut self) {
            unsafe {
                match self.0.take() {
                    Some(home) => std::env::set_var("NEOTH_HOME", home),
                    None => std::env::remove_var("NEOTH_HOME"),
                }
            }
        }
    }

    struct RestoreEnv {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl Drop for RestoreEnv {
        fn drop(&mut self) {
            unsafe {
                match self.previous.take() {
                    Some(value) => std::env::set_var(self.key, value),
                    None => std::env::remove_var(self.key),
                }
            }
        }
    }

    fn set_test_env(key: &'static str, value: impl AsRef<std::ffi::OsStr>) -> RestoreEnv {
        let previous = std::env::var_os(key);
        unsafe { std::env::set_var(key, value) };
        RestoreEnv { key, previous }
    }

    async fn controlled_empty_searxng() -> (wiremock::MockServer, Vec<RestoreEnv>) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/search"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": []
            })))
            .expect(1)
            .mount(&server)
            .await;
        let restores = vec![
            set_test_env("NEOTH_WEB_SEARCH_PROVIDER", "searxng"),
            set_test_env("NEOTH_SEARXNG_URL", server.uri()),
            set_test_env("NEOTH_SEARXNG_LANG", "all"),
        ];
        (server, restores)
    }

    fn dispatch_args(action: ResearchAction) -> ResearchArgs {
        ResearchArgs {
            action,
            output: OutputFormat::Json,
        }
    }

    fn deep_research_lifecycle_payloads(home: &std::path::Path) -> Vec<(u8, serde_json::Value)> {
        let mut events = Vec::new();
        crate::wal::scan::for_each_frame_at_home(
            home,
            crate::wal::scan::HomeWalScanLimits::default(),
            |_, frame| {
                if matches!(
                    frame.header.event_type,
                    crate::wal::events::EVENT_TYPE_DEEP_RESEARCH_STARTED
                        | crate::wal::events::EVENT_TYPE_DEEP_RESEARCH_COMPLETED
                ) {
                    events.push((
                        frame.header.event_type,
                        serde_json::from_slice(frame.payload)
                            .expect("decode research lifecycle WAL payload"),
                    ));
                }
                Ok(())
            },
        )
        .expect("decode authenticated research lifecycle WAL");
        events
    }

    struct CountingProvider(Arc<AtomicUsize>);
    #[async_trait::async_trait]
    impl crate::providers::Provider for CountingProvider {
        fn name(&self) -> &'static str {
            "research-call-cap-test"
        }

        fn default_model(&self) -> Option<&str> {
            Some("research-fixture-model")
        }

        async fn complete(
            &self,
            _req: crate::providers::Request,
        ) -> Result<crate::providers::Completion> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(crate::providers::Completion {
                termination: Default::default(),
                text: "ok".into(),
                identity: Default::default(),
                model: "test".into(),
                latency: std::time::Duration::ZERO,
                input_tokens: None,
                output_tokens: None,
                cache_creation_tokens: None,
                cache_read_tokens: None,
                usage_measurements: None,
            })
        }
    }

    struct InterruptedProvider(Arc<AtomicUsize>);

    #[async_trait::async_trait]
    impl crate::providers::Provider for InterruptedProvider {
        fn name(&self) -> &'static str {
            "research-interrupted-provider-test"
        }

        fn default_model(&self) -> Option<&str> {
            Some("research-fixture-model")
        }

        async fn complete(
            &self,
            _req: crate::providers::Request,
        ) -> Result<crate::providers::Completion> {
            let call = self.0.fetch_add(1, Ordering::SeqCst);
            if call == 1 {
                anyhow::bail!("controlled synthesis interruption")
            }
            Ok(crate::providers::Completion {
                termination: Default::default(),
                text: "[\"bounded local query\"]".into(),
                identity: Default::default(),
                model: "test".into(),
                latency: std::time::Duration::ZERO,
                input_tokens: None,
                output_tokens: None,
                cache_creation_tokens: None,
                cache_read_tokens: None,
                usage_measurements: None,
            })
        }
    }

    #[tokio::test]
    async fn provider_call_cap_rejects_next_call_without_inner_invocation() {
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = CountingProvider(Arc::clone(&calls));
        let home = tempfile::tempdir().unwrap();
        let budget = ResearchRunBudget {
            max_rounds: 1,
            results_per_query: 1,
            pages_per_round: 1,
            max_provider_tokens: 1,
            max_wall_secs: 60,
            max_provider_calls: 1,
        };
        let draft =
            research_runs::create(home.path(), "topic".into(), "scope".into(), budget).unwrap();
        let approved = research_runs::approve(home.path(), &draft.id, draft.revision).unwrap();
        let claimed =
            research_runs::claim_run(home.path(), &approved.id, approved.revision).unwrap();
        let attempt = claimed.attempt_token.as_deref().unwrap();
        let capped = RunCallBudget {
            inner: &provider,
            home: home.path(),
            id: &claimed.id,
            attempt,
        };
        capped
            .complete(crate::providers::Request::default())
            .await
            .unwrap();
        assert!(
            capped
                .complete(crate::providers::Request::default())
                .await
                .is_err()
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "exhausted cap must reject before inner provider invocation"
        );
    }

    #[test]
    fn paused_or_cancelled_terminal_wal_failure_is_reported_without_mutation() {
        let home = tempfile::tempdir().unwrap();
        let budget = ResearchRunBudget {
            max_rounds: 1,
            results_per_query: 1,
            pages_per_round: 1,
            max_provider_tokens: 1,
            max_wall_secs: 60,
            max_provider_calls: 1,
        };
        let draft =
            research_runs::create(home.path(), "topic".into(), "scope".into(), budget).unwrap();
        let approved = research_runs::approve(home.path(), &draft.id, draft.revision).unwrap();
        let running =
            research_runs::claim_run(home.path(), &approved.id, approved.revision).unwrap();
        let attempt = running.attempt_token.as_deref().unwrap();
        research_runs::checkpoint(
            home.path(),
            &running.id,
            attempt,
            crate::tools::deep_research::ResearchCheckpoint::default(),
        )
        .unwrap();
        let requested = research_runs::request_control(
            home.path(),
            &running.id,
            research_runs::load(home.path(), &running.id)
                .unwrap()
                .revision,
            "pause",
        )
        .unwrap();
        let paused = research_runs::pause_at_boundary(home.path(), &requested.id, attempt).unwrap();
        assert!(
            controlled_terminal_wal_result(
                &paused,
                Some(&anyhow::anyhow!("injected WAL join failure")),
            )
            .is_err()
        );
        let persisted = research_runs::load(home.path(), &paused.id).unwrap();
        assert_eq!(persisted.state, research_runs::ResearchRunState::Paused);
        assert_eq!(persisted.wall_elapsed_ms, paused.wall_elapsed_ms);
        assert_eq!(persisted.attempt_started_unix_ms, None);

        let cancelled = research_runs::request_control(
            home.path(),
            &persisted.id,
            persisted.revision,
            "cancel",
        )
        .unwrap();
        assert_eq!(cancelled.state, research_runs::ResearchRunState::Cancelled);
        assert!(
            controlled_terminal_wal_result(
                &cancelled,
                Some(&anyhow::anyhow!("injected WAL join failure")),
            )
            .is_err()
        );
        assert_eq!(
            research_runs::load(home.path(), &cancelled.id)
                .unwrap()
                .state,
            research_runs::ResearchRunState::Cancelled
        );
    }

    #[test]
    fn research_parser_requires_revision_for_mutations_and_keeps_read_commands() {
        assert!(
            crate::cli::Cli::try_parse_from([
                "neoth",
                "research",
                "approve",
                "rr-0123456789abcdef"
            ])
            .is_err()
        );
        assert!(
            crate::cli::Cli::try_parse_from(["neoth", "research", "run", "rr-0123456789abcdef"])
                .is_err()
        );
        assert!(
            crate::cli::Cli::try_parse_from(["neoth", "research", "pause", "rr-0123456789abcdef"])
                .is_err()
        );
        assert!(
            crate::cli::Cli::try_parse_from(["neoth", "research", "resume", "rr-0123456789abcdef"])
                .is_err()
        );
        assert!(
            crate::cli::Cli::try_parse_from(["neoth", "research", "cancel", "rr-0123456789abcdef"])
                .is_err()
        );
        assert!(crate::cli::Cli::try_parse_from(["neoth", "research", "create", "topic"]).is_ok());
        assert!(
            crate::cli::Cli::try_parse_from(["neoth", "research", "show", "rr-0123456789abcdef"])
                .is_ok()
        );
        assert!(crate::cli::Cli::try_parse_from(["neoth", "research", "list"]).is_ok());
    }

    #[tokio::test]
    async fn operator_lifecycle_dispatches_create_approve_run_pause_resume_cancel_show_and_list_with_exact_revisions()
     {
        // The public research dispatcher deliberately resolves NEOTH_HOME at
        // invocation time. Serialize the process-wide override so this test
        // drives that same operator path without inheriting a developer home.
        let _env = crate::test_env::lock();
        let home = tempfile::tempdir().expect("create isolated CLI home");
        let previous_home = std::env::var_os("NEOTH_HOME");
        unsafe { std::env::set_var("NEOTH_HOME", home.path()) };
        let _restore_home = RestoreNeothHome(previous_home);

        run_research(dispatch_args(ResearchAction::Create {
            topic: "W329 dispatch run".into(),
            scope: "bounded fixture".into(),
        }))
        .await
        .expect("create dispatch succeeds");
        let created = research_runs::list(home.path())
            .expect("list created run")
            .pop()
            .expect("one created run");
        run_research(dispatch_args(ResearchAction::Show {
            id: created.id.clone(),
        }))
        .await
        .expect("show dispatch succeeds for created run");
        run_research(dispatch_args(ResearchAction::List))
            .await
            .expect("list dispatch succeeds for created run");
        assert!(
            run_research(dispatch_args(ResearchAction::Approve {
                id: created.id.clone(),
                revision: created.revision.saturating_add(1),
            }))
            .await
            .is_err(),
            "stale approval revision must be refused by the dispatched command"
        );
        run_research(dispatch_args(ResearchAction::Approve {
            id: created.id.clone(),
            revision: created.revision,
        }))
        .await
        .expect("revision-bound approve dispatch succeeds");
        let approved = research_runs::load(home.path(), &created.id).expect("load approved run");
        assert_eq!(approved.state, research_runs::ResearchRunState::Approved);

        // An empty isolated home cannot resolve a provider. The actual Run
        // command must still claim the approved record and persist a
        // pre-effect terminal failure through its real CLI dispatch path.
        assert!(
            run_research(dispatch_args(ResearchAction::Run {
                id: approved.id.clone(),
                revision: approved.revision,
            }))
            .await
            .is_err(),
            "run dispatch must surface unavailable provider configuration"
        );
        let run_terminal =
            research_runs::load(home.path(), &approved.id).expect("load run terminal");
        assert_eq!(run_terminal.state, research_runs::ResearchRunState::Failed);
        assert!(!run_terminal.effect_started);

        let paused_draft = research_runs::create(
            home.path(),
            "W329 pause/resume dispatch".into(),
            "bounded fixture".into(),
            ResearchRunBudget::from_config(&crate::config::DeepResearchConfig::default()),
        )
        .expect("create pause fixture");
        let paused_approved =
            research_runs::approve(home.path(), &paused_draft.id, paused_draft.revision)
                .expect("approve pause fixture");
        let paused_running =
            research_runs::claim_run(home.path(), &paused_approved.id, paused_approved.revision)
                .expect("claim pause fixture");
        run_research(dispatch_args(ResearchAction::Pause {
            id: paused_running.id.clone(),
            revision: paused_running.revision,
        }))
        .await
        .expect("pause dispatch records a control request");
        let attempt = paused_running
            .attempt_token
            .as_deref()
            .expect("claimed run has attempt token");
        let paused = research_runs::pause_at_boundary(home.path(), &paused_running.id, attempt)
            .expect("executor observes dispatched pause request");
        assert_eq!(paused.state, research_runs::ResearchRunState::Paused);
        assert!(
            run_research(dispatch_args(ResearchAction::Resume {
                id: paused.id.clone(),
                revision: paused.revision,
            }))
            .await
            .is_err(),
            "resume dispatch reaches the same unavailable-provider pre-effect failure"
        );
        assert_eq!(
            research_runs::load(home.path(), &paused.id)
                .expect("load resumed terminal")
                .state,
            research_runs::ResearchRunState::Failed
        );

        let cancel_draft = research_runs::create(
            home.path(),
            "W329 cancel dispatch".into(),
            "bounded fixture".into(),
            ResearchRunBudget::from_config(&crate::config::DeepResearchConfig::default()),
        )
        .expect("create cancel fixture");
        let cancel_approved =
            research_runs::approve(home.path(), &cancel_draft.id, cancel_draft.revision)
                .expect("approve cancel fixture");
        let cancel_running =
            research_runs::claim_run(home.path(), &cancel_approved.id, cancel_approved.revision)
                .expect("claim cancel fixture");
        run_research(dispatch_args(ResearchAction::Cancel {
            id: cancel_running.id.clone(),
            revision: cancel_running.revision,
        }))
        .await
        .expect("cancel dispatch records a control request");
        let cancel_attempt = cancel_running
            .attempt_token
            .as_deref()
            .expect("claimed cancel run has attempt token");
        assert_eq!(
            research_runs::observe_control(home.path(), &cancel_running.id, cancel_attempt)
                .expect("executor observes dispatched cancel request"),
            research_runs::ResearchControl::Cancelled
        );
        let cancelled =
            research_runs::load(home.path(), &cancel_running.id).expect("load cancelled run");
        assert_eq!(cancelled.state, research_runs::ResearchRunState::Cancelled);
        run_research(dispatch_args(ResearchAction::Show {
            id: cancelled.id.clone(),
        }))
        .await
        .expect("show dispatch succeeds for cancelled run");
        run_research(dispatch_args(ResearchAction::List))
            .await
            .expect("list dispatch succeeds after full lifecycle");
    }

    #[tokio::test]
    async fn successful_lifecycle_dispatches_real_authorized_producer_and_decodes_wal_terminals_without_replay()
     {
        let _env = crate::test_env::lock();
        let home = tempfile::tempdir().expect("create isolated successful lifecycle home");
        std::fs::write(
            home.path().join("freedom.yaml"),
            "autonomy: full\ntokens:\n  max_per_request: 4096\ndeep_research:\n  max_rounds: 1\n  results_per_query: 1\n  pages_per_round: 1\n",
        )
        .expect("write isolated full-autonomy research configuration");

        let topic = "W329 successful CLI lifecycle";
        let draft = research_runs::create(
            home.path(),
            topic.into(),
            "controlled provider with bounded local search failure".into(),
            ResearchRunBudget {
                max_rounds: 1,
                results_per_query: 1,
                pages_per_round: 1,
                max_provider_tokens: 4096,
                max_wall_secs: 60,
                max_provider_calls: 3,
            },
        )
        .expect("create approved fixture through durable store");
        let approved = research_runs::approve(home.path(), &draft.id, draft.revision)
            .expect("approve successful fixture");
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = CountingProvider(Arc::clone(&calls));

        let (search_server, _restore_search_env) = controlled_empty_searxng().await;

        run_research_at(
            home.path(),
            dispatch_args(ResearchAction::Run {
                id: approved.id.clone(),
                revision: approved.revision,
            }),
            Some(&provider),
        )
        .await
        .expect("real controlled producer completes through dispatched lifecycle");

        let completed = research_runs::load(home.path(), &approved.id)
            .expect("load completed research lifecycle");
        assert_eq!(completed.state, research_runs::ResearchRunState::Completed);
        assert!(
            completed.effect_started,
            "successful run crosses the durable effect boundary"
        );
        assert!(
            completed
                .audit
                .iter()
                .any(|entry| entry.event == "completed")
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "plan plus synthesis are authorized"
        );

        let events = deep_research_lifecycle_payloads(home.path());
        let topic_hash = format!("{:016x}", xxhash_rust::xxh3::xxh3_64(topic.as_bytes()));
        assert_eq!(
            events.len(),
            2,
            "the isolated producer writes exactly its start and completion lifecycle receipts"
        );
        assert_eq!(
            events[0].0,
            crate::wal::events::EVENT_TYPE_DEEP_RESEARCH_STARTED,
            "start receipt precedes completion"
        );
        assert_eq!(
            events[0].1["topic_hash"].as_str(),
            Some(topic_hash.as_str())
        );
        assert_eq!(
            events[1].0,
            crate::wal::events::EVENT_TYPE_DEEP_RESEARCH_COMPLETED,
            "completion receipt follows the same exact-topic start"
        );
        assert_eq!(
            events[1].1["topic_hash"].as_str(),
            Some(topic_hash.as_str())
        );
        assert_eq!(events[1].1["rounds"].as_u64(), Some(1));
        assert_eq!(
            events[1].1["citation_count"].as_u64(),
            Some(0),
            "the controlled empty SearXNG response contributes no source citations"
        );
        search_server.verify().await;

        assert!(
            run_research_at(
                home.path(),
                dispatch_args(ResearchAction::Run {
                    id: completed.id.clone(),
                    revision: completed.revision,
                }),
                Some(&provider),
            )
            .await
            .is_err(),
            "a completed lifecycle cannot be replayed through the dispatcher"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "terminal replay refusal occurs before another provider invocation"
        );
    }

    #[tokio::test]
    async fn interrupted_lifecycle_decodes_started_wal_and_refuses_replay_after_terminal_failure() {
        let _env = crate::test_env::lock();
        let home = tempfile::tempdir().expect("create isolated interrupted lifecycle home");
        std::fs::write(
            home.path().join("freedom.yaml"),
            "autonomy: full\ntokens:\n  max_per_request: 4096\ndeep_research:\n  max_rounds: 1\n  results_per_query: 1\n  pages_per_round: 1\n",
        )
        .expect("write isolated full-autonomy research configuration");
        let topic = "W329 interrupted CLI lifecycle";
        let draft = research_runs::create(
            home.path(),
            topic.into(),
            "controlled provider interruption".into(),
            ResearchRunBudget {
                max_rounds: 1,
                results_per_query: 1,
                pages_per_round: 1,
                max_provider_tokens: 4096,
                max_wall_secs: 60,
                max_provider_calls: 3,
            },
        )
        .expect("create interrupted fixture");
        let approved = research_runs::approve(home.path(), &draft.id, draft.revision)
            .expect("approve interrupted fixture");
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = InterruptedProvider(Arc::clone(&calls));
        let (search_server, _restore_search_env) = controlled_empty_searxng().await;

        assert!(
            run_research_at(
                home.path(),
                dispatch_args(ResearchAction::Run {
                    id: approved.id.clone(),
                    revision: approved.revision,
                }),
                Some(&provider),
            )
            .await
            .is_err(),
            "a post-effect provider failure becomes an interrupted lifecycle"
        );
        let interrupted = research_runs::load(home.path(), &approved.id)
            .expect("load interrupted research lifecycle");
        assert_eq!(
            interrupted.state,
            research_runs::ResearchRunState::Interrupted
        );
        assert!(
            interrupted.effect_started,
            "interrupted run crossed the effect boundary"
        );
        assert!(
            interrupted
                .audit
                .iter()
                .any(|entry| entry.event == "interrupted_unknown_effect"),
            "post-effect provider failure persists the durable unknown-interruption audit contract"
        );
        let events = deep_research_lifecycle_payloads(home.path());
        let topic_hash = format!("{:016x}", xxhash_rust::xxh3::xxh3_64(topic.as_bytes()));
        assert_eq!(
            events.len(),
            1,
            "interrupted producer must not append a completion receipt"
        );
        assert_eq!(
            events[0].0,
            crate::wal::events::EVENT_TYPE_DEEP_RESEARCH_STARTED
        );
        assert_eq!(
            events[0].1["topic_hash"].as_str(),
            Some(topic_hash.as_str()),
            "the remaining start receipt belongs to this exact interrupted topic"
        );
        search_server.verify().await;
        assert!(
            run_research_at(
                home.path(),
                dispatch_args(ResearchAction::Run {
                    id: interrupted.id.clone(),
                    revision: interrupted.revision,
                }),
                Some(&provider),
            )
            .await
            .is_err(),
            "interrupted lifecycle remains terminal until a separate operator recovery path exists"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "terminal interruption refusal occurs before another provider invocation"
        );
    }

    #[tokio::test]
    async fn pre_effect_config_setup_failure_persists_failed_without_provider_or_http_effect() {
        let home = tempfile::tempdir().unwrap();
        std::fs::write(home.path().join("freedom.yaml"), "deep_research: [\n").unwrap();
        let budget = ResearchRunBudget {
            max_rounds: 1,
            results_per_query: 1,
            pages_per_round: 1,
            max_provider_tokens: 1,
            max_wall_secs: 60,
            max_provider_calls: 3,
        };
        let draft =
            research_runs::create(home.path(), "topic".into(), "scope".into(), budget).unwrap();
        let approved = research_runs::approve(home.path(), &draft.id, draft.revision).unwrap();
        let _error = run(
            home.path(),
            &approved.id,
            approved.revision,
            &OutputFormat::Table,
            None,
        )
        .await
        .unwrap_err();
        let stored = research_runs::load(home.path(), &approved.id).unwrap();
        assert_eq!(stored.state, research_runs::ResearchRunState::Failed);
        assert!(
            !stored.effect_started,
            "invalid configuration must fail before provider or HTTP effect"
        );
    }
}
