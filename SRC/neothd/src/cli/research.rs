//! `neoth research` — explicit, durable operator lifecycle for deep research.
//!
//! `create` only snapshots bounded intent. `approve` is deliberately separate
//! from `run`; no provider or HTTP authorizer is constructed before `run`.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::cli::OutputFormat;
use crate::daemon::research_runs::{self, ResearchRun, ResearchRunBudget};

/// Counts every real producer `complete` call after the ordinary cost boundary.
/// Bound: plan + at most one extraction/provider call per fetched page + one
/// continue check between rounds + final synthesis.
struct RunCallBudget<'a> { inner: &'a dyn crate::providers::Provider, remaining: AtomicUsize }
#[async_trait::async_trait]
impl crate::providers::Provider for RunCallBudget<'_> {
    fn name(&self)->&'static str { self.inner.name() }
    fn default_model(&self)->Option<&str>{self.inner.default_model()}
    async fn complete(&self, req:crate::providers::Request)->Result<crate::providers::Completion>{
        self.remaining.fetch_update(Ordering::SeqCst,Ordering::SeqCst,|left|left.checked_sub(1)).map_err(|_|anyhow::anyhow!("immutable research provider-call budget exhausted"))?;
        self.inner.complete(req).await
    }
}

struct DurableControl<'a> { home: &'a std::path::Path, id: &'a str, attempt: &'a str }
impl crate::tools::deep_research::ResearchRunControl for DurableControl<'_> {
    fn checkpoint(&self, phase: &'static str) -> Result<()> {
        match research_runs::observe_control(self.home, self.id, self.attempt)? {
            research_runs::ResearchControl::Cancelled => anyhow::bail!("research run cancelled before {phase}"),
            // Pause is intentionally cooperative: preserve the current bounded
            // round, checkpoint it, then consume the request at that boundary.
            research_runs::ResearchControl::PauseRequested if matches!(phase, "continue_check" | "synthesis") => { research_runs::pause_at_boundary(self.home,self.id,self.attempt)?; anyhow::bail!("research run paused at completed-round boundary before {phase}") }
            research_runs::ResearchControl::Continue | research_runs::ResearchControl::PauseRequested => research_runs::begin_effect(self.home, self.id, self.attempt).context("persist research effect boundary")
        }
    }
    fn resume_checkpoint(&self) -> Result<Option<crate::tools::deep_research::ResearchCheckpoint>> { Ok(Some(research_runs::load(self.home, self.id)?.checkpoint)) }
    fn persist_checkpoint(&self, checkpoint: &crate::tools::deep_research::ResearchCheckpoint) -> Result<()> { research_runs::checkpoint(self.home, self.id, self.attempt, checkpoint.clone()) }
    fn round_completed(&self) -> Result<()> { if matches!(research_runs::observe_control(self.home,self.id,self.attempt)?,research_runs::ResearchControl::PauseRequested) { research_runs::pause_at_boundary(self.home,self.id,self.attempt)?; anyhow::bail!("research run paused after durable round checkpoint") } Ok(()) }
}

#[derive(Args, Debug, Clone)]
pub struct ResearchArgs { #[command(subcommand)] pub action: ResearchAction, #[arg(skip)] pub output: OutputFormat }

#[derive(Subcommand, Debug, Clone)]
pub enum ResearchAction {
    Create { topic: String, #[arg(long, default_value = "operator-requested bounded web research")] scope: String },
    Show { id: String },
    List,
    Approve { id: String, #[arg(long)] revision: u64 },
    Run { id: String, #[arg(long)] revision: u64 },
    Pause { id: String, #[arg(long)] revision: u64 },
    Resume { id: String, #[arg(long)] revision: u64 },
    Cancel { id: String, #[arg(long)] revision: u64 },
}

pub async fn run_research(args: ResearchArgs) -> Result<()> {
    let home = crate::config::FreedomConfig::default_neoth_home();
    match args.action {
        ResearchAction::Create { topic, scope } => {
            // Configuration is read exactly once and the resolved caps are stored
            // immutably; later freedom.yaml changes cannot widen this run.
            let cfg = crate::config::FreedomConfig::load_from_path_or_default(&home.join("freedom.yaml"))?;
            let mut budget=ResearchRunBudget::from_config(&cfg.deep_research); budget.max_provider_tokens=cfg.tokens.max_per_request; budget.max_wall_secs=900;
            render(&research_runs::create(&home, topic, scope, budget)?, &args.output)
        }
        ResearchAction::Show { id } => render(&research_runs::load(&home, &id)?, &args.output),
        ResearchAction::List => render_list(&research_runs::list(&home)?, &args.output),
        ResearchAction::Approve { id, revision } => render(&research_runs::approve(&home, &id, revision)?, &args.output),
        ResearchAction::Pause { id, revision } => render(&research_runs::request_control(&home, &id, revision, "pause")?, &args.output),
        ResearchAction::Cancel { id, revision } => render(&research_runs::request_control(&home, &id, revision, "cancel")?, &args.output),
        ResearchAction::Resume { id, revision } => run(&home, &id, revision, &args.output).await,
        ResearchAction::Run { id, revision } => run(&home, &id, revision, &args.output).await,
    }
}

async fn run(home: &std::path::Path, id: &str, revision: u64, output: &OutputFormat) -> Result<()> {
    let claimed = research_runs::claim_run(home, id, revision)?;
    if matches!(claimed.state, research_runs::ResearchRunState::Cancelled) { return render(&claimed, output); }
    let attempt = claimed.attempt_token.as_deref().context("claimed research run missing executor attempt token")?;
    // Resolve current provider credentials only after the durable approval/claim.
    // The immutable run budget is reconstituted into a local config copy so the
    // existing engine receives its normal bounded producer, without reading
    // mutable operator caps again.
    let mut cfg = match crate::config::FreedomConfig::load_from_path_or_default(&home.join("freedom.yaml")) { Ok(value)=>value, Err(error)=>return Err(pre_effect_failure(home,id,attempt,error)) };
    cfg.deep_research.max_rounds = Some(claimed.budget.max_rounds);
    cfg.deep_research.results_per_query = Some(claimed.budget.results_per_query);
    cfg.deep_research.pages_per_round = Some(claimed.budget.pages_per_round);
    let provider = match crate::providers::from_config_for_utility_at(&cfg, home).await { Ok(value)=>value, Err(error)=>return Err(pre_effect_failure(home,id,attempt,error.context("resolve approved research provider"))) };
    let search_provider = crate::tools::deep_research::resolve_search_provider();
    let search_key = match crate::tools::deep_research::resolve_search_key(search_provider) { Ok(value)=>value, Err(error)=>return Err(pre_effect_failure(home,id,attempt,error)) };
    let wal_dir = home.join("wal"); if let Err(error)=std::fs::create_dir_all(&wal_dir) { return Err(pre_effect_failure(home,id,attempt,error.into())); }
    let segment = crate::wal::writer::unique_standalone_segment_path(&wal_dir, "research-run");
    let (writer, join) = match crate::wal::writer::spawn_for_home(segment, home.to_path_buf()) { Ok(value)=>value, Err(error)=>return Err(pre_effect_failure(home,id,attempt,error.into())) };
    let provider_auth = crate::providers::cost_authorization::ProviderCallAuthorizer::interactive(cfg.autonomy_policy(), Some(writer.clone()), claimed.budget.max_provider_tokens).with_usage_home(home.to_path_buf());
    let wrapped = crate::providers::cost_authorization::CostAuthorizingProvider::new(provider.as_ref(), provider_auth, crate::providers::utility_model_for_config(&cfg), "deep_research_run");
    let budgeted = RunCallBudget { inner:&wrapped, remaining:AtomicUsize::new(claimed.budget.max_provider_calls as usize) };
    let http = match crate::tools::external_http::ExternalHttpAuthorizer::interactive(cfg.autonomy_policy()) { Ok(value)=>value, Err(error)=> { drop(budgeted); drop(wrapped); drop(writer); let wal=join.await.context("join research lifecycle WAL writer"); return match wal { Ok(())=>Err(pre_effect_failure(home,id,attempt,error)), Err(wal_error)=>Err(anyhow::anyhow!("research setup failed: {error:#}; WAL finalization failed: {wal_error:#}")) }; } };
    // `run_deep_research` is the existing real producer: this CLI never
    // substitutes a proposal/ledger for a network execution.
    let control = DurableControl { home, id, attempt };
    let result = match tokio::time::timeout(std::time::Duration::from_secs(claimed.budget.max_wall_secs), crate::tools::deep_research::run_deep_research_controlled(&claimed.topic, &budgeted, &search_key, search_provider, &cfg.deep_research, &writer, &http, Some(&control))).await { Ok(result)=>result, Err(_)=>Err(anyhow::anyhow!("immutable research wall-time budget exhausted")) };
    drop(budgeted); drop(wrapped); drop(http); drop(writer); let wal_result = join.await.context("join research lifecycle WAL writer");
    match result {
        Ok(report) => {
            if let Err(wal)=wal_result { return Err(interrupted_failure(home,id,attempt,anyhow::anyhow!("research completed but WAL finalization failed: {wal:#}"))); }
            let finished = match research_runs::complete(home, id, attempt, &report.article, &report.citations) { Ok(value)=>value, Err(error)=>return Err(interrupted_failure(home,id,attempt,error.context("persist completed research report"))) };
            render(&finished, output)?;
            Ok(())
        }
        Err(error) => {
            // A provider/search/fetch may already have crossed the network
            // boundary. Persist an explicit unknown-interruption state and do
            // not silently replay it on another `run` invocation.
            let wal_error=wal_result.err(); let current = research_runs::load(home, id)?;
            if matches!(current.state, research_runs::ResearchRunState::Paused | research_runs::ResearchRunState::Cancelled) { return render(&current, output); }
            if !current.effect_started { return Err(pre_effect_failure(home,id,attempt,error)); }
            let terminal=research_runs::fail_interrupted(home, id, attempt);
            match (terminal,wal_error) { (Ok(_),None)=>Err(error).context("approved research run interrupted; reissue refused pending operator inspection"), (Err(persist),None)=>Err(anyhow::anyhow!("research failure: {error:#}; terminal persistence failed: {persist:#}")), (Ok(_),Some(wal))=>Err(anyhow::anyhow!("research failure: {error:#}; WAL finalization failed: {wal:#}")), (Err(persist),Some(wal))=>Err(anyhow::anyhow!("research failure: {error:#}; WAL finalization failed: {wal:#}; terminal persistence failed: {persist:#}")) }
        }
    }
}

fn pre_effect_failure(home:&std::path::Path,id:&str,attempt:&str,error:anyhow::Error)->anyhow::Error { match research_runs::fail_pre_effect(home,id,attempt) { Ok(())=>error, Err(persist)=>anyhow::anyhow!("research setup failed: {error:#}; pre-effect terminal persistence failed: {persist:#}") } }
fn interrupted_failure(home:&std::path::Path,id:&str,attempt:&str,error:anyhow::Error)->anyhow::Error { match research_runs::fail_interrupted(home,id,attempt) { Ok(_)=>error, Err(persist)=>anyhow::anyhow!("research terminal transition failed: {error:#}; interrupted persistence failed: {persist:#}") } }

fn render(run: &ResearchRun, output: &OutputFormat) -> Result<()> { match output { OutputFormat::Json|OutputFormat::Jsonl => println!("{}",serde_json::to_string(run)?), OutputFormat::Table => { println!("{}  rev={}  state={:?}  rounds={}/{}",run.id,run.revision,run.state,run.completed_rounds,run.budget.max_rounds); if let Some(report)=&run.report { println!("\n{report}"); for (index,citation) in run.citations.iter().enumerate(){println!("[{}] {} — {}",index+1,citation.title,citation.url);} } } }; Ok(()) }
fn render_list(runs:&[ResearchRun], output:&OutputFormat)->Result<()> { match output { OutputFormat::Json|OutputFormat::Jsonl=>println!("{}",serde_json::to_string(runs)?), OutputFormat::Table=>for run in runs { println!("{}  rev={}  state={:?}  {}",run.id,run.revision,run.state,run.topic); } }; Ok(()) }

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use crate::providers::Provider as _;
    use std::sync::Arc;

    struct CountingProvider(Arc<AtomicUsize>);
    #[async_trait::async_trait]
    impl crate::providers::Provider for CountingProvider {
        fn name(&self) -> &'static str { "research-call-cap-test" }
        async fn complete(&self, _req: crate::providers::Request) -> Result<crate::providers::Completion> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(crate::providers::Completion { termination: Default::default(), text: "ok".into(), identity: Default::default(), model: "test".into(), latency: std::time::Duration::ZERO, input_tokens: None, output_tokens: None, cache_creation_tokens: None, cache_read_tokens: None, usage_measurements: None })
        }
    }

    #[tokio::test]
    async fn provider_call_cap_rejects_next_call_without_inner_invocation() {
        let calls=Arc::new(AtomicUsize::new(0)); let provider=CountingProvider(Arc::clone(&calls));
        let capped=RunCallBudget { inner:&provider, remaining:AtomicUsize::new(1) };
        capped.complete(crate::providers::Request::default()).await.unwrap();
        assert!(capped.complete(crate::providers::Request::default()).await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst),1,"exhausted cap must reject before inner provider invocation");
    }

    #[test]
    fn research_parser_requires_revision_for_mutations_and_keeps_read_commands() {
        assert!(crate::cli::Cli::try_parse_from(["neoth","research","approve","rr-0123456789abcdef"]).is_err());
        assert!(crate::cli::Cli::try_parse_from(["neoth","research","run","rr-0123456789abcdef"]).is_err());
        assert!(crate::cli::Cli::try_parse_from(["neoth","research","pause","rr-0123456789abcdef"]).is_err());
        assert!(crate::cli::Cli::try_parse_from(["neoth","research","resume","rr-0123456789abcdef"]).is_err());
        assert!(crate::cli::Cli::try_parse_from(["neoth","research","cancel","rr-0123456789abcdef"]).is_err());
        assert!(crate::cli::Cli::try_parse_from(["neoth","research","create","topic"]).is_ok());
        assert!(crate::cli::Cli::try_parse_from(["neoth","research","show","rr-0123456789abcdef"]).is_ok());
        assert!(crate::cli::Cli::try_parse_from(["neoth","research","list"]).is_ok());
    }

    #[tokio::test]
    async fn pre_effect_config_setup_failure_persists_failed_without_provider_or_http_effect() {
        let home=tempfile::tempdir().unwrap();
        std::fs::write(home.path().join("freedom.yaml"), "deep_research: [\n").unwrap();
        let budget=ResearchRunBudget { max_rounds:1, results_per_query:1, pages_per_round:1, max_provider_tokens:1, max_wall_secs:60, max_provider_calls:3 };
        let draft=research_runs::create(home.path(),"topic".into(),"scope".into(),budget).unwrap();
        let approved=research_runs::approve(home.path(),&draft.id,draft.revision).unwrap();
        let _error=run(home.path(),&approved.id,approved.revision,&OutputFormat::Table).await.unwrap_err();
        let stored=research_runs::load(home.path(),&approved.id).unwrap();
        assert_eq!(stored.state,research_runs::ResearchRunState::Failed);
        assert!(!stored.effect_started,"invalid configuration must fail before provider or HTTP effect");
    }
}
