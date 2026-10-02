//! Explicit, bounded NCT-01 live-route baseline harness.
//!
//! This command is default-off.  It dispatches only the two public benign
//! recipe rows through the normal `chat` command, then projects the existing
//! authoritative provider lifecycle WAL frames into a content-free receipt.
//! It neither selects a provider nor grants consent, egress, or budget.

use std::{
    collections::HashSet,
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use clap::Args;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::cli::{Cli, Commands, OutputFormat};

pub const NCT_LIVE_RECIPE_SCHEMA_V1: &str = "neoth.nct-live-route-recipe.v1";
const MAX_ROWS: usize = 2;
const MAX_PROMPT_BYTES: usize = 256;
const NCT_MAX_TOKENS_PER_REQUEST: u32 = 1_024;
const NCT_MAX_OUTPUT_TOKENS: u32 = 256;
const BUILTIN_RECIPE: &str =
    include_str!("../../tests/fixtures/nct_baseline/nct_live_recipe_v1.json");

#[derive(Args, Debug, Clone)]
pub struct NctBaselineArgs {
    /// Use the reviewed public benign two-route recipe shipped with NEOTH.
    #[arg(long, conflicts_with = "recipe")]
    pub builtin_recipe: bool,
    /// Operator-reviewed live recipe. It may only use public benign prompts.
    #[arg(long)]
    pub recipe: Option<PathBuf>,
    /// Required: perform the two real provider calls. Without this flag, validate only.
    #[arg(long)]
    pub execute: bool,
    /// Direct-route config; its consent, egress and budget remain authoritative.
    #[arg(long, requires = "execute")]
    pub direct_config: Option<PathBuf>,
    /// Fallback-route config; it must contain one approved fallback hop.
    #[arg(long, requires = "execute")]
    pub fallback_config: Option<PathBuf>,
    /// Directory for content-free receipts and exclusive per-row WAL segments.
    #[arg(long)]
    pub receipt_dir: PathBuf,
    #[arg(long, default_value = "json")]
    pub output: OutputFormat,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Recipe {
    schema: String,
    recipe_id: String,
    recipe_revision: String,
    rows: Vec<RecipeRow>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecipeRow {
    id: String,
    split: Split,
    route: Route,
    prompt: String,
    expected_terminal: Terminal,
}
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Split {
    Train,
    Holdout,
}
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Route {
    Direct,
    Fallback,
}
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Terminal {
    Success,
    Blocked,
}

enum NctRunner<'a> {
    Production(std::marker::PhantomData<&'a ()>),
    #[cfg(test)]
    Hermetic {
        direct: &'a dyn crate::providers::Provider,
        fallback: &'a dyn crate::providers::Provider,
    },
}

#[derive(Debug, Serialize)]
struct Receipt<'a> {
    schema: &'static str,
    recipe_id: &'a str,
    row_id: &'a str,
    split: Split,
    route: Route,
    expected_terminal: Terminal,
    recipe_revision: &'a str,
    recipe_sha256: String,
    producer_revision: String,
    // All remaining fields are projected from existing provider lifecycle frames.
    provider: String,
    wire_model: String,
    request_binding_sha256: String,
    invocation_id: String,
    prompt_bytes: u64,
    system_bytes: u64,
    input_tokens: Option<u32>,
    output_tokens: Option<u32>,
    cache_creation_tokens: Option<u32>,
    cache_read_tokens: Option<u32>,
    latency_ms: Option<u64>,
    cost_status: &'static str,
    terminal: Terminal,
    route_evidence: &'static str,
}

/// Validate recipe boundaries before config/provider construction. The recipe
/// is not a corpus and no synthetic fixture case ID is accepted here.
fn validate_recipe(recipe: &Recipe) -> Result<()> {
    ensure!(
        recipe.schema == NCT_LIVE_RECIPE_SCHEMA_V1,
        "unsupported NCT live recipe schema"
    );
    ensure!(
        !recipe.recipe_id.trim().is_empty() && recipe.recipe_id.len() <= 96,
        "invalid recipe id"
    );
    ensure!(
        recipe.recipe_revision.len() == 64
            && recipe
                .recipe_revision
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit()),
        "NCT recipe must carry an immutable recipe revision"
    );
    ensure!(
        recipe.rows.len() == MAX_ROWS,
        "NCT live recipe must contain exactly two rows"
    );
    let mut direct = 0;
    let mut fallback = 0;
    let mut ids = HashSet::new();
    for row in &recipe.rows {
        ensure!(
            !row.id.trim().is_empty()
                && row.id.len() <= 96
                && row.id.bytes().all(|byte| byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || byte == b'-'
                    || byte == b'_'),
            "NCT row id must be a lowercase ASCII slug"
        );
        // Device basenames remain reserved on Windows even with the receipt
        // extension. Reject them before creating directories or dispatching.
        let reserved_device = matches!(row.id.as_str(), "con" | "prn" | "aux" | "nul")
            || ["com", "lpt"].into_iter().any(|prefix| {
                row.id
                    .strip_prefix(prefix)
                    .is_some_and(|suffix| matches!(suffix.as_bytes(), [b'1'..=b'9']))
            });
        ensure!(
            !reserved_device,
            "NCT row id is a reserved Windows device basename"
        );
        ensure!(ids.insert(row.id.as_str()), "duplicate NCT recipe row id");
        ensure!(
            row.prompt.is_ascii()
                && !row.prompt.trim().is_empty()
                && row.prompt.len() <= MAX_PROMPT_BYTES,
            "NCT live recipe prompt exceeds public benign bound"
        );
        match row.route {
            Route::Direct => direct += 1,
            Route::Fallback => fallback += 1,
        }
    }
    ensure!(
        direct == 1 && fallback == 1,
        "NCT live recipe requires one direct and one fallback row"
    );
    Ok(())
}

pub async fn run_nct_baseline(args: NctBaselineArgs) -> Result<()> {
    run_nct_baseline_with(args, NctRunner::Production(std::marker::PhantomData)).await
}

async fn run_nct_baseline_with(args: NctBaselineArgs, runner: NctRunner<'_>) -> Result<()> {
    let recipe_bytes = match (&args.recipe, args.builtin_recipe) {
        (Some(path), false) => {
            std::fs::read(path).with_context(|| format!("read NCT recipe {}", path.display()))?
        }
        (None, true) => BUILTIN_RECIPE.as_bytes().to_vec(),
        _ => bail!("choose exactly one of --builtin-recipe or --recipe"),
    };
    let recipe: Recipe =
        serde_json::from_slice(&recipe_bytes).context("parse bounded NCT live recipe")?;
    validate_recipe(&recipe)?;
    if !args.execute {
        return render_plan(&recipe, &recipe_bytes, args.output);
    }
    let direct_path = args
        .direct_config
        .as_deref()
        .context("--execute requires --direct-config and --fallback-config")?;
    let fallback_path = args
        .fallback_config
        .as_deref()
        .context("--execute requires --direct-config and --fallback-config")?;
    let direct_config = crate::config::FreedomConfig::load_public_from_path(direct_path)
        .context("load direct NCT config for admission")?;
    let fallback_config = crate::config::FreedomConfig::load_public_from_path(fallback_path)
        .context("load fallback NCT config for admission")?;
    ensure!(
        (1..=NCT_MAX_TOKENS_PER_REQUEST).contains(&direct_config.tokens.max_per_request)
            && (1..=NCT_MAX_TOKENS_PER_REQUEST).contains(&fallback_config.tokens.max_per_request),
        "NCT requires 1 <= tokens.max_per_request <= {NCT_MAX_TOKENS_PER_REQUEST}"
    );
    admit_route(&direct_config, Route::Direct)?;
    admit_route(&fallback_config, Route::Fallback)?;
    std::fs::create_dir_all(&args.receipt_dir).context("create NCT receipt directory")?;
    preflight_receipt_targets(&args.receipt_dir, &recipe)?;
    for row in &recipe.rows {
        let config_path = match row.route {
            Route::Direct => direct_path,
            Route::Fallback => fallback_path,
        };
        let config = match row.route {
            Route::Direct => &direct_config,
            Route::Fallback => &fallback_config,
        };
        run_row(
            &args,
            &recipe,
            &recipe_bytes,
            row,
            config_path,
            config,
            &runner,
        )
        .await?;
    }
    Ok(())
}

/// Reject every pre-existing destination before any row can allocate a WAL or
/// dispatch a provider. Lowercase validated IDs make this check stable on
/// case-insensitive filesystems as well as POSIX filesystems.
fn preflight_receipt_targets(dir: &Path, recipe: &Recipe) -> Result<()> {
    for row in &recipe.rows {
        let target = dir.join(format!("{}.receipt.json", row.id));
        match std::fs::symlink_metadata(&target) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("inspect NCT receipt destination"),
            Ok(_) => bail!("refuse to overwrite NCT receipt {}", target.display()),
        }
    }
    Ok(())
}

fn admit_route(config: &crate::config::FreedomConfig, route: Route) -> Result<()> {
    match route {
        Route::Direct => ensure!(
            config.fallback.chain.is_empty() || config.fallback.max_hops == 0,
            "direct NCT row refuses configured fallback"
        ),
        Route::Fallback => ensure!(
            !config.fallback.chain.is_empty() && config.fallback.max_hops == 1,
            "fallback NCT row requires exactly one configured fallback hop"
        ),
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)] // row custody inputs stay explicit at the effect boundary
async fn run_row(
    args: &NctBaselineArgs,
    recipe: &Recipe,
    recipe_bytes: &[u8],
    row: &RecipeRow,
    config_path: &Path,
    config: &crate::config::FreedomConfig,
    runner: &NctRunner<'_>,
) -> Result<()> {
    let config_home = config_path
        .parent()
        .context("NCT route config requires a parent home")?
        .to_path_buf();
    let wal_dir = config_home.join("wal");
    std::fs::create_dir_all(&wal_dir).context("create existing NEOTH WAL directory for NCT row")?;
    let wal = crate::wal::writer::unique_standalone_segment_path(&wal_dir, "nct-live");
    let mut argv = vec![
        "neoth".to_owned(),
        "chat".to_owned(),
        "--wal-segment".to_owned(),
        wal.display().to_string(),
    ];
    argv.extend(["--config".to_owned(), config_path.display().to_string()]);
    argv.push(row.prompt.clone());
    let cli = <Cli as clap::Parser>::try_parse_from(argv)
        .context("build ordinary chat invocation from NCT recipe")?;
    let Commands::Chat(chat_args) = cli.command else {
        unreachable!("NCT argv constructs chat only")
    };
    // Preserve an audited provider failure long enough to project its paired
    // terminal; after the immutable receipt is written, report the failed row.
    let chat_result = match runner {
        NctRunner::Production(_) => {
            Box::pin(crate::cli::chat::run_chat_bounded_output(
                chat_args,
                config,
                NCT_MAX_OUTPUT_TOKENS,
            ))
            .await
        }
        #[cfg(test)]
        NctRunner::Hermetic { direct, fallback } => {
            Box::pin(crate::cli::chat::run_chat_with_output_cap(
                chat_args,
                config.clone(),
                match row.route {
                    Route::Direct => *direct,
                    Route::Fallback => *fallback,
                },
                NCT_MAX_OUTPUT_TOKENS,
            ))
            .await
        }
    };
    let projection = project_terminal(&wal, row.route)?;
    let receipt = Receipt {
        schema: "neoth.nct-live-route-receipt.v1",
        recipe_id: &recipe.recipe_id,
        row_id: &row.id,
        split: row.split,
        route: row.route,
        expected_terminal: row.expected_terminal,
        recipe_revision: &recipe.recipe_revision,
        recipe_sha256: sha256_hex(recipe_bytes),
        producer_revision: producer_revision(),
        provider: projection.provider,
        wire_model: projection.wire_model,
        request_binding_sha256: projection.request_binding_sha256,
        invocation_id: projection.invocation_id,
        prompt_bytes: projection.prompt_bytes,
        system_bytes: projection.system_bytes,
        input_tokens: projection.input_tokens,
        output_tokens: projection.output_tokens,
        cache_creation_tokens: projection.cache_creation_tokens,
        cache_read_tokens: projection.cache_read_tokens,
        latency_ms: projection.latency_ms,
        cost_status: "unknown",
        terminal: projection.terminal,
        route_evidence: projection.route_evidence,
    };
    write_receipt_new(&args.receipt_dir, &row.id, &receipt)?;
    ensure!(
        matches!(
            (row.expected_terminal, receipt.terminal),
            (Terminal::Success, Terminal::Success) | (Terminal::Blocked, Terminal::Blocked)
        ),
        "NCT row terminal differs from immutable recipe expectation"
    );
    chat_result.context("NCT chat producer returned an audited terminal error")
}

fn write_receipt_new(dir: &Path, row_id: &str, receipt: &Receipt<'_>) -> Result<()> {
    let target = dir.join(format!("{row_id}.receipt.json"));
    let bytes = serde_json::to_vec_pretty(receipt).context("serialize content-free NCT receipt")?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&target)
        .with_context(|| format!("refuse to overwrite NCT receipt {}", target.display()))?;
    file.write_all(&bytes).context("write new NCT receipt")?;
    Ok(())
}

struct Projection {
    provider: String,
    wire_model: String,
    request_binding_sha256: String,
    invocation_id: String,
    prompt_bytes: u64,
    system_bytes: u64,
    input_tokens: Option<u32>,
    output_tokens: Option<u32>,
    cache_creation_tokens: Option<u32>,
    cache_read_tokens: Option<u32>,
    latency_ms: Option<u64>,
    terminal: Terminal,
    route_evidence: &'static str,
}

/// Scans only the fresh exclusive segment and accepts a terminal only when it
/// is the typed v1 provider lifecycle terminal paired to an owned request.
fn project_terminal(wal: &Path, route: Route) -> Result<Projection> {
    let bytes = std::fs::read(wal).with_context(|| format!("read NCT WAL {}", wal.display()))?;
    let mut fallback_seen = false;
    let mut requests = HashSet::new();
    let mut terminal = None;
    crate::wal::scan::for_each_frame(&bytes, |_, frame| {
        if !matches!(
            frame.header.event_type,
            crate::wal::events::EVENT_TYPE_PROVIDER_REQUEST
                | crate::wal::events::EVENT_TYPE_PROVIDER_RESPONSE
                | crate::wal::events::EVENT_TYPE_PROVIDER_ERROR
                | crate::wal::events::EVENT_TYPE_PROVIDER_FALLBACK_ATTEMPTED
        ) {
            return Ok(());
        }
        if frame.header.event_type == crate::wal::events::EVENT_TYPE_PROVIDER_FALLBACK_ATTEMPTED {
            fallback_seen = true;
            return Ok(());
        }
        let value: serde_json::Value =
            serde_json::from_slice(frame.payload).context("decode provider lifecycle payload")?;
        ensure!(
            value.get("schema").and_then(serde_json::Value::as_str)
                == Some("neoth.provider-lifecycle.v1"),
            "NCT refuses untyped lifecycle frame"
        );
        let invocation = value
            .get("invocation_id")
            .and_then(serde_json::Value::as_str)
            .context("missing lifecycle invocation id")?
            .to_owned();
        let binding = value
            .get("request_binding_sha256")
            .and_then(serde_json::Value::as_str)
            .context("missing lifecycle request binding")?
            .to_owned();
        if frame.header.event_type == crate::wal::events::EVENT_TYPE_PROVIDER_REQUEST {
            requests.insert((invocation, binding));
        } else {
            ensure!(
                requests.contains(&(invocation.clone(), binding.clone())),
                "NCT terminal has no paired lifecycle request"
            );
            terminal = Some(value);
        }
        Ok(())
    })
    .context("scan exclusive NCT WAL segment")?;
    let value = terminal.context("NCT segment has no paired provider terminal")?;
    let string = |name: &str| {
        value
            .get(name)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .filter(|v| !v.is_empty())
            .context("missing lifecycle identity")
    };
    let number = |name: &str| value.get(name).and_then(serde_json::Value::as_u64);
    let route_evidence = match route {
        Route::Direct => {
            ensure!(
                !fallback_seen,
                "direct recipe row crossed a fallback attempt"
            );
            "direct_completed"
        }
        Route::Fallback if fallback_seen => "fallback_exercised",
        Route::Fallback => "fallback_not_exercised_primary_succeeded",
    };
    Ok(Projection {
        provider: string("provider")?,
        wire_model: string("wire_model")?,
        request_binding_sha256: string("request_binding_sha256")?,
        invocation_id: string("invocation_id")?,
        prompt_bytes: number("prompt_bytes").context("missing prompt byte count")?,
        system_bytes: number("system_bytes").context("missing system byte count")?,
        input_tokens: number("input_tokens").map(|v| v as u32),
        output_tokens: number("output_tokens").map(|v| v as u32),
        cache_creation_tokens: number("cache_creation_tokens").map(|v| v as u32),
        cache_read_tokens: number("cache_read_tokens").map(|v| v as u32),
        latency_ms: number("latency_ms"),
        terminal: if value.get("ok").and_then(serde_json::Value::as_bool) == Some(true) {
            Terminal::Success
        } else {
            Terminal::Blocked
        },
        route_evidence,
    })
}
fn producer_revision() -> String {
    option_env!("NEOTH_SOURCE_HEAD")
        .or(option_env!("GITHUB_SHA"))
        .or(option_env!("VERGEN_GIT_SHA"))
        .unwrap_or("unknown")
        .to_owned()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn render_plan(recipe: &Recipe, recipe_bytes: &[u8], output: OutputFormat) -> Result<()> {
    let value = serde_json::json!({"schema":"neoth.nct-live-route-plan.v1","recipe_id":recipe.recipe_id,"recipe_revision":recipe.recipe_revision,"recipe_sha256":sha256_hex(recipe_bytes),"producer_revision":producer_revision(),"execute_required":true,"rows":recipe.rows.iter().map(|r| serde_json::json!({"id":r.id,"split":r.split,"route":r.route,"prompt_bytes":r.prompt.len(),"configured_input_token_cap_required":true,"cost_status":"unknown"})).collect::<Vec<_>>()});
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string_pretty(&value)?)
        }
        OutputFormat::Table => println!(
            "NCT live baseline recipe validated; rerun with --execute after ordinary chat consent/provider/budget gates are ready."
        ),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::Duration;

    use crate::config::FreedomConfig;
    use crate::consent::ProviderKind;
    use crate::permissions::AutonomyLevel;
    use crate::providers::{
        Completion, CompletionUsageMeasurements, Provider, ProviderRequestControls, Request,
    };
    use async_trait::async_trait;
    use clap::Parser;

    const NCT_TEST_MODEL: &str = "nct-hermetic-model";

    struct CountingLeaf {
        calls: Arc<AtomicUsize>,
        output_caps: Arc<Mutex<Vec<Option<u32>>>>,
    }
    #[async_trait]
    impl Provider for CountingLeaf {
        fn name(&self) -> &'static str {
            "nct-hermetic-leaf"
        }
        fn default_model(&self) -> Option<&str> {
            Some(NCT_TEST_MODEL)
        }
        fn request_controls(&self) -> ProviderRequestControls {
            ProviderRequestControls::OUTPUT_TOKEN_LIMIT
        }
        fn output_token_ceiling(&self, request: &Request) -> Option<u32> {
            request.max_output_tokens
        }
        async fn complete(&self, request: Request) -> Result<Completion> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.output_caps
                .lock()
                .expect("output cap mutex")
                .push(request.max_output_tokens);
            Ok(Completion {
                termination: Default::default(),
                text: "NCT hermetic reply".into(),
                identity: Default::default(),
                model: NCT_TEST_MODEL.into(),
                latency: Duration::from_millis(7),
                input_tokens: Some(12),
                output_tokens: Some(8),
                cache_creation_tokens: Some(3),
                cache_read_tokens: Some(5),
                usage_measurements: Some(CompletionUsageMeasurements::provider_reported(
                    Some(12),
                    Some(8),
                    Some(3),
                    Some(5),
                    None,
                    Some(7),
                )?),
            })
        }
    }

    struct QuotaLeaf;
    #[async_trait]
    impl Provider for QuotaLeaf {
        fn name(&self) -> &'static str {
            "nct-hermetic-quota"
        }
        fn default_model(&self) -> Option<&str> {
            Some(NCT_TEST_MODEL)
        }
        fn request_controls(&self) -> ProviderRequestControls {
            ProviderRequestControls::OUTPUT_TOKEN_LIMIT
        }
        fn output_token_ceiling(&self, request: &Request) -> Option<u32> {
            request.max_output_tokens
        }
        async fn complete(&self, _: Request) -> Result<Completion> {
            Err(anyhow::Error::new(crate::providers::quota::QuotaError {
                provider: "nct-hermetic-quota",
                retry_after: Some(Duration::from_secs(1)),
                body: "hermetic quota".into(),
            }))
        }
    }

    fn normal_config() -> FreedomConfig {
        let mut config = FreedomConfig {
            provider_kind: Some(ProviderKind::ClaudeCli),
            provider_model: Some(NCT_TEST_MODEL.into()),
            autonomy: AutonomyLevel::Full,
            review_gate_enabled: false,
            steps_completed: vec![1, 2, 3, 4, 5, 6, 7],
            ..Default::default()
        };
        config.council.disabled = Some(true);
        config.memory.recall_shortcut = false;
        config
    }

    fn chat_args(home: &Path, wal: &Path, prompt: &str) -> crate::cli::chat::ChatArgs {
        let cli = Cli::try_parse_from([
            "neoth",
            "chat",
            "--config",
            home.join("freedom.yaml").to_str().unwrap(),
            "--wal-segment",
            wal.to_str().unwrap(),
            prompt,
        ])
        .expect("parse ordinary chat argv");
        let Commands::Chat(args) = cli.command else {
            unreachable!("test constructs chat")
        };
        args
    }

    fn canonical_wal(home: &Path, namespace: &str) -> PathBuf {
        let wal = home.join("wal").join(format!("{namespace}-000001.wal"));
        std::fs::create_dir_all(wal.parent().unwrap()).unwrap();
        wal
    }

    fn write_test_route_configs(root: &Path) -> (PathBuf, PathBuf) {
        use crate::config::inference::{HemisphereSlot, InferenceProvider};

        let direct_home = root.join("direct");
        let fallback_home = root.join("fallback");
        std::fs::create_dir_all(&direct_home).unwrap();
        std::fs::create_dir_all(&fallback_home).unwrap();
        crate::consent::grant(&direct_home, ProviderKind::ClaudeCli).unwrap();
        crate::consent::grant(&fallback_home, ProviderKind::ClaudeCli).unwrap();
        let mut direct = normal_config();
        direct.tokens.max_per_request = NCT_MAX_TOKENS_PER_REQUEST;
        let mut fallback = direct.clone();
        fallback.fallback.max_hops = 1;
        fallback.fallback.chain.push(HemisphereSlot {
            provider: Some(InferenceProvider::ClaudeCli),
            model: Some(NCT_TEST_MODEL.into()),
            ..Default::default()
        });
        let direct_path = direct_home.join("freedom.yaml");
        let fallback_path = fallback_home.join("freedom.yaml");
        std::fs::write(&direct_path, direct.public_yaml().unwrap()).unwrap();
        std::fs::write(&fallback_path, fallback.public_yaml().unwrap()).unwrap();
        (direct_path, fallback_path)
    }

    fn executing_args(root: &Path, direct: PathBuf, fallback: PathBuf) -> NctBaselineArgs {
        NctBaselineArgs {
            builtin_recipe: true,
            recipe: None,
            execute: true,
            direct_config: Some(direct),
            fallback_config: Some(fallback),
            receipt_dir: root.join("receipts"),
            output: OutputFormat::Json,
        }
    }

    #[tokio::test]
    async fn existing_second_receipt_prevents_every_provider_and_wal_effect() {
        let root = tempfile::tempdir().unwrap();
        let (direct_path, fallback_path) = write_test_route_configs(root.path());
        let args = executing_args(root.path(), direct_path, fallback_path);
        std::fs::create_dir_all(&args.receipt_dir).unwrap();
        let preserved = args
            .receipt_dir
            .join("nct-live-fallback-public-v1.receipt.json");
        std::fs::write(&preserved, b"prior receipt").unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let leaf = CountingLeaf {
            calls: Arc::clone(&calls),
            output_caps: Arc::new(Mutex::new(Vec::new())),
        };
        let result = Box::pin(run_nct_baseline_with(
            args,
            NctRunner::Hermetic {
                direct: &leaf,
                fallback: &leaf,
            },
        ))
        .await;
        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(!root.path().join("direct/wal").exists());
        assert!(!root.path().join("fallback/wal").exists());
        assert_eq!(std::fs::read(preserved).unwrap(), b"prior receipt");
    }

    #[tokio::test]
    async fn unexpected_provider_error_retains_actual_blocked_receipt() {
        let root = tempfile::tempdir().unwrap();
        let (direct_path, fallback_path) = write_test_route_configs(root.path());
        let args = executing_args(root.path(), direct_path, fallback_path);
        let receipt_path = args
            .receipt_dir
            .join("nct-live-direct-public-v1.receipt.json");
        let fallback_calls = Arc::new(AtomicUsize::new(0));
        let fallback = CountingLeaf {
            calls: Arc::clone(&fallback_calls),
            output_caps: Arc::new(Mutex::new(Vec::new())),
        };
        let result = Box::pin(run_nct_baseline_with(
            args,
            NctRunner::Hermetic {
                direct: &QuotaLeaf,
                fallback: &fallback,
            },
        ))
        .await;
        assert!(
            result.is_err(),
            "the recipe expected success, not a fabricated pass"
        );
        assert_eq!(fallback_calls.load(Ordering::SeqCst), 0);
        let raw = std::fs::read_to_string(receipt_path).unwrap();
        let receipt: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(receipt["terminal"], "blocked");
        assert_eq!(receipt["expected_terminal"], "success");
        assert_eq!(receipt["provider"], "nct-hermetic-quota");
        assert!(!receipt["invocation_id"].as_str().unwrap().is_empty());
        assert!(
            !receipt["request_binding_sha256"]
                .as_str()
                .unwrap()
                .is_empty()
        );
        assert!(!raw.contains("hermetic quota"));
        assert!(!raw.contains("NEOTH baseline acknowledged"));
    }

    #[tokio::test]
    async fn bounded_production_entry_rejects_loaded_config_drift_before_wal() {
        let home = tempfile::tempdir().unwrap();
        let mut admitted = normal_config();
        admitted.tokens.max_per_request = NCT_MAX_TOKENS_PER_REQUEST;
        let mut changed = admitted.clone();
        changed.tokens.max_per_request = NCT_MAX_TOKENS_PER_REQUEST + 1;
        std::fs::write(
            home.path().join("freedom.yaml"),
            changed.public_yaml().unwrap(),
        )
        .unwrap();
        let wal = home.path().join("wal/nct-drift-000001.wal");
        let error = Box::pin(crate::cli::chat::run_chat_bounded_output(
            chat_args(home.path(), &wal, "public NCT direct"),
            &admitted,
            NCT_MAX_OUTPUT_TOKENS,
        ))
        .await
        .expect_err("the actual config read must remain admitted");
        assert!(format!("{error:#}").contains("NCT admitted public config changed"));
        assert!(!wal.exists());
        assert!(!home.path().join("wal").exists());
    }

    #[tokio::test]
    async fn output_bound_does_not_leak_into_following_ordinary_chat() {
        let home = tempfile::tempdir().unwrap();
        crate::consent::grant(home.path(), ProviderKind::ClaudeCli).unwrap();
        let caps = Arc::new(Mutex::new(Vec::new()));
        let leaf = CountingLeaf {
            calls: Arc::new(AtomicUsize::new(0)),
            output_caps: Arc::clone(&caps),
        };
        let bounded_wal = canonical_wal(home.path(), "nct-scoped");
        Box::pin(crate::cli::chat::run_chat_with_output_cap(
            chat_args(home.path(), &bounded_wal, "public bounded probe"),
            normal_config(),
            &leaf,
            NCT_MAX_OUTPUT_TOKENS,
        ))
        .await
        .unwrap();
        let ordinary_wal = canonical_wal(home.path(), "nct-ordinary");
        Box::pin(crate::cli::chat::run_chat_with(
            chat_args(home.path(), &ordinary_wal, "public ordinary probe"),
            normal_config(),
            &leaf,
        ))
        .await
        .unwrap();
        assert_eq!(
            caps.lock().unwrap().as_slice(),
            &[Some(NCT_MAX_OUTPUT_TOKENS), None]
        );
    }

    #[test]
    fn builtin_recipe_is_one_public_direct_and_one_public_fallback() {
        let recipe: Recipe = serde_json::from_str(BUILTIN_RECIPE).unwrap();
        validate_recipe(&recipe).unwrap();
    }

    #[test]
    fn row_ids_are_unique_safe_slugs_and_receipts_refuse_overwrite() {
        let mut traversal: Recipe = serde_json::from_str(BUILTIN_RECIPE).unwrap();
        traversal.rows[1].id = "../escape".into();
        assert!(validate_recipe(&traversal).is_err());
        let mut duplicate: Recipe = serde_json::from_str(BUILTIN_RECIPE).unwrap();
        duplicate.rows[1].id = duplicate.rows[0].id.clone();
        assert!(validate_recipe(&duplicate).is_err());
        let mut case_collision: Recipe = serde_json::from_str(BUILTIN_RECIPE).unwrap();
        case_collision.rows[1].id = "Foo".into();
        assert!(validate_recipe(&case_collision).is_err());
        for id in ["con", "prn", "aux", "nul", "com1", "com9", "lpt1", "lpt9"] {
            let mut reserved: Recipe = serde_json::from_str(BUILTIN_RECIPE).unwrap();
            reserved.rows[1].id = id.into();
            assert!(
                validate_recipe(&reserved).is_err(),
                "reserved basename {id}"
            );
        }
        for id in ["console", "nul-route", "com10", "lpt10"] {
            let mut valid: Recipe = serde_json::from_str(BUILTIN_RECIPE).unwrap();
            valid.rows[1].id = id.into();
            validate_recipe(&valid).unwrap();
        }
        let home = tempfile::tempdir().unwrap();
        let receipt = Receipt {
            schema: "neoth.nct-live-route-receipt.v1",
            recipe_id: "test",
            row_id: "safe",
            split: Split::Train,
            route: Route::Direct,
            expected_terminal: Terminal::Success,
            recipe_revision: "a",
            recipe_sha256: "b".into(),
            producer_revision: "unknown".into(),
            provider: "p".into(),
            wire_model: "m".into(),
            request_binding_sha256: "c".into(),
            invocation_id: "d".into(),
            prompt_bytes: 1,
            system_bytes: 0,
            input_tokens: None,
            output_tokens: None,
            cache_creation_tokens: None,
            cache_read_tokens: None,
            latency_ms: None,
            cost_status: "unknown",
            terminal: Terminal::Success,
            route_evidence: "direct_completed",
        };
        write_receipt_new(home.path(), "safe", &receipt).unwrap();
        assert!(write_receipt_new(home.path(), "safe", &receipt).is_err());
    }
    #[tokio::test]
    async fn malformed_recipe_and_missing_execute_config_fail_before_receipt_directory_creation() {
        let home = tempfile::tempdir().unwrap();
        let invalid_recipe = home.path().join("invalid.json");
        std::fs::write(&invalid_recipe, r#"{"schema":"neoth.nct-live-route-recipe.v1","recipe_id":"bad","recipe_revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","rows":[]}"#).unwrap();
        let receipt_dir = home.path().join("must-not-exist");
        let malformed = NctBaselineArgs {
            builtin_recipe: false,
            recipe: Some(invalid_recipe),
            execute: true,
            direct_config: Some(home.path().join("direct.yaml")),
            fallback_config: Some(home.path().join("fallback.yaml")),
            receipt_dir: receipt_dir.clone(),
            output: OutputFormat::Json,
        };
        assert!(run_nct_baseline(malformed).await.is_err());
        assert!(
            !receipt_dir.exists(),
            "malformed input cannot create receipt/WAL effects"
        );
        let missing_config = NctBaselineArgs {
            builtin_recipe: true,
            recipe: None,
            execute: true,
            direct_config: None,
            fallback_config: None,
            receipt_dir,
            output: OutputFormat::Json,
        };
        let error = run_nct_baseline(missing_config)
            .await
            .expect_err("execute without explicit home must fail");
        assert!(format!("{error:#}").contains("--direct-config"));
    }

    #[tokio::test]
    async fn wrapper_runs_two_admitted_rows_with_private_receipts_and_real_fallback() {
        use crate::config::inference::{HemisphereSlot, InferenceProvider};

        let root = tempfile::tempdir().unwrap();
        let direct_home = root.path().join("direct");
        let fallback_home = root.path().join("fallback");
        std::fs::create_dir_all(&direct_home).unwrap();
        std::fs::create_dir_all(&fallback_home).unwrap();
        crate::consent::grant(&direct_home, ProviderKind::ClaudeCli).unwrap();
        crate::consent::grant(&fallback_home, ProviderKind::ClaudeCli).unwrap();
        let mut direct_config = normal_config();
        direct_config.tokens.max_per_request = NCT_MAX_TOKENS_PER_REQUEST;
        let mut fallback_config = direct_config.clone();
        fallback_config.fallback.max_hops = 1;
        fallback_config.fallback.chain.push(HemisphereSlot {
            provider: Some(InferenceProvider::ClaudeCli),
            model: Some(NCT_TEST_MODEL.into()),
            ..Default::default()
        });
        let direct_path = direct_home.join("freedom.yaml");
        let fallback_path = fallback_home.join("freedom.yaml");
        std::fs::write(&direct_path, serde_yaml::to_string(&direct_config).unwrap()).unwrap();
        std::fs::write(
            &fallback_path,
            serde_yaml::to_string(&fallback_config).unwrap(),
        )
        .unwrap();
        let direct_calls = Arc::new(AtomicUsize::new(0));
        let direct_caps = Arc::new(Mutex::new(Vec::new()));
        let fallback_calls = Arc::new(AtomicUsize::new(0));
        let fallback_caps = Arc::new(Mutex::new(Vec::new()));
        let direct = CountingLeaf {
            calls: Arc::clone(&direct_calls),
            output_caps: Arc::clone(&direct_caps),
        };
        let fallback = crate::providers::fallback::FallbackProvider::new_with_models_at(
            vec![
                Box::new(QuotaLeaf),
                Box::new(CountingLeaf {
                    calls: Arc::clone(&fallback_calls),
                    output_caps: Arc::clone(&fallback_caps),
                }),
            ],
            vec![Some(NCT_TEST_MODEL.into()), Some(NCT_TEST_MODEL.into())],
            1,
            None,
            fallback_home.join("quota.json"),
        );
        let receipts = root.path().join("receipts");
        let args = NctBaselineArgs {
            builtin_recipe: true,
            recipe: None,
            execute: true,
            direct_config: Some(direct_path.clone()),
            fallback_config: Some(fallback_path.clone()),
            receipt_dir: receipts.clone(),
            output: OutputFormat::Json,
        };
        run_nct_baseline_with(
            args,
            NctRunner::Hermetic {
                direct: &direct,
                fallback: &fallback,
            },
        )
        .await
        .unwrap();
        assert_eq!(direct_calls.load(Ordering::SeqCst), 1);
        assert_eq!(fallback_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            direct_caps.lock().unwrap().as_slice(),
            &[Some(NCT_MAX_OUTPUT_TOKENS)]
        );
        assert_eq!(
            fallback_caps.lock().unwrap().as_slice(),
            &[Some(NCT_MAX_OUTPUT_TOKENS)]
        );
        let direct_receipt =
            std::fs::read_to_string(receipts.join("nct-live-direct-public-v1.receipt.json"))
                .unwrap();
        let fallback_receipt =
            std::fs::read_to_string(receipts.join("nct-live-fallback-public-v1.receipt.json"))
                .unwrap();
        assert!(
            direct_receipt.contains("direct_completed")
                && fallback_receipt.contains("fallback_exercised")
        );
        assert!(
            direct_receipt.contains("nct-hermetic-leaf")
                && fallback_receipt.contains("nct-hermetic-leaf")
        );
        assert!(
            !direct_receipt.contains("NEOTH baseline acknowledged")
                && !fallback_receipt.contains("NEOTH fallback baseline acknowledged")
        );
        let repeat = NctBaselineArgs {
            builtin_recipe: true,
            recipe: None,
            execute: true,
            direct_config: Some(direct_path),
            fallback_config: Some(fallback_path),
            receipt_dir: receipts,
            output: OutputFormat::Json,
        };
        assert!(
            run_nct_baseline_with(
                repeat,
                NctRunner::Hermetic {
                    direct: &direct,
                    fallback: &fallback
                }
            )
            .await
            .is_err(),
            "create_new preserves first receipts"
        );
        assert_eq!(
            direct_calls.load(Ordering::SeqCst),
            1,
            "existing receipt preflight prevents repeat direct dispatch"
        );
        assert_eq!(
            fallback_calls.load(Ordering::SeqCst),
            1,
            "existing receipt preflight prevents repeat fallback dispatch"
        );
    }

    #[tokio::test]
    async fn hermetic_normal_chat_direct_emits_lifecycle_identity_native_usage_and_private_receipt()
    {
        let home = tempfile::tempdir().unwrap();
        crate::consent::grant(home.path(), ProviderKind::ClaudeCli).unwrap();
        let wal = canonical_wal(home.path(), "nct-direct");
        let calls = Arc::new(AtomicUsize::new(0));
        let output_caps = Arc::new(Mutex::new(Vec::new()));
        crate::cli::chat::run_chat_with_output_cap(
            chat_args(home.path(), &wal, "public NCT direct"),
            normal_config(),
            &CountingLeaf {
                calls: Arc::clone(&calls),
                output_caps: Arc::clone(&output_caps),
            },
            NCT_MAX_OUTPUT_TOKENS,
        )
        .await
        .expect("ordinary direct chat");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            output_caps.lock().expect("output cap mutex").as_slice(),
            &[Some(NCT_MAX_OUTPUT_TOKENS)]
        );
        let projection =
            project_terminal(&wal, Route::Direct).expect("project only owned direct WAL");
        assert_eq!(projection.provider, "nct-hermetic-leaf");
        assert_eq!(projection.wire_model, NCT_TEST_MODEL);
        assert_eq!(projection.input_tokens, Some(12));
        assert_eq!(projection.cache_read_tokens, Some(5));
        let recipe_revision = "a".repeat(64);
        let receipt = Receipt {
            schema: "neoth.nct-live-route-receipt.v1",
            recipe_id: "test",
            row_id: "direct",
            split: Split::Train,
            route: Route::Direct,
            expected_terminal: Terminal::Success,
            recipe_revision: &recipe_revision,
            recipe_sha256: "b".repeat(64),
            producer_revision: "unknown".into(),
            provider: projection.provider,
            wire_model: projection.wire_model,
            request_binding_sha256: projection.request_binding_sha256,
            invocation_id: projection.invocation_id,
            prompt_bytes: projection.prompt_bytes,
            system_bytes: projection.system_bytes,
            input_tokens: projection.input_tokens,
            output_tokens: projection.output_tokens,
            cache_creation_tokens: projection.cache_creation_tokens,
            cache_read_tokens: projection.cache_read_tokens,
            latency_ms: projection.latency_ms,
            cost_status: "unknown",
            terminal: projection.terminal,
            route_evidence: projection.route_evidence,
        };
        let serialized = serde_json::to_string(&receipt).unwrap();
        assert!(!serialized.contains("public NCT direct"));
        assert!(!serialized.contains("NCT hermetic reply"));
    }

    #[tokio::test]
    async fn hermetic_normal_chat_fallback_projects_actual_leaf_and_fallback_event() {
        let home = tempfile::tempdir().unwrap();
        crate::consent::grant(home.path(), ProviderKind::ClaudeCli).unwrap();
        let wal = canonical_wal(home.path(), "nct-fallback");
        let calls = Arc::new(AtomicUsize::new(0));
        let output_caps = Arc::new(Mutex::new(Vec::new()));
        let chain = crate::providers::fallback::FallbackProvider::new_with_models_at(
            vec![
                Box::new(QuotaLeaf),
                Box::new(CountingLeaf {
                    calls: Arc::clone(&calls),
                    output_caps: Arc::clone(&output_caps),
                }),
            ],
            vec![Some(NCT_TEST_MODEL.into()), Some(NCT_TEST_MODEL.into())],
            1,
            None,
            home.path().join("quota.json"),
        );
        crate::cli::chat::run_chat_with_output_cap(
            chat_args(home.path(), &wal, "public NCT fallback"),
            normal_config(),
            &chain,
            NCT_MAX_OUTPUT_TOKENS,
        )
        .await
        .expect("ordinary fallback chat");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            output_caps.lock().expect("output cap mutex").as_slice(),
            &[Some(NCT_MAX_OUTPUT_TOKENS)]
        );
        let projection =
            project_terminal(&wal, Route::Fallback).expect("project only owned fallback WAL");
        assert_eq!(
            projection.provider, "nct-hermetic-leaf",
            "receipt records actual fallback leaf"
        );
        assert_eq!(projection.wire_model, NCT_TEST_MODEL);
        assert_eq!(projection.input_tokens, Some(12));
    }
}
