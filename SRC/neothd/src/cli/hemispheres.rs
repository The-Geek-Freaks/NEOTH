//! `neoth hemispheres {show, set, test}` — per-role LLM provider
//! configuration. Per `PLAN/SPEC_hemisphere_provider_selection.md`.
//!
//! NEOTH's brain maps to 3 logical roles — Left (analytic), Right
//! (creative), Cerebellum (router). The data model already lives in
//! `config::inference::InferenceTopology`; this CLI surfaces it.
//!
//! v0.1 ships `show` + `set` + `test`. The wizard step 5d that
//! configures all three at onboarding lands in a separate pass against
//! `cli::init`.

use anyhow::{Context, Result};
use clap::{Args, Subcommand, ValueEnum};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::config::inference::{HemisphereRole, InferenceProvider};
use crate::providers::Provider;

#[derive(Args, Debug, Clone)]
pub struct HemispheresArgs {
    #[command(subcommand)]
    pub action: HemisphereAction,

    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum HemisphereAction {
    /// Show the current per-hemisphere provider binding.
    Show,
    /// Rebind one hemisphere role to a provider. Writes
    /// `~/.neoth/freedom.yaml` atomically and emits a WAL 0x1F
    /// HEMISPHERE_REBOUND audit frame immediately into
    /// `~/.neoth/wal/hemisphere-rebind-<ts>.wal`.
    Set {
        /// Role to rebind: `left` / `right` / `cerebellum`.
        #[arg(long)]
        role: String,
        /// Provider name: `claude_cli` / `anthropic_api` / `openai_api` /
        /// `openai_compat` / `gemini_api` / `local_qwen` / `local_ouro` /
        /// `aws_bedrock` / `azure_openai`.
        #[arg(long)]
        provider: String,
        /// Model identifier (e.g. `claude-opus-4-7`, `gpt-4o`).
        #[arg(long)]
        model: Option<String>,
        /// API key (when the provider needs one).
        #[arg(long)]
        key: Option<String>,
        /// Endpoint URL (for `openai_compat`).
        #[arg(long)]
        endpoint: Option<String>,
    },
    /// Sanity-check the provider bound to a role. Default behaviour:
    /// build the adapter + report load latency only. Pass `--question
    /// "X"` to additionally fire a live LLM round-trip against the
    /// bound provider — the smallest possible end-to-end smoke-test
    /// per hemisphere. Pair with `--dry-run` to print what would be
    /// sent without making the call (useful for cost-sensitive cloud
    /// providers).
    Test {
        #[arg(long)]
        role: String,
        /// Optional question to send live to the bound provider.
        /// Without this flag the command is build-only.
        #[arg(long)]
        question: Option<String>,
        /// When set with `--question`, print what would be sent +
        /// resolved provider/model without making the LLM call.
        #[arg(long)]
        dry_run: bool,
    },
    /// Apply a named hemisphere preset to `freedom.yaml` non-interactively
    /// (GOLD-ADOPT-12) — the same presets the `neoth init` wizard offers.
    /// Writes atomically + emits a 0x1F HEMISPHERE_REBOUND audit frame per
    /// changed role (with a pre-mutation rollback snapshot).
    Preset {
        /// Preset to apply: `local` / `local-reasoning` / `local-abliterated` /
        /// `single`.
        #[arg(value_enum)]
        name: PresetName,
        /// (local-abliterated) override detected VRAM in MiB instead of probing.
        #[arg(long)]
        vram: Option<u32>,
        /// (local-abliterated) how many hemispheres run local — default = the
        /// most the VRAM supports.
        #[arg(long)]
        count: Option<u8>,
    },
    /// GOLD-FEAT-01a: switch to single-provider mode — set `inference.mode =
    /// single` so all three roles resolve to ONE provider (`default_slot`) and
    /// bind that provider in one step. Unlike `preset single` (which keeps the
    /// existing default slot), this picks the provider explicitly. Writes
    /// freedom.yaml atomically with a pre-mutation rollback snapshot.
    Mode {
        /// Provider all hemispheres route to: `claude_cli` / `anthropic_api` /
        /// `openai_api` / `openai_compat` / `gemini_api` / `local_qwen` /
        /// `local_ouro` / `aws_bedrock` / `azure_openai`.
        #[arg(long)]
        provider: String,
        /// Model identifier for the single provider.
        #[arg(long)]
        model: Option<String>,
        /// API key (when the provider needs one).
        #[arg(long)]
        key: Option<String>,
        /// Endpoint URL (for `openai_compat`).
        #[arg(long)]
        endpoint: Option<String>,
    },
}

/// Named hemisphere presets for `neoth hemispheres preset` (GOLD-ADOPT-12).
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresetName {
    /// All three hemispheres → local Qwen via candle (Triplet, zero cloud, one
    /// shared model — the VRAM-safe default).
    Local,
    /// Local reasoning split: LEFT → local Ouro (explicit-reasoning LoopLM),
    /// RIGHT + CEREBELLUM → local Qwen. Loads TWO local model families — needs
    /// the VRAM for both.
    LocalReasoning,
    /// VRAM-sized abliterated GGUFs via Ollama (1..=count local hemispheres,
    /// rest stay on the existing slot).
    LocalAbliterated,
    /// Single-provider mode — all roles use `freedom.yaml::provider_kind`.
    Single,
}

pub async fn run_hemispheres(args: HemispheresArgs) -> Result<()> {
    let cfg = FreedomConfig::load_from_default_path()
        .context("load freedom.yaml — run `neoth init` first")?;
    match args.action {
        HemisphereAction::Show => run_show(&cfg, &args.output),
        HemisphereAction::Set {
            role,
            provider,
            model,
            key,
            endpoint,
        } => run_set(&role, &provider, model, key, endpoint, &args.output).await,
        HemisphereAction::Test {
            role,
            question,
            dry_run,
        } => run_test(&cfg, &role, question.as_deref(), dry_run, &args.output).await,
        HemisphereAction::Preset { name, vram, count } => {
            run_preset(name, vram, count, &args.output).await
        }
        HemisphereAction::Mode {
            provider,
            model,
            key,
            endpoint,
        } => run_mode_single(&provider, model, key, endpoint, &args.output).await,
    }
}

/// Apply a named preset onto an existing topology (pure — VRAM is injected so
/// the abliterated path is testable offline). `Local`/`Single` fully overwrite;
/// `LocalReasoning` rebinds all three roles; `LocalAbliterated` rebinds only the
/// local roles and PRESERVES the operator's existing (cloud) slots on the rest.
/// Returns the new topology + a one-line operator summary, or `Err` when no
/// local model fits the requested abliterated plan.
pub(crate) fn build_preset_topology(
    name: PresetName,
    mut base: crate::config::inference::InferenceTopology,
    vram_mib: Option<u32>,
    count: Option<u8>,
) -> Result<(crate::config::inference::InferenceTopology, String)> {
    use crate::config::inference::{HemisphereSlot, TopologyMode};
    let summary = match name {
        PresetName::Local => {
            crate::cli::init::apply_local_only_preset(&mut base);
            "all hemispheres → local Qwen (candle, Triplet, one shared model)".to_string()
        }
        PresetName::LocalReasoning => {
            let local_slot = |role: &str| HemisphereSlot {
                provider: Some(crate::cli::init::recommended_local_provider_for_role(role)),
                model: None,
                key: None,
                endpoint: None,
                region: None,
                api_version: None,
                voice: None,
            };
            base.mode = TopologyMode::Triplet;
            base.left = local_slot("left"); // LocalOuro — reasoning
            base.right = local_slot("right"); // LocalQwen
            base.cerebellum = local_slot("cerebellum"); // LocalQwen
            base.default_slot = base.right.clone();
            "left → local Ouro (reasoning), right + cerebellum → local Qwen".to_string()
        }
        PresetName::LocalAbliterated => {
            let n = count.unwrap_or_else(|| {
                crate::models::selector::recommended_local_count(vram_mib).max(1)
            });
            let preset = crate::models::hemisphere_preset::build_local_preset(
                vram_mib,
                n,
                crate::models::gguf_variants::VariantClass::Abliterated,
                crate::installers::ollama::DEFAULT_OLLAMA_PORT,
            );
            if preset.locals.is_empty() {
                anyhow::bail!(
                    "no local model fits {} — add a GPU, pass --vram, or pick a cloud provider",
                    vram_mib
                        .map(|m| format!("{:.1} GiB VRAM", m as f32 / 1024.0))
                        .unwrap_or_else(|| "this machine".to_string())
                );
            }
            let n_local = preset.locals.len();
            crate::cli::init::apply_local_abliterated_preset(&mut base, &preset);
            format!("{n_local} local abliterated hemisphere(s) via Ollama (Q4/Q8 GGUF)")
        }
        PresetName::Single => {
            base.mode = TopologyMode::Single;
            "single-provider mode — all roles use freedom.yaml::provider_kind".to_string()
        }
    };
    Ok((base, summary))
}

async fn run_preset(
    name: PresetName,
    vram: Option<u32>,
    count: Option<u8>,
    output: &OutputFormat,
) -> Result<()> {
    // VRAM is only consulted by the abliterated plan; probe lazily so the
    // other presets stay offline-pure.
    let vram_mib = if matches!(name, PresetName::LocalAbliterated) {
        vram.or_else(|| crate::installers::gpu::probe_gpu().vram_mib)
    } else {
        vram
    };

    let path = FreedomConfig::default_path();
    let (prepared, (cfg, prior, summary)) = FreedomConfig::prepare_update_at(&path, |cfg| {
        let prior = [
            (HemisphereRole::Left, cfg.inference.left.clone()),
            (HemisphereRole::Right, cfg.inference.right.clone()),
            (HemisphereRole::Cerebellum, cfg.inference.cerebellum.clone()),
        ];
        let (new_topo, summary) =
            build_preset_topology(name, std::mem::take(&mut cfg.inference), vram_mib, count)?;
        cfg.inference = new_topo;
        Ok((cfg.clone(), prior, summary))
    })
    .context("prepare lossless hemisphere preset update")?;
    let now_unix = crate::time::now_unix_i64();

    // Pre-mutation rollback snapshot (mirrors run_set), so a mis-applied preset
    // can be reverted via `neoth rollback apply`.
    let prior_yaml_bytes = prepared
        .source_bytes()
        .ok_or_else(|| anyhow::anyhow!("freedom.yaml is missing at {}", path.display()))?;
    let wal_dir = FreedomConfig::default_wal_dir();
    std::fs::create_dir_all(&wal_dir).context("create WAL dir for hemispheres preset audit")?;
    let snapshot_segment = wal_dir.join(format!("hemispheres-preset-snapshot-{now_unix}.wal"));
    let (snap_writer, snap_join) = crate::wal::writer::spawn(snapshot_segment)
        .context("spawn WAL writer for hemispheres preset rollback snapshot")?;
    let _ = crate::wal::snapshot::emit_if_policy_allows(
        &snap_writer,
        &cfg.rollback,
        crate::wal::snapshot::MutationKind::ConfigWrite,
        path.display().to_string(),
        prior_yaml_bytes,
        now_unix,
        Some(format!("hemispheres preset {name:?} via CLI")),
    )
    .await
    .context("emit pre-mutation snapshot for freedom.yaml preset write")?;
    drop(snap_writer);
    let _ = snap_join.await;

    prepared
        .commit()
        .with_context(|| format!("publish reviewed {} update", path.display()))?;

    // Emit a HEMISPHERE_REBOUND frame for each role the preset actually changed.
    let mut changed: Vec<&str> = Vec::new();
    let mut audit_segment: Option<std::path::PathBuf> = None;
    for (role, prior_slot) in &prior {
        let new_slot = cfg.inference.slot_for(*role);
        if new_slot.provider != prior_slot.provider || new_slot.model != prior_slot.model {
            audit_segment = Some(emit_rebind_audit(*role, prior_slot, new_slot, now_unix).await?);
            changed.push(role.as_str());
        }
    }

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "preset": format!("{name:?}"),
                    "mode": cfg.inference.mode.as_str(),
                    "summary": summary,
                    "changed_roles": changed,
                    "audit_segment": audit_segment.map(|p| p.display().to_string()),
                }))?
            );
        }
        OutputFormat::Table => {
            println!("# Hemisphere preset applied: {name:?}");
            println!("  {summary}");
            println!(
                "  freedom.yaml::inference updated atomically (mode now {})",
                cfg.inference.mode.as_str()
            );
            if changed.is_empty() {
                println!("  (no role binding changed)");
            } else {
                println!(
                    "  WAL 0x1F HEMISPHERE_REBOUND frames written for: {}",
                    changed.join(", ")
                );
            }
        }
    }
    Ok(())
}

fn run_show(cfg: &FreedomConfig, output: &OutputFormat) -> Result<()> {
    let topo = &cfg.inference;
    let rows = [
        HemisphereRole::Left,
        HemisphereRole::Right,
        HemisphereRole::Cerebellum,
    ]
    .iter()
    .map(|r| {
        let slot = topo.slot_for(*r);
        (*r, slot.clone())
    })
    .collect::<Vec<_>>();

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let body = serde_json::json!({
                "mode": topo.mode.as_str(),
                "single_provider_fallback": cfg.provider_kind.as_ref().map(|p| format!("{p:?}")),
                "roles": rows.iter().map(|(role, slot)| serde_json::json!({
                    "role": role.as_str(),
                    "provider": slot.provider.map(|p| p.as_str()),
                    "model": slot.model,
                    "endpoint": slot.endpoint,
                    "has_key": slot.key.is_some(),
                    // GOLD-WIRE-04: surface the specialist voice bound to this slot.
                    "voice": slot.voice.map(|v| v.as_str()),
                })).collect::<Vec<_>>(),
            });
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        OutputFormat::Table => {
            println!("# Hemispheres — mode: {}", topo.mode.as_str());
            if matches!(topo.mode, crate::config::inference::TopologyMode::Single) {
                println!("  All three roles route to the single-mode provider configured");
                println!(
                    "  in `freedom.yaml::provider_kind` ({:?}).",
                    cfg.provider_kind
                        .as_ref()
                        .map(|p| format!("{p:?}"))
                        .unwrap_or_else(|| "Skip".into())
                );
            }
            for (role, slot) in &rows {
                let provider = slot.provider.map(|p| p.as_str()).unwrap_or("(default)");
                let model = slot.model.as_deref().unwrap_or("(default)");
                let endpoint = slot.endpoint.as_deref().unwrap_or("");
                // GOLD-WIRE-04: show the specialist voice bound to this slot.
                let voice = slot.voice.map(|v| v.as_str()).unwrap_or("(none)");
                println!(
                    "  {:<10}  provider={:<16} model={:<28} voice={:<24} endpoint={endpoint}",
                    role.as_str(),
                    provider,
                    model,
                    voice,
                );
            }
        }
    }
    Ok(())
}

/// GOLD-FEAT-01a — `neoth hemispheres mode --provider X` — switch to
/// single-provider mode (`TopologyMode::Single`) and bind `default_slot` to X so
/// all three roles resolve to one provider. Mirrors `run_set`'s atomic save +
/// pre-mutation rollback snapshot. `preset single` keeps the existing default
/// slot; this picks the provider explicitly in one command.
fn apply_single_mode_update(
    cfg: &mut FreedomConfig,
    credentials: &mut crate::config::credentials::Credentials,
    provider: InferenceProvider,
    model: Option<&str>,
    supplied_key: Option<&crate::secret::SecretString>,
    endpoint: Option<&str>,
) -> FreedomConfig {
    let prior_voice = cfg.inference.default_slot.voice;
    if let Some(key) = supplied_key {
        credentials.inference_default_slot_key = Some(key.clone());
    } else if credentials.inference_default_slot_key.is_none() {
        // Preserve the pre-split default-slot key in the dedicated store
        // before the public topology is rewritten.
        credentials.inference_default_slot_key = cfg.inference.default_slot.key.clone();
    }
    cfg.inference.mode = crate::config::inference::TopologyMode::Single;
    cfg.inference.default_slot = crate::config::inference::HemisphereSlot {
        provider: Some(provider),
        model: model.map(str::to_owned),
        key: None,
        endpoint: endpoint.map(str::to_owned),
        region: None,
        api_version: None,
        voice: prior_voice,
    };
    cfg.clone()
}

async fn run_mode_single(
    provider_str: &str,
    model: Option<String>,
    key: Option<String>,
    endpoint: Option<String>,
    output: &OutputFormat,
) -> Result<()> {
    let provider = InferenceProvider::from_str(provider_str).ok_or_else(|| {
        anyhow::anyhow!(
            "unknown provider `{provider_str}`. Valid: claude_cli, anthropic_api, \
             openai_api, openai_compat, gemini_api, local_qwen, local_ouro, \
             aws_bedrock, azure_openai"
        )
    })?;

    let path = FreedomConfig::default_path();
    let credentials_path = FreedomConfig::default_neoth_home().join("credentials.yaml");
    let snapshot = crate::config::snapshot_raw_config_pair(&path)
        .context("capture coherent config/credential generation before single-mode update")?;
    let prior_yaml_bytes = snapshot
        .freedom
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("freedom.yaml is missing at {}", path.display()))?;
    let snapshot_config: FreedomConfig =
        serde_yaml::from_slice(prior_yaml_bytes).context("parse snapshotted freedom.yaml")?;
    let prior_mode = snapshot_config.inference.mode;
    let now_unix = crate::time::now_unix_i64();

    // Pre-mutation rollback snapshot (same policy gate as `run_set`) so
    // `neoth rollback apply` can restore the prior topology.
    let wal_dir = FreedomConfig::default_wal_dir();
    std::fs::create_dir_all(&wal_dir).context("create WAL dir for hemispheres audit")?;
    let snapshot_segment = wal_dir.join(format!("hemispheres-snapshot-{now_unix}.wal"));
    let (snap_writer, snap_join) = crate::wal::writer::spawn(snapshot_segment.clone())
        .context("spawn WAL writer for hemispheres rollback snapshot")?;
    let _ = crate::wal::snapshot::emit_if_policy_allows(
        &snap_writer,
        &snapshot_config.rollback,
        crate::wal::snapshot::MutationKind::ConfigWrite,
        path.display().to_string(),
        prior_yaml_bytes,
        now_unix,
        Some("hemispheres mode single via CLI".to_string()),
    )
    .await
    .context("emit pre-mutation snapshot for freedom.yaml rewrite")?;
    drop(snap_writer);
    let _ = snap_join.await;

    let supplied_key = key.map(crate::secret::SecretString::from);
    let cfg = crate::config::credentials::Credentials::update_with_freedom_at_if_source(
        &path,
        &credentials_path,
        prior_yaml_bytes,
        |cfg, credentials| {
            Ok(apply_single_mode_update(
                cfg,
                credentials,
                provider,
                model.as_deref(),
                supplied_key.as_ref(),
                endpoint.as_deref(),
            ))
        },
    )
    .with_context(|| format!("publish reviewed {} and credentials", path.display()))?;

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "mode": cfg.inference.mode.as_str(),
                    "prior_mode": prior_mode.as_str(),
                    "single_provider": provider.as_str(),
                    "model": model,
                }))?
            );
        }
        OutputFormat::Table => {
            println!(
                "# Single-provider mode: all hemispheres → {}",
                provider.as_str()
            );
            println!("  mode: {} → single", prior_mode.as_str());
            if let Some(m) = &model {
                println!("  model: {m}");
            }
            println!("  freedom.yaml updated (pre-mutation rollback snapshot written).");
        }
    }
    Ok(())
}

async fn run_set(
    role_str: &str,
    provider_str: &str,
    model: Option<String>,
    key: Option<String>,
    endpoint: Option<String>,
    output: &OutputFormat,
) -> Result<()> {
    let result = rebind_at(
        &FreedomConfig::default_neoth_home(),
        role_str,
        provider_str,
        model,
        key,
        endpoint,
    )
    .await?;

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "role": result.role.as_str(),
                    "prior_provider": result.prior.provider.map(|p| p.as_str()),
                    "new_provider": result.provider.as_str(),
                    "model": result.new_slot.model,
                    "mode": result.mode.as_str(),
                    "audit_segment": result.audit_segment.display().to_string(),
                }))?
            );
        }
        OutputFormat::Table => {
            let prior_p = result
                .prior
                .provider
                .map(|p| p.as_str())
                .unwrap_or("(default)");
            println!(
                "# Hemisphere rebind: {:?}  {prior_p} → {}",
                result.role,
                result.provider.as_str()
            );
            println!(
                "  freedom.yaml::inference.{} updated atomically (mode now {})",
                result.role.as_str(),
                result.mode.as_str()
            );
            println!(
                "  WAL 0x1F HEMISPHERE_REBOUND audit frame written to {}",
                result.audit_segment.display()
            );
        }
    }
    Ok(())
}

pub(crate) struct RebindResult {
    pub role: HemisphereRole,
    pub provider: InferenceProvider,
    pub prior: crate::config::inference::HemisphereSlot,
    pub new_slot: crate::config::inference::HemisphereSlot,
    pub mode: crate::config::inference::TopologyMode,
    pub audit_segment: std::path::PathBuf,
}

/// Shared hemisphere rebind used by CLI and slash dispatch. Config mutation is
/// a locked reload-under-lock RMW; an optional API key is written only to the
/// role-specific credentials field, never freedom.yaml.
pub(crate) async fn rebind_at(
    home: &std::path::Path,
    role_str: &str,
    provider_str: &str,
    model: Option<String>,
    key: Option<String>,
    endpoint: Option<String>,
) -> Result<RebindResult> {
    let role = parse_role(role_str)?;
    let provider = InferenceProvider::from_str(provider_str).ok_or_else(|| {
        anyhow::anyhow!(
            "unknown provider `{provider_str}`. Valid: claude_cli, anthropic_api, \
             openai_api, openai_compat, gemini_api, local_qwen, local_ouro, \
             aws_bedrock, azure_openai"
        )
    })?;
    let path = home.join("freedom.yaml");
    let credentials_path = home.join("credentials.yaml");
    let config_snapshot = crate::config::snapshot_raw_config_pair(&path)
        .context("capture coherent freedom/credential generation before provider rebind")?;
    let prior_yaml_bytes = config_snapshot
        .freedom
        .ok_or_else(|| anyhow::anyhow!("freedom.yaml is missing at {}", path.display()))?;
    let snapshot: FreedomConfig =
        serde_yaml::from_slice(&prior_yaml_bytes).context("parse freedom.yaml")?;
    let now_unix = crate::time::now_unix_i64();
    let wal_dir = home.join("wal");
    std::fs::create_dir_all(&wal_dir).context("create WAL dir for hemispheres audit")?;
    let snapshot_segment = wal_dir.join(format!("hemispheres-snapshot-{now_unix}.wal"));
    let (snap_writer, snap_join) =
        crate::wal::writer::spawn_for_home(snapshot_segment, home.to_path_buf())
            .context("spawn WAL writer for hemispheres rollback snapshot")?;
    let _ = crate::wal::snapshot::emit_if_policy_allows(
        &snap_writer,
        &snapshot.rollback,
        crate::wal::snapshot::MutationKind::ConfigWrite,
        path.display().to_string(),
        &prior_yaml_bytes,
        now_unix,
        Some(format!("hemispheres set --role {} via CLI", role.as_str())),
    )
    .await
    .context("emit pre-mutation snapshot for freedom.yaml rewrite")?;
    drop(snap_writer);
    let _ = snap_join.await;

    let supplied_key = key.map(crate::secret::SecretString::from);
    let (prior, new_slot, mode) =
        crate::config::credentials::Credentials::update_raw_freedom_with_credentials_at(
            &path,
            &credentials_path,
            |source, credentials| {
                let source = source.ok_or_else(|| {
                    anyhow::anyhow!("freedom.yaml disappeared at {}", path.display())
                })?;
                anyhow::ensure!(
                    source.as_bytes() == prior_yaml_bytes.as_slice(),
                    "freedom.yaml changed after its rollback snapshot; retry the hemisphere rebind"
                );
                let mut persisted: serde_yaml::Value = serde_yaml::from_str(source)
                    .with_context(|| format!("parse {} for lossless rebind", path.display()))?;
                let mut cfg: FreedomConfig = serde_yaml::from_str(source)
                    .with_context(|| format!("parse config at {}", path.display()))?;
                let prior = cfg.inference.slot_for(role).clone();
                let role_credential = match role {
                    HemisphereRole::Left => &mut credentials.inference_left_key,
                    HemisphereRole::Right => &mut credentials.inference_right_key,
                    HemisphereRole::Cerebellum => &mut credentials.inference_cerebellum_key,
                };
                if let Some(key) = supplied_key.as_ref() {
                    *role_credential = Some(key.clone());
                } else if role_credential.is_none() {
                    // Pre-split configs stored the key inline in this slot.
                    // Rebinding always removes inline secrets, so migrate the
                    // legacy value into the role-specific credential field
                    // before publishing the public slot without `key`.
                    *role_credential = prior.key.clone();
                }

                if matches!(
                    cfg.inference.mode,
                    crate::config::inference::TopologyMode::Single
                ) {
                    cfg.inference.mode = crate::config::inference::TopologyMode::Custom;
                }
                let new_slot = crate::config::inference::HemisphereSlot {
                    provider: Some(provider),
                    model: model.clone(),
                    key: None,
                    endpoint: endpoint.clone(),
                    region: None,
                    api_version: None,
                    voice: prior.voice,
                };
                match role {
                    HemisphereRole::Left => cfg.inference.left = new_slot.clone(),
                    HemisphereRole::Right => cfg.inference.right = new_slot.clone(),
                    HemisphereRole::Cerebellum => cfg.inference.cerebellum = new_slot.clone(),
                }

                let root = persisted
                    .as_mapping_mut()
                    .context("freedom.yaml root must be a YAML mapping")?;
                let inference_key = serde_yaml::Value::String("inference".to_string());
                let inference = root
                    .entry(inference_key)
                    .or_insert_with(|| serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));
                let inference = inference
                    .as_mapping_mut()
                    .context("freedom.yaml inference must be a YAML mapping")?;
                inference.insert(
                    serde_yaml::Value::String("mode".to_string()),
                    serde_yaml::to_value(cfg.inference.mode)
                        .context("serialize inference topology mode")?,
                );
                let role_key = serde_yaml::Value::String(role.as_str().to_string());
                let new_slot_value =
                    serde_yaml::to_value(&new_slot).context("serialize rebound hemisphere slot")?;
                if let (Some(current), serde_yaml::Value::Mapping(new_fields)) =
                    (inference.get_mut(&role_key), &new_slot_value)
                    && let Some(current) = current.as_mapping_mut()
                {
                    for (key, value) in new_fields {
                        current.insert(key.clone(), value.clone());
                    }
                } else {
                    inference.insert(role_key, new_slot_value);
                }
                let target = serde_yaml::to_string(&persisted)
                    .context("serialize losslessly rebound freedom.yaml")?;
                Ok((Some(target), (prior, new_slot, cfg.inference.mode)))
            },
        )
        .with_context(|| format!("atomically update {} and credentials", path.display()))?;

    let audit_segment =
        emit_rebind_audit_to(home, &wal_dir, role, &prior, &new_slot, now_unix).await?;
    Ok(RebindResult {
        role,
        provider,
        prior,
        new_slot,
        mode,
        audit_segment,
    })
}

/// Open a one-shot WAL segment under `~/.neoth/wal/` and append the
/// `EVENT_TYPE_HEMISPHERE_REBOUND` (0x1F) audit frame. Closes the writer
/// before returning so the segment is flushed to disk. Returns the
/// segment path so the caller can include it in the operator-facing
/// output.
///
/// `prior` and `new` are the per-role slots before/after the rebind;
/// `prior.provider` may be `None` when the role was inheriting from the
/// single-mode default — recorded as a `null` JSON field in the payload.
async fn emit_rebind_audit(
    role: HemisphereRole,
    prior: &crate::config::inference::HemisphereSlot,
    new_slot: &crate::config::inference::HemisphereSlot,
    now_unix: i64,
) -> Result<std::path::PathBuf> {
    let home = FreedomConfig::default_neoth_home();
    emit_rebind_audit_to(
        &home,
        &FreedomConfig::default_wal_dir(),
        role,
        prior,
        new_slot,
        now_unix,
    )
    .await
}

/// Test-friendly inner helper — accepts an explicit WAL directory so
/// integration tests can drive the audit path without colliding with the
/// operator's real `~/.neoth/wal/`.
async fn emit_rebind_audit_to(
    home: &std::path::Path,
    wal_dir: &std::path::Path,
    role: HemisphereRole,
    prior: &crate::config::inference::HemisphereSlot,
    new_slot: &crate::config::inference::HemisphereSlot,
    now_unix: i64,
) -> Result<std::path::PathBuf> {
    std::fs::create_dir_all(wal_dir).context("create WAL dir for hemisphere rebind audit")?;
    let segment = wal_dir.join(format!("hemisphere-rebind-{now_unix}.wal"));

    let payload = serde_json::to_vec(&serde_json::json!({
        "role": role.as_str(),
        "prior_provider": prior.provider.map(|p| p.as_str()),
        "new_provider": new_slot.provider.map(|p| p.as_str()),
        "model": new_slot.model,
        "source": "cli",
        "ts_unix": now_unix,
    }))
    .context("serialize HEMISPHERE_REBOUND payload")?;

    let header =
        crate::wal::HeaderBuilder::new(crate::wal::events::EVENT_TYPE_HEMISPHERE_REBOUND, &payload)
            .build();

    let (writer, join) = crate::wal::writer::spawn_for_home(segment.clone(), home.to_path_buf())
        .context("spawn WAL writer for hemisphere rebind audit")?;
    writer
        .append(header, payload)
        .await
        .context("append HEMISPHERE_REBOUND frame")?;
    drop(writer);
    let _ = join.await;

    Ok(segment)
}

async fn run_test(
    cfg: &FreedomConfig,
    role_str: &str,
    question: Option<&str>,
    dry_run: bool,
    output: &OutputFormat,
) -> Result<()> {
    let role = parse_role(role_str)?;
    let started = std::time::Instant::now();
    let provider = crate::providers::from_config_for_role_at(
        cfg,
        role,
        &crate::config::FreedomConfig::default_neoth_home(),
    )
    .await
    .with_context(|| format!("build provider for role {}", role.as_str()))?;
    let default_model = crate::providers::provider_default_wire_model(provider.as_ref());
    let provider = crate::providers::cost_authorization::AuthorizedProvider::from_box(
        provider,
        crate::providers::cost_authorization::ProviderCallAuthorizer::interactive_one_shot(
            cfg.autonomy_policy(),
            cfg.tokens.max_per_request,
        )?,
        default_model,
        "hemispheres.test",
    );
    let construct_elapsed_ms = started.elapsed().as_millis();

    // Live-call branch (D-1 Session 13). Gated by `question.is_some()` so
    // existing build-only callers see zero change. `--dry-run` short-
    // circuits the actual `provider.complete` so cost-sensitive operators
    // can verify routing without paying for a token.
    let live = if let Some(q) = question {
        // V03-08 / A-2 contract: consent must be granted for the
        // specific hemisphere's provider before any live call. The
        // hemispheres test surface is a fresh entry-point, not covered
        // by the chat/serve pre-flight, so it gates explicitly here.
        if let Some(route) = crate::consent::route_for_role(cfg, role) {
            let home = FreedomConfig::default_neoth_home();
            crate::consent::ensure_route_granted_or_prompt(&home, &route)?;
        }
        if dry_run {
            Some(LiveResult::dry_run(q))
        } else {
            Some(run_test_live_call(&provider, q).await?)
        }
    } else {
        None
    };

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let mut body = serde_json::json!({
                "role": role.as_str(),
                "provider": provider.name(),
                "construct_latency_ms": construct_elapsed_ms,
            });
            if let Some(live) = live {
                let obj = body.as_object_mut().unwrap();
                obj.insert("question".into(), serde_json::Value::String(live.question));
                if live.dry_run {
                    obj.insert("dry_run".into(), serde_json::Value::Bool(true));
                    obj.insert(
                        "note".into(),
                        serde_json::Value::String(
                            "dry-run: routing verified, no LLM call made".into(),
                        ),
                    );
                } else {
                    obj.insert(
                        "response".into(),
                        serde_json::Value::String(live.response.unwrap_or_default()),
                    );
                    obj.insert(
                        "completion_latency_ms".into(),
                        serde_json::Value::Number(
                            (live.completion_latency_ms.unwrap_or(0) as u64).into(),
                        ),
                    );
                    if let Some(it) = live.input_tokens {
                        obj.insert("input_tokens".into(), serde_json::Value::Number(it.into()));
                    }
                    if let Some(ot) = live.output_tokens {
                        obj.insert("output_tokens".into(), serde_json::Value::Number(ot.into()));
                    }
                }
            } else {
                body.as_object_mut().unwrap().insert(
                    "note".into(),
                    serde_json::Value::String(
                        "build-only sanity check; pass --question to fire a live LLM call".into(),
                    ),
                );
            }
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        OutputFormat::Table => {
            println!("# Hemisphere test — {}", role.as_str());
            println!("  provider:  {}", provider.name());
            println!("  construct: {construct_elapsed_ms}ms");
            match live {
                None => println!("  (build-only sanity check; pass --question for live call)"),
                Some(live) if live.dry_run => {
                    println!("  question:  {}", live.question);
                    println!("  dry-run:   would call provider; no token spent");
                }
                Some(live) => {
                    println!("  question:  {}", live.question);
                    println!(
                        "  response:  {}",
                        live.response.as_deref().unwrap_or("(empty)")
                    );
                    println!("  complete:  {}ms", live.completion_latency_ms.unwrap_or(0));
                    if let Some(it) = live.input_tokens {
                        println!("  in_tokens: {it}");
                    }
                    if let Some(ot) = live.output_tokens {
                        println!("  out_tokens:{ot}");
                    }
                }
            }
        }
    }
    Ok(())
}

/// D-1 live-call outcome. Carried back to `run_test` so the rendering
/// code stays separate from the provider-touching code (testable in
/// isolation).
#[derive(Debug)]
pub(crate) struct LiveResult {
    question: String,
    dry_run: bool,
    response: Option<String>,
    completion_latency_ms: Option<u128>,
    input_tokens: Option<u32>,
    output_tokens: Option<u32>,
}

impl LiveResult {
    fn dry_run(q: &str) -> Self {
        Self {
            question: q.to_string(),
            dry_run: true,
            response: None,
            completion_latency_ms: None,
            input_tokens: None,
            output_tokens: None,
        }
    }
}

/// D-1 (Session 13) — extracted live-call path so tests can inject a
/// stub `Provider` without exercising the full `run_test` rendering
/// code. Keeps the test surface a single function call.
pub(crate) async fn run_test_live_call(
    provider: &dyn crate::providers::Provider,
    question: &str,
) -> Result<LiveResult> {
    let req = crate::providers::Request {
        prompt: question.to_string(),
        ..crate::providers::Request::default()
    };
    let started = std::time::Instant::now();
    let completion = provider
        .complete(req)
        .await
        .with_context(|| format!("live call to provider `{}`", provider.name()))?;
    let elapsed_ms = started.elapsed().as_millis();
    Ok(LiveResult {
        question: question.to_string(),
        dry_run: false,
        response: Some(completion.text),
        completion_latency_ms: Some(elapsed_ms),
        input_tokens: completion.input_tokens,
        output_tokens: completion.output_tokens,
    })
}

fn parse_role(s: &str) -> Result<HemisphereRole> {
    match s.to_ascii_lowercase().as_str() {
        "left" | "l" => Ok(HemisphereRole::Left),
        "right" | "r" => Ok(HemisphereRole::Right),
        "cerebellum" | "c" | "cb" => Ok(HemisphereRole::Cerebellum),
        other => Err(anyhow::anyhow!(
            "unknown role `{other}`. Valid: left, right, cerebellum"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_mode_stores_supplied_key_in_credentials_not_public_slot() {
        let mut cfg = FreedomConfig::default();
        cfg.inference.default_slot.key = Some(crate::secret::SecretString::from("legacy-key"));
        let mut credentials = crate::config::credentials::Credentials::default();
        let supplied = crate::secret::SecretString::from("new-key");

        let updated = apply_single_mode_update(
            &mut cfg,
            &mut credentials,
            InferenceProvider::OpenAiCompat,
            Some("new-model"),
            Some(&supplied),
            Some("http://127.0.0.1:11434/v1"),
        );

        assert_eq!(
            credentials
                .inference_default_slot_key
                .as_ref()
                .expect("dedicated default-slot key")
                .expose(),
            "new-key"
        );
        assert!(updated.inference.default_slot.key.is_none());
        assert_eq!(
            updated.inference.mode,
            crate::config::inference::TopologyMode::Single
        );
        assert_eq!(
            updated.inference.default_slot.provider,
            Some(InferenceProvider::OpenAiCompat)
        );
    }

    #[test]
    fn parse_role_accepts_canonical_names() {
        assert_eq!(parse_role("left").unwrap(), HemisphereRole::Left);
        assert_eq!(parse_role("right").unwrap(), HemisphereRole::Right);
        assert_eq!(
            parse_role("cerebellum").unwrap(),
            HemisphereRole::Cerebellum
        );
    }

    #[test]
    fn parse_role_accepts_short_aliases() {
        assert_eq!(parse_role("l").unwrap(), HemisphereRole::Left);
        assert_eq!(parse_role("r").unwrap(), HemisphereRole::Right);
        assert_eq!(parse_role("cb").unwrap(), HemisphereRole::Cerebellum);
    }

    #[test]
    fn parse_role_case_insensitive() {
        assert_eq!(parse_role("LEFT").unwrap(), HemisphereRole::Left);
        assert_eq!(parse_role("Right").unwrap(), HemisphereRole::Right);
    }

    #[test]
    fn parse_role_rejects_unknown() {
        let err = parse_role("frontal").unwrap_err();
        assert!(err.to_string().contains("frontal"));
        assert!(err.to_string().contains("left"));
    }

    // ── GOLD-ADOPT-12 `neoth hemispheres preset` ──────────────────────────

    #[test]
    fn preset_local_binds_every_slot_to_local_qwen() {
        use crate::config::inference::{InferenceProvider, InferenceTopology, TopologyMode};
        let (topo, summary) =
            build_preset_topology(PresetName::Local, InferenceTopology::default(), None, None)
                .unwrap();
        assert_eq!(topo.mode, TopologyMode::Triplet);
        for slot in [&topo.left, &topo.right, &topo.cerebellum] {
            assert_eq!(slot.provider, Some(InferenceProvider::LocalQwen));
        }
        assert!(summary.contains("local Qwen"));
    }

    #[test]
    fn preset_local_reasoning_puts_ouro_on_left_qwen_elsewhere() {
        use crate::config::inference::{InferenceProvider, InferenceTopology, TopologyMode};
        let (topo, _) = build_preset_topology(
            PresetName::LocalReasoning,
            InferenceTopology::default(),
            None,
            None,
        )
        .unwrap();
        assert_eq!(topo.mode, TopologyMode::Triplet);
        assert_eq!(topo.left.provider, Some(InferenceProvider::LocalOuro));
        assert_eq!(topo.right.provider, Some(InferenceProvider::LocalQwen));
        assert_eq!(topo.cerebellum.provider, Some(InferenceProvider::LocalQwen));
    }

    #[test]
    fn preset_single_sets_single_mode() {
        use crate::config::inference::{InferenceTopology, TopologyMode};
        let (topo, _) =
            build_preset_topology(PresetName::Single, InferenceTopology::default(), None, None)
                .unwrap();
        assert_eq!(topo.mode, TopologyMode::Single);
    }

    #[test]
    fn preset_local_abliterated_24gib_is_all_local_ollama() {
        use crate::config::inference::{InferenceProvider, InferenceTopology, TopologyMode};
        let (topo, summary) = build_preset_topology(
            PresetName::LocalAbliterated,
            InferenceTopology::default(),
            Some(24 * 1024),
            Some(3),
        )
        .unwrap();
        assert_eq!(topo.mode, TopologyMode::Triplet);
        // Every slot is an Ollama OpenAI-compat endpoint with an hf.co GGUF ref.
        for slot in [&topo.left, &topo.right, &topo.cerebellum] {
            assert_eq!(slot.provider, Some(InferenceProvider::OpenAiCompat));
            assert!(slot.model.as_deref().unwrap_or("").starts_with("hf.co/"));
        }
        assert!(summary.contains("abliterated"));
    }

    #[test]
    fn preset_local_abliterated_preserves_cloud_slots_when_mixed() {
        use crate::config::inference::{HemisphereSlot, InferenceProvider, InferenceTopology};
        // Operator already has Gemini on right; a 1-local preset must keep it.
        let mut base = InferenceTopology::default();
        base.right = HemisphereSlot {
            provider: Some(InferenceProvider::Gemini),
            model: Some("gemini-3.1-pro-preview".to_string()),
            ..Default::default()
        };
        let (topo, _) =
            build_preset_topology(PresetName::LocalAbliterated, base, Some(24 * 1024), Some(1))
                .unwrap();
        // Left went local; right kept its cloud binding.
        assert_eq!(topo.left.provider, Some(InferenceProvider::OpenAiCompat));
        assert_eq!(topo.right.provider, Some(InferenceProvider::Gemini));
    }

    #[test]
    fn preset_local_abliterated_errors_when_nothing_fits() {
        use crate::config::inference::InferenceTopology;
        let err = build_preset_topology(
            PresetName::LocalAbliterated,
            InferenceTopology::default(),
            Some(256), // 256 MiB holds no usable model
            Some(3),
        )
        .unwrap_err();
        assert!(err.to_string().contains("no local model fits"), "{err}");
    }

    // ── D-1 (Session 13) live-call path ───────────────────────────────

    /// Stub provider that echoes the prompt back as its completion text.
    /// Used to exercise `run_test_live_call` without touching a real LLM.
    struct EchoProvider;

    #[async_trait::async_trait]
    impl crate::providers::Provider for EchoProvider {
        fn name(&self) -> &'static str {
            "echo"
        }
        async fn complete(
            &self,
            req: crate::providers::Request,
        ) -> anyhow::Result<crate::providers::Completion> {
            Ok(crate::providers::Completion {
                text: format!("echo: {}", req.prompt),
                identity: Default::default(),
                model: "echo-1".to_string(),
                latency: std::time::Duration::from_millis(1),
                input_tokens: Some(req.prompt.split_whitespace().count() as u32),
                output_tokens: Some(2),
                cache_creation_tokens: None,
                cache_read_tokens: None,
            })
        }
    }

    #[tokio::test]
    async fn run_test_live_call_routes_question_to_provider() {
        let p = EchoProvider;
        let result = run_test_live_call(&p, "2+2").await.unwrap();
        assert!(!result.dry_run);
        assert_eq!(result.question, "2+2");
        assert_eq!(result.response.as_deref(), Some("echo: 2+2"));
    }

    #[tokio::test]
    async fn run_test_live_call_records_completion_latency_and_tokens() {
        let p = EchoProvider;
        let result = run_test_live_call(&p, "hello world").await.unwrap();
        // Latency MUST be Some(_) (we recorded the elapsed millis); on
        // a fast mock it can be 0ms but the field must be populated.
        assert!(
            result.completion_latency_ms.is_some(),
            "live call should record completion_latency_ms"
        );
        assert_eq!(result.input_tokens, Some(2));
        assert_eq!(result.output_tokens, Some(2));
    }

    /// Stub provider that always errors. Pins the propagation contract:
    /// `run_test_live_call` returns `Err` with the provider name in
    /// context, not a partially-populated `LiveResult`.
    struct FailingProvider;

    #[async_trait::async_trait]
    impl crate::providers::Provider for FailingProvider {
        fn name(&self) -> &'static str {
            "failing"
        }
        async fn complete(
            &self,
            _req: crate::providers::Request,
        ) -> anyhow::Result<crate::providers::Completion> {
            anyhow::bail!("simulated provider failure")
        }
    }

    #[tokio::test]
    async fn run_test_live_call_surfaces_provider_error() {
        let p = FailingProvider;
        let err = run_test_live_call(&p, "anything").await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("failing"), "error should name provider: {msg}");
        assert!(
            msg.contains("simulated provider failure"),
            "inner error should propagate: {msg}",
        );
    }

    #[test]
    fn live_result_dry_run_constructor_sets_flag() {
        let r = LiveResult::dry_run("ping");
        assert!(r.dry_run);
        assert_eq!(r.question, "ping");
        assert!(r.response.is_none());
        assert!(r.completion_latency_ms.is_none());
    }

    #[tokio::test]
    async fn rebind_migrates_legacy_inline_key_and_preserves_unknown_slot_fields() {
        let home = tempfile::tempdir().unwrap();
        let freedom = home.path().join("freedom.yaml");
        std::fs::write(
            &freedom,
            r#"operator_id: test-operator
inference:
  mode: custom
  left:
    provider: openai_api
    model: old-model
    key: legacy-inline-key
    future_slot_field: preserve-me
"#,
        )
        .unwrap();

        rebind_at(
            home.path(),
            "left",
            "openai_compat",
            Some("new-model".to_string()),
            None,
            Some("http://127.0.0.1:11434/v1".to_string()),
        )
        .await
        .unwrap();

        let raw: serde_yaml::Value =
            serde_yaml::from_slice(&std::fs::read(&freedom).unwrap()).unwrap();
        assert_eq!(
            raw["inference"]["left"]["future_slot_field"].as_str(),
            Some("preserve-me")
        );
        assert!(
            raw["inference"]["left"]["key"].is_null(),
            "the legacy inline key must leave the public config"
        );
        let credentials = crate::config::credentials::Credentials::load_or_default(
            &home.path().join("credentials.yaml"),
        )
        .unwrap();
        assert_eq!(
            credentials.inference_left_key.as_ref().unwrap().expose(),
            "legacy-inline-key"
        );
        let effective = FreedomConfig::load_from_path(&freedom).unwrap();
        assert_eq!(
            effective.inference.left.key.as_ref().unwrap().expose(),
            "legacy-inline-key"
        );
    }

    #[tokio::test]
    async fn emit_rebind_audit_writes_0x1f_frame_with_payload() {
        use crate::config::inference::HemisphereSlot;
        use crate::wal::events::EVENT_TYPE_HEMISPHERE_REBOUND;
        use crate::wal::frame::decode_frame;
        use crate::wal::segment_header::SEGMENT_HEADER_LEN;
        use tempfile::tempdir;
        use tokio::fs::read;

        let dir = tempdir().unwrap();
        let prior = HemisphereSlot {
            provider: Some(InferenceProvider::ClaudeCli),
            model: Some("claude-opus-4-7".into()),
            key: None,
            endpoint: None,
            region: None,
            api_version: None,
            voice: None,
        };
        let new_slot = HemisphereSlot {
            provider: Some(InferenceProvider::Gemini),
            model: Some("gemini-2.5-pro".into()),
            key: None,
            endpoint: None,
            region: None,
            api_version: None,
            voice: None,
        };
        let segment = emit_rebind_audit_to(
            dir.path(),
            dir.path(),
            HemisphereRole::Right,
            &prior,
            &new_slot,
            1_700_000_000,
        )
        .await
        .unwrap();
        assert!(segment.exists(), "segment file must land on disk");

        let bytes = read(&segment).await.unwrap();
        let mut cursor = &bytes[SEGMENT_HEADER_LEN..];
        let mut found = None;
        while !cursor.is_empty() {
            let frame = decode_frame(cursor).expect("decode frame");
            if frame.header.event_type == EVENT_TYPE_HEMISPHERE_REBOUND {
                let p: serde_json::Value = serde_json::from_slice(frame.payload).unwrap();
                found = Some(p);
                break;
            }
            cursor = &cursor[frame.header.total_len as usize..];
        }
        let payload = found.expect("HEMISPHERE_REBOUND frame must be present");
        assert_eq!(payload["role"], "right");
        assert_eq!(payload["prior_provider"], "claude_cli");
        assert_eq!(payload["new_provider"], "gemini_api");
        assert_eq!(payload["model"], "gemini-2.5-pro");
        assert_eq!(payload["source"], "cli");
        assert_eq!(payload["ts_unix"], 1_700_000_000_i64);
    }

    #[tokio::test]
    async fn emit_rebind_audit_records_null_prior_when_inheriting_default() {
        use crate::config::inference::HemisphereSlot;
        use crate::wal::events::EVENT_TYPE_HEMISPHERE_REBOUND;
        use crate::wal::frame::decode_frame;
        use crate::wal::segment_header::SEGMENT_HEADER_LEN;
        use tempfile::tempdir;
        use tokio::fs::read;

        let dir = tempdir().unwrap();
        // Prior slot inheriting from single-mode default → provider None.
        let prior = HemisphereSlot {
            provider: None,
            model: None,
            key: None,
            endpoint: None,
            region: None,
            api_version: None,
            voice: None,
        };
        let new_slot = HemisphereSlot {
            provider: Some(InferenceProvider::LocalQwen),
            model: Some("Qwen/Qwen2.5-3B-Instruct".into()),
            key: None,
            endpoint: None,
            region: None,
            api_version: None,
            voice: None,
        };
        let segment = emit_rebind_audit_to(
            dir.path(),
            dir.path(),
            HemisphereRole::Cerebellum,
            &prior,
            &new_slot,
            1_700_000_001,
        )
        .await
        .unwrap();

        let bytes = read(&segment).await.unwrap();
        let mut cursor = &bytes[SEGMENT_HEADER_LEN..];
        let frame = decode_frame(cursor).expect("decode frame");
        // First frame may be HBOOT or rebind depending on writer impl —
        // walk until the right event type is found.
        let mut found = None;
        loop {
            let f = decode_frame(cursor).expect("decode frame");
            if f.header.event_type == EVENT_TYPE_HEMISPHERE_REBOUND {
                let p: serde_json::Value = serde_json::from_slice(f.payload).unwrap();
                found = Some(p);
                break;
            }
            cursor = &cursor[f.header.total_len as usize..];
            if cursor.is_empty() {
                break;
            }
        }
        let _ = frame; // silence unused-var warning from the placeholder decode above
        let payload = found.expect("HEMISPHERE_REBOUND frame must be present");
        assert!(payload["prior_provider"].is_null());
        assert_eq!(payload["new_provider"], "local_qwen");
        assert_eq!(payload["role"], "cerebellum");
    }
}
