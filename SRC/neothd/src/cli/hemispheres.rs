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
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::config::inference::{HemisphereRole, InferenceProvider};

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
        /// Provider name: `claude_cli` / `openai_api` / `openai_compat` /
        /// `gemini_api` / `local_qwen` / `hermes` / `openclaw` /
        /// `anthropic_api`.
        #[arg(long)]
        provider: String,
        /// Model identifier (e.g. `claude-opus-4-7`, `gpt-4o`).
        #[arg(long)]
        model: Option<String>,
        /// API key (when the provider needs one).
        #[arg(long)]
        key: Option<String>,
        /// Endpoint URL (for `openai_compat` / `hermes` / `openclaw`).
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
    }
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
                println!(
                    "  {:<10}  provider={:<16} model={:<28} endpoint={endpoint}",
                    role.as_str(),
                    provider,
                    model,
                );
            }
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
    let role = parse_role(role_str)?;
    let provider = InferenceProvider::from_str(provider_str).ok_or_else(|| {
        anyhow::anyhow!(
            "unknown provider `{provider_str}`. Valid: claude_cli, anthropic_api, \
             openai_api, openai_compat, gemini_api, local_qwen, hermes, openclaw"
        )
    })?;

    let mut cfg = FreedomConfig::load_from_default_path().context("load freedom.yaml")?;
    let prior = cfg.inference.slot_for(role).clone();

    // Switch the topology to Custom so per-slot overrides take effect.
    if matches!(
        cfg.inference.mode,
        crate::config::inference::TopologyMode::Single
    ) {
        cfg.inference.mode = crate::config::inference::TopologyMode::Custom;
    }

    let new_slot = crate::config::inference::HemisphereSlot {
        provider: Some(provider),
        model,
        key: key.map(crate::secret::SecretString::from),
        endpoint,
        region: None,
        api_version: None,
    };
    match role {
        HemisphereRole::Left => cfg.inference.left = new_slot.clone(),
        HemisphereRole::Right => cfg.inference.right = new_slot.clone(),
        HemisphereRole::Cerebellum => cfg.inference.cerebellum = new_slot.clone(),
    }

    let path = FreedomConfig::default_path();
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    // A3 / B-Rollback: snapshot the freedom.yaml BEFORE rewriting it,
    // so `neoth rollback apply` can restore the prior hemisphere
    // binding if this rebind turns out to be wrong. Off when operator
    // removed `config_write` from `rollback.capture_kinds`.
    let prior_yaml_bytes = std::fs::read(&path).unwrap_or_default();
    let wal_dir = FreedomConfig::default_wal_dir();
    std::fs::create_dir_all(&wal_dir).context("create WAL dir for hemispheres audit")?;
    let snapshot_segment = wal_dir.join(format!("hemispheres-snapshot-{}.wal", now_unix));
    let (snap_writer, snap_join) = crate::wal::writer::spawn(snapshot_segment.clone())
        .context("spawn WAL writer for hemispheres rollback snapshot")?;
    let _ = crate::wal::snapshot::emit_if_policy_allows(
        &snap_writer,
        &cfg.rollback,
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

    cfg.save_public_to_default_path()
        .with_context(|| format!("write {}", path.display()))?;

    // SPEC §4: emit the rebind audit frame immediately so the operator
    // sees provenance in the WAL even when the daemon is not running.
    // Mirrors the `memory forget --audit` pattern from CDX-01.
    let audit_segment = emit_rebind_audit(role, &prior, &new_slot, now_unix).await?;

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "role": role.as_str(),
                    "prior_provider": prior.provider.map(|p| p.as_str()),
                    "new_provider": provider.as_str(),
                    "model": new_slot.model,
                    "mode": cfg.inference.mode.as_str(),
                    "audit_segment": audit_segment.display().to_string(),
                }))?
            );
        }
        OutputFormat::Table => {
            let prior_p = prior.provider.map(|p| p.as_str()).unwrap_or("(default)");
            println!(
                "# Hemisphere rebind: {role:?}  {prior_p} → {}",
                provider.as_str()
            );
            println!(
                "  freedom.yaml::inference.{} updated atomically (mode now {})",
                role.as_str(),
                cfg.inference.mode.as_str()
            );
            println!(
                "  WAL 0x1F HEMISPHERE_REBOUND audit frame written to {}",
                audit_segment.display()
            );
        }
    }
    Ok(())
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
    emit_rebind_audit_to(
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
    wal_dir: &std::path::Path,
    role: HemisphereRole,
    prior: &crate::config::inference::HemisphereSlot,
    new_slot: &crate::config::inference::HemisphereSlot,
    now_unix: i64,
) -> Result<std::path::PathBuf> {
    std::fs::create_dir_all(wal_dir).context("create WAL dir for hemisphere rebind audit")?;
    let segment = wal_dir.join(format!("hemisphere-rebind-{}.wal", now_unix));

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

    let (writer, join) = crate::wal::writer::spawn(segment.clone())
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
    let provider = crate::providers::from_config_for_role(cfg, role)
        .await
        .with_context(|| format!("build provider for role {}", role.as_str()))?;
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
        let slot = cfg.inference.slot_for(role);
        if let Some(slot_provider) = slot.provider {
            let kind = slot_provider.to_provider_kind();
            let home = FreedomConfig::default_neoth_home();
            crate::consent::ensure_granted_or_prompt(&home, kind)?;
        }
        if dry_run {
            Some(LiveResult::dry_run(q))
        } else {
            Some(run_test_live_call(provider.as_ref(), q).await?)
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
                model: "echo-1".to_string(),
                latency: std::time::Duration::from_millis(1),
                input_tokens: Some(req.prompt.split_whitespace().count() as u32),
                output_tokens: Some(2),
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
        };
        let new_slot = HemisphereSlot {
            provider: Some(InferenceProvider::Gemini),
            model: Some("gemini-2.5-pro".into()),
            key: None,
            endpoint: None,
            region: None,
            api_version: None,
        };
        let segment = emit_rebind_audit_to(
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
        };
        let new_slot = HemisphereSlot {
            provider: Some(InferenceProvider::LocalQwen),
            model: Some("Qwen/Qwen2.5-3B-Instruct".into()),
            key: None,
            endpoint: None,
            region: None,
            api_version: None,
        };
        let segment = emit_rebind_audit_to(
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
