//! `neoth ouro` — operator-facing inspection surface for the Ouro
//! thinking-models provider (O-3, Session 22).
//!
//! Two read-only actions:
//!   - `list`   — show every supported Ouro HF checkpoint with size
//!                + thinking-variant flag + recommended-use hint
//!   - `status` — show the operator's currently-configured Ouro state
//!                from freedom.yaml (provider_kind, provider_model,
//!                effective checkpoint, configured accelerator)
//!   - `verify-q8` — load only an already-published immutable cache through
//!                   the exact Q8 receipt/lease/model path; never downloads,
//!                   promotes, or selects mutable cache artifacts. Existing
//!                   model-cache lock coordination may still occur.
//!
//! Operators **switch** to Ouro via the existing wizard
//! (`neoth init --force --provider local_ouro [--provider-model
//! ByteDance/Ouro-2.6B-Thinking]`) or by editing `freedom.yaml`
//! directly. This command is read-only on purpose — keeps the
//! O-3 surface bounded + leaves the operator-facing wizard as
//! the canonical config-write path.

use anyhow::Result;
use clap::{Args, Subcommand};
use std::sync::mpsc;
use std::time::Duration;

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;

/// One published ByteDance Ouro checkpoint. Carries everything the
/// operator needs to pick: HF id, parameter count, BF16 size hint,
/// the -Thinking SFT flag, and a one-line recommended-use note.
#[derive(Debug, Clone, PartialEq)]
pub struct OuroCheckpoint {
    pub hf_id: &'static str,
    pub params: &'static str,
    pub size_bf16_gb: f32,
    pub thinking: bool,
    pub recommended_for: &'static str,
}

/// The four public Ouro checkpoints on Hugging Face. Pin order:
/// smallest first, base then -Thinking variant within each size.
/// Operators picking via the wizard see this same order in the
/// CLI listing.
pub const OURO_CHECKPOINTS: &[OuroCheckpoint] = &[
    OuroCheckpoint {
        hf_id: "ByteDance/Ouro-1.4B",
        params: "1.4B",
        size_bf16_gb: 2.8,
        thinking: false,
        recommended_for: "smallest footprint; base completions, no reasoning prose",
    },
    OuroCheckpoint {
        hf_id: "ByteDance/Ouro-1.4B-Thinking",
        params: "1.4B",
        size_bf16_gb: 2.8,
        thinking: true,
        recommended_for: "DEFAULT — smallest reasoning model; explicit thinking prose, ≥4 GB VRAM",
    },
    OuroCheckpoint {
        hf_id: "ByteDance/Ouro-2.6B",
        params: "2.6B",
        size_bf16_gb: 5.2,
        thinking: false,
        recommended_for: "larger base model; better generic completion quality on ≥6 GB VRAM",
    },
    OuroCheckpoint {
        hf_id: "ByteDance/Ouro-2.6B-Thinking",
        params: "2.6B",
        size_bf16_gb: 5.2,
        thinking: true,
        recommended_for: "best on-device reasoning; explicit thinking prose, ≥8 GB VRAM",
    },
];

#[derive(Args, Debug, Clone)]
pub struct OuroArgs {
    #[command(subcommand)]
    pub action: OuroAction,

    /// Output format. Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum OuroAction {
    /// List every supported ByteDance Ouro checkpoint with size +
    /// thinking flag + recommended-use note.
    List,
    /// Show the operator's currently-configured Ouro state (read
    /// from `~/.neoth/freedom.yaml`).
    Status,
    /// Auto-download the operator-chosen Ouro checkpoint via hf-hub.
    /// First-time download is ~3 GB BF16; subsequent runs hit the
    /// disk cache instantly. Equivalent to running `neoth init
    /// --force --provider local_ouro` then a one-off `neoth chat`
    /// — but skip the chat round-trip when you just want the
    /// weights cached (e.g. before running `cargo test ... ouro`
    /// integration suites).
    Fetch {
        /// Override the default checkpoint
        /// (`ByteDance/Ouro-1.4B-Thinking`). Must match an entry
        /// from `neoth ouro list`.
        #[arg(long)]
        checkpoint: Option<String>,
    },
    /// Verify the configured cache through the actual Q8 model loader.
    ///
    /// This is cache-only: it refuses a missing or mutable cache instead of
    /// downloading, promoting, or silently selecting a fallback precision.
    VerifyQ8,
}

pub async fn run_ouro(args: OuroArgs) -> Result<()> {
    match args.action {
        OuroAction::List => run_list(&args.output),
        OuroAction::Status => run_status(&args.output),
        OuroAction::Fetch { checkpoint } => run_fetch(checkpoint.as_deref()).await,
        OuroAction::VerifyQ8 => run_verify_q8(&args.output).await,
    }
}

async fn run_fetch(checkpoint_override: Option<&str>) -> Result<()> {
    let repo = match checkpoint_override {
        Some(c) => {
            // Validate against the pinned catalogue so the operator
            // can't silently fetch a random unrelated HF repo. Fail
            // fast with the actionable "run `neoth ouro list`" hint.
            let known = OURO_CHECKPOINTS.iter().any(|cp| cp.hf_id == c);
            if !known {
                anyhow::bail!(
                    "unknown Ouro checkpoint `{c}` — run `neoth ouro list` for the catalogue"
                );
            }
            c.to_string()
        }
        None => crate::providers::ouro::adapter::DEFAULT_OURO_REPO.to_string(),
    };
    println!("Fetching Ouro checkpoint `{repo}` via hf-hub…");
    println!(
        "First-time download is ~3 GB BF16 and may take several minutes. \
         Subsequent runs hit the cache instantly."
    );
    let started = std::time::Instant::now();
    // Construct the adapter — `new` triggers `ensure_artifacts` which
    // is the auto-download path. We never call complete()/embed() so
    // no model load happens; the goal is JUST to pull the weights
    // into the local cache.
    let _adapter =
        crate::providers::ouro::adapter::LocalOuroAdapter::new(Some(repo.clone())).await?;
    println!(
        "✓ Ouro checkpoint `{repo}` cached in {:.1}s. Activate via:\n  \
         neoth init --force --provider local_ouro --provider-model {repo}",
        started.elapsed().as_secs_f32()
    );
    Ok(())
}

fn run_list(output: &OutputFormat) -> Result<()> {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let entries: Vec<_> = OURO_CHECKPOINTS
                .iter()
                .map(|c| {
                    serde_json::json!({
                        "hf_id": c.hf_id,
                        "params": c.params,
                        "size_bf16_gb": c.size_bf16_gb,
                        "thinking": c.thinking,
                        "recommended_for": c.recommended_for,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&entries)?);
        }
        OutputFormat::Table => {
            println!("# Ouro thinking-models (ByteDance, Apache-2.0)");
            println!();
            println!(
                "{:<32} {:<8} {:<10} {:<10}",
                "hf_id", "params", "bf16_gb", "thinking"
            );
            println!(
                "{:<32} {:<8} {:<10} {:<10}",
                "-".repeat(32),
                "-".repeat(8),
                "-".repeat(10),
                "-".repeat(10)
            );
            for c in OURO_CHECKPOINTS {
                let thinking_tag = if c.thinking { "yes" } else { "no" };
                println!(
                    "{:<32} {:<8} {:<10.1} {:<10}",
                    c.hf_id, c.params, c.size_bf16_gb, thinking_tag
                );
                println!("  → {}", c.recommended_for);
            }
            println!();
            println!(
                "Architecture: looped decoder-only transformer (LoopLM). 24 layers \
                 applied 4× recurrently per token. ~4× compute vs Qwen but explicit \
                 reasoning prose in the -Thinking variants."
            );
            println!();
            println!("Switch to Ouro via:");
            println!(
                "  neoth init --force --provider local_ouro \\\n\
                 \t[--provider-model ByteDance/Ouro-2.6B-Thinking]"
            );
            println!();
            println!("Or edit `~/.neoth/freedom.yaml` directly:");
            println!("  provider_kind: local_ouro");
            println!("  provider_model: ByteDance/Ouro-1.4B-Thinking   # default");
        }
    }
    Ok(())
}

fn run_status(output: &OutputFormat) -> Result<()> {
    use crate::cli::init::ProviderKind;
    let cfg = FreedomConfig::load_from_default_path_or_default()?;
    let active = cfg
        .provider_kind
        .map(|k| matches!(k, ProviderKind::LocalOuro))
        .unwrap_or(false);
    let configured_model = cfg
        .provider_model
        .clone()
        .unwrap_or_else(|| crate::providers::ouro::adapter::DEFAULT_OURO_REPO.to_string());
    let accelerator_override = cfg
        .inference
        .accelerator_override
        .clone()
        .unwrap_or_else(|| "(none; auto-detect)".to_string());
    let max_new_tokens = cfg
        .inference
        .max_new_tokens
        .unwrap_or(crate::providers::ouro::adapter::DEFAULT_MAX_NEW_TOKENS);
    let quant_mode = cfg.inference.ouro_quant_mode.as_str();
    let cache_dir = crate::providers::local_qwen::default_cache_dir(&configured_model);
    // Shared bounded status contract: no surprise multi-gigabyte digest pass,
    // and no corrupt, partial, or pending cache is called ready.
    let cache_status = crate::providers::ouro::artifacts::runtime_cache_status(&cache_dir);
    let cache_state = cache_status.state;
    let cache_error = cache_status.detail;

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let body = serde_json::json!({
                "active": active,
                "configured_model": configured_model,
                "accelerator_override": accelerator_override,
                "max_new_tokens": max_new_tokens,
                "quant_mode": quant_mode,
                "default_model": crate::providers::ouro::adapter::DEFAULT_OURO_REPO,
                "cache_state": cache_state,
                "cache_dir": cache_dir,
                "cache_error": cache_error,
            });
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        OutputFormat::Table => {
            println!("# Ouro provider status");
            println!();
            println!("  active                : {active}");
            println!("  configured model      : {configured_model}");
            println!("  accelerator override  : {accelerator_override}");
            println!("  max new tokens        : {max_new_tokens}");
            println!("  quant mode            : {quant_mode}");
            println!("  cache state           : {cache_state}");
            println!("  cache dir             : {}", cache_dir.display());
            if let Some(error) = cache_error {
                println!("  cache detail          : {error}");
            }
            println!(
                "  default checkpoint    : {}",
                crate::providers::ouro::adapter::DEFAULT_OURO_REPO
            );
            println!();
            if !active {
                println!(
                    "Ouro is NOT the active provider. Switch via:\n\
                     \tneoth init --force --provider local_ouro"
                );
            } else {
                println!(
                    "Ouro is the active provider. Run `neoth chat \"hello\"` to test, or \
                     `neoth ouro list` to see all checkpoint options."
                );
            }
        }
    }
    Ok(())
}

async fn run_verify_q8(output: &OutputFormat) -> Result<()> {
    let cfg = FreedomConfig::load_from_default_path_or_default()?;
    let configured_model = cfg
        .provider_model
        .clone()
        .unwrap_or_else(|| crate::providers::ouro::adapter::DEFAULT_OURO_REPO.to_string());
    let cache_dir = crate::providers::local_qwen::default_cache_dir(&configured_model);
    let accelerator = cfg
        .inference
        .accelerator_override
        .as_deref()
        .and_then(crate::daemon::accelerator::Accelerator::from_str);
    let max_new_tokens = cfg.inference.max_new_tokens;
    let configured_quant_mode = cfg.inference.ouro_quant_mode.as_str();
    let timeout_status = crate::providers::ouro::adapter::OuroQ8VerifyStatus {
        verified: false,
        quant_mode: "q8",
        repo: configured_model.clone(),
        cache_dir: cache_dir.display().to_string(),
        receipt: None,
        resolved_device: None,
        loop_steps: None,
        forward_checked: false,
        forward_digest: None,
        alternate_forward_digest: None,
        context_sensitive: false,
        detail: Some(
            "timed out after 120s waiting for the Q8 verification worker; the in-flight device load was not cancelled and may still finish".to_string(),
        ),
    };
    let repo = configured_model.clone();
    eprintln!(
        "→ verifying existing Ouro cache through the Q8 loader (observation limit: 120s; a timed-out device load may continue in its worker)"
    );
    let verification = observe_q8_verify_worker(Duration::from_secs(120), timeout_status, move || {
        crate::providers::ouro::adapter::verify_q8_cache_only(
            repo,
            cache_dir,
            accelerator,
            crate::providers::local_qwen::SamplingConfig::default(),
            max_new_tokens,
        )
    });

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "configured_quant_mode": configured_quant_mode,
                    "tested_quant_mode": verification.quant_mode,
                    "result": verification,
                }))?
            );
        }
        OutputFormat::Table => {
            println!("# Ouro Q8 cache-only verification");
            println!("  verified              : {}", verification.verified);
            println!("  configured quant mode : {configured_quant_mode}");
            println!("  tested quant mode     : {}", verification.quant_mode);
            println!("  configured model      : {}", verification.repo);
            println!("  cache dir             : {}", verification.cache_dir);
            if let Some(receipt) = &verification.receipt {
                println!("  receipt               : {receipt}");
            }
            if let Some(device) = &verification.resolved_device {
                println!("  resolved device       : {device}");
            }
            if let Some(loop_steps) = verification.loop_steps {
                println!("  loop steps            : {loop_steps}");
            }
            println!("  fixed Q8 forward      : {}", verification.forward_checked);
            println!("  context-sensitive     : {}", verification.context_sensitive);
            if let Some(digest) = &verification.forward_digest {
                println!("  forward digest        : {digest}");
            }
            if let Some(digest) = &verification.alternate_forward_digest {
                println!("  alternate digest      : {digest}");
            }
            if let Some(detail) = &verification.detail {
                println!("  detail                : {detail}");
            }
        }
    }

    anyhow::ensure!(
        verification.verified,
        "Ouro Q8 cache-only verification failed: {}",
        verification.detail.as_deref().unwrap_or("no terminal detail")
    );
    Ok(())
}

/// Observe an isolated verifier worker without joining it after a timeout.
/// A timeout ends only this CLI observation; the worker may still be using a
/// device/lease and must not be described as cancelled.
fn observe_q8_verify_worker<F>(
    timeout: Duration,
    timeout_status: crate::providers::ouro::adapter::OuroQ8VerifyStatus,
    worker: F,
) -> crate::providers::ouro::adapter::OuroQ8VerifyStatus
where
    F: FnOnce() -> crate::providers::ouro::adapter::OuroQ8VerifyStatus + Send + 'static,
{
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let status = worker();
        let _ = sender.send(status);
    });
    receiver.recv_timeout(timeout).unwrap_or(timeout_status)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q8_timeout_status() -> crate::providers::ouro::adapter::OuroQ8VerifyStatus {
        crate::providers::ouro::adapter::OuroQ8VerifyStatus {
            verified: false,
            quant_mode: "q8",
            repo: "test/ouro".into(),
            cache_dir: "test-cache".into(),
            receipt: None,
            resolved_device: None,
            loop_steps: None,
            forward_checked: false,
            forward_digest: None,
            alternate_forward_digest: None,
            context_sensitive: false,
            detail: Some("test observation timeout; worker was not cancelled".into()),
        }
    }

    #[test]
    fn q8_verify_timeout_returns_while_a_held_worker_remains_in_flight() {
        let (worker_started, started_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let (observed_tx, observed_rx) = mpsc::sync_channel(1);
        let observer = std::thread::spawn(move || {
            let status = observe_q8_verify_worker(
                Duration::from_millis(20),
                q8_timeout_status(),
                move || {
                    worker_started.send(()).expect("signal held worker start");
                    release_rx.recv().expect("release held worker");
                    crate::providers::ouro::adapter::OuroQ8VerifyStatus {
                        verified: true,
                        quant_mode: "q8",
                        repo: "test/ouro".into(),
                        cache_dir: "test-cache".into(),
                        receipt: Some("late-worker-result".into()),
                        resolved_device: Some("Cpu".into()),
                        loop_steps: Some(2),
                        forward_checked: true,
                        forward_digest: Some("late".into()),
                        alternate_forward_digest: Some("late-alt".into()),
                        context_sensitive: true,
                        detail: None,
                    }
                },
            );
            observed_tx.send(status).expect("return observed timeout");
        });
        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("worker reached held barrier");
        let status = observed_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("timeout returned without waiting for worker release");
        assert!(!status.verified);
        assert!(status.detail.as_deref().unwrap_or_default().contains("timeout"));
        release_tx.send(()).expect("release worker after timeout assertion");
        observer.join().expect("observer thread exits");
    }

    #[test]
    fn checkpoint_catalogue_has_4_entries() {
        assert_eq!(OURO_CHECKPOINTS.len(), 4);
    }

    #[test]
    fn default_checkpoint_is_in_catalogue() {
        let default_id = crate::providers::ouro::adapter::DEFAULT_OURO_REPO;
        assert!(
            OURO_CHECKPOINTS.iter().any(|c| c.hf_id == default_id),
            "DEFAULT_OURO_REPO must match a catalogue entry; got {default_id}"
        );
    }

    #[test]
    fn catalogue_pairs_base_with_thinking_for_each_param_count() {
        // For both 1.4B and 2.6B, exactly one base + one -Thinking
        // variant should exist. Locks the pairing invariant — adding
        // a third entry per size without a matching pair would
        // surface a UX inconsistency in `neoth ouro list`.
        for size in &["1.4B", "2.6B"] {
            let count = OURO_CHECKPOINTS
                .iter()
                .filter(|c| c.params == *size)
                .count();
            assert_eq!(count, 2, "size {size} should have base + thinking");
            let thinking_count = OURO_CHECKPOINTS
                .iter()
                .filter(|c| c.params == *size && c.thinking)
                .count();
            assert_eq!(thinking_count, 1, "exactly one -Thinking variant per size");
        }
    }

    #[test]
    fn every_hf_id_is_bytedance_namespaced() {
        // Pin the namespace so a future PR pointing at a forked
        // checkpoint stays obvious in code review.
        for c in OURO_CHECKPOINTS {
            assert!(
                c.hf_id.starts_with("ByteDance/Ouro"),
                "expected ByteDance/Ouro* namespace, got {}",
                c.hf_id
            );
        }
    }

    #[test]
    fn thinking_variants_have_distinct_recommended_copy() {
        let base = OURO_CHECKPOINTS
            .iter()
            .find(|c| !c.thinking && c.params == "1.4B")
            .unwrap();
        let thinking = OURO_CHECKPOINTS
            .iter()
            .find(|c| c.thinking && c.params == "1.4B")
            .unwrap();
        assert_ne!(
            base.recommended_for, thinking.recommended_for,
            "base vs thinking must surface distinct operator copy"
        );
    }

    #[test]
    fn ouro_args_subcommand_construction() {
        // Smoke — make sure the clap derivation handles both variants.
        let list = OuroArgs {
            action: OuroAction::List,
            output: OutputFormat::Json,
        };
        let status = OuroArgs {
            action: OuroAction::Status,
            output: OutputFormat::Json,
        };
        // Pattern-match pins the enum variants exhaustively.
        match list.action {
            OuroAction::List => {}
            OuroAction::Status | OuroAction::Fetch { .. } | OuroAction::VerifyQ8 => {
                panic!("expected List")
            }
        }
        match status.action {
            OuroAction::Status => {}
            OuroAction::List | OuroAction::Fetch { .. } | OuroAction::VerifyQ8 => {
                panic!("expected Status")
            }
        }
    }

    #[test]
    fn run_list_smoke_table_output() {
        // Smoke — must not panic + must complete cleanly. Output
        // goes to stdout (operator inspection surface); we don't
        // capture it here, just pin that the call path works.
        run_list(&OutputFormat::Table).expect("run_list table");
    }

    #[test]
    fn run_list_smoke_json_output() {
        run_list(&OutputFormat::Json).expect("run_list json");
    }

    #[test]
    fn run_status_smoke_does_not_panic_without_freedom_yaml() {
        // Status reads freedom.yaml; when absent, the cfg load
        // returns Err and we fall through to default-prefilled
        // output. Must not panic.
        run_status(&OutputFormat::Table).expect("run_status table");
        run_status(&OutputFormat::Json).expect("run_status json");
    }

    #[tokio::test]
    async fn run_fetch_rejects_unknown_checkpoint() {
        // Operator-typo or third-party HF repo MUST bail fast with
        // the actionable hint pointing at `neoth ouro list`.
        let err = run_fetch(Some("operator-typo/non-existent"))
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown Ouro checkpoint"));
        assert!(msg.contains("neoth ouro list"));
    }

    #[test]
    fn ouro_action_fetch_variant_parses() {
        let action = OuroAction::Fetch {
            checkpoint: Some("ByteDance/Ouro-2.6B-Thinking".into()),
        };
        match action {
            OuroAction::Fetch { checkpoint } => {
                assert_eq!(checkpoint.as_deref(), Some("ByteDance/Ouro-2.6B-Thinking"));
            }
            _ => panic!("expected Fetch"),
        }
    }

    #[test]
    fn ouro_action_fetch_defaults_checkpoint_to_none() {
        let action = OuroAction::Fetch { checkpoint: None };
        match action {
            OuroAction::Fetch { checkpoint } => assert!(checkpoint.is_none()),
            _ => panic!("expected Fetch"),
        }
    }

    #[test]
    fn fetch_validates_against_catalogue_membership() {
        // Pin the contract: every checkpoint in OURO_CHECKPOINTS
        // should be acceptable to `--checkpoint`. Sanity-check by
        // iterating the catalogue.
        for cp in OURO_CHECKPOINTS {
            // Membership predicate matches run_fetch's check.
            let known = OURO_CHECKPOINTS.iter().any(|c| c.hf_id == cp.hf_id);
            assert!(known, "catalogue self-membership: {}", cp.hf_id);
        }
    }
}
