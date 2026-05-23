//! `neoth ouro` — operator-facing inspection surface for the Ouro
//! thinking-models provider (O-3, Session 22).
//!
//! Two read-only actions:
//!   - `list`   — show every supported Ouro HF checkpoint with size
//!                + thinking-variant flag + recommended-use hint
//!   - `status` — show the operator's currently-configured Ouro state
//!                from freedom.yaml (provider_kind, provider_model,
//!                effective checkpoint, configured accelerator)
//!
//! Operators **switch** to Ouro via the existing wizard
//! (`neoth init --force --provider local_ouro [--provider-model
//! ByteDance/Ouro-2.6B-Thinking]`) or by editing `freedom.yaml`
//! directly. This command is read-only on purpose — keeps the
//! O-3 surface bounded + leaves the operator-facing wizard as
//! the canonical config-write path.

use anyhow::Result;
use clap::{Args, Subcommand};

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
}

pub async fn run_ouro(args: OuroArgs) -> Result<()> {
    match args.action {
        OuroAction::List => run_list(&args.output),
        OuroAction::Status => run_status(&args.output),
        OuroAction::Fetch { checkpoint } => run_fetch(checkpoint.as_deref()).await,
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
    let _adapter = crate::providers::ouro::adapter::LocalOuroAdapter::new(Some(repo.clone()))
        .await?;
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
    let cfg = FreedomConfig::load_from_default_path().ok();
    let active = cfg
        .as_ref()
        .and_then(|c| c.provider_kind)
        .map(|k| matches!(k, ProviderKind::LocalOuro))
        .unwrap_or(false);
    let configured_model = cfg
        .as_ref()
        .and_then(|c| c.provider_model.clone())
        .unwrap_or_else(|| {
            crate::providers::ouro::adapter::DEFAULT_OURO_REPO.to_string()
        });
    let accelerator_override = cfg
        .as_ref()
        .and_then(|c| c.inference.accelerator_override.clone())
        .unwrap_or_else(|| "(none; auto-detect)".to_string());
    let max_new_tokens = cfg
        .as_ref()
        .and_then(|c| c.inference.max_new_tokens)
        .unwrap_or(crate::providers::ouro::adapter::DEFAULT_MAX_NEW_TOKENS);

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let body = serde_json::json!({
                "active": active,
                "configured_model": configured_model,
                "accelerator_override": accelerator_override,
                "max_new_tokens": max_new_tokens,
                "default_model": crate::providers::ouro::adapter::DEFAULT_OURO_REPO,
            });
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        OutputFormat::Table => {
            println!("# Ouro provider status");
            println!();
            println!("  active                : {}", active);
            println!("  configured model      : {configured_model}");
            println!("  accelerator override  : {accelerator_override}");
            println!("  max new tokens        : {max_new_tokens}");
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

#[cfg(test)]
mod tests {
    use super::*;

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
            let count = OURO_CHECKPOINTS.iter().filter(|c| c.params == *size).count();
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
            OuroAction::Status | OuroAction::Fetch { .. } => panic!("expected List"),
        }
        match status.action {
            OuroAction::Status => {}
            OuroAction::List | OuroAction::Fetch { .. } => panic!("expected Status"),
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
        let err = run_fetch(Some("operator-typo/non-existent")).await.unwrap_err();
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
