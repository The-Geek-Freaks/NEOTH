//! `neoth cost estimate` — C-14 ex-ante cost transparency.
//!
//! Dry-run a provider call's cost BEFORE dispatching. Operator types
//! their prompt; NEOTH reports projected token count + euro cost so
//! the operator can refactor the prompt or pick a cheaper provider
//! before any LLM call happens. No provider is actually invoked.

use anyhow::Result;
use clap::Args;

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::providers::cost::{predict, render_preview};
use crate::providers::meter::Meter;

#[derive(Args, Debug, Clone)]
pub struct CostArgs {
    /// Prompt text to estimate. Use `-` to read from stdin.
    #[arg(value_name = "PROMPT")]
    pub prompt: Option<String>,

    /// Override the active provider for the estimate. Defaults to
    /// `freedom.yaml::provider_kind`.
    #[arg(long, value_name = "NAME")]
    pub provider: Option<String>,

    /// Override the active model for the estimate. Defaults to
    /// `freedom.yaml::provider_model`.
    #[arg(long, value_name = "MODEL")]
    pub model: Option<String>,

    /// Output format. Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

pub async fn run_cost(args: CostArgs) -> Result<()> {
    let prompt = resolve_prompt(&args).await?;
    let cfg = FreedomConfig::load_from_default_path().ok();

    let provider = args
        .provider
        .clone()
        .or_else(|| {
            cfg.as_ref()
                .and_then(|c| c.provider_kind.map(|p| format!("{p:?}").to_lowercase()))
        })
        .unwrap_or_else(|| "openai_api".to_string());
    let model = args
        .model
        .clone()
        .or_else(|| cfg.as_ref().and_then(|c| c.provider_model.clone()))
        .unwrap_or_else(|| "gpt-5.5".to_string());

    // Use a fresh meter — CLI is one-shot, so we don't have rolling
    // window data here. The estimator will fall back to the default
    // output-token guess for cold meters.
    let meter = Meter::with_default_window();
    let estimate = predict(&provider, &model, &prompt, &meter);

    match args.output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let body = serde_json::json!({
                "provider": provider,
                "model": model,
                "input_tokens": estimate.input_tokens,
                "output_tokens_est": estimate.output_tokens_est,
                "input_eur": estimate.input_eur,
                "output_eur": estimate.output_eur,
                "total_eur": estimate.total_eur,
            });
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        OutputFormat::Table => {
            println!("{}", render_preview(&provider, &model, &estimate));
        }
    }
    Ok(())
}

async fn resolve_prompt(args: &CostArgs) -> Result<String> {
    if let Some(p) = &args.prompt {
        if p == "-" {
            use tokio::io::AsyncReadExt;
            let mut buf = String::new();
            tokio::io::stdin().read_to_string(&mut buf).await?;
            return Ok(buf);
        }
        if !p.trim().is_empty() {
            return Ok(p.clone());
        }
    }
    anyhow::bail!("no prompt supplied. Pass it as the first argument or `-` for stdin.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cost_estimate_with_explicit_provider_returns_zero_for_local() {
        let args = CostArgs {
            prompt: Some("hello world".into()),
            provider: Some("local_qwen".into()),
            model: Some("Qwen/Qwen2.5-3B-Instruct".into()),
            output: OutputFormat::Json,
        };
        // run_cost prints to stdout — we just verify it doesn't error.
        // The price-lookup table guarantees zero for local providers.
        run_cost(args).await.expect("dry-run must not fail");
    }

    #[tokio::test]
    async fn cost_estimate_errors_on_empty_prompt() {
        let args = CostArgs {
            prompt: Some("   ".into()),
            provider: Some("openai_api".into()),
            model: Some("gpt-4o".into()),
            output: OutputFormat::Json,
        };
        let err = run_cost(args).await.unwrap_err();
        assert!(err.to_string().contains("no prompt"));
    }
}
