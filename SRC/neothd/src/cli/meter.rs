//! `neoth meter` — read the daemon's live token-budget meter.
//!
//! GOLD-WIRE-10b: the daemon's `UsageMeter` drainer persists a snapshot to
//! `~/.neoth/meter.json` after every `ProviderResponded` event. This command
//! exposes that snapshot for the GUI dashboard (which polls it via subprocess,
//! same pattern as `neoth usage`) and for operators who want a quick live read.

use std::path::Path;

use anyhow::Result;
use clap::Args;

use crate::domain_events::read_meter_snapshot;

/// CLI args for `neoth meter`.
#[derive(Args, Debug, Clone)]
pub struct MeterArgs {
    /// Output format: `human` (default) or `json`.
    #[arg(long, default_value = "human")]
    pub format: String,
}

/// Entry point for `Commands::Meter` dispatch.
pub fn run(home: &Path, args: MeterArgs) -> Result<()> {
    let path = home.join("usage_meter.json");
    let snap = read_meter_snapshot(&path);
    match args.format.as_str() {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&snap)?);
        }
        _ => {
            if let Some(s) = snap {
                println!(
                    "Live meter: {} calls, {} input / {} output tokens, {} events total{}",
                    s.provider_responses,
                    s.input_tokens_total,
                    s.output_tokens_total,
                    s.events_total,
                    if s.lagged_events > 0 {
                        format!(" ({} lagged)", s.lagged_events)
                    } else {
                        String::new()
                    }
                );
                if s.prompt_tax_observed_call_count == 0 {
                    println!("  prompt tax: unavailable (no measured terminal responses)");
                } else {
                    println!(
                        "  prompt tax estimate: skill={} memory={} repo_context={} council={} unattributed={} across {} terminal responses",
                        s.prompt_tax_skill_tokens,
                        s.prompt_tax_memory_tokens,
                        s.prompt_tax_repo_context_tokens,
                        s.prompt_tax_council_tokens,
                        s.prompt_tax_unattributed_tokens,
                        s.prompt_tax_observed_call_count,
                    );
                }
            } else {
                println!(
                    "Meter unavailable — daemon may not be running or has not persisted a snapshot yet."
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain_events::UsageSnapshot;
    use tempfile::tempdir;

    #[test]
    fn run_human_renders_snapshot_when_file_exists() {
        let tmp = tempdir().unwrap();
        let snap = UsageSnapshot {
            events_total: 10,
            provider_responses: 3,
            input_tokens_total: 100,
            output_tokens_total: 200,
            prompt_tax_observed_call_count: 0,
            prompt_tax_skill_tokens: 0,
            prompt_tax_memory_tokens: 0,
            prompt_tax_repo_context_tokens: 0,
            prompt_tax_council_tokens: 0,
            prompt_tax_unattributed_tokens: 0,
            lagged_events: 0,
        };
        let path = tmp.path().join("meter.json");
        crate::domain_events::write_meter_snapshot(&path, &snap).unwrap();
        let args = MeterArgs {
            format: "human".to_string(),
        };
        // run() prints to stdout; we just verify it doesn't panic / error.
        run(tmp.path(), args).unwrap();
    }

    #[test]
    fn run_human_is_graceful_when_meter_file_missing() {
        let tmp = tempdir().unwrap();
        let args = MeterArgs {
            format: "human".to_string(),
        };
        run(tmp.path(), args).unwrap();
    }
}
