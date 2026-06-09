//! `neoth status` — daemon-state snapshot. Phase 33c BS-1.
//!
//! Reads the same on-disk surfaces the future `/healthz` HTTP endpoint
//! will read. Pure CLI — no daemon connection required, no IPC. Useful
//! when the operator wants to check tier counts, WAL growth, or active
//! channels without tailing logs.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::daemon::observability::snapshot;

#[derive(Args, Debug, Clone)]
pub struct StatusArgs {
    /// Override the `~/.neoth/` home dir (mostly for tests).
    #[arg(long, value_name = "DIR")]
    pub home: Option<PathBuf>,

    /// Print as Prometheus text format instead of the default table.
    /// Useful when the operator wants to scrape NEOTH from a Prometheus
    /// instance running on the same host.
    #[arg(long)]
    pub prometheus: bool,

    /// Output format. Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

pub async fn run_status(args: StatusArgs) -> Result<()> {
    let home = args.home.unwrap_or_else(FreedomConfig::default_neoth_home);

    // Best-effort config load — a freshly-init'd home has a freedom.yaml,
    // but the operator might run `neoth status` against an arbitrary dir
    // for diagnostics. Missing config → snapshot still works, channels +
    // operator-id come back as None.
    let cfg = FreedomConfig::load_from_path(&home.join("freedom.yaml")).ok();
    let snap = snapshot(&home, cfg.as_ref())?;

    // GOLD-ADOPT-27 — channel health probe (which channels are live /
    // misconfigured / absent). Best-effort credential load from this home.
    let creds = crate::config::credentials::Credentials::load_or_default(
        &home.join("credentials.yaml"),
    )
    .unwrap_or_default();
    let channel_health = crate::channels::probe::probe_all(
        &crate::channels::probe::ChannelCredsView::from_config(cfg.as_ref(), &creds),
    );

    if args.prometheus {
        // Channel health is config state, not a time-series metric — keep the
        // Prometheus surface unchanged.
        print!("{}", snap.render_prometheus());
        return Ok(());
    }

    // Headline operating mode (gated | full-auto | advanced) — derived from the
    // (autonomy, skills.enable_all_bundled) pair. `None` when no config loaded.
    let operating_mode = cfg
        .as_ref()
        .map(crate::cli::autonomy::operating_mode_label);

    match args.output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            // Merge the channel-health rows into the snapshot object so the
            // output stays a single JSON document.
            let mut v: serde_json::Value = serde_json::from_str(&snap.render_json())
                .unwrap_or_else(|_| serde_json::json!({}));
            if let Some(obj) = v.as_object_mut() {
                obj.insert("channels".into(), serde_json::to_value(&channel_health)?);
                obj.insert("operating_mode".into(), serde_json::to_value(operating_mode)?);
            }
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
        OutputFormat::Table => {
            print!("{}", snap.render_table());
            if let Some(mode) = operating_mode {
                let hint = match mode {
                    "full-auto" => " (acts without asking; whole skill library routed — `neoth autonomy gated` to revert)",
                    "gated" => " (asks before sensitive actions — `neoth autonomy full-auto` for hands-off)",
                    _ => " (raw autonomy level set directly)",
                };
                println!("operating mode: {mode}{hint}");
            }
            print!("{}", render_channel_health_table(&channel_health));
        }
    }
    Ok(())
}

/// Render the GOLD-ADOPT-27 channel health probe as an operator table.
fn render_channel_health_table(health: &[crate::channels::probe::ChannelHealth]) -> String {
    let mut out = String::from("\nChannels:\n");
    for h in health {
        out.push_str(&format!(
            "  {} {:<18} {:<14} {}\n",
            h.status.glyph(),
            h.channel,
            h.status.as_str(),
            h.message
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channels::probe::{ChannelCredsView, probe_all};

    #[test]
    fn channel_table_lists_every_channel_with_status() {
        // A slack-bot-only view → slack shows `error`, others their states.
        let v = ChannelCredsView {
            slack_bot: true,
            ..Default::default()
        };
        let table = render_channel_health_table(&probe_all(&v));
        assert!(table.contains("Channels:"));
        assert!(table.contains("telegram"));
        assert!(table.contains("slack"));
        assert!(table.contains("error"), "slack-bot-only must surface error");
        assert!(table.contains("not_configured"));
    }
}
