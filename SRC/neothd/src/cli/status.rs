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

    if args.prometheus {
        print!("{}", snap.render_prometheus());
        return Ok(());
    }

    match args.output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", snap.render_json());
        }
        OutputFormat::Table => {
            print!("{}", snap.render_table());
        }
    }
    Ok(())
}
