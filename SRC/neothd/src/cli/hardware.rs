//! `neoth hardware` — operator-facing view of the consolidated hardware
//! probe. CPU + RAM + accelerator + ffmpeg/CLI presence + cached model
//! detection. Drives the onboarding GUI's welcome step + lets operators
//! `neothd hardware --output json | jq` to script around it.

use anyhow::Result;
use clap::Args;

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::daemon::hardware;

#[derive(Args, Debug, Clone)]
pub struct HardwareArgs {
    /// Output format. Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

pub async fn run_hardware(args: HardwareArgs) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    let report = hardware::probe(&home);
    match args.output {
        OutputFormat::Table => {
            print!("{}", report.render_summary());
        }
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
    }
    Ok(())
}
