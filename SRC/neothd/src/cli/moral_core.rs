//! `neoth moral-core` — inspect the LOWKEY moral-core directives (GOLD-FEAT-07).
//!
//! Read-only surface over [`crate::memory::moral_core`]: `list` the parsed
//! blocks, `preview` the compact text that would be injected at enrichment
//! position 0, or `doctor` the directory. The actual enrichment injection +
//! config land in a later slice.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::memory::moral_core;

#[derive(Args, Debug, Clone)]
pub struct MoralCoreArgs {
    #[command(subcommand)]
    pub action: MoralCoreAction,
    /// Override the moral-core directory. Defaults to `~/.neoth/moral_core/`.
    #[arg(long, value_name = "PATH", global = true)]
    pub dir: Option<PathBuf>,
    /// Populated from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum MoralCoreAction {
    /// List the parsed blocks (tag, directive count, source file).
    List,
    /// Print the compact directive text that WOULD be injected at enrichment
    /// position 0 (highest priority). Empty when no moral core is configured.
    Preview,
    /// Validate the moral-core directory: report presence + block/directive
    /// counts, and warn when it is empty or has no directives.
    Doctor,
}

pub fn run_moral_core(args: MoralCoreArgs) -> Result<()> {
    let dir = args.dir.clone().unwrap_or_else(moral_core::default_dir);
    let blocks = moral_core::load_moral_core(&dir)?;
    let directive_total: usize = blocks.iter().map(|b| b.directive_count()).sum();

    match args.action {
        MoralCoreAction::List => match args.output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                let rows: Vec<_> = blocks
                    .iter()
                    .map(|b| {
                        serde_json::json!({
                            "tag": b.tag,
                            "directives": b.directive_count(),
                            "source": b.source,
                        })
                    })
                    .collect();
                println!("{}", serde_json::json!({ "dir": dir.display().to_string(), "blocks": rows }));
            }
            OutputFormat::Table => {
                if blocks.is_empty() {
                    println!("no moral-core blocks in {}", dir.display());
                } else {
                    println!("moral-core blocks ({}):", blocks.len());
                    for b in &blocks {
                        println!("  [{}] {} directive(s)  ({})", b.tag, b.directive_count(), b.source);
                    }
                }
            }
        },
        MoralCoreAction::Preview => {
            let compact = moral_core::compact_directives(&blocks);
            if compact.is_empty() {
                println!("(no moral core configured — nothing would be injected)");
            } else {
                print!("{compact}");
            }
        }
        MoralCoreAction::Doctor => {
            let exists = dir.exists();
            match args.output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    println!(
                        "{}",
                        serde_json::json!({
                            "dir": dir.display().to_string(),
                            "exists": exists,
                            "blocks": blocks.len(),
                            "directives": directive_total,
                            "ok": exists && directive_total > 0,
                        })
                    );
                }
                OutputFormat::Table => {
                    println!("moral-core doctor — {}", dir.display());
                    println!("  dir exists:   {exists}");
                    println!("  blocks:       {}", blocks.len());
                    println!("  directives:   {directive_total}");
                    if !exists {
                        println!("  ⚠ directory missing — moral core is opt-in; create it + add `*.md` files");
                    } else if directive_total == 0 {
                        println!("  ⚠ no directives parsed — add `- directive` bullets under `# Heading`s");
                    } else {
                        println!("  ✓ {directive_total} directive(s) ready to inject");
                    }
                }
            }
        }
    }
    Ok(())
}
