//! `neoth adr` — list, write, or extract ADRs. Phase 31 R-21 ADR-3.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::adr;
use crate::cli::OutputFormat;

#[derive(Args, Debug, Clone)]
pub struct AdrArgs {
    #[command(subcommand)]
    pub action: AdrAction,

    /// Override the `~/.neoth/adr/` location (mostly for tests).
    #[arg(long, value_name = "DIR", global = true)]
    pub dir: Option<PathBuf>,

    /// Output format. Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum AdrAction {
    /// List every ADR in number order.
    List,
    /// Scan a file (or stdin with `-`) for decision markers and write any
    /// extracted ADRs.
    Extract {
        /// Path to a markdown / text file. Use `-` to read from stdin.
        path: String,
        /// Print extracted ADRs without writing them.
        #[arg(long)]
        dry_run: bool,
    },
}

pub async fn run_adr(args: AdrArgs) -> Result<()> {
    let dir = args.dir.clone().unwrap_or_else(adr::default_adr_dir);
    match args.action {
        AdrAction::List => list(&dir, args.output),
        AdrAction::Extract { path, dry_run } => extract(&dir, &path, dry_run, args.output),
    }
}

fn list(dir: &std::path::Path, output: OutputFormat) -> Result<()> {
    let entries = adr::list_adrs(dir)?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let rows: Vec<_> = entries
                .iter()
                .map(|a| {
                    serde_json::json!({
                        "number": a.number,
                        "title": a.title,
                        "path": a.path.display().to_string(),
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&rows)?);
        }
        OutputFormat::Table => {
            if entries.is_empty() {
                println!(
                    "no ADRs at {} yet — `neoth adr extract <path>` to seed one.",
                    dir.display()
                );
                return Ok(());
            }
            println!("# {} ADR(s)", entries.len());
            for a in &entries {
                println!("  {:04}  {:<60}  {}", a.number, a.title, a.path.display());
            }
        }
    }
    Ok(())
}

fn extract(dir: &std::path::Path, path: &str, dry_run: bool, output: OutputFormat) -> Result<()> {
    let body = if path == "-" {
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf).context("read stdin")?;
        buf
    } else {
        std::fs::read_to_string(path).with_context(|| format!("read {path}"))?
    };
    let decisions = adr::extract_decisions(&body);

    if dry_run {
        match output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                let rows: Vec<_> = decisions
                    .iter()
                    .map(|d| serde_json::json!({"title": d.title, "body": d.body}))
                    .collect();
                println!("{}", serde_json::to_string_pretty(&rows)?);
            }
            OutputFormat::Table => {
                println!("# {} decision(s) detected (dry-run)", decisions.len());
                for d in &decisions {
                    println!("  · {}", d.title);
                }
            }
        }
        return Ok(());
    }

    let mut written = Vec::new();
    for d in &decisions {
        let p = adr::write_adr(dir, d)?;
        written.push(p);
    }
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::json!({
                    "written": written.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
                    "count": written.len(),
                })
            );
        }
        OutputFormat::Table => {
            for p in &written {
                println!("wrote {}", p.display());
            }
            if written.is_empty() {
                println!("no decision markers found — pass `--dry-run` for a preview.");
            }
        }
    }
    Ok(())
}
