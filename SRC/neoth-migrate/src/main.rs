//! `neoth-migrate` — prior-AI memory import tool.
//!
//! Imports memory from a previous AI assistant into the NEOTH WAL +
//! tier views. The operator declares THEIR OWN stores in an
//! `import-manifest.yaml` (see `examples/import-manifest.example.yaml`);
//! nothing is hardcoded to any one machine. Emits a `dry-run` report;
//! the `apply` migration is **post-v1.0** — not yet implemented, so
//! `apply` validates the manifest then refuses and points back to
//! `dry-run`. This release is dry-run / preview only.
//!
//! Lives outside `neothd` so a daemon release doesn't carry the
//! migration-only deps (pulldown-cmark today; future lance + git2).
//! Operators run this once during cutover, then never again.
//!
//! ## CLI
//!
//! ```text
//! neoth-migrate dry-run --manifest <PATH> [--root <PATH>]
//!     Scan-only. No WAL writes. Reads the operator's import manifest
//!     and prints a JSON report of every declared source: path, kind,
//!     row-count estimate, sample entries (first 3 rows / files).
//!
//! neoth-migrate apply --manifest <PATH> --confirm [--root <PATH>]
//!     POST-v1.0 / preview only: the real import path is not yet
//!     implemented. Today `apply` validates the manifest then refuses
//!     and points back to `dry-run`. (When it ships it will append
//!     frames to the WAL and be replay-only undoable, hence `--confirm`.)
//!
//! neoth-migrate import-config [--auth-profiles <PATH>] [--models-providers <PATH>] [--json]
//!     Convert OpenClaw `auth.profiles` + `models.providers` JSON files
//!     into NEOTH `freedom.yaml` provider stanzas.  API keys are NEVER
//!     extracted — the output YAML contains a comment instructing the
//!     operator to add keys to `credentials.yaml` separately.
//!
//! neoth-migrate import-crons [--timer <PATH>]... [--crontab <PATH>] [--json]
//!     Convert systemd `.timer` units and/or a crontab file into NEOTH
//!     `jobs.yaml` Job entries.  Recognises OnCalendar / OnUnitActiveSec /
//!     ExecStart in timer units and standard 5-field + @shorthand crontab
//!     syntax.  Outputs YAML ready to paste into jobs.yaml.
//! ```

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

mod import_config;
mod import_crons;
mod readers;

/// Phase-3 store-migration tool. See module-doc for usage examples.
#[derive(Parser, Debug)]
#[command(
    name = "neoth-migrate",
    version,
    about = "Phase-3 prior-agent store cutover for NEOTH (V10-06)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Scan-only. Walks every known store, reports rows + sample
    /// entries. Never writes to the WAL.
    DryRun(DryRunArgs),
    /// Preview only in this release — `apply` is post-v1.0. The real
    /// import path (WAL writer + per-reader emitters) is not yet
    /// implemented, so this subcommand validates the manifest then
    /// refuses and points you back at `dry-run`. `--confirm` is reserved
    /// for when apply ships.
    Apply(ApplyArgs),
    /// Convert OpenClaw auth.profiles + models.providers JSON files into
    /// NEOTH freedom.yaml provider stanzas. Keys are NEVER extracted
    /// from the input — the output instructs the operator to add keys
    /// to credentials.yaml separately. At least one of --auth-profiles
    /// or --models-providers is required.
    ImportConfig(ImportConfigArgs),
    /// Convert systemd .timer unit files and/or a crontab file into
    /// NEOTH jobs.yaml Job entries. Parses OnCalendar / OnUnitActiveSec /
    /// ExecStart in timer units and 5-field + @shorthand crontab syntax.
    /// Emits YAML ready to paste into jobs.yaml. At least one of --timer
    /// or --crontab is required.
    ImportCrons(ImportCronsArgs),
}

#[derive(clap::Args, Debug)]
struct DryRunArgs {
    /// Path to your import manifest (YAML). Declare your prior-AI
    /// memory stores here — see examples/import-manifest.example.yaml.
    #[arg(long, value_name = "PATH")]
    manifest: std::path::PathBuf,
    /// Operator home override. Default: `$HOME` resolved at runtime.
    #[arg(long, value_name = "PATH")]
    root: Option<std::path::PathBuf>,
}

#[derive(clap::Args, Debug)]
struct ApplyArgs {
    /// Path to your import manifest (YAML). Same file you used for
    /// dry-run.
    #[arg(long, value_name = "PATH")]
    manifest: std::path::PathBuf,
    /// Operator home override. Default: `$HOME` resolved at runtime.
    #[arg(long, value_name = "PATH")]
    root: Option<std::path::PathBuf>,
    /// Required positive consent. Without it the binary refuses to run.
    #[arg(long)]
    confirm: bool,
}

#[derive(clap::Args, Debug)]
struct ImportConfigArgs {
    /// Path to your OpenClaw `auth.profiles` JSON file.
    /// Typically `~/.openclaw/auth.profiles` or `~/.jarvis/auth.profiles`.
    #[arg(long, value_name = "PATH")]
    auth_profiles: Option<std::path::PathBuf>,
    /// Path to your OpenClaw `models.providers` JSON file.
    /// Typically `~/.openclaw/models.providers` or similar.
    #[arg(long, value_name = "PATH")]
    models_providers: Option<std::path::PathBuf>,
    /// Emit machine-readable JSON instead of YAML (useful for piping).
    #[arg(long, default_value = "false")]
    json: bool,
}

#[derive(clap::Args, Debug)]
struct ImportCronsArgs {
    /// Path to a systemd `.timer` unit file. May be repeated for multiple
    /// timer units: `--timer foo.timer --timer bar.timer`.
    #[arg(long, value_name = "PATH", num_args = 1..)]
    timer: Vec<std::path::PathBuf>,
    /// Path to a crontab file (as produced by `crontab -l`).
    #[arg(long, value_name = "PATH")]
    crontab: Option<std::path::PathBuf>,
    /// Emit machine-readable JSON instead of YAML (useful for piping).
    #[arg(long, default_value = "false")]
    json: bool,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let cli = Cli::parse();
    match cli.command {
        Command::DryRun(args) => run_dry_run(args),
        Command::Apply(args) => run_apply(args),
        Command::ImportConfig(args) => run_import_config(args),
        Command::ImportCrons(args) => run_import_crons(args),
    }
}

fn run_dry_run(args: DryRunArgs) -> Result<()> {
    let home = args.root.clone().unwrap_or_else(default_home);
    let manifest = readers::load_manifest(&args.manifest)?;
    tracing::info!(
        home = %home.display(),
        sources = manifest.sources.len(),
        "neoth-migrate dry-run"
    );
    let report = readers::scan_all(&manifest.sources, &home);
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn run_apply(args: ApplyArgs) -> Result<()> {
    // Validate the manifest loads before talking about confirm, so a
    // bad manifest is the first thing the operator hears about.
    let _manifest = readers::load_manifest(&args.manifest)?;
    if !args.confirm {
        anyhow::bail!(
            "Memory import (apply) is not yet available in this release — \
             `--confirm` is reserved for when apply ships. \
             Use `neoth-migrate dry-run --manifest <PATH>` to preview your import sources."
        );
    }
    // The apply path (WAL writer + per-reader emitters) is a follow-up
    // implementation; today the dry-run path is what operators use to
    // validate their import layout before a cutover.
    anyhow::bail!(
        "Memory import (apply) is not yet available in this release. Use \
         `neoth-migrate dry-run --manifest <PATH>` to preview your import sources."
    );
}

fn run_import_config(args: ImportConfigArgs) -> Result<()> {
    let auth_path = args.auth_profiles.as_deref();
    let models_path = args.models_providers.as_deref();
    tracing::info!(
        auth_profiles = auth_path.map(|p| p.display().to_string()).as_deref().unwrap_or("<none>"),
        models_providers = models_path.map(|p| p.display().to_string()).as_deref().unwrap_or("<none>"),
        "neoth-migrate import-config"
    );
    let result = import_config::import_config(auth_path, models_path)?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("{}", import_config::render_yaml(&result));
        if !result.skipped.is_empty() {
            eprintln!(
                "warn: {} OpenClaw kind(s) had no NEOTH mapping and were skipped: {}",
                result.skipped.len(),
                result.skipped.join(", ")
            );
        }
        eprintln!(
            "info: {} sensitive field(s) stripped from input (no key material in output)",
            result.sensitive_fields_dropped
        );
    }
    Ok(())
}

fn run_import_crons(args: ImportCronsArgs) -> Result<()> {
    let timer_refs: Vec<&std::path::Path> = args.timer.iter().map(|p| p.as_path()).collect();
    let crontab_ref = args.crontab.as_deref();
    tracing::info!(
        timers = args.timer.len(),
        crontab = crontab_ref
            .map(|p| p.display().to_string())
            .as_deref()
            .unwrap_or("<none>"),
        "neoth-migrate import-crons"
    );
    let result = import_crons::import_crons(&timer_refs, crontab_ref)?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("{}", import_crons::render_yaml(&result));
        if !result.skipped.is_empty() {
            eprintln!(
                "warn: {} source(s) could not be converted and were skipped:",
                result.skipped.len()
            );
            for s in &result.skipped {
                eprintln!("  {s}");
            }
        }
        eprintln!(
            "info: {} job(s) imported",
            result.jobs.len()
        );
    }
    Ok(())
}

fn default_home() -> std::path::PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("."))
}
