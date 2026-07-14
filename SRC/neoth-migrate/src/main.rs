//! `neoth-migrate` — prior-AI memory import tool.
//!
//! Imports memory from a previous AI assistant into NEOTH's ground-truth
//! candidate view with a separate durable audit lifecycle. The operator
//! declares THEIR OWN stores in an
//! `import-manifest.yaml` (see `examples/import-manifest.example.yaml`)
//! or bootstraps one with `detect` (complete OpenClaw/Hermes/OpenHuman/
//! Veronica homes); nothing is hardcoded to any one machine.
//! `dry-run` previews; `apply --confirm` performs the real import
//! (claims → idx_groundtruth in one transaction, JSONL-sidecar
//! audited). Without `--confirm`, `apply` validates then refuses —
//! that is the consent gate, not a stub. (GOLD-ADAPT-OH-01 doc fix
//! 2026-07-04: earlier prose called apply "post-v1.0 / not yet
//! implemented" long after the import path landed below.)
//!
//! Lives outside `neothd` so a daemon release doesn't carry the
//! migration-only dependencies. Operators run this during assistant cutover.
//!
//! ## CLI
//!
//! ```text
//! neoth-migrate detect [--root <PATH>] [--output <PATH>] [--json]
//!     Scan complete prior-AI homes and generate a
//!     ready-to-review import-manifest.yaml (stdout or --output).
//!     --json emits sources + row-count estimates for the GUI card.
//!
//! neoth-migrate dry-run --manifest <PATH> [--root <PATH>]
//!     Source-read-only. Persists an immutable SHA-256 plan checkpoint and
//!     prints every memory/runtime/credential/vector disposition.
//!
//! neoth-migrate apply --manifest <PATH> --confirm [--root <PATH>]
//!     The real import: every source is bound to the reviewed plan, memory is
//!     INSERT OR IGNOREd in one transaction, and foreign runtime artifacts are
//!     staged for review without activation. `--confirm` is the consent gate.
//!
//! neoth-migrate status [--root <PATH>] [--json]
//!     Show the latest durable migration lifecycle (never started, in
//!     progress, complete, or failed/rolled back).
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

use anyhow::{Context as _, Result};
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

mod detect;
mod import_config;
mod import_crons;
mod migration_plan;
mod readers;
mod wal_emit;

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
    /// GOLD-ADAPT-OH-01 — scan complete prior-AI install homes and generate a
    /// ready-to-review
    /// import-manifest.yaml. Read-only; the operator edits the manifest,
    /// then runs `dry-run` and `apply --confirm` against it.
    Detect(DetectArgs),
    /// Scan-only. Walks every known store, reports rows + sample
    /// entries. Never writes to the WAL.
    DryRun(DryRunArgs),
    /// Import the declared stores into ground-truth. `--confirm` is the
    /// consent gate: without it this subcommand validates the manifest
    /// then refuses (use `--dry-run` to preview). With it, claims are
    /// extracted per source and INSERT OR IGNOREd into idx_groundtruth
    /// in one transaction, audited to the JSONL sidecar
    /// (`~/.neoth/neoth-migrate-audit.jsonl`).
    Apply(ApplyArgs),
    /// Show the latest durable migration lifecycle from the audit sidecar.
    Status(StatusArgs),
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
struct DetectArgs {
    /// Operator home override (tests / unusual layouts). Default: `$HOME`.
    #[arg(long, value_name = "PATH")]
    root: Option<std::path::PathBuf>,
    /// Write the generated manifest here instead of stdout.
    #[arg(long, value_name = "PATH")]
    output: Option<std::path::PathBuf>,
    /// Emit a machine-readable JSON report (sources + scan estimates)
    /// instead of the YAML manifest. Used by the GUI onboarding card.
    #[arg(long)]
    json: bool,
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
    /// Preview what would be inserted without writing to views.db.
    /// Prints the same JSON report as `dry-run` then exits cleanly.
    /// Takes precedence over `--confirm`.
    #[arg(long)]
    dry_run: bool,
    /// Override the views.db path. Defaults to `<root>/.neoth/views.db`.
    #[arg(long, value_name = "PATH")]
    db: Option<std::path::PathBuf>,
}

#[derive(clap::Args, Debug)]
struct StatusArgs {
    /// Operator home override. Default: `$HOME` resolved at runtime.
    #[arg(long, value_name = "PATH")]
    root: Option<std::path::PathBuf>,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
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
        Command::Detect(args) => run_detect(args),
        Command::DryRun(args) => run_dry_run(args),
        Command::Apply(args) => run_apply(args),
        Command::Status(args) => run_status(args),
        Command::ImportConfig(args) => run_import_config(args),
        Command::ImportCrons(args) => run_import_crons(args),
    }
}

/// GOLD-ADAPT-OH-01 — complete assistant-home detection → generated manifest.
fn run_detect(args: DetectArgs) -> Result<()> {
    let home = args.root.clone().unwrap_or_else(default_home);
    let detection = detect::detect_sources(&home);
    if args.json {
        let report = serde_json::json!({
            "sources": detection.manifest.sources,
            "scans": detection.scans,
        });
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    let yaml = detect::render_manifest_yaml(&detection)?;
    match &args.output {
        Some(path) => {
            std::fs::write(path, &yaml)
                .with_context(|| format!("write manifest to {}", path.display()))?;
            eprintln!(
                "manifest written to {} ({} source(s) detected)",
                path.display(),
                detection.manifest.sources.len()
            );
        }
        None => print!("{yaml}"),
    }
    if detection.manifest.sources.is_empty() {
        eprintln!(
            "no prior-AI homes found under {} — declare custom \
             stores by hand (examples/import-manifest.example.yaml)",
            home.display()
        );
    }
    Ok(())
}

fn run_dry_run(args: DryRunArgs) -> Result<()> {
    let home = args.root.clone().unwrap_or_else(default_home);
    let manifest = readers::load_manifest(&args.manifest)?;
    let db_path = home.join(".neoth").join("views.db");
    readers::validate_sources_not_target(&manifest.sources, &home, &db_path)?;
    tracing::info!(
        home = %home.display(),
        sources = manifest.sources.len(),
        "neoth-migrate dry-run"
    );
    let scans = readers::scan_all(&manifest.sources, &home);
    let plan = migration_plan::build_plan(&manifest, &home, &db_path)?;
    let plan_path = migration_plan::checkpoint_plan(&home, &plan)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "plan": plan,
            "plan_path": plan_path,
            "scans": scans,
        }))?
    );
    Ok(())
}

fn run_status(args: StatusArgs) -> Result<()> {
    let home = args.root.unwrap_or_else(default_home);
    let audit = wal_emit::load_status(&home)?;
    let plan = migration_plan::load_plan_status(&home)?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "audit": audit,
                "plan": plan,
            }))?
        );
    } else {
        println!("migration: {}", audit.state);
        println!("audit: {}", audit.audit_path);
        println!("plan: {}", plan.state);
        if let Some(plan_sha256) = &plan.plan_sha256 {
            println!("plan sha256: {plan_sha256}");
            println!(
                "artifacts: {}/{} committed; unsupported: {} (acknowledged={})",
                plan.artifacts_committed,
                plan.artifacts_total,
                plan.blocked_unsupported,
                plan.acknowledge_unsupported
            );
        }
        if let Some(operation_id) = &audit.operation_id {
            println!("operation: {operation_id}");
        }
        if audit.sources_total > 0 {
            println!(
                "sources: {}/{} complete; claims seen: {}; inserted: {}",
                audit.batches_completed, audit.sources_total, audit.claims_seen, audit.inserted
            );
        }
        if let Some(error) = &audit.error {
            println!("error: {error}");
        }
        if let Some(rolled_back) = audit.rolled_back {
            println!("rolled back: {rolled_back}");
        }
    }
    Ok(())
}

fn run_apply(args: ApplyArgs) -> Result<()> {
    let manifest = readers::load_manifest(&args.manifest)?;
    let home = args.root.clone().unwrap_or_else(default_home);
    let db_path = args
        .db
        .clone()
        .unwrap_or_else(|| home.join(".neoth").join("views.db"));
    let plan = migration_plan::build_plan(&manifest, &home, &db_path)?;

    if args.dry_run {
        readers::validate_sources_not_target(&manifest.sources, &home, &db_path)?;
        let scans = readers::scan_all_for_target(&manifest.sources, &home, &db_path);
        let plan_path = migration_plan::checkpoint_plan(&home, &plan)?;
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "plan": plan,
                "plan_path": plan_path,
                "scans": scans,
            }))?
        );
        eprintln!(
            "dry-run: {} source(s) scanned and bound to SHA-256 plan {}. Re-run without --dry-run and with --confirm to apply.",
            manifest.sources.len(),
            plan.plan_sha256
        );
        return Ok(());
    }

    if !args.confirm {
        anyhow::bail!(
            "Migration apply requires --confirm. Use --dry-run first to create a reviewed plan, \
             then re-run with --confirm to apply."
        );
    }

    let plan_path = migration_plan::require_checkpoint(&home, &plan)?;
    let blocked = migration_plan::blocked_artifacts(&plan);
    anyhow::ensure!(
        blocked.is_empty() || plan.acknowledge_unsupported,
        "{} unsupported artifact(s) block apply. Review the dry-run and set `acknowledge_unsupported: true` to record an explicit skip",
        blocked.len()
    );
    readers::validate_sources_not_target(&manifest.sources, &home, &db_path)?;
    let transactional_names = migration_plan::transactional_source_names(&plan);
    let transactional_sources: Vec<readers::ImportSource> = manifest
        .sources
        .iter()
        .filter(|source| transactional_names.contains(source.name.as_str()))
        .cloned()
        .collect();
    if !transactional_sources.is_empty() {
        readers::validate_sources_for_apply(&transactional_sources, &home, &db_path)?;
    }

    let emitter = wal_emit::OperatorWalEmitter::open(&home)?;
    emitter.emit_migration_started(manifest.sources.len(), &db_path)?;
    type BatchEvent = (String, usize, usize);
    let already_committed = audit_stage(
        &emitter,
        "resume-state",
        true,
        migration_plan::memory_already_committed(&home, &plan, &db_path),
    )?;
    let mut total_inserted = 0usize;
    let mut batch_events: Vec<BatchEvent> = Vec::new();
    let mut per_source = Vec::new();
    let mut memory_wrote = false;

    if already_committed {
        per_source.push(serde_json::json!({
            "status": "memory_phase_resumed",
            "inserted_this_run": 0,
        }));
    } else if transactional_sources.is_empty() {
        audit_stage(
            &emitter,
            "resume-state",
            true,
            migration_plan::mark_memory_committed(&home, &plan, &db_path),
        )?;
    } else {
        let conn = audit_stage(
            &emitter,
            "target-open",
            true,
            rusqlite::Connection::open(&db_path)
                .with_context(|| format!("open views.db at {}", db_path.display())),
        )?;
        audit_stage(
            &emitter,
            "target-schema",
            true,
            check_groundtruth_schema(&conn)
                .with_context(|| format!("schema check on {}", db_path.display())),
        )?;

        let mut prepared = Vec::with_capacity(transactional_sources.len());
        for source in &transactional_sources {
            match readers::emit_claims_for_target(source, &home, &db_path)
                .with_context(|| format!("preflight source '{}'", source.name))
            {
                Ok(claims) => prepared.push((source.name.clone(), claims)),
                Err(error) => {
                    if let Err(audit_error) =
                        emitter.emit_migration_failed("preflight", &error, true)
                    {
                        return Err(error.context(format!(
                            "also failed to persist MIGRATION_FAILED audit: {audit_error:#}"
                        )));
                    }
                    return Err(error);
                }
            }
        }

        // Close the plan/preflight TOCTOU window before BEGIN IMMEDIATE.
        let revalidated = audit_stage(
            &emitter,
            "plan-revalidation",
            true,
            migration_plan::build_plan(&manifest, &home, &db_path),
        )?;
        audit_stage(
            &emitter,
            "plan-revalidation",
            true,
            migration_plan::require_checkpoint(&home, &revalidated).map(|_| ()),
        )?;
        audit_stage(
            &emitter,
            "plan-revalidation",
            true,
            if revalidated == plan {
                Ok(())
            } else {
                Err(anyhow::anyhow!(
                    "migration sources changed during preflight"
                ))
            },
        )?;

        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("system clock is before Unix epoch")?
            .as_nanos()
            .min(i64::MAX as u128) as i64;
        let mut began = false;
        let transaction = (|| -> Result<()> {
            conn.execute_batch("BEGIN IMMEDIATE")?;
            began = true;
            for (source_name, claims) in &prepared {
                let mut source_inserted = 0usize;
                for (statement, source_tag, scope) in claims {
                    source_inserted += conn
                        .execute(
                            "INSERT OR IGNORE INTO idx_groundtruth \
                             (statement, source, scope, asserted_at, revoked_at, \
                              fact_state, source_weight, confidence, evidence, \
                              maturity, confirmed_count) \
                             VALUES (?1, ?2, ?3, ?4, NULL, \
                                     'candidate', json_object(?2, 1), 0.5, '[]', \
                                     'emerging', 0)",
                            rusqlite::params![statement, source_tag, scope, now_ns],
                        )
                        .with_context(|| format!("insert source '{source_name}'"))?;
                }
                total_inserted += source_inserted;
                batch_events.push((source_name.clone(), claims.len(), source_inserted));
                per_source.push(serde_json::json!({
                    "name": source_name,
                    "claims_seen": claims.len(),
                    "inserted": source_inserted,
                    "skipped_duplicates": claims.len().saturating_sub(source_inserted),
                }));
            }
            conn.execute_batch("COMMIT")?;
            began = false;
            Ok(())
        })();
        if let Err(error) = transaction {
            let rolled_back = !began || conn.execute_batch("ROLLBACK").is_ok();
            if let Err(audit_error) =
                emitter.emit_migration_failed("transaction", &error, rolled_back)
            {
                return Err(error.context(format!(
                    "also failed to persist MIGRATION_FAILED audit: {audit_error:#}"
                )));
            }
            return Err(error);
        }
        memory_wrote = true;
        audit_stage(
            &emitter,
            "memory-resume-marker",
            false,
            migration_plan::mark_memory_committed(&home, &plan, &db_path),
        )?;
    }

    let stage = match migration_plan::stage_review_artifacts(&home, &plan) {
        Ok(stage) => stage,
        Err(error) => {
            if let Err(audit_error) =
                emitter.emit_migration_failed("review-staging", &error, !memory_wrote)
            {
                return Err(error.context(format!(
                    "also failed to persist MIGRATION_FAILED audit: {audit_error:#}"
                )));
            }
            return Err(error);
        }
    };
    audit_stage(
        &emitter,
        "completion-marker",
        false,
        migration_plan::mark_complete(&home, &plan),
    )?;

    let audit_result = (|| -> Result<()> {
        for (name, claims_seen, inserted) in &batch_events {
            emitter.emit_migration_batch(name, *claims_seen, *inserted)?;
        }
        emitter.emit_migration_complete(total_inserted)
    })();
    if let Err(audit_error) = audit_result {
        let error = anyhow::anyhow!(
            "{} migration row(s) committed, but terminal audit persistence failed: {audit_error:#}",
            total_inserted
        );
        if let Err(failure_audit_error) =
            emitter.emit_migration_failed("post-commit-audit", &error, false)
        {
            return Err(error.context(format!(
                "also failed to persist MIGRATION_FAILED audit: {failure_audit_error:#}"
            )));
        }
        return Err(error);
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "sources": manifest.sources.len(),
            "plan_sha256": plan.plan_sha256,
            "plan_path": plan_path,
            "inserted": total_inserted,
            "memory_resumed": already_committed,
            "review": stage,
            "atomic": true,
            "detail": per_source,
        }))?
    );

    Ok(())
}

fn audit_stage<T>(
    emitter: &wal_emit::OperatorWalEmitter,
    stage: &str,
    rolled_back: bool,
    result: Result<T>,
) -> Result<T> {
    match result {
        Ok(value) => Ok(value),
        Err(error) => {
            if let Err(audit_error) = emitter.emit_migration_failed(stage, &error, rolled_back) {
                return Err(error.context(format!(
                    "also failed to persist MIGRATION_FAILED audit: {audit_error:#}"
                )));
            }
            Err(error)
        }
    }
}

/// Assert that `idx_groundtruth` has every column we INSERT into.
/// This protects against schema drift if neothd adds a NOT NULL column
/// without a DEFAULT — a hard fail here is clearer than a mid-import
/// SQLite constraint error.
fn check_groundtruth_schema(conn: &rusqlite::Connection) -> Result<()> {
    let mut stmt = conn.prepare("PRAGMA table_info(idx_groundtruth)")?;
    let cols: std::collections::HashSet<String> = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<_>>()
        .context("read idx_groundtruth schema columns")?;

    if cols.is_empty() {
        anyhow::bail!(
            "idx_groundtruth does not exist in views.db. \
             Run `neoth migrate run` (or start the daemon once) to apply the schema first."
        );
    }

    const REQUIRED: &[&str] = &[
        "statement",
        "source",
        "scope",
        "asserted_at",
        "fact_state",
        "source_weight",
        "confidence",
        "evidence",
        "maturity",
        "confirmed_count",
    ];
    let missing: Vec<&str> = REQUIRED
        .iter()
        .copied()
        .filter(|c| !cols.contains(*c))
        .collect();
    if !missing.is_empty() {
        anyhow::bail!(
            "idx_groundtruth is missing required column(s): {:?}. \
             Schema may be out of date — run `neoth migrate run` to update.",
            missing
        );
    }
    Ok(())
}

fn run_import_config(args: ImportConfigArgs) -> Result<()> {
    let auth_path = args.auth_profiles.as_deref();
    let models_path = args.models_providers.as_deref();
    tracing::info!(
        auth_profiles = auth_path
            .map(|p| p.display().to_string())
            .as_deref()
            .unwrap_or("<none>"),
        models_providers = models_path
            .map(|p| p.display().to_string())
            .as_deref()
            .unwrap_or("<none>"),
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
        eprintln!("info: {} job(s) imported", result.jobs.len());
    }
    Ok(())
}

fn default_home() -> std::path::PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("."))
}

// ── Integration tests for run_apply ──────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Create a minimal views.db at `<dir>/.neoth/views.db` with the
    /// idx_groundtruth table. Returns the db path.
    fn make_views_db(dir: &std::path::Path) -> std::path::PathBuf {
        let neoth_dir = dir.join(".neoth");
        std::fs::create_dir_all(&neoth_dir).unwrap();
        let db_path = neoth_dir.join("views.db");
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS idx_groundtruth (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                statement       TEXT    NOT NULL,
                source          TEXT    NOT NULL,
                scope           TEXT    NOT NULL,
                asserted_at     INTEGER NOT NULL,
                revoked_at      INTEGER,
                fact_state      TEXT    NOT NULL DEFAULT 'verified',
                source_weight   TEXT    NOT NULL DEFAULT '{}',
                confidence      REAL    NOT NULL DEFAULT 0.5,
                evidence        TEXT    NOT NULL DEFAULT '[]',
                maturity        TEXT    NOT NULL DEFAULT 'emerging',
                confirmed_count INTEGER NOT NULL DEFAULT 0
            );
            CREATE UNIQUE INDEX IF NOT EXISTS ux_gt_stmt_scope
                ON idx_groundtruth(statement, scope);",
        )
        .unwrap();
        db_path
    }

    fn write_manifest(dir: &std::path::Path, content: &str) -> std::path::PathBuf {
        let p = dir.join("manifest.yaml");
        std::fs::write(&p, content).unwrap();
        // Direct run_apply tests model the real CLI contract: dry-run creates
        // the immutable reviewed plan before apply is allowed to mutate.
        let manifest = readers::load_manifest(&p).unwrap();
        let plan = migration_plan::build_plan(&manifest, dir, &dir.join(".neoth").join("views.db"))
            .unwrap();
        migration_plan::checkpoint_plan(dir, &plan).unwrap();
        p
    }

    // ── dry_run branch ────────────────────────────────────────────────────────

    #[test]
    fn apply_dry_run_prints_scan_no_db_write() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("claims.json");
        std::fs::write(
            &src,
            r#"[{"statement":"fact A here long"},{"statement":"fact B here long"}]"#,
        )
        .unwrap();
        let manifest_path = write_manifest(
            dir.path(),
            &format!(
                "sources:\n  - name: test-json\n    path: {}\n    kind: json_file\n",
                src.display()
            ),
        );
        let args = ApplyArgs {
            manifest: manifest_path,
            root: Some(dir.path().to_path_buf()),
            confirm: false,
            dry_run: true,
            db: None,
        };
        // dry_run must succeed without --confirm and without a views.db
        run_apply(args).unwrap();
        // views.db must NOT exist (no write happened)
        assert!(!dir.path().join(".neoth").join("views.db").exists());
    }

    // ── error: missing --confirm ──────────────────────────────────────────────

    #[test]
    fn apply_without_confirm_errors_with_helpful_message() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("c.json");
        std::fs::write(&src, r#"[]"#).unwrap();
        let manifest_path = write_manifest(
            dir.path(),
            &format!(
                "sources:\n  - name: t\n    path: {}\n    kind: json_file\n",
                src.display()
            ),
        );
        let args = ApplyArgs {
            manifest: manifest_path,
            root: Some(dir.path().to_path_buf()),
            confirm: false,
            dry_run: false,
            db: None,
        };
        let err = run_apply(args).unwrap_err();
        assert!(
            err.to_string().contains("--confirm"),
            "error must mention --confirm; got: {err}"
        );
    }

    // ── full apply + rows in db + audit JSONL ────────────────────────────────

    #[test]
    fn apply_confirm_inserts_rows_and_writes_audit() {
        let dir = tempdir().unwrap();
        let db_path = make_views_db(dir.path());

        let src = dir.path().join("claims.json");
        std::fs::write(
            &src,
            r#"[{"statement":"fact A is true and important"},{"statement":"fact B is also true"}]"#,
        )
        .unwrap();
        let manifest_path = write_manifest(
            dir.path(),
            &format!(
                "sources:\n  - name: test-json\n    path: {}\n    kind: json_file\n",
                src.display()
            ),
        );
        let args = ApplyArgs {
            manifest: manifest_path,
            root: Some(dir.path().to_path_buf()),
            confirm: true,
            dry_run: false,
            db: Some(db_path.clone()),
        };
        run_apply(args).unwrap();

        // Both rows must be in views.db
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM idx_groundtruth", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 2, "both claims must be in views.db");

        // fact_state must be 'candidate' (import sources are external → candidate)
        let state: String = conn
            .query_row(
                "SELECT fact_state FROM idx_groundtruth WHERE statement = 'fact A is true and important'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(state, "candidate");

        // Audit JSONL must mention GROUNDTRUTH_IMPORTED and event_type 153 (0x99)
        let audit =
            std::fs::read_to_string(dir.path().join(".neoth").join("neoth-migrate-audit.jsonl"))
                .unwrap();
        assert!(
            audit.contains("GROUNDTRUTH_IMPORTED"),
            "audit must contain GROUNDTRUTH_IMPORTED; got: {audit}"
        );
        assert!(
            audit.contains("153"),
            "audit must contain event_type 153 (0x99); got: {audit}"
        );
    }

    // ── OperatorWalEmitter: STARTED + BATCH + COMPLETE lifecycle events ──────

    #[test]
    fn apply_emits_migration_jsonl_with_started_batch_complete_events() {
        let dir = tempdir().unwrap();
        let db_path = make_views_db(dir.path());

        let src = dir.path().join("claims2.json");
        std::fs::write(
            &src,
            r#"[{"statement":"lifecycle claim one here"},{"statement":"lifecycle claim two here"}]"#,
        )
        .unwrap();
        let manifest_path = write_manifest(
            dir.path(),
            &format!(
                "sources:\n  - name: lc-source\n    path: {}\n    kind: json_file\n",
                src.display()
            ),
        );

        // ── dry_run=true must write zero JSONL lines ──────────────────────────
        run_apply(ApplyArgs {
            manifest: manifest_path.clone(),
            root: Some(dir.path().to_path_buf()),
            confirm: false,
            dry_run: true,
            db: Some(db_path.clone()),
        })
        .unwrap();
        let audit_path = dir.path().join(".neoth").join("neoth-migrate-audit.jsonl");
        assert!(
            !audit_path.exists(),
            "dry_run must not create the audit file"
        );

        // ── real apply ────────────────────────────────────────────────────────
        run_apply(ApplyArgs {
            manifest: manifest_path,
            root: Some(dir.path().to_path_buf()),
            confirm: true,
            dry_run: false,
            db: Some(db_path.clone()),
        })
        .unwrap();

        // Both rows in db
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM idx_groundtruth", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 2, "both lifecycle claims must be in views.db");

        // Parse JSONL
        let raw = std::fs::read_to_string(&audit_path).unwrap();
        let lines: Vec<serde_json::Value> = raw
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).expect("valid JSON line"))
            .collect();

        // Must have exactly 3 lines: STARTED, BATCH, COMPLETE
        assert_eq!(
            lines.len(),
            3,
            "expected STARTED + BATCH + COMPLETE; got {raw}"
        );

        // MIGRATION_STARTED
        assert_eq!(
            lines[0]["kind"], "MIGRATION_STARTED",
            "first line must be MIGRATION_STARTED"
        );
        assert_eq!(lines[0]["sources_total"], 1, "sources_total must be 1");

        // MIGRATION_BATCH for lc-source
        assert_eq!(
            lines[1]["kind"], "MIGRATION_BATCH",
            "second line must be MIGRATION_BATCH"
        );
        assert_eq!(lines[1]["source_name"], "lc-source");
        assert_eq!(lines[1]["inserted"], 2, "inserted must be 2");

        // MIGRATION_COMPLETE
        assert_eq!(
            lines[2]["kind"], "MIGRATION_COMPLETE",
            "third line must be MIGRATION_COMPLETE"
        );
        assert_eq!(lines[2]["inserted"], 2, "COMPLETE.inserted must be 2");
        assert_eq!(lines[2]["skipped_sources"], 0);
        // Legacy compat fields
        assert_eq!(lines[2]["event"], "GROUNDTRUTH_IMPORTED");
        assert_eq!(lines[2]["event_type"], 153);
    }

    // ── idempotency: re-run does not double-insert ────────────────────────────

    #[test]
    fn apply_is_idempotent_via_insert_or_ignore() {
        let dir = tempdir().unwrap();
        let db_path = make_views_db(dir.path());

        let src = dir.path().join("once.json");
        std::fs::write(&src, r#"[{"statement":"idempotent fact check here"}]"#).unwrap();
        let manifest_content = format!(
            "sources:\n  - name: idem\n    path: {}\n    kind: json_file\n",
            src.display()
        );

        for _ in 0..2 {
            let mp = write_manifest(dir.path(), &manifest_content);
            run_apply(ApplyArgs {
                manifest: mp,
                root: Some(dir.path().to_path_buf()),
                confirm: true,
                dry_run: false,
                db: Some(db_path.clone()),
            })
            .unwrap();
        }

        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM idx_groundtruth", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1, "second run must not create a duplicate row");
    }

    // ── schema check: missing table → clear error ─────────────────────────────

    #[test]
    fn apply_fails_cleanly_when_idx_groundtruth_missing() {
        let dir = tempdir().unwrap();
        // Create a views.db with NO tables (empty db)
        let neoth_dir = dir.path().join(".neoth");
        std::fs::create_dir_all(&neoth_dir).unwrap();
        let db_path = neoth_dir.join("views.db");
        rusqlite::Connection::open(&db_path).unwrap(); // empty

        let src = dir.path().join("x.json");
        std::fs::write(&src, r#"[]"#).unwrap();
        let mp = write_manifest(
            dir.path(),
            &format!(
                "sources:\n  - name: t\n    path: {}\n    kind: json_file\n",
                src.display()
            ),
        );
        let err = run_apply(ApplyArgs {
            manifest: mp,
            root: Some(dir.path().to_path_buf()),
            confirm: true,
            dry_run: false,
            db: Some(db_path),
        })
        .unwrap_err();
        // The error chain: outer context ("schema check on …") wraps the inner
        // message which names idx_groundtruth. Check the full chain.
        let chain = format!("{err:#}");
        assert!(
            chain.contains("idx_groundtruth"),
            "error chain must mention idx_groundtruth; got: {chain}"
        );
    }

    #[test]
    fn apply_preflights_every_source_and_never_commits_a_partial_batch() {
        let dir = tempdir().unwrap();
        let db_path = make_views_db(dir.path());
        let valid = dir.path().join("valid.json");
        let broken = dir.path().join("broken.json");
        std::fs::write(
            &valid,
            r#"[{"statement":"This valid row must still roll back"}]"#,
        )
        .unwrap();
        std::fs::write(&broken, "{not valid json").unwrap();
        let manifest = write_manifest(
            dir.path(),
            &format!(
                "sources:\n  - name: valid\n    path: {}\n    kind: json_file\n  - name: broken\n    path: {}\n    kind: json_file\n",
                valid.display(),
                broken.display()
            ),
        );

        let error = run_apply(ApplyArgs {
            manifest,
            root: Some(dir.path().to_path_buf()),
            confirm: true,
            dry_run: false,
            db: Some(db_path.clone()),
        })
        .unwrap_err();
        assert!(format!("{error:#}").contains("broken"));

        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM idx_groundtruth", [], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, 0, "preflight failure must leave zero imported rows");

        let status = wal_emit::load_status(dir.path()).unwrap();
        assert_eq!(status.state, "failed");
        assert_eq!(status.rolled_back, Some(true));
        assert_eq!(status.batches_completed, 0);
    }

    #[test]
    fn openhuman_apply_commits_memory_and_quarantines_runtime_artifacts() {
        let dir = tempdir().unwrap();
        let db_path = make_views_db(dir.path());
        let home = dir.path().join(".openhuman");
        std::fs::create_dir_all(home.join("workspace/agents")).unwrap();
        std::fs::create_dir_all(home.join("workspace/.agents/skills/mail")).unwrap();
        std::fs::write(
            home.join("config.toml"),
            "default_model = \"local\"\napi_key = \"NEVER_STAGE_THIS_VALUE\"\n",
        )
        .unwrap();
        std::fs::write(
            home.join("workspace/agents/research.toml"),
            "id = \"research\"\nsystem_prompt = \"Research carefully\"\n",
        )
        .unwrap();
        std::fs::write(
            home.join("workspace/.agents/skills/mail/SKILL.md"),
            "---\nname: mail\ndescription: Mail helper\n---\nUse mail safely.",
        )
        .unwrap();
        let foreign_db = home.join("state.db");
        let connection = rusqlite::Connection::open(&foreign_db).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE memories (content TEXT);\n                 INSERT INTO memories VALUES ('OpenHuman durable memory survives migration.');\n                 CREATE TABLE cron_jobs (id TEXT, expression TEXT, command TEXT, schedule TEXT, job_type TEXT, prompt TEXT, name TEXT, session_target TEXT, model TEXT, enabled INTEGER, delivery TEXT, delete_after_run INTEGER);\n                 INSERT INTO cron_jobs VALUES ('job','0 * * * *','echo runtime-only','{\"kind\":\"cron\",\"expr\":\"0 * * * *\"}','shell',NULL,'hourly','isolated',NULL,1,'{\"mode\":\"none\"}',0);",
            )
            .unwrap();
        drop(connection);

        let manifest = write_manifest(
            dir.path(),
            &format!(
                "sources:\n  - name: openhuman-home\n    path: {}\n    kind: assistant_home\n    hint: openhuman\n",
                home.display()
            ),
        );
        run_apply(ApplyArgs {
            manifest,
            root: Some(dir.path().to_path_buf()),
            confirm: true,
            dry_run: false,
            db: Some(db_path.clone()),
        })
        .unwrap();

        let connection = rusqlite::Connection::open(&db_path).unwrap();
        let statements: Vec<String> = connection
            .prepare("SELECT statement FROM idx_groundtruth ORDER BY statement")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(
            statements,
            vec!["OpenHuman durable memory survives migration."]
        );
        let plan_status = migration_plan::load_plan_status(dir.path()).unwrap();
        assert_eq!(plan_status.state, "complete");
        let review = std::fs::read_to_string(
            std::path::Path::new(plan_status.review_path.as_deref().unwrap()).join("plan.json"),
        )
        .unwrap();
        assert!(!review.contains("NEVER_STAGE_THIS_VALUE"));
        let review_root = std::path::Path::new(plan_status.review_path.as_deref().unwrap());
        assert!(review_root.join("config").is_dir());
        assert!(review_root.join("cron").is_dir());
        assert!(review_root.join("agents").is_dir());
        assert!(review_root.join("skills").is_dir());
        assert!(review_root.join("credential-references.json").is_file());
    }

    #[test]
    fn apply_rejects_source_mutation_after_reviewed_plan() {
        let dir = tempdir().unwrap();
        let db_path = make_views_db(dir.path());
        let source = dir.path().join("mutable.md");
        std::fs::write(&source, "Reviewed migration statement.").unwrap();
        let manifest = write_manifest(
            dir.path(),
            &format!(
                "sources:\n  - name: notes\n    path: {}\n    kind: markdown_file\n",
                source.display()
            ),
        );
        std::fs::write(&source, "Changed after the reviewed dry-run.").unwrap();
        let error = run_apply(ApplyArgs {
            manifest,
            root: Some(dir.path().to_path_buf()),
            confirm: true,
            dry_run: false,
            db: Some(db_path.clone()),
        })
        .unwrap_err();
        assert!(format!("{error:#}").contains("no reviewed plan checkpoint"));
        let connection = rusqlite::Connection::open(db_path).unwrap();
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM idx_groundtruth", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn unsupported_apply_blocks_then_records_explicit_acknowledgement() {
        let dir = tempdir().unwrap();
        let vectors = dir.path().join("vectors");
        std::fs::create_dir_all(&vectors).unwrap();
        std::fs::write(vectors.join("index.faiss"), [7_u8; 64]).unwrap();

        let blocked_manifest = write_manifest(
            dir.path(),
            &format!(
                "sources:\n  - name: raw-vectors\n    path: {}\n    kind: faiss_flat\n",
                vectors.display()
            ),
        );
        let error = run_apply(ApplyArgs {
            manifest: blocked_manifest,
            root: Some(dir.path().to_path_buf()),
            confirm: true,
            dry_run: false,
            db: None,
        })
        .unwrap_err();
        assert!(error.to_string().contains("unsupported artifact"));

        let acknowledged_manifest = write_manifest(
            dir.path(),
            &format!(
                "acknowledge_unsupported: true\nsources:\n  - name: raw-vectors\n    path: {}\n    kind: faiss_flat\n",
                vectors.display()
            ),
        );
        run_apply(ApplyArgs {
            manifest: acknowledged_manifest,
            root: Some(dir.path().to_path_buf()),
            confirm: true,
            dry_run: false,
            db: None,
        })
        .unwrap();
        let status = migration_plan::load_plan_status(dir.path()).unwrap();
        assert_eq!(status.state, "complete");
        assert_eq!(status.blocked_unsupported, 1);
        assert!(status.acknowledge_unsupported);
        let unsupported =
            std::path::Path::new(status.review_path.as_deref().unwrap()).join("unsupported");
        assert!(unsupported.is_dir());
    }
}
