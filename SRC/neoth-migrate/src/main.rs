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

use anyhow::{Context as _, Result};
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
    // Manifest validation first — a bad manifest is the first thing the
    // operator should hear about, not missing --confirm or missing db.
    let manifest = readers::load_manifest(&args.manifest)?;
    let home = args.root.clone().unwrap_or_else(default_home);

    // ── Dry-run branch ────────────────────────────────────────────────────────
    //
    // --dry-run takes precedence over --confirm; no db is opened, no rows
    // are written. The JSON report is identical to `neoth-migrate dry-run`.
    if args.dry_run {
        tracing::info!(
            sources = manifest.sources.len(),
            "neoth-migrate apply --dry-run (preview only)"
        );
        let report = readers::scan_all(&manifest.sources, &home);
        println!("{}", serde_json::to_string_pretty(&report)?);
        eprintln!(
            "dry-run: {} source(s) scanned. Re-run without --dry-run and with \
             --confirm to apply.",
            manifest.sources.len()
        );
        return Ok(());
    }

    // ── Guard: --confirm required for a real insert ────────────────────────
    if !args.confirm {
        anyhow::bail!(
            "Memory import requires --confirm. Use --dry-run first to preview, \
             then re-run with --confirm to apply."
        );
    }

    // ── Open views.db ─────────────────────────────────────────────────────────
    let db_path = args
        .db
        .clone()
        .unwrap_or_else(|| home.join(".neoth").join("views.db"));
    let conn = rusqlite::Connection::open(&db_path)
        .with_context(|| format!("open views.db at {}", db_path.display()))?;

    // Sanity-check: confirm idx_groundtruth has the columns we INSERT into.
    // A schema mismatch (neothd added a NOT NULL column without a default)
    // would otherwise produce a cryptic SQLite error mid-import.
    check_groundtruth_schema(&conn)
        .with_context(|| format!("schema check on {}", db_path.display()))?;

    // ── Single transaction for speed + atomicity ──────────────────────────────
    conn.execute_batch("BEGIN")?;

    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as i64;

    let mut total_inserted: usize = 0;
    let mut total_skipped_sources: usize = 0;
    let mut per_source: Vec<serde_json::Value> = Vec::new();

    for src in &manifest.sources {
        match readers::emit_claims(src, &home) {
            Ok(claims) => {
                let mut src_inserted = 0usize;
                for (statement, source_tag, scope) in &claims {
                    // INSERT OR IGNORE — idempotent: (statement, scope) unique index
                    // means re-runs are safe.  Do NOT use INSERT OR REPLACE: that
                    // re-inserts with a new id, resetting confirmed_count.
                    let n = conn
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
                        .with_context(|| {
                            format!("INSERT OR IGNORE for source '{}'", src.name)
                        })?;
                    if n > 0 {
                        src_inserted += 1;
                    }
                }
                total_inserted += src_inserted;
                per_source.push(serde_json::json!({
                    "name": src.name,
                    "claims_seen": claims.len(),
                    "inserted": src_inserted,
                    "skipped_duplicates": claims.len() - src_inserted,
                }));
            }
            Err(e) => {
                tracing::warn!(
                    source = %src.name,
                    kind  = ?src.kind,
                    err   = %e,
                    "emit_claims failed for source — skipping"
                );
                total_skipped_sources += 1;
                per_source.push(serde_json::json!({
                    "name": src.name,
                    "skipped": true,
                    "reason": e.to_string(),
                }));
            }
        }
    }

    conn.execute_batch("COMMIT")?;

    // ── WAL audit (IMPORT_COMPLETE 0x99) ──────────────────────────────────────
    //
    // neoth-migrate is a standalone binary with no access to neothd's
    // WalWriterHandle. Per the design note at wal/events.rs: "CLI one-shots
    // stay silent." We therefore emit a JSONL audit line to
    // ~/.neoth/neoth-migrate-audit.jsonl which the daemon reconciles on
    // next start. Event type 0x99 = 153 decimal (GROUNDTRUTH_IMPORTED).
    let audit_path = home.join(".neoth").join("neoth-migrate-audit.jsonl");
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&audit_path)
    {
        use std::io::Write;
        let _ = writeln!(
            f,
            "{}",
            serde_json::json!({
                "event": "GROUNDTRUTH_IMPORTED",
                "event_type": 0x99u8,  // = 153
                "sources_total": manifest.sources.len(),
                "sources_skipped": total_skipped_sources,
                "inserted": total_inserted,
                "ts_ns": now_ns,
            })
        );
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "sources": manifest.sources.len(),
            "inserted": total_inserted,
            "skipped_sources": total_skipped_sources,
            "detail": per_source,
        }))?
    );

    Ok(())
}

/// Assert that `idx_groundtruth` has every column we INSERT into.
/// This protects against schema drift if neothd adds a NOT NULL column
/// without a DEFAULT — a hard fail here is clearer than a mid-import
/// SQLite constraint error.
fn check_groundtruth_schema(conn: &rusqlite::Connection) -> Result<()> {
    let mut stmt = conn.prepare("PRAGMA table_info(idx_groundtruth)")?;
    let cols: std::collections::HashSet<String> = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .filter_map(|r| r.ok())
        .collect();

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
        p
    }

    // ── dry_run branch ────────────────────────────────────────────────────────

    #[test]
    fn apply_dry_run_prints_scan_no_db_write() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("claims.json");
        std::fs::write(&src, r#"[{"statement":"fact A here long"},{"statement":"fact B here long"}]"#).unwrap();
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
}
