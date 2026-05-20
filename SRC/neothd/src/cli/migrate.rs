//! `neoth migrate` — explicit schema migration runner.
//!
//! `neoth serve` runs migrations automatically on startup (see
//! `memory::store::open`). This command exposes the same path for
//! operators who want to migrate offline (without booting the daemon),
//! inspect the migration plan, or pin a specific target version for
//! rollback testing.
//!
//! Subcommands:
//!   `list`     — print every registered migration + current db version
//!   `run`      — apply migrations up to the current `SCHEMA_VERSION`
//!   `run --to N` — apply migrations only up to version N (advanced)
//!   `--dry-run` — print the plan without touching the database
//!
//! The dispatcher in `memory::migrations` is the source of truth; this
//! command is a thin operator handle over it.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use rusqlite::Connection;

use crate::cli::OutputFormat;
use crate::memory::migrations;
use crate::memory::store;

#[derive(Args, Debug, Clone)]
pub struct MigrateArgs {
    #[command(subcommand)]
    pub action: MigrateAction,
    /// Override the views.db path (mostly for tests).
    #[arg(long, value_name = "PATH", global = true)]
    pub db: Option<PathBuf>,
    /// Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum MigrateAction {
    /// List registered migrations + current db version.
    List,
    /// Apply migrations up to the highest registered version (or `--to N`).
    Run {
        /// Stop at this schema version (advanced; default = run to latest).
        #[arg(long, value_name = "N")]
        to: Option<i64>,
        /// Print the plan without modifying the database.
        #[arg(long)]
        dry_run: bool,
    },
    /// V03-04: revert `~/.neoth/` from a `neoth backup` tarball. Defaults
    /// to the most-recent backup in `~/.neoth/backups/`; pass `--from
    /// <path>` to pick a specific one. Use when a schema migration made
    /// views.db inconsistent and you want to fall back to a known-good
    /// snapshot.
    Rollback {
        /// Specific backup tarball to restore. Defaults to the
        /// newest-mtime file matching `neoth-*.tar.gz` under
        /// `~/.neoth/backups/`.
        #[arg(long, value_name = "PATH")]
        from: Option<std::path::PathBuf>,
        /// Override `~/.neoth/` target dir (mostly for tests).
        #[arg(long, value_name = "DIR")]
        home: Option<std::path::PathBuf>,
        /// Overwrite the target dir even if it's non-empty. Required when
        /// the daemon has live files (the common case post-migration).
        #[arg(long)]
        force: bool,
    },
}

pub async fn run_migrate(args: MigrateArgs) -> Result<()> {
    let db_path = args.db.clone().unwrap_or_else(store::default_path);
    match args.action {
        MigrateAction::List => list(&db_path, args.output),
        MigrateAction::Run { to, dry_run } => run(&db_path, to, dry_run, args.output),
        MigrateAction::Rollback { from, home, force } => {
            rollback(from, home, force, args.output).await
        }
    }
}

/// V03-04 2026-05-17: restore the operator's `~/.neoth/` from a
/// `neoth backup`-generated tarball. Thin convenience wrapper over
/// `daemon::backup::restore_backup` — distinct from `neoth restore`
/// in that it auto-discovers the latest backup when `--from` isn't
/// passed, which is the common "I messed up the migration, just
/// revert" path.
async fn rollback(
    from: Option<std::path::PathBuf>,
    home: Option<std::path::PathBuf>,
    force: bool,
    output: OutputFormat,
) -> Result<()> {
    let home = home.unwrap_or_else(crate::config::FreedomConfig::default_neoth_home);
    let archive = match from {
        Some(p) => p,
        None => {
            let backup_dir = home.join("backups");
            find_latest_backup(&backup_dir).with_context(|| {
                format!(
                    "no `neoth-*.tar.gz` found under {}. Pass --from <path> \
                     or run `neoth backup` first.",
                    backup_dir.display()
                )
            })?
        }
    };
    let n = crate::daemon::backup::restore_backup(&archive, &home, force)
        .with_context(|| format!("restore from {}", archive.display()))?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::json!({
                    "rolled_back_from": archive.display().to_string(),
                    "restored_into": home.display().to_string(),
                    "entries": n,
                })
            );
        }
        OutputFormat::Table => {
            println!(
                "rolled back {} entry/entries into {} from {}",
                n,
                home.display(),
                archive.display(),
            );
        }
    }
    Ok(())
}

/// Find the most-recent-mtime file matching `neoth-*.tar.gz` under
/// `backup_dir`. Returns `Err` when the dir doesn't exist OR contains
/// no matching files (operator hasn't run `neoth backup` yet).
fn find_latest_backup(backup_dir: &std::path::Path) -> Result<std::path::PathBuf> {
    if !backup_dir.exists() {
        anyhow::bail!("backup dir {} does not exist", backup_dir.display());
    }
    let mut newest: Option<(std::time::SystemTime, std::path::PathBuf)> = None;
    for entry in std::fs::read_dir(backup_dir)
        .with_context(|| format!("read_dir {}", backup_dir.display()))?
    {
        let entry = entry.with_context(|| "read backup dir entry")?;
        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };
        if !(name.starts_with("neoth-") && name.ends_with(".tar.gz")) {
            continue;
        }
        let mtime = entry
            .metadata()
            .and_then(|m| m.modified())
            .with_context(|| format!("stat {}", path.display()))?;
        match &newest {
            Some((best_ts, _)) if *best_ts >= mtime => {}
            _ => newest = Some((mtime, path)),
        }
    }
    newest
        .map(|(_, p)| p)
        .ok_or_else(|| anyhow::anyhow!("no neoth-*.tar.gz files found"))
}

fn list(db_path: &std::path::Path, output: OutputFormat) -> Result<()> {
    let current = current_version(db_path);
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let registry: Vec<_> = migrations::MIGRATIONS
                .iter()
                .map(|m| {
                    serde_json::json!({
                        "from": m.from,
                        "to": m.to,
                        "description": m.description,
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::json!({
                    "db_path": db_path.display().to_string(),
                    "current_version": current,
                    "target_version": store::SCHEMA_VERSION,
                    "migrations": registry,
                })
            );
        }
        OutputFormat::Table => {
            println!("# db at {}: schema v{}", db_path.display(), current);
            println!("# target version: v{}", store::SCHEMA_VERSION);
            if migrations::MIGRATIONS.is_empty() {
                println!("(no migrations registered)");
                return Ok(());
            }
            for m in migrations::MIGRATIONS {
                let marker = if m.to <= current {
                    "[applied]"
                } else {
                    "[pending]"
                };
                println!("  {marker} v{}→v{}  {}", m.from, m.to, m.description);
            }
        }
    }
    Ok(())
}

fn run(
    db_path: &std::path::Path,
    explicit_to: Option<i64>,
    dry_run: bool,
    output: OutputFormat,
) -> Result<()> {
    let target = explicit_to.unwrap_or(store::SCHEMA_VERSION);
    let current = current_version(db_path);
    if current >= target {
        match output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                println!(
                    "{}",
                    serde_json::json!({
                        "no_op": true,
                        "current": current,
                        "target": target,
                    })
                );
            }
            OutputFormat::Table => {
                println!("schema is at v{current}; target v{target} already reached. No-op.");
            }
        }
        return Ok(());
    }

    let plan: Vec<_> = migrations::MIGRATIONS
        .iter()
        .filter(|m| m.from >= current && m.to <= target)
        .collect();

    if dry_run {
        match output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                let rows: Vec<_> = plan
                    .iter()
                    .map(|m| {
                        serde_json::json!({
                            "from": m.from,
                            "to": m.to,
                            "description": m.description,
                        })
                    })
                    .collect();
                println!(
                    "{}",
                    serde_json::json!({
                        "dry_run": true,
                        "current": current,
                        "target": target,
                        "plan": rows,
                    })
                );
            }
            OutputFormat::Table => {
                println!(
                    "# dry-run: would migrate v{current} → v{target} via {} step(s):",
                    plan.len()
                );
                for m in &plan {
                    println!("  v{}→v{}  {}", m.from, m.to, m.description);
                }
            }
        }
        return Ok(());
    }

    // Real run. Open + migrate.
    let mut conn = Connection::open(db_path)
        .with_context(|| format!("open {} for migration", db_path.display()))?;
    let reached = migrations::migrate(&mut conn, current, target)?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::json!({
                    "applied": plan.len(),
                    "from": current,
                    "to": reached,
                })
            );
        }
        OutputFormat::Table => {
            println!(
                "migrated v{current} → v{reached} ({} step(s) applied)",
                plan.len()
            );
        }
    }
    Ok(())
}

fn current_version(db_path: &std::path::Path) -> i64 {
    let Ok(conn) = Connection::open(db_path) else {
        return 0;
    };
    migrations::current_version(&conn).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    // ── V03-04 2026-05-17: migrate rollback ───────────────────────────

    #[test]
    fn find_latest_backup_picks_newest_mtime() {
        let dir = tempdir().unwrap();
        let backup_dir = dir.path().join("backups");
        std::fs::create_dir_all(&backup_dir).unwrap();
        // Create three files in increasing-mtime order so the test is
        // deterministic across filesystem mtime resolutions.
        for (i, name) in ["neoth-001.tar.gz", "neoth-002.tar.gz", "neoth-003.tar.gz"]
            .iter()
            .enumerate()
        {
            let path = backup_dir.join(name);
            std::fs::write(&path, b"dummy").unwrap();
            std::thread::sleep(std::time::Duration::from_millis(20));
            let _ = i;
        }
        let picked = find_latest_backup(&backup_dir).unwrap();
        assert_eq!(picked.file_name().unwrap(), "neoth-003.tar.gz");
    }

    #[test]
    fn find_latest_backup_skips_non_neoth_archives() {
        let dir = tempdir().unwrap();
        let backup_dir = dir.path().join("backups");
        std::fs::create_dir_all(&backup_dir).unwrap();
        std::fs::write(backup_dir.join("notes.tar.gz"), b"x").unwrap();
        std::fs::write(backup_dir.join("README.md"), b"y").unwrap();
        std::fs::write(backup_dir.join("neoth-001.tar.gz"), b"z").unwrap();
        let picked = find_latest_backup(&backup_dir).unwrap();
        assert_eq!(picked.file_name().unwrap(), "neoth-001.tar.gz");
    }

    #[test]
    fn find_latest_backup_errors_on_empty_dir() {
        let dir = tempdir().unwrap();
        let backup_dir = dir.path().join("empty-backups");
        std::fs::create_dir_all(&backup_dir).unwrap();
        let err = find_latest_backup(&backup_dir).unwrap_err();
        assert!(err.to_string().contains("no neoth-"));
    }

    #[test]
    fn find_latest_backup_errors_on_missing_dir() {
        let dir = tempdir().unwrap();
        let nope = dir.path().join("does-not-exist");
        let err = find_latest_backup(&nope).unwrap_err();
        assert!(err.to_string().contains("does not exist"));
    }

    #[tokio::test]
    async fn rollback_errors_when_no_backup_found() {
        // Fresh home dir with no `backups/` subdir → bail with actionable
        // pointer naming `neoth backup`.
        let dir = tempdir().unwrap();
        let args = MigrateArgs {
            action: MigrateAction::Rollback {
                from: None,
                home: Some(dir.path().to_path_buf()),
                force: false,
            },
            db: None,
            output: OutputFormat::Table,
        };
        let err = run_migrate(args).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("neoth backup") || msg.contains("no `neoth-"),
            "expected actionable pointer, got: {msg}"
        );
    }

    #[tokio::test]
    async fn list_on_fresh_db_reports_version_0() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("fresh.db");
        let args = MigrateArgs {
            action: MigrateAction::List,
            db: Some(db),
            output: OutputFormat::Table,
        };
        // Just ensure it doesn't error; full output capture would need
        // stdout redirection.
        run_migrate(args).await.unwrap();
    }

    #[tokio::test]
    async fn dry_run_does_not_modify_db() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("v3.db");
        // Bootstrap a v3 stamp.
        {
            let conn = Connection::open(&db).unwrap();
            conn.execute_batch(
                "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                 INSERT INTO meta (key, value) VALUES ('schema_version', '3');",
            )
            .unwrap();
        }
        let args = MigrateArgs {
            action: MigrateAction::Run {
                to: Some(store::SCHEMA_VERSION),
                dry_run: true,
            },
            db: Some(db.clone()),
            output: OutputFormat::Table,
        };
        run_migrate(args).await.unwrap();
        // Stamp should still read 3.
        let conn = Connection::open(&db).unwrap();
        let v = migrations::current_version(&conn).unwrap();
        assert_eq!(v, 3, "dry-run must not change the stamp");
    }

    #[tokio::test]
    async fn run_reaches_target() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("v.db");
        // Open via store so all tables exist + the stamp is current.
        let _conn = store::open(&db).unwrap();
        // Force the stamp back to v3 to simulate an upgrade scenario.
        {
            let c = Connection::open(&db).unwrap();
            c.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', '3')",
                [],
            )
            .unwrap();
        }
        let args = MigrateArgs {
            action: MigrateAction::Run {
                to: None,
                dry_run: false,
            },
            db: Some(db.clone()),
            output: OutputFormat::Table,
        };
        run_migrate(args).await.unwrap();
        let c = Connection::open(&db).unwrap();
        assert_eq!(
            migrations::current_version(&c).unwrap(),
            store::SCHEMA_VERSION,
        );
    }

    #[tokio::test]
    async fn run_is_noop_when_already_current() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("current.db");
        let _ = store::open(&db).unwrap(); // stamps SCHEMA_VERSION
        let args = MigrateArgs {
            action: MigrateAction::Run {
                to: None,
                dry_run: false,
            },
            db: Some(db),
            output: OutputFormat::Table,
        };
        run_migrate(args).await.unwrap();
    }

    #[test]
    fn current_version_returns_zero_for_missing_db() {
        let dir = tempdir().unwrap();
        let v = super::current_version(&dir.path().join("absent.db"));
        assert_eq!(v, 0);
    }
}
