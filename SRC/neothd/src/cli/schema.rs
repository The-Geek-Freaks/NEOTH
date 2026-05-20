//! `neoth schema` — inspect the live SQLite schema in `~/.neoth/views.db`.
//!
//! Pairs with `neoth migrate list` (which shows the registered upgrade
//! chain): `neoth schema` shows the actual on-disk shape — every table,
//! column count, row count, and the version stamp from `meta`.
//!
//! Pure read-only. No daemon required. Operators use it to debug "is
//! `idx_groundtruth` actually present in my install?" without firing up
//! `sqlite3` shell.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args;
use rusqlite::Connection;

use crate::cli::OutputFormat;
use crate::memory::{migrations, store};

#[derive(Args, Debug, Clone)]
pub struct SchemaArgs {
    /// Override the views.db path (mostly for tests).
    #[arg(long, value_name = "PATH")]
    pub db: Option<PathBuf>,
    /// Show column details per table (name, type, nullable, default).
    #[arg(long)]
    pub columns: bool,
    /// Output format inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Debug, Clone)]
pub struct TableInfo {
    pub name: String,
    pub kind: String,
    pub row_count: i64,
    pub columns: Vec<ColumnInfo>,
}

#[derive(Debug, Clone)]
pub struct ColumnInfo {
    pub name: String,
    pub data_type: String,
    pub not_null: bool,
    pub default_value: Option<String>,
    pub primary_key: bool,
}

pub async fn run_schema(args: SchemaArgs) -> Result<()> {
    let db_path = args.db.clone().unwrap_or_else(store::default_path);

    if !db_path.exists() {
        match args.output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                println!(
                    "{}",
                    serde_json::json!({
                        "exists": false,
                        "path": db_path.display().to_string(),
                    })
                );
            }
            OutputFormat::Table => {
                println!(
                    "views.db absent at {}. Run `neoth serve` (or `neoth migrate run`) to create it.",
                    db_path.display()
                );
            }
        }
        return Ok(());
    }

    let conn = Connection::open(&db_path).with_context(|| format!("open {}", db_path.display()))?;

    let stamped = migrations::current_version(&conn).unwrap_or(0);
    let target = store::SCHEMA_VERSION;
    let tables = collect_tables(&conn, args.columns)?;

    match args.output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let json_tables: Vec<_> = tables
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "name": t.name,
                        "kind": t.kind,
                        "row_count": t.row_count,
                        "columns": t.columns.iter().map(|c| serde_json::json!({
                            "name": c.name,
                            "type": c.data_type,
                            "not_null": c.not_null,
                            "default": c.default_value,
                            "primary_key": c.primary_key,
                        })).collect::<Vec<_>>(),
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::json!({
                    "db_path": db_path.display().to_string(),
                    "current_version": stamped,
                    "target_version": target,
                    "tables": json_tables,
                })
            );
        }
        OutputFormat::Table => {
            println!("# views.db at {}", db_path.display());
            println!(
                "# schema v{} (target v{}){}",
                stamped,
                target,
                if stamped == target {
                    " — current"
                } else {
                    " — migration pending; run `neoth migrate run`"
                },
            );
            println!();
            println!(
                "  {:<28}  {:<6}  {:>10}  {:>5}",
                "table", "kind", "rows", "cols"
            );
            for t in &tables {
                println!(
                    "  {:<28}  {:<6}  {:>10}  {:>5}",
                    t.name,
                    t.kind,
                    t.row_count,
                    t.columns.len()
                );
            }
            if args.columns {
                println!();
                for t in &tables {
                    if t.columns.is_empty() {
                        continue;
                    }
                    println!("## {} ({})", t.name, t.kind);
                    for c in &t.columns {
                        let tag = format!(
                            "{}{}{}",
                            if c.primary_key { "PK " } else { "" },
                            if c.not_null { "NOT NULL " } else { "" },
                            c.default_value
                                .as_deref()
                                .map(|d| format!("DEFAULT {d}"))
                                .unwrap_or_default(),
                        );
                        println!("  {:<24} {:<12} {}", c.name, c.data_type, tag.trim());
                    }
                    println!();
                }
            }
        }
    }
    Ok(())
}

fn collect_tables(conn: &Connection, with_columns: bool) -> Result<Vec<TableInfo>> {
    // SELECT every table + view from sqlite_master, plus FTS5 virtuals
    // (which show up as type='table' with sql starting `CREATE VIRTUAL`).
    let mut stmt = conn
        .prepare(
            "SELECT name, type, sql FROM sqlite_master \
             WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%' \
             ORDER BY type, name",
        )
        .context("query sqlite_master")?;
    let rows: Vec<(String, String, Option<String>)> = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("collect sqlite_master rows")?;

    let mut out = Vec::with_capacity(rows.len());
    for (name, kind, sql) in rows {
        let kind = if sql.as_deref().unwrap_or("").contains("VIRTUAL TABLE") {
            "fts5".to_string()
        } else {
            kind
        };
        let row_count = count_rows(conn, &name).unwrap_or(-1);
        let columns = if with_columns {
            pragma_columns(conn, &name).unwrap_or_default()
        } else {
            pragma_columns(conn, &name)
                .unwrap_or_default()
                .into_iter()
                .map(|c| ColumnInfo {
                    name: c.name,
                    data_type: String::new(),
                    not_null: false,
                    default_value: None,
                    primary_key: false,
                })
                .collect()
        };
        out.push(TableInfo {
            name,
            kind,
            row_count,
            columns,
        });
    }
    Ok(out)
}

fn count_rows(conn: &Connection, table: &str) -> Result<i64> {
    // FTS5 content tables sometimes refuse COUNT(*) at runtime; treat
    // an error as "unknown" rather than failing the whole command.
    let sql = format!("SELECT count(*) FROM \"{}\"", table.replace('"', "\"\""));
    conn.query_row(&sql, [], |r| r.get::<_, i64>(0))
        .map_err(|e| anyhow::anyhow!("count {}: {e}", table))
}

fn pragma_columns(conn: &Connection, table: &str) -> Result<Vec<ColumnInfo>> {
    let sql = format!("PRAGMA table_info(\"{}\")", table.replace('"', "\"\""));
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map([], |r| {
            Ok(ColumnInfo {
                name: r.get::<_, String>(1)?,
                data_type: r.get::<_, String>(2)?,
                not_null: r.get::<_, i64>(3)? != 0,
                default_value: r.get::<_, Option<String>>(4)?,
                primary_key: r.get::<_, i64>(5)? != 0,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn missing_db_prints_helpful_message() {
        let dir = tempdir().unwrap();
        let args = SchemaArgs {
            db: Some(dir.path().join("absent.db")),
            columns: false,
            output: OutputFormat::Table,
        };
        run_schema(args).await.unwrap();
    }

    #[tokio::test]
    async fn schema_lists_every_table() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("v.db");
        let _ = store::open(&db).unwrap(); // creates the full v5 schema
        let conn = Connection::open(&db).unwrap();
        let tables = collect_tables(&conn, false).unwrap();
        // Expect every documented table to be present.
        let names: Vec<&str> = tables.iter().map(|t| t.name.as_str()).collect();
        for required in [
            "meta",
            "wal_cursor",
            "idx_episode",
            "idx_provider",
            "idx_consolidated",
            "idx_longterm",
            "idx_groundtruth",
            "sources",
            "vocabulary",
        ] {
            assert!(
                names.contains(&required),
                "table `{required}` missing; got: {names:?}",
            );
        }
    }

    #[tokio::test]
    async fn schema_columns_flag_pulls_pragma_details() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("v.db");
        let _ = store::open(&db).unwrap();
        let conn = Connection::open(&db).unwrap();
        let tables = collect_tables(&conn, true).unwrap();
        let episode = tables
            .iter()
            .find(|t| t.name == "idx_episode")
            .expect("idx_episode in registry");
        // Phase 28a added `importance` + `last_access_ts` columns.
        assert!(
            episode.columns.iter().any(|c| c.name == "importance"),
            "idx_episode must carry an `importance` column post-v4",
        );
        assert!(
            episode.columns.iter().any(|c| c.name == "last_access_ts"),
            "idx_episode must carry `last_access_ts` post-v4",
        );
    }

    #[tokio::test]
    async fn row_count_reflects_inserts() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("v.db");
        let conn = store::open(&db).unwrap();
        conn.execute(
            "INSERT INTO idx_episode (event_id, event_type, ts_ns, text, text_hash, importance, last_access_ts) \
             VALUES (1, 1, 1, 'x', 'h', 0.5, 0)",
            [],
        )
        .unwrap();
        let tables = collect_tables(&conn, false).unwrap();
        let episode = tables.iter().find(|t| t.name == "idx_episode").unwrap();
        assert_eq!(episode.row_count, 1);
    }

    #[tokio::test]
    async fn fts5_tables_are_tagged_as_fts5() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("v.db");
        let _ = store::open(&db).unwrap();
        let conn = Connection::open(&db).unwrap();
        let tables = collect_tables(&conn, false).unwrap();
        // idx_episode_fts is a CREATE VIRTUAL TABLE — must come back as fts5.
        let fts = tables
            .iter()
            .find(|t| t.name == "idx_episode_fts")
            .expect("idx_episode_fts present");
        assert_eq!(fts.kind, "fts5");
    }

    #[tokio::test]
    async fn run_schema_with_columns_does_not_error() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("v.db");
        let _ = store::open(&db).unwrap();
        let args = SchemaArgs {
            db: Some(db),
            columns: true,
            output: OutputFormat::Table,
        };
        run_schema(args).await.unwrap();
    }
}
