//! `neoth import` — import past AI-agent SESSION TRANSCRIPTS into NEOTH's
//! ground-truth as un-surfaced corroboration candidates. GOLD-ADAPT-VIEW-04.
//!
//! Complements `neoth groundtruth import-agent` (which imports another agent's
//! MEMORY store). This reads the on-disk conversation logs of claude-code /
//! codex / gemini — the formats agentsview reverse-engineered — so NEOTH can
//! learn what the operator worked on across their other tools.
//!
//! Imported rows are `Source::ImportSession` → `FactState::Candidate`: they do
//! not surface in recall until corroborated (GOLD-ADAPT-MEM-01 gate). The
//! daemon need not be running; this writes `views.db` directly.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::memory::{groundtruth, session_import, store};

#[derive(Args, Debug, Clone)]
pub struct ImportArgs {
    #[command(subcommand)]
    pub action: ImportAction,

    /// Override the views.db path. Defaults to `~/.neoth/views.db`.
    #[arg(long, value_name = "PATH", global = true)]
    pub db: Option<PathBuf>,

    /// Output format. Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ImportAction {
    /// Import a past agent session transcript into ground-truth candidates.
    Session {
        /// Path to the session transcript (`.jsonl` / `.json`).
        path: String,
        /// Source format: `claude | codex | gemini`.
        #[arg(long, default_value = "claude")]
        format: String,
        /// Scope tag for every inserted row.
        #[arg(long, default_value = "session:imported")]
        scope: String,
        /// Claim granularity: `turns` (digest + each operator request) or
        /// `digest` (one summary row only).
        #[arg(long, default_value = "turns")]
        granularity: String,
        /// Parse + print claims without inserting any rows.
        #[arg(long)]
        dry_run: bool,
    },
}

pub async fn run_import(args: ImportArgs) -> Result<()> {
    let db_path = args.db.clone().unwrap_or_else(store::default_path);
    match args.action {
        ImportAction::Session {
            path,
            format,
            scope,
            granularity,
            dry_run,
        } => {
            let conn = store::open(&db_path).context("open views.db")?;
            import_session(&conn, &path, &format, &scope, &granularity, dry_run, args.output)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn import_session(
    conn: &rusqlite::Connection,
    path_str: &str,
    format: &str,
    scope: &str,
    granularity: &str,
    dry_run: bool,
    output: OutputFormat,
) -> Result<()> {
    let gran = match granularity {
        "turns" => session_import::Granularity::Turns,
        "digest" => session_import::Granularity::Digest,
        other => anyhow::bail!("unknown granularity '{other}'. Expected: turns | digest"),
    };

    let body = std::fs::read_to_string(path_str).with_context(|| format!("read {path_str}"))?;
    let session = session_import::parse_session(&body, format)
        .with_context(|| format!("parse {format} session at {path_str}"))?;
    let claims = session_import::session_to_claims(&session, scope, gran);

    if dry_run {
        match output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                println!(
                    "{}",
                    serde_json::json!({
                        "format": format,
                        "session_id": session.session_id,
                        "messages": session.messages.len(),
                        "count": claims.len(),
                        "preview": claims.iter().take(5).map(|c| &c.statement).collect::<Vec<_>>(),
                    })
                );
            }
            OutputFormat::Table => {
                println!(
                    "# {} claim(s) from {format} session {} ({} message(s)) — dry-run, no rows inserted",
                    claims.len(),
                    session.session_id,
                    session.messages.len(),
                );
                for c in claims.iter().take(20) {
                    println!("  · [{}] {}", c.scope, c.statement);
                }
                if claims.len() > 20 {
                    println!("  … and {} more", claims.len() - 20);
                }
            }
        }
        return Ok(());
    }

    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    let mut inserted = 0usize;
    for c in &claims {
        groundtruth::insert(conn, &c.statement, &c.source, &c.scope, now_ns)?;
        inserted += 1;
    }

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::json!({
                    "inserted": inserted,
                    "format": format,
                    "session_id": session.session_id,
                })
            );
        }
        OutputFormat::Table => {
            println!(
                "imported {inserted} ground-truth candidate(s) from {format} session {} at {path_str}",
                session.session_id
            );
        }
    }
    Ok(())
}
