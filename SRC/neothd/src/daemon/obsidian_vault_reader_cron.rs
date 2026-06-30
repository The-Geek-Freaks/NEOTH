//! GOLD-ADAPT-JV-IMP-05 — Obsidian vault bidirectional sync cron.
//!
//! Runs two passes on each tick:
//!
//! **Reader pass** — walks the vault looking for files where
//! `is_managed_obsidian_note` returns `true` (i.e. files with
//! `source: openclaw-*` or `source: neoth-*` YAML frontmatter).  For each
//! such file it computes a SHA-256 digest; if the digest differs from the
//! persistent state map (`~/.neoth/obsidian_vault_reader_state.json`) the
//! note body is extracted and inserted into `idx_groundtruth` via
//! `groundtruth::insert` with `Source::ImportObsidian`.  The state file is
//! written atomically (tmp → rename) after every pass so a daemon kill
//! mid-pass is always safe.
//!
//! **Writer pass** — queries `idx_groundtruth` for rows where the source is
//! `"onboarding"` or `"operator-runtime"` (operator-attested / Verified),
//! and writes or updates one `<vault>/NEOTH-Facts/<scope>/<id>.md` file per
//! row.  Each file carries YAML frontmatter (`source: neoth-groundtruth`,
//! `id`, `scope`, `updated`) so the reader pass recognises it as managed and
//! picks it up on the next cycle.  `WriteCoalescer` skips identical-content
//! writes to break the reader-writer echo loop.
//!
//! **Weekly synthesis** (Phase-1, WAL-free) — on the first tick that falls in
//! a new ISO week, reads a window of `idx_groundtruth` rows and writes a
//! brief summary note to `<vault>/NEOTH-Synthesis/<YYYY-WW>.md`, then inserts
//! it as `Source::Synthesis` into `idx_groundtruth`.
//!
//! ## Design
//!
//! - **WAL-free**: `groundtruth::insert` is the durable audit record (all WAL
//!   bands 0x00..=0xFF are assigned/reserved; no new event type is needed).
//! - **spawn_blocking for DB writes**: `rusqlite::Connection` is `!Send`; every
//!   DB access opens a new connection INSIDE `spawn_blocking` and never crosses
//!   an `.await` boundary.
//! - **Fail-soft per file**: per-file errors are logged and skipped; the cron
//!   never crashes the daemon on a bad note.
//! - **Off by default**: `obsidian_vault_reader_enabled = false` in config.
//!   Requires `obsidian_vault` to be set as well.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::cli::obsidian_sync_util::WriteCoalescer;
use crate::memory::{
    foreign_import::{is_managed_obsidian_note, obsidian_folder_scope, strip_yaml_frontmatter},
    groundtruth::{self, Source},
    store,
};

/// Default cron interval: 6 hours.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// Path to the persistent SHA-256 change-tracking state file.
fn state_file_path(home: &Path) -> PathBuf {
    home.join("obsidian_vault_reader_state.json")
}

/// Load the persisted SHA-256 map from disk.  Missing file → empty map.
fn load_state(home: &Path) -> HashMap<PathBuf, [u8; 32]> {
    let path = state_file_path(home);
    if !path.exists() {
        return HashMap::new();
    }
    let body = match std::fs::read_to_string(&path) {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "obsidian vault reader: failed to read state file; starting fresh");
            return HashMap::new();
        }
    };
    // State is stored as a JSON map of path-string → hex-encoded SHA-256.
    let raw: HashMap<String, String> = serde_json::from_str(&body).unwrap_or_default();
    raw.into_iter()
        .filter_map(|(k, v)| {
            let path = PathBuf::from(k);
            let bytes = hex::decode(&v).ok()?;
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Some((path, arr))
            } else {
                None
            }
        })
        .collect()
}

/// Persist the SHA-256 map to disk atomically (tmp → rename).
fn save_state(home: &Path, state: &HashMap<PathBuf, [u8; 32]>) -> Result<()> {
    let raw: HashMap<String, String> = state
        .iter()
        .map(|(k, v)| (k.to_string_lossy().into_owned(), hex::encode(v)))
        .collect();
    let json = serde_json::to_string(&raw).context("serialize vault reader state")?;
    let dest = state_file_path(home);
    let tmp = dest.with_extension("tmp");
    std::fs::write(&tmp, &json).context("write vault reader state tmp")?;
    std::fs::rename(&tmp, &dest).context("rename vault reader state")?;
    Ok(())
}

/// SHA-256 of `bytes`.
fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// Extract the scope from a managed note's path relative to the vault root.
fn scope_for_managed_note(vault: &Path, path: &Path) -> String {
    let rel = path.strip_prefix(vault).unwrap_or(path);
    let folder = rel
        .parent()
        .and_then(|p| p.components().next())
        .and_then(|c| {
            use std::path::Component;
            if let Component::Normal(n) = c {
                n.to_str()
            } else {
                None
            }
        })
        .unwrap_or("");
    obsidian_folder_scope(folder).to_string()
}

// ── Reader pass ──────────────────────────────────────────────────────────────

/// One managed note collected during the reader pass.
struct ManagedNote {
    path: PathBuf,
    digest: [u8; 32],
    statement: String,
    scope: String,
}

/// Walk the vault and collect all managed notes whose digest has changed since
/// the last pass.  Never returns `Err` for per-file failures — only for a
/// catastrophic directory-walk failure.
fn collect_changed_managed_notes(
    vault: &Path,
    state: &HashMap<PathBuf, [u8; 32]>,
) -> Result<Vec<ManagedNote>> {
    let mut out = Vec::new();
    walk_vault_for_managed(vault, vault, state, &mut out)?;
    Ok(out)
}

fn walk_vault_for_managed(
    vault_root: &Path,
    current: &Path,
    state: &HashMap<PathBuf, [u8; 32]>,
    out: &mut Vec<ManagedNote>,
) -> Result<()> {
    let entries = std::fs::read_dir(current)
        .with_context(|| format!("read dir {}", current.display()))?;
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                warn!(error = %e, dir = %current.display(), "obsidian reader: dir entry error; skipping");
                continue;
            }
        };
        let path = entry.path();
        if path.is_dir() {
            let dir_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !dir_name.starts_with('.') {
                walk_vault_for_managed(vault_root, &path, state, out)?;
            }
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        let body = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, path = %path.display(), "obsidian reader: unreadable note; skipping");
                continue;
            }
        };
        let body_str = String::from_utf8_lossy(&body);
        // Only pick up managed notes (source: openclaw-* or neoth-*).
        if !is_managed_obsidian_note(&body_str) {
            continue;
        }
        let digest = sha256(&body);
        // Skip if digest unchanged.
        if state.get(&path).is_some_and(|prev| *prev == digest) {
            continue;
        }
        // Extract body text (frontmatter stripped).
        let content = strip_yaml_frontmatter(&body_str);
        let content = content.trim();
        if content.is_empty() {
            debug!(path = %path.display(), "obsidian reader: managed note has empty body after frontmatter strip; skipping");
            continue;
        }
        let title = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("untitled");
        let statement = format!("[{title}] {content}");
        let scope = scope_for_managed_note(vault_root, &path);
        out.push(ManagedNote {
            path,
            digest,
            statement,
            scope,
        });
    }
    Ok(())
}

/// Run one reader pass.  Opens `views.db` inside `spawn_blocking` per the
/// `arxiv_skill_scan_cron` pattern — `rusqlite::Connection` is `!Send`.
///
/// Returns `(inserted, skipped)` counts.
pub async fn run_one_reader_pass(
    vault: &Path,
    home: &Path,
) -> Result<(usize, usize)> {
    let mut state = load_state(home);

    let changed = match collect_changed_managed_notes(vault, &state) {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "obsidian vault reader: directory walk failed; skipping pass");
            return Ok((0, 0));
        }
    };

    if changed.is_empty() {
        return Ok((0, 0));
    }

    let db_path = home.join("views.db");
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0);

    // Collect (statement, scope, path, digest) — all Send.
    let rows: Vec<(String, String, PathBuf, [u8; 32])> = changed
        .into_iter()
        .map(|n| (n.statement, n.scope, n.path, n.digest))
        .collect();

    let inserted_paths = tokio::task::spawn_blocking(move || -> Vec<(PathBuf, [u8; 32], bool)> {
        let conn = match store::open(&db_path) {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "obsidian vault reader: failed to open views.db");
                return vec![];
            }
        };
        let mut results = Vec::with_capacity(rows.len());
        for (statement, scope, path, digest) in rows {
            match groundtruth::insert(&conn, &statement, &Source::ImportObsidian, &scope, now_ns) {
                Ok(_) => results.push((path, digest, true)),
                Err(e) => {
                    warn!(error = %e, path = %path.display(), "obsidian vault reader: groundtruth::insert failed; skipping");
                    results.push((path, digest, false));
                }
            }
        }
        results
    })
    .await
    .unwrap_or_default();

    let mut inserted = 0usize;
    let mut skipped = 0usize;
    for (path, digest, ok) in inserted_paths {
        if ok {
            state.insert(path, digest);
            inserted += 1;
        } else {
            skipped += 1;
        }
    }

    // Atomically persist the updated state map.
    if let Err(e) = save_state(home, &state) {
        warn!(error = %e, "obsidian vault reader: failed to persist state file (non-fatal)");
    }

    Ok((inserted, skipped))
}

// ── Writer pass ───────────────────────────────────────────────────────────────

/// One operator-attested groundtruth row returned from the DB for vault writing.
struct WriterRow {
    id: i64,
    statement: String,
    scope: String,
    asserted_at: i64,
}

/// Fetch operator-attested rows from `idx_groundtruth` (source = `onboarding`
/// or `operator-runtime`, active only).
fn fetch_operator_rows(db_path: &Path) -> Vec<WriterRow> {
    let conn = match store::open(db_path) {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "obsidian vault writer: failed to open views.db");
            return vec![];
        }
    };
    let mut stmt = match conn.prepare(
        "SELECT id, statement, scope, asserted_at \
         FROM idx_groundtruth \
         WHERE source IN ('onboarding', 'operator-runtime') \
           AND revoked_at IS NULL \
         ORDER BY id",
    ) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "obsidian vault writer: failed to prepare SELECT");
            return vec![];
        }
    };
    let mut rows = Vec::new();
    if let Ok(mapped) = stmt.query_map([], |r| {
        Ok(WriterRow {
            id: r.get(0)?,
            statement: r.get(1)?,
            scope: r.get(2)?,
            asserted_at: r.get(3)?,
        })
    }) {
        for row in mapped.flatten() {
            rows.push(row);
        }
    }
    rows
}

/// Format a Unix nanosecond timestamp as a date string (YYYY-MM-DD).
fn format_date_from_ns(ns: i64) -> String {
    let secs = ns / 1_000_000_000;
    let days_since_epoch = secs / 86_400;
    // Simplified Gregorian approximation (sufficient for a vault label).
    let mut y = 1970i64;
    let mut remaining_days = days_since_epoch;
    loop {
        let days_in_year = if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        y += 1;
    }
    let feb = if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) { 29i64 } else { 28i64 };
    let month_days = [31i64, feb, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut m = 1usize;
    for days in &month_days {
        if remaining_days < *days {
            break;
        }
        remaining_days -= days;
        m += 1;
    }
    let d = remaining_days + 1;
    format!("{y:04}-{m:02}-{d:02}")
}

/// Render one groundtruth row as vault-note bytes.
fn render_fact_note(row: &WriterRow) -> Vec<u8> {
    let updated = format_date_from_ns(row.asserted_at);
    let content = format!(
        "---\nsource: neoth-groundtruth\nid: {}\nscope: {}\nupdated: {}\n---\n\n{}\n",
        row.id, row.scope, updated, row.statement
    );
    content.into_bytes()
}

/// Run one writer pass: fetch operator-attested rows and write/update vault
/// notes in `<vault>/NEOTH-Facts/<scope>/<id>.md`.
///
/// Uses `WriteCoalescer` to skip identical-content rewrites (echo-loop guard).
pub fn run_one_writer_pass(vault: &Path, db_path: &Path) -> Result<(usize, usize)> {
    let rows = fetch_operator_rows(db_path);
    if rows.is_empty() {
        return Ok((0, 0));
    }

    let facts_dir = vault.join("NEOTH-Facts");
    let mut coalescer = WriteCoalescer::new();

    for row in &rows {
        // Sanitize scope for use as a directory name.
        let safe_scope = row.scope.replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_");
        let note_dir = facts_dir.join(&safe_scope);
        let note_path = note_dir.join(format!("{}.md", row.id));
        let bytes = render_fact_note(row);
        coalescer.push(note_path, bytes);
    }

    let (written, skipped) = coalescer.flush().context("WriteCoalescer flush (writer pass)")?;
    Ok((written, skipped))
}

// ── Weekly synthesis ─────────────────────────────────────────────────────────

/// ISO week label for a Unix second timestamp: `"YYYY-Www"`.
/// Duplicated from `daemon::synthesis_cron` (private there) so this module
/// stays self-contained.
fn iso_week_label(unix_secs: i64) -> String {
    let days = unix_secs / 86_400;
    let approx_year = 1970 + (days / 365);
    let day_of_year = days % 365;
    let week_num = (day_of_year / 7) + 1;
    format!("{:04}-W{:02}", approx_year, week_num.clamp(1, 53))
}

/// Run the weekly synthesis if the current ISO week is new relative to the
/// `last_synthesis_week` field in the state file.
///
/// Returns `true` if a synthesis note was written this call.
pub async fn run_synthesis_if_new_week(vault: &Path, home: &Path) -> bool {
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let this_week = iso_week_label(now_unix);

    // Read last_synthesis_week from a side-file.
    let week_marker = home.join("obsidian_vault_reader_last_week.txt");
    let last_week = std::fs::read_to_string(&week_marker).unwrap_or_default();
    let last_week = last_week.trim().to_string();

    if last_week == this_week {
        return false;
    }

    // Collect a window of recent operator-attested + synthesis facts.
    let db_path = home.join("views.db");
    let vault_path = vault.to_path_buf();
    let _home_path = home.to_path_buf();
    let week_label = this_week.clone();

    let written = tokio::task::spawn_blocking(move || -> bool {
        let conn = match store::open(&db_path) {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "obsidian synthesis: failed to open views.db");
                return false;
            }
        };

        // Fetch up to 50 recent verified facts for the note body.
        let mut stmt = match conn.prepare(
            "SELECT statement, scope, source \
             FROM idx_groundtruth \
             WHERE revoked_at IS NULL \
               AND fact_state = 'verified' \
             ORDER BY asserted_at DESC LIMIT 50",
        ) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "obsidian synthesis: failed to prepare SELECT");
                return false;
            }
        };
        let mut rows: Vec<(String, String, String)> = Vec::new();
        if let Ok(mapped) = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))) {
            for row in mapped.flatten() {
                rows.push(row);
            }
        }

        if rows.is_empty() {
            return false;
        }

        // Build the synthesis note.
        let mut body = format!(
            "---\nsource: neoth-synthesis\nweek: {}\n---\n\n# NEOTH Weekly Synthesis — {}\n\n",
            week_label, week_label
        );
        body.push_str("## Verified ground-truth snapshot\n\n");
        for (statement, scope, source) in &rows {
            body.push_str(&format!("- **[{scope}]** ({source}) {statement}\n"));
        }

        // Write the vault note.
        let synth_dir = vault_path.join("NEOTH-Synthesis");
        if let Err(e) = std::fs::create_dir_all(&synth_dir) {
            warn!(error = %e, "obsidian synthesis: failed to create NEOTH-Synthesis dir");
            return false;
        }
        let note_path = synth_dir.join(format!("{}.md", week_label));
        let tmp = note_path.with_extension("tmp");
        if let Err(e) = std::fs::write(&tmp, body.as_bytes()) {
            warn!(error = %e, "obsidian synthesis: failed to write tmp note");
            return false;
        }
        if let Err(e) = std::fs::rename(&tmp, &note_path) {
            warn!(error = %e, "obsidian synthesis: failed to rename note");
            return false;
        }

        // Insert the synthesis fact into idx_groundtruth.
        let statement = format!(
            "[NEOTH-Synthesis {week_label}] {count} verified facts as of this week.",
            count = rows.len()
        );
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);
        if let Err(e) = groundtruth::insert(&conn, &statement, &Source::Synthesis, "meta", now_ns) {
            warn!(error = %e, "obsidian synthesis: groundtruth::insert failed (non-fatal)");
        }

        true
    })
    .await
    .unwrap_or(false);

    if written {
        // Persist the new week marker.
        if let Err(e) = std::fs::write(&week_marker, &this_week) {
            warn!(error = %e, "obsidian synthesis: failed to persist week marker");
        }
        info!(week = %this_week, "obsidian synthesis note written");
    }

    written
}

// ── Cron spawn ────────────────────────────────────────────────────────────────

/// Spawn the Obsidian vault reader+writer cron.
///
/// `interval = None` → [`DEFAULT_INTERVAL`] (6 hours).
/// Returns a `JoinHandle` for abort-on-shutdown (WAL-free; abort is safe at any
/// point — at worst one SHA-256 state map update is not persisted and the next
/// boot re-reads the file).
pub fn spawn(
    vault: PathBuf,
    home: PathBuf,
    interval: Option<Duration>,
) -> JoinHandle<Result<()>> {
    let interval = interval.unwrap_or(DEFAULT_INTERVAL);
    tokio::spawn(async move { run(vault, home, interval).await })
}

async fn run(vault: PathBuf, home: PathBuf, interval: Duration) -> Result<()> {
    info!(
        vault = %vault.display(),
        interval_secs = interval.as_secs(),
        "obsidian vault reader cron started"
    );
    let mut ticker = tokio::time::interval(interval);
    // Burn the first tick — fresh boot has nothing new to import yet.
    ticker.tick().await;
    loop {
        ticker.tick().await;
        run_tick(&vault, &home).await;
    }
}

async fn run_tick(vault: &Path, home: &Path) {
    // Reader pass.
    match run_one_reader_pass(vault, home).await {
        Ok((inserted, skipped)) if inserted > 0 || skipped > 0 => {
            info!(
                inserted,
                skipped,
                "obsidian vault reader: managed-note import pass complete"
            );
        }
        Ok(_) => {}
        Err(e) => warn!(error = %e, "obsidian vault reader: reader pass failed (will retry next tick)"),
    }

    // Writer pass (sync; blocking DB read + coalesced vault writes).
    let db_path = home.join("views.db");
    match run_one_writer_pass(vault, &db_path) {
        Ok((written, skipped)) if written > 0 || skipped > 0 => {
            info!(
                written,
                skipped_identical = skipped,
                "obsidian vault writer: fact-note sync complete"
            );
        }
        Ok(_) => {}
        Err(e) => warn!(error = %e, "obsidian vault writer: writer pass failed (will retry next tick)"),
    }

    // Weekly synthesis (Phase-1).
    run_synthesis_if_new_week(vault, home).await;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::FreedomConfig;
    use crate::memory::store;
    use tempfile::tempdir;

    fn write_managed_note(dir: &Path, name: &str, source_tag: &str, body: &str) {
        let content = format!(
            "---\nsource: {source_tag}\ntitle: {name}\n---\n\n{body}\n"
        );
        std::fs::write(dir.join(format!("{name}.md")), content).unwrap();
    }

    fn write_manual_note(dir: &Path, name: &str, body: &str) {
        std::fs::write(dir.join(format!("{name}.md")), format!("# {name}\n\n{body}\n"))
            .unwrap();
    }

    fn count_groundtruth_rows(db_path: &Path, source_str: &str) -> usize {
        let conn = store::open(db_path).expect("open views.db");
        conn.query_row(
            "SELECT COUNT(*) FROM idx_groundtruth \
             WHERE source_weight LIKE ?1 AND revoked_at IS NULL",
            rusqlite::params![format!("%{source_str}%")],
            |r| r.get::<_, usize>(0),
        )
        .unwrap_or(0)
    }

    // TEST 1: reader picks up a managed note on first pass.
    #[tokio::test]
    async fn reader_picks_up_managed_note_on_first_pass() {
        let vault_dir = tempdir().unwrap();
        let home_dir = tempdir().unwrap();
        // Init the DB.
        let _conn = store::open(&home_dir.path().join("views.db")).unwrap();

        write_managed_note(
            vault_dir.path(),
            "session-notes",
            "openclaw-session",
            "The operator uses Rust for all backend work.",
        );

        let (inserted, _skipped) =
            run_one_reader_pass(vault_dir.path(), home_dir.path())
                .await
                .unwrap();

        assert!(inserted >= 1, "expected at least 1 inserted fact; got {inserted}");

        let rows = count_groundtruth_rows(
            &home_dir.path().join("views.db"),
            "import:obsidian",
        );
        assert!(rows >= 1, "expected groundtruth rows with source import:obsidian; got {rows}");
    }

    // TEST 2: reader skips unchanged file on second pass (SHA-256 dedup).
    #[tokio::test]
    async fn reader_skips_unchanged_file_on_second_pass() {
        let vault_dir = tempdir().unwrap();
        let home_dir = tempdir().unwrap();
        let _conn = store::open(&home_dir.path().join("views.db")).unwrap();

        write_managed_note(
            vault_dir.path(),
            "notes",
            "neoth-groundtruth",
            "Operator prefers direct output.",
        );

        // First pass.
        let (first_inserted, _) =
            run_one_reader_pass(vault_dir.path(), home_dir.path())
                .await
                .unwrap();
        assert!(first_inserted >= 1, "first pass must insert");

        let rows_after_first =
            count_groundtruth_rows(&home_dir.path().join("views.db"), "import:obsidian");

        // Second pass — file unchanged.
        let (second_inserted, _) =
            run_one_reader_pass(vault_dir.path(), home_dir.path())
                .await
                .unwrap();
        assert_eq!(second_inserted, 0, "second pass must not re-insert unchanged file");

        let rows_after_second =
            count_groundtruth_rows(&home_dir.path().join("views.db"), "import:obsidian");
        assert_eq!(
            rows_after_first, rows_after_second,
            "row count must not grow on second pass for unchanged file"
        );
    }

    // TEST 3: reader skips manual (unmanaged) notes.
    #[tokio::test]
    async fn reader_skips_manual_note() {
        let vault_dir = tempdir().unwrap();
        let home_dir = tempdir().unwrap();
        let _conn = store::open(&home_dir.path().join("views.db")).unwrap();

        write_manual_note(vault_dir.path(), "manual", "This is a hand-written note.");

        let (inserted, _) =
            run_one_reader_pass(vault_dir.path(), home_dir.path())
                .await
                .unwrap();
        assert_eq!(inserted, 0, "manual notes must not be imported by vault reader");

        let rows = count_groundtruth_rows(&home_dir.path().join("views.db"), "import:obsidian");
        assert_eq!(rows, 0, "no groundtruth rows should be written for manual notes");
    }

    // TEST 4: spawn returns None for default config (no vault, reader disabled).
    #[test]
    fn spawn_returns_none_for_default_config() {
        let cfg = FreedomConfig::default();
        let handle = crate::cli::serve_tasks::spawn_obsidian_vault_reader(&cfg);
        assert!(
            handle.is_none(),
            "default FreedomConfig must not spawn vault reader (no vault + disabled)"
        );
    }
}
