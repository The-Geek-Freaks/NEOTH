//! SC-02 — named checkpoints over the shipped `PRE_MUTATION_SNAPSHOT` (0xF2)
//! rollback primitive.
//!
//! `neoth rollback` already captures + restores pre-mutation state, but
//! addresses snapshots by raw `(segment, offset)`. SC-02 adds an operator-
//! friendly NAME: `neoth checkpoint save <label>` tags the most recent 0xF2
//! snapshot with a validated label in a sidecar index, and
//! `neoth checkpoint restore <label>` resolves the name back to its
//! `(segment, offset)` and delegates to the existing rollback `apply` path —
//! no new restore logic, no new WAL event (the snapshot IS the 0xF2 frame; the
//! label is metadata).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;

/// Max label length (the strict-regex bound `…{0,63}` after the first char ⇒ 64).
const MAX_LABEL_LEN: usize = 64;

#[derive(Args, Debug, Clone)]
pub struct CheckpointArgs {
    #[command(subcommand)]
    pub action: CheckpointAction,
    /// Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum CheckpointAction {
    /// Tag the most recent pre-mutation snapshot with a name. The snapshot must
    /// already exist (run a mutation first, e.g. `neoth config set`).
    Save {
        /// Checkpoint label: `[A-Za-z0-9_-][A-Za-z0-9_.-]{0,63}`.
        label: String,
        /// Optional human description.
        #[arg(long)]
        description: Option<String>,
        /// Overwrite an existing checkpoint with the same label.
        #[arg(long)]
        force: bool,
    },
    /// List saved checkpoints.
    List,
    /// Restore the state captured by a named checkpoint (delegates to the
    /// rollback `apply` path with `--confirm`).
    Restore {
        /// Checkpoint label saved via `neoth checkpoint save`.
        label: String,
    },
}

/// Why a checkpoint label was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointError {
    Empty,
    TooLong,
    InvalidChar { pos: usize, ch: char },
}

impl std::fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckpointError::Empty => write!(f, "checkpoint label must not be empty"),
            CheckpointError::TooLong => {
                write!(f, "checkpoint label too long (max {MAX_LABEL_LEN} chars)")
            }
            CheckpointError::InvalidChar { pos, ch } => write!(
                f,
                "invalid character {ch:?} at position {pos} — labels are \
                 [A-Za-z0-9_-] then [A-Za-z0-9_.-] (no spaces, slashes, or a leading dot)"
            ),
        }
    }
}

/// Validate a checkpoint label against the strict path-safe regex
/// `[A-Za-z0-9_-][A-Za-z0-9_.-]{0,63}`. The leading-char restriction (no `.`)
/// prevents `.`/`..`-style traversal labels; no `/`/`\\`/space anywhere.
pub fn validate_checkpoint_label(label: &str) -> std::result::Result<(), CheckpointError> {
    if label.is_empty() {
        return Err(CheckpointError::Empty);
    }
    if label.len() > MAX_LABEL_LEN {
        return Err(CheckpointError::TooLong);
    }
    let mut chars = label.chars();
    let first = chars.next().expect("non-empty checked above");
    if !first.is_ascii_alphanumeric() && first != '_' && first != '-' {
        return Err(CheckpointError::InvalidChar { pos: 0, ch: first });
    }
    for (i, ch) in chars.enumerate() {
        if !ch.is_ascii_alphanumeric() && ch != '_' && ch != '.' && ch != '-' {
            return Err(CheckpointError::InvalidChar { pos: i + 1, ch });
        }
    }
    Ok(())
}

/// One named checkpoint: the validated label + the `(segment, offset)` of the
/// 0xF2 snapshot it tags + metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CheckpointEntry {
    pub label: String,
    pub segment: String,
    pub offset: u64,
    pub ts_unix: u64,
    #[serde(default)]
    pub description: Option<String>,
}

fn index_path(home: &Path) -> PathBuf {
    home.join("checkpoints").join("index.json")
}

/// Load the checkpoint index (empty when absent). A corrupt index is a hard
/// error — silently dropping it would lose an operator's named restore points.
fn load_index(home: &Path) -> Result<Vec<CheckpointEntry>> {
    let path = index_path(home);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
}

/// Atomically and durably write the private checkpoint index so a crash
/// mid-write never leaves a half-written index.
fn save_index(home: &Path, entries: &[CheckpointEntry]) -> Result<()> {
    let path = index_path(home);
    let body = serde_json::to_vec_pretty(entries).context("serialise checkpoint index")?;
    crate::util::atomic_write::atomic_write_private(&path, &body)
        .with_context(|| format!("atomically write {}", path.display()))?;
    Ok(())
}

/// Find the `(segment, offset)` of the MOST RECENT `PRE_MUTATION_SNAPSHOT`
/// (0xF2) frame across all WAL segments, or `None` if none exist. Tolerant of
/// torn tails. The offset is the frame's start position — exactly what
/// `rollback apply --to` expects.
fn find_latest_snapshot(wal_dir: &Path) -> Result<Option<(PathBuf, u64)>> {
    use crate::wal::events::EVENT_TYPE_PRE_MUTATION_SNAPSHOT;

    if !wal_dir.exists() {
        return Ok(None);
    }
    let entries = std::fs::read_dir(wal_dir)
        .with_context(|| format!("read WAL directory {}", wal_dir.display()))?
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| format!("enumerate WAL directory {}", wal_dir.display()))?;
    let mut segments: Vec<PathBuf> = entries
        .into_iter()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("wal"))
        .collect();
    segments.sort();

    let mut latest = None;
    for seg in &segments {
        let bytes = std::fs::read(seg)
            .with_context(|| format!("read checkpoint WAL segment {}", seg.display()))?;
        // GOLD-ARCH-03: for_each_frame so a PRE_MUTATION_SNAPSHOT inside a
        // v2/zstd-compressed segment is found, not silently skipped. `cursor` is
        // the frame's logical offset.
        crate::wal::scan::for_each_frame(&bytes, |cursor, dec| {
            if dec.header.event_type == EVENT_TYPE_PRE_MUTATION_SNAPSHOT {
                latest = Some((seg.clone(), cursor as u64));
            }
            Ok(())
        })
        .with_context(|| format!("scan checkpoint WAL segment {}", seg.display()))?;
    }
    Ok(latest)
}

pub async fn run_checkpoint(args: CheckpointArgs) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    match args.action {
        CheckpointAction::Save {
            label,
            description,
            force,
        } => run_save(&home, &label, description, force, args.output),
        CheckpointAction::List => run_list(&home, args.output),
        CheckpointAction::Restore { label } => run_restore(&home, &label, args.output).await,
    }
}

fn run_save(
    home: &Path,
    label: &str,
    description: Option<String>,
    force: bool,
    output: OutputFormat,
) -> Result<()> {
    validate_checkpoint_label(label).map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut index = load_index(home)?;
    if index.iter().any(|e| e.label == label) && !force {
        anyhow::bail!(
            "checkpoint '{label}' already exists — pass --force to overwrite, or pick another name"
        );
    }

    let wal_dir = FreedomConfig::default_wal_dir();
    let (segment, offset) = find_latest_snapshot(&wal_dir)?.context(
        "no PRE_MUTATION_SNAPSHOT (0xF2) frame found — run a mutation first \
         (e.g. `neoth config set ...`) to create one, then checkpoint it",
    )?;
    let ts_unix = crate::time::now_unix_secs();

    index.retain(|e| e.label != label); // force-overwrite drops the old entry
    let entry = CheckpointEntry {
        label: label.to_string(),
        segment: segment.display().to_string(),
        offset,
        ts_unix,
        description,
    };
    index.push(entry.clone());
    save_index(home, &index)?;

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string(&entry)?);
        }
        OutputFormat::Table => {
            println!("✓ checkpoint '{label}' saved (snapshot at offset {offset})");
        }
    }
    Ok(())
}

fn run_list(home: &Path, output: OutputFormat) -> Result<()> {
    let index = load_index(home)?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string_pretty(&index)?);
        }
        OutputFormat::Table => {
            if index.is_empty() {
                println!("(no checkpoints — `neoth checkpoint save <label>` after a mutation)");
                return Ok(());
            }
            for e in &index {
                let desc = e
                    .description
                    .as_deref()
                    .map(|d| format!("  — {d}"))
                    .unwrap_or_default();
                println!("{}  (offset {}){}", e.label, e.offset, desc);
            }
        }
    }
    Ok(())
}

async fn run_restore(home: &Path, label: &str, output: OutputFormat) -> Result<()> {
    validate_checkpoint_label(label).map_err(|e| anyhow::anyhow!("{e}"))?;
    let index = load_index(home)?;
    let entry = index
        .iter()
        .find(|e| e.label == label)
        .with_context(|| format!("no checkpoint named '{label}' — `neoth checkpoint list`"))?;

    // Delegate to the existing rollback apply path — no new restore logic.
    let rb = crate::cli::rollback::RollbackArgs {
        action: crate::cli::rollback::RollbackAction::Apply {
            to: entry.offset,
            segment: PathBuf::from(&entry.segment),
            confirm: true,
        },
        output,
    };
    crate::cli::rollback::run_rollback(rb)
        .await
        .with_context(|| format!("restore checkpoint '{label}'"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_label_accepts_valid_labels() {
        for ok in ["a", "v1", "my-checkpoint", "pre_deploy.2026", "X-_.9", "Z"] {
            assert!(
                validate_checkpoint_label(ok).is_ok(),
                "{ok} should be valid"
            );
        }
    }

    #[test]
    fn validate_label_rejects_empty() {
        assert_eq!(validate_checkpoint_label(""), Err(CheckpointError::Empty));
    }

    #[test]
    fn validate_label_rejects_too_long() {
        let long = "a".repeat(65);
        assert_eq!(
            validate_checkpoint_label(&long),
            Err(CheckpointError::TooLong)
        );
        // Exactly 64 is allowed.
        assert!(validate_checkpoint_label(&"a".repeat(64)).is_ok());
    }

    #[test]
    fn validate_label_rejects_dot_at_start() {
        assert_eq!(
            validate_checkpoint_label(".hidden"),
            Err(CheckpointError::InvalidChar { pos: 0, ch: '.' })
        );
        // A traversal attempt is rejected at the leading dot.
        assert!(matches!(
            validate_checkpoint_label("../etc"),
            Err(CheckpointError::InvalidChar { pos: 0, .. })
        ));
    }

    #[test]
    fn validate_label_rejects_slash_and_space() {
        assert_eq!(
            validate_checkpoint_label("foo/bar"),
            Err(CheckpointError::InvalidChar { pos: 3, ch: '/' })
        );
        assert_eq!(
            validate_checkpoint_label("my label"),
            Err(CheckpointError::InvalidChar { pos: 2, ch: ' ' })
        );
        assert!(matches!(
            validate_checkpoint_label("a\\b"),
            Err(CheckpointError::InvalidChar { ch: '\\', .. })
        ));
    }

    fn entry(label: &str) -> CheckpointEntry {
        CheckpointEntry {
            label: label.to_string(),
            segment: "000001.wal".to_string(),
            offset: 42,
            ts_unix: 1000,
            description: None,
        }
    }

    #[test]
    fn index_save_and_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let entries = vec![entry("a"), entry("b")];
        save_index(dir.path(), &entries).unwrap();
        let loaded = load_index(dir.path()).unwrap();
        assert_eq!(loaded, entries);
    }

    #[test]
    fn load_index_absent_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_index(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn save_index_is_atomic_no_tmp_leak() {
        let dir = tempfile::tempdir().unwrap();
        save_index(dir.path(), &[entry("a")]).unwrap();
        assert!(
            !std::fs::read_dir(dir.path().join("checkpoints"))
                .unwrap()
                .any(|entry| entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp"))
        );
        assert!(index_path(dir.path()).exists());
    }

    #[test]
    fn list_rejects_corrupt_index_instead_of_reporting_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = index_path(dir.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"{not json").unwrap();
        let error = run_list(dir.path(), OutputFormat::Table).unwrap_err();
        assert!(error.to_string().contains("parse"), "got: {error:#}");
        assert_eq!(std::fs::read(path).unwrap(), b"{not json");
    }

    #[test]
    fn find_latest_snapshot_none_for_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        assert!(find_latest_snapshot(dir.path()).unwrap().is_none());
    }

    #[tokio::test]
    async fn find_latest_snapshot_picks_the_last_0xf2_frame() {
        use crate::wal::events::{EVENT_TYPE_PRE_MUTATION_SNAPSHOT, EVENT_TYPE_RAW_TEXT};
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (writer, join) = crate::wal::writer::spawn(seg.clone()).unwrap();
        // A non-snapshot, then two snapshots — the LAST one wins.
        for et in [
            EVENT_TYPE_RAW_TEXT,
            EVENT_TYPE_PRE_MUTATION_SNAPSHOT,
            EVENT_TYPE_PRE_MUTATION_SNAPSHOT,
        ] {
            let payload = b"{}".to_vec();
            let header = crate::wal::HeaderBuilder::new(et, &payload).build();
            writer.append(header, payload).await.unwrap();
        }
        drop(writer);
        join.await.ok();

        let (found_seg, off) = find_latest_snapshot(dir.path())
            .unwrap()
            .expect("a 0xF2 frame exists");
        assert_eq!(found_seg, seg);
        // The offset must point at a real 0xF2 frame (the LAST one).
        let bytes = std::fs::read(&seg).unwrap();
        let dec = crate::wal::frame::decode_frame(&bytes[off as usize..]).unwrap();
        assert_eq!(dec.header.event_type, EVENT_TYPE_PRE_MUTATION_SNAPSHOT);
    }
}
