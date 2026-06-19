//! GOLD-ADAPT-KB-03 — `neoth distill`
//!
//! Scans session trajectory files produced by HARNESS-02
//! (`~/.neoth/trajectories/<session_id>.jsonl`) for repeated tool-call
//! sequences and surfaces them as candidate skills to distill.
//!
//! A "repeated sequence" is any contiguous sub-sequence of tool-call labels
//! (across turns) that appears at least `--min-occurrences` times (default 3)
//! and has length at least `--min-len` (default 2).  The algorithm uses a
//! simple n-gram count up to a small cap — no suffix automaton needed.
//!
//! Example output (table mode):
//! ```text
//!   occurrences  len  sequence
//!   -----------  ---  --------
//!            5    2   read_file → edit
//!            4    3   bash → read_file → edit
//!
//!   Candidate skill: ["read_file","edit"] seen 5× — consider `neoth skill --create`
//! ```

use std::io::BufRead as _;
use std::path::Path;

use anyhow::{Context, Result};
use clap::Args;
use serde::Serialize;

use crate::config::FreedomConfig;
use crate::mcp::harness::TurnRecord;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A contiguous tool-call sub-sequence that recurs across trajectory turns.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RepeatedPattern {
    pub sequence: Vec<String>,
    pub occurrences: usize,
}

// ---------------------------------------------------------------------------
// Args
// ---------------------------------------------------------------------------

#[derive(Args, Debug, Clone)]
pub struct DistillArgs {
    /// Minimum number of times a sequence must appear to be reported.
    #[arg(long, default_value = "3")]
    pub min_occurrences: usize,

    /// Minimum sequence length (number of tool calls) to consider.
    #[arg(long, default_value = "2")]
    pub min_len: usize,

    /// Emit JSON array instead of the default table.
    #[arg(long)]
    pub json: bool,
}

// ---------------------------------------------------------------------------
// Core logic — pure and unit-testable
// ---------------------------------------------------------------------------

/// Maximum n-gram length considered.  Keeps the count table bounded.
const MAX_NGRAM_LEN: usize = 6;

/// Read every `*.jsonl` file under `dir` and parse each line as a
/// [`TurnRecord`].  Malformed lines are skipped without panic.  Missing or
/// unreadable directory returns an empty vec.
pub fn read_trajectories(dir: &Path) -> Vec<TurnRecord> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    let mut records = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
            continue;
        }
        let file = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(_) => continue,
        };
        for line in std::io::BufReader::new(file).lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => continue,
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            match serde_json::from_str::<TurnRecord>(trimmed) {
                Ok(rec) => records.push(rec),
                Err(_) => { /* skip malformed */ }
            }
        }
    }
    records
}

/// Find contiguous sub-sequences of tool-call labels that recur
/// `>= min_occurrences` times across all `records`.  Only sequences of
/// length in `[min_len, MAX_NGRAM_LEN]` are examined.
///
/// Returns patterns sorted by (occurrences desc, sequence-length desc).
pub fn find_repeated_sequences(
    records: &[TurnRecord],
    min_occurrences: usize,
    min_len: usize,
) -> Vec<RepeatedPattern> {
    use std::collections::HashMap;

    let cap = MAX_NGRAM_LEN.max(min_len);

    // Flat list of tool-call labels per turn (turns that had no tool calls
    // contribute nothing to the sequence corpus).
    let sequences: Vec<Vec<String>> = records
        .iter()
        .filter(|r| !r.tool_calls.is_empty())
        .map(|r| r.tool_calls.clone())
        .collect();

    let mut counts: HashMap<Vec<String>, usize> = HashMap::new();

    for seq in &sequences {
        let n = seq.len();
        for len in min_len..=cap {
            if len > n {
                break;
            }
            for start in 0..=(n - len) {
                let ngram = seq[start..start + len].to_vec();
                *counts.entry(ngram).or_insert(0) += 1;
            }
        }
    }

    let mut patterns: Vec<RepeatedPattern> = counts
        .into_iter()
        .filter(|(_, count)| *count >= min_occurrences)
        .map(|(sequence, occurrences)| RepeatedPattern {
            sequence,
            occurrences,
        })
        .collect();

    // Sort: most frequent first, then longest first.
    patterns.sort_by(|a, b| {
        b.occurrences
            .cmp(&a.occurrences)
            .then(b.sequence.len().cmp(&a.sequence.len()))
    });

    patterns
}

// ---------------------------------------------------------------------------
// CLI entry point
// ---------------------------------------------------------------------------

/// Entry point called from the `Commands` dispatch match.
pub async fn run_distill(args: DistillArgs) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    let traj_dir = home.join("trajectories");

    let records = read_trajectories(&traj_dir);

    let patterns = find_repeated_sequences(
        &records,
        args.min_occurrences,
        args.min_len,
    );

    if args.json {
        let json = serde_json::to_string_pretty(&patterns)
            .context("failed to serialize patterns")?;
        println!("{json}");
        return Ok(());
    }

    // Table output
    if patterns.is_empty() {
        println!(
            "No repeated tool-call sequences found (min_occurrences={}, min_len={}).",
            args.min_occurrences, args.min_len
        );
        return Ok(());
    }

    println!();
    println!("  {:<12}  {:>3}  sequence", "occurrences", "len");
    println!("  {:-<12}  {:->3}  {}", "", "", "-".repeat(40));

    for p in &patterns {
        let seq_str = p
            .sequence
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(" → ");
        println!(
            "  {:>12}  {:>3}  {}",
            p.occurrences,
            p.sequence.len(),
            seq_str
        );
    }

    println!();
    println!("  Candidate skills:");
    for p in &patterns {
        let seq_str = p
            .sequence
            .iter()
            .map(|s| format!("{s:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "    [{}] seen {}× — consider `neoth skill --create`",
            seq_str, p.occurrences
        );
    }
    println!();

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use tempfile::TempDir;

    fn make_record(tools: &[&str]) -> TurnRecord {
        TurnRecord {
            turn: 1,
            prompt_hash: "aabbccdd11223344".to_string(),
            prompt_len: 42,
            tool_calls: tools.iter().map(|s| s.to_string()).collect(),
            verdict: "tool_calls".to_string(),
            ts_unix: 0,
        }
    }

    // ── find_repeated_sequences ───────────────────────────────────────────

    #[test]
    fn test_sequence_above_threshold_returned() {
        // [read_file, edit] appears 4 times → must be returned (min=3)
        let records: Vec<TurnRecord> = (0..4)
            .map(|_| make_record(&["read_file", "edit"]))
            .collect();
        let patterns = find_repeated_sequences(&records, 3, 2);
        let found = patterns
            .iter()
            .any(|p| p.sequence == vec!["read_file", "edit"] && p.occurrences >= 3);
        assert!(found, "expected [read_file, edit] with occurrences>=3, got: {patterns:?}");
    }

    #[test]
    fn test_sequence_below_threshold_not_returned() {
        // [read_file, edit] appears only 2 times — must NOT be returned (min=3)
        let records: Vec<TurnRecord> = (0..2)
            .map(|_| make_record(&["read_file", "edit"]))
            .collect();
        let patterns = find_repeated_sequences(&records, 3, 2);
        let found = patterns
            .iter()
            .any(|p| p.sequence == vec!["read_file", "edit"]);
        assert!(!found, "should NOT report sequence appearing only 2 times");
    }

    #[test]
    fn test_empty_records_returns_empty() {
        let patterns = find_repeated_sequences(&[], 3, 2);
        assert!(patterns.is_empty());
    }

    #[test]
    fn test_single_tool_call_below_min_len() {
        // Single-element sequence, min_len=2 → should not appear
        let records: Vec<TurnRecord> = (0..5)
            .map(|_| make_record(&["bash"]))
            .collect();
        let patterns = find_repeated_sequences(&records, 3, 2);
        assert!(
            patterns.is_empty(),
            "single-label sequence should not appear when min_len=2"
        );
    }

    #[test]
    fn test_sorted_by_occurrences_desc() {
        // [a, b] appears 5×; [c, d] appears 3×.
        let mut records: Vec<TurnRecord> = (0..5)
            .map(|_| make_record(&["a", "b"]))
            .collect();
        records.extend((0..3).map(|_| make_record(&["c", "d"])));

        let patterns = find_repeated_sequences(&records, 3, 2);
        assert!(!patterns.is_empty());
        // First pattern must have the highest occurrence count.
        assert!(
            patterns[0].occurrences >= patterns.last().unwrap().occurrences,
            "patterns not sorted by occurrences desc"
        );
    }

    // ── read_trajectories ─────────────────────────────────────────────────

    #[test]
    fn test_read_trajectories_valid_and_malformed() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("session_abc.jsonl");
        let mut f = std::fs::File::create(&file_path).unwrap();

        // Two valid records.
        let r1 = TurnRecord {
            turn: 1,
            prompt_hash: "aabb".to_string(),
            prompt_len: 10,
            tool_calls: vec!["read_file".to_string()],
            verdict: "tool_calls".to_string(),
            ts_unix: 1000,
        };
        let r2 = TurnRecord {
            turn: 2,
            prompt_hash: "ccdd".to_string(),
            prompt_len: 20,
            tool_calls: vec!["edit".to_string()],
            verdict: "tool_calls".to_string(),
            ts_unix: 2000,
        };
        writeln!(f, "{}", serde_json::to_string(&r1).unwrap()).unwrap();
        writeln!(f, "{{this is not valid json}}").unwrap(); // malformed
        writeln!(f, "{}", serde_json::to_string(&r2).unwrap()).unwrap();

        let records = read_trajectories(dir.path());
        assert_eq!(records.len(), 2, "expected 2 valid records, malformed line skipped");
    }

    #[test]
    fn test_read_trajectories_empty_dir() {
        let dir = TempDir::new().unwrap();
        let records = read_trajectories(dir.path());
        assert!(records.is_empty(), "empty dir must return empty vec");
    }

    #[test]
    fn test_read_trajectories_missing_dir() {
        let records = read_trajectories(Path::new("/nonexistent/path/trajectories"));
        assert!(records.is_empty(), "missing dir must return empty vec, not panic");
    }
}
