//! GOLD-ADAPT-KB-03 — `neoth distill`
//!
//! Scans a hard-bounded newest-session corpus produced by HARNESS-02
//! (`~/.neoth/trajectories/<session_id>.jsonl`) for repeated tool-call
//! sequences and surfaces them as candidate skills to distill.
//!
//! A candidate is a contiguous tool-call sequence that appears in more than
//! three distinct session traces and has cross-session support above 0.8.
//! Counting distinct traces prevents one looping session from manufacturing a
//! high-confidence skill. The algorithm uses bounded n-grams; no suffix
//! automaton or new dependency is needed.
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
use std::path::{Path, PathBuf};

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

/// Parsed records from one trajectory file. File names are deliberately not
/// retained: candidate generation needs an independence boundary, not a raw
/// session identifier that could leak into proposals or WAL payloads.
#[derive(Debug, Clone)]
pub struct TrajectorySession {
    pub records: Vec<TurnRecord>,
}

/// A repeated sequence that passed the cross-session confidence gate.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DistillCandidate {
    pub sequence: Vec<String>,
    pub occurrences: usize,
    pub supporting_sessions: usize,
    pub eligible_sessions: usize,
    pub confidence: f64,
}

// ---------------------------------------------------------------------------
// Args
// ---------------------------------------------------------------------------

#[derive(Args, Debug, Clone)]
pub struct DistillArgs {
    /// Minimum number of distinct sessions containing a sequence.
    #[arg(long, default_value = "4")]
    pub min_occurrences: usize,

    /// Minimum sequence length (number of tool calls) to consider.
    #[arg(long, default_value = "2")]
    pub min_len: usize,

    /// Required cross-session support. The comparison is strict (`>`), so the
    /// default implements the roadmap's confidence > 0.8 contract.
    #[arg(long, default_value = "0.8")]
    pub min_confidence: f64,

    /// Emit JSON array instead of the default table.
    #[arg(long)]
    pub json: bool,
}

// ---------------------------------------------------------------------------
// Core logic — pure and unit-testable
// ---------------------------------------------------------------------------

/// Maximum n-gram length considered.  Keeps the count table bounded.
const MAX_NGRAM_LEN: usize = 6;

const MAX_TRAJECTORY_SESSIONS: usize = 512;
const MAX_TRAJECTORY_DIRECTORY_ENTRIES: usize = 4_096;
const MAX_TRAJECTORY_CORPUS_BYTES: u64 = 64 * 1024 * 1024;
const MAX_TRAJECTORY_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_TRAJECTORY_LINE_BYTES: usize = 256 * 1024;
const MAX_TRAJECTORY_RECORDS_PER_SESSION: usize = 4_096;
const MAX_TRAJECTORY_RECORDS_TOTAL: usize = 65_536;

#[derive(Clone, Copy)]
struct TrajectoryReadLimits {
    max_sessions: usize,
    max_directory_entries: usize,
    max_total_bytes: u64,
    max_file_bytes: u64,
    max_line_bytes: usize,
    max_records_per_session: usize,
    max_records_total: usize,
}

impl Default for TrajectoryReadLimits {
    fn default() -> Self {
        Self {
            max_sessions: MAX_TRAJECTORY_SESSIONS,
            max_directory_entries: MAX_TRAJECTORY_DIRECTORY_ENTRIES,
            max_total_bytes: MAX_TRAJECTORY_CORPUS_BYTES,
            max_file_bytes: MAX_TRAJECTORY_FILE_BYTES,
            max_line_bytes: MAX_TRAJECTORY_LINE_BYTES,
            max_records_per_session: MAX_TRAJECTORY_RECORDS_PER_SESSION,
            max_records_total: MAX_TRAJECTORY_RECORDS_TOTAL,
        }
    }
}

enum BoundedLine {
    Eof,
    Line(Vec<u8>),
    TooLong,
}

/// Consume one line without ever allocating more than `max_bytes`. Oversized
/// lines are drained through the newline and reported to the caller so the
/// entire trace can be rejected instead of partially trusted.
fn read_bounded_line<R: std::io::BufRead>(
    reader: &mut R,
    max_bytes: usize,
) -> std::io::Result<BoundedLine> {
    let mut line = Vec::new();
    let mut too_long = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return if line.is_empty() && !too_long {
                Ok(BoundedLine::Eof)
            } else if too_long {
                Ok(BoundedLine::TooLong)
            } else {
                Ok(BoundedLine::Line(line))
            };
        }

        let newline = available.iter().position(|byte| *byte == b'\n');
        let chunk_len = newline.unwrap_or(available.len());
        if !too_long {
            if line.len().saturating_add(chunk_len) > max_bytes {
                too_long = true;
                line.clear();
            } else {
                line.extend_from_slice(&available[..chunk_len]);
            }
        }
        let consumed = chunk_len + usize::from(newline.is_some());
        reader.consume(consumed);
        if newline.is_some() {
            return if too_long {
                Ok(BoundedLine::TooLong)
            } else {
                Ok(BoundedLine::Line(line))
            };
        }
    }
}

/// Read a bounded, newest-first set of `*.jsonl` files under `dir`, preserving
/// the file boundary as an independent session. Oversized, malformed, symlinked,
/// or partially unreadable traces are rejected as a whole. Missing/unreadable
/// directories return an empty vector and all hard-limit decisions are logged.
pub fn read_trajectory_sessions(dir: &Path) -> Vec<TrajectorySession> {
    read_trajectory_sessions_with_limits(dir, TrajectoryReadLimits::default())
}

fn read_trajectory_sessions_with_limits(
    dir: &Path,
    limits: TrajectoryReadLimits,
) -> Vec<TrajectorySession> {
    use std::cmp::Reverse;
    use std::collections::BinaryHeap;

    if limits.max_sessions == 0
        || limits.max_directory_entries == 0
        || limits.max_total_bytes == 0
        || limits.max_file_bytes == 0
        || limits.max_line_bytes == 0
        || limits.max_records_per_session == 0
        || limits.max_records_total == 0
    {
        return Vec::new();
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(error) => {
            tracing::warn!(
                error = %error,
                path = %dir.display(),
                "KB-03 trajectory directory cannot be read"
            );
            return Vec::new();
        }
    };

    // Keep only the newest N paths in memory even if the directory itself is
    // very large. `Reverse` makes the heap pop the oldest retained entry.
    let mut newest: BinaryHeap<Reverse<(std::time::SystemTime, PathBuf, u64)>> =
        BinaryHeap::with_capacity(limits.max_sessions.saturating_add(1));
    let mut jsonl_files_seen = 0usize;
    for (entry_index, entry) in entries.enumerate() {
        if entry_index == limits.max_directory_entries {
            tracing::warn!(
                max_directory_entries = limits.max_directory_entries,
                "KB-03 trajectory directory enumeration capped"
            );
            break;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                tracing::warn!(error = %error, "KB-03 trajectory directory entry unreadable");
                continue;
            }
        };
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("jsonl") {
            continue;
        }
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) => {
                tracing::warn!(error = %error, path = %path.display(), "KB-03 trajectory file type unreadable");
                continue;
            }
        };
        if !file_type.is_file() {
            tracing::warn!(path = %path.display(), "KB-03 non-regular trajectory ignored");
            continue;
        }
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(error) => {
                tracing::warn!(error = %error, path = %path.display(), "KB-03 trajectory metadata unreadable");
                continue;
            }
        };
        jsonl_files_seen = jsonl_files_seen.saturating_add(1);
        let modified = metadata.modified().unwrap_or(std::time::UNIX_EPOCH);
        newest.push(Reverse((modified, path, metadata.len())));
        if newest.len() > limits.max_sessions {
            newest.pop();
        }
    }
    if jsonl_files_seen > limits.max_sessions {
        tracing::warn!(
            files_seen = jsonl_files_seen,
            sessions_selected = limits.max_sessions,
            "KB-03 trajectory corpus capped to the newest sessions"
        );
    }

    let mut paths: Vec<_> = newest
        .into_iter()
        .map(|Reverse((modified, path, bytes))| (modified, path, bytes))
        .collect();
    paths.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));

    let mut sessions = Vec::new();
    let mut total_bytes = 0u64;
    let mut total_records = 0usize;
    for (_modified, path, file_bytes) in paths {
        if file_bytes > limits.max_file_bytes {
            tracing::warn!(
                path = %path.display(),
                file_bytes,
                max_file_bytes = limits.max_file_bytes,
                "KB-03 oversized trajectory rejected"
            );
            continue;
        }
        if total_bytes.saturating_add(file_bytes) > limits.max_total_bytes {
            tracing::warn!(
                path = %path.display(),
                file_bytes,
                max_total_bytes = limits.max_total_bytes,
                "KB-03 trajectory corpus byte budget reached; session rejected"
            );
            continue;
        }
        total_bytes += file_bytes;
        let file = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(error) => {
                tracing::warn!(error = %error, path = %path.display(), "KB-03 trajectory open failed");
                continue;
            }
        };
        let mut reader = std::io::BufReader::new(file);
        let mut records = Vec::new();
        let mut invalid = false;
        loop {
            let line = match read_bounded_line(&mut reader, limits.max_line_bytes) {
                Ok(BoundedLine::Eof) => break,
                Ok(BoundedLine::TooLong) => {
                    tracing::warn!(
                        path = %path.display(),
                        max_line_bytes = limits.max_line_bytes,
                        "KB-03 trajectory contains an oversized line; rejecting session"
                    );
                    invalid = true;
                    break;
                }
                Ok(BoundedLine::Line(line)) => line,
                Err(error) => {
                    tracing::warn!(error = %error, path = %path.display(), "KB-03 trajectory read failed; rejecting session");
                    invalid = true;
                    break;
                }
            };
            if line.iter().all(|byte| byte.is_ascii_whitespace()) {
                continue;
            }
            if records.len() == limits.max_records_per_session {
                tracing::warn!(
                    path = %path.display(),
                    max_records = limits.max_records_per_session,
                    "KB-03 trajectory record limit exceeded; rejecting session"
                );
                invalid = true;
                break;
            }
            match serde_json::from_slice::<TurnRecord>(&line) {
                Ok(rec) => records.push(rec),
                Err(error) => {
                    tracing::warn!(error = %error, path = %path.display(), "KB-03 malformed trajectory; rejecting session");
                    invalid = true;
                    break;
                }
            }
        }
        if invalid || records.is_empty() {
            continue;
        }
        if total_records.saturating_add(records.len()) > limits.max_records_total {
            tracing::warn!(
                path = %path.display(),
                max_total_records = limits.max_records_total,
                "KB-03 total trajectory record budget reached; remaining session rejected"
            );
            continue;
        }
        total_records += records.len();
        sessions.push(TrajectorySession { records });
    }
    sessions
}

/// Compatibility view used by existing callers and tests that only need a
/// flat record list.
pub fn read_trajectories(dir: &Path) -> Vec<TurnRecord> {
    read_trajectory_sessions(dir)
        .into_iter()
        .flat_map(|session| session.records)
        .collect()
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

    let cap = MAX_NGRAM_LEN;

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

/// Find candidate sequences with independent cross-session support.
///
/// A candidate must occur in at least `min_occurrences` distinct session
/// files and its supporting-session ratio must be strictly greater than
/// `min_confidence`. Total occurrences remain diagnostic only; they cannot
/// compensate for missing independent support.
pub fn find_distill_candidates(
    sessions: &[TrajectorySession],
    min_occurrences: usize,
    min_len: usize,
    min_confidence: f64,
) -> Vec<DistillCandidate> {
    use std::collections::HashMap;

    if min_len == 0
        || min_len > MAX_NGRAM_LEN
        || min_occurrences == 0
        || !min_confidence.is_finite()
        || !(0.0..=1.0).contains(&min_confidence)
    {
        return Vec::new();
    }

    let flattened: Vec<Vec<String>> = sessions
        .iter()
        .map(|session| {
            session
                .records
                .iter()
                .flat_map(|record| record.tool_calls.iter().cloned())
                .collect::<Vec<_>>()
        })
        .collect();
    // Confidence is support across every valid independent session in the
    // bounded corpus. A valid 0/1-call trace is a real non-supporting session,
    // not something to erase from the denominator merely because it cannot
    // contain this n-gram.
    let eligible_sessions = flattened.len();
    if eligible_sessions < min_occurrences {
        return Vec::new();
    }

    // (total occurrences, number of distinct sessions containing the n-gram)
    let mut totals: HashMap<Vec<String>, (usize, usize)> = HashMap::new();
    for calls in &flattened {
        if calls.len() < min_len {
            continue;
        }
        let mut local: HashMap<Vec<String>, usize> = HashMap::new();
        for len in min_len..=MAX_NGRAM_LEN.min(calls.len()) {
            for start in 0..=(calls.len() - len) {
                *local.entry(calls[start..start + len].to_vec()).or_default() += 1;
            }
        }
        for (sequence, occurrences) in local {
            let total = totals.entry(sequence).or_default();
            total.0 += occurrences;
            total.1 += 1;
        }
    }

    let mut candidates: Vec<_> = totals
        .into_iter()
        .filter_map(|(sequence, (occurrences, supporting_sessions))| {
            let confidence = supporting_sessions as f64 / eligible_sessions as f64;
            (supporting_sessions >= min_occurrences && confidence > min_confidence).then_some(
                DistillCandidate {
                    sequence,
                    occurrences,
                    supporting_sessions,
                    eligible_sessions,
                    confidence,
                },
            )
        })
        .collect();

    candidates.sort_by(|a, b| {
        b.confidence
            .total_cmp(&a.confidence)
            .then(b.supporting_sessions.cmp(&a.supporting_sessions))
            .then(b.occurrences.cmp(&a.occurrences))
            .then(b.sequence.len().cmp(&a.sequence.len()))
            .then(a.sequence.cmp(&b.sequence))
    });
    let mut non_redundant: Vec<DistillCandidate> = Vec::new();
    for candidate in candidates {
        let covered_by_longer = non_redundant.iter().any(|kept| {
            kept.supporting_sessions == candidate.supporting_sessions
                && kept.occurrences == candidate.occurrences
                && kept.sequence.len() > candidate.sequence.len()
                && kept
                    .sequence
                    .windows(candidate.sequence.len())
                    .any(|window| window == candidate.sequence.as_slice())
        });
        if !covered_by_longer {
            non_redundant.push(candidate);
        }
        if non_redundant.len() == 8 {
            break;
        }
    }
    non_redundant
}

// ---------------------------------------------------------------------------
// CLI entry point
// ---------------------------------------------------------------------------

/// Entry point called from the `Commands` dispatch match.
pub async fn run_distill(args: DistillArgs) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    let traj_dir = home.join("trajectories");

    anyhow::ensure!(
        args.min_occurrences > 3,
        "--min-occurrences must be greater than 3"
    );
    anyhow::ensure!(
        args.min_confidence.is_finite() && (0.0..1.0).contains(&args.min_confidence),
        "--min-confidence must be finite and between 0 and 1"
    );
    let sessions = read_trajectory_sessions(&traj_dir);
    let patterns = find_distill_candidates(
        &sessions,
        args.min_occurrences,
        args.min_len,
        args.min_confidence,
    );

    if args.json {
        let json =
            serde_json::to_string_pretty(&patterns).context("failed to serialize patterns")?;
        println!("{json}");
        return Ok(());
    }

    // Table output
    if patterns.is_empty() {
        println!(
            "No repeated tool-call sequences passed the gate (sessions>={}, confidence>{:.2}, min_len={}).",
            args.min_occurrences, args.min_confidence, args.min_len
        );
        return Ok(());
    }

    println!();
    println!(
        "  {:<12}  {:>8}  {:>10}  {:>3}  sequence",
        "occurrences", "sessions", "confidence", "len"
    );
    println!(
        "  {:-<12}  {:->8}  {:->10}  {:->3}  {}",
        "",
        "",
        "",
        "",
        "-".repeat(32)
    );

    for p in &patterns {
        let seq_str = p
            .sequence
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(" → ");
        println!(
            "  {:>12}  {:>3}/{:<4}  {:>9.1}%  {:>3}  {}",
            p.occurrences,
            p.supporting_sessions,
            p.eligible_sessions,
            p.confidence * 100.0,
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
            "    [{}] seen {}× across {}/{} sessions ({:.1}%) — candidate for operator review",
            seq_str,
            p.occurrences,
            p.supporting_sessions,
            p.eligible_sessions,
            p.confidence * 100.0,
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

    fn make_session(tools: &[&str]) -> TrajectorySession {
        TrajectorySession {
            records: vec![make_record(tools)],
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
        assert!(
            found,
            "expected [read_file, edit] with occurrences>=3, got: {patterns:?}"
        );
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
        let records: Vec<TurnRecord> = (0..5).map(|_| make_record(&["bash"])).collect();
        let patterns = find_repeated_sequences(&records, 3, 2);
        assert!(
            patterns.is_empty(),
            "single-label sequence should not appear when min_len=2"
        );
    }

    #[test]
    fn test_sorted_by_occurrences_desc() {
        // [a, b] appears 5×; [c, d] appears 3×.
        let mut records: Vec<TurnRecord> = (0..5).map(|_| make_record(&["a", "b"])).collect();
        records.extend((0..3).map(|_| make_record(&["c", "d"])));

        let patterns = find_repeated_sequences(&records, 3, 2);
        assert!(!patterns.is_empty());
        // First pattern must have the highest occurrence count.
        assert!(
            patterns[0].occurrences >= patterns.last().unwrap().occurrences,
            "patterns not sorted by occurrences desc"
        );
    }

    #[test]
    fn distill_candidate_requires_four_independent_sessions_and_gt_point_eight() {
        let sessions: Vec<_> = (0..5)
            .map(|_| make_session(&["read_file", "edit"]))
            .collect();
        let candidates = find_distill_candidates(&sessions, 4, 2, 0.8);
        let candidate = candidates
            .iter()
            .find(|candidate| candidate.sequence == ["read_file", "edit"])
            .expect("5/5 independent support must pass");
        assert_eq!(candidate.supporting_sessions, 5);
        assert_eq!(candidate.eligible_sessions, 5);
        assert_eq!(candidate.confidence, 1.0);

        let mut exact_boundary = sessions[..4].to_vec();
        exact_boundary.push(make_session(&["search", "summarize"]));
        assert!(
            find_distill_candidates(&exact_boundary, 4, 2, 0.8)
                .iter()
                .all(|candidate| candidate.sequence != ["read_file", "edit"]),
            "4/5 is exactly 0.8 and must not satisfy confidence > 0.8"
        );
    }

    #[test]
    fn one_looping_session_cannot_manufacture_a_candidate() {
        let session = make_session(&[
            "read_file",
            "edit",
            "read_file",
            "edit",
            "read_file",
            "edit",
            "read_file",
            "edit",
        ]);
        assert!(find_distill_candidates(&[session], 4, 2, 0.8).is_empty());
    }

    #[test]
    fn short_valid_sessions_remain_in_confidence_denominator() {
        let mut sessions: Vec<_> = (0..5)
            .map(|_| make_session(&["read_file", "edit"]))
            .collect();
        sessions.extend((0..5).map(|_| make_session(&["status"])));

        assert!(
            find_distill_candidates(&sessions, 4, 2, 0.8).is_empty(),
            "five supports among ten valid sessions are 0.5 confidence, not 5/5"
        );
    }

    #[test]
    fn exact_long_workflow_does_not_spawn_redundant_subsequence_candidates() {
        let sessions: Vec<_> = (0..5)
            .map(|_| make_session(&["read", "edit", "test"]))
            .collect();
        let candidates = find_distill_candidates(&sessions, 4, 2, 0.8);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].sequence, vec!["read", "edit", "test"]);
    }

    // ── read_trajectories ─────────────────────────────────────────────────

    #[test]
    fn malformed_trajectory_is_rejected_without_poisoning_other_sessions() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("session_bad.jsonl");
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
        writeln!(f, "{{this is not valid json}}").unwrap();
        writeln!(f, "{}", serde_json::to_string(&r2).unwrap()).unwrap();

        let mut valid = std::fs::File::create(dir.path().join("session_good.jsonl")).unwrap();
        writeln!(valid, "{}", serde_json::to_string(&r1).unwrap()).unwrap();
        writeln!(valid, "{}", serde_json::to_string(&r2).unwrap()).unwrap();

        let records = read_trajectories(dir.path());
        assert_eq!(
            records.len(),
            2,
            "the malformed file is rejected as a whole; only the valid session remains"
        );
        let sessions = read_trajectory_sessions(dir.path());
        assert_eq!(sessions.len(), 1);
    }

    #[test]
    fn trajectory_reader_enforces_line_record_and_total_limits() {
        let dir = TempDir::new().unwrap();
        let record = make_record(&["read", "edit"]);
        let json = serde_json::to_string(&record).unwrap();

        std::fs::write(dir.path().join("good.jsonl"), format!("{json}\n")).unwrap();
        std::fs::write(dir.path().join("oversized-line.jsonl"), "x".repeat(600)).unwrap();
        std::fs::write(
            dir.path().join("too-many-records.jsonl"),
            format!("{json}\n{json}\n{json}\n"),
        )
        .unwrap();

        let sessions = read_trajectory_sessions_with_limits(
            dir.path(),
            TrajectoryReadLimits {
                max_sessions: 10,
                max_directory_entries: 10,
                max_total_bytes: 4_096,
                max_file_bytes: 2_048,
                max_line_bytes: 512,
                max_records_per_session: 2,
                max_records_total: 1,
            },
        );
        assert_eq!(
            sessions.len(),
            1,
            "only the bounded valid trace is retained"
        );
        assert_eq!(sessions[0].records.len(), 1);
    }

    #[test]
    fn trajectory_reader_caps_the_session_corpus() {
        let dir = TempDir::new().unwrap();
        let json = serde_json::to_string(&make_record(&["read", "edit"])).unwrap();
        for index in 0..3 {
            std::fs::write(
                dir.path().join(format!("session-{index}.jsonl")),
                format!("{json}\n"),
            )
            .unwrap();
        }

        let sessions = read_trajectory_sessions_with_limits(
            dir.path(),
            TrajectoryReadLimits {
                max_sessions: 2,
                max_directory_entries: 10,
                max_total_bytes: 4_096,
                max_file_bytes: 2_048,
                max_line_bytes: 512,
                max_records_per_session: 2,
                max_records_total: 10,
            },
        );
        assert_eq!(sessions.len(), 2);
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
        assert!(
            records.is_empty(),
            "missing dir must return empty vec, not panic"
        );
    }
}
