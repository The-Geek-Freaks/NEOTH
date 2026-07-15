//! `neoth code-intel` — git-derived repo intelligence (REPOW-01/02/03).
//!
//! Enumerates tracked source files, computes per-file ownership + churn via
//! `git log`, ranks them by change-risk, and optionally surfaces hidden
//! structural coupling from the persisted code-map edge graph.
//!
//! All operations are read-only; no WAL frames, no mutations.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use clap::Args;

use crate::code_map::{co_change, graph::CallGraph, ownership, persist, risk};

/// Source-file extensions to include in the analysis pass.
/// Mirrors the set that NEOTH's code-map walker classifies as code.
const CODE_EXTENSIONS: &[&str] = &[
    "rs", "py", "js", "ts", "go", "java", "c", "cpp", "h", "hpp", "cs", "rb", "kt", "swift", "php",
];

/// Upper bound on files processed in one pass. Protects against monorepos
/// with tens of thousands of tracked files making the `git log` fan-out
/// unbearably slow.
const FILE_CAP: usize = 2_000;

#[derive(Args, Debug, Clone)]
pub struct CodeIntelArgs {
    /// Path to the git repository root. Defaults to the current directory.
    #[arg(long, default_value = ".")]
    pub repo: PathBuf,

    /// Show the top N riskiest files.
    #[arg(long, default_value = "15")]
    pub top: usize,

    /// Also compute hidden co-change coupling pairs (slower: requires git
    /// log of the full commit history). Reads `~/.neoth/code_map.db` for
    /// the call-graph edge set; if the DB is absent only commit-frequency
    /// coupling is suppressed by an empty graph.
    #[arg(long)]
    pub coupling: bool,
}

/// Entry point called from the `Commands` dispatch match.
pub async fn run_code_intel(args: CodeIntelArgs) -> Result<()> {
    let repo = args.repo.canonicalize().unwrap_or(args.repo.clone());

    // ── 1. Enumerate tracked source files ───────────────────────────────────
    let files = tracked_source_files(&repo)?;
    if files.is_empty() {
        println!("No tracked source files found in {}", repo.display());
        return Ok(());
    }
    let capped = files.len().min(FILE_CAP);
    if files.len() > FILE_CAP {
        println!(
            "  (capped to {FILE_CAP} of {} tracked source files for performance)",
            files.len()
        );
    }
    let files = &files[..capped];

    // ── 2. Ownership + churn per file ────────────────────────────────────────
    let mut triples: Vec<(String, ownership::FileOwnership, u32)> = Vec::with_capacity(files.len());
    for f in files {
        match ownership::file_ownership(&repo, f) {
            Ok(ow) => {
                let churn = ow.total_commits;
                triples.push((f.clone(), ow, churn));
            }
            Err(e) => {
                // Non-fatal: a file might have been deleted between ls-files
                // and the log query. Skip it silently.
                tracing::debug!("ownership error for {f}: {e}");
            }
        }
    }

    if triples.is_empty() {
        println!("No git history found for any tracked file (new repo or no commits yet).");
        return Ok(());
    }

    // ── 3. Rank by risk ──────────────────────────────────────────────────────
    let ranked = risk::rank_files(&triples);
    let top_n = args.top.min(ranked.len());

    // ── 4. Render risk table ─────────────────────────────────────────────────
    println!();
    println!("  Top {} riskiest files in {}", top_n, repo.display());
    println!();
    println!(
        "  {:<55}  {:>6}  {:>3}  {:<32}  {:>7}",
        "File", "Risk", "BF", "Primary owner", "Commits"
    );
    println!("  {}", "-".repeat(110));

    for risk_entry in ranked.iter().take(top_n) {
        // Look up the matching ownership record for display fields.
        let ow = triples
            .iter()
            .find(|(p, _, _)| p == &risk_entry.path)
            .map(|(_, o, _)| o);

        let bus_factor = ow.map(|o| o.bus_factor).unwrap_or(0);
        let primary = ow.map(|o| o.primary_owner.as_str()).unwrap_or("—");
        let commits = ow.map(|o| o.total_commits).unwrap_or(0);

        let bf_flag = if bus_factor == 1 { "⚠ " } else { "  " };
        // char-safe: a git author name can carry multibyte UTF-8 — a raw
        // `&primary[..29]` byte slice panics on a non-char-boundary cut.
        let primary_display = if primary.chars().count() > 30 {
            let head: String = primary.chars().take(29).collect();
            format!("{head}…")
        } else {
            primary.to_string()
        };

        println!(
            "  {:<55}  {:>6.3}  {}{:>1}  {:<32}  {:>7}",
            truncate_path(&risk_entry.path, 54),
            risk_entry.score,
            bf_flag,
            bus_factor,
            primary_display,
            commits,
        );
    }
    println!();
    println!("  BF = bus-factor  ⚠ = single-owner (bus_factor 1)");

    // ── 5. Optional: hidden coupling ─────────────────────────────────────────
    if args.coupling {
        println!();
        println!("  Computing hidden co-change coupling …");

        let graph = load_graph_from_db();
        match co_change::hidden_coupling(&repo, &graph, 3) {
            Ok(pairs) if pairs.is_empty() => {
                println!("  No hidden coupling pairs found (threshold: ≥3 co-changes).");
            }
            Ok(pairs) => {
                let show = pairs.len().min(20);
                println!();
                println!(
                    "  Top {} hidden coupling pairs (co-changed ≥3 times, no call edge):",
                    show
                );
                println!();
                println!("  {:<50}  {:<50}  {:>10}", "File A", "File B", "Co-changes");
                println!("  {}", "-".repeat(115));
                for p in pairs.iter().take(show) {
                    println!(
                        "  {:<50}  {:<50}  {:>10}",
                        truncate_path(&p.a, 49),
                        truncate_path(&p.b, 49),
                        p.co_changes
                    );
                }
                println!();
            }
            Err(e) => {
                println!("  Warning: co-change analysis failed: {e}");
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Return all git-tracked files under `repo` whose extension is in
/// `CODE_EXTENSIONS`. Paths are repo-relative (as returned by `git ls-files`).
fn tracked_source_files(repo: &Path) -> Result<Vec<String>> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["ls-files"])
        .output()
        .context("spawn git ls-files")?;

    if !out.status.success() || out.stdout.is_empty() {
        return Ok(vec![]);
    }

    let raw = String::from_utf8_lossy(&out.stdout);
    let files: Vec<String> = raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .filter(|l| is_code_file(l))
        .map(str::to_string)
        .collect();

    Ok(files)
}

/// Returns `true` when the file has a recognised source-code extension.
fn is_code_file(path: &str) -> bool {
    let ext = std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    CODE_EXTENSIONS.contains(&ext)
}

/// Open `~/.neoth/code_map.db` (if present), load all edges, and return a
/// `CallGraph`. Falls back to an empty graph on any error (missing DB is
/// not fatal for the coupling pass — it just means no edges are suppressed).
fn load_graph_from_db() -> CallGraph {
    let db_path = persist::default_path();
    if !db_path.exists() {
        println!(
            "  (code_map.db not found at {} — run `neoth code-map persist` to \
             build the call-graph; coupling pairs are shown without edge suppression)",
            db_path.display()
        );
        return CallGraph::from_edges(vec![]);
    }
    match persist::open(&db_path) {
        Ok(conn) => match persist::load_all_edges(&conn) {
            Ok(edges) => {
                let n = edges.len();
                println!("  (loaded {n} call-graph edges from {})", db_path.display());
                CallGraph::from_edges(edges)
            }
            Err(e) => {
                println!("  Warning: could not load edges from code_map.db: {e}");
                CallGraph::from_edges(vec![])
            }
        },
        Err(e) => {
            println!("  Warning: could not open code_map.db: {e}");
            CallGraph::from_edges(vec![])
        }
    }
}

/// Truncate a path string to `max_chars`, adding `…` when truncated.
fn truncate_path(path: &str, max_chars: usize) -> String {
    // char-safe: code-intel runs against arbitrary foreign repos, whose
    // paths can contain multibyte UTF-8 — count + slice on chars, not bytes,
    // so a cut at the boundary never panics ("byte index is not a char
    // boundary").
    let char_count = path.chars().count();
    if char_count <= max_chars {
        path.to_string()
    } else {
        let keep = max_chars.saturating_sub(1);
        let tail: String = path.chars().skip(char_count - keep).collect();
        format!("…{tail}")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_code_file_accepts_known_extensions() {
        assert!(is_code_file("src/main.rs"));
        assert!(is_code_file("lib/util.py"));
        assert!(is_code_file("index.js"));
        assert!(is_code_file("app.ts"));
        assert!(is_code_file("main.go"));
        assert!(is_code_file("Foo.java"));
        assert!(is_code_file("algo.c"));
        assert!(is_code_file("algo.cpp"));
        assert!(is_code_file("algo.h"));
        assert!(is_code_file("algo.hpp"));
    }

    #[test]
    fn is_code_file_rejects_non_code_extensions() {
        assert!(!is_code_file("README.md"));
        assert!(!is_code_file("Cargo.toml"));
        assert!(!is_code_file("freedom.yaml"));
        assert!(!is_code_file("icon.png"));
        assert!(!is_code_file("data.json"));
        assert!(!is_code_file("nosuffix"));
    }

    #[test]
    fn truncate_path_short_string_unchanged() {
        assert_eq!(truncate_path("src/foo.rs", 20), "src/foo.rs");
    }

    #[test]
    fn truncate_path_long_string_elided() {
        let long = "a/very/deep/path/to/some/file.rs";
        let t = truncate_path(long, 15);
        assert!(t.starts_with('…'), "expected leading ellipsis, got: {t}");
        // `…` is one char (3 UTF-8 bytes) → count chars, not bytes.
        assert_eq!(t.chars().count(), 15, "truncated char len mismatch: {t}");
    }

    #[test]
    fn truncate_path_exact_length_unchanged() {
        let s = "src/foo.rs"; // 10 chars
        assert_eq!(truncate_path(s, 10), s);
    }

    #[test]
    fn truncate_path_multibyte_does_not_panic() {
        // multibyte path — a byte slice at the cut would panic; char-safe must not.
        let p = "süß/möhre/straße/ünïcödé/datei.rs";
        let t = truncate_path(p, 10);
        assert!(t.starts_with('…'));
        assert_eq!(t.chars().count(), 10);
    }
}
