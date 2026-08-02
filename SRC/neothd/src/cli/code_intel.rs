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
const EDGE_CAP: usize = 250_000;
const EDGE_TEXT_BYTE_CAP: usize = 32 * 1024 * 1024;

#[derive(Args, Debug, Clone)]
pub struct CodeIntelArgs {
    /// Path to the git repository root. Defaults to the current directory.
    #[arg(long, default_value = ".")]
    pub repo: PathBuf,

    /// Show the top N riskiest files.
    #[arg(long, default_value = "15")]
    pub top: usize,

    /// Also compute hidden co-change coupling pairs (slower: requires git
    /// log of the full commit history). Requires a fresh, complete, certified
    /// call-graph snapshot for this exact physical repository root.
    #[arg(long)]
    pub coupling: bool,
}

/// Entry point called from the `Commands` dispatch match.
pub async fn run_code_intel(args: CodeIntelArgs) -> Result<()> {
    let repo = args
        .repo
        .canonicalize()
        .with_context(|| format!("canonicalize repository {}", args.repo.display()))?;

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

        let graph = load_graph_from_db(&repo)
            .context("load certified call graph for hidden-coupling analysis")?;
        let pairs = co_change::hidden_coupling(&repo, &graph, 3)
            .context("compute hidden coupling from git history and certified call graph")?;
        if pairs.is_empty() {
            println!("  No hidden coupling pairs found (threshold: ≥3 co-changes).");
        } else {
            let show = pairs.len().min(20);
            println!();
            println!("  Top {show} hidden coupling pairs (co-changed ≥3 times, no call edge):");
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

/// One root-scoped graph read with the generation metadata operators need to
/// decide whether the persisted snapshot is the one they expected.
enum RootGraphLoad {
    Loaded {
        graph: CallGraph,
        root: String,
        index_generation: i64,
        graph_generation: i64,
    },
    Unavailable {
        message: String,
    },
}

/// Open `~/.neoth/code_map.db` (if present), resolve the physical repository
/// selected by `repo`, and load only that root's certified edge set. An
/// unavailable or unverifiable graph is an explicit error: treating it as an
/// empty graph would falsely label co-change pairs as having no call edge.
fn load_graph_from_db(repo: &Path) -> Result<CallGraph> {
    let db_path = persist::default_path();
    match load_root_graph_from_path(repo, &db_path) {
        RootGraphLoad::Loaded {
            graph,
            root,
            index_generation,
            graph_generation,
        } => {
            println!(
                "  (loaded {} call-graph edges for root {}; index generation {}, graph generation {})",
                graph.edges().len(),
                root,
                index_generation,
                graph_generation
            );
            Ok(graph)
        }
        RootGraphLoad::Unavailable { message } => anyhow::bail!(message),
    }
}

fn load_root_graph_from_path(repo: &Path, db_path: &Path) -> RootGraphLoad {
    load_root_graph_from_path_with_hook(repo, db_path, || {})
}

fn load_root_graph_from_path_with_hook<F>(
    repo: &Path,
    db_path: &Path,
    before_recheck: F,
) -> RootGraphLoad
where
    F: FnOnce(),
{
    match db_path.try_exists() {
        Ok(true) => {}
        Ok(false) => {
            return RootGraphLoad::Unavailable {
                message: format!(
                    "code_map.db not found at {} — run `neoth code-map persist` in {}; \
                     hidden-coupling analysis is unavailable",
                    db_path.display(),
                    repo.display()
                ),
            };
        }
        Err(error) => {
            return RootGraphLoad::Unavailable {
                message: format!(
                    "could not inspect code_map.db at {}: {error}; hidden-coupling analysis refused",
                    db_path.display()
                ),
            };
        }
    }

    let conn = match persist::open(db_path) {
        Ok(conn) => conn,
        Err(error) => {
            return RootGraphLoad::Unavailable {
                message: format!("Warning: could not open code_map.db: {error}"),
            };
        }
    };
    let initial = match crate::code_map::resolve_active_root_snapshot(&conn, repo) {
        Ok(Some(snapshot)) => snapshot,
        Ok(None) => {
            return RootGraphLoad::Unavailable {
                message: format!(
                    "Warning: code_map.db has no physical root mapping for {}; run \
                     `neoth code-map persist` there; hidden-coupling analysis refused",
                    repo.display()
                ),
            };
        }
        Err(error) => {
            return RootGraphLoad::Unavailable {
                message: format!(
                    "Warning: could not verify the code-map root for {}: {error}; \
                     hidden-coupling analysis refused",
                    repo.display()
                ),
            };
        }
    };

    if initial.index_generation <= 0
        || initial.graph_generation <= 0
        || initial.index_generation != initial.graph_generation
    {
        return RootGraphLoad::Unavailable {
            message: format!(
                "Warning: code-map graph for root {} is not a current certified snapshot \
                 (index generation {}, graph generation {}); run `neoth code-map persist`; \
                 hidden-coupling analysis refused",
                initial.root.display(),
                initial.index_generation,
                initial.graph_generation
            ),
        };
    }
    match persist::root_snapshot_complete(&conn, initial.root.display()) {
        Ok(true) => {}
        Ok(false) => {
            return RootGraphLoad::Unavailable {
                message: format!(
                    "Warning: code-map graph for root {} came from a partial scan; run \
                     `neoth code-map persist` without explicit limits; hidden-coupling analysis refused",
                    initial.root.display()
                ),
            };
        }
        Err(error) => {
            return RootGraphLoad::Unavailable {
                message: format!(
                    "Warning: could not verify code-map completeness for root {}: {error}; \
                     hidden-coupling analysis refused",
                    initial.root.display()
                ),
            };
        }
    }

    let initial_freshness = match persist::index_freshness_receipt(&conn, initial.root.display()) {
        Ok(freshness) => freshness,
        Err(error) => {
            return RootGraphLoad::Unavailable {
                message: format!(
                    "Warning: could not verify filesystem freshness for root {}: {error}; \
                     hidden-coupling analysis refused",
                    initial.root.display()
                ),
            };
        }
    };
    if initial_freshness.stale {
        return RootGraphLoad::Unavailable {
            message: format!(
                "Warning: code-map graph for root {} is stale against the repository; run \
                 `neoth code-map persist`; hidden-coupling analysis refused",
                initial.root.display()
            ),
        };
    }

    let edges = match persist::load_edges_for_root_bounded_with_text_limit(
        &conn,
        initial.root.display(),
        EDGE_CAP,
        EDGE_TEXT_BYTE_CAP,
    ) {
        Ok((edges, false, _)) => edges,
        Ok((_edges, true, bytes)) => {
            return RootGraphLoad::Unavailable {
                message: format!(
                    "Warning: code-map graph for root {} exceeds the bounded coupling read \
                     (more than {EDGE_CAP} edges or {EDGE_TEXT_BYTE_CAP} text bytes; \
                     observed {bytes} bytes); hidden-coupling analysis refused",
                    initial.root.display()
                ),
            };
        }
        Err(error) => {
            return RootGraphLoad::Unavailable {
                message: format!(
                    "Warning: could not load call-graph edges for root {} at index generation {} \
                     / graph generation {}: {error}; hidden-coupling analysis refused",
                    initial.root.display(),
                    initial.index_generation,
                    initial.graph_generation
                ),
            };
        }
    };

    before_recheck();
    let final_freshness = match persist::index_freshness_receipt(&conn, initial.root.display()) {
        Ok(freshness) => freshness,
        Err(error) => {
            return RootGraphLoad::Unavailable {
                message: format!(
                    "Warning: could not re-verify filesystem freshness for root {}: {error}; \
                     hidden-coupling analysis refused",
                    initial.root.display()
                ),
            };
        }
    };
    if final_freshness.stale
        || final_freshness.filesystem_fingerprint != initial_freshness.filesystem_fingerprint
    {
        return RootGraphLoad::Unavailable {
            message: format!(
                "Warning: repository {} changed while its call graph was read; hidden-coupling \
                 analysis refused",
                initial.root.display()
            ),
        };
    }
    let final_snapshot = match crate::code_map::resolve_active_root_snapshot(&conn, repo) {
        Ok(Some(snapshot)) => snapshot,
        Ok(None) => {
            return RootGraphLoad::Unavailable {
                message: format!(
                    "Warning: code-map root mapping for {} disappeared while edges were read; \
                     hidden-coupling analysis refused",
                    repo.display()
                ),
            };
        }
        Err(error) => {
            return RootGraphLoad::Unavailable {
                message: format!(
                    "Warning: could not re-verify the code-map root for {} after reading edges: \
                     {error}; hidden-coupling analysis refused",
                    repo.display()
                ),
            };
        }
    };

    if final_snapshot.root != initial.root
        || final_snapshot.index_generation != initial.index_generation
        || final_snapshot.graph_generation != initial.graph_generation
    {
        return RootGraphLoad::Unavailable {
            message: format!(
                "Warning: code-map root or generation changed while reading edges for {} \
                 (started at index generation {}, graph generation {}); retry after the writer \
                 finishes; hidden-coupling analysis refused",
                initial.root.display(),
                initial.index_generation,
                initial.graph_generation
            ),
        };
    }

    RootGraphLoad::Loaded {
        graph: CallGraph::from_edges(edges),
        root: initial.root.display().to_owned(),
        index_generation: initial.index_generation,
        graph_generation: initial.graph_generation,
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
    use crate::code_map::graph::{CodeEdge, EdgeKind};
    use crate::code_map::{RepoMap, ScanReport};
    use tempfile::tempdir;

    fn empty_map(root: &Path) -> RepoMap {
        RepoMap {
            root: crate::code_map::CanonicalRepoRoot::discover(root)
                .unwrap()
                .display()
                .to_owned(),
            files: vec![],
            report: ScanReport::default(),
        }
    }

    fn edge(target: &str) -> CodeEdge {
        CodeEdge {
            from_file: "src/shared.rs".into(),
            from_symbol: "same_caller".into(),
            to_name: target.into(),
            kind: EdgeKind::Calls,
        }
    }

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

    #[test]
    fn coupling_graph_load_is_scoped_to_the_selected_physical_root() {
        let temp = tempdir().unwrap();
        let repo_a = temp.path().join("repo-a");
        let repo_b = temp.path().join("repo-b");
        std::fs::create_dir_all(&repo_a).unwrap();
        std::fs::create_dir_all(&repo_b).unwrap();
        let db_path = temp.path().join("code_map.db");
        let mut conn = persist::open(&db_path).unwrap();
        let map_a = empty_map(&repo_a);
        let map_b = empty_map(&repo_b);
        persist::persist_map_and_edges(&mut conn, &map_a, &[edge("only_a")]).unwrap();
        persist::persist_map_and_edges(&mut conn, &map_b, &[edge("only_b")]).unwrap();
        drop(conn);

        let RootGraphLoad::Loaded { graph, root, .. } =
            load_root_graph_from_path(&repo_a, &db_path)
        else {
            panic!("repo A must resolve to its persisted physical root");
        };
        assert_eq!(root, map_a.root);
        assert_eq!(graph.edges(), &[edge("only_a")]);

        let RootGraphLoad::Loaded { graph, root, .. } =
            load_root_graph_from_path(&repo_b, &db_path)
        else {
            panic!("repo B must resolve to its persisted physical root");
        };
        assert_eq!(root, map_b.root);
        assert_eq!(graph.edges(), &[edge("only_b")]);
    }

    #[test]
    fn coupling_graph_load_discards_edges_when_generation_changes_during_read() {
        let temp = tempdir().unwrap();
        let repo = temp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let db_path = temp.path().join("code_map.db");
        let map = empty_map(&repo);
        let mut conn = persist::open(&db_path).unwrap();
        persist::persist_map_and_edges(&mut conn, &map, &[edge("before")]).unwrap();
        drop(conn);

        let writer_path = db_path.clone();
        let replacement_map = map.clone();
        let outcome = load_root_graph_from_path_with_hook(&repo, &db_path, move || {
            let mut writer = persist::open(&writer_path).unwrap();
            persist::persist_map_and_edges(&mut writer, &replacement_map, &[edge("after")])
                .unwrap();
        });

        let RootGraphLoad::Unavailable { message } = outcome else {
            panic!("a generation race must discard the already-read edge set");
        };
        assert!(message.contains("changed while reading edges"));
        assert!(!message.contains("windows:"));
        assert!(!message.contains("unix:"));
    }

    #[test]
    fn coupling_graph_load_keeps_missing_snapshot_distinct_from_zero_edges() {
        let temp = tempdir().unwrap();
        let repo = temp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let db_path = temp.path().join("missing-code-map.db");

        let RootGraphLoad::Unavailable { message } = load_root_graph_from_path(&repo, &db_path)
        else {
            panic!("missing code-map DB must not become a successful empty graph");
        };
        assert!(message.contains("not found"));
    }

    #[test]
    fn coupling_graph_load_accepts_certified_snapshot_with_zero_edges() {
        let temp = tempdir().unwrap();
        let repo = temp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let db_path = temp.path().join("code_map.db");
        let map = empty_map(&repo);
        let mut conn = persist::open(&db_path).unwrap();
        persist::persist_map_and_edges(&mut conn, &map, &[]).unwrap();
        drop(conn);

        let RootGraphLoad::Loaded { graph, .. } = load_root_graph_from_path(&repo, &db_path) else {
            panic!("certified zero-edge snapshot must remain a valid graph");
        };
        assert!(graph.edges().is_empty());
    }
}
