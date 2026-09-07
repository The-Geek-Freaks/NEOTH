//! Prepared delta-refresh core for the next CRG-01 wave.
//!
//! This module is part of the lifecycle publication path. Its invariant is
//! conservative:
//! unchanged bytes reuse persisted declarations, while any global declaration
//! name-set change invalidates every supported code source's outgoing edges.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;

use anyhow::{Context, Result, ensure};

use super::graph::CodeEdge;
use super::root_identity::CanonicalRepoRoot;
use super::snapshot::RebuildOptions;
use super::symbols::extract_symbols;
use super::walker::{
    DEFAULT_MAX_FILE_BYTES, RepoFile, RepoMap, RepoMapBuilder, ScanCancellation, read_file_bounded,
};

/// One fully hashed delta candidate.  It contains no source text for unchanged
/// files; the later graph phase re-reads only [`Self::edge_sources`] and the
/// final fence re-hashes the entire corpus.
#[derive(Clone, Debug)]
pub(crate) struct PreparedDeltaRefresh {
    pub(crate) map: RepoMap,
    /// Every source file whose outgoing edges must be replaced atomically.
    pub(crate) edge_sources: BTreeSet<String>,
    /// Existing edges whose source is outside `edge_sources` and may survive.
    pub(crate) retained_edges: Vec<CodeEdge>,
    /// Sources whose persisted outgoing edges must be removed because the path
    /// vanished or changed out of a supported code language.
    pub(crate) removed_paths: BTreeSet<String>,
}

/// Read only the evidence needed before a delta rebuild.  Integration calls
/// this only after the current root is complete, identity-bound and stale.
pub(crate) fn prepare(
    root: &CanonicalRepoRoot,
    database_path: &Path,
    options: RebuildOptions,
    cancellation: &ScanCancellation,
) -> Result<Option<PreparedDeltaRefresh>> {
    cancellation.checkpoint()?;
    let connection = super::persist::open_read_only(database_path)?;
    let Some(previous) = super::persist::load_map(&connection, root.display())? else {
        return Ok(None);
    };
    let prior_edges = super::persist::load_edges_for_delta_refresh(&connection, root.display())?;
    drop(connection);

    // This inventory reads and hashes every selected file but intentionally
    // skips declaration parsing.  Equal hash is the only parse-reuse proof.
    let inventory = scan_inventory(root, options, cancellation)
        .context("build bounded delta refresh inventory")?;
    ensure!(
        inventory.report.truncated_at.is_none() && inventory.report.oversize_skipped == 0,
        "delta refresh refuses incomplete source inventory"
    );
    ensure!(
        inventory.root == root.display(),
        "delta inventory root changed"
    );

    let prior_by_path: HashMap<&str, &RepoFile> = previous
        .files
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect();
    let current_paths: BTreeSet<&str> = inventory
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect();
    let mut removed_paths: BTreeSet<String> = previous
        .files
        .iter()
        .filter(|file| !current_paths.contains(file.path.as_str()))
        .map(|file| file.path.clone())
        .collect();

    let mut files = Vec::with_capacity(inventory.files.len());
    let mut changed_or_added = BTreeSet::new();
    for observed in inventory.files {
        cancellation.checkpoint()?;
        let prior = prior_by_path.get(observed.path.as_str()).copied();
        if prior.is_some_and(|file| file.language.is_code()) && !observed.language.is_code() {
            removed_paths.insert(observed.path.clone());
        }
        let unchanged = prior.is_some_and(|file| {
            file.sha256 == observed.sha256 && file.language == observed.language
        });
        if unchanged {
            let prior = prior.expect("checked above");
            // Retain the new filesystem metadata but reuse only declarations
            // proven to derive from identical bytes.
            files.push(RepoFile {
                symbols: prior.symbols.clone(),
                ..observed
            });
            continue;
        }

        let absolute = root.path().join(&observed.path);
        let max_file_bytes = options.max_file_bytes.unwrap_or(DEFAULT_MAX_FILE_BYTES);
        let raw = read_file_bounded(&absolute, max_file_bytes)?
            .context("delta candidate grew past bounded file limit")?;
        cancellation.checkpoint()?;
        let symbols = if observed.language.is_code() {
            extract_symbols(&String::from_utf8_lossy(&raw), observed.language)
        } else {
            Vec::new()
        };
        changed_or_added.insert(observed.path.clone());
        files.push(RepoFile {
            symbols,
            ..observed
        });
    }
    let map = RepoMap {
        root: inventory.root,
        files,
        report: inventory.report,
    };

    let prior_names = declaration_names(&previous);
    let next_names = declaration_names(&map);
    let global_name_set_changed = prior_names != next_names;
    let edge_sources: BTreeSet<String> = if global_name_set_changed {
        map.files
            .iter()
            .filter(|file| file.language.is_code())
            .map(|file| file.path.clone())
            .collect()
    } else {
        changed_or_added
            .into_iter()
            .filter(|path| {
                map.files
                    .iter()
                    .find(|file| file.path == *path)
                    .is_some_and(|file| file.language.is_code())
            })
            .collect()
    };
    let retained_edges = prior_edges
        .into_iter()
        .filter(|edge| !edge_sources.contains(&edge.from_file))
        .filter(|edge| !removed_paths.contains(&edge.from_file))
        .collect();

    Ok(Some(PreparedDeltaRefresh {
        map,
        edge_sources,
        retained_edges,
        removed_paths,
    }))
}

/// Re-hash every selected source and reject any path/hash difference observed
/// after [`prepare`]. The snapshot integration calls this under its IMMEDIATE
/// transaction after staging map and edge changes, immediately before commit.
pub(crate) fn validate_final_source_fence(
    root: &CanonicalRepoRoot,
    prepared: &PreparedDeltaRefresh,
    options: RebuildOptions,
    cancellation: &ScanCancellation,
) -> Result<()> {
    cancellation.checkpoint()?;
    let final_inventory =
        scan_inventory(root, options, cancellation).context("perform final delta source fence")?;
    ensure!(
        final_inventory.report.truncated_at.is_none()
            && final_inventory.report.oversize_skipped == 0,
        "delta final source fence is incomplete"
    );
    ensure!(
        final_inventory.root == prepared.map.root,
        "delta refresh root changed"
    );
    let observed: Vec<(&str, &str)> = final_inventory
        .files
        .iter()
        .map(|file| (file.path.as_str(), file.sha256.as_str()))
        .collect();
    let prepared_paths: Vec<(&str, &str)> = prepared
        .map
        .files
        .iter()
        .map(|file| (file.path.as_str(), file.sha256.as_str()))
        .collect();
    ensure!(
        observed == prepared_paths,
        "source changed between delta inventory and publication"
    );
    let observed_root = CanonicalRepoRoot::discover(root.path())?;
    ensure!(
        observed_root == *root,
        "repository root was replaced during delta refresh"
    );
    cancellation.checkpoint()
}

fn scan_inventory(
    root: &CanonicalRepoRoot,
    options: RebuildOptions,
    cancellation: &ScanCancellation,
) -> Result<RepoMap> {
    let mut builder = RepoMapBuilder::new(root.path())
        .with_symbols(false)
        .strict_errors(options.require_complete);
    if let Some(max_files) = options.max_files {
        builder = builder.max_files(max_files);
    }
    if let Some(max_file_bytes) = options.max_file_bytes {
        builder = builder.max_file_bytes(max_file_bytes);
    }
    if options.include_hidden {
        builder = builder.include_hidden(true);
    }
    builder
        .scan_with_cancellation(cancellation)
        .context("build bounded delta refresh inventory")
}

fn declaration_names(map: &RepoMap) -> BTreeSet<String> {
    map.files
        .iter()
        .flat_map(|file| file.symbols.iter().map(|symbol| symbol.name.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn unchanged_hash_reuses_symbols_while_changed_file_is_reparsed() {
        let repo = tempdir().unwrap();
        std::fs::write(repo.path().join("a.rs"), "pub fn a() {}\n").unwrap();
        std::fs::write(repo.path().join("b.rs"), "pub fn b() {}\n").unwrap();
        let root = CanonicalRepoRoot::discover(repo.path()).unwrap();
        let db_dir = tempdir().unwrap();
        let db = db_dir.path().join("code_map.db");
        let initial = super::super::snapshot::rebuild_snapshot(
            &root,
            &db,
            super::super::snapshot::RebuildOptions::default(),
        )
        .unwrap();
        assert_eq!(initial.index_generation, 1);
        std::fs::write(repo.path().join("a.rs"), "pub fn renamed_a() {}\n").unwrap();

        let prepared = prepare(
            &root,
            &db,
            RebuildOptions::default(),
            &ScanCancellation::new(),
        )
        .unwrap()
        .unwrap();
        let a = prepared
            .map
            .files
            .iter()
            .find(|file| file.path == "a.rs")
            .unwrap();
        let b = prepared
            .map
            .files
            .iter()
            .find(|file| file.path == "b.rs")
            .unwrap();
        assert_eq!(a.symbols[0].name, "renamed_a");
        assert_eq!(b.symbols[0].name, "b");
        assert_eq!(
            prepared.edge_sources,
            BTreeSet::from(["a.rs".to_owned(), "b.rs".to_owned()]),
            "a declaration-name change must rebuild every code source"
        );
    }

    #[test]
    fn unchanged_name_set_limits_edge_sources_to_changed_code_file() {
        let repo = tempdir().unwrap();
        std::fs::write(repo.path().join("a.rs"), "pub fn a() { b(); }\n").unwrap();
        std::fs::write(repo.path().join("b.rs"), "pub fn b() {}\n").unwrap();
        let root = CanonicalRepoRoot::discover(repo.path()).unwrap();
        let db_dir = tempdir().unwrap();
        let db = db_dir.path().join("code_map.db");
        super::super::snapshot::rebuild_snapshot(
            &root,
            &db,
            super::super::snapshot::RebuildOptions::default(),
        )
        .unwrap();
        std::fs::write(repo.path().join("a.rs"), "pub fn a() { b(); b(); }\n").unwrap();

        let prepared = prepare(
            &root,
            &db,
            RebuildOptions::default(),
            &ScanCancellation::new(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(prepared.edge_sources, BTreeSet::from(["a.rs".to_owned()]));
        assert!(
            prepared
                .retained_edges
                .iter()
                .all(|edge| edge.from_file != "a.rs")
        );
    }

    #[test]
    fn new_declaration_invalidates_unchanged_ambiguous_caller() {
        let repo = tempdir().unwrap();
        std::fs::write(
            repo.path().join("caller.rs"),
            "pub fn caller() { future_target(); }\n",
        )
        .unwrap();
        let root = CanonicalRepoRoot::discover(repo.path()).unwrap();
        let db_dir = tempdir().unwrap();
        let db = db_dir.path().join("code_map.db");
        super::super::snapshot::rebuild_snapshot(
            &root,
            &db,
            super::super::snapshot::RebuildOptions::default(),
        )
        .unwrap();
        std::fs::write(repo.path().join("target.rs"), "pub fn future_target() {}\n").unwrap();

        let prepared = prepare(
            &root,
            &db,
            RebuildOptions::default(),
            &ScanCancellation::new(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            prepared.edge_sources,
            BTreeSet::from(["caller.rs".to_owned(), "target.rs".to_owned()]),
            "a new target name must rebuild the unchanged caller too"
        );
        assert!(prepared.retained_edges.is_empty());
    }
    #[test]
    fn final_fence_rejects_post_inventory_edit() {
        let repo = tempdir().unwrap();
        std::fs::write(repo.path().join("a.rs"), "pub fn a() {}\n").unwrap();
        let root = CanonicalRepoRoot::discover(repo.path()).unwrap();
        let db_dir = tempdir().unwrap();
        let db = db_dir.path().join("code_map.db");
        super::super::snapshot::rebuild_snapshot(
            &root,
            &db,
            super::super::snapshot::RebuildOptions::default(),
        )
        .unwrap();
        std::fs::write(repo.path().join("a.rs"), "pub fn a() { let _ = 1; }\n").unwrap();
        let prepared = prepare(
            &root,
            &db,
            RebuildOptions::default(),
            &ScanCancellation::new(),
        )
        .unwrap()
        .unwrap();
        std::fs::write(repo.path().join("a.rs"), "pub fn a() { let _ = 2; }\n").unwrap();

        assert!(
            validate_final_source_fence(
                &root,
                &prepared,
                RebuildOptions::default(),
                &ScanCancellation::new()
            )
            .is_err()
        );
    }

    #[test]
    fn hidden_files_remain_in_the_delta_corpus_when_requested() {
        let repo = tempdir().unwrap();
        std::fs::write(repo.path().join("visible.rs"), "pub fn visible() {}\n").unwrap();
        std::fs::write(repo.path().join(".hidden.rs"), "pub fn hidden() {}\n").unwrap();
        let root = CanonicalRepoRoot::discover(repo.path()).unwrap();
        let db_dir = tempdir().unwrap();
        let db = db_dir.path().join("code_map.db");
        let options = RebuildOptions {
            include_hidden: true,
            ..RebuildOptions::default()
        };
        super::super::snapshot::rebuild_snapshot(&root, &db, options).unwrap();
        std::fs::write(
            repo.path().join("visible.rs"),
            "pub fn visible() { let _ = 1; }\n",
        )
        .unwrap();

        super::super::snapshot::rebuild_snapshot_delta_cancellable(
            &root,
            &db,
            options,
            &ScanCancellation::new(),
        )
        .unwrap();
        let persisted = super::super::persist::load_map(
            &super::super::persist::open_read_only(&db).unwrap(),
            root.display(),
        )
        .unwrap()
        .unwrap();
        assert!(persisted.files.iter().any(|file| file.path == ".hidden.rs"));
    }
}
