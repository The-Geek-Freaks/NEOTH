//! Canonical, generation-bound native code-map rebuilds.
//!
//! Every production writer uses this service so a code-map index and its call
//! graph are built from one verified filesystem snapshot and published in one
//! SQLite transaction. Graphify remains a complementary report generator; it
//! is never allowed to emit a completion receipt without this native snapshot.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};

use super::graph::{CallGraph, DEFAULT_MAX_GRAPH_EDGES, FileInput};
use super::persist::PersistStats;
use super::root_identity::CanonicalRepoRoot;
use super::walker::{
    DEFAULT_MAX_FILE_BYTES, Language, RepoMap, RepoMapBuilder, ScanReport, read_file_bounded,
};

/// Maximum owned source text retained while building one native call graph.
/// CallGraph construction is linear after token indexing, but retaining an
/// entire multi-gigabyte corpus would still make completion vulnerable to OOM.
const MAX_GRAPH_SOURCE_BYTES: usize = 128 * 1024 * 1024;

/// Bounded filesystem options for one native snapshot rebuild.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RebuildOptions {
    pub max_files: Option<u64>,
    pub max_file_bytes: Option<u64>,
    pub include_hidden: bool,
    /// Refuse to publish when the walker omitted files because of a file-count
    /// or per-file byte ceiling. Every production persistence/completion path
    /// enables this; bounded diagnostic scans remain non-publishing.
    pub require_complete: bool,
}

impl Default for RebuildOptions {
    fn default() -> Self {
        Self {
            max_files: None,
            max_file_bytes: None,
            include_hidden: false,
            require_complete: true,
        }
    }
}

/// Auditable result of one fully published index/graph generation.
#[derive(Clone, Debug)]
pub struct RebuildSnapshot {
    pub root: CanonicalRepoRoot,
    /// SHA-256 of the OS-backed physical root identity. Completion audit
    /// surfaces use this digest instead of persisting the raw identity.
    pub root_identity_sha256: String,
    pub index_generation: i64,
    pub graph_generation: i64,
    /// Deterministic digest of the physical root plus every published file
    /// path/length/content hash. Companion consumers can bind their own output
    /// receipts to this value; computing it alone makes no such claim.
    pub source_fingerprint_sha256: String,
    pub stats: PersistStats,
    pub edges_inserted: usize,
    pub cycles: Vec<Vec<String>>,
    pub scan_report: ScanReport,
}

/// Rebuild and atomically publish one native code-map snapshot.
///
/// `root` is deliberately a [`CanonicalRepoRoot`], not a raw path: callers
/// must resolve the exact physical repository before invoking the service.
/// Every scanned file is then re-read and its byte length plus SHA-256 checked
/// before graph construction. Any read, identity, or hash mismatch leaves the
/// prior index and graph generations untouched.
pub fn rebuild_snapshot(
    root: &CanonicalRepoRoot,
    db_path: &Path,
    options: RebuildOptions,
) -> Result<RebuildSnapshot> {
    let max_file_bytes = options.max_file_bytes.unwrap_or(DEFAULT_MAX_FILE_BYTES);
    rebuild_snapshot_with_reader(root, db_path, options, move |path| {
        read_file_bounded(path, max_file_bytes)?.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("file grew beyond the {max_file_bytes}-byte snapshot limit"),
            )
        })
    })
}

fn rebuild_snapshot_with_reader<F>(
    root: &CanonicalRepoRoot,
    db_path: &Path,
    options: RebuildOptions,
    mut read_file: F,
) -> Result<RebuildSnapshot>
where
    F: FnMut(&Path) -> std::io::Result<Vec<u8>>,
{
    let mut builder = RepoMapBuilder::new(root.path())
        .with_symbols(true)
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
    let map = builder.scan().context("scan native code-map snapshot")?;
    if options.require_complete {
        ensure!(
            map.report.truncated_at.is_none(),
            "native code-map scan hit its file-count ceiling at {:?}; refusing a partial completion snapshot",
            map.report.truncated_at
        );
        ensure!(
            map.report.oversize_skipped == 0,
            "native code-map scan skipped {} oversized file(s); refusing a partial completion snapshot",
            map.report.oversize_skipped
        );
    }
    ensure_root_unchanged(root, &map)?;

    let graph = build_graph_from_scan_snapshot(&map, &mut read_file)?;
    // A file validated early during graph construction can still change while
    // later files are read. Revalidate the complete corpus immediately before
    // entering the publication transaction.
    validate_scan_fingerprint(&map, &mut read_file)?;
    let mut verification_builder = RepoMapBuilder::new(root.path())
        .with_symbols(false)
        .strict_errors(options.require_complete);
    if let Some(max_files) = options.max_files {
        verification_builder = verification_builder.max_files(max_files);
    }
    if let Some(max_file_bytes) = options.max_file_bytes {
        verification_builder = verification_builder.max_file_bytes(max_file_bytes);
    }
    if options.include_hidden {
        verification_builder = verification_builder.include_hidden(true);
    }
    let verification_map = verification_builder
        .scan()
        .context("final rescan of native code-map corpus")?;
    ensure_same_scanned_corpus(&map, &verification_map)?;
    // Close a directory-replacement race between the scan/reread and publish.
    ensure_root_unchanged(root, &map)?;
    let cycles = graph
        .find_cycles(50)
        .context("run bounded call-cycle analysis before snapshot publication")?;
    let source_fingerprint_sha256 = source_fingerprint_digest(root, &map);

    let mut conn = super::persist::open(db_path)
        .with_context(|| format!("open code-map database at {}", db_path.display()))?;
    let publication =
        super::persist::persist_map_and_edges_bound(&mut conn, &map, graph.edges(), root)
            .context("atomically persist identity-bound code-map index and call graph")?;

    Ok(RebuildSnapshot {
        root: root.clone(),
        root_identity_sha256: root_identity_digest(root),
        index_generation: publication.index_generation,
        graph_generation: publication.graph_generation,
        source_fingerprint_sha256,
        stats: publication.stats,
        edges_inserted: publication.edges_inserted,
        cycles,
        scan_report: map.report,
    })
}

fn ensure_root_unchanged(expected: &CanonicalRepoRoot, map: &RepoMap) -> Result<()> {
    ensure!(
        map.root == expected.display(),
        "native code-map scan changed canonical root from {:?} to {:?}",
        expected.display(),
        map.root
    );
    let observed = CanonicalRepoRoot::discover(Path::new(&map.root))?;
    ensure!(
        observed == *expected,
        "native code-map repository root was replaced during rebuild"
    );
    Ok(())
}

fn build_graph_from_scan_snapshot<F>(map: &RepoMap, mut read_file: F) -> Result<CallGraph>
where
    F: FnMut(&Path) -> std::io::Result<Vec<u8>>,
{
    build_graph_from_scan_snapshot_with_limit(map, &mut read_file, MAX_GRAPH_SOURCE_BYTES)
}

fn build_graph_from_scan_snapshot_with_limit<F>(
    map: &RepoMap,
    mut read_file: F,
    max_graph_source_bytes: usize,
) -> Result<CallGraph>
where
    F: FnMut(&Path) -> std::io::Result<Vec<u8>>,
{
    let root_dir = PathBuf::from(&map.root);
    let mut inputs = Vec::with_capacity(map.files.len());
    let mut retained_source_bytes = 0usize;
    for file in &map.files {
        let absolute = root_dir.join(&file.path);
        let raw = read_file(&absolute)
            .with_context(|| format!("re-read scanned code-map file {}", absolute.display()))?;
        let actual_bytes = u64::try_from(raw.len()).context("code-map file length exceeds u64")?;
        if actual_bytes != file.bytes {
            bail!(
                "code-map file {} changed after the scan (expected {} bytes, got {}); \
                 no index or graph generation was published",
                file.path,
                file.bytes,
                actual_bytes
            );
        }
        let actual_sha256 = hex::encode(Sha256::digest(&raw));
        if actual_sha256 != file.sha256 {
            bail!(
                "code-map file {} changed after the scan (expected SHA-256 {}, got {}); \
                 no index or graph generation was published",
                file.path,
                file.sha256,
                actual_sha256
            );
        }
        if file.symbols.is_empty() {
            continue;
        }
        retained_source_bytes = retained_source_bytes
            .checked_add(raw.len())
            .context("native call-graph source-byte count overflow")?;
        ensure!(
            retained_source_bytes <= max_graph_source_bytes,
            "native call-graph source exceeds bounded {}-byte work budget; no generation was published",
            max_graph_source_bytes
        );

        // The scanner used `from_utf8_lossy` on these exact bytes. Reuse its
        // declarations so persisted endpoints and graph identities cannot
        // drift through a second extraction pass.
        let source = String::from_utf8_lossy(&raw).into_owned();
        let input = match file.language {
            Language::Python
            | Language::Ruby
            | Language::Shell
            | Language::Toml
            | Language::Yaml
            | Language::Dockerfile => {
                FileInput::hash_family(file.path.clone(), source, file.symbols.clone())
            }
            _ => FileInput::c_family(file.path.clone(), source, file.symbols.clone()),
        };
        inputs.push(input);
    }
    CallGraph::build_bounded(&inputs, DEFAULT_MAX_GRAPH_EDGES)
}

fn validate_scan_fingerprint<F>(map: &RepoMap, mut read_file: F) -> Result<()>
where
    F: FnMut(&Path) -> std::io::Result<Vec<u8>>,
{
    let root_dir = PathBuf::from(&map.root);
    for file in &map.files {
        let absolute = root_dir.join(&file.path);
        let raw = read_file(&absolute).with_context(|| {
            format!(
                "final re-read of scanned code-map file {}",
                absolute.display()
            )
        })?;
        let actual_bytes = u64::try_from(raw.len()).context("code-map file length exceeds u64")?;
        ensure!(
            actual_bytes == file.bytes,
            "code-map file {} changed before publication (expected {} bytes, got {}); no index or graph generation was published",
            file.path,
            file.bytes,
            actual_bytes
        );
        let actual_sha256 = hex::encode(Sha256::digest(&raw));
        ensure!(
            actual_sha256 == file.sha256,
            "code-map file {} changed before publication (expected SHA-256 {}, got {}); no index or graph generation was published",
            file.path,
            file.sha256,
            actual_sha256
        );
    }
    Ok(())
}

fn ensure_same_scanned_corpus(initial: &RepoMap, final_map: &RepoMap) -> Result<()> {
    ensure!(
        initial.root == final_map.root,
        "native code-map root changed during final corpus rescan"
    );
    ensure!(
        initial.report.truncated_at == final_map.report.truncated_at
            && initial.report.oversize_skipped == final_map.report.oversize_skipped,
        "native code-map scan boundaries changed before publication"
    );
    let mut initial_files: Vec<_> = initial
        .files
        .iter()
        .map(|file| (&file.path, file.bytes, &file.sha256))
        .collect();
    let mut final_files: Vec<_> = final_map
        .files
        .iter()
        .map(|file| (&file.path, file.bytes, &file.sha256))
        .collect();
    initial_files.sort();
    final_files.sort();
    ensure!(
        initial_files == final_files,
        "native code-map corpus changed before publication; no index or graph generation was published"
    );
    Ok(())
}

fn source_fingerprint_digest(root: &CanonicalRepoRoot, map: &RepoMap) -> String {
    let mut files: Vec<_> = map.files.iter().collect();
    files.sort_by(|left, right| left.path.cmp(&right.path));
    let mut digest = Sha256::new();
    digest.update(b"neoth.code-map.source-snapshot.v1\0");
    digest.update(root.identity().as_str().as_bytes());
    for file in files {
        digest.update(b"\0");
        digest.update(file.path.as_bytes());
        digest.update(b"\0");
        digest.update(file.bytes.to_le_bytes());
        digest.update(b"\0");
        digest.update(file.sha256.as_bytes());
    }
    hex::encode(digest.finalize())
}

fn root_identity_digest(root: &CanonicalRepoRoot) -> String {
    let mut digest = Sha256::new();
    digest.update(b"neoth.code-map.root-identity.v1\0");
    digest.update(root.identity().as_str().as_bytes());
    hex::encode(digest.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn rebuild_publishes_one_verified_index_graph_generation() {
        let repo = tempdir().unwrap();
        std::fs::write(
            repo.path().join("lib.rs"),
            "pub fn alpha() { beta(); }\npub fn beta() {}\n",
        )
        .unwrap();
        let root = CanonicalRepoRoot::discover(repo.path()).unwrap();
        let db_dir = tempdir().unwrap();
        let db = db_dir.path().join("code_map.db");

        let rebuilt = rebuild_snapshot(&root, &db, RebuildOptions::default()).unwrap();

        assert_eq!(rebuilt.root, root);
        assert_eq!(rebuilt.index_generation, 1);
        assert_eq!(rebuilt.graph_generation, 1);
        assert_eq!(rebuilt.root_identity_sha256.len(), 64);
        assert_eq!(rebuilt.stats.files_inserted, 1);
        assert!(rebuilt.stats.symbols_inserted >= 2);
        assert!(rebuilt.edges_inserted >= 1);
    }

    #[test]
    fn graph_build_refuses_cumulative_source_bytes_above_budget() {
        let repo = tempdir().unwrap();
        std::fs::write(repo.path().join("a.rs"), "pub fn alpha() {}\n").unwrap();
        std::fs::write(repo.path().join("b.rs"), "pub fn beta() {}\n").unwrap();
        let map = RepoMapBuilder::new(repo.path())
            .with_symbols(true)
            .strict_errors(true)
            .scan()
            .unwrap();

        let error = build_graph_from_scan_snapshot_with_limit(&map, |path| std::fs::read(path), 8)
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("source exceeds bounded 8-byte work budget")
        );
    }

    #[test]
    fn same_length_hash_mismatch_preserves_prior_generations() {
        let repo = tempdir().unwrap();
        let source = repo.path().join("lib.rs");
        std::fs::write(&source, "pub fn before() {}\n").unwrap();
        let root = CanonicalRepoRoot::discover(repo.path()).unwrap();
        let db_dir = tempdir().unwrap();
        let db = db_dir.path().join("code_map.db");
        rebuild_snapshot(&root, &db, RebuildOptions::default()).unwrap();

        let error = rebuild_snapshot_with_reader(&root, &db, RebuildOptions::default(), |path| {
            let mut bytes = std::fs::read(path)?;
            bytes[0] ^= 1;
            Ok(bytes)
        })
        .unwrap_err();

        assert!(error.to_string().contains("changed after the scan"));
        assert!(error.to_string().contains("expected SHA-256"));
        let conn = super::super::persist::open(&db).unwrap();
        assert_eq!(
            super::super::persist::root_index_generation(&conn, root.display()).unwrap(),
            Some(1)
        );
        assert_eq!(
            super::super::persist::root_graph_generation(&conn, root.display()).unwrap(),
            Some(1)
        );
    }

    #[test]
    fn unreadable_reread_publishes_no_generation() {
        let repo = tempdir().unwrap();
        std::fs::write(repo.path().join("lib.rs"), "pub fn scanned() {}\n").unwrap();
        let root = CanonicalRepoRoot::discover(repo.path()).unwrap();
        let db_dir = tempdir().unwrap();
        let db = db_dir.path().join("code_map.db");

        let error = rebuild_snapshot_with_reader(&root, &db, RebuildOptions::default(), |_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "injected unreadable snapshot file",
            ))
        })
        .unwrap_err();

        assert!(format!("{error:#}").contains("injected unreadable snapshot file"));
        let conn = super::super::persist::open(&db).unwrap();
        assert_eq!(
            super::super::persist::root_index_generation(&conn, root.display()).unwrap(),
            None
        );
        assert_eq!(
            super::super::persist::root_graph_generation(&conn, root.display()).unwrap(),
            None
        );
    }

    #[test]
    fn rebuild_applies_explicit_scan_limits() {
        let repo = tempdir().unwrap();
        std::fs::write(repo.path().join("a.rs"), "pub fn a() {}\n").unwrap();
        std::fs::write(repo.path().join("b.rs"), "pub fn b() {}\n").unwrap();
        let root = CanonicalRepoRoot::discover(repo.path()).unwrap();
        let db_dir = tempdir().unwrap();

        let rebuilt = rebuild_snapshot(
            &root,
            &db_dir.path().join("code_map.db"),
            RebuildOptions {
                max_files: Some(1),
                max_file_bytes: Some(1024),
                include_hidden: false,
                require_complete: false,
            },
        )
        .unwrap();

        assert_eq!(rebuilt.scan_report.total_files, 1);
        assert_eq!(rebuilt.scan_report.truncated_at, Some(1));
    }

    #[test]
    fn completion_rebuild_refuses_truncated_snapshot_before_publication() {
        let repo = tempdir().unwrap();
        std::fs::write(repo.path().join("a.rs"), "pub fn a() {}\n").unwrap();
        std::fs::write(repo.path().join("b.rs"), "pub fn b() {}\n").unwrap();
        let root = CanonicalRepoRoot::discover(repo.path()).unwrap();
        let db_dir = tempdir().unwrap();
        let db = db_dir.path().join("code_map.db");

        let error = rebuild_snapshot(
            &root,
            &db,
            RebuildOptions {
                max_files: Some(1),
                max_file_bytes: None,
                include_hidden: false,
                require_complete: true,
            },
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("refusing a partial completion snapshot")
        );
        let conn = super::super::persist::open(&db).unwrap();
        assert_eq!(
            super::super::persist::root_index_generation(&conn, root.display()).unwrap(),
            None
        );
    }

    #[test]
    fn bound_publish_rolls_back_when_path_now_names_another_directory() {
        let parent = tempdir().unwrap();
        let repo = parent.path().join("repo");
        let moved = parent.path().join("moved-original");
        std::fs::create_dir(&repo).unwrap();
        std::fs::write(repo.join("original.rs"), "pub fn original() {}\n").unwrap();
        let expected = CanonicalRepoRoot::discover(&repo).unwrap();
        let db_dir = tempdir().unwrap();
        let db = db_dir.path().join("code_map.db");
        rebuild_snapshot(&expected, &db, RebuildOptions::default()).unwrap();

        std::fs::rename(&repo, &moved).unwrap();
        std::fs::create_dir(&repo).unwrap();
        std::fs::write(repo.join("replacement.rs"), "pub fn replacement() {}\n").unwrap();
        let replacement_map = RepoMapBuilder::new(&repo)
            .with_symbols(true)
            .scan()
            .unwrap();
        let mut conn = super::super::persist::open(&db).unwrap();
        let error = super::super::persist::persist_map_and_edges_bound(
            &mut conn,
            &replacement_map,
            &[],
            &expected,
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("replaced before bound snapshot commit")
        );
        assert_eq!(
            super::super::persist::root_index_generation(&conn, expected.display()).unwrap(),
            Some(1)
        );
        assert_eq!(
            super::super::persist::root_graph_generation(&conn, expected.display()).unwrap(),
            Some(1)
        );
        let preserved = super::super::persist::load_map(&conn, expected.display())
            .unwrap()
            .expect("prior snapshot must survive rollback");
        assert_eq!(preserved.files.len(), 1);
        assert_eq!(preserved.files[0].path, "original.rs");
        drop(conn);

        // Restore the original object at its canonical path so TempDir cleanup
        // does not leave the renamed directory behind on Windows.
        std::fs::remove_dir_all(&repo).unwrap();
        std::fs::rename(&moved, &repo).unwrap();
    }
}
