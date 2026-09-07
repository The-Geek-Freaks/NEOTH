//! Read-only, bounded Git diff acquisition and exact parser-declaration seeds.
//!
//! This module intentionally stops before persistence or graph refresh. It
//! acquires one explicit diff source, validates it with the existing bounded
//! unified-diff parser, and maps hunk ranges to the narrowest parser-certified
//! declaration extent that wholly contains them. Unknown/legacy extents,
//! unparseable languages, binary files, and uncovered hunks become file seeds.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use super::diff::{DiffChange, DiffFile, DiffRange, MAX_DIFF_BYTES, parse_unified_diff};
use super::impact::ImpactSeed;
use super::walker::{DEFAULT_MAX_SYMBOLS, Language, RepoMap};

/// Maximum time a read-only `git diff` child may run.
pub const GIT_DIFF_TIMEOUT: Duration = Duration::from_secs(15);
/// Maximum source text read while looking for declarations in changed files.
pub const MAX_DIFF_SOURCE_BYTES: usize = 2 * 1024 * 1024;
/// Maximum source text retained across one diff-to-impact mapping request.
/// The per-file cap alone would otherwise allow 256 accepted files to retain
/// 512 MiB in the source map before parser mapping begins.
pub const MAX_DIFF_TOTAL_SOURCE_BYTES: usize = 128 * 1024 * 1024;
const MAX_GIT_STDERR_BYTES: usize = 64 * 1024;

/// A parser-certified inclusive declaration span: `(name, start_line, end_line)`.
type CertifiedSymbolExtent = (String, u32, u32);
/// Certified declaration spans grouped by repo-relative source path.
type CertifiedExtentsByPath = BTreeMap<String, BTreeSet<CertifiedSymbolExtent>>;

/// Explicit authority for one Git diff acquisition. No ambient branch, ref,
/// or current directory is inferred by the library API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GitDiffSource {
    WorkingTree,
    Staged,
    Committed {
        base: String,
        target: String,
    },
    /// Use [`parse_stdin_diff`] for an already-captured unified diff.
    Stdin,
}

/// A successfully parsed deterministic diff attached to its explicit source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcquiredDiff {
    pub source: GitDiffSource,
    pub files: Vec<DiffFile>,
}

/// One input for CRG-02 impact analysis. `exact_symbol` is true only when the
/// existing declaration parser matched its declaration line inside a hunk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiffImpactSeed {
    pub seed: ImpactSeed,
    pub exact_symbol: bool,
}

/// Acquire and parse one Git diff beneath an explicit repository directory.
///
/// Git receives argument vectors directly, with `--` terminating revisions,
/// so an operator-provided ref cannot become an option or shell fragment.
/// Git failures, non-UTF-8 text, timeouts, and output caps are errors.
pub fn acquire_git_diff(repo_root: &Path, source: GitDiffSource) -> Result<AcquiredDiff> {
    if matches!(&source, GitDiffSource::Stdin) {
        bail!("stdin diff must use parse_stdin_diff");
    }
    let root = canonical_repo_root(repo_root)?;
    let mut args = vec![
        "-c".into(),
        "core.pager=cat".into(),
        "-c".into(),
        "core.quotepath=false".into(),
        "-C".into(),
        root.to_string_lossy().into_owned(),
        "diff".into(),
        "--no-ext-diff".into(),
        "--no-color".into(),
        "--no-textconv".into(),
        "--unified=0".into(),
        "--find-renames".into(),
    ];
    match &source {
        GitDiffSource::WorkingTree => {}
        GitDiffSource::Staged => args.push("--cached".into()),
        GitDiffSource::Committed { base, target } => {
            validate_git_ref(base)?;
            validate_git_ref(target)?;
            args.push(base.clone());
            args.push(target.clone());
        }
        GitDiffSource::Stdin => unreachable!("checked above"),
    }
    args.push("--".into());
    let text = run_git_bounded(&args)?;
    Ok(AcquiredDiff {
        source,
        files: parse_unified_diff(&text).map_err(anyhow::Error::from)?,
    })
}

/// Parse an already captured unified diff under the same bounded parser
/// contract as Git-acquired text.
pub fn parse_stdin_diff(input: &str) -> Result<AcquiredDiff> {
    Ok(AcquiredDiff {
        source: GitDiffSource::Stdin,
        files: parse_unified_diff(input).map_err(anyhow::Error::from)?,
    })
}

/// Read the exact Git side for each changed file and derive impact seeds.
///
/// Every parser-normalized path is re-contained beneath the canonical root
/// before opening. For committed/staged/deleted changes the source comes from
/// the corresponding Git tree rather than ambient working-tree bytes. A
/// missing, oversized, non-UTF-8, or externally symlinked required text file
/// is an error, never an empty successful seed list.
pub fn map_acquired_diff_to_impact_seeds(
    repo_root: &Path,
    acquired: &AcquiredDiff,
) -> Result<Vec<DiffImpactSeed>> {
    let root = canonical_repo_root(repo_root)?;
    let sources = collect_diff_sources(&root, acquired, MAX_DIFF_TOTAL_SOURCE_BYTES)?;
    Ok(map_diff_to_impact_seeds(&acquired.files, &sources))
}

/// Map a diff using parser-certified source extents only when they match the
/// persisted snapshot exactly. A stale index, a legacy `NULL` extent, or a
/// source/row mismatch becomes a file seed rather than an invented symbol.
pub fn map_acquired_diff_to_indexed_impact_seeds(
    repo_root: &Path,
    acquired: &AcquiredDiff,
    indexed: &RepoMap,
) -> Result<Vec<DiffImpactSeed>> {
    let root = canonical_repo_root(repo_root)?;
    let certified = certified_extents_with_limit(indexed, DEFAULT_MAX_SYMBOLS)?;
    let sources = collect_diff_sources(&root, acquired, MAX_DIFF_TOTAL_SOURCE_BYTES)?;
    Ok(map_diff_to_impact_seeds_with_certified_extents(
        &acquired.files,
        &sources,
        Some(&certified),
    ))
}

fn collect_diff_sources(
    root: &Path,
    acquired: &AcquiredDiff,
    max_total_source_bytes: usize,
) -> Result<BTreeMap<String, (Language, String)>> {
    let mut sources = BTreeMap::new();
    let mut retained_source_bytes = 0usize;
    for file in &acquired.files {
        if file.change == DiffChange::Binary
            || (file.change == DiffChange::Deleted && acquired.source == GitDiffSource::Stdin)
        {
            continue;
        }
        let path = match file.change {
            DiffChange::Deleted => file.old_path.as_deref(),
            _ => file.new_path.as_deref().or(file.old_path.as_deref()),
        };
        let Some(path) = path else { continue };
        let language = Language::from_path(Path::new(path));
        if language == Language::Other {
            continue;
        }
        let source = read_source_for_diff_file(root, &acquired.source, file, path)?;
        admit_source(
            &mut sources,
            &mut retained_source_bytes,
            path,
            language,
            source,
            max_total_source_bytes,
        )?;
    }
    Ok(sources)
}

fn admit_source(
    sources: &mut BTreeMap<String, (Language, String)>,
    retained_source_bytes: &mut usize,
    path: &str,
    language: Language,
    source: String,
    max_total_source_bytes: usize,
) -> Result<()> {
    let replaced_bytes = sources.get(path).map_or(0, |(_, source)| source.len());
    let retained_without_replaced = retained_source_bytes
        .checked_sub(replaced_bytes)
        .context("diff source accounting lost an existing path")?;
    let next = retained_without_replaced
        .checked_add(source.len())
        .context("diff aggregate source-byte count overflow")?;
    if next > max_total_source_bytes {
        bail!(
            "diff changed source set exceeds bounded {max_total_source_bytes}-byte admission cap"
        );
    }
    sources.insert(path.to_owned(), (language, source));
    *retained_source_bytes = next;
    Ok(())
}

fn certified_extents_with_limit(
    indexed: &RepoMap,
    max_symbols: usize,
) -> Result<CertifiedExtentsByPath> {
    let mut admitted_symbols = 0usize;
    for file in &indexed.files {
        admitted_symbols = admitted_symbols
            .checked_add(file.symbols.len())
            .context("indexed diff symbol count overflow")?;
        if admitted_symbols > max_symbols {
            bail!(
                "indexed diff map exceeds bounded {max_symbols}-symbol admission cap before mapping"
            );
        }
    }
    Ok(indexed
        .files
        .iter()
        .map(|file| {
            let extents = file
                .symbols
                .iter()
                .filter_map(|symbol| {
                    symbol
                        .line_end
                        .map(|end| (symbol.name.clone(), symbol.line, end))
                })
                .collect();
            (file.path.clone(), extents)
        })
        .collect())
}

/// Map parsed hunk ranges to parser-backed seeds. This pure helper is useful
/// for callers that already have source text held under their own authority.
pub fn map_diff_to_impact_seeds(
    files: &[DiffFile],
    sources: &BTreeMap<String, (Language, String)>,
) -> Vec<DiffImpactSeed> {
    map_diff_to_impact_seeds_with_certified_extents(files, sources, None)
}

fn map_diff_to_impact_seeds_with_certified_extents(
    files: &[DiffFile],
    sources: &BTreeMap<String, (Language, String)>,
    certified: Option<&CertifiedExtentsByPath>,
) -> Vec<DiffImpactSeed> {
    let mut out = Vec::new();
    for file in files {
        let path = match file.change {
            DiffChange::Deleted => file.old_path.as_deref(),
            _ => file.new_path.as_deref().or(file.old_path.as_deref()),
        };
        let Some(path) = path else { continue };
        let Some((language, source)) = sources.get(path) else {
            out.push(DiffImpactSeed {
                seed: ImpactSeed::file(path),
                exact_symbol: false,
            });
            continue;
        };
        let ranges: Vec<DiffRange> = match file.change {
            DiffChange::Deleted => file.hunks.iter().map(|hunk| hunk.old).collect(),
            _ => file.hunks.iter().map(|hunk| hunk.new).collect(),
        };
        let mut symbols = super::symbols::extract_symbols(source, *language);
        if let Some(certified) = certified {
            let allowed = certified.get(path);
            symbols.retain(|symbol| {
                symbol.line_end.is_some_and(|end| {
                    allowed.is_some_and(|extents| {
                        extents.contains(&(symbol.name.clone(), symbol.line, end))
                    })
                })
            });
        }
        let mut exact = false;
        let mut uncovered_hunk = false;
        for range in ranges {
            let Some(symbol) = narrowest_symbol_for_range(&symbols, range) else {
                uncovered_hunk = true;
                continue;
            };
            {
                out.push(DiffImpactSeed {
                    seed: ImpactSeed::symbol(path, symbol.name.clone()),
                    exact_symbol: true,
                });
                exact = true;
            }
        }
        if !exact || uncovered_hunk {
            out.push(DiffImpactSeed {
                seed: ImpactSeed::file(path),
                exact_symbol: false,
            });
        }
    }
    // A declaration seed is more precise than a duplicate file seed. Stable
    // ordering and de-duplication make CLI/MCP requests reproducible.
    out.sort_by(|left, right| {
        left.seed
            .cmp(&right.seed)
            .then(right.exact_symbol.cmp(&left.exact_symbol))
    });
    out.dedup_by(|left, right| left.seed == right.seed);
    out
}

fn narrowest_symbol_for_range(
    symbols: &[super::symbols::Symbol],
    range: DiffRange,
) -> Option<&super::symbols::Symbol> {
    let end = range.last_line()?;
    symbols
        .iter()
        .filter_map(|symbol| {
            let symbol_end = symbol.line_end?;
            (symbol.line <= range.start && end <= symbol_end)
                .then_some((symbol, symbol_end - symbol.line))
        })
        .min_by_key(|(symbol, width)| (*width, symbol.line, symbol.name.clone()))
        .map(|(symbol, _)| symbol)
}

fn canonical_repo_root(repo_root: &Path) -> Result<PathBuf> {
    let root = repo_root
        .canonicalize()
        .with_context(|| format!("canonicalize explicit Git root {}", repo_root.display()))?;
    if !root.is_dir() {
        bail!("explicit Git root is not a directory: {}", root.display());
    }
    Ok(root)
}

fn read_source_for_diff_file(
    root: &Path,
    source: &GitDiffSource,
    file: &DiffFile,
    path: &str,
) -> Result<String> {
    let deleted = file.change == DiffChange::Deleted;
    match source {
        GitDiffSource::WorkingTree if !deleted => read_repo_source(root, path),
        GitDiffSource::WorkingTree => read_git_blob(root, "HEAD", path),
        GitDiffSource::Staged if !deleted => read_git_blob(root, ":", path),
        GitDiffSource::Staged => read_git_blob(root, "HEAD", path),
        GitDiffSource::Committed { base, target } if !deleted => read_git_blob(root, target, path),
        GitDiffSource::Committed { base, .. } => read_git_blob(root, base, path),
        // A caller-provided stdin diff has no authenticated base/target tree.
        // Current bytes can only serve additions/modifications; deletions stay
        // a conservative file seed because their old tree was not supplied.
        GitDiffSource::Stdin if !deleted => read_repo_source(root, path),
        GitDiffSource::Stdin => bail!("stdin deletion has no explicit base tree for {path:?}"),
    }
}

fn read_git_blob(root: &Path, revision: &str, path: &str) -> Result<String> {
    if revision != ":" {
        validate_git_ref(revision)?;
    }
    // The diff parser already rejects rooted, parent, backslash, and quoted
    // paths. `--` does not apply to the `REV:path` grammar, so validate the
    // complete argument before passing it as exactly one argv element.
    if path.is_empty() || path.starts_with('-') || path.bytes().any(|byte| byte == 0) {
        bail!("invalid normalized Git path for blob read");
    }
    // `git show :path` addresses the staging index. The ordinary `REV:path`
    // spelling would turn its colon marker into the invalid `::path`.
    let object = if revision == ":" {
        format!(":{path}")
    } else {
        format!("{revision}:{path}")
    };
    let args = vec![
        "-c".into(),
        "core.pager=cat".into(),
        "-C".into(),
        root.to_string_lossy().into_owned(),
        "show".into(),
        "--no-textconv".into(),
        object,
    ];
    run_git_bounded(&args).with_context(|| format!("read Git blob {revision}:{path}"))
}

fn read_repo_source(root: &Path, relative: &str) -> Result<String> {
    let joined = root.join(relative);
    let resolved = joined
        .canonicalize()
        .with_context(|| format!("resolve changed source {relative:?}"))?;
    if !resolved.starts_with(root) {
        bail!("changed source {relative:?} resolves outside explicit Git root");
    }
    let mut file =
        File::open(&resolved).with_context(|| format!("open changed source {relative:?}"))?;
    let mut bytes = Vec::with_capacity(MAX_DIFF_SOURCE_BYTES.min(64 * 1024));
    file.by_ref()
        .take((MAX_DIFF_SOURCE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read changed source {relative:?}"))?;
    if bytes.len() > MAX_DIFF_SOURCE_BYTES {
        bail!("changed source {relative:?} exceeds {MAX_DIFF_SOURCE_BYTES} byte bound");
    }
    String::from_utf8(bytes).with_context(|| format!("changed source {relative:?} is not UTF-8"))
}

fn validate_git_ref(reference: &str) -> Result<()> {
    if reference.is_empty()
        || reference.len() > 1024
        || reference.starts_with('-')
        || reference
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        bail!("invalid explicit Git ref");
    }
    Ok(())
}

fn run_git_bounded(args: &[String]) -> Result<String> {
    let mut child = Command::new("git")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawn git diff")?;
    let overflow = Arc::new(AtomicBool::new(false));
    let stdout = child.stdout.take().context("capture git stdout")?;
    let stderr = child.stderr.take().context("capture git stderr")?;
    let output_overflow = Arc::clone(&overflow);
    let output = std::thread::spawn(move || read_capped(stdout, MAX_DIFF_BYTES, output_overflow));
    let errors_overflow = Arc::clone(&overflow);
    let errors =
        std::thread::spawn(move || read_capped(stderr, MAX_GIT_STDERR_BYTES, errors_overflow));
    let started = Instant::now();
    let mut timed_out = false;
    loop {
        if overflow.load(Ordering::Relaxed) {
            let _ = child.kill();
        }
        if started.elapsed() > GIT_DIFF_TIMEOUT {
            timed_out = true;
            let _ = child.kill();
        }
        if child.try_wait().context("poll git diff")?.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let status = child.wait().context("wait git diff")?;
    let output = output
        .join()
        .map_err(|_| anyhow::anyhow!("git stdout reader panicked"))??;
    let errors = errors
        .join()
        .map_err(|_| anyhow::anyhow!("git stderr reader panicked"))??;
    if timed_out {
        bail!(
            "git diff exceeded {} second timeout",
            GIT_DIFF_TIMEOUT.as_secs()
        );
    }
    if output.len() > MAX_DIFF_BYTES || errors.len() > MAX_GIT_STDERR_BYTES {
        bail!("git diff output exceeded configured bound");
    }
    if !status.success() {
        bail!("git diff failed: {}", String::from_utf8_lossy(&errors));
    }
    String::from_utf8(output).context("git diff emitted non-UTF-8 data")
}

fn read_capped<R: Read>(
    mut reader: R,
    maximum: usize,
    overflow: Arc<AtomicBool>,
) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut buffer = [0; 8192];
    loop {
        let count = reader.read(&mut buffer).context("read git output")?;
        if count == 0 {
            break;
        }
        let room = maximum.saturating_add(1).saturating_sub(bytes.len());
        bytes.extend_from_slice(&buffer[..count.min(room)]);
        if bytes.len() > maximum {
            overflow.store(true, Ordering::Relaxed);
            break;
        }
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn git(root: &Path, args: &[&str]) {
        let status = Command::new("git")
            .current_dir(root)
            .args(args)
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?} failed");
    }

    fn commit(root: &Path, message: &str) {
        git(root, &["add", "--all"]);
        git(
            root,
            &[
                "-c",
                "user.name=CRG Test",
                "-c",
                "user.email=crg@example.invalid",
                "commit",
                "-m",
                message,
            ],
        );
    }

    #[test]
    fn hunk_ranges_promote_the_containing_certified_declaration_extent() {
        let diff = parse_stdin_diff(concat!(
            "diff --git a/src/lib.rs b/src/lib.rs\n",
            "--- a/src/lib.rs\n",
            "+++ b/src/lib.rs\n",
            "@@ -1 +1 @@\n",
            "-fn changed() {}\n",
            "+fn changed() { body(); }\n",
            "@@ -2 +2 @@\n",
            "-    old();\n",
            "+    new();\n",
        ))
        .unwrap();
        let sources = BTreeMap::from([(
            "src/lib.rs".to_owned(),
            (Language::Rust, "fn changed() {\n    new();\n}\n".to_owned()),
        )]);
        let mapped = map_diff_to_impact_seeds(&diff.files, &sources);
        assert_eq!(
            mapped,
            vec![DiffImpactSeed {
                seed: ImpactSeed::symbol("src/lib.rs", "changed"),
                exact_symbol: true
            }]
        );

        let body_only = parse_stdin_diff(concat!(
            "diff --git a/src/lib.rs b/src/lib.rs\n",
            "--- a/src/lib.rs\n",
            "+++ b/src/lib.rs\n",
            "@@ -2 +2 @@\n",
            "-    old();\n",
            "+    new();\n",
        ))
        .unwrap();
        let mapped = map_diff_to_impact_seeds(&body_only.files, &sources);
        assert_eq!(
            mapped,
            vec![DiffImpactSeed {
                seed: ImpactSeed::symbol("src/lib.rs", "changed"),
                exact_symbol: true
            }]
        );
    }

    #[test]
    fn real_git_sources_cover_worktree_staged_committed_rename_binary_and_delete() {
        let dir = tempdir().unwrap();
        git(dir.path(), &["init"]);
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/lib.rs"), "fn initial() {}\n").unwrap();
        std::fs::write(dir.path().join("src/grüße.rs"), "fn hallo() {}\n").unwrap();
        std::fs::write(dir.path().join("delete.rs"), "fn deleted() {}\n").unwrap();
        std::fs::write(dir.path().join("asset.bin"), [0_u8, 159, 146, 150]).unwrap();
        commit(dir.path(), "initial");
        std::fs::write(dir.path().join("src/lib.rs"), "fn working() {}\n").unwrap();
        let worktree = acquire_git_diff(dir.path(), GitDiffSource::WorkingTree).unwrap();
        assert!(
            worktree
                .files
                .iter()
                .any(|f| f.new_path.as_deref() == Some("src/lib.rs"))
        );
        git(dir.path(), &["add", "src/lib.rs"]);
        let staged = acquire_git_diff(dir.path(), GitDiffSource::Staged).unwrap();
        let mapped = map_acquired_diff_to_impact_seeds(dir.path(), &staged).unwrap();
        assert_eq!(
            mapped,
            vec![DiffImpactSeed {
                seed: ImpactSeed::symbol("src/lib.rs", "working"),
                exact_symbol: true
            }]
        );
        // Commit the content edit before the rename so Git can identify the
        // following move by exact content rather than heuristic similarity.
        commit(dir.path(), "working declaration");
        git(dir.path(), &["mv", "src/lib.rs", "src/renamed.rs"]);
        git(dir.path(), &["rm", "delete.rs"]);
        std::fs::write(dir.path().join("src/grüße.rs"), "fn hallo_neu() {}\n").unwrap();
        std::fs::write(dir.path().join("asset.bin"), [0_u8, 159, 146, 151]).unwrap();
        git(dir.path(), &["add", "--all"]);
        let staged = acquire_git_diff(dir.path(), GitDiffSource::Staged).unwrap();
        assert!(staged.files.iter().any(|f| f.change == DiffChange::Renamed));
        assert!(staged.files.iter().any(|f| f.change == DiffChange::Deleted));
        assert!(staged.files.iter().any(|f| f.change == DiffChange::Binary));
        assert!(
            staged
                .files
                .iter()
                .any(|f| f.new_path.as_deref() == Some("src/grüße.rs"))
        );
        let seeds = map_acquired_diff_to_impact_seeds(dir.path(), &staged).unwrap();
        assert!(
            seeds
                .iter()
                .any(|s| s.seed == ImpactSeed::file("src/renamed.rs"))
        );
        assert!(
            seeds
                .iter()
                .any(|s| s.seed == ImpactSeed::symbol("delete.rs", "deleted"))
        );
        assert!(
            seeds
                .iter()
                .any(|s| s.seed == ImpactSeed::file("asset.bin"))
        );
        assert!(
            seeds
                .iter()
                .any(|s| s.seed == ImpactSeed::symbol("src/grüße.rs", "hallo_neu"))
        );
        commit(dir.path(), "rename delete binary");
        let committed = acquire_git_diff(
            dir.path(),
            GitDiffSource::Committed {
                base: "HEAD~1".into(),
                target: "HEAD".into(),
            },
        )
        .unwrap();
        assert!(!committed.files.is_empty());
        let committed_seeds = map_acquired_diff_to_impact_seeds(dir.path(), &committed).unwrap();
        assert!(
            committed_seeds
                .iter()
                .any(|s| s.seed == ImpactSeed::symbol("src/grüße.rs", "hallo_neu"))
        );
    }

    #[test]
    fn malicious_refs_and_external_symlinked_sources_fail_closed() {
        assert!(validate_git_ref("--output=/tmp/pwn").is_err());
        assert!(validate_git_ref("bad\nref").is_err());
        let dir = tempdir().unwrap();
        let outside = tempdir().unwrap();
        std::fs::write(outside.path().join("outside.rs"), "fn escaped() {}\n").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            outside.path().join("outside.rs"),
            dir.path().join("linked.rs"),
        )
        .unwrap();
        #[cfg(windows)]
        if std::os::windows::fs::symlink_file(
            outside.path().join("outside.rs"),
            dir.path().join("linked.rs"),
        )
        .is_err()
        {
            // Some locked-down Windows CI accounts cannot create a file
            // symlink. The production containment check is exercised where
            // the platform permits a reparse point.
            return;
        }
        let acquired = parse_stdin_diff(concat!(
            "diff --git a/linked.rs b/linked.rs\n",
            "--- a/linked.rs\n",
            "+++ b/linked.rs\n",
            "@@ -1 +1 @@\n",
            "-fn old() {}\n",
            "+fn escaped() {}\n",
        ))
        .unwrap();
        assert!(map_acquired_diff_to_impact_seeds(dir.path(), &acquired).is_err());
    }

    #[test]
    fn source_read_cap_is_enforced() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("large.rs"),
            "x".repeat(MAX_DIFF_SOURCE_BYTES + 1),
        )
        .unwrap();
        let acquired = parse_stdin_diff(concat!(
            "diff --git a/large.rs b/large.rs\n",
            "--- a/large.rs\n",
            "+++ b/large.rs\n",
            "@@ -1 +1 @@\n",
            "-x\n",
            "+y\n",
        ))
        .unwrap();
        assert!(map_acquired_diff_to_impact_seeds(dir.path(), &acquired).is_err());
    }

    #[test]
    fn source_admission_enforces_aggregate_limit_before_insertion() {
        let mut sources = BTreeMap::new();
        let mut retained = 0;
        admit_source(
            &mut sources,
            &mut retained,
            "one.rs",
            Language::Rust,
            "abc".to_owned(),
            5,
        )
        .unwrap();
        let error = admit_source(
            &mut sources,
            &mut retained,
            "two.rs",
            Language::Rust,
            "def".to_owned(),
            5,
        )
        .unwrap_err();
        assert!(error.to_string().contains("5-byte admission cap"));
        assert_eq!(retained, 3);
        assert_eq!(sources.len(), 1, "overflowing source was never retained");
    }

    #[test]
    fn indexed_extent_admission_enforces_native_symbol_limit_before_mapping() {
        let indexed = RepoMap {
            root: "/repo".to_owned(),
            files: vec![super::super::walker::RepoFile {
                path: "lib.rs".to_owned(),
                language: Language::Rust,
                bytes: 0,
                loc: 2,
                sha256: String::new(),
                mtime_ns: 0,
                symbols: vec![
                    super::super::symbols::Symbol {
                        name: "one".to_owned(),
                        kind: super::super::symbols::SymbolKind::Function,
                        line: 1,
                        line_end: Some(1),
                    },
                    super::super::symbols::Symbol {
                        name: "two".to_owned(),
                        kind: super::super::symbols::SymbolKind::Function,
                        line: 2,
                        line_end: Some(2),
                    },
                ],
            }],
            report: Default::default(),
        };
        let error = certified_extents_with_limit(&indexed, 1).unwrap_err();
        assert!(error.to_string().contains("1-symbol admission cap"));
        let extents = certified_extents_with_limit(&indexed, 2).unwrap();
        assert_eq!(extents["lib.rs"].len(), 2);
    }

    #[test]
    fn indexed_mapping_requires_the_persisted_certified_extent() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("lib.rs"),
            "fn changed() {\n    body();\n}\n",
        )
        .unwrap();
        let acquired = parse_stdin_diff(concat!(
            "diff --git a/lib.rs b/lib.rs\n",
            "--- a/lib.rs\n",
            "+++ b/lib.rs\n",
            "@@ -2 +2 @@\n",
            "-    old();\n",
            "+    body();\n",
        ))
        .unwrap();
        let indexed = RepoMap {
            root: dir.path().to_string_lossy().into_owned(),
            files: vec![super::super::walker::RepoFile {
                path: "lib.rs".into(),
                language: Language::Rust,
                bytes: 0,
                loc: 3,
                sha256: String::new(),
                mtime_ns: 0,
                symbols: vec![super::super::symbols::Symbol {
                    name: "changed".into(),
                    kind: super::super::symbols::SymbolKind::Function,
                    line: 1,
                    line_end: None,
                }],
            }],
            report: Default::default(),
        };
        let mapped =
            map_acquired_diff_to_indexed_impact_seeds(dir.path(), &acquired, &indexed).unwrap();
        assert_eq!(
            mapped,
            vec![DiffImpactSeed {
                seed: ImpactSeed::file("lib.rs"),
                exact_symbol: false
            }]
        );
    }

    #[test]
    fn nested_ranges_select_the_narrowest_certified_symbol_and_crossing_hunks_fall_back() {
        let source = concat!(
            "fn outer() {\n",
            "    fn inner() {\n",
            "        work();\n",
            "    }\n",
            "}\n",
        );
        let sources =
            BTreeMap::from([("nested.rs".to_owned(), (Language::Rust, source.to_owned()))]);
        let inner = parse_stdin_diff(concat!(
            "diff --git a/nested.rs b/nested.rs\n",
            "--- a/nested.rs\n",
            "+++ b/nested.rs\n",
            "@@ -3 +3 @@\n",
            "-        old();\n",
            "+        work();\n",
        ))
        .unwrap();
        assert_eq!(
            map_diff_to_impact_seeds(&inner.files, &sources),
            vec![DiffImpactSeed {
                seed: ImpactSeed::symbol("nested.rs", "inner"),
                exact_symbol: true
            }]
        );
        let crossing = parse_stdin_diff(concat!(
            "diff --git a/nested.rs b/nested.rs\n",
            "--- a/nested.rs\n",
            "+++ b/nested.rs\n",
            "@@ -4,2 +4,2 @@\n",
            "-    }\n",
            "-}\n",
            "+    }\n",
            "+}\n",
        ))
        .unwrap();
        assert_eq!(
            map_diff_to_impact_seeds(&crossing.files, &sources),
            vec![DiffImpactSeed {
                seed: ImpactSeed::symbol("nested.rs", "outer"),
                exact_symbol: true
            }]
        );
    }
}
