//! Verified, release-bound Graphify self-knowledge.
//!
//! A real release ships a `self-knowledge/` directory produced by
//! `scripts/build_release_self_knowledge.py`.  The release archive signature
//! authenticates that directory; this module additionally verifies its closed
//! file manifest before making any byte visible to recall or an Obsidian vault.
//!
//! The shipped baseline is never edited in place.  Each release is copied into
//! a version/HEAD-specific read-only directory, while operator and Self-Improve
//! notes live in a stable sibling `User Overlays/` directory that upgrades do
//! not touch.

use std::collections::{BTreeSet, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

pub const MANIFEST_FILE: &str = "manifest.json";
pub const RELEASE_KNOWLEDGE_DIR: &str = "Release Knowledge";
pub const USER_OVERLAYS_DIR: &str = "User Overlays";
pub const RECALL_SCOPE: &str = "neoth-release-self-knowledge";
pub const OVERLAY_RECALL_SCOPE: &str = "neoth-release-self-knowledge-overlays";

pub(crate) const OPERATOR_NOTES_DIR: &str = "Operator Notes";
pub(crate) const REVIEWED_SELF_IMPROVE_DIR: &str = "Reviewed Self-Improve";
pub(crate) const SELF_IMPROVE_PROPOSALS_DIR: &str = "Self-Improve Proposals";

const SCHEMA_VERSION: u32 = 1;
const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
const MAX_FILES: usize = 100_000;
const MAX_TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_INGEST_MARKDOWN_BYTES: u64 = 64 * 1024 * 1024;
const MAX_INGEST_CLAIMS: usize = 20_000;
const MAX_OVERLAY_FILES: usize = 10_000;
const MAX_OVERLAY_MARKDOWN_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseSnapshotManifest {
    pub schema_version: u32,
    pub product: String,
    pub release_version: String,
    pub source_head: String,
    pub source_tree_sha256: String,
    pub generated_at: String,
    pub graphify_version: String,
    pub graphify_backend: String,
    pub graphify_model: String,
    pub graphify_distribution: String,
    pub graphify_toolchain_sha256: String,
    pub node_count: u64,
    pub edge_count: u64,
    pub payload_sha256: String,
    pub files: Vec<ReleaseSnapshotFile>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseSnapshotFile {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
    pub role: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceManifestIdentity {
    schema_version: u32,
    source_head: String,
    source_tree_sha256: String,
    files: Vec<SourceManifestFileIdentity>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceManifestFileIdentity {
    path: String,
    bytes: u64,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GenerationReceiptIdentity {
    schema_version: u32,
    source_head_before: String,
    source_head_after: String,
    started_unix_ns: u64,
    finished_unix_ns: u64,
    graphify_version: String,
    graphify_backend: String,
    graphify_model: String,
    graphify_distribution: String,
    graphify_toolchain_sha256: String,
    toolchain: GenerationToolchainIdentity,
    pipeline: Vec<Vec<String>>,
    node_count: u64,
    edge_count: u64,
    graphify_file_count: usize,
    semantic_file_count: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GenerationToolchainIdentity {
    schema_version: u32,
    python_implementation: String,
    python_version: String,
    rustc_verbose_version: String,
    cargo_version: String,
    packages: Vec<GenerationToolchainPackage>,
    inventory_sha256: String,
    graphify_distribution: String,
    graphify_distribution_version: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GenerationToolchainPackage {
    name: String,
    version: String,
}

#[derive(Clone, Copy)]
enum ManifestBinding<'a> {
    CurrentBinary,
    UpdateTarget(&'a str),
}

#[derive(Clone, Debug)]
pub struct VerifiedReleaseSnapshot {
    root: PathBuf,
    manifest: ReleaseSnapshotManifest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaterializedReleaseSnapshot {
    pub baseline_dir: PathBuf,
    pub overlays_dir: PathBuf,
    pub files: usize,
    pub already_present: bool,
}

impl VerifiedReleaseSnapshot {
    /// Open and fully verify a release snapshot. Unknown fields, unlisted
    /// files, symlinks, traversal paths, hash drift, and build identity drift
    /// all fail closed.
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_binding(root.as_ref(), ManifestBinding::CurrentBinary)
    }

    /// Verify a snapshot extracted for an update before the old binary swaps
    /// it into place. Archive authentication remains the updater's outer trust
    /// boundary; this applies the same inner closed-set/provenance checks as
    /// [`Self::open`] while binding to the exact target tag/version instead of
    /// the currently-running binary's version and compile-time digests.
    pub(crate) fn open_for_update(
        root: impl AsRef<Path>,
        expected_release_version: &str,
    ) -> Result<Self> {
        let expected_release_version = normalise_target_version(expected_release_version)?;
        Self::open_with_binding(
            root.as_ref(),
            ManifestBinding::UpdateTarget(expected_release_version),
        )
    }

    fn open_with_binding(root: &Path, binding: ManifestBinding<'_>) -> Result<Self> {
        let root = root.to_path_buf();
        let metadata = fs::symlink_metadata(&root)
            .with_context(|| format!("read self-knowledge root {}", root.display()))?;
        if metadata_is_link_like(&metadata) || !metadata.is_dir() {
            anyhow::bail!(
                "release self-knowledge root must be a non-symlink directory: {}",
                root.display()
            );
        }

        let manifest_path = root.join(MANIFEST_FILE);
        let manifest_meta = regular_file_metadata(&manifest_path)?;
        if manifest_meta.len() == 0 || manifest_meta.len() > MAX_MANIFEST_BYTES {
            anyhow::bail!(
                "release self-knowledge manifest has invalid size: {} bytes",
                manifest_meta.len()
            );
        }
        let manifest: ReleaseSnapshotManifest = serde_json::from_reader(BufReader::new(
            File::open(&manifest_path).context("open release self-knowledge manifest")?,
        ))
        .context("parse release self-knowledge manifest")?;
        validate_manifest_identity(&manifest, binding)?;

        let mut previous = "";
        let mut listed = BTreeSet::new();
        let mut portable_paths = HashSet::new();
        let mut roles = std::collections::BTreeMap::<&str, usize>::new();
        let mut payload_hasher = Sha256::new();
        let mut total_bytes = 0_u64;
        let mut wiki_markdown = 0_usize;
        let mut obsidian_markdown = 0_usize;
        for entry in &manifest.files {
            validate_relative_path(&entry.path)?;
            let portable_path = portable_path_key(&entry.path)?;
            if entry.path.as_str() <= previous
                || !listed.insert(entry.path.clone())
                || !portable_paths.insert(portable_path)
            {
                anyhow::bail!(
                    "release self-knowledge files must be portable, strictly sorted, and unique"
                );
            }
            previous = &entry.path;
            if !valid_sha256(&entry.sha256) {
                anyhow::bail!("invalid SHA-256 for self-knowledge file {}", entry.path);
            }
            let expected_role = role_for_path(&entry.path)?;
            if entry.role != expected_role {
                anyhow::bail!(
                    "self-knowledge role mismatch for {}: {:?} != {:?}",
                    entry.path,
                    entry.role,
                    expected_role
                );
            }
            total_bytes = total_bytes
                .checked_add(entry.bytes)
                .ok_or_else(|| anyhow::anyhow!("self-knowledge byte count overflow"))?;
            if total_bytes > MAX_TOTAL_BYTES {
                anyhow::bail!("release self-knowledge exceeds the 2 GiB safety ceiling");
            }
            let path = safe_join(&root, &entry.path)?;
            let file_meta = regular_file_metadata(&path)?;
            if file_meta.len() != entry.bytes {
                anyhow::bail!("self-knowledge size mismatch for {}", entry.path);
            }
            if sha256_file(&path)? != entry.sha256 {
                anyhow::bail!("self-knowledge SHA-256 mismatch for {}", entry.path);
            }
            payload_hasher.update(entry.path.as_bytes());
            payload_hasher.update(b"\0");
            payload_hasher.update(entry.sha256.as_bytes());
            payload_hasher.update(b"\0");
            payload_hasher.update(entry.bytes.to_string().as_bytes());
            payload_hasher.update(b"\0");
            payload_hasher.update(entry.role.as_bytes());
            payload_hasher.update(b"\n");
            *roles.entry(entry.role.as_str()).or_default() += 1;
            if entry.bytes > 0 && entry.path.to_ascii_lowercase().ends_with(".md") {
                if entry.role == "wiki" {
                    wiki_markdown += 1;
                } else if entry.role == "obsidian" {
                    obsidian_markdown += 1;
                }
            }
        }
        if hex::encode(payload_hasher.finalize()) != manifest.payload_sha256 {
            anyhow::bail!("release self-knowledge payload hash mismatch");
        }

        require_singleton(&listed, &roles, "graph.json", "graph")?;
        require_singleton(&listed, &roles, "GRAPH_REPORT.md", "report")?;
        require_singleton(&listed, &roles, "graph.html", "html")?;
        require_singleton(
            &listed,
            &roles,
            "graphify-manifest.json",
            "graphify_manifest",
        )?;
        require_singleton(&listed, &roles, "SOURCE_MANIFEST.json", "source_manifest")?;
        require_singleton(
            &listed,
            &roles,
            "GENERATION_RECEIPT.json",
            "generation_receipt",
        )?;
        require_path(&listed, "graph.svg")?;
        require_path(&listed, "graph.graphml")?;
        require_singleton(&listed, &roles, "BASELINE_READ_ONLY.md", "operator_guide")?;
        for required in [
            "graph.json",
            "GRAPH_REPORT.md",
            "graph.html",
            "graph.svg",
            "graph.graphml",
            "graphify-manifest.json",
            "SOURCE_MANIFEST.json",
            "GENERATION_RECEIPT.json",
            "BASELINE_READ_ONLY.md",
        ] {
            if manifest
                .files
                .iter()
                .find(|entry| entry.path == required)
                .is_none_or(|entry| entry.bytes == 0)
            {
                anyhow::bail!("required release self-knowledge file is empty: {required}");
            }
        }
        if wiki_markdown == 0 || obsidian_markdown == 0 {
            anyhow::bail!("release self-knowledge requires non-empty Wiki and Obsidian Markdown");
        }

        let actual = collect_payload_paths(&root)?;
        if actual != listed {
            anyhow::bail!(
                "release self-knowledge closed file set mismatch (unlisted or missing files)"
            );
        }
        verify_generation_identity(&root, &manifest)?;

        Ok(Self { root, manifest })
    }

    /// Discover the installed snapshot without trusting the process CWD.
    /// `NEOTH_SELF_KNOWLEDGE_DIR` is an explicit operator/test override; normal
    /// candidates cover portable archives, Linux packages, Windows installs,
    /// and macOS app bundles.
    pub fn discover() -> Result<Option<Self>> {
        Self::discover_from(
            std::env::var_os("NEOTH_SELF_KNOWLEDGE_DIR"),
            std::env::current_exe().ok(),
        )
    }

    fn discover_from(
        explicit: Option<std::ffi::OsString>,
        executable: Option<PathBuf>,
    ) -> Result<Option<Self>> {
        let mut candidates = Vec::new();
        if let Some(explicit) = explicit {
            if explicit.is_empty() {
                anyhow::bail!("NEOTH_SELF_KNOWLEDGE_DIR is set but empty");
            }
            let explicit = PathBuf::from(explicit);
            return Self::open(&explicit).map(Some).with_context(|| {
                format!(
                    "explicit NEOTH_SELF_KNOWLEDGE_DIR failed verification: {}",
                    explicit.display()
                )
            });
        }
        if let Some(executable) = executable {
            candidates.extend(installed_candidates_for_executable(&executable));
            // macOS packages expose `/usr/local/bin/neoth` as a symlink into
            // `NEOTH.app/Contents/MacOS`. `_NSGetExecutablePath` may preserve
            // that launch path, so search both the raw executable location and
            // its canonical app-bundle target. Verification still binds every
            // discovered snapshot to the compiled release identity.
            if let Ok(canonical) = fs::canonicalize(&executable)
                && canonical != executable
            {
                candidates.extend(installed_candidates_for_executable(&canonical));
            }
        }
        #[cfg(unix)]
        candidates.push(PathBuf::from("/usr/share/neoth/self-knowledge"));

        let mut seen = HashSet::new();
        for candidate in candidates {
            let key = candidate.to_string_lossy().into_owned();
            if !seen.insert(key) {
                continue;
            }
            match fs::symlink_metadata(&candidate) {
                Ok(_) => return Self::open(&candidate).map(Some),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "inspect release self-knowledge candidate {}",
                            candidate.display()
                        )
                    });
                }
            }
        }
        Ok(None)
    }

    pub fn manifest(&self) -> &ReleaseSnapshotManifest {
        &self.manifest
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Copy the verified baseline into the operator's wiki. Existing baselines
    /// are verified, never repaired in place; a corrupt copy therefore fails
    /// loudly. A new release gets a new HEAD-bound directory. The stable
    /// `User Overlays` sibling is create-only and never removed or overwritten.
    pub fn materialize_into(&self, wiki_dir: &Path) -> Result<MaterializedReleaseSnapshot> {
        ensure_real_directory(wiki_dir)
            .with_context(|| format!("create self-wiki directory {}", wiki_dir.display()))?;
        let releases_dir = wiki_dir.join(RELEASE_KNOWLEDGE_DIR);
        ensure_real_directory(&releases_dir)
            .with_context(|| format!("create release knowledge dir {}", releases_dir.display()))?;
        let short_head = &self.manifest.source_head[..12];
        let identity = format!(
            "{}-{}",
            safe_version_component(&self.manifest.release_version)?,
            short_head
        );
        let baseline_dir = releases_dir.join(identity);
        let already_present = match fs::symlink_metadata(&baseline_dir) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("inspect release baseline {}", baseline_dir.display())
                });
            }
        };
        if already_present {
            let installed = Self::open(&baseline_dir)
                .context("verify already-materialized release self-knowledge")?;
            if installed.manifest.payload_sha256 != self.manifest.payload_sha256 {
                anyhow::bail!(
                    "materialized release self-knowledge identity collides with different bytes"
                );
            }
        } else {
            self.copy_new_baseline(&releases_dir, &baseline_dir)?;
        }

        let overlays_dir = wiki_dir.join(USER_OVERLAYS_DIR);
        ensure_real_directory(&overlays_dir)
            .with_context(|| format!("create user overlay dir {}", overlays_dir.display()))?;
        for subdir in [
            OPERATOR_NOTES_DIR,
            REVIEWED_SELF_IMPROVE_DIR,
            SELF_IMPROVE_PROPOSALS_DIR,
        ] {
            ensure_real_directory(&overlays_dir.join(subdir))
                .with_context(|| format!("create self-knowledge overlay subdir {subdir}"))?;
        }
        let overlay_readme = overlays_dir.join("README.md");
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&overlay_readme)
        {
            Ok(mut file) => {
                use std::io::Write;
                file.write_all(
                    b"# NEOTH self-knowledge overlays\n\n\
The sibling `Release Knowledge` directory is the immutable release-signed baseline. \
NEOTH upgrades never overwrite this directory or any file below it.\n\n\
- Put explicit operator corrections in `Operator Notes/`. Declarative Markdown \
  there is ingested as operator-attested self-knowledge.\n\
- Move an accepted Self-Improve architecture note into `Reviewed Self-Improve/`. \
  Only this reviewed directory is ingested.\n\
- `Self-Improve Proposals/` is advisory staging only: NEOTH never ingests, applies, \
  or promotes those files automatically. Code and policy changes remain behind \
  their normal review gates.\n",
                )
                .context("write self-knowledge overlay README")?;
                file.sync_all()
                    .context("sync self-knowledge overlay README")?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error).context("create self-knowledge overlay README"),
        }

        Ok(MaterializedReleaseSnapshot {
            baseline_dir,
            overlays_dir,
            files: self.manifest.files.len() + 1,
            already_present,
        })
    }

    fn copy_new_baseline(&self, parent: &Path, destination: &Path) -> Result<()> {
        let stage = parent.join(format!(
            ".self-knowledge-{}-{}",
            std::process::id(),
            crate::time::now_unix_ns()
        ));
        fs::create_dir(&stage)
            .with_context(|| format!("create self-knowledge stage {}", stage.display()))?;
        let result = (|| {
            for entry in &self.manifest.files {
                let source = safe_join(&self.root, &entry.path)?;
                let target = safe_join(&stage, &entry.path)?;
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent).with_context(|| {
                        format!("create self-knowledge parent {}", parent.display())
                    })?;
                }
                fs::copy(&source, &target).with_context(|| {
                    format!(
                        "copy release self-knowledge {} -> {}",
                        source.display(),
                        target.display()
                    )
                })?;
            }
            fs::copy(self.root.join(MANIFEST_FILE), stage.join(MANIFEST_FILE))
                .context("copy release self-knowledge manifest as commit point")?;
            let staged = Self::open(&stage).context("verify staged release self-knowledge")?;
            if staged.manifest.payload_sha256 != self.manifest.payload_sha256 {
                anyhow::bail!("staged self-knowledge payload identity changed during copy");
            }
            set_tree_read_only(&stage)?;
            match fs::rename(&stage, destination) {
                Ok(()) => Ok(()),
                // Windows commonly reports a destination race as
                // PermissionDenied instead of AlreadyExists. Inspect the
                // destination after *any* rename failure and accept only an
                // independently verified byte-identical snapshot.
                Err(rename_error) => match fs::symlink_metadata(destination) {
                    Ok(_) => {
                        let raced = Self::open(destination)
                            .context("verify concurrently materialized release self-knowledge")?;
                        if raced.manifest.payload_sha256 != self.manifest.payload_sha256 {
                            anyhow::bail!(
                                "concurrent self-knowledge materialization wrote different bytes"
                            );
                        }
                        Ok(())
                    }
                    Err(inspect_error) if inspect_error.kind() == std::io::ErrorKind::NotFound => {
                        Err(rename_error).with_context(|| {
                            format!(
                                "commit release self-knowledge {} -> {}",
                                stage.display(),
                                destination.display()
                            )
                        })
                    }
                    Err(inspect_error) => Err(inspect_error).with_context(|| {
                        format!(
                            "inspect destination after self-knowledge rename failed: {}",
                            destination.display()
                        )
                    }),
                },
            }
        })();
        if stage.exists() {
            let _ = make_tree_writable(&stage);
            let _ = fs::remove_dir_all(&stage);
        }
        result
    }

    /// Refresh recall from the verified report + Wiki/Obsidian Markdown.
    /// The revoke-and-insert pass is one SQLite transaction, so recall never
    /// observes a partial release snapshot.
    pub fn ingest_into(&self, conn: &rusqlite::Connection, now_ns: i64) -> Result<usize> {
        let claims = self.recall_claims()?;

        let tx = conn
            .unchecked_transaction()
            .context("begin release self-knowledge ingest transaction")?;
        for prior in crate::memory::groundtruth::list_for_scope(&tx, RECALL_SCOPE)? {
            if prior.revoked_at.is_none() {
                crate::memory::groundtruth::revoke(&tx, prior.id, now_ns)?;
            }
        }
        crate::memory::groundtruth::insert(
            &tx,
            &claims[0],
            &crate::memory::groundtruth::Source::ReleaseBuildIdentity,
            RECALL_SCOPE,
            now_ns,
        )?;
        for statement in &claims[1..] {
            crate::memory::groundtruth::insert(
                &tx,
                statement,
                &crate::memory::groundtruth::Source::ReleaseSelfKnowledge,
                RECALL_SCOPE,
                now_ns,
            )?;
        }
        tx.commit()
            .context("commit release self-knowledge ingest transaction")?;
        Ok(claims.len())
    }

    /// Exercise the exact bounded recall parser without opening the operator's
    /// database or mutating any materialized state. Release assembly calls this
    /// through `neoth self-knowledge verify`, ensuring an artifact cannot pass
    /// cryptographic verification yet fail on its first daemon ingest.
    pub fn validate_recall_payload(&self) -> Result<usize> {
        Ok(self.recall_claims()?.len())
    }

    fn recall_claims(&self) -> Result<Vec<String>> {
        let mut markdown_bytes = 0_u64;
        let mut claims = Vec::new();
        let mut seen = HashSet::new();
        let identity = format!(
            "NEOTH release {} self-knowledge is bound to source HEAD {} and payload SHA-256 {} with {} graph nodes and {} edges.",
            self.manifest.release_version,
            self.manifest.source_head,
            self.manifest.payload_sha256,
            self.manifest.node_count,
            self.manifest.edge_count
        );
        seen.insert(crate::memory::bulk_text::normalise_for_dedup(&identity));
        claims.push(identity);

        for entry in &self.manifest.files {
            if entry.role != "report" && entry.role != "wiki" && entry.role != "obsidian" {
                continue;
            }
            if !entry.path.to_ascii_lowercase().ends_with(".md") {
                continue;
            }
            markdown_bytes = markdown_bytes
                .checked_add(entry.bytes)
                .ok_or_else(|| anyhow::anyhow!("release self-knowledge ingest size overflow"))?;
            if markdown_bytes > MAX_INGEST_MARKDOWN_BYTES {
                anyhow::bail!("release self-knowledge Markdown exceeds the 64 MiB ingest ceiling");
            }
            // Re-open, bound the read, and re-hash against the verified
            // manifest immediately before extraction. `open()` verification
            // alone is insufficient because the baseline may drift between
            // initial verification and a later cron ingest.
            let text = read_verified_utf8(&self.root, entry)?;
            for claim in crate::memory::bulk_text::extract_claims_heuristic(&text) {
                let normalised = crate::memory::bulk_text::normalise_for_dedup(&claim.statement);
                if seen.insert(normalised) {
                    claims.push(claim.statement);
                    if claims.len() > MAX_INGEST_CLAIMS {
                        anyhow::bail!(
                            "release self-knowledge exceeds the 20,000-claim ingest ceiling"
                        );
                    }
                }
            }
        }
        if claims.len() == 1 {
            anyhow::bail!("release self-knowledge yielded no recallable Markdown claims");
        }
        Ok(claims)
    }

    /// Refresh the persistent operator overlay recall scope. Only Markdown
    /// below `Operator Notes/` and `Reviewed Self-Improve/` is considered.
    /// `Self-Improve Proposals/` is deliberately outside this traversal and
    /// can never be promoted merely by being generated.
    pub fn ingest_overlays_into(
        &self,
        overlays_dir: &Path,
        conn: &rusqlite::Connection,
        now_ns: i64,
    ) -> Result<usize> {
        let files = collect_overlay_markdown(overlays_dir)?;
        let mut claims = Vec::new();
        let mut seen = HashSet::new();
        for (path, expected_bytes) in files {
            let text = read_overlay_utf8(&path, expected_bytes)?;
            for claim in crate::memory::bulk_text::extract_claims_heuristic(&text) {
                let normalised = crate::memory::bulk_text::normalise_for_dedup(&claim.statement);
                if seen.insert(normalised) {
                    claims.push(claim.statement);
                    if claims.len() > MAX_INGEST_CLAIMS {
                        anyhow::bail!(
                            "self-knowledge overlays exceed the 20,000-claim ingest ceiling"
                        );
                    }
                }
            }
        }

        let tx = conn
            .unchecked_transaction()
            .context("begin self-knowledge overlay ingest transaction")?;
        for prior in crate::memory::groundtruth::list_for_scope(&tx, OVERLAY_RECALL_SCOPE)? {
            if prior.revoked_at.is_none() {
                crate::memory::groundtruth::revoke(&tx, prior.id, now_ns)?;
            }
        }
        for statement in &claims {
            crate::memory::groundtruth::insert(
                &tx,
                statement,
                &crate::memory::groundtruth::Source::SelfKnowledgeOverlay,
                OVERLAY_RECALL_SCOPE,
                now_ns,
            )?;
        }
        tx.commit()
            .context("commit self-knowledge overlay ingest transaction")?;
        Ok(claims.len())
    }
}

/// Installation-owned snapshot locations derived solely from the executable.
/// Updaters must use these candidates rather than the writable
/// `NEOTH_SELF_KNOWLEDGE_DIR` read override.
pub(crate) fn installed_candidates_for_executable(executable: &Path) -> Vec<PathBuf> {
    let Some(bin_dir) = executable.parent() else {
        return Vec::new();
    };
    vec![
        bin_dir
            .join(crate::updater::release_bundle::PORTABLE_SUPPORT_DIR)
            .join("self-knowledge"),
        bin_dir.join("self-knowledge"),
        bin_dir
            .join("..")
            .join("share")
            .join("neoth")
            .join("self-knowledge"),
        bin_dir.join("..").join("Resources").join("self-knowledge"),
    ]
}

fn read_verified_utf8(root: &Path, entry: &ReleaseSnapshotFile) -> Result<String> {
    let path = safe_join(root, &entry.path)?;
    let before = regular_file_metadata(&path)?;
    if before.len() != entry.bytes {
        anyhow::bail!(
            "self-knowledge size changed before ingest for {}",
            entry.path
        );
    }
    let file = File::open(&path)
        .with_context(|| format!("open self-knowledge Markdown {}", entry.path))?;
    let opened = file
        .metadata()
        .with_context(|| format!("inspect opened self-knowledge Markdown {}", entry.path))?;
    if !opened.is_file() || opened.len() != entry.bytes {
        anyhow::bail!("self-knowledge file changed while opening {}", entry.path);
    }
    let limit = entry
        .bytes
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("self-knowledge ingest byte limit overflow"))?;
    let mut bytes = Vec::with_capacity(entry.bytes.min(MAX_INGEST_MARKDOWN_BYTES) as usize);
    file.take(limit)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read self-knowledge Markdown {}", entry.path))?;
    let after = regular_file_metadata(&path)?;
    if bytes.len() as u64 != entry.bytes || after.len() != entry.bytes {
        anyhow::bail!(
            "self-knowledge size changed during ingest for {}",
            entry.path
        );
    }
    if hex::encode(Sha256::digest(&bytes)) != entry.sha256 {
        anyhow::bail!(
            "self-knowledge SHA-256 changed during ingest for {}",
            entry.path
        );
    }
    String::from_utf8(bytes)
        .with_context(|| format!("self-knowledge Markdown is not UTF-8: {}", entry.path))
}

fn collect_overlay_markdown(overlays_dir: &Path) -> Result<Vec<(PathBuf, u64)>> {
    collect_overlay_markdown_with_limits(
        overlays_dir,
        MAX_OVERLAY_FILES,
        MAX_OVERLAY_MARKDOWN_BYTES,
    )
}

fn collect_overlay_markdown_with_limits(
    overlays_dir: &Path,
    max_entries: usize,
    max_markdown_bytes: u64,
) -> Result<Vec<(PathBuf, u64)>> {
    let root_metadata = fs::symlink_metadata(overlays_dir)
        .with_context(|| format!("inspect self-knowledge overlays {}", overlays_dir.display()))?;
    if metadata_is_link_like(&root_metadata) || !root_metadata.is_dir() {
        anyhow::bail!(
            "self-knowledge overlays must be a non-symlink directory: {}",
            overlays_dir.display()
        );
    }

    // Validate the excluded staging root itself, but intentionally never walk
    // its contents. This makes the non-ingestion boundary obvious in code.
    for name in [
        OPERATOR_NOTES_DIR,
        REVIEWED_SELF_IMPROVE_DIR,
        SELF_IMPROVE_PROPOSALS_DIR,
    ] {
        let path = overlays_dir.join(name);
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("inspect self-knowledge overlay root {}", path.display()))?;
        if metadata_is_link_like(&metadata) || !metadata.is_dir() {
            anyhow::bail!("overlay root must be a real directory: {}", path.display());
        }
    }

    fn visit(
        root: &Path,
        current: &Path,
        seen_paths: &mut HashSet<String>,
        visited_entries: &mut usize,
        markdown_bytes: &mut u64,
        files: &mut Vec<(PathBuf, u64)>,
        max_entries: usize,
        max_markdown_bytes: u64,
    ) -> Result<()> {
        for entry in fs::read_dir(current)
            .with_context(|| format!("read self-knowledge overlay dir {}", current.display()))?
        {
            let path = entry?.path();
            *visited_entries = visited_entries
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("overlay entry count overflow"))?;
            if *visited_entries > max_entries {
                anyhow::bail!("self-knowledge overlays exceed their entry ceiling");
            }
            let metadata = fs::symlink_metadata(&path)?;
            if metadata_is_link_like(&metadata) {
                anyhow::bail!(
                    "symlink/reparse point in self-knowledge overlays: {}",
                    path.display()
                );
            }
            let relative = path
                .strip_prefix(root)
                .context("self-knowledge overlay walk escaped its root")?
                .components()
                .map(|component| component.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            validate_relative_path(&relative)?;
            let scoped_relative = format!(
                "{}/{}",
                root.file_name()
                    .and_then(|name| name.to_str())
                    .context("overlay root name is not UTF-8")?,
                relative
            );
            if !seen_paths.insert(portable_path_key(&scoped_relative)?) {
                anyhow::bail!("portable path collision in self-knowledge overlays: {relative}");
            }
            if metadata.is_dir() {
                visit(
                    root,
                    &path,
                    seen_paths,
                    visited_entries,
                    markdown_bytes,
                    files,
                    max_entries,
                    max_markdown_bytes,
                )?;
            } else if metadata.is_file() {
                if path
                    .extension()
                    .and_then(|extension| extension.to_str())
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("md"))
                {
                    *markdown_bytes = markdown_bytes
                        .checked_add(metadata.len())
                        .ok_or_else(|| anyhow::anyhow!("overlay Markdown byte count overflow"))?;
                    if *markdown_bytes > max_markdown_bytes {
                        anyhow::bail!("self-knowledge overlay Markdown exceeds its byte ceiling");
                    }
                    files.push((path, metadata.len()));
                }
            } else {
                anyhow::bail!(
                    "non-regular entry in self-knowledge overlays: {}",
                    path.display()
                );
            }
        }
        Ok(())
    }

    let mut files = Vec::new();
    let mut seen_paths = HashSet::new();
    let mut visited_entries = 0_usize;
    let mut markdown_bytes = 0_u64;
    for name in [OPERATOR_NOTES_DIR, REVIEWED_SELF_IMPROVE_DIR] {
        let root = overlays_dir.join(name);
        visit(
            &root,
            &root,
            &mut seen_paths,
            &mut visited_entries,
            &mut markdown_bytes,
            &mut files,
            max_entries,
            max_markdown_bytes,
        )?;
    }
    files.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(files)
}

fn read_overlay_utf8(path: &Path, expected_bytes: u64) -> Result<String> {
    let before = regular_file_metadata(path)?;
    if before.len() != expected_bytes {
        anyhow::bail!(
            "self-knowledge overlay changed before ingest: {}",
            path.display()
        );
    }
    let file = File::open(path)
        .with_context(|| format!("open self-knowledge overlay {}", path.display()))?;
    let opened = file.metadata()?;
    if !opened.is_file() || opened.len() != expected_bytes {
        anyhow::bail!(
            "self-knowledge overlay changed while opening: {}",
            path.display()
        );
    }
    let limit = expected_bytes
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("overlay ingest byte limit overflow"))?;
    let mut bytes = Vec::with_capacity(expected_bytes.min(MAX_OVERLAY_MARKDOWN_BYTES) as usize);
    file.take(limit)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read self-knowledge overlay {}", path.display()))?;
    let after = regular_file_metadata(path)?;
    if bytes.len() as u64 != expected_bytes || after.len() != expected_bytes {
        anyhow::bail!(
            "self-knowledge overlay changed during ingest: {}",
            path.display()
        );
    }
    String::from_utf8(bytes)
        .with_context(|| format!("self-knowledge overlay is not UTF-8: {}", path.display()))
}

fn validate_manifest_identity(
    manifest: &ReleaseSnapshotManifest,
    binding: ManifestBinding<'_>,
) -> Result<()> {
    if manifest.schema_version != SCHEMA_VERSION || manifest.product != "NEOTH" {
        anyhow::bail!("unsupported release self-knowledge schema/product");
    }
    if manifest.release_version.trim().is_empty()
        || manifest.generated_at.trim().is_empty()
        || manifest.graphify_version.trim().is_empty()
        || manifest.graphify_backend.trim().is_empty()
        || manifest.graphify_model.trim().is_empty()
        || manifest.graphify_distribution.trim().is_empty()
        || manifest
            .graphify_version
            .to_ascii_lowercase()
            .contains("unknown")
    {
        anyhow::bail!("release self-knowledge identity fields must be non-empty");
    }
    if manifest.files.is_empty() || manifest.files.len() > MAX_FILES {
        anyhow::bail!("release self-knowledge file count is invalid");
    }
    let parsed_release = semver::Version::parse(&manifest.release_version)
        .context("release self-knowledge version is not SemVer")?;
    if parsed_release.to_string() != manifest.release_version {
        anyhow::bail!("release self-knowledge version is not canonical SemVer");
    }
    if !valid_head(&manifest.source_head)
        || !valid_sha256(&manifest.source_tree_sha256)
        || !valid_sha256(&manifest.payload_sha256)
        || !valid_sha256(&manifest.graphify_toolchain_sha256)
    {
        anyhow::bail!("release self-knowledge contains an invalid identity digest");
    }
    if manifest.node_count == 0 || manifest.edge_count == 0 {
        anyhow::bail!("release self-knowledge graph counters must be non-zero");
    }
    match binding {
        ManifestBinding::CurrentBinary => {
            if manifest.release_version != env!("CARGO_PKG_VERSION") {
                anyhow::bail!(
                    "release self-knowledge version {} does not match running NEOTH {}",
                    manifest.release_version,
                    env!("CARGO_PKG_VERSION")
                );
            }
            validate_compiled_bindings(
                manifest,
                option_env!("NEOTH_SOURCE_HEAD"),
                option_env!("NEOTH_SELF_KNOWLEDGE_PAYLOAD_SHA256"),
                !cfg!(debug_assertions),
            )?;
        }
        ManifestBinding::UpdateTarget(expected_version) => {
            if manifest.release_version != expected_version {
                anyhow::bail!(
                    "release self-knowledge version {} does not match update target {}",
                    manifest.release_version,
                    expected_version
                );
            }
        }
    }
    Ok(())
}

fn validate_compiled_bindings(
    manifest: &ReleaseSnapshotManifest,
    compiled_head: Option<&str>,
    compiled_payload: Option<&str>,
    require_bindings: bool,
) -> Result<()> {
    match compiled_head {
        Some(value) if !valid_head(value) => {
            anyhow::bail!("compiled NEOTH_SOURCE_HEAD is not a lowercase Git object id")
        }
        Some(value) if manifest.source_head != value => anyhow::bail!(
            "release self-knowledge HEAD {} does not match compiled HEAD {}",
            manifest.source_head,
            value
        ),
        Some(_) => {}
        None if require_bindings => {
            anyhow::bail!("release binary is missing its NEOTH_SOURCE_HEAD binding")
        }
        None => {}
    }
    match compiled_payload {
        Some(value) if !valid_sha256(value) => {
            anyhow::bail!("compiled NEOTH_SELF_KNOWLEDGE_PAYLOAD_SHA256 is not a lowercase SHA-256")
        }
        Some(value) if manifest.payload_sha256 != value => anyhow::bail!(
            "release self-knowledge payload {} does not match compiled payload {}",
            manifest.payload_sha256,
            value
        ),
        Some(_) => {}
        None if require_bindings => anyhow::bail!(
            "release binary is missing its NEOTH_SELF_KNOWLEDGE_PAYLOAD_SHA256 binding"
        ),
        None => {}
    }
    Ok(())
}

fn normalise_target_version(raw: &str) -> Result<&str> {
    if raw.trim() != raw {
        anyhow::bail!("update target version contains leading or trailing whitespace");
    }
    let version = raw.strip_prefix('v').unwrap_or(raw);
    let parsed = semver::Version::parse(version).context("update target version is not SemVer")?;
    if parsed.to_string() != version {
        anyhow::bail!("update target version is not canonical SemVer");
    }
    Ok(version)
}

fn verify_generation_identity(root: &Path, manifest: &ReleaseSnapshotManifest) -> Result<()> {
    let source: SourceManifestIdentity = serde_json::from_reader(BufReader::new(File::open(
        root.join("SOURCE_MANIFEST.json"),
    )?))
    .context("parse SOURCE_MANIFEST.json identity")?;
    if source.schema_version != SCHEMA_VERSION
        || source.source_head != manifest.source_head
        || source.source_tree_sha256 != manifest.source_tree_sha256
    {
        anyhow::bail!("source manifest identity disagrees with release self-knowledge manifest");
    }
    validate_source_manifest_entries(&source)?;

    let receipt: GenerationReceiptIdentity = serde_json::from_reader(BufReader::new(File::open(
        root.join("GENERATION_RECEIPT.json"),
    )?))
    .context("parse GENERATION_RECEIPT.json identity")?;
    if receipt.schema_version != SCHEMA_VERSION
        || receipt.source_head_before != manifest.source_head
        || receipt.source_head_after != manifest.source_head
        || receipt.graphify_version != manifest.graphify_version
        || receipt.graphify_backend != manifest.graphify_backend
        || receipt.graphify_model != manifest.graphify_model
        || receipt.graphify_distribution != manifest.graphify_distribution
        || receipt.graphify_toolchain_sha256 != manifest.graphify_toolchain_sha256
        || receipt.node_count != manifest.node_count
        || receipt.edge_count != manifest.edge_count
    {
        anyhow::bail!("Graphify generation receipt is not bound to the release identity");
    }
    if receipt.started_unix_ns == 0
        || receipt.finished_unix_ns < receipt.started_unix_ns
        || receipt.graphify_file_count == 0
        || receipt.semantic_file_count == 0
    {
        anyhow::bail!("Graphify generation receipt has invalid timing/extraction counters");
    }
    validate_toolchain_identity(&receipt.toolchain, manifest)?;
    validate_pipeline(&receipt.pipeline, manifest)?;

    let graphify_manifest: serde_json::Value = serde_json::from_reader(BufReader::new(File::open(
        root.join("graphify-manifest.json"),
    )?))
    .context("parse graphify-manifest.json")?;
    validate_graphify_source_manifest(&graphify_manifest, &source, &receipt)?;

    let graph: serde_json::Value =
        serde_json::from_reader(BufReader::new(File::open(root.join("graph.json"))?))
            .context("parse graph.json")?;
    let nodes = graph
        .get("nodes")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("release graph.json has no nodes array"))?;
    let edges = graph
        .get("links")
        .or_else(|| graph.get("edges"))
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("release graph.json has no links/edges array"))?;
    if graph.get("directed").and_then(serde_json::Value::as_bool) != Some(true)
        || nodes.len() as u64 != manifest.node_count
        || edges.len() as u64 != manifest.edge_count
    {
        anyhow::bail!("release graph direction/counters disagree with manifest.json");
    }
    validate_graph_source_coverage(nodes, edges, &graphify_manifest)?;
    Ok(())
}

fn validate_source_manifest_entries(source: &SourceManifestIdentity) -> Result<()> {
    if source.files.is_empty() || source.files.len() > MAX_FILES {
        anyhow::bail!("SOURCE_MANIFEST.json has an invalid file count");
    }
    let mut previous = "";
    let mut portable_paths = HashSet::new();
    let mut hasher = Sha256::new();
    let mut total_bytes = 0_u64;
    for entry in &source.files {
        validate_relative_path(&entry.path)?;
        if entry.path.as_str() <= previous
            || !portable_paths.insert(portable_path_key(&entry.path)?)
            || !valid_sha256(&entry.sha256)
        {
            anyhow::bail!("SOURCE_MANIFEST.json paths/hashes must be portable, sorted, and unique");
        }
        previous = &entry.path;
        total_bytes = total_bytes
            .checked_add(entry.bytes)
            .ok_or_else(|| anyhow::anyhow!("source manifest byte count overflow"))?;
        if total_bytes > MAX_TOTAL_BYTES {
            anyhow::bail!("SOURCE_MANIFEST.json exceeds the 2 GiB safety ceiling");
        }
        hasher.update(entry.path.as_bytes());
        hasher.update(b"\0");
        hasher.update(entry.sha256.as_bytes());
        hasher.update(b"\0");
        hasher.update(entry.bytes.to_string().as_bytes());
        hasher.update(b"\n");
    }
    if hex::encode(hasher.finalize()) != source.source_tree_sha256 {
        anyhow::bail!("SOURCE_MANIFEST.json source tree hash is invalid");
    }
    Ok(())
}

fn validate_toolchain_identity(
    toolchain: &GenerationToolchainIdentity,
    manifest: &ReleaseSnapshotManifest,
) -> Result<()> {
    if toolchain.schema_version != SCHEMA_VERSION
        || toolchain.python_implementation.trim().is_empty()
        || toolchain.python_version.trim().is_empty()
        || toolchain.graphify_distribution != manifest.graphify_distribution
        || toolchain.inventory_sha256 != manifest.graphify_toolchain_sha256
        || !valid_sha256(&toolchain.inventory_sha256)
        || toolchain.packages.is_empty()
        || toolchain.packages.len() > MAX_FILES
    {
        anyhow::bail!("Graphify toolchain receipt identity is invalid");
    }
    validate_rust_toolchain_versions(&toolchain.rustc_verbose_version, &toolchain.cargo_version)?;

    let wanted_distribution = normalise_distribution_name(&manifest.graphify_distribution);
    let mut previous: Option<(String, String)> = None;
    let mut found_distribution_version = None;
    for package in &toolchain.packages {
        if package.name.trim() != package.name
            || package.version.trim() != package.version
            || package.name.is_empty()
            || package.version.is_empty()
        {
            anyhow::bail!("Graphify toolchain package identity is invalid");
        }
        let key = (package.name.to_lowercase(), package.version.clone());
        if previous.as_ref().is_some_and(|prior| key <= prior.clone()) {
            anyhow::bail!("Graphify toolchain package inventory is not sorted and unique");
        }
        previous = Some(key);
        if normalise_distribution_name(&package.name) == wanted_distribution {
            found_distribution_version = Some(package.version.as_str());
        }
    }
    if found_distribution_version != Some(toolchain.graphify_distribution_version.as_str())
        || manifest.graphify_version
            != format!("graphify {}", toolchain.graphify_distribution_version)
    {
        anyhow::bail!("Graphify distribution/version provenance is inconsistent");
    }

    let packages = toolchain
        .packages
        .iter()
        .map(|package| {
            format!(
                "{{\"name\":{},\"version\":{}}}",
                serde_json::to_string(&package.name).expect("serialize package name"),
                serde_json::to_string(&package.version).expect("serialize package version")
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let canonical = format!(
        "{{\"cargo_version\":{},\"packages\":[{packages}],\"python_implementation\":{},\"python_version\":{},\"rustc_verbose_version\":{},\"schema_version\":{}}}",
        serde_json::to_string(&toolchain.cargo_version).expect("serialize Cargo version"),
        serde_json::to_string(&toolchain.python_implementation)
            .expect("serialize Python implementation"),
        serde_json::to_string(&toolchain.python_version).expect("serialize Python version"),
        serde_json::to_string(&toolchain.rustc_verbose_version).expect("serialize rustc version"),
        toolchain.schema_version
    );
    if hex::encode(Sha256::digest(canonical.as_bytes())) != toolchain.inventory_sha256 {
        anyhow::bail!("Graphify toolchain inventory hash is invalid");
    }
    Ok(())
}

fn validate_rust_toolchain_versions(
    rustc_verbose_version: &str,
    cargo_version: &str,
) -> Result<()> {
    if rustc_verbose_version.len() > 16 * 1024
        || cargo_version.len() > 16 * 1024
        || rustc_verbose_version.contains('\r')
        || rustc_verbose_version.contains('\0')
        || cargo_version.contains('\r')
        || cargo_version.contains('\n')
        || cargo_version.contains('\0')
    {
        anyhow::bail!("Rust/Cargo toolchain receipt is malformed");
    }
    let rustc_lines = rustc_verbose_version.split('\n').collect::<Vec<_>>();
    if rustc_lines.len() != 7
        || rustc_lines
            .iter()
            .any(|line| line.is_empty() || line.trim() != *line)
        || cargo_version.is_empty()
        || cargo_version.trim() != cargo_version
    {
        anyhow::bail!("Rust/Cargo toolchain receipt is malformed");
    }
    let (release, abbreviated_commit, commit_date) =
        parse_tool_version_line(rustc_lines[0], "rustc ")
            .context("rustc -Vv receipt has an invalid release identity")?;

    let mut binary = None;
    let mut full_commit = None;
    let mut full_commit_date = None;
    let mut host = None;
    let mut field_release = None;
    let mut llvm_version = None;
    for line in &rustc_lines[1..] {
        let (key, value) = line
            .split_once(": ")
            .context("rustc -Vv receipt contains an invalid identity field")?;
        let slot = match key {
            "binary" => &mut binary,
            "commit-hash" => &mut full_commit,
            "commit-date" => &mut full_commit_date,
            "host" => &mut host,
            "release" => &mut field_release,
            "LLVM version" => &mut llvm_version,
            _ => anyhow::bail!("rustc -Vv receipt contains an unknown identity field"),
        };
        if value.is_empty() || slot.replace(value).is_some() {
            anyhow::bail!("rustc -Vv receipt contains a duplicate or empty identity field");
        }
    }
    let full_commit = full_commit.context("rustc -Vv receipt lacks commit-hash")?;
    let llvm_version = llvm_version.context("rustc -Vv receipt lacks LLVM version")?;
    if binary != Some("rustc")
        || !(40..=64).contains(&full_commit.len())
        || !full_commit
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || !full_commit.starts_with(abbreviated_commit)
        || full_commit_date != Some(commit_date)
        || field_release != Some(release)
        || host.is_none_or(|value| value.is_empty() || value.chars().any(char::is_whitespace))
        || llvm_version.split('.').count() < 2
        || !llvm_version
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        anyhow::bail!("rustc -Vv receipt is internally inconsistent");
    }

    let (cargo_release, _, _) = parse_tool_version_line(cargo_version, "cargo ")
        .context("cargo -V receipt has an invalid release identity")?;
    if cargo_release != release {
        anyhow::bail!("Cargo and rustc release versions disagree");
    }
    Ok(())
}

fn parse_tool_version_line<'a>(line: &'a str, prefix: &str) -> Option<(&'a str, &'a str, &'a str)> {
    let (version, identity) = line.strip_prefix(prefix)?.split_once(" (")?;
    let identity = identity.strip_suffix(')')?;
    let mut identity_parts = identity.split(' ');
    let commit = identity_parts.next()?;
    let date = identity_parts.next()?;
    if identity_parts.next().is_some()
        || semver::Version::parse(version).is_err()
        || !(7..=64).contains(&commit.len())
        || !commit
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || !valid_date_shape(date)
    {
        return None;
    }
    Some((version, commit, date))
}

fn valid_date_shape(value: &str) -> bool {
    value.len() == 10
        && value.as_bytes()[4] == b'-'
        && value.as_bytes()[7] == b'-'
        && value
            .bytes()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit())
}

fn normalise_distribution_name(value: &str) -> String {
    value.to_ascii_lowercase().replace('_', "-")
}

fn validate_pipeline(pipeline: &[Vec<String>], manifest: &ReleaseSnapshotManifest) -> Result<()> {
    if !matches!(pipeline.len(), 7 | 8)
        || pipeline
            .iter()
            .any(|command| command.is_empty() || command.iter().any(String::is_empty))
    {
        anyhow::bail!(
            "Graphify receipt must contain seven phases and at most one tracked-code AST augmentation"
        );
    }
    let extract_index = pipeline[0]
        .iter()
        .position(|part| part == "extract")
        .filter(|index| *index > 0)
        .ok_or_else(|| anyhow::anyhow!("Graphify pipeline does not begin with extract"))?;
    let launcher = &pipeline[0][..extract_index];
    let extract = &pipeline[0][extract_index..];
    if extract.first().map(String::as_str) != Some("extract")
        || extract.get(1).map(String::as_str) != Some(".")
        || !extract.iter().any(|part| part == "--cargo")
        || !extract.iter().any(|part| part == "--no-cluster")
        || !command_has_pair(extract, "--mode", "deep")
        || !command_has_pair(extract, "--backend", &manifest.graphify_backend)
        || !command_has_pair(extract, "--model", &manifest.graphify_model)
    {
        anyhow::bail!("Graphify extract phase is not deep/Cargo/raw and release-bound");
    }

    let mut command_index = 1;
    if pipeline.len() == 8 {
        let augmentation = &pipeline[1];
        let script = augmentation
            .get(1)
            .map(|value| value.replace('\\', "/"))
            .unwrap_or_default();
        let arguments_are_bound = augmentation.get(2..).is_some_and(|arguments| {
            arguments.len() == 4
                && arguments[0] == "--repo"
                && arguments[1] == "."
                && arguments[2] == "--graph"
                && arguments[3] == "graphify-out/graph.json"
        });
        if !script.ends_with("scripts/augment_graphify_tracked_code.py") || !arguments_are_bound {
            anyhow::bail!("Graphify tracked-code AST augmentation phase is invalid");
        }
        command_index += 1;
    }

    let cluster = &pipeline[command_index];
    if !cluster.starts_with(launcher)
        || cluster.get(launcher.len()).map(String::as_str) != Some("cluster-only")
        || cluster.get(launcher.len() + 1).map(String::as_str) != Some(".")
        || !command_has_pair(cluster, "--graph", "graphify-out/graph.json")
        || !command_has_pair(cluster, "--backend", &manifest.graphify_backend)
        || !command_has_pair(cluster, "--model", &manifest.graphify_model)
    {
        anyhow::bail!("Graphify cluster-only phase is not release-bound");
    }

    let exports = &pipeline[command_index + 1..];
    for (command, export) in exports
        .iter()
        .zip(["html", "wiki", "obsidian", "svg", "graphml"])
    {
        if !command.starts_with(launcher)
            || command.get(launcher.len()).map(String::as_str) != Some("export")
            || command.get(launcher.len() + 1).map(String::as_str) != Some(export)
            || !command_has_pair(command, "--graph", "graphify-out/graph.json")
        {
            anyhow::bail!("Graphify {export} export phase is missing or unbound");
        }
    }
    if !command_has_pair(&exports[2], "--dir", "graphify-out/obsidian") {
        anyhow::bail!("Graphify Obsidian export does not use the release output directory");
    }
    Ok(())
}

fn command_has_pair(command: &[String], flag: &str, value: &str) -> bool {
    command
        .windows(2)
        .any(|pair| pair[0] == flag && pair[1] == value)
}

fn validate_graphify_source_manifest(
    value: &serde_json::Value,
    source: &SourceManifestIdentity,
    receipt: &GenerationReceiptIdentity,
) -> Result<()> {
    let entries = value
        .as_object()
        .filter(|entries| !entries.is_empty())
        .ok_or_else(|| anyhow::anyhow!("Graphify source manifest is empty or malformed"))?;
    if entries.len() != receipt.graphify_file_count {
        anyhow::bail!("Graphify source manifest file count disagrees with receipt");
    }
    let tracked_paths = source
        .files
        .iter()
        .map(|entry| entry.path.as_str())
        .collect::<HashSet<_>>();
    let mut portable_paths = HashSet::new();
    let mut semantic_complete = 0_usize;
    for (path, entry) in entries {
        validate_relative_path(path)?;
        if !tracked_paths.contains(path.as_str()) {
            anyhow::bail!("Graphify consumed an input outside the tracked release source: {path}");
        }
        if !portable_paths.insert(portable_path_key(path)?) {
            anyhow::bail!("Graphify source manifest has a portable path collision");
        }
        let entry = entry
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("Graphify source manifest entry is malformed"))?;
        let ast_hash = entry
            .get("ast_hash")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("Graphify AST hash is not a string"))?;
        let semantic_hash = entry
            .get("semantic_hash")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("Graphify semantic hash is not a string"))?;
        if (!ast_hash.is_empty() && !valid_content_hash(ast_hash))
            || (!semantic_hash.is_empty() && !valid_content_hash(semantic_hash))
            || (ast_hash.is_empty() && semantic_hash.is_empty())
        {
            anyhow::bail!("Graphify extraction hash is invalid for {path}");
        }
        if !semantic_hash.is_empty() {
            semantic_complete += 1;
        }
    }
    if semantic_complete == 0 || semantic_complete != receipt.semantic_file_count {
        anyhow::bail!("Graphify semantic extraction count disagrees with receipt");
    }
    Ok(())
}

fn validate_graph_source_coverage(
    nodes: &[serde_json::Value],
    edges: &[serde_json::Value],
    graphify_manifest: &serde_json::Value,
) -> Result<()> {
    let manifest_paths = graphify_manifest
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("Graphify source manifest is malformed"))?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut node_sources = BTreeSet::new();

    for node in nodes {
        let node = node
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("release graph contains a non-object node"))?;
        let Some(source) = node.get("source_file") else {
            continue;
        };
        let source = source
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("release graph node source_file is not a string"))?;
        if source.is_empty() {
            continue;
        }
        validate_relative_path(source)?;
        if !manifest_paths.contains(source) {
            anyhow::bail!("release graph node references an unsealed source input: {source}");
        }
        node_sources.insert(source.to_string());
    }
    for edge in edges {
        let edge = edge
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("release graph contains a non-object edge"))?;
        let Some(source) = edge.get("source_file") else {
            continue;
        };
        let source = source
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("release graph edge source_file is not a string"))?;
        if source.is_empty() {
            continue;
        }
        validate_relative_path(source)?;
        if !manifest_paths.contains(source) {
            anyhow::bail!("release graph edge references an unsealed source input: {source}");
        }
    }

    let missing = manifest_paths
        .difference(&node_sources)
        .take(8)
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        anyhow::bail!(
            "release graph has no node/file anchor for sealed Graphify inputs: {}",
            missing.join(", ")
        );
    }
    Ok(())
}

fn valid_content_hash(value: &str) -> bool {
    (32..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn role_for_path(path: &str) -> Result<&'static str> {
    match path {
        "graph.json" => Ok("graph"),
        "GRAPH_REPORT.md" => Ok("report"),
        "graph.html" => Ok("html"),
        "graphify-manifest.json" => Ok("graphify_manifest"),
        "SOURCE_MANIFEST.json" => Ok("source_manifest"),
        "GENERATION_RECEIPT.json" => Ok("generation_receipt"),
        "graph.svg" | "graph.graphml" => Ok("visualization"),
        "BASELINE_READ_ONLY.md" => Ok("operator_guide"),
        _ if path.starts_with("wiki/") => Ok("wiki"),
        _ if path.starts_with("obsidian/") => Ok("obsidian"),
        _ => anyhow::bail!("unclassified release self-knowledge file {path}"),
    }
}

fn require_singleton(
    listed: &BTreeSet<String>,
    roles: &std::collections::BTreeMap<&str, usize>,
    path: &str,
    role: &str,
) -> Result<()> {
    if !listed.contains(path) || roles.get(role).copied() != Some(1) {
        anyhow::bail!("required release self-knowledge file/role missing: {path}/{role}");
    }
    Ok(())
}

fn require_path(listed: &BTreeSet<String>, path: &str) -> Result<()> {
    if !listed.contains(path) {
        anyhow::bail!("required release self-knowledge file missing: {path}");
    }
    Ok(())
}

fn validate_relative_path(raw: &str) -> Result<()> {
    if raw.is_empty()
        || raw.contains('\\')
        || raw.contains('\0')
        || raw.nfc().collect::<String>() != raw
    {
        anyhow::bail!("invalid release self-knowledge path {raw:?}");
    }
    let path = Path::new(raw);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        anyhow::bail!("unsafe release self-knowledge path {raw:?}");
    }
    let canonical = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(part) => part.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/");
    if canonical != raw {
        anyhow::bail!("non-canonical release self-knowledge path {raw:?}");
    }
    Ok(())
}

fn portable_path_key(raw: &str) -> Result<String> {
    validate_relative_path(raw)?;
    const RESERVED: [&str; 22] = [
        "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
        "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
    ];
    for component in raw.split('/') {
        if (component.ends_with(' ') || component.ends_with('.'))
            || component
                .chars()
                .any(|character| character < ' ' || "<>:\"|?*".contains(character))
        {
            anyhow::bail!("Windows-unsafe self-knowledge path component: {raw:?}");
        }
        let stem = component
            .split_once('.')
            .map_or(component, |(stem, _)| stem)
            .to_ascii_lowercase();
        if RESERVED.contains(&stem.as_str()) {
            anyhow::bail!("Windows-reserved self-knowledge path component: {raw:?}");
        }
    }
    Ok(raw.to_lowercase())
}

fn safe_join(root: &Path, relative: &str) -> Result<PathBuf> {
    validate_relative_path(relative)?;
    let mut path = root.to_path_buf();
    for component in Path::new(relative).components() {
        match component {
            Component::Normal(part) => path.push(part),
            _ => unreachable!("validated path contains only normal components"),
        }
    }
    Ok(path)
}

fn regular_file_metadata(path: &Path) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect release self-knowledge file {}", path.display()))?;
    if metadata_is_link_like(&metadata) || !metadata.is_file() {
        anyhow::bail!(
            "release self-knowledge entry is not a regular non-symlink file: {}",
            path.display()
        );
    }
    Ok(metadata)
}

fn metadata_is_link_like(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    false
}

fn ensure_real_directory(path: &Path) -> Result<()> {
    match fs::create_dir_all(path) {
        Ok(()) => {}
        Err(error) => {
            return Err(error).with_context(|| format!("create directory {}", path.display()));
        }
    }
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect directory {}", path.display()))?;
    if metadata_is_link_like(&metadata) || !metadata.is_dir() {
        anyhow::bail!(
            "directory must not be a symlink/reparse point: {}",
            path.display()
        );
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file =
        File::open(path).with_context(|| format!("open {} for SHA-256", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("read {} for SHA-256", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn collect_payload_paths(root: &Path) -> Result<BTreeSet<String>> {
    fn visit(root: &Path, current: &Path, out: &mut BTreeSet<String>) -> Result<()> {
        for entry in fs::read_dir(current)
            .with_context(|| format!("read release self-knowledge dir {}", current.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata_is_link_like(&metadata) {
                anyhow::bail!(
                    "symlink/reparse point in release self-knowledge: {}",
                    path.display()
                );
            }
            if metadata.is_dir() {
                visit(root, &path, out)?;
            } else if metadata.is_file() {
                if path == root.join(MANIFEST_FILE) {
                    continue;
                }
                let relative = path
                    .strip_prefix(root)
                    .context("self-knowledge walk escaped root")?
                    .components()
                    .map(|component| component.as_os_str().to_string_lossy())
                    .collect::<Vec<_>>()
                    .join("/");
                validate_relative_path(&relative)?;
                out.insert(relative);
                if out.len() > MAX_FILES {
                    anyhow::bail!("release self-knowledge contains too many files");
                }
            } else {
                anyhow::bail!(
                    "non-regular entry in release self-knowledge: {}",
                    path.display()
                );
            }
        }
        Ok(())
    }

    let mut out = BTreeSet::new();
    visit(root, root, &mut out)?;
    Ok(out)
}

fn safe_version_component(version: &str) -> Result<String> {
    if version.is_empty()
        || !version.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '+')
        })
    {
        anyhow::bail!("release version is unsafe for a materialization path: {version:?}");
    }
    Ok(version.to_string())
}

fn valid_head(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn set_tree_read_only(root: &Path) -> Result<()> {
    for relative in collect_payload_paths(root)?
        .into_iter()
        .chain(std::iter::once(MANIFEST_FILE.to_string()))
    {
        let path = safe_join(root, &relative)?;
        let mut permissions = fs::metadata(&path)?.permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&path, permissions)
            .with_context(|| format!("make release baseline read-only: {}", path.display()))?;
    }
    let mut directories = collect_real_directories(root)?;
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for path in directories {
        let mut permissions = fs::metadata(&path)?.permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&path, permissions).with_context(|| {
            format!(
                "make release baseline directory read-only: {}",
                path.display()
            )
        })?;
    }
    Ok(())
}

fn make_tree_writable(root: &Path) -> Result<()> {
    let mut directories = collect_real_directories(root)?;
    directories.sort_by_key(|path| path.components().count());
    for path in directories {
        make_path_owner_writable(&path)?;
    }
    for relative in collect_payload_paths(root)?
        .into_iter()
        .chain(std::iter::once(MANIFEST_FILE.to_string()))
    {
        let path = safe_join(root, &relative)?;
        make_path_owner_writable(&path)?;
    }
    Ok(())
}

// Windows `readonly` is a file attribute, not a Unix-style write mask; clearing
// it does not grant write access beyond the existing ACL.
#[cfg_attr(windows, allow(clippy::permissions_set_readonly_false))]
fn make_path_owner_writable(path: &Path) -> Result<()> {
    let mut permissions = fs::metadata(path)?.permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = permissions.mode() | 0o200;
        permissions.set_mode(mode);
    }
    #[cfg(windows)]
    permissions.set_readonly(false);
    #[cfg(not(any(unix, windows)))]
    {
        let _ = permissions;
        anyhow::bail!("owner-writable permission repair is unsupported on this platform");
    }
    #[cfg(any(unix, windows))]
    {
        fs::set_permissions(path, permissions)
            .with_context(|| format!("make path owner-writable: {}", path.display()))
    }
}

fn collect_real_directories(root: &Path) -> Result<Vec<PathBuf>> {
    fn visit(current: &Path, output: &mut Vec<PathBuf>) -> Result<()> {
        let metadata = fs::symlink_metadata(current)?;
        if metadata_is_link_like(&metadata) || !metadata.is_dir() {
            anyhow::bail!(
                "directory tree contains a symlink/reparse point: {}",
                current.display()
            );
        }
        output.push(current.to_path_buf());
        for entry in fs::read_dir(current)? {
            let path = entry?.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata_is_link_like(&metadata) {
                anyhow::bail!(
                    "directory tree contains a symlink/reparse point: {}",
                    path.display()
                );
            }
            if metadata.is_dir() {
                visit(&path, output)?;
            } else if !metadata.is_file() {
                anyhow::bail!(
                    "directory tree contains a non-regular entry: {}",
                    path.display()
                );
            }
        }
        Ok(())
    }

    let mut output = Vec::new();
    visit(root, &mut output)?;
    Ok(output)
}

/// Shared full-contract fixture for sibling updater/package tests. Keeping the
/// producer here prevents those tests from drifting behind the release
/// manifest, receipt, and toolchain schemas.
#[cfg(test)]
pub(crate) fn write_test_snapshot(root: &Path, release_version: &str) -> Result<()> {
    use serde_json::json;

    fn write_json(path: &Path, value: &serde_json::Value) -> Result<()> {
        fs::write(path, serde_json::to_vec_pretty(value)?)?;
        Ok(())
    }

    fs::create_dir_all(root.join("wiki"))?;
    fs::create_dir_all(root.join("obsidian"))?;
    let head = "a".repeat(40);
    let source_inputs = [
        ("docs/architecture.md", b"# Architecture\n".as_slice()),
        ("src/lib.rs", b"pub fn runtime() {}\n".as_slice()),
    ];
    let source_entries = source_inputs
        .iter()
        .map(|(path, bytes)| {
            json!({
                "path": path,
                "bytes": bytes.len(),
                "sha256": hex::encode(Sha256::digest(bytes)),
            })
        })
        .collect::<Vec<_>>();
    let mut source_hasher = Sha256::new();
    for entry in &source_entries {
        source_hasher.update(entry["path"].as_str().unwrap().as_bytes());
        source_hasher.update(b"\0");
        source_hasher.update(entry["sha256"].as_str().unwrap().as_bytes());
        source_hasher.update(b"\0");
        source_hasher.update(entry["bytes"].as_u64().unwrap().to_string().as_bytes());
        source_hasher.update(b"\n");
    }
    let source_tree = hex::encode(source_hasher.finalize());

    let rustc_verbose_version = concat!(
        "rustc 1.91.0 (f8297e351 2025-10-28)\n",
        "binary: rustc\n",
        "commit-hash: f8297e3510000000000000000000000000000000\n",
        "commit-date: 2025-10-28\n",
        "host: x86_64-unknown-linux-gnu\n",
        "release: 1.91.0\n",
        "LLVM version: 21.1.2"
    );
    let cargo_version = "cargo 1.91.0 (ea2d97820 2025-10-10)";
    let inventory_core = format!(
        "{{\"cargo_version\":{},\"packages\":[{{\"name\":\"pip\",\"version\":\"1.0\"}}],\"python_implementation\":\"CPython\",\"python_version\":\"3.12.10\",\"rustc_verbose_version\":{},\"schema_version\":1}}",
        serde_json::to_string(cargo_version)?,
        serde_json::to_string(rustc_verbose_version)?,
    );
    let toolchain_hash = hex::encode(Sha256::digest(inventory_core.as_bytes()));
    let toolchain = json!({
        "schema_version": 1,
        "python_implementation": "CPython",
        "python_version": "3.12.10",
        "rustc_verbose_version": rustc_verbose_version,
        "cargo_version": cargo_version,
        "packages": [{"name": "pip", "version": "1.0"}],
        "inventory_sha256": toolchain_hash,
        "graphify_distribution": "pip",
        "graphify_distribution_version": "1.0",
    });
    let pipeline = json!([
        [
            "graphify",
            "extract",
            ".",
            "--mode",
            "deep",
            "--cargo",
            "--no-cluster",
            "--backend",
            "fixture",
            "--model",
            "fixture-model"
        ],
        [
            "graphify",
            "cluster-only",
            ".",
            "--graph",
            "graphify-out/graph.json",
            "--backend",
            "fixture",
            "--model",
            "fixture-model"
        ],
        [
            "graphify",
            "export",
            "html",
            "--graph",
            "graphify-out/graph.json"
        ],
        [
            "graphify",
            "export",
            "wiki",
            "--graph",
            "graphify-out/graph.json"
        ],
        [
            "graphify",
            "export",
            "obsidian",
            "--graph",
            "graphify-out/graph.json",
            "--dir",
            "graphify-out/obsidian"
        ],
        [
            "graphify",
            "export",
            "svg",
            "--graph",
            "graphify-out/graph.json"
        ],
        [
            "graphify",
            "export",
            "graphml",
            "--graph",
            "graphify-out/graph.json"
        ],
    ]);

    fs::write(
        root.join("BASELINE_READ_ONLY.md"),
        "# Baseline\nDo not edit this signed baseline.\n",
    )?;
    fs::write(
        root.join("GRAPH_REPORT.md"),
        "# NEOTH Graph\nNEOTH contains a generated runtime architecture.\n",
    )?;
    fs::write(
        root.join("graph.html"),
        "<!doctype html><title>NEOTH graph</title>",
    )?;
    fs::write(
        root.join("graph.svg"),
        "<svg xmlns=\"http://www.w3.org/2000/svg\"/>",
    )?;
    fs::write(
        root.join("graph.graphml"),
        "<graphml><graph edgedefault=\"directed\"/></graphml>",
    )?;
    write_json(
        &root.join("graph.json"),
        &json!({
            "directed": true,
            "nodes": [
                {"id": "a", "source_file": "docs/architecture.md"},
                {"id": "b", "source_file": "src/lib.rs"}
            ],
            "links": [
                {"source": "a", "target": "b", "source_file": "docs/architecture.md"}
            ],
        }),
    )?;
    write_json(
        &root.join("graphify-manifest.json"),
        &json!({
            "docs/architecture.md": {"ast_hash": "", "semantic_hash": "c".repeat(64)},
            "src/lib.rs": {"ast_hash": "d".repeat(64), "semantic_hash": ""},
        }),
    )?;
    fs::write(
        root.join("obsidian/Runtime.md"),
        "# Runtime\nNEOTH runtime dispatch is review gated.\n",
    )?;
    fs::write(
        root.join("wiki/index.md"),
        "# Wiki\nNEOTH architecture links runtime and memory.\n",
    )?;
    write_json(
        &root.join("SOURCE_MANIFEST.json"),
        &json!({
            "schema_version": 1,
            "source_head": head,
            "source_tree_sha256": source_tree,
            "files": source_entries,
        }),
    )?;
    write_json(
        &root.join("GENERATION_RECEIPT.json"),
        &json!({
            "schema_version": 1,
            "source_head_before": head,
            "source_head_after": head,
            "started_unix_ns": 1,
            "finished_unix_ns": 2,
            "graphify_version": "graphify 1.0",
            "graphify_backend": "fixture",
            "graphify_model": "fixture-model",
            "graphify_distribution": "pip",
            "graphify_toolchain_sha256": toolchain_hash,
            "toolchain": toolchain,
            "pipeline": pipeline,
            "node_count": 2,
            "edge_count": 1,
            "graphify_file_count": 2,
            "semantic_file_count": 1,
        }),
    )?;

    let paths_and_roles = [
        ("BASELINE_READ_ONLY.md", "operator_guide"),
        ("GENERATION_RECEIPT.json", "generation_receipt"),
        ("GRAPH_REPORT.md", "report"),
        ("SOURCE_MANIFEST.json", "source_manifest"),
        ("graph.graphml", "visualization"),
        ("graph.html", "html"),
        ("graph.json", "graph"),
        ("graph.svg", "visualization"),
        ("graphify-manifest.json", "graphify_manifest"),
        ("obsidian/Runtime.md", "obsidian"),
        ("wiki/index.md", "wiki"),
    ];
    let entries = paths_and_roles
        .iter()
        .map(|(path, role)| {
            let target = root.join(path);
            Ok(json!({
                "path": path,
                "bytes": fs::metadata(&target)?.len(),
                "sha256": sha256_file(&target)?,
                "role": role,
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut payload_hasher = Sha256::new();
    for entry in &entries {
        payload_hasher.update(entry["path"].as_str().unwrap().as_bytes());
        payload_hasher.update(b"\0");
        payload_hasher.update(entry["sha256"].as_str().unwrap().as_bytes());
        payload_hasher.update(b"\0");
        payload_hasher.update(entry["bytes"].as_u64().unwrap().to_string().as_bytes());
        payload_hasher.update(b"\0");
        payload_hasher.update(entry["role"].as_str().unwrap().as_bytes());
        payload_hasher.update(b"\n");
    }
    write_json(
        &root.join(MANIFEST_FILE),
        &json!({
            "schema_version": 1,
            "product": "NEOTH",
            "release_version": release_version,
            "source_head": head,
            "source_tree_sha256": source_tree,
            "generated_at": "2026-01-01T00:00:00+00:00",
            "graphify_version": "graphify 1.0",
            "graphify_backend": "fixture",
            "graphify_model": "fixture-model",
            "graphify_distribution": "pip",
            "graphify_toolchain_sha256": toolchain_hash,
            "node_count": 2,
            "edge_count": 1,
            "payload_sha256": hex::encode(payload_hasher.finalize()),
            "files": entries,
        }),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        write_test_snapshot(dir.path(), env!("CARGO_PKG_VERSION")).unwrap();
        dir
    }

    #[test]
    fn verifies_and_materializes_without_touching_overlays() {
        let source = fixture();
        let snapshot = VerifiedReleaseSnapshot::open(source.path()).unwrap();
        let vault = tempfile::tempdir().unwrap();
        let wiki = vault.path().join("NEOTH-Wiki");
        let first = snapshot.materialize_into(&wiki).unwrap();
        assert!(!first.already_present);
        let operator_note = first.overlays_dir.join(OPERATOR_NOTES_DIR).join("Mine.md");
        fs::write(&operator_note, "operator edit").unwrap();
        let second = snapshot.materialize_into(&wiki).unwrap();
        assert!(second.already_present);
        assert_eq!(fs::read_to_string(operator_note).unwrap(), "operator edit");
        assert!(second.baseline_dir.join("graph.json").is_file());
    }

    #[test]
    fn destination_race_accepts_only_the_verified_identical_baseline() {
        let source = fixture();
        let snapshot = VerifiedReleaseSnapshot::open(source.path()).unwrap();
        let vault = tempfile::tempdir().unwrap();
        let wiki = vault.path().join("NEOTH-Wiki");
        let first = snapshot.materialize_into(&wiki).unwrap();
        snapshot
            .copy_new_baseline(first.baseline_dir.parent().unwrap(), &first.baseline_dir)
            .unwrap();
        assert_eq!(
            VerifiedReleaseSnapshot::open(&first.baseline_dir)
                .unwrap()
                .manifest()
                .payload_sha256,
            snapshot.manifest().payload_sha256
        );
    }

    #[test]
    fn tampered_baseline_fails_closed() {
        let source = fixture();
        fs::write(source.path().join("GRAPH_REPORT.md"), "tampered").unwrap();
        assert!(VerifiedReleaseSnapshot::open(source.path()).is_err());
    }

    #[test]
    fn unlisted_file_fails_closed() {
        let source = fixture();
        fs::write(source.path().join("unlisted.txt"), "surprise").unwrap();
        assert!(VerifiedReleaseSnapshot::open(source.path()).is_err());
    }

    #[test]
    fn ingest_is_atomic_and_version_scoped() {
        let source = fixture();
        let snapshot = VerifiedReleaseSnapshot::open(source.path()).unwrap();
        let db = tempfile::tempdir().unwrap();
        let conn = crate::memory::store::open(&db.path().join("views.db")).unwrap();
        let inserted = snapshot.ingest_into(&conn, 1_000).unwrap();
        assert!(inserted >= 3);
        let first = crate::memory::groundtruth::list_for_scope(&conn, RECALL_SCOPE).unwrap();
        assert_eq!(first.len(), inserted);
        let inserted_again = snapshot.ingest_into(&conn, 2_000).unwrap();
        assert_eq!(inserted_again, inserted);
        let active = crate::memory::groundtruth::list_for_scope(&conn, RECALL_SCOPE).unwrap();
        assert_eq!(active.len(), inserted);
        assert!(active.iter().all(|row| row.revoked_at.is_none()));
        assert_eq!(
            active
                .iter()
                .filter(|row| row.source == "release-build-identity")
                .map(|row| row.fact_state.as_str())
                .collect::<Vec<_>>(),
            vec!["verified"]
        );
        assert!(
            active
                .iter()
                .any(|row| { row.source == "release-self-knowledge" && row.fact_state == "raw" })
        );
    }

    #[test]
    fn ingest_rehashes_markdown_at_use_time() {
        let source = fixture();
        let snapshot = VerifiedReleaseSnapshot::open(source.path()).unwrap();
        fs::write(
            source.path().join("GRAPH_REPORT.md"),
            "# Drift\nThese bytes changed after initial verification.\n",
        )
        .unwrap();
        let db = tempfile::tempdir().unwrap();
        let conn = crate::memory::store::open(&db.path().join("views.db")).unwrap();
        assert!(snapshot.ingest_into(&conn, 1_000).is_err());
        assert!(
            crate::memory::groundtruth::list_for_scope(&conn, RECALL_SCOPE)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn overlays_ingest_only_operator_and_reviewed_directories() {
        let source = fixture();
        let snapshot = VerifiedReleaseSnapshot::open(source.path()).unwrap();
        let vault = tempfile::tempdir().unwrap();
        let materialized = snapshot
            .materialize_into(&vault.path().join("NEOTH-Wiki"))
            .unwrap();
        let operator = materialized
            .overlays_dir
            .join(OPERATOR_NOTES_DIR)
            .join("channels.md");
        let reviewed = materialized
            .overlays_dir
            .join(REVIEWED_SELF_IMPROVE_DIR)
            .join("runtime.md");
        let proposal = materialized
            .overlays_dir
            .join(SELF_IMPROVE_PROPOSALS_DIR)
            .join("unsafe.md");
        fs::write(
            &operator,
            "NEOTH operator notes require channel adapters to preserve migration identifiers.",
        )
        .unwrap();
        fs::write(
            &reviewed,
            "Reviewed NEOTH architecture keeps release self-knowledge immutable across upgrades.",
        )
        .unwrap();
        fs::write(
            &proposal,
            "UNREVIEWED_SENTINEL proposals must never enter trusted recall automatically.",
        )
        .unwrap();

        let db = tempfile::tempdir().unwrap();
        let conn = crate::memory::store::open(&db.path().join("views.db")).unwrap();
        let inserted = snapshot
            .ingest_overlays_into(&materialized.overlays_dir, &conn, 10_000)
            .unwrap();
        assert_eq!(inserted, 2);
        let active =
            crate::memory::groundtruth::list_for_scope(&conn, OVERLAY_RECALL_SCOPE).unwrap();
        assert_eq!(active.len(), 2);
        assert!(
            active.iter().all(|row| {
                row.source == "self-knowledge-overlay" && row.fact_state == "verified"
            })
        );
        assert!(
            active
                .iter()
                .all(|row| !row.statement.contains("UNREVIEWED_SENTINEL"))
        );

        fs::remove_file(operator).unwrap();
        fs::remove_file(reviewed).unwrap();
        assert_eq!(
            snapshot
                .ingest_overlays_into(&materialized.overlays_dir, &conn, 20_000)
                .unwrap(),
            0
        );
        assert!(
            crate::memory::groundtruth::list_for_scope(&conn, OVERLAY_RECALL_SCOPE)
                .unwrap()
                .is_empty()
        );
        let revoked: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM idx_groundtruth WHERE scope = ?1 AND revoked_at = ?2",
                rusqlite::params![OVERLAY_RECALL_SCOPE, 20_000_i64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(revoked, 2);
    }

    #[test]
    fn explicit_discovery_override_never_falls_back() {
        let layout = tempfile::tempdir().unwrap();
        let portable = layout.path().join("bin/self-knowledge");
        write_test_snapshot(&portable, env!("CARGO_PKG_VERSION")).unwrap();
        let executable = layout.path().join("bin/neoth");
        let missing = layout.path().join("explicit-missing");
        let result = VerifiedReleaseSnapshot::discover_from(
            Some(missing.into_os_string()),
            Some(executable),
        );
        assert!(result.is_err());
    }

    #[test]
    fn discovers_portable_linux_and_macos_release_layouts() {
        let cases = [
            ("bin/neoth", "bin/neoth-support/self-knowledge"),
            // Native Windows Setup owns a dedicated NEOTH application root.
            ("NEOTH/neoth.exe", "NEOTH/self-knowledge"),
            ("bin/neoth", "share/neoth/self-knowledge"),
            (
                "NEOTH.app/Contents/MacOS/neoth",
                "NEOTH.app/Contents/Resources/self-knowledge",
            ),
        ];
        for (executable, snapshot_dir) in cases {
            let layout = tempfile::tempdir().unwrap();
            write_test_snapshot(&layout.path().join(snapshot_dir), env!("CARGO_PKG_VERSION"))
                .unwrap();
            let discovered =
                VerifiedReleaseSnapshot::discover_from(None, Some(layout.path().join(executable)))
                    .unwrap()
                    .expect("layout should be discovered");
            assert_eq!(discovered.manifest().source_head, "a".repeat(40));
        }
    }

    #[cfg(unix)]
    #[test]
    fn discovers_macos_app_snapshot_when_launched_through_cli_symlink() {
        use std::os::unix::fs::symlink;

        let layout = tempfile::tempdir().unwrap();
        let app_binary = layout
            .path()
            .join("Applications/NEOTH.app/Contents/MacOS/neoth");
        fs::create_dir_all(app_binary.parent().unwrap()).unwrap();
        fs::write(&app_binary, b"fixture").unwrap();
        write_test_snapshot(
            &layout
                .path()
                .join("Applications/NEOTH.app/Contents/Resources/self-knowledge"),
            env!("CARGO_PKG_VERSION"),
        )
        .unwrap();

        let cli_binary = layout.path().join("usr/local/bin/neoth");
        fs::create_dir_all(cli_binary.parent().unwrap()).unwrap();
        symlink(&app_binary, &cli_binary).unwrap();

        let discovered = VerifiedReleaseSnapshot::discover_from(None, Some(cli_binary))
            .unwrap()
            .expect("canonical app-bundle snapshot should be discovered");
        assert_eq!(discovered.manifest().source_head, "a".repeat(40));
    }

    #[test]
    fn update_verifier_binds_exact_normalised_target_version() {
        let source = tempfile::tempdir().unwrap();
        write_test_snapshot(source.path(), "9.8.7").unwrap();
        assert!(VerifiedReleaseSnapshot::open_for_update(source.path(), "v9.8.7").is_ok());
        assert!(VerifiedReleaseSnapshot::open_for_update(source.path(), "9.8.6").is_err());
    }

    #[test]
    fn compiled_payload_mismatch_fails_closed() {
        let source = fixture();
        let snapshot = VerifiedReleaseSnapshot::open(source.path()).unwrap();
        assert!(
            validate_compiled_bindings(
                snapshot.manifest(),
                Some(&"a".repeat(40)),
                Some(&"f".repeat(64)),
                true,
            )
            .is_err()
        );
    }

    #[test]
    fn overlay_symlink_is_rejected_when_supported() {
        let source = fixture();
        let snapshot = VerifiedReleaseSnapshot::open(source.path()).unwrap();
        let vault = tempfile::tempdir().unwrap();
        let materialized = snapshot
            .materialize_into(&vault.path().join("NEOTH-Wiki"))
            .unwrap();
        let external = vault.path().join("external.md");
        fs::write(
            &external,
            "External bytes must not enter a self-knowledge overlay through a link.",
        )
        .unwrap();
        let link = materialized
            .overlays_dir
            .join(OPERATOR_NOTES_DIR)
            .join("linked.md");
        #[cfg(unix)]
        let linked = std::os::unix::fs::symlink(&external, &link).is_ok();
        #[cfg(windows)]
        let linked = std::os::windows::fs::symlink_file(&external, &link).is_ok();
        #[cfg(not(any(unix, windows)))]
        let linked = false;
        if !linked {
            return;
        }
        let db = tempfile::tempdir().unwrap();
        let conn = crate::memory::store::open(&db.path().join("views.db")).unwrap();
        assert!(
            snapshot
                .ingest_overlays_into(&materialized.overlays_dir, &conn, 1_000)
                .is_err()
        );
    }

    #[test]
    fn overlay_entry_and_byte_limits_fail_closed() {
        let source = fixture();
        let snapshot = VerifiedReleaseSnapshot::open(source.path()).unwrap();
        let vault = tempfile::tempdir().unwrap();
        let materialized = snapshot
            .materialize_into(&vault.path().join("NEOTH-Wiki"))
            .unwrap();
        fs::write(
            materialized
                .overlays_dir
                .join(OPERATOR_NOTES_DIR)
                .join("one.md"),
            "First bounded operator statement remains inside the curated overlay.",
        )
        .unwrap();
        fs::write(
            materialized
                .overlays_dir
                .join(REVIEWED_SELF_IMPROVE_DIR)
                .join("two.md"),
            "Second bounded reviewed statement remains inside the curated overlay.",
        )
        .unwrap();
        assert!(
            collect_overlay_markdown_with_limits(&materialized.overlays_dir, 1, u64::MAX).is_err()
        );
        assert!(
            collect_overlay_markdown_with_limits(&materialized.overlays_dir, usize::MAX, 1)
                .is_err()
        );
    }
}
