//! Atomic, root-bound publication of Graphify artifacts into an operator vault.
//!
//! Graphify output is complementary evidence for the native code map.  This
//! module publishes only after a complete native snapshot exists and binds the
//! copied report bytes to that snapshot's physical repository identity,
//! source fingerprint, and equal positive index/graph generation.
//!
//! A corpus directory contains immutable `generations/<id>/` directories and
//! one atomically replaced `CURRENT` pointer.  A failed prepare/finalize may
//! leave an unreferenced immutable generation, but can never expose a mixed
//! report/tree pair or disturb the previously referenced generation.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::code_map::snapshot::ScopedRebuildSnapshot;
use crate::code_map::{CanonicalRepoRoot, RebuildSnapshot};
use crate::wiki::GraphifyIngestScope;

pub const GRAPHIFY_PUBLISH_SCHEMA: u32 = 1;
pub const GRAPH_REPORT_NAME: &str = "GRAPH_REPORT.md";
pub const GRAPH_TREE_NAME: &str = "GRAPH_TREE.html";
pub const GENERATION_RECEIPT_NAME: &str = "GENERATION_RECEIPT.json";
pub const CURRENT_POINTER_NAME: &str = "CURRENT";
pub const GRAPHIFY_TRANSACTION_NAME: &str = ".neoth-graphify-transaction.json";

const CORPUS_BINDING_NAME: &str = ".neoth-graphify-binding.json";
const GENERATIONS_DIR_NAME: &str = "generations";
const MAX_FRIENDLY_SUBDIR_BYTES: usize = 96;
const MAX_REPORT_BYTES: u64 = 32 * 1024 * 1024;
const MAX_TREE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_TOTAL_ARTIFACT_BYTES: u64 = MAX_REPORT_BYTES + MAX_TREE_BYTES;
const MAX_RECEIPT_BYTES: u64 = 256 * 1024;
const MAX_POINTER_BYTES: u64 = 16 * 1024;
const MAX_BINDING_BYTES: u64 = 32 * 1024;
const MAX_TRANSACTION_BYTES: u64 = 128 * 1024;
const LEASES_DIR_NAME: &str = ".neoth-graphify-leases";
const LEASE_WAIT: Duration = Duration::from_secs(5);
const LEASE_RETRY: Duration = Duration::from_millis(50);

/// One complete request.  `native_snapshot` supplies the canonical repository
/// root and the source fingerprint which Graphify output is being associated
/// with.  `friendly_subdir = None` selects a stable root-identity-derived name.
pub(crate) struct GraphifyPublishRequest<'a> {
    pub(crate) vault_root: &'a Path,
    pub(crate) friendly_subdir: Option<&'a str>,
    pub(crate) native_snapshot: &'a ScopedRebuildSnapshot,
    /// Persisted in the pre-CURRENT transaction intent so a crash cannot make
    /// an indexed publication indistinguishable from deliberate --no-ingest.
    pub(crate) ingest_mode: GraphifyPublicationIngestMode,
    /// Durable caller ownership domain. Written in the pre-CURRENT journal so
    /// recovery never infers a destructive SQLite scope from its caller.
    pub(crate) ingest_scope: GraphifyIngestScope,
    /// Acquired before Graphify rewrites `graphify-out`; ownership moves
    /// through prepare/publish and remains with the caller through WAL.
    pub(crate) lease: GraphifyPublicationLease,
}

/// Hash/size evidence for one copied Graphify artifact.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GraphifyArtifactReceipt {
    pub name: String,
    pub bytes: u64,
    pub sha256: String,
}

/// Durable evidence stored inside every immutable generation.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GraphifyGenerationReceipt {
    pub schema_version: u32,
    /// Stable identity for the physical repository, independent of a friendly
    /// directory name or the repository's basename.
    pub corpus_id: String,
    /// Exact-snapshot namespace.  It binds the physical root and native source
    /// fingerprint so two source states cannot share an evidence namespace.
    pub corpus_namespace: String,
    pub generation_id: String,
    pub friendly_subdir: String,
    pub canonical_repo_root: String,
    pub repo_root_identity_sha256: String,
    pub canonical_vault_root: String,
    pub vault_root_identity_sha256: String,
    pub source_fingerprint_sha256: String,
    pub native_index_generation: i64,
    pub native_graph_generation: i64,
    pub artifacts: Vec<GraphifyArtifactReceipt>,
}

/// The atomically replaced pointer.  Consumers read this first, then open the
/// immutable generation and verify its receipt before ingesting artifacts.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CurrentGraphifyPointer {
    pub schema_version: u32,
    pub corpus_id: String,
    pub corpus_namespace: String,
    pub generation_id: String,
    pub source_fingerprint_sha256: String,
    pub native_index_generation: i64,
    pub native_graph_generation: i64,
}

/// Prepared publication.  Dropping this value aborts and removes its private
/// staging directory without changing `CURRENT`.
pub struct PreparedGraphifyPublication {
    vault_root: CanonicalRepoRoot,
    repository_root: CanonicalRepoRoot,
    corpus_dir: PathBuf,
    generation_dir: PathBuf,
    binding: CorpusBinding,
    native_snapshot: ScopedRebuildSnapshot,
    expected_current: Option<CurrentGraphifyPointer>,
    expected_current_bytes: Option<Vec<u8>>,
    ingest_mode: GraphifyPublicationIngestMode,
    ingest_scope: GraphifyIngestScope,
    receipt: GraphifyGenerationReceipt,
    stage: tempfile::TempDir,
    // Deliberately retained from preparation through CURRENT. This is the
    // cooperative cross-process CAS boundary; do not shorten its lifetime.
    _lease: GraphifyPublicationLease,
}

/// Per-corpus writer lease for Graphify publication.
///
/// The lease combines a bounded process-local keyed mutex with the repository
/// standard bounded OS file lock. Writers must acquire it before inspecting a
/// corpus binding/CURRENT and retain it until their CURRENT transition has
/// either succeeded or been recovered. Callers acquire this capability before
/// external Graphify work and transfer it into `GraphifyPublishRequest`; the
/// published result retains it until the caller records a terminal WAL state.
pub(crate) struct GraphifyPublicationLease {
    vault_root: CanonicalRepoRoot,
    corpus_id: String,
    // Rust drops fields in declaration order. Keep the OS lease first so
    // release is the inverse of acquisition: process-local → OS on acquire,
    // then OS → process-local on drop. Otherwise another local task could
    // start contending for the OS lock before this handle has released it.
    _file: File,
    _process: ProcessCorpusLease,
}

struct ProcessCorpusLease {
    key: PathBuf,
}

impl Drop for ProcessCorpusLease {
    fn drop(&mut self) {
        if let Ok(mut held) = process_lease_set().lock() {
            held.remove(&self.key);
        }
    }
}

/// Result of a successful publication.  The generation directory is immutable
/// and `CURRENT` already names it when this value is returned.
pub struct PublishedGraphifyPublication {
    pub corpus_dir: PathBuf,
    pub generation_dir: PathBuf,
    pub current_pointer: PathBuf,
    pub receipt: GraphifyGenerationReceipt,
    lease: GraphifyPublicationLease,
    journal_path: PathBuf,
    journal: GraphifyPublicationJournal,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CorpusBinding {
    schema_version: u32,
    corpus_id: String,
    friendly_subdir: String,
    canonical_repo_root: String,
    repo_root_identity_sha256: String,
    canonical_vault_root: String,
    vault_root_identity_sha256: String,
}

/// Durable phase of the caller-owned Graphify transaction. The journal is
/// intentionally separate from the caller's completion WAL: it captures the
/// filesystem CURRENT transition, while the caller's WAL records application
/// work such as SQLite ingest. Recovery compares raw pointer bytes and never
/// guesses which side of a crash boundary won.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GraphifyTransactionPhase {
    Prepared,
    CurrentPublished,
    Ingested,
    IngestSkipped,
    Completed,
}

/// Intended post-CURRENT groundtruth action, fixed before `CURRENT` changes.
/// `SkippedAndRevoked` means the caller deliberately leaves no active
/// Graphify scope for this generation; it is not a failed or pending ingest.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GraphifyPublicationIngestMode {
    Indexed,
    SkippedAndRevoked,
}

/// Minimal durable transaction view for a coordinator. It intentionally does
/// not expose raw CURRENT bytes, which are recovery-only compare-and-swap
/// material, but identifies the exact receipt and its filesystem phase.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GraphifyTransactionInspection {
    pub(crate) transaction_id: String,
    pub(crate) phase: GraphifyTransactionPhase,
    pub(crate) ingest_mode: GraphifyPublicationIngestMode,
    pub(crate) ingest_scope: GraphifyIngestScope,
    pub(crate) corpus_id: String,
    pub(crate) generation_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct GraphifyPublicationJournal {
    schema_version: u32,
    transaction_id: String,
    phase: GraphifyTransactionPhase,
    ingest_mode: GraphifyPublicationIngestMode,
    ingest_scope: GraphifyIngestScope,
    corpus_id: String,
    generation_id: String,
    previous_current_hex: Option<String>,
    new_current_hex: String,
}

#[derive(Clone, Debug)]
struct StagedArtifact {
    receipt: GraphifyArtifactReceipt,
    bytes: Vec<u8>,
}

impl PreparedGraphifyPublication {
    pub fn receipt(&self) -> &GraphifyGenerationReceipt {
        &self.receipt
    }

    pub fn corpus_dir(&self) -> &Path {
        &self.corpus_dir
    }

    pub fn staged_generation_dir(&self) -> &Path {
        self.stage.path()
    }

    /// Explicit abort hook for callers which prefer visible lifecycle control.
    /// Drop performs the same private-stage cleanup.
    pub fn abort(self) {}

    /// Publish the staged immutable generation and atomically advance CURRENT.
    pub fn publish(self) -> Result<PublishedGraphifyPublication> {
        ensure_root_unchanged(&self.repository_root, "repository")?;
        ensure_root_unchanged(&self.vault_root, "vault")?;
        ensure_real_directory(&self.corpus_dir, "Graphify corpus directory")?;
        ensure_direct_child(
            &self.vault_root,
            &self.corpus_dir,
            "Graphify corpus directory",
        )?;
        validate_staged_generation(self.stage.path(), &self.receipt)?;

        ensure_corpus_binding(&self.corpus_dir, &self.binding)?;
        let generations_dir = ensure_real_child_directory(
            &self.corpus_dir,
            GENERATIONS_DIR_NAME,
            "Graphify generations directory",
        )?;
        ensure!(
            self.generation_dir.parent() == Some(generations_dir.as_path()),
            "prepared Graphify generation escaped its generations directory"
        );

        match fs::symlink_metadata(&self.generation_dir) {
            Ok(_) => {
                validate_published_generation(&self.generation_dir, &self.receipt)
                    .context("verify existing immutable Graphify generation")?;
                make_generation_read_only(&self.generation_dir)
                    .context("restore immutable Graphify generation permissions")?;
                validate_generation_read_only(&self.generation_dir)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                harden_staged_generation(self.stage.path())
                    .context("harden staged Graphify generation before publication")?;
                if let Err(error) = fs::rename(self.stage.path(), &self.generation_dir) {
                    let cleanup = make_generation_writable_for_cleanup(self.stage.path());
                    return match cleanup {
                        Ok(()) => Err(error).with_context(|| {
                            format!(
                                "publish immutable Graphify generation {}",
                                self.generation_dir.display()
                            )
                        }),
                        Err(cleanup_error) => Err(anyhow::anyhow!(
                            "publish immutable Graphify generation {} failed: {error}; staged permission rollback also failed: {cleanup_error:#}",
                            self.generation_dir.display()
                        )),
                    };
                }
                crate::util::atomic_write::sync_parent_directory_required(&self.generation_dir)
                    .context("durably publish Graphify generation directory entry")?;
                validate_published_generation(&self.generation_dir, &self.receipt)
                    .context("verify newly published immutable Graphify generation")?;
                validate_generation_read_only(&self.generation_dir)?;
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "inspect Graphify generation destination {}",
                        self.generation_dir.display()
                    )
                });
            }
        }

        // Recheck both physical roots immediately before crossing the only
        // visibility boundary.  An orphan immutable generation is harmless;
        // a pointer to evidence from a replaced root is not.
        ensure_root_unchanged(&self.repository_root, "repository")?;
        ensure_root_unchanged(&self.vault_root, "vault")?;
        validate_corpus_binding(&self.corpus_dir, &self.binding)?;
        self.native_snapshot
            .revalidate_companion_publication()
            .context("revalidate native snapshot at Graphify visibility boundary")?;
        validate_published_generation(&self.generation_dir, &self.receipt)
            .context("revalidate complete immutable Graphify generation before CURRENT")?;
        validate_generation_read_only(&self.generation_dir)?;

        let pointer = CurrentGraphifyPointer::from(&self.receipt);
        let pointer_bytes = json_line(&pointer).context("serialize Graphify CURRENT pointer")?;
        let pointer_path = self.corpus_dir.join(CURRENT_POINTER_NAME);
        let journal_path = self.corpus_dir.join(GRAPHIFY_TRANSACTION_NAME);
        let mut journal = GraphifyPublicationJournal {
            schema_version: GRAPHIFY_PUBLISH_SCHEMA,
            transaction_id: transaction_id(&self.receipt, self.ingest_scope),
            phase: GraphifyTransactionPhase::Prepared,
            ingest_mode: self.ingest_mode,
            ingest_scope: self.ingest_scope,
            corpus_id: self.receipt.corpus_id.clone(),
            generation_id: self.receipt.generation_id.clone(),
            previous_current_hex: self.expected_current_bytes.as_deref().map(hex::encode),
            new_current_hex: hex::encode(&pointer_bytes),
        };
        write_transaction_journal(&journal_path, &journal)
            .context("durably record Graphify CURRENT intent before publication")?;
        if let Err(error) = compare_and_swap_current_under_lease(
            &pointer_path,
            self.expected_current.as_ref(),
            self.expected_current_bytes.as_deref(),
            &pointer_bytes,
        ) {
            return match crate::util::atomic_write::durable_remove_file(&journal_path) {
                Ok(()) => Err(error).context("Graphify CURRENT CAS rejected stale publication"),
                Err(cleanup_error) => Err(anyhow::anyhow!(
                    "Graphify CURRENT CAS rejected stale publication: {error:#}; transaction-intent cleanup failed: {cleanup_error:#}"
                )),
            };
        }
        (|| -> Result<()> {
            crate::util::atomic_write::sync_parent_directory_required(&pointer_path)
                .context("durably publish Graphify CURRENT pointer")?;
            let observed = read_current_pointer(&self.corpus_dir)?
                .context("Graphify CURRENT pointer disappeared after publication")?;
            ensure!(
                observed == pointer,
                "Graphify CURRENT pointer did not retain the published generation"
            );
            Ok(())
        })()
        .context(
            "Graphify CURRENT may be visible; durable transaction intent was retained for recovery",
        )?;
        journal.phase = GraphifyTransactionPhase::CurrentPublished;
        write_transaction_journal(&journal_path, &journal)
            .context("CURRENT is durable but Graphify transaction phase update failed; recovery intent remains")?;

        Ok(PublishedGraphifyPublication {
            corpus_dir: self.corpus_dir,
            generation_dir: self.generation_dir,
            current_pointer: pointer_path,
            receipt: self.receipt,
            lease: self._lease,
            journal_path,
            journal,
        })
    }
}

impl PublishedGraphifyPublication {
    /// Stable receipt-bound identifier used to deduplicate caller WAL/recovery
    /// work. It survives a process crash because it is durably recorded in
    /// the transaction journal before CURRENT can change.
    pub(crate) fn transaction_id(&self) -> &str {
        &self.journal.transaction_id
    }

    /// Current durable filesystem transaction phase for publication tests.
    #[cfg(test)]
    pub(crate) fn phase(&self) -> GraphifyTransactionPhase {
        self.journal.phase
    }

    /// The ingest/revoke outcome committed in the pre-CURRENT intent.
    pub(crate) fn ingest_mode(&self) -> GraphifyPublicationIngestMode {
        self.journal.ingest_mode
    }

    /// Exact caller scope committed before `CURRENT` moved.  Recovery and the
    /// normal SQLite coordinator must use this value rather than infer scope
    /// from a friendly corpus name.
    pub(crate) fn ingest_scope(&self) -> GraphifyIngestScope {
        self.journal.ingest_scope
    }

    /// Exact immutable-generation receipt associated with this transaction.
    pub(crate) fn receipt(&self) -> &GraphifyGenerationReceipt {
        &self.receipt
    }

    /// Record successful groundtruth ingest before the caller writes its
    /// completion WAL. A failed ingest must leave the transaction at
    /// `current_published` for crash recovery rather than pretending it ran.
    pub(crate) fn mark_ingested(&mut self) -> Result<()> {
        ensure!(
            self.journal.ingest_mode == GraphifyPublicationIngestMode::Indexed,
            "Graphify transaction was committed as skipped-and-revoked, not indexed"
        );
        self.advance(GraphifyTransactionPhase::Ingested)
    }

    /// Record that the caller intentionally selected the `--no-ingest` path.
    /// This makes CURRENT-without-SQLite explicit and recoverable rather than
    /// indistinguishable from a crash after publication.
    pub(crate) fn mark_ingest_skipped(&mut self) -> Result<()> {
        ensure!(
            self.journal.ingest_mode == GraphifyPublicationIngestMode::SkippedAndRevoked,
            "Graphify transaction was committed for indexed ingest, not skipped-and-revoked"
        );
        self.advance(GraphifyTransactionPhase::IngestSkipped)
    }

    /// Explicitly end the caller-owned transaction only after its completion
    /// or recovery WAL has reached a terminal durable state. Dropping releases
    /// the lease too, but deliberately leaves the journal for recovery.
    pub(crate) fn finish(mut self) -> Result<()> {
        ensure!(
            matches!(
                self.journal.phase,
                GraphifyTransactionPhase::Ingested | GraphifyTransactionPhase::IngestSkipped
            ),
            "Graphify transaction cannot finish before ingest is recorded or intentionally skipped"
        );
        self.advance(GraphifyTransactionPhase::Completed)?;
        crate::util::atomic_write::durable_remove_file(&self.journal_path)
            .context("durably remove completed Graphify transaction journal")?;
        let _ = self.lease;
        Ok(())
    }

    fn advance(&mut self, phase: GraphifyTransactionPhase) -> Result<()> {
        let valid = matches!(
            (self.journal.phase, phase),
            (
                GraphifyTransactionPhase::CurrentPublished,
                GraphifyTransactionPhase::Ingested
            ) | (
                GraphifyTransactionPhase::CurrentPublished,
                GraphifyTransactionPhase::IngestSkipped
            ) | (
                GraphifyTransactionPhase::Ingested,
                GraphifyTransactionPhase::Completed
            ) | (
                GraphifyTransactionPhase::IngestSkipped,
                GraphifyTransactionPhase::Completed
            )
        );
        ensure!(valid, "invalid Graphify transaction phase transition");
        self.journal.phase = phase;
        write_transaction_journal(&self.journal_path, &self.journal)
    }
}

impl From<&GraphifyGenerationReceipt> for CurrentGraphifyPointer {
    fn from(receipt: &GraphifyGenerationReceipt) -> Self {
        Self {
            schema_version: receipt.schema_version,
            corpus_id: receipt.corpus_id.clone(),
            corpus_namespace: receipt.corpus_namespace.clone(),
            generation_id: receipt.generation_id.clone(),
            source_fingerprint_sha256: receipt.source_fingerprint_sha256.clone(),
            native_index_generation: receipt.native_index_generation,
            native_graph_generation: receipt.native_graph_generation,
        }
    }
}

/// Acquire the writer lease before Graphify begins writing `graphify-out`.
///
/// `corpus_id` is intentionally the opaque root-derived identity rather than
/// a friendly subdirectory, so an operator rename cannot split the lock
/// domain. The lock file lives under the validated vault root, never in a
/// possibly still-unbound corpus directory.
pub(crate) fn acquire_graphify_publication_lease(
    vault_root: &Path,
    repository_root: &CanonicalRepoRoot,
) -> Result<GraphifyPublicationLease> {
    // Recovery deliberately acquires this from the canonical physical root,
    // not a freshly rebuilt snapshot.  A crash must be repairable before any
    // native generation-mutating work is permitted.
    let observed_repository = CanonicalRepoRoot::discover(repository_root.path())
        .context("revalidate canonical repository root for Graphify lease")?;
    ensure!(
        observed_repository == *repository_root,
        "Graphify lease repository identity changed"
    );
    let vault_root = discover_strict_directory(vault_root, "Graphify vault root")?;
    let corpus_id = corpus_id_for_root(repository_root);
    ensure!(
        corpus_id.starts_with("graphify-root-v1-")
            && corpus_id
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
        "Graphify corpus identifier is not a canonical opaque lock key"
    );
    ensure_root_unchanged(&vault_root, "vault")?;
    let leases_dir = ensure_real_child_directory(
        vault_root.path(),
        LEASES_DIR_NAME,
        "Graphify publication lease directory",
    )?;
    ensure_direct_child(
        &vault_root,
        &leases_dir,
        "Graphify publication lease directory",
    )?;
    let lock_path = leases_dir.join(format!("{corpus_id}.lock"));
    let process = acquire_process_corpus_lease(lock_path.clone())?;
    let file = crate::util::locked_file::lock_file_blocking(&lock_path, "Graphify publication")?;
    reject_non_regular_existing_file(&lock_path, "Graphify publication lease")?;
    Ok(GraphifyPublicationLease {
        vault_root,
        corpus_id,
        _file: file,
        _process: process,
    })
}

fn acquire_process_corpus_lease(key: PathBuf) -> Result<ProcessCorpusLease> {
    let started = Instant::now();
    loop {
        match process_lease_set().try_lock() {
            Ok(mut held) => {
                if held.insert(key.clone()) {
                    return Ok(ProcessCorpusLease { key });
                }
            }
            Err(std::sync::TryLockError::Poisoned(_)) => {
                bail!("Graphify process-local publication lease is poisoned")
            }
            Err(std::sync::TryLockError::WouldBlock) => {}
        }
        ensure!(
            started.elapsed() < LEASE_WAIT,
            "Graphify publication lease {key:?} held by this process for >5s"
        );
        std::thread::sleep(LEASE_RETRY);
    }
}

fn process_lease_set() -> &'static Mutex<BTreeSet<PathBuf>> {
    static HELD_CORPORA: OnceLock<Mutex<BTreeSet<PathBuf>>> = OnceLock::new();
    HELD_CORPORA.get_or_init(|| Mutex::new(BTreeSet::<PathBuf>::new()))
}

/// Validate, copy, hash, and privately stage one complete Graphify generation.
/// No consumer-visible pointer is changed by this function.
pub(crate) fn prepare_graphify_publication(
    request: GraphifyPublishRequest<'_>,
) -> Result<PreparedGraphifyPublication> {
    let native_snapshot = request.native_snapshot.snapshot();
    validate_native_snapshot(native_snapshot)?;
    let repository_root = native_snapshot.root.clone();
    ensure_root_unchanged(&repository_root, "repository")?;

    let vault_root = discover_strict_directory(request.vault_root, "Graphify vault root")?;
    ensure!(
        vault_root.identity() != repository_root.identity(),
        "Graphify vault root must not be the repository root"
    );

    let friendly_subdir = match request.friendly_subdir {
        Some(value) => validate_friendly_subdir(value)?,
        None => default_friendly_subdir(native_snapshot),
    };
    let corpus_id = corpus_id(native_snapshot);
    let corpus_namespace = corpus_namespace(native_snapshot);
    let binding = CorpusBinding {
        schema_version: GRAPHIFY_PUBLISH_SCHEMA,
        corpus_id: corpus_id.clone(),
        friendly_subdir: friendly_subdir.clone(),
        canonical_repo_root: repository_root.display().to_owned(),
        repo_root_identity_sha256: native_snapshot.root_identity_sha256.clone(),
        canonical_vault_root: vault_root.display().to_owned(),
        vault_root_identity_sha256: physical_root_digest(
            b"neoth.graphify.vault-root.v1\0",
            &vault_root,
        ),
    };
    ensure!(
        request.lease.vault_root == vault_root && request.lease.corpus_id == corpus_id,
        "Graphify publication lease is bound to a different vault or native corpus"
    );
    let requested_corpus_dir = vault_root.path().join(&friendly_subdir);
    ensure_unique_corpus_binding_under_lease(&request.lease, &requested_corpus_dir)?;
    let corpus_dir = ensure_real_child_directory(
        vault_root.path(),
        &friendly_subdir,
        "Graphify corpus directory",
    )?;
    // The caller acquired the lease before Graphify rewrote `graphify-out`.
    // A stage is never created in an unbound corpus: either we durably bind
    // the empty corpus under that still-held lease, or preparation fails
    // before leaving any staged evidence behind.
    prepare_or_validate_corpus_directory(&corpus_dir, &binding)?;
    ensure_corpus_binding(&corpus_dir, &binding)?;
    let expected_current = read_current_pointer(&corpus_dir)?;
    let expected_current_bytes = if expected_current.is_some() {
        Some(read_regular_bounded_no_follow(
            &corpus_dir.join(CURRENT_POINTER_NAME),
            MAX_POINTER_BYTES,
            CURRENT_POINTER_NAME,
        )?)
    } else {
        None
    };

    let graphify_output = repository_root.path().join("graphify-out");
    ensure_real_directory(&graphify_output, "Graphify source output directory")?;
    ensure_direct_child(
        &repository_root,
        &graphify_output,
        "Graphify source output directory",
    )?;

    let artifacts = collect_source_artifacts(&graphify_output)?;
    let total_bytes = artifacts.iter().try_fold(0_u64, |total, artifact| {
        total
            .checked_add(artifact.receipt.bytes)
            .context("Graphify artifact byte total overflow")
    })?;
    ensure!(
        total_bytes <= MAX_TOTAL_ARTIFACT_BYTES,
        "Graphify artifacts exceed aggregate byte limit"
    );
    ensure_root_unchanged(&repository_root, "repository")?;

    let mut receipt = GraphifyGenerationReceipt {
        schema_version: GRAPHIFY_PUBLISH_SCHEMA,
        corpus_id,
        corpus_namespace,
        generation_id: String::new(),
        friendly_subdir,
        canonical_repo_root: repository_root.display().to_owned(),
        repo_root_identity_sha256: native_snapshot.root_identity_sha256.clone(),
        canonical_vault_root: vault_root.display().to_owned(),
        vault_root_identity_sha256: binding.vault_root_identity_sha256.clone(),
        source_fingerprint_sha256: native_snapshot.source_fingerprint_sha256.clone(),
        native_index_generation: native_snapshot.index_generation,
        native_graph_generation: native_snapshot.graph_generation,
        artifacts: artifacts
            .iter()
            .map(|artifact| artifact.receipt.clone())
            .collect(),
    };
    receipt.generation_id = generation_id(&receipt);

    let stage = tempfile::Builder::new()
        .prefix(".neoth-graphify-stage-")
        .tempdir_in(&corpus_dir)
        .with_context(|| format!("create private Graphify stage in {}", corpus_dir.display()))?;
    ensure_real_directory(stage.path(), "Graphify staging directory")?;
    ensure_direct_path_child(&corpus_dir, stage.path(), "Graphify staging directory")?;

    for artifact in &artifacts {
        let target = stage.path().join(&artifact.receipt.name);
        crate::util::atomic_write::write_private_create_new_durable(&target, &artifact.bytes)
            .with_context(|| format!("stage Graphify artifact {}", artifact.receipt.name))?;
    }
    let receipt_path = stage.path().join(GENERATION_RECEIPT_NAME);
    let receipt_bytes = json_line(&receipt).context("serialize Graphify generation receipt")?;
    ensure!(
        receipt_bytes.len() as u64 <= MAX_RECEIPT_BYTES,
        "Graphify generation receipt exceeds byte limit"
    );
    crate::util::atomic_write::write_private_create_new_durable(&receipt_path, &receipt_bytes)
        .context("stage Graphify generation receipt")?;
    validate_staged_generation(stage.path(), &receipt)?;

    let generation_dir = corpus_dir
        .join(GENERATIONS_DIR_NAME)
        .join(&receipt.generation_id);
    Ok(PreparedGraphifyPublication {
        vault_root,
        repository_root,
        corpus_dir,
        generation_dir,
        binding,
        native_snapshot: request.native_snapshot.clone(),
        expected_current,
        expected_current_bytes,
        ingest_mode: request.ingest_mode,
        ingest_scope: request.ingest_scope,
        receipt,
        stage,
        _lease: request.lease,
    })
}

/// Read and validate the atomic pointer from one already-validated corpus
/// directory.  This is intentionally small: consumers still verify the named
/// generation receipt/artifacts before ingesting them.
pub fn read_current_graphify_pointer(
    corpus_dir: impl AsRef<Path>,
) -> Result<Option<CurrentGraphifyPointer>> {
    ensure_real_directory(corpus_dir.as_ref(), "Graphify corpus directory")?;
    read_current_pointer(corpus_dir.as_ref())
}

/// Load the exact immutable generation named by a corpus `CURRENT` pointer.
///
/// This is the recovery-safe counterpart to reading the small pointer: it
/// accepts no path supplied by the pointer until the ID is validated as a
/// normal generation name, then verifies the bounded no-follow receipt, every
/// receipted artifact, the closed entry set, and immutable permissions.
pub(crate) fn load_current_graphify_generation_receipt(
    corpus_dir: &Path,
) -> Result<Option<(PathBuf, GraphifyGenerationReceipt)>> {
    ensure_real_directory(corpus_dir, "Graphify corpus directory")?;
    let Some(pointer) = read_current_pointer(corpus_dir)? else {
        return Ok(None);
    };
    ensure!(
        valid_generation_id(&pointer.generation_id),
        "Graphify CURRENT pointer carries an invalid generation identifier"
    );
    let generations_dir = existing_real_child_directory(
        corpus_dir,
        GENERATIONS_DIR_NAME,
        "Graphify generations directory",
    )?;
    let generation_dir = existing_real_child_directory(
        &generations_dir,
        &pointer.generation_id,
        "Graphify CURRENT generation directory",
    )?;
    let receipt_bytes = read_regular_bounded_no_follow(
        &generation_dir.join(GENERATION_RECEIPT_NAME),
        MAX_RECEIPT_BYTES,
        GENERATION_RECEIPT_NAME,
    )?;
    let receipt: GraphifyGenerationReceipt = serde_json::from_slice(&receipt_bytes)
        .context("parse Graphify CURRENT generation receipt")?;
    validate_receipt_shape(&receipt)?;
    ensure!(
        receipt.corpus_id == pointer.corpus_id
            && receipt.corpus_namespace == pointer.corpus_namespace
            && receipt.generation_id == pointer.generation_id
            && receipt.source_fingerprint_sha256 == pointer.source_fingerprint_sha256
            && receipt.native_index_generation == pointer.native_index_generation
            && receipt.native_graph_generation == pointer.native_graph_generation,
        "Graphify CURRENT pointer does not exactly match its generation receipt"
    );
    validate_published_generation(&generation_dir, &receipt)?;
    validate_generation_read_only(&generation_dir)?;
    Ok(Some((generation_dir, receipt)))
}

/// Discover the one pending corpus transaction for this root-bound lease even
/// if an operator has changed the configured friendly subdirectory since the
/// transaction started. The vault is treated as a strict namespace: an opaque
/// corpus identity may be bound to zero or exactly one real immediate child.
pub(crate) fn discover_graphify_recovery_targets_under_lease(
    lease: &GraphifyPublicationLease,
) -> Result<Vec<PathBuf>> {
    let bindings = scan_corpus_bindings_for_lease(lease)?;
    let mut targets = Vec::new();
    for (corpus_dir, binding) in bindings {
        let journal_path = corpus_dir.join(GRAPHIFY_TRANSACTION_NAME);
        let Some(journal) = read_transaction_journal(&journal_path)? else {
            continue;
        };
        ensure!(
            journal.corpus_id == binding.corpus_id,
            "Graphify transaction journal does not match its corpus binding"
        );
        targets.push(corpus_dir);
    }
    targets.sort();
    Ok(targets)
}

fn validate_native_snapshot(snapshot: &RebuildSnapshot) -> Result<()> {
    ensure!(
        snapshot.index_generation > 0 && snapshot.graph_generation > 0,
        "Graphify publication requires positive native generations"
    );
    ensure!(
        snapshot.index_generation == snapshot.graph_generation,
        "Graphify publication requires equal native index/graph generations"
    );
    ensure!(
        snapshot.scan_report.oversize_skipped == 0 && snapshot.scan_report.truncated_at.is_none(),
        "Graphify publication requires a complete native source snapshot"
    );
    ensure!(
        valid_sha256(&snapshot.source_fingerprint_sha256),
        "native source fingerprint is not a canonical lowercase SHA-256"
    );
    ensure!(
        valid_sha256(&snapshot.root_identity_sha256),
        "native root identity is not a canonical lowercase SHA-256"
    );
    let expected = physical_root_digest(b"neoth.code-map.root-identity.v1\0", &snapshot.root);
    ensure!(
        snapshot.root_identity_sha256 == expected,
        "native root identity digest does not match the physical repository root"
    );
    Ok(())
}

fn corpus_id(snapshot: &RebuildSnapshot) -> String {
    corpus_id_for_root(&snapshot.root)
}

fn corpus_id_for_root(root: &CanonicalRepoRoot) -> String {
    let mut digest = Sha256::new();
    digest.update(b"neoth.graphify.corpus-root.v1\0");
    digest.update(root.identity().as_str().as_bytes());
    format!("graphify-root-v1-{}", hex::encode(digest.finalize()))
}

fn corpus_namespace(snapshot: &RebuildSnapshot) -> String {
    let mut digest = Sha256::new();
    digest.update(b"neoth.graphify.corpus-snapshot.v1\0");
    digest.update(snapshot.root.identity().as_str().as_bytes());
    digest.update(b"\0");
    digest.update(snapshot.source_fingerprint_sha256.as_bytes());
    format!("graphify-v1-{}", hex::encode(digest.finalize()))
}

fn default_friendly_subdir(snapshot: &RebuildSnapshot) -> String {
    format!("NEOTH-Graphify-{}", &snapshot.root_identity_sha256[..24])
}

fn generation_id(receipt: &GraphifyGenerationReceipt) -> String {
    let mut digest = Sha256::new();
    digest.update(b"neoth.graphify.generation.v1\0");
    digest.update(receipt.corpus_namespace.as_bytes());
    digest.update(b"\0");
    digest.update(receipt.native_index_generation.to_le_bytes());
    digest.update(receipt.native_graph_generation.to_le_bytes());
    for artifact in &receipt.artifacts {
        digest.update(b"\0");
        digest.update(artifact.name.as_bytes());
        digest.update(b"\0");
        digest.update(artifact.bytes.to_le_bytes());
        digest.update(b"\0");
        digest.update(artifact.sha256.as_bytes());
    }
    format!("gen-v1-{}", hex::encode(digest.finalize()))
}

fn valid_generation_id(value: &str) -> bool {
    value.starts_with("gen-v1-")
        && value.len() == "gen-v1-".len() + 64
        && value["gen-v1-".len()..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn transaction_id(receipt: &GraphifyGenerationReceipt, scope: GraphifyIngestScope) -> String {
    crate::wiki::ingest::graphify_ingest_transaction_id(receipt, scope)
}

fn validate_friendly_subdir(raw: &str) -> Result<String> {
    ensure!(!raw.is_empty(), "Graphify friendly subdirectory is empty");
    ensure!(
        raw.len() <= MAX_FRIENDLY_SUBDIR_BYTES,
        "Graphify friendly subdirectory exceeds {MAX_FRIENDLY_SUBDIR_BYTES} UTF-8 bytes"
    );
    ensure!(
        !raw.chars().any(char::is_control),
        "Graphify friendly subdirectory contains a control character"
    );
    ensure!(
        !raw.contains('/') && !raw.contains('\\'),
        "Graphify friendly subdirectory must be one path segment"
    );
    ensure!(
        !raw.ends_with('.') && !raw.ends_with(' '),
        "Graphify friendly subdirectory has a non-portable trailing character"
    );
    ensure!(
        !raw.chars()
            .any(|ch| matches!(ch, ':' | '*' | '?' | '"' | '<' | '>' | '|')),
        "Graphify friendly subdirectory contains a non-portable path character"
    );
    let path = Path::new(raw);
    let mut components = path.components();
    let Some(Component::Normal(component)) = components.next() else {
        bail!("Graphify friendly subdirectory is not a normal path segment");
    };
    ensure!(
        components.next().is_none() && component == OsStr::new(raw),
        "Graphify friendly subdirectory must be exactly one normal path segment"
    );
    let portable_stem = raw
        .split('.')
        .next()
        .unwrap_or(raw)
        .trim_end_matches([' ', '.'])
        .to_ascii_uppercase();
    ensure!(
        !matches!(
            portable_stem.as_str(),
            "CON"
                | "PRN"
                | "AUX"
                | "NUL"
                | "COM1"
                | "COM2"
                | "COM3"
                | "COM4"
                | "COM5"
                | "COM6"
                | "COM7"
                | "COM8"
                | "COM9"
                | "LPT1"
                | "LPT2"
                | "LPT3"
                | "LPT4"
                | "LPT5"
                | "LPT6"
                | "LPT7"
                | "LPT8"
                | "LPT9"
        ),
        "Graphify friendly subdirectory is a reserved portable device name"
    );
    Ok(raw.to_owned())
}

fn collect_source_artifacts(graphify_output: &Path) -> Result<Vec<StagedArtifact>> {
    // The report and tree are one logical evidence set. Read every required
    // member twice and require the complete second set to match the first;
    // accepting a report without its paired tree (or a mix observed during a
    // Graphify rewrite) would make an immutable generation misleading.
    let artifacts = read_source_artifact_set(graphify_output)?;
    let rechecked = read_source_artifact_set(graphify_output)?;
    ensure!(
        artifacts
            .iter()
            .map(|artifact| (&artifact.receipt, &artifact.bytes))
            .eq(rechecked
                .iter()
                .map(|artifact| (&artifact.receipt, &artifact.bytes))),
        "Graphify artifact set changed while publication was being prepared"
    );
    Ok(artifacts)
}

fn read_source_artifact_set(graphify_output: &Path) -> Result<Vec<StagedArtifact>> {
    Ok(vec![
        read_stable_artifact(
            &graphify_output.join(GRAPH_REPORT_NAME),
            GRAPH_REPORT_NAME,
            MAX_REPORT_BYTES,
        )?,
        read_stable_artifact(
            &graphify_output.join(GRAPH_TREE_NAME),
            GRAPH_TREE_NAME,
            MAX_TREE_BYTES,
        )?,
    ])
}

fn read_stable_artifact(path: &Path, name: &str, max_bytes: u64) -> Result<StagedArtifact> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            bail!("required Graphify artifact {name} is missing")
        }
        Err(error) => {
            return Err(error).with_context(|| format!("inspect Graphify artifact {name}"));
        }
    }
    let bytes = read_regular_bounded_no_follow(path, max_bytes, name)?;
    ensure!(
        bytes.iter().any(|byte| !byte.is_ascii_whitespace()),
        "Graphify artifact {name} is empty or whitespace-only"
    );
    let first_sha256 = sha256_bytes(&bytes);
    let (second_bytes, second_sha256) = hash_regular_bounded_no_follow(path, max_bytes, name)?;
    ensure!(
        second_bytes == bytes.len() as u64 && second_sha256 == first_sha256,
        "Graphify artifact {name} changed while publication was being prepared"
    );
    Ok(StagedArtifact {
        receipt: GraphifyArtifactReceipt {
            name: name.to_owned(),
            bytes: bytes.len() as u64,
            sha256: first_sha256,
        },
        bytes,
    })
}

fn validate_staged_generation(stage: &Path, receipt: &GraphifyGenerationReceipt) -> Result<()> {
    ensure_real_directory(stage, "Graphify staging directory")?;
    validate_generation_contents(stage, receipt)
}

fn validate_published_generation(
    generation: &Path,
    receipt: &GraphifyGenerationReceipt,
) -> Result<()> {
    ensure_real_directory(generation, "Graphify immutable generation directory")?;
    validate_generation_contents(generation, receipt)
}

fn validate_generation_contents(
    generation: &Path,
    expected: &GraphifyGenerationReceipt,
) -> Result<()> {
    validate_receipt_shape(expected)?;
    let receipt_bytes = read_regular_bounded_no_follow(
        &generation.join(GENERATION_RECEIPT_NAME),
        MAX_RECEIPT_BYTES,
        GENERATION_RECEIPT_NAME,
    )?;
    let observed: GraphifyGenerationReceipt =
        serde_json::from_slice(&receipt_bytes).context("parse Graphify generation receipt")?;
    ensure!(
        observed == *expected,
        "Graphify generation receipt differs from the prepared receipt"
    );

    let mut expected_names = BTreeSet::from([GENERATION_RECEIPT_NAME.to_owned()]);
    for artifact in &expected.artifacts {
        expected_names.insert(artifact.name.clone());
        let (bytes, sha256) = hash_regular_bounded_no_follow(
            &generation.join(&artifact.name),
            limit_for_artifact(&artifact.name)?,
            &artifact.name,
        )?;
        ensure!(
            bytes == artifact.bytes && sha256 == artifact.sha256,
            "published Graphify artifact {} differs from its receipt",
            artifact.name
        );
    }
    let actual_names = directory_entry_names(generation)?;
    ensure!(
        actual_names == expected_names,
        "Graphify generation contains an unreceipted or missing artifact"
    );
    Ok(())
}

fn validate_receipt_shape(receipt: &GraphifyGenerationReceipt) -> Result<()> {
    ensure!(
        receipt.schema_version == GRAPHIFY_PUBLISH_SCHEMA,
        "unsupported Graphify generation receipt schema"
    );
    ensure!(
        receipt.native_index_generation > 0
            && receipt.native_index_generation == receipt.native_graph_generation,
        "Graphify receipt carries invalid native generations"
    );
    ensure!(
        valid_sha256(&receipt.repo_root_identity_sha256)
            && valid_sha256(&receipt.vault_root_identity_sha256)
            && valid_sha256(&receipt.source_fingerprint_sha256),
        "Graphify receipt carries a non-canonical SHA-256"
    );
    ensure!(
        receipt.generation_id == generation_id(receipt),
        "Graphify generation id does not bind the receipt contents"
    );
    ensure!(
        receipt.artifacts.len() == 2,
        "Graphify receipt must carry exactly the complete report/tree artifact set"
    );
    ensure!(
        receipt.artifacts[0].name == GRAPH_REPORT_NAME,
        "Graphify receipt is missing its required report"
    );
    ensure!(
        receipt.artifacts[1].name == GRAPH_TREE_NAME,
        "Graphify receipt is missing its required tree"
    );
    Ok(())
}

fn limit_for_artifact(name: &str) -> Result<u64> {
    match name {
        GRAPH_REPORT_NAME => Ok(MAX_REPORT_BYTES),
        GRAPH_TREE_NAME => Ok(MAX_TREE_BYTES),
        _ => bail!("unsupported Graphify artifact name {name:?}"),
    }
}

fn prepare_or_validate_corpus_directory(corpus_dir: &Path, expected: &CorpusBinding) -> Result<()> {
    let binding_path = corpus_dir.join(CORPUS_BINDING_NAME);
    match fs::symlink_metadata(&binding_path) {
        Ok(_) => validate_corpus_binding(corpus_dir, expected),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            ensure!(
                directory_entry_names(corpus_dir)?.is_empty(),
                "unbound Graphify corpus directory is not empty"
            );
            Ok(())
        }
        Err(error) => Err(error).context("inspect Graphify corpus binding"),
    }
}

fn ensure_corpus_binding(corpus_dir: &Path, expected: &CorpusBinding) -> Result<()> {
    let path = corpus_dir.join(CORPUS_BINDING_NAME);
    let bytes = json_line(expected).context("serialize Graphify corpus binding")?;
    match crate::util::atomic_write::write_private_create_new_durable(&path, &bytes) {
        Ok(()) => validate_corpus_binding(corpus_dir, expected),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            validate_corpus_binding(corpus_dir, expected)
        }
        Err(error) => Err(error).context("create durable Graphify corpus binding"),
    }
}

fn validate_corpus_binding(corpus_dir: &Path, expected: &CorpusBinding) -> Result<()> {
    let bytes = read_regular_bounded_no_follow(
        &corpus_dir.join(CORPUS_BINDING_NAME),
        MAX_BINDING_BYTES,
        CORPUS_BINDING_NAME,
    )?;
    let observed: CorpusBinding =
        serde_json::from_slice(&bytes).context("parse Graphify corpus binding")?;
    ensure!(
        observed == *expected,
        "Graphify friendly subdirectory is already bound to another physical root or vault"
    );
    Ok(())
}

/// Enforce the one-corpus/one-friendly-subdirectory invariant while the
/// caller-owned lease is held. Without this, two CURRENT pointers for one
/// source root could share a lock/SQLite scope and make recovery ordering
/// ambiguous.
fn ensure_unique_corpus_binding_under_lease(
    lease: &GraphifyPublicationLease,
    requested_corpus_dir: &Path,
) -> Result<()> {
    let bindings = scan_corpus_bindings_for_lease(lease)?;
    match bindings.as_slice() {
        [] => Ok(()),
        [(bound_corpus_dir, _)] if bound_corpus_dir == requested_corpus_dir => Ok(()),
        [(bound_corpus_dir, _)] => bail!(
            "Graphify corpus {} is already bound to friendly subdirectory {}; refusing a second subdirectory {} without a typed rename",
            lease.corpus_id,
            bound_corpus_dir.display(),
            requested_corpus_dir.display()
        ),
        _ => bail!(
            "Graphify corpus {} has multiple friendly-subdirectory bindings in vault {}; recovery is ambiguous",
            lease.corpus_id,
            lease.vault_root.display()
        ),
    }
}

/// Return every real immediate vault child bound to this lease's opaque corpus
/// identity. A malformed/reparse binding is an error, not a path to skip:
/// silently skipping it would make an attacker-controlled duplicate invisible
/// to recovery and preparation.
fn scan_corpus_bindings_for_lease(
    lease: &GraphifyPublicationLease,
) -> Result<Vec<(PathBuf, CorpusBinding)>> {
    ensure_root_unchanged(&lease.vault_root, "vault")?;
    let expected_vault_digest =
        physical_root_digest(b"neoth.graphify.vault-root.v1\0", &lease.vault_root);
    let mut bindings = Vec::new();
    for entry in fs::read_dir(lease.vault_root.path())
        .with_context(|| format!("scan Graphify vault {}", lease.vault_root.display()))?
    {
        let entry = entry.context("read Graphify vault entry")?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("inspect Graphify vault entry {}", path.display()))?;
        ensure!(
            !metadata_is_link_like(&metadata),
            "Graphify vault contains a symlink/reparse immediate child {}; refusing ambiguous corpus scan",
            path.display()
        );
        if !metadata.is_dir() {
            continue;
        }
        ensure_direct_child(&lease.vault_root, &path, "Graphify vault corpus candidate")?;
        let binding_path = path.join(CORPUS_BINDING_NAME);
        let binding = match fs::symlink_metadata(&binding_path) {
            Ok(_) => {
                let bytes = read_regular_bounded_no_follow(
                    &binding_path,
                    MAX_BINDING_BYTES,
                    CORPUS_BINDING_NAME,
                )?;
                serde_json::from_slice::<CorpusBinding>(&bytes)
                    .context("parse Graphify corpus binding during vault scan")?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).context("inspect Graphify corpus binding during vault scan");
            }
        };
        ensure!(
            binding.schema_version == GRAPHIFY_PUBLISH_SCHEMA
                && binding.canonical_vault_root == lease.vault_root.display()
                && binding.vault_root_identity_sha256 == expected_vault_digest,
            "Graphify vault contains an invalid or foreign corpus binding {}",
            binding_path.display()
        );
        let child_name = path
            .file_name()
            .and_then(OsStr::to_str)
            .context("Graphify vault corpus binding has a non-UTF-8 directory name")?;
        ensure!(
            binding.friendly_subdir == child_name,
            "Graphify corpus binding friendly subdirectory does not match its directory"
        );
        if binding.corpus_id == lease.corpus_id {
            bindings.push((path, binding));
        }
    }
    bindings.sort_by(|left, right| left.0.cmp(&right.0));
    ensure!(
        bindings.len() <= 1,
        "Graphify corpus {} has duplicate friendly-subdirectory bindings in vault {}; refusing ambiguous recovery",
        lease.corpus_id,
        lease.vault_root.display()
    );
    Ok(bindings)
}

fn read_current_pointer(corpus_dir: &Path) -> Result<Option<CurrentGraphifyPointer>> {
    let path = corpus_dir.join(CURRENT_POINTER_NAME);
    let Some(bytes) = read_optional_current_bytes(&path)? else {
        return Ok(None);
    };
    let pointer: CurrentGraphifyPointer =
        serde_json::from_slice(&bytes).context("parse Graphify CURRENT pointer")?;
    validate_current_pointer(&pointer)?;
    Ok(Some(pointer))
}

fn read_optional_current_bytes(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("inspect Graphify CURRENT pointer"),
    }
    Ok(Some(read_regular_bounded_no_follow(
        path,
        MAX_POINTER_BYTES,
        CURRENT_POINTER_NAME,
    )?))
}

fn validate_current_pointer(pointer: &CurrentGraphifyPointer) -> Result<()> {
    ensure!(
        pointer.schema_version == GRAPHIFY_PUBLISH_SCHEMA,
        "unsupported Graphify CURRENT pointer schema"
    );
    ensure!(
        pointer.native_index_generation > 0
            && pointer.native_index_generation == pointer.native_graph_generation,
        "Graphify CURRENT pointer carries invalid native generations"
    );
    ensure!(
        valid_sha256(&pointer.source_fingerprint_sha256),
        "Graphify CURRENT pointer carries an invalid source fingerprint"
    );
    Ok(())
}

fn discover_strict_directory(path: &Path, label: &str) -> Result<CanonicalRepoRoot> {
    validate_existing_directory_chain(path, label)?;
    let root = CanonicalRepoRoot::discover(path).with_context(|| format!("resolve {label}"))?;
    validate_existing_directory_chain(root.path(), label)?;
    Ok(root)
}

fn validate_existing_directory_chain(path: &Path, label: &str) -> Result<()> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("resolve current directory for physical path validation")?
            .join(path)
    };
    let mut current = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                current.push(component.as_os_str());
            }
            Component::CurDir | Component::ParentDir => {
                bail!("{label} contains a dot path component")
            }
        }
        // A Windows drive prefix is not independently stat-able.
        if matches!(component, Component::Prefix(_)) {
            continue;
        }
        let metadata = fs::symlink_metadata(&current)
            .with_context(|| format!("inspect {label} component {}", current.display()))?;
        ensure!(
            !metadata_is_link_like(&metadata) && metadata.is_dir(),
            "{label} contains a symlink, junction, reparse point, or non-directory component: {}",
            current.display()
        );
    }
    Ok(())
}

fn ensure_real_directory(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect {label} {}", path.display()))?;
    ensure!(
        !metadata_is_link_like(&metadata) && metadata.is_dir(),
        "{label} must be a real directory, not a symlink/junction/reparse/special path: {}",
        path.display()
    );
    Ok(())
}

fn ensure_real_child_directory(parent: &Path, name: &str, label: &str) -> Result<PathBuf> {
    validate_friendly_subdir(name)?;
    ensure_real_directory(parent, "Graphify publication parent")?;
    let child = parent.join(name);
    match fs::create_dir(&child) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(error).with_context(|| format!("create {label} {}", child.display()));
        }
    }
    ensure_real_directory(&child, label)?;
    ensure_direct_path_child(parent, &child, label)?;
    Ok(child)
}

fn existing_real_child_directory(parent: &Path, name: &str, label: &str) -> Result<PathBuf> {
    let child = parent.join(name);
    ensure_real_directory(&child, label)?;
    ensure_direct_path_child(parent, &child, label)?;
    Ok(child)
}

fn ensure_direct_child(root: &CanonicalRepoRoot, child: &Path, label: &str) -> Result<()> {
    ensure_direct_path_child(root.path(), child, label)
}

fn ensure_direct_path_child(parent: &Path, child: &Path, label: &str) -> Result<()> {
    let canonical_parent =
        fs::canonicalize(parent).with_context(|| format!("canonicalize parent of {label}"))?;
    let canonical_child = fs::canonicalize(child)
        .with_context(|| format!("canonicalize {label} {}", child.display()))?;
    ensure!(
        canonical_child.parent() == Some(canonical_parent.as_path()),
        "{label} escaped its canonical parent"
    );
    Ok(())
}

fn ensure_root_unchanged(expected: &CanonicalRepoRoot, label: &str) -> Result<()> {
    let observed = CanonicalRepoRoot::discover(expected.path())
        .with_context(|| format!("revalidate physical {label} root"))?;
    ensure!(
        observed == *expected,
        "physical {label} root changed during Graphify publication"
    );
    Ok(())
}

fn reject_non_regular_existing_file(path: &Path, label: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure!(
                !metadata_is_link_like(&metadata) && metadata.is_file(),
                "existing {label} is not a regular no-follow file"
            );
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("inspect existing {label}")),
    }
}

fn open_read_no_follow(path: &Path) -> std::io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        OpenOptions::new()
            .read(true)
            // Metadata is checked only after opening. O_NONBLOCK prevents a
            // hostile FIFO from turning that validation into an unbounded
            // publisher hang; the subsequent regular-file check rejects it.
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        OpenOptions::new().read(true).open(path)
    }
}

fn read_regular_bounded_no_follow(path: &Path, max_bytes: u64, label: &str) -> Result<Vec<u8>> {
    let file = open_read_no_follow(path)
        .with_context(|| format!("open {label} without following links"))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("read handle metadata for {label}"))?;
    ensure!(
        metadata.is_file() && !metadata_is_link_like(&metadata),
        "{label} is not a regular no-follow file"
    );
    ensure!(
        metadata.len() <= max_bytes,
        "{label} exceeds its byte limit"
    );
    let capacity = usize::try_from(metadata.len()).context("convert artifact capacity")?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("read bounded {label}"))?;
    ensure!(
        bytes.len() as u64 <= max_bytes,
        "{label} grew beyond its byte limit"
    );
    ensure!(
        bytes.len() as u64 == metadata.len(),
        "{label} changed length while it was being read"
    );
    Ok(bytes)
}

fn hash_regular_bounded_no_follow(
    path: &Path,
    max_bytes: u64,
    label: &str,
) -> Result<(u64, String)> {
    let mut file = open_read_no_follow(path)
        .with_context(|| format!("reopen {label} without following links"))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("read handle metadata for {label}"))?;
    ensure!(
        metadata.is_file() && !metadata_is_link_like(&metadata),
        "{label} is not a regular no-follow file"
    );
    ensure!(
        metadata.len() <= max_bytes,
        "{label} exceeds its byte limit"
    );
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("hash bounded {label}"))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .context("Graphify artifact byte count overflow")?;
        ensure!(total <= max_bytes, "{label} grew beyond its byte limit");
        digest.update(&buffer[..read]);
    }
    ensure!(
        total == metadata.len(),
        "{label} changed length while it was hashed"
    );
    Ok((total, hex::encode(digest.finalize())))
}

fn metadata_is_link_like(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn directory_entry_names(directory: &Path) -> Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    for entry in fs::read_dir(directory)
        .with_context(|| format!("enumerate Graphify directory {}", directory.display()))?
    {
        let entry = entry.context("read Graphify directory entry")?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("Graphify directory contains a non-UTF-8 entry"))?;
        ensure!(names.insert(name), "duplicate Graphify directory entry");
    }
    Ok(names)
}

fn make_generation_read_only(generation: &Path) -> Result<()> {
    for entry in fs::read_dir(generation).context("enumerate published Graphify generation")? {
        let path = entry.context("read published Graphify entry")?.path();
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("inspect published Graphify entry {}", path.display()))?;
        ensure!(
            metadata.is_file() && !metadata_is_link_like(&metadata),
            "published Graphify generation contains a non-regular entry"
        );
        let mut permissions = metadata.permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&path, permissions)
            .with_context(|| format!("make Graphify artifact read-only {}", path.display()))?;
    }
    let mut permissions = fs::symlink_metadata(generation)?.permissions();
    permissions.set_readonly(true);
    fs::set_permissions(generation, permissions).context("make Graphify generation read-only")?;
    Ok(())
}

/// Permission hardening happens before rename. If it fails after changing a
/// subset of files, restore writability so `TempDir` can deterministically
/// clean the private stage rather than stranding a non-removable directory.
fn harden_staged_generation(generation: &Path) -> Result<()> {
    if let Err(error) = make_generation_read_only(generation) {
        return combine_stage_permission_failure(generation, error);
    }
    if let Err(error) = validate_generation_read_only(generation) {
        return combine_stage_permission_failure(generation, error);
    }
    Ok(())
}

fn combine_stage_permission_failure(generation: &Path, error: anyhow::Error) -> Result<()> {
    match make_generation_writable_for_cleanup(generation) {
        Ok(()) => Err(error).context("staged Graphify permissions were restored for cleanup"),
        Err(cleanup_error) => Err(anyhow::anyhow!(
            "Graphify staged permission hardening failed: {error:#}; permission rollback for cleanup also failed: {cleanup_error:#}"
        )),
    }
}

fn validate_generation_read_only(generation: &Path) -> Result<()> {
    let directory = fs::symlink_metadata(generation)
        .with_context(|| format!("inspect Graphify generation {}", generation.display()))?;
    ensure!(
        directory.is_dir()
            && !metadata_is_link_like(&directory)
            && directory.permissions().readonly(),
        "Graphify generation directory is not immutable"
    );
    for entry in fs::read_dir(generation).context("enumerate immutable Graphify generation")? {
        let path = entry
            .context("read immutable Graphify generation entry")?
            .path();
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("inspect immutable Graphify entry {}", path.display()))?;
        ensure!(
            metadata.is_file()
                && !metadata_is_link_like(&metadata)
                && metadata.permissions().readonly(),
            "Graphify generation contains a writable or non-regular entry"
        );
    }
    Ok(())
}

// Clearing the Windows read-only file attribute is the platform-correct
// prerequisite for deleting the private staging tree. The Unix branch below
// uses explicit owner-only modes and never calls `set_readonly(false)`.
#[cfg_attr(windows, allow(clippy::permissions_set_readonly_false))]
fn make_generation_writable_for_cleanup(generation: &Path) -> Result<()> {
    // On Unix, unlinking staged files only requires write+search permission on
    // their containing directory.  Do not make the artifacts writable again:
    // that would expand their authority needlessly, and never grant group or
    // world write permission while recovering the private temporary stage.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let metadata = fs::symlink_metadata(generation)
            .context("inspect staged Graphify directory for cleanup")?;
        ensure!(
            metadata.is_dir() && !metadata_is_link_like(&metadata),
            "staged Graphify generation is not a real directory"
        );
        let mut permissions = metadata.permissions();
        permissions.set_mode((permissions.mode() & !0o022) | 0o300);
        fs::set_permissions(generation, permissions)
            .context("restore owner cleanup permission for staged Graphify directory")?;
    }

    // Windows models this as a read-only attribute on every child as well as
    // the directory, so it must be cleared before TempDir can remove the stage.
    #[cfg(windows)]
    {
        for entry in fs::read_dir(generation).context("enumerate staged Graphify generation")? {
            let path = entry
                .context("read staged Graphify generation entry")?
                .path();
            let mut permissions = fs::symlink_metadata(&path)?.permissions();
            permissions.set_readonly(false);
            fs::set_permissions(&path, permissions).with_context(|| {
                format!("restore staged Graphify permissions {}", path.display())
            })?;
        }
        let mut permissions = fs::symlink_metadata(generation)?.permissions();
        permissions.set_readonly(false);
        fs::set_permissions(generation, permissions)
            .context("restore staged Graphify directory permissions")
    }

    #[cfg(unix)]
    {
        Ok(())
    }
}

/// Recover a durable Graphify CURRENT intent while holding the same per-corpus
/// lease used by the normal writer. This never invents an ingest outcome: a
/// pointer at the new value returns `CurrentPublished`/later for the caller to
/// reconcile with its SQLite/completion WAL; a pointer at the old value is an
/// uncommitted intent and its journal is removed.
pub(crate) fn recover_graphify_transaction_under_lease(
    lease: &GraphifyPublicationLease,
    corpus_dir: &Path,
) -> Result<GraphifyTransactionPhase> {
    ensure_real_directory(corpus_dir, "Graphify corpus directory")?;
    let journal_path = corpus_dir.join(GRAPHIFY_TRANSACTION_NAME);
    let Some(mut journal) = read_transaction_journal(&journal_path)? else {
        return Ok(GraphifyTransactionPhase::Completed);
    };
    ensure!(
        journal.corpus_id == lease.corpus_id,
        "Graphify transaction journal belongs to a different corpus lease"
    );
    if journal.phase == GraphifyTransactionPhase::Completed {
        ensure_journal_still_owns_current(corpus_dir, &journal)?;
        crate::util::atomic_write::durable_remove_file(&journal_path)
            .context("remove already-completed Graphify transaction journal")?;
        return Ok(GraphifyTransactionPhase::Completed);
    }
    let previous = decode_journal_pointer(journal.previous_current_hex.as_deref())?;
    let next = decode_journal_pointer(Some(&journal.new_current_hex))?
        .context("Graphify transaction journal is missing its replacement CURRENT")?;
    let observed = read_optional_current_bytes(&corpus_dir.join(CURRENT_POINTER_NAME))?;
    if journal.phase == GraphifyTransactionPhase::Prepared {
        if observed.as_deref() == previous.as_deref() {
            crate::util::atomic_write::durable_remove_file(&journal_path)
                .context("remove uncommitted Graphify transaction intent")?;
            return Ok(GraphifyTransactionPhase::Prepared);
        }
        ensure!(
            observed.as_deref() == Some(next.as_slice()),
            "Graphify CURRENT is neither the journal's old nor new value; refusing recovery guess"
        );
        ensure_journal_still_owns_current(corpus_dir, &journal)?;
        journal.phase = GraphifyTransactionPhase::CurrentPublished;
        write_transaction_journal(&journal_path, &journal)
            .context("record recovered Graphify CURRENT publication")?;
    } else {
        ensure_journal_still_owns_current(corpus_dir, &journal)?;
    }
    Ok(journal.phase)
}

/// Inspect the durable local Graphify transaction journal while a caller owns
/// the per-corpus lease. `None` means no active/recoverable transaction.
pub(crate) fn inspect_graphify_transaction_under_lease(
    lease: &GraphifyPublicationLease,
    corpus_dir: &Path,
) -> Result<Option<GraphifyTransactionInspection>> {
    let Some(journal) = read_transaction_journal(&corpus_dir.join(GRAPHIFY_TRANSACTION_NAME))?
    else {
        return Ok(None);
    };
    ensure!(
        journal.corpus_id == lease.corpus_id,
        "Graphify transaction journal belongs to a different corpus lease"
    );
    Ok(Some(GraphifyTransactionInspection {
        transaction_id: journal.transaction_id,
        phase: journal.phase,
        ingest_mode: journal.ingest_mode,
        ingest_scope: journal.ingest_scope,
        corpus_id: journal.corpus_id,
        generation_id: journal.generation_id,
    }))
}

/// After recovery has completed the journal's declared groundtruth action,
/// persist the matching ingest phase. The intent is not caller-selectable:
/// `Indexed` becomes `Ingested`, while `SkippedAndRevoked` becomes
/// `IngestSkipped`, preventing a recovery from changing the pre-CURRENT
/// contract after observing an empty database.
pub(crate) fn mark_recovered_graphify_ingest_phase_under_lease(
    lease: &GraphifyPublicationLease,
    corpus_dir: &Path,
    expected_transaction_id: &str,
) -> Result<GraphifyTransactionPhase> {
    let journal_path = corpus_dir.join(GRAPHIFY_TRANSACTION_NAME);
    let mut journal =
        read_exact_active_journal_under_lease(lease, &journal_path, expected_transaction_id)?;
    ensure!(
        journal.phase == GraphifyTransactionPhase::CurrentPublished,
        "recovered Graphify ingest may be marked only from current_published"
    );
    ensure_journal_still_owns_current(corpus_dir, &journal)?;
    journal.phase = match journal.ingest_mode {
        GraphifyPublicationIngestMode::Indexed => GraphifyTransactionPhase::Ingested,
        GraphifyPublicationIngestMode::SkippedAndRevoked => GraphifyTransactionPhase::IngestSkipped,
    };
    write_transaction_journal(&journal_path, &journal)
        .context("durably record recovered Graphify ingest phase")?;
    Ok(journal.phase)
}

/// Finish exactly one recovered transaction after the coordinator has durably
/// written its own terminal completion/recovery WAL. `allowed_phases` accepts
/// a singleton for an exact expected phase or an explicit allow-list for a
/// coordinator that handles both indexed and skipped/revoked terminal paths.
/// No caller can use this to erase a `current_published` intent before its
/// declared groundtruth action has been recorded.
pub(crate) fn finish_recovered_transaction_under_lease(
    lease: &GraphifyPublicationLease,
    corpus_dir: &Path,
    expected_transaction_id: &str,
    allowed_phases: &[GraphifyTransactionPhase],
) -> Result<()> {
    ensure!(
        !allowed_phases.is_empty(),
        "recovered Graphify finish requires at least one expected phase"
    );
    let journal_path = corpus_dir.join(GRAPHIFY_TRANSACTION_NAME);
    let mut journal =
        read_exact_active_journal_under_lease(lease, &journal_path, expected_transaction_id)?;
    ensure!(
        allowed_phases.contains(&journal.phase),
        "recovered Graphify transaction phase is not allowed for this finish"
    );
    ensure!(
        matches!(
            journal.phase,
            GraphifyTransactionPhase::Ingested | GraphifyTransactionPhase::IngestSkipped
        ),
        "recovered Graphify transaction cannot finish before its ingest mode is recorded"
    );
    ensure_journal_still_owns_current(corpus_dir, &journal)?;
    journal.phase = GraphifyTransactionPhase::Completed;
    write_transaction_journal(&journal_path, &journal)
        .context("durably record completed recovered Graphify transaction")?;
    crate::util::atomic_write::durable_remove_file(&journal_path)
        .context("durably remove completed recovered Graphify transaction journal")
}

fn read_exact_active_journal_under_lease(
    lease: &GraphifyPublicationLease,
    journal_path: &Path,
    expected_transaction_id: &str,
) -> Result<GraphifyPublicationJournal> {
    let journal = read_transaction_journal(journal_path)?
        .context("Graphify transaction journal is missing during recovery")?;
    ensure!(
        journal.corpus_id == lease.corpus_id,
        "Graphify transaction journal belongs to a different corpus lease"
    );
    ensure!(
        journal.transaction_id == expected_transaction_id,
        "Graphify transaction ID changed during recovery"
    );
    ensure!(
        journal.phase != GraphifyTransactionPhase::Completed,
        "Graphify transaction was already completed"
    );
    Ok(journal)
}

fn ensure_journal_still_owns_current(
    corpus_dir: &Path,
    journal: &GraphifyPublicationJournal,
) -> Result<()> {
    let next = decode_journal_pointer(Some(&journal.new_current_hex))?
        .context("Graphify transaction journal is missing its replacement CURRENT")?;
    let pointer: CurrentGraphifyPointer =
        serde_json::from_slice(&next).context("parse Graphify transaction replacement CURRENT")?;
    validate_current_pointer(&pointer)?;
    ensure!(
        pointer.corpus_id == journal.corpus_id && pointer.generation_id == journal.generation_id,
        "Graphify transaction replacement CURRENT does not match its journal identity"
    );
    ensure!(
        read_optional_current_bytes(&corpus_dir.join(CURRENT_POINTER_NAME))?.as_deref()
            == Some(next.as_slice()),
        "Graphify CURRENT no longer matches durable transaction journal"
    );
    Ok(())
}

/// Safely roll back a prepared or current-published intent when the caller's
/// own recovery policy has established that ingest/WAL must not proceed. The
/// helper only replaces CURRENT if its raw bytes are still this transaction's
/// new value; a concurrent or manual pointer change is never overwritten.
#[cfg(test)]
pub(crate) fn rollback_graphify_transaction_under_lease(
    lease: &GraphifyPublicationLease,
    corpus_dir: &Path,
) -> Result<()> {
    let journal_path = corpus_dir.join(GRAPHIFY_TRANSACTION_NAME);
    let Some(journal) = read_transaction_journal(&journal_path)? else {
        return Ok(());
    };
    ensure!(
        journal.corpus_id == lease.corpus_id,
        "Graphify transaction journal belongs to a different corpus lease"
    );
    ensure!(
        matches!(
            journal.phase,
            GraphifyTransactionPhase::Prepared | GraphifyTransactionPhase::CurrentPublished
        ),
        "Graphify transaction may not be rolled back after ingest state was recorded"
    );
    let previous = decode_journal_pointer(journal.previous_current_hex.as_deref())?;
    let next = decode_journal_pointer(Some(&journal.new_current_hex))?
        .context("Graphify transaction journal is missing its replacement CURRENT")?;
    restore_current_pointer_if_ours(
        &corpus_dir.join(CURRENT_POINTER_NAME),
        previous.as_deref(),
        &next,
    )?;
    crate::util::atomic_write::durable_remove_file(&journal_path)
        .context("durably remove rolled-back Graphify transaction journal")
}

fn write_transaction_journal(path: &Path, journal: &GraphifyPublicationJournal) -> Result<()> {
    let bytes = json_line(journal).context("serialize Graphify transaction journal")?;
    ensure!(
        bytes.len() as u64 <= MAX_TRANSACTION_BYTES,
        "Graphify transaction journal exceeds byte limit"
    );
    crate::util::atomic_write::atomic_write_private(path, &bytes)
        .context("atomically write Graphify transaction journal")?;
    crate::util::atomic_write::sync_parent_directory_required(path)
        .context("durably publish Graphify transaction journal")
}

fn read_transaction_journal(path: &Path) -> Result<Option<GraphifyPublicationJournal>> {
    let Some(bytes) = (match fs::symlink_metadata(path) {
        Ok(_) => Some(read_regular_bounded_no_follow(
            path,
            MAX_TRANSACTION_BYTES,
            "Graphify transaction journal",
        )?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error).context("inspect Graphify transaction journal"),
    }) else {
        return Ok(None);
    };
    let journal: GraphifyPublicationJournal =
        serde_json::from_slice(&bytes).context("parse Graphify transaction journal")?;
    ensure!(
        journal.schema_version == GRAPHIFY_PUBLISH_SCHEMA
            && !journal.corpus_id.is_empty()
            && !journal.generation_id.is_empty()
            && !journal.new_current_hex.is_empty()
            && journal.transaction_id
                == format!(
                    "graphify-txn-v2-{}-{}",
                    journal.ingest_scope.id_component(),
                    journal.generation_id
                ),
        "Graphify transaction journal has an invalid identity or schema"
    );
    Ok(Some(journal))
}

fn decode_journal_pointer(hex_value: Option<&str>) -> Result<Option<Vec<u8>>> {
    hex_value
        .map(|value| {
            let bytes = hex::decode(value).context("decode Graphify transaction pointer bytes")?;
            ensure!(
                bytes.len() as u64 <= MAX_POINTER_BYTES,
                "Graphify transaction pointer exceeds byte limit"
            );
            Ok(bytes)
        })
        .transpose()
}

/// Cooperative raw-byte CAS. `GraphifyPublicationLease` is retained by the
/// prepared value, so every NEOTH writer observes this exact check-and-write
/// as one serialized transition. The byte comparison is intentionally stricter
/// than deserializing pointers: a concurrently replaced but semantically equal
/// JSON document is still a lost-update signal.
fn compare_and_swap_current_under_lease(
    pointer_path: &Path,
    expected_pointer: Option<&CurrentGraphifyPointer>,
    expected_bytes: Option<&[u8]>,
    replacement: &[u8],
) -> Result<()> {
    reject_non_regular_existing_file(pointer_path, "Graphify CURRENT pointer")?;
    let observed_bytes = read_optional_current_bytes(pointer_path)?;
    ensure!(
        observed_bytes.as_deref() == expected_bytes,
        "Graphify CURRENT changed after preparation; refusing stale publication"
    );
    let observed_pointer = match observed_bytes.as_deref() {
        Some(bytes) => {
            let pointer: CurrentGraphifyPointer =
                serde_json::from_slice(bytes).context("parse Graphify CURRENT during CAS")?;
            validate_current_pointer(&pointer)?;
            Some(pointer)
        }
        None => None,
    };
    ensure!(
        observed_pointer.as_ref() == expected_pointer,
        "Graphify CURRENT changed semantic value after preparation; refusing stale publication"
    );
    crate::util::atomic_write::atomic_write_private(pointer_path, replacement)
        .with_context(|| format!("atomically publish {}", pointer_path.display()))
}

/// Undo only our own just-written pointer. If another writer has advanced the
/// pointer after us, overwriting it would turn recovery into data loss, so we
/// leave the state untouched and report it as indeterminate to the caller.
#[cfg(test)]
fn restore_current_pointer_if_ours(
    pointer_path: &Path,
    previous: Option<&[u8]>,
    our_bytes: &[u8],
) -> Result<()> {
    ensure!(
        read_optional_current_bytes(pointer_path)?.as_deref() == Some(our_bytes),
        "CURRENT changed after this publisher wrote it; refusing unsafe rollback"
    );
    match previous {
        Some(bytes) => {
            crate::util::atomic_write::atomic_write_private(pointer_path, bytes)
                .context("atomically restore previous Graphify CURRENT pointer")?;
            crate::util::atomic_write::sync_parent_directory_required(pointer_path)
                .context("durably restore previous Graphify CURRENT pointer")
        }
        None => crate::util::atomic_write::durable_remove_file(pointer_path)
            .context("durably remove newly created Graphify CURRENT pointer"),
    }
}

fn physical_root_digest(domain: &[u8], root: &CanonicalRepoRoot) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(root.identity().as_str().as_bytes());
    hex::encode(digest.finalize())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn json_line<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code_map::RebuildOptions;
    use crate::code_map::snapshot::rebuild_snapshot_scoped;
    use tempfile::TempDir;

    struct Fixture {
        repo: TempDir,
        vault: TempDir,
        database: TempDir,
    }

    impl Fixture {
        fn new() -> Self {
            let repo = crate::test_env::canonical_tempdir().unwrap();
            let vault = crate::test_env::canonical_tempdir().unwrap();
            let database = crate::test_env::canonical_tempdir().unwrap();
            fs::write(repo.path().join(".gitignore"), "graphify-out/\n").unwrap();
            fs::write(repo.path().join("lib.rs"), "pub fn alpha() {}\n").unwrap();
            fs::create_dir(repo.path().join("graphify-out")).unwrap();
            fs::write(
                repo.path().join("graphify-out").join(GRAPH_REPORT_NAME),
                "# Graph report\n",
            )
            .unwrap();
            fs::write(
                repo.path().join("graphify-out").join(GRAPH_TREE_NAME),
                "<html>tree</html>\n",
            )
            .unwrap();
            Self {
                repo,
                vault,
                database,
            }
        }

        fn snapshot(&self) -> ScopedRebuildSnapshot {
            let root = CanonicalRepoRoot::discover(self.repo.path()).unwrap();
            rebuild_snapshot_scoped(
                &root,
                &self.database.path().join("code-map.db"),
                RebuildOptions::default(),
                &[],
                &[],
            )
            .unwrap()
        }

        fn prepare<'a>(
            &'a self,
            snapshot: &'a ScopedRebuildSnapshot,
            friendly: Option<&'a str>,
        ) -> Result<PreparedGraphifyPublication> {
            self.prepare_with_ingest_mode(
                snapshot,
                friendly,
                GraphifyPublicationIngestMode::SkippedAndRevoked,
            )
        }

        fn prepare_with_ingest_mode<'a>(
            &'a self,
            snapshot: &'a ScopedRebuildSnapshot,
            friendly: Option<&'a str>,
            ingest_mode: GraphifyPublicationIngestMode,
        ) -> Result<PreparedGraphifyPublication> {
            prepare_graphify_publication(GraphifyPublishRequest {
                vault_root: self.vault.path(),
                friendly_subdir: friendly,
                native_snapshot: snapshot,
                ingest_mode,
                ingest_scope: GraphifyIngestScope::Corpus,
                lease: acquire_graphify_publication_lease(
                    self.vault.path(),
                    &snapshot.snapshot().root,
                )?,
            })
        }
    }

    fn finish_without_ingest(mut published: PublishedGraphifyPublication) {
        published.mark_ingest_skipped().unwrap();
        published.finish().unwrap();
    }

    #[test]
    fn friendly_subdir_rejects_traversal_absolute_controls_and_long_names() {
        assert_eq!(
            validate_friendly_subdir("NEOTH Self").unwrap(),
            "NEOTH Self"
        );
        for invalid in [
            "",
            ".",
            "..",
            "a/b",
            "a\\b",
            "C:\\escape",
            "bad\0name",
            "trailing.",
            "trailing ",
            "CON",
        ] {
            assert!(
                validate_friendly_subdir(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
        let absolute = std::env::temp_dir().join("absolute-graphify-name");
        assert!(validate_friendly_subdir(&absolute.to_string_lossy()).is_err());
        assert!(validate_friendly_subdir(&"x".repeat(MAX_FRIENDLY_SUBDIR_BYTES + 1)).is_err());

        // No lossy slug/truncation layer exists: distinct valid Unicode names
        // remain distinct, while overlong inputs fail instead of colliding.
        assert_ne!(
            validate_friendly_subdir("Resume").unwrap(),
            validate_friendly_subdir("Resume-2").unwrap()
        );
    }

    #[test]
    fn same_basename_roots_get_distinct_default_names_and_explicit_name_cannot_rebind() {
        let base = crate::test_env::canonical_tempdir().unwrap();
        let vault = crate::test_env::canonical_tempdir().unwrap();
        let db = crate::test_env::canonical_tempdir().unwrap();
        let first_repo = base.path().join("first").join("repo");
        let second_repo = base.path().join("second").join("repo");
        for repo in [&first_repo, &second_repo] {
            fs::create_dir_all(repo.join("graphify-out")).unwrap();
            fs::write(repo.join(".gitignore"), "graphify-out/\n").unwrap();
            fs::write(repo.join("lib.rs"), "pub fn root() {}\n").unwrap();
            fs::write(repo.join("graphify-out").join(GRAPH_REPORT_NAME), "# map\n").unwrap();
            fs::write(
                repo.join("graphify-out").join(GRAPH_TREE_NAME),
                "<tree />\n",
            )
            .unwrap();
        }
        let first_root = CanonicalRepoRoot::discover(&first_repo).unwrap();
        let second_root = CanonicalRepoRoot::discover(&second_repo).unwrap();
        let first = rebuild_snapshot_scoped(
            &first_root,
            &db.path().join("first.db"),
            RebuildOptions::default(),
            &[],
            &[],
        )
        .unwrap();
        let second = rebuild_snapshot_scoped(
            &second_root,
            &db.path().join("second.db"),
            RebuildOptions::default(),
            &[],
            &[],
        )
        .unwrap();
        // Two physical roots may share a basename but must receive distinct
        // default namespaces.  Do not prepare them here: preparation durably
        // binds a corpus to that default subdirectory, and the invariant
        // deliberately forbids rebinding it later to an explicit name.
        assert_ne!(first_root.identity(), second_root.identity());
        assert_ne!(
            default_friendly_subdir(first.snapshot()),
            default_friendly_subdir(second.snapshot())
        );

        let published = prepare_graphify_publication(GraphifyPublishRequest {
            vault_root: vault.path(),
            friendly_subdir: Some("Shared-Knowledge"),
            native_snapshot: &first,
            ingest_mode: GraphifyPublicationIngestMode::SkippedAndRevoked,
            ingest_scope: GraphifyIngestScope::Corpus,
            lease: acquire_graphify_publication_lease(vault.path(), &first.snapshot().root)
                .unwrap(),
        })
        .unwrap()
        .publish()
        .unwrap();
        assert!(published.current_pointer.is_file());
        finish_without_ingest(published);
        let error = prepare_graphify_publication(GraphifyPublishRequest {
            vault_root: vault.path(),
            friendly_subdir: Some("Shared-Knowledge"),
            native_snapshot: &second,
            ingest_mode: GraphifyPublicationIngestMode::SkippedAndRevoked,
            ingest_scope: GraphifyIngestScope::Corpus,
            lease: acquire_graphify_publication_lease(vault.path(), &second.snapshot().root)
                .unwrap(),
        })
        .err()
        .expect("second physical root must not claim an explicit friendly name");
        assert!(error.to_string().contains("already bound"));
    }

    #[test]
    fn changed_source_fingerprint_publishes_new_generation_and_keeps_previous() {
        let fixture = Fixture::new();
        let first_snapshot = fixture.snapshot();
        let first = fixture
            .prepare(&first_snapshot, Some("Knowledge"))
            .unwrap()
            .publish()
            .unwrap();
        let first_pointer = read_current_graphify_pointer(&first.corpus_dir)
            .unwrap()
            .unwrap();
        let first_generation = first.generation_dir.clone();
        finish_without_ingest(first);

        fs::write(
            fixture.repo.path().join("lib.rs"),
            "pub fn alpha() {}\npub fn beta() {}\n",
        )
        .unwrap();
        fs::write(
            fixture
                .repo
                .path()
                .join("graphify-out")
                .join(GRAPH_REPORT_NAME),
            "# Graph report v2\n",
        )
        .unwrap();
        let second_snapshot = fixture.snapshot();
        assert_ne!(
            first_snapshot.snapshot().source_fingerprint_sha256,
            second_snapshot.snapshot().source_fingerprint_sha256
        );
        let second = fixture
            .prepare(&second_snapshot, Some("Knowledge"))
            .unwrap()
            .publish()
            .unwrap();
        let second_pointer = read_current_graphify_pointer(&second.corpus_dir)
            .unwrap()
            .unwrap();
        assert_ne!(first_pointer.generation_id, second_pointer.generation_id);
        assert!(first_generation.is_dir());
        assert!(second.generation_dir.is_dir());
        finish_without_ingest(second);
    }

    #[test]
    fn copy_failure_and_finalize_failure_leave_prior_current() {
        let fixture = Fixture::new();
        let snapshot = fixture.snapshot();
        let first = fixture
            .prepare(&snapshot, Some("Knowledge"))
            .unwrap()
            .publish()
            .unwrap();
        let current_before = fs::read(&first.current_pointer).unwrap();
        let current_pointer = first.current_pointer.clone();
        let first_generation = first.generation_dir.clone();
        finish_without_ingest(first);

        fs::remove_file(
            fixture
                .repo
                .path()
                .join("graphify-out")
                .join(GRAPH_REPORT_NAME),
        )
        .unwrap();
        assert!(fixture.prepare(&snapshot, Some("Knowledge")).is_err());
        assert_eq!(fs::read(&current_pointer).unwrap(), current_before);

        fs::write(
            fixture
                .repo
                .path()
                .join("graphify-out")
                .join(GRAPH_REPORT_NAME),
            "# replacement\n",
        )
        .unwrap();
        let prepared = fixture.prepare(&snapshot, Some("Knowledge")).unwrap();
        fs::remove_file(prepared.stage.path().join(GENERATION_RECEIPT_NAME)).unwrap();
        assert!(prepared.publish().is_err());
        assert_eq!(fs::read(&current_pointer).unwrap(), current_before);
        assert!(first_generation.is_dir());
    }

    #[test]
    fn required_tree_and_non_whitespace_report_are_rejected() {
        let fixture = Fixture::new();
        let snapshot = fixture.snapshot();
        fs::remove_file(
            fixture
                .repo
                .path()
                .join("graphify-out")
                .join(GRAPH_TREE_NAME),
        )
        .unwrap();
        let error = fixture.prepare(&snapshot, Some("Knowledge")).err().unwrap();
        assert!(error.to_string().contains("GRAPH_TREE.html"));

        fs::write(
            fixture
                .repo
                .path()
                .join("graphify-out")
                .join(GRAPH_TREE_NAME),
            "<tree />\n",
        )
        .unwrap();
        fs::write(
            fixture
                .repo
                .path()
                .join("graphify-out")
                .join(GRAPH_REPORT_NAME),
            " \t\r\n",
        )
        .unwrap();
        let error = fixture.prepare(&snapshot, Some("Knowledge")).err().unwrap();
        assert!(error.to_string().contains("whitespace-only"));
    }

    #[test]
    fn source_mutation_after_prepare_cannot_advance_current() {
        let fixture = Fixture::new();
        let snapshot = fixture.snapshot();
        let prepared = fixture.prepare(&snapshot, Some("Knowledge")).unwrap();
        fs::write(fixture.repo.path().join("lib.rs"), "pub fn changed() {}\n").unwrap();
        let corpus = prepared.corpus_dir().to_owned();
        let error = prepared.publish().err().unwrap();
        assert_eq!(
            format!("{error:#}"),
            "revalidate native snapshot at Graphify visibility boundary: source corpus changed after native code-map publication"
        );
        assert!(read_current_graphify_pointer(corpus).unwrap().is_none());
    }

    #[test]
    fn raw_current_cas_rejects_semantically_equal_pointer_mutation() {
        let fixture = Fixture::new();
        let first_snapshot = fixture.snapshot();
        let first = fixture
            .prepare(&first_snapshot, Some("Knowledge"))
            .unwrap()
            .publish()
            .unwrap();
        let pointer_path = first.current_pointer.clone();
        finish_without_ingest(first);

        fs::write(fixture.repo.path().join("lib.rs"), "pub fn next() {}\n").unwrap();
        fs::write(
            fixture
                .repo
                .path()
                .join("graphify-out")
                .join(GRAPH_REPORT_NAME),
            "# next\n",
        )
        .unwrap();
        let second_snapshot = fixture.snapshot();
        let prepared = fixture
            .prepare(&second_snapshot, Some("Knowledge"))
            .unwrap();
        let mut bytes = fs::read(&pointer_path).unwrap();
        bytes.extend_from_slice(b" \n");
        fs::write(&pointer_path, &bytes).unwrap();
        let error = prepared.publish().err().unwrap();
        assert!(error.to_string().contains("CAS rejected stale publication"));
        assert_eq!(fs::read(&pointer_path).unwrap(), bytes);
        assert!(
            !pointer_path
                .parent()
                .unwrap()
                .join(GRAPHIFY_TRANSACTION_NAME)
                .exists(),
            "failed CAS must not strand an intent which it did not publish"
        );
    }

    #[test]
    fn published_generation_is_read_only_and_journal_tracks_postcommit_phase() {
        let fixture = Fixture::new();
        let snapshot = fixture.snapshot();
        let mut published = fixture
            .prepare(&snapshot, Some("Knowledge"))
            .unwrap()
            .publish()
            .unwrap();
        assert!(
            fs::symlink_metadata(&published.generation_dir)
                .unwrap()
                .permissions()
                .readonly()
        );
        for entry in fs::read_dir(&published.generation_dir).unwrap() {
            assert!(entry.unwrap().metadata().unwrap().permissions().readonly());
        }
        let journal =
            read_transaction_journal(&published.corpus_dir.join(GRAPHIFY_TRANSACTION_NAME))
                .unwrap()
                .unwrap();
        assert_eq!(journal.phase, GraphifyTransactionPhase::CurrentPublished);
        published.mark_ingest_skipped().unwrap();
        published.finish().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_permission_restore_keeps_artifacts_immutable_and_owner_scoped() {
        use std::os::unix::fs::PermissionsExt;

        let stage = crate::test_env::canonical_tempdir().unwrap();
        let generation = stage.path().join("generation");
        fs::create_dir(&generation).unwrap();
        let artifact = generation.join(GRAPH_REPORT_NAME);
        fs::write(&artifact, "immutable\n").unwrap();
        fs::set_permissions(&artifact, fs::Permissions::from_mode(0o444)).unwrap();
        fs::set_permissions(&generation, fs::Permissions::from_mode(0o555)).unwrap();

        make_generation_writable_for_cleanup(&generation).unwrap();

        let directory_mode = fs::symlink_metadata(&generation)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(directory_mode & 0o300, 0o300, "owner can unlink stage");
        assert_eq!(
            directory_mode & 0o022,
            0,
            "cleanup never grants group/world write"
        );
        assert_eq!(
            fs::symlink_metadata(&artifact)
                .unwrap()
                .permissions()
                .mode()
                & 0o222,
            0,
            "unlinking does not require widening artifact write permissions"
        );
    }

    #[test]
    fn intended_ingest_mode_is_durable_before_current_and_enforced_afterward() {
        let fixture = Fixture::new();
        let snapshot = fixture.snapshot();
        let mut published = fixture
            .prepare_with_ingest_mode(
                &snapshot,
                Some("Knowledge"),
                GraphifyPublicationIngestMode::Indexed,
            )
            .unwrap()
            .publish()
            .unwrap();
        assert_eq!(
            published.ingest_mode(),
            GraphifyPublicationIngestMode::Indexed
        );
        let journal =
            read_transaction_journal(&published.corpus_dir.join(GRAPHIFY_TRANSACTION_NAME))
                .unwrap()
                .unwrap();
        assert_eq!(journal.ingest_mode, GraphifyPublicationIngestMode::Indexed);
        assert!(published.mark_ingest_skipped().is_err());
        published.mark_ingested().unwrap();
        published.finish().unwrap();
    }

    #[test]
    fn recovered_finish_requires_exact_id_and_declared_ingest_mode_phase() {
        let fixture = Fixture::new();
        let snapshot = fixture.snapshot();
        let published = fixture
            .prepare(&snapshot, Some("Knowledge"))
            .unwrap()
            .publish()
            .unwrap();
        let corpus = published.corpus_dir.clone();
        let transaction_id = published.transaction_id().to_owned();
        drop(published); // Recovery runs in a later invocation.

        let lease =
            acquire_graphify_publication_lease(fixture.vault.path(), &snapshot.snapshot().root)
                .unwrap();
        assert_eq!(
            recover_graphify_transaction_under_lease(&lease, &corpus).unwrap(),
            GraphifyTransactionPhase::CurrentPublished
        );
        assert_eq!(
            mark_recovered_graphify_ingest_phase_under_lease(&lease, &corpus, &transaction_id)
                .unwrap(),
            GraphifyTransactionPhase::IngestSkipped
        );
        assert!(
            finish_recovered_transaction_under_lease(
                &lease,
                &corpus,
                "wrong-transaction",
                &[GraphifyTransactionPhase::IngestSkipped],
            )
            .is_err()
        );
        finish_recovered_transaction_under_lease(
            &lease,
            &corpus,
            &transaction_id,
            &[GraphifyTransactionPhase::IngestSkipped],
        )
        .unwrap();
        assert!(
            inspect_graphify_transaction_under_lease(&lease, &corpus)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn load_current_generation_receipt_requires_closed_immutable_pointer_target() {
        let fixture = Fixture::new();
        let snapshot = fixture.snapshot();
        let mut published = fixture
            .prepare(&snapshot, Some("Knowledge"))
            .unwrap()
            .publish()
            .unwrap();
        let (generation_dir, receipt) =
            load_current_graphify_generation_receipt(&published.corpus_dir)
                .unwrap()
                .unwrap();
        assert_eq!(generation_dir, published.generation_dir);
        assert_eq!(receipt, published.receipt);
        published.mark_ingest_skipped().unwrap();
        published.finish().unwrap();
    }

    #[test]
    fn recovery_target_discovery_finds_old_bound_subdir_and_rejects_second_binding() {
        let fixture = Fixture::new();
        let snapshot = fixture.snapshot();
        let published = fixture
            .prepare(&snapshot, Some("Old-Friendly-Name"))
            .unwrap()
            .publish()
            .unwrap();
        let old_corpus_dir = published.corpus_dir.clone();
        drop(published); // Simulate config changing before recovery starts.

        let lease =
            acquire_graphify_publication_lease(fixture.vault.path(), &snapshot.snapshot().root)
                .unwrap();
        assert_eq!(
            discover_graphify_recovery_targets_under_lease(&lease).unwrap(),
            vec![old_corpus_dir.clone()]
        );
        drop(lease);

        let error = fixture
            .prepare(&snapshot, Some("New-Friendly-Name"))
            .err()
            .unwrap();
        assert!(error.to_string().contains("already bound"));

        let duplicate_dir = fixture.vault.path().join("Duplicate-Friendly-Name");
        fs::create_dir(&duplicate_dir).unwrap();
        let mut duplicate_binding: CorpusBinding =
            serde_json::from_slice(&fs::read(old_corpus_dir.join(CORPUS_BINDING_NAME)).unwrap())
                .unwrap();
        duplicate_binding.friendly_subdir = "Duplicate-Friendly-Name".to_owned();
        fs::write(
            duplicate_dir.join(CORPUS_BINDING_NAME),
            json_line(&duplicate_binding).unwrap(),
        )
        .unwrap();
        let lease =
            acquire_graphify_publication_lease(fixture.vault.path(), &snapshot.snapshot().root)
                .unwrap();
        let error = discover_graphify_recovery_targets_under_lease(&lease)
            .err()
            .unwrap();
        assert!(
            error
                .to_string()
                .contains("duplicate friendly-subdirectory bindings")
        );
    }

    #[test]
    fn postcommit_journal_recovers_or_rolls_back_without_guessing() {
        let fixture = Fixture::new();
        let snapshot = fixture.snapshot();
        let published = fixture
            .prepare(&snapshot, Some("Knowledge"))
            .unwrap()
            .publish()
            .unwrap();
        let corpus = published.corpus_dir.clone();
        let transaction_id = published.transaction_id().to_owned();
        assert_eq!(
            published.phase(),
            GraphifyTransactionPhase::CurrentPublished
        );
        assert_eq!(
            published.receipt().generation_id,
            published.receipt.generation_id
        );
        drop(published); // Simulate a caller crash before ingest/completion WAL.

        let lease =
            acquire_graphify_publication_lease(fixture.vault.path(), &snapshot.snapshot().root)
                .unwrap();
        let inspection = inspect_graphify_transaction_under_lease(&lease, &corpus)
            .unwrap()
            .unwrap();
        assert_eq!(inspection.transaction_id, transaction_id);
        assert_eq!(inspection.phase, GraphifyTransactionPhase::CurrentPublished);
        assert_eq!(
            recover_graphify_transaction_under_lease(&lease, &corpus).unwrap(),
            GraphifyTransactionPhase::CurrentPublished
        );
        assert_eq!(
            inspect_graphify_transaction_under_lease(&lease, &corpus)
                .unwrap()
                .unwrap()
                .transaction_id,
            transaction_id,
            "recovery must retain the stable WAL deduplication ID"
        );
        rollback_graphify_transaction_under_lease(&lease, &corpus).unwrap();
        assert!(read_current_graphify_pointer(&corpus).unwrap().is_none());
        assert!(!corpus.join(GRAPHIFY_TRANSACTION_NAME).exists());
    }

    #[cfg(unix)]
    #[test]
    fn fifo_artifact_is_rejected_without_blocking() {
        use std::ffi::CString;

        let fixture = Fixture::new();
        let snapshot = fixture.snapshot();
        let tree = fixture
            .repo
            .path()
            .join("graphify-out")
            .join(GRAPH_TREE_NAME);
        fs::remove_file(&tree).unwrap();
        let tree_c = CString::new(tree.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: valid NUL-free pathname and mode; this test owns the path.
        assert_eq!(unsafe { libc::mkfifo(tree_c.as_ptr(), 0o600) }, 0);
        let started = Instant::now();
        assert!(fixture.prepare(&snapshot, Some("Knowledge")).is_err());
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "FIFO validation must not block a publisher"
        );
    }

    #[test]
    fn source_artifact_symlink_or_reparse_is_rejected() {
        let fixture = Fixture::new();
        let snapshot = fixture.snapshot();
        let report = fixture
            .repo
            .path()
            .join("graphify-out")
            .join(GRAPH_REPORT_NAME);
        let outside = fixture.repo.path().join("outside.md");
        fs::write(&outside, "outside\n").unwrap();
        fs::remove_file(&report).unwrap();
        if !create_file_link(&outside, &report) {
            return;
        }
        assert!(fixture.prepare(&snapshot, Some("Knowledge")).is_err());
    }

    #[test]
    fn existing_destination_symlink_or_reparse_escape_is_rejected() {
        let fixture = Fixture::new();
        let snapshot = fixture.snapshot();
        let outside = crate::test_env::canonical_tempdir().unwrap();
        let destination = fixture.vault.path().join("Knowledge");
        if !create_directory_link(outside.path(), &destination) {
            return;
        }
        assert!(fixture.prepare(&snapshot, Some("Knowledge")).is_err());
        assert!(directory_entry_names(outside.path()).unwrap().is_empty());
    }

    #[cfg(unix)]
    fn create_file_link(target: &Path, link: &Path) -> bool {
        std::os::unix::fs::symlink(target, link).is_ok()
    }

    #[cfg(windows)]
    fn create_file_link(target: &Path, link: &Path) -> bool {
        std::os::windows::fs::symlink_file(target, link).is_ok()
    }

    #[cfg(not(any(unix, windows)))]
    fn create_file_link(_target: &Path, _link: &Path) -> bool {
        false
    }

    #[cfg(unix)]
    fn create_directory_link(target: &Path, link: &Path) -> bool {
        std::os::unix::fs::symlink(target, link).is_ok()
    }

    #[cfg(windows)]
    fn create_directory_link(target: &Path, link: &Path) -> bool {
        std::os::windows::fs::symlink_dir(target, link).is_ok()
    }

    #[cfg(not(any(unix, windows)))]
    fn create_directory_link(_target: &Path, _link: &Path) -> bool {
        false
    }
}
