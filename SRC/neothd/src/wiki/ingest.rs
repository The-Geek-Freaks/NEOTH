//! GOLD-FEAT-03 slice 2 — push self-wiki pages into ground-truth.
//!
//! Makes the rendered design corpus discoverable via recall: one short,
//! recall-friendly POINTER statement per doc (not the doc body — ground-truth
//! stays lean) is inserted into `idx_groundtruth` under the
//! [`WIKI_SCOPE`]. Re-ingest is idempotent: prior active self-wiki rows are
//! revoked first, so a rebuild never accretes duplicates.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use rusqlite::{Connection, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::graphify_publish::{
    CURRENT_POINTER_NAME, CurrentGraphifyPointer, GENERATION_RECEIPT_NAME, GRAPH_REPORT_NAME,
    GRAPH_TREE_NAME, GRAPHIFY_PUBLISH_SCHEMA, GraphifyGenerationReceipt,
    read_current_graphify_pointer,
};
use crate::memory::groundtruth::{Source, insert, list_for_scope, revoke};
use crate::wiki::sources::{WikiSource, prettify_stem, slug_for};

const GRAPHIFY_GENERATIONS_DIR: &str = "generations";
const MAX_GRAPHIFY_RECEIPT_BYTES: u64 = 256 * 1024;
const MAX_GRAPHIFY_REPORT_BYTES: u64 = 32 * 1024 * 1024;
const MAX_GRAPHIFY_TREE_BYTES: u64 = 128 * 1024 * 1024;
const GRAPHIFY_CORPUS_SCOPE_PREFIX: &str = "graphify-corpus-";
const GRAPHIFY_SELF_MAP_SCOPE_PREFIX: &str = "neoth-self-map-";
const MAX_GRAPHIFY_SCOPE_CORPUS_LEN: usize = 40;
const MAX_GRAPHIFY_FRIENDLY_SUBDIR_BYTES: usize = 96;
const REQUIRED_GRAPHIFY_ARTIFACTS: [(&str, u64); 2] = [
    (GRAPH_REPORT_NAME, MAX_GRAPHIFY_REPORT_BYTES),
    (GRAPH_TREE_NAME, MAX_GRAPHIFY_TREE_BYTES),
];

/// Scope tag carried by every self-wiki ground-truth row — segregates the
/// corpus pointers from operator facts so they can be re-ingested as a unit.
pub const WIKI_SCOPE: &str = "neoth-self-wiki";

/// Counters returned by [`ingest_sources`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IngestStats {
    /// Fresh statements inserted this pass.
    pub inserted: usize,
    /// Prior active self-wiki rows revoked before re-inserting.
    pub revoked: usize,
}

/// Result of an explicit Graphify `--no-ingest` replacement.  This is kept
/// separate from [`IngestStats`] so callers cannot accidentally interpret a
/// revoke-only request as successful artifact ingest.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GraphifyIngestRevocation {
    /// Active pointers removed from the exact root-bound Graphify scope.
    pub revoked: usize,
}

/// Typed ownership boundary for a Graphify ground-truth replacement.
///
/// Callers never supply the destructive SQLite scope directly. A normal
/// corpus scope is derived from the receipt's friendly name plus its complete
/// physical-root digest; the one NEOTH self-map scope is an explicit variant.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GraphifyIngestScope {
    SelfMap,
    Corpus,
}

/// Stable identifier shared by the SQLite pointer set, the completion WAL,
/// and recovery inspection.  It is deterministic because the immutable
/// generation receipt is itself content-bound; it must never be replaced by a
/// process-local random value after a crash.
pub(crate) fn graphify_ingest_transaction_id(
    receipt: &GraphifyGenerationReceipt,
    scope: GraphifyIngestScope,
) -> String {
    // Scope is an immutable part of the durable transaction identity.  A
    // self-map transaction and a user corpus transaction can legitimately
    // publish the same receipt-shaped artifact set, but must never share a
    // SQLite/WAL recovery token or be replayed across their revoke boundary.
    format!(
        "graphify-txn-v2-{}-{}",
        scope.id_component(),
        receipt.generation_id
    )
}

impl GraphifyIngestScope {
    pub(crate) const fn id_component(self) -> &'static str {
        match self {
            Self::SelfMap => "self_map",
            Self::Corpus => "corpus",
        }
    }

    pub fn groundtruth_scope(self, receipt: &GraphifyGenerationReceipt) -> String {
        match self {
            // The daemon self-map uses an intentional typed variant, but it
            // cannot share a destructive SQLite scope with a different
            // physical repository root.
            Self::SelfMap => format!(
                "{GRAPHIFY_SELF_MAP_SCOPE_PREFIX}{}",
                receipt.repo_root_identity_sha256
            ),
            Self::Corpus => graphify_corpus_scope(receipt),
        }
    }
}

/// The recall-friendly pointer statement for one doc: names the doc + links to
/// its Obsidian page, but carries no body text.
pub fn statement_for(source: &WikiSource) -> String {
    format!(
        "NEOTH {} design doc: {} — self-wiki page [[{}]] (source: {})",
        source.category.tag(),
        source.title,
        source.slug,
        source.rel_path
    )
}

/// Revoke the prior active self-wiki rows, then insert one fresh statement per
/// source. `now_ns` is injected so the asserted/revoked timestamps are
/// deterministic in tests.
pub fn ingest_sources(
    conn: &Connection,
    sources: &[WikiSource],
    now_ns: i64,
) -> Result<IngestStats> {
    ingest_sources_for_scope(conn, sources, WIKI_SCOPE, now_ns)
}

/// Rebuild one explicitly owned ground-truth scope atomically.
///
/// Self-map and per-corpus Graphify pages must never reuse [`WIKI_SCOPE`]: a
/// revoke pass is intentionally scope-wide, so sharing it would delete the
/// canonical self-wiki pointers. Callers must provide their stable scope.
fn ingest_sources_for_scope(
    conn: &Connection,
    sources: &[WikiSource],
    scope: &str,
    now_ns: i64,
) -> Result<IngestStats> {
    let statements = sources.iter().map(statement_for).collect::<Vec<_>>();
    ingest_statements_for_scope(conn, &statements, scope, now_ns)
}

/// Atomically publish recall pointers for one exact immutable Graphify
/// generation. Every pointer carries the same root/source/generation evidence
/// as the vault receipt.  Source construction is deliberately internal: the
/// generation receipt is the bounded authoritative artifact manifest.
pub fn ingest_graphify_generation_for_scope(
    conn: &Connection,
    generation_dir: &Path,
    scope: GraphifyIngestScope,
    receipt: &GraphifyGenerationReceipt,
    now_ns: i64,
) -> Result<IngestStats> {
    ingest_graphify_generation_for_scope_guarded(
        conn,
        generation_dir,
        scope,
        receipt,
        now_ns,
        || Ok(()),
    )
}

/// Crate-internal transaction variant that runs its companion-snapshot fence
/// both before mutation and immediately before the SQLite commit.
pub(crate) fn ingest_graphify_generation_for_scope_guarded<F>(
    conn: &Connection,
    generation_dir: &Path,
    scope: GraphifyIngestScope,
    receipt: &GraphifyGenerationReceipt,
    now_ns: i64,
    mut validate_companion_snapshot: F,
) -> Result<IngestStats>
where
    F: FnMut() -> Result<()>,
{
    let verified = verify_graphify_generation(generation_dir, receipt)?;
    let transaction_id = graphify_ingest_transaction_id(receipt, scope);
    let destructive_scope = scope.groundtruth_scope(receipt);
    ensure!(
        destructive_scope != WIKI_SCOPE,
        "Graphify ingest cannot own the canonical self-wiki scope"
    );
    let statements = verified
        .sources
        .into_iter()
        .map(|source| {
            format!(
                "Graphify corpus `{}` generation `{}` doc: {} — vault page \
                 [[{}/generations/{}/{}]] (artifact: {}; artifact_sha256: {}; \
                 source_fingerprint_sha256: {}; native_generation: {}; corpus_id: {}; \
                 transaction_id: {})",
                receipt.friendly_subdir,
                receipt.generation_id,
                source.title,
                receipt.friendly_subdir,
                receipt.generation_id,
                source.slug,
                source.name,
                source.sha256,
                receipt.source_fingerprint_sha256,
                receipt.native_index_generation,
                receipt.corpus_id,
                transaction_id,
            )
        })
        .collect::<Vec<_>>();
    // This is the only full source-tree pass in the ingest path. Callers hold
    // the per-corpus publish/ingest lock across this preflight and the short
    // SQLite transaction below; arbitrary external repository writers do not
    // participate in that lock, so this binds the published snapshot rather
    // than claiming a live filesystem transaction through SQLite commit.
    ensure_receipted_source_is_current(&verified.repository, receipt)?;
    ingest_statements_for_scope_guarded(conn, &statements, &destructive_scope, now_ns, || {
        ensure_current_graphify_generation(&verified.corpus_dir, receipt)?;
        validate_companion_snapshot()?;
        // Keep this full source pass last inside the pre-commit fence. The
        // companion DB-generation check may itself take observable time; a
        // source mutation injected during it must still abort before commit.
        ensure_receipted_source_is_current(&verified.repository, receipt)
    })
}

/// Revoke Graphify recall pointers without ingesting a replacement generation.
///
/// This is the only supported `--no-ingest` path.  It accepts the typed scope
/// and root-bound receipt rather than an arbitrary SQLite scope, ensuring a
/// CLI flag can never revoke the canonical self-wiki or another corpus.
pub fn revoke_graphify_scope_for_no_ingest(
    conn: &Connection,
    corpus_dir: &Path,
    scope: GraphifyIngestScope,
    receipt: &GraphifyGenerationReceipt,
    now_ns: i64,
) -> Result<GraphifyIngestRevocation> {
    revoke_graphify_scope_for_no_ingest_guarded(conn, corpus_dir, scope, receipt, now_ns, || Ok(()))
}

/// Internal `--no-ingest` variant which keeps the receipt `CURRENT` check and
/// native attestation inside the same SQLite pre-commit fence as the revoke.
/// A caller must use this when a Graphify publication transaction owns the
/// lease; otherwise a changed CURRENT/native generation could revoke pointers
/// after the publication it was supposed to authorize has been superseded.
pub(crate) fn revoke_graphify_scope_for_no_ingest_guarded<F>(
    conn: &Connection,
    corpus_dir: &Path,
    scope: GraphifyIngestScope,
    receipt: &GraphifyGenerationReceipt,
    now_ns: i64,
    mut validate_companion_snapshot: F,
) -> Result<GraphifyIngestRevocation>
where
    F: FnMut() -> Result<()>,
{
    validate_graphify_receipt_shape(receipt)?;
    let vault = validate_receipted_vault(receipt)?;
    let expected_corpus = vault.path().join(&receipt.friendly_subdir);
    ensure!(
        corpus_dir == expected_corpus,
        "Graphify no-ingest corpus path does not match its receipt"
    );
    validate_existing_directory_chain(corpus_dir, "Graphify no-ingest corpus")?;
    ensure_current_graphify_generation(corpus_dir, receipt)?;
    validate_companion_snapshot()
        .context("Graphify no-ingest native attestation pre-mutation fence failed")?;
    let destructive_scope = scope.groundtruth_scope(receipt);
    ensure!(
        destructive_scope != WIKI_SCOPE,
        "Graphify no-ingest cannot revoke the canonical self-wiki scope"
    );
    revoke_scope_atomically_guarded(conn, &destructive_scope, now_ns, || {
        ensure_current_graphify_generation(corpus_dir, receipt)?;
        validate_companion_snapshot()
            .context("revalidate native attestation before Graphify no-ingest revoke")
    })
}

struct VerifiedGraphifyGeneration {
    sources: Vec<VerifiedGraphifySource>,
    corpus_dir: PathBuf,
    repository: crate::code_map::CanonicalRepoRoot,
}

struct VerifiedGraphifySource {
    name: String,
    title: String,
    slug: String,
    sha256: String,
}

struct VerifiedGraphifyFile {
    bytes: u64,
    sha256: String,
    non_whitespace: bool,
    retained: Option<Vec<u8>>,
}

/// Verify an immutable generation in full before the caller may enter the
/// revoke-and-insert transaction. In particular, a failed/empty discovery can
/// never turn into an empty replacement scope.
fn verify_graphify_generation(
    generation_dir: &Path,
    expected: &GraphifyGenerationReceipt,
) -> Result<VerifiedGraphifyGeneration> {
    validate_graphify_receipt_shape(expected)?;
    let vault = validate_receipted_vault(expected)?;
    let repository = validate_receipted_repository(expected)?;
    ensure!(
        vault.identity() != repository.identity(),
        "Graphify receipt binds the vault and repository to the same physical root"
    );
    let corpus_dir = vault.path().join(&expected.friendly_subdir);
    let expected_generation = corpus_dir
        .join(GRAPHIFY_GENERATIONS_DIR)
        .join(&expected.generation_id);
    ensure!(
        generation_dir == expected_generation,
        "Graphify ingest generation path does not match its receipt"
    );
    validate_existing_directory_chain(generation_dir, "Graphify ingest generation")?;
    let generation_identity = crate::code_map::CanonicalRepoRoot::discover(generation_dir)
        .context("resolve physical Graphify ingest generation")?;
    ensure!(
        generation_identity.path() == expected_generation,
        "Graphify ingest generation is not its expected canonical path"
    );
    ensure_current_graphify_generation(&corpus_dir, expected)?;

    let persisted_receipt = read_regular_bounded_no_follow(
        &generation_dir.join(GENERATION_RECEIPT_NAME),
        MAX_GRAPHIFY_RECEIPT_BYTES,
        GENERATION_RECEIPT_NAME,
    )?;
    let observed: GraphifyGenerationReceipt = serde_json::from_slice(&persisted_receipt)
        .context("parse published Graphify generation receipt")?;
    ensure!(
        observed == *expected,
        "published Graphify generation receipt does not match the expected receipt"
    );

    let expected_entries = expected
        .artifacts
        .iter()
        .map(|artifact| artifact.name.clone())
        .chain(std::iter::once(GENERATION_RECEIPT_NAME.to_owned()))
        .collect::<BTreeSet<_>>();
    ensure!(
        directory_entry_names(generation_dir)? == expected_entries,
        "published Graphify generation has a missing or unreceipted entry"
    );

    let mut verified_sources = BTreeMap::new();
    for artifact in &expected.artifacts {
        let retain = artifact.name.eq_ignore_ascii_case(GRAPH_REPORT_NAME);
        let verified = verify_regular_artifact(
            &generation_dir.join(&artifact.name),
            graphify_artifact_limit(&artifact.name)?,
            &artifact.name,
            retain,
        )?;
        ensure!(
            verified.bytes == artifact.bytes && verified.sha256 == artifact.sha256,
            "published Graphify artifact {} differs from its receipt",
            artifact.name
        );
        ensure!(
            verified.non_whitespace,
            "required Graphify artifact {} is empty or whitespace-only",
            artifact.name
        );
        if artifact
            .name
            .rsplit_once('.')
            .is_some_and(|(_, extension)| extension.eq_ignore_ascii_case("md"))
        {
            let bytes = verified
                .retained
                .context("receipted Graphify markdown bytes were not retained")?;
            let (title, slug) = graphify_markdown_identity(&artifact.name, &bytes)?;
            ensure!(
                verified_sources
                    .insert(
                        artifact.name.clone(),
                        VerifiedGraphifySource {
                            name: artifact.name.clone(),
                            title,
                            slug,
                            sha256: verified.sha256,
                        },
                    )
                    .is_none(),
                "Graphify receipt contains duplicate markdown artifacts"
            );
        }
    }

    ensure!(
        !verified_sources.is_empty(),
        "Graphify receipt has no ingestible markdown source"
    );

    validate_existing_directory_chain(generation_dir, "Graphify ingest generation")?;
    let after = crate::code_map::CanonicalRepoRoot::discover(generation_dir)
        .context("revalidate physical Graphify ingest generation")?;
    ensure!(
        after == generation_identity,
        "Graphify ingest generation changed while artifacts were verified"
    );
    ensure_current_graphify_generation(&corpus_dir, expected)?;
    Ok(VerifiedGraphifyGeneration {
        sources: verified_sources.into_values().collect(),
        corpus_dir,
        repository,
    })
}

fn validate_graphify_receipt_shape(receipt: &GraphifyGenerationReceipt) -> Result<()> {
    ensure!(
        receipt.schema_version == GRAPHIFY_PUBLISH_SCHEMA,
        "unsupported Graphify ingest receipt schema"
    );
    ensure!(
        receipt.native_index_generation > 0
            && receipt.native_index_generation == receipt.native_graph_generation,
        "Graphify ingest receipt has invalid native generations"
    );
    ensure!(
        valid_sha256(&receipt.repo_root_identity_sha256)
            && valid_sha256(&receipt.vault_root_identity_sha256)
            && valid_sha256(&receipt.source_fingerprint_sha256),
        "Graphify ingest receipt has invalid hash evidence"
    );
    validate_normal_component(&receipt.friendly_subdir, "Graphify friendly subdirectory")?;
    validate_required_graphify_artifact_manifest(receipt)?;
    let mut total = 0_u64;
    for artifact in &receipt.artifacts {
        ensure!(
            valid_sha256(&artifact.sha256),
            "Graphify ingest artifact receipt has an invalid SHA-256"
        );
        ensure!(
            artifact.bytes <= graphify_artifact_limit(&artifact.name)?,
            "Graphify ingest artifact receipt exceeds its byte limit"
        );
        total = total
            .checked_add(artifact.bytes)
            .context("Graphify ingest artifact byte total overflow")?;
    }
    ensure!(
        total <= MAX_GRAPHIFY_REPORT_BYTES + MAX_GRAPHIFY_TREE_BYTES,
        "Graphify ingest artifact receipts exceed their aggregate byte limit"
    );
    ensure!(
        receipt.generation_id == graphify_generation_id(receipt),
        "Graphify ingest generation id does not bind its receipt"
    );
    Ok(())
}

/// One closed artifact policy shared by the public compatibility wrapper, the
/// guarded transaction path, and no-ingest receipt admission. A library caller
/// cannot weaken Graphify publication's REPORT+TREE completion contract.
fn validate_required_graphify_artifact_manifest(receipt: &GraphifyGenerationReceipt) -> Result<()> {
    ensure!(
        receipt.artifacts.len() == REQUIRED_GRAPHIFY_ARTIFACTS.len(),
        "Graphify ingest requires exactly GRAPH_REPORT.md and GRAPH_TREE.html"
    );
    for (artifact, (required_name, _)) in receipt.artifacts.iter().zip(REQUIRED_GRAPHIFY_ARTIFACTS)
    {
        ensure!(
            artifact.name.as_str() == required_name,
            "Graphify ingest artifact manifest is not the canonical REPORT+TREE pair"
        );
    }
    Ok(())
}

fn validate_receipted_vault(
    receipt: &GraphifyGenerationReceipt,
) -> Result<crate::code_map::CanonicalRepoRoot> {
    let vault =
        crate::code_map::CanonicalRepoRoot::discover(Path::new(&receipt.canonical_vault_root))
            .context("resolve Graphify receipt vault root")?;
    ensure!(
        vault.display() == receipt.canonical_vault_root,
        "Graphify receipt vault root is not its canonical display path"
    );
    validate_existing_directory_chain(vault.path(), "Graphify receipt vault root")?;
    let mut digest = Sha256::new();
    digest.update(b"neoth.graphify.vault-root.v1\0");
    digest.update(vault.identity().as_str().as_bytes());
    ensure!(
        receipt.vault_root_identity_sha256 == hex::encode(digest.finalize()),
        "Graphify receipt vault identity no longer matches the physical root"
    );
    Ok(vault)
}

fn validate_receipted_repository(
    receipt: &GraphifyGenerationReceipt,
) -> Result<crate::code_map::CanonicalRepoRoot> {
    let repository =
        crate::code_map::CanonicalRepoRoot::discover(Path::new(&receipt.canonical_repo_root))
            .context("resolve Graphify receipt repository root")?;
    ensure!(
        repository.display() == receipt.canonical_repo_root,
        "Graphify receipt repository root is not its canonical display path"
    );
    validate_existing_directory_chain(repository.path(), "Graphify receipt repository root")?;
    ensure!(
        receipt.repo_root_identity_sha256
            == physical_root_digest(b"neoth.code-map.root-identity.v1\0", &repository),
        "Graphify receipt repository identity no longer matches the physical root"
    );
    ensure!(
        receipt.corpus_id == graphify_corpus_id(&repository),
        "Graphify receipt corpus id does not match the physical repository root"
    );
    ensure!(
        receipt.corpus_namespace
            == graphify_corpus_namespace(&repository, &receipt.source_fingerprint_sha256),
        "Graphify receipt corpus namespace does not bind its root and source fingerprint"
    );
    Ok(repository)
}

fn ensure_current_graphify_generation(
    corpus_dir: &Path,
    receipt: &GraphifyGenerationReceipt,
) -> Result<()> {
    let observed = read_current_graphify_pointer(corpus_dir)?
        .with_context(|| format!("published Graphify {CURRENT_POINTER_NAME} pointer is missing"))?;
    ensure!(
        observed == CurrentGraphifyPointer::from(receipt),
        "published Graphify CURRENT pointer no longer names the ingested generation"
    );
    Ok(())
}

fn ensure_receipted_source_is_current(
    repository: &crate::code_map::CanonicalRepoRoot,
    receipt: &GraphifyGenerationReceipt,
) -> Result<()> {
    let observed_root = crate::code_map::CanonicalRepoRoot::discover(repository.path())
        .context("revalidate Graphify receipt repository root")?;
    ensure!(
        observed_root == *repository,
        "Graphify receipt repository root changed before ingest"
    );
    validate_existing_directory_chain(observed_root.path(), "Graphify receipt repository root")?;
    let observed_fingerprint = crate::code_map::stable_source_fingerprint(
        &observed_root,
        crate::code_map::RebuildOptions::default(),
    )
    .context("validate stable current Graphify receipt source fingerprint")?;
    ensure!(
        observed_fingerprint == receipt.source_fingerprint_sha256,
        "current repository sources no longer match the published Graphify receipt"
    );
    Ok(())
}

fn physical_root_digest(domain: &[u8], root: &crate::code_map::CanonicalRepoRoot) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(root.identity().as_str().as_bytes());
    hex::encode(digest.finalize())
}

fn graphify_corpus_id(root: &crate::code_map::CanonicalRepoRoot) -> String {
    format!(
        "graphify-root-v1-{}",
        physical_root_digest(b"neoth.graphify.corpus-root.v1\0", root)
    )
}

fn graphify_corpus_namespace(
    root: &crate::code_map::CanonicalRepoRoot,
    source_fingerprint_sha256: &str,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"neoth.graphify.corpus-snapshot.v1\0");
    digest.update(root.identity().as_str().as_bytes());
    digest.update(b"\0");
    digest.update(source_fingerprint_sha256.as_bytes());
    format!("graphify-v1-{}", hex::encode(digest.finalize()))
}

fn graphify_corpus_scope(receipt: &GraphifyGenerationReceipt) -> String {
    let slug = receipt
        .friendly_subdir
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '_' | '-') {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    let slug = slug
        .trim_matches('-')
        .chars()
        .take(MAX_GRAPHIFY_SCOPE_CORPUS_LEN)
        .collect::<String>();
    let slug = slug.trim_end_matches('-');
    let safe = if slug.is_empty() { "corpus" } else { slug };
    format!(
        "{GRAPHIFY_CORPUS_SCOPE_PREFIX}{safe}-{}",
        receipt.repo_root_identity_sha256
    )
}

fn graphify_generation_id(receipt: &GraphifyGenerationReceipt) -> String {
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

fn graphify_artifact_limit(name: &str) -> Result<u64> {
    REQUIRED_GRAPHIFY_ARTIFACTS
        .iter()
        .find_map(|(required_name, limit)| (*required_name == name).then_some(*limit))
        .ok_or_else(|| anyhow::anyhow!("unsupported Graphify ingest artifact name"))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_normal_component(value: &str, label: &str) -> Result<()> {
    ensure!(
        !value.is_empty() && !value.chars().any(char::is_control),
        "{label} is empty or contains a control character"
    );
    ensure!(
        value.len() <= MAX_GRAPHIFY_FRIENDLY_SUBDIR_BYTES,
        "{label} exceeds its portable byte limit"
    );
    ensure!(
        !value.ends_with('.')
            && !value.ends_with(' ')
            && !value.chars().any(|character| matches!(
                character,
                '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|'
            )),
        "{label} contains a non-portable path character"
    );
    let path = Path::new(value);
    let mut components = path.components();
    let Some(Component::Normal(component)) = components.next() else {
        bail!("{label} is not a normal path component");
    };
    ensure!(
        components.next().is_none() && component == OsStr::new(value),
        "{label} must be exactly one path component"
    );
    let portable_stem = value
        .split('.')
        .next()
        .unwrap_or(value)
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
        "{label} is a reserved portable device name"
    );
    Ok(())
}

/// Build the sole Graphify source identity from bytes read through the bounded
/// no-follow handle.  This deliberately does not delegate to generic wiki
/// discovery: that walker is suitable for a trusted source tree, whereas a
/// published generation is a fixed receipt-defined artifact set and must not
/// open a FIFO, traverse a link, or accept an extra file.
fn graphify_markdown_identity(name: &str, bytes: &[u8]) -> Result<(String, String)> {
    let text = std::str::from_utf8(bytes).context("Graphify markdown artifact is not UTF-8")?;
    let path = Path::new(name);
    let stem = path
        .file_stem()
        .and_then(OsStr::to_str)
        .context("Graphify markdown artifact has no UTF-8 file stem")?;
    let title = text
        .lines()
        .take(40)
        .find_map(|line| {
            line.trim_start()
                .strip_prefix("# ")
                .map(|heading| heading.trim().to_owned())
        })
        .filter(|title| !title.is_empty())
        .unwrap_or_else(|| prettify_stem(stem));
    Ok((title, slug_for(stem)))
}

fn read_regular_bounded_no_follow(path: &Path, max_bytes: u64, label: &str) -> Result<Vec<u8>> {
    let verified = verify_regular_artifact(path, max_bytes, label, true)?;
    verified
        .retained
        .context("bounded no-follow read did not retain requested bytes")
}

fn verify_regular_artifact(
    path: &Path,
    max_bytes: u64,
    label: &str,
    retain: bool,
) -> Result<VerifiedGraphifyFile> {
    let mut file = open_read_no_follow(path)
        .with_context(|| format!("open {label} without following links"))?;
    let before = file
        .metadata()
        .with_context(|| format!("read handle metadata for {label}"))?;
    ensure!(
        before.is_file() && !metadata_is_link_like(&before),
        "{label} is not a regular no-follow file"
    );
    ensure!(before.len() <= max_bytes, "{label} exceeds its byte limit");
    let mut retained = retain.then(|| {
        Vec::with_capacity(
            usize::try_from(before.len())
                .unwrap_or(64 * 1024)
                .min(64 * 1024),
        )
    });
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut non_whitespace = false;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("read bounded {label}"))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .context("Graphify ingest artifact byte count overflow")?;
        ensure!(total <= max_bytes, "{label} grew beyond its byte limit");
        non_whitespace |= buffer[..read]
            .iter()
            .any(|byte| !byte.is_ascii_whitespace());
        digest.update(&buffer[..read]);
        if let Some(bytes) = &mut retained {
            bytes.extend_from_slice(&buffer[..read]);
        }
    }
    let after = file
        .metadata()
        .with_context(|| format!("recheck handle metadata for {label}"))?;
    ensure!(
        after.is_file()
            && !metadata_is_link_like(&after)
            && before.len() == after.len()
            && total == after.len(),
        "{label} changed while it was read"
    );
    Ok(VerifiedGraphifyFile {
        bytes: total,
        sha256: hex::encode(digest.finalize()),
        non_whitespace,
        retained,
    })
}

fn open_read_no_follow(path: &Path) -> std::io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        OpenOptions::new()
            .read(true)
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

fn validate_existing_directory_chain(path: &Path, label: &str) -> Result<()> {
    ensure!(path.is_absolute(), "{label} is not absolute");
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                current.push(component.as_os_str());
            }
            Component::CurDir | Component::ParentDir => {
                bail!("{label} contains a dot path component")
            }
        }
        if matches!(component, Component::Prefix(_)) {
            continue;
        }
        let metadata = fs::symlink_metadata(&current)
            .with_context(|| format!("inspect {label} component {}", current.display()))?;
        ensure!(
            metadata.is_dir() && !metadata_is_link_like(&metadata),
            "{label} contains a symlink, junction, reparse point, or non-directory component"
        );
    }
    Ok(())
}

fn directory_entry_names(directory: &Path) -> Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    for entry in fs::read_dir(directory).context("enumerate published Graphify generation")? {
        let name = entry
            .context("read published Graphify generation entry")?
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("Graphify generation has a non-UTF-8 entry"))?;
        ensure!(
            names.insert(name),
            "Graphify generation has a duplicate entry"
        );
    }
    Ok(names)
}

fn ingest_statements_for_scope(
    conn: &Connection,
    statements: &[String],
    scope: &str,
    now_ns: i64,
) -> Result<IngestStats> {
    ingest_statements_for_scope_guarded(conn, statements, scope, now_ns, || Ok(()))
}

fn ingest_statements_for_scope_guarded<F>(
    conn: &Connection,
    statements: &[String],
    scope: &str,
    now_ns: i64,
    mut validate_fence: F,
) -> Result<IngestStats>
where
    F: FnMut() -> Result<()>,
{
    ensure!(
        !scope.trim().is_empty(),
        "ground-truth ingest scope is empty"
    );
    ensure!(
        !statements.is_empty(),
        "ground-truth ingest discovery returned no statements"
    );
    let mut stats = IngestStats::default();
    // F46 — revoke-all-then-insert-all must be ATOMIC: without a transaction a
    // mid-insert failure leaves the old rows already revoked and only part of
    // the new rows written (the module-doc idempotency claim would hold only on
    // success). One transaction → commit on success, roll back on any error/drop.
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)?;
    validate_fence().context("ground-truth ingest pre-mutation fence failed")?;
    for gt in list_for_scope(&tx, scope)? {
        if gt.revoked_at.is_none() {
            revoke(&tx, gt.id, now_ns)?;
            stats.revoked += 1;
        }
    }
    for statement in statements {
        insert(&tx, statement, &Source::BulkText, scope, now_ns)?;
        stats.inserted += 1;
    }
    validate_fence().context("ground-truth ingest pre-commit fence failed")?;
    tx.commit()?;
    Ok(stats)
}

fn revoke_scope_atomically_guarded<F>(
    conn: &Connection,
    scope: &str,
    now_ns: i64,
    mut validate_fence: F,
) -> Result<GraphifyIngestRevocation>
where
    F: FnMut() -> Result<()>,
{
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)?;
    validate_fence().context("ground-truth revoke pre-mutation fence failed")?;
    let mut result = GraphifyIngestRevocation::default();
    for groundtruth in list_for_scope(&tx, scope)? {
        if groundtruth.revoked_at.is_none() {
            revoke(&tx, groundtruth.id, now_ns)?;
            result.revoked += 1;
        }
    }
    validate_fence().context("ground-truth revoke pre-commit fence failed")?;
    tx.commit()?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wiki::sources::SourceCategory;
    use std::path::PathBuf;

    fn src(slug: &str, title: &str, cat: SourceCategory) -> WikiSource {
        WikiSource {
            title: title.to_string(),
            slug: slug.to_string(),
            rel_path: format!("{slug}.md"),
            abs_path: PathBuf::from(format!("/x/{slug}.md")),
            category: cat,
        }
    }

    fn conn() -> (tempfile::TempDir, Connection) {
        let dir = tempfile::tempdir().unwrap();
        let c = crate::memory::store::open(&dir.path().join("views.db")).unwrap();
        (dir, c)
    }

    struct GraphifyFixture {
        repository: tempfile::TempDir,
        vault: tempfile::TempDir,
        corpus_dir: PathBuf,
        generation_dir: PathBuf,
        receipt: GraphifyGenerationReceipt,
    }

    impl GraphifyFixture {
        fn new(include_tree: bool) -> Self {
            Self::with_report(
                include_tree,
                b"# Graph report\n\nverified graph bytes\n".to_vec(),
            )
        }

        fn with_report(_legacy_include_tree: bool, report: Vec<u8>) -> Self {
            Self::with_report_and_tree(report, b"<html>verified tree</html>\n".to_vec())
        }

        fn with_report_and_tree(report: Vec<u8>, tree: Vec<u8>) -> Self {
            let repository = crate::test_env::canonical_tempdir().unwrap();
            fs::write(repository.path().join("lib.rs"), b"fn graph_source() {}\n").unwrap();
            let canonical_repository =
                crate::code_map::CanonicalRepoRoot::discover(repository.path()).unwrap();
            let source_fingerprint_sha256 = crate::code_map::stable_source_fingerprint(
                &canonical_repository,
                crate::code_map::RebuildOptions::default(),
            )
            .unwrap();
            let vault = crate::test_env::canonical_tempdir().unwrap();
            let canonical_vault =
                crate::code_map::CanonicalRepoRoot::discover(vault.path()).unwrap();
            // Every valid fixture models the publisher's closed REPORT+TREE
            // completion contract. Tests for partial manifests derive an
            // explicitly invalid receipt from this complete baseline.
            let artifact_bytes = vec![(GRAPH_REPORT_NAME, report), (GRAPH_TREE_NAME, tree)];
            let artifacts = artifact_bytes
                .iter()
                .map(
                    |(name, bytes)| crate::graphify_publish::GraphifyArtifactReceipt {
                        name: (*name).to_owned(),
                        bytes: bytes.len() as u64,
                        sha256: hex::encode(Sha256::digest(bytes)),
                    },
                )
                .collect();
            let mut receipt = GraphifyGenerationReceipt {
                schema_version: GRAPHIFY_PUBLISH_SCHEMA,
                corpus_id: graphify_corpus_id(&canonical_repository),
                corpus_namespace: graphify_corpus_namespace(
                    &canonical_repository,
                    &source_fingerprint_sha256,
                ),
                generation_id: String::new(),
                friendly_subdir: "repo".to_owned(),
                canonical_repo_root: canonical_repository.display().to_owned(),
                repo_root_identity_sha256: physical_root_digest(
                    b"neoth.code-map.root-identity.v1\0",
                    &canonical_repository,
                ),
                canonical_vault_root: canonical_vault.display().to_owned(),
                vault_root_identity_sha256: physical_root_digest(
                    b"neoth.graphify.vault-root.v1\0",
                    &canonical_vault,
                ),
                source_fingerprint_sha256,
                native_index_generation: 7,
                native_graph_generation: 7,
                artifacts,
            };
            receipt.generation_id = graphify_generation_id(&receipt);
            let corpus_dir = canonical_vault.path().join(&receipt.friendly_subdir);
            let generation_dir = corpus_dir
                .join(GRAPHIFY_GENERATIONS_DIR)
                .join(&receipt.generation_id);
            fs::create_dir_all(&generation_dir).unwrap();
            for (name, bytes) in artifact_bytes {
                fs::write(generation_dir.join(name), bytes).unwrap();
            }
            let mut receipt_bytes = serde_json::to_vec_pretty(&receipt).unwrap();
            receipt_bytes.push(b'\n');
            fs::write(generation_dir.join(GENERATION_RECEIPT_NAME), receipt_bytes).unwrap();
            let current = CurrentGraphifyPointer::from(&receipt);
            let mut current_bytes = serde_json::to_vec_pretty(&current).unwrap();
            current_bytes.push(b'\n');
            fs::write(corpus_dir.join(CURRENT_POINTER_NAME), current_bytes).unwrap();
            Self {
                repository,
                vault,
                corpus_dir,
                generation_dir,
                receipt,
            }
        }

        fn scope(&self) -> String {
            GraphifyIngestScope::Corpus.groundtruth_scope(&self.receipt)
        }
    }

    fn assert_scope_preserved(conn: &Connection, scope: &str, expected_title: &str) {
        let rows = list_for_scope(conn, scope).unwrap();
        assert_eq!(rows.len(), 1);
        assert!(rows[0].statement.contains(expected_title));
        assert!(rows[0].revoked_at.is_none());
    }

    #[test]
    fn statement_is_a_pointer_not_the_body() {
        let s = src("SPEC_x", "Spec X", SourceCategory::Spec);
        let st = statement_for(&s);
        assert!(st.contains("Spec X"));
        assert!(st.contains("[[SPEC_x]]"));
        assert!(st.contains("spec"));
        assert!(st.contains("SPEC_x.md"));
    }

    #[test]
    fn ingest_inserts_one_row_per_source() {
        let (_d, c) = conn();
        let sources = vec![
            src("SPEC_a", "Spec A", SourceCategory::Spec),
            src("00_DESIGN", "Design", SourceCategory::Design),
        ];
        let stats = ingest_sources(&c, &sources, 1_000).unwrap();
        assert_eq!(stats.inserted, 2);
        assert_eq!(stats.revoked, 0);
        let rows = list_for_scope(&c, WIKI_SCOPE).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].source, "bulk-text");
        assert!(rows.iter().all(|r| r.revoked_at.is_none()));
    }

    #[test]
    fn re_ingest_revokes_prior_and_stays_idempotent() {
        let (_d, c) = conn();
        let sources = vec![src("SPEC_a", "Spec A", SourceCategory::Spec)];
        ingest_sources(&c, &sources, 1_000).unwrap();
        // Second pass with a changed corpus: the old row is revoked, the new
        // set inserted — active count reflects only the latest build.
        let sources2 = vec![
            src("SPEC_a", "Spec A v2", SourceCategory::Spec),
            src("SPEC_b", "Spec B", SourceCategory::Spec),
        ];
        let stats = ingest_sources(&c, &sources2, 2_000).unwrap();
        assert_eq!(stats.revoked, 1, "prior active row revoked");
        assert_eq!(stats.inserted, 2);
        let active = list_for_scope(&c, WIKI_SCOPE).unwrap();
        assert_eq!(active.len(), 2, "only the latest build is active");
        assert!(active.iter().any(|r| r.statement.contains("Spec A v2")));
    }

    #[test]
    fn empty_generic_discovery_never_revokes_prior_scope() {
        let (_d, c) = conn();
        let sources = vec![src("SPEC_a", "Spec A", SourceCategory::Spec)];
        ingest_sources(&c, &sources, 1_000).unwrap();

        let error = ingest_sources(&c, &[], 2_000).unwrap_err();
        assert!(error.to_string().contains("returned no statements"));
        assert_scope_preserved(&c, WIKI_SCOPE, "Spec A");
    }

    #[test]
    fn failed_pre_commit_fence_rolls_back_revoke_and_insert() {
        let (_d, c) = conn();
        let scope = "guarded-scope";
        ingest_sources_for_scope(
            &c,
            &[src("SPEC_a", "Spec A", SourceCategory::Spec)],
            scope,
            1_000,
        )
        .unwrap();
        let calls = std::cell::Cell::new(0_u8);
        let statements = vec!["replacement".to_owned()];

        let error = ingest_statements_for_scope_guarded(&c, &statements, scope, 2_000, || {
            calls.set(calls.get() + 1);
            ensure!(calls.get() == 1, "injected pre-commit fence failure");
            Ok(())
        })
        .unwrap_err();
        assert!(error.to_string().contains("pre-commit fence failed"));
        assert_scope_preserved(&c, scope, "Spec A");
    }

    #[test]
    fn explicit_scope_rebuild_never_revokes_self_wiki_rows() {
        let (_d, c) = conn();
        let wiki = vec![src("SPEC_a", "Spec A", SourceCategory::Spec)];
        let fixture = GraphifyFixture::new(false);
        ingest_sources(&c, &wiki, 1_000).unwrap();
        ingest_graphify_generation_for_scope(
            &c,
            &fixture.generation_dir,
            GraphifyIngestScope::SelfMap,
            &fixture.receipt,
            2_000,
        )
        .unwrap();

        let wiki_rows = list_for_scope(&c, WIKI_SCOPE).unwrap();
        assert_eq!(wiki_rows.len(), 1);
        assert!(wiki_rows[0].revoked_at.is_none());
        let self_map_scope = GraphifyIngestScope::SelfMap.groundtruth_scope(&fixture.receipt);
        let self_map_rows = list_for_scope(&c, &self_map_scope).unwrap();
        assert_eq!(self_map_rows.len(), 1);
        assert!(self_map_rows[0].revoked_at.is_none());
    }

    #[test]
    fn self_map_scopes_are_isolated_by_physical_repository_root() {
        let (_d, c) = conn();
        let first = GraphifyFixture::new(false);
        let second = GraphifyFixture::new(false);
        let first_scope = GraphifyIngestScope::SelfMap.groundtruth_scope(&first.receipt);
        let second_scope = GraphifyIngestScope::SelfMap.groundtruth_scope(&second.receipt);
        assert_ne!(first_scope, second_scope);

        ingest_graphify_generation_for_scope(
            &c,
            &first.generation_dir,
            GraphifyIngestScope::SelfMap,
            &first.receipt,
            1_000,
        )
        .unwrap();
        ingest_graphify_generation_for_scope(
            &c,
            &second.generation_dir,
            GraphifyIngestScope::SelfMap,
            &second.receipt,
            2_000,
        )
        .unwrap();

        assert_scope_preserved(&c, &first_scope, "Graph report");
        assert_scope_preserved(&c, &second_scope, "Graph report");
    }

    #[test]
    fn no_ingest_revokes_only_the_typed_current_graphify_scope() {
        let (_d, c) = conn();
        let fixture = GraphifyFixture::new(false);
        let scope = fixture.scope();
        ingest_graphify_generation_for_scope(
            &c,
            &fixture.generation_dir,
            GraphifyIngestScope::Corpus,
            &fixture.receipt,
            1_000,
        )
        .unwrap();
        ingest_sources_for_scope(
            &c,
            &[src("SPEC_a", "Canonical wiki", SourceCategory::Spec)],
            WIKI_SCOPE,
            1_000,
        )
        .unwrap();

        let result = revoke_graphify_scope_for_no_ingest(
            &c,
            &fixture.corpus_dir,
            GraphifyIngestScope::Corpus,
            &fixture.receipt,
            2_000,
        )
        .unwrap();
        assert_eq!(result.revoked, 1);
        assert!(
            list_for_scope(&c, &scope)
                .unwrap()
                .iter()
                .all(|row| row.revoked_at.is_some())
        );
        assert_scope_preserved(&c, WIKI_SCOPE, "Canonical wiki");
    }

    #[test]
    fn guarded_no_ingest_current_fence_rolls_back_revocation() {
        let (_d, c) = conn();
        let fixture = GraphifyFixture::new(false);
        let scope = fixture.scope();
        ingest_graphify_generation_for_scope(
            &c,
            &fixture.generation_dir,
            GraphifyIngestScope::Corpus,
            &fixture.receipt,
            1_000,
        )
        .unwrap();

        let checks = std::cell::Cell::new(0_u8);
        let error = revoke_graphify_scope_for_no_ingest_guarded(
            &c,
            &fixture.corpus_dir,
            GraphifyIngestScope::Corpus,
            &fixture.receipt,
            2_000,
            || {
                if checks.replace(checks.get() + 1) == 1 {
                    let mut newer = CurrentGraphifyPointer::from(&fixture.receipt);
                    newer.generation_id = format!("gen-v1-{}", "d".repeat(64));
                    fs::write(
                        fixture.corpus_dir.join(CURRENT_POINTER_NAME),
                        serde_json::to_vec_pretty(&newer)?,
                    )?;
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("pre-commit fence failed"));
        assert_scope_preserved(&c, &scope, "Graph report");
    }

    #[test]
    fn graphify_ingest_binds_every_pointer_to_exact_generation() {
        let (_d, c) = conn();
        let fixture = GraphifyFixture::new(true);
        let stats = ingest_graphify_generation_for_scope(
            &c,
            &fixture.generation_dir,
            GraphifyIngestScope::Corpus,
            &fixture.receipt,
            2_000,
        )
        .unwrap();
        assert_eq!(stats.inserted, 1);
        let rows = list_for_scope(&c, &fixture.scope()).unwrap();
        let statement = &rows[0].statement;
        assert!(statement.contains(&fixture.receipt.generation_id));
        assert!(statement.contains(&fixture.receipt.source_fingerprint_sha256));
        assert!(statement.contains(&fixture.receipt.artifacts[0].sha256));
        assert!(statement.contains("native_generation: 7"));
        assert!(!statement.contains(&fixture.receipt.canonical_repo_root));
        assert!(!statement.contains(&fixture.receipt.canonical_vault_root));
    }

    #[test]
    fn graphify_blank_report_never_revokes_prior_scope() {
        let (_d, c) = conn();
        let fixture = GraphifyFixture::with_report(false, b" \r\n\t".to_vec());
        let scope = fixture.scope();
        ingest_sources_for_scope(
            &c,
            &[src("GRAPH_REPORT", "Prior graph", SourceCategory::Design)],
            &scope,
            1_000,
        )
        .unwrap();

        let error = ingest_graphify_generation_for_scope(
            &c,
            &fixture.generation_dir,
            GraphifyIngestScope::Corpus,
            &fixture.receipt,
            2_000,
        )
        .unwrap_err();
        assert!(error.to_string().contains("empty or whitespace-only"));
        assert_scope_preserved(&c, &scope, "Prior graph");
    }

    #[test]
    fn graphify_source_change_never_revokes_prior_scope() {
        let (_d, c) = conn();
        let fixture = GraphifyFixture::new(false);
        let scope = fixture.scope();
        ingest_graphify_generation_for_scope(
            &c,
            &fixture.generation_dir,
            GraphifyIngestScope::Corpus,
            &fixture.receipt,
            1_000,
        )
        .unwrap();
        fs::write(
            fixture.repository.path().join("lib.rs"),
            b"fn changed_after_publication() {}\n",
        )
        .unwrap();

        let error = ingest_graphify_generation_for_scope(
            &c,
            &fixture.generation_dir,
            GraphifyIngestScope::Corpus,
            &fixture.receipt,
            2_000,
        )
        .unwrap_err();
        assert!(
            format!("{error:#}")
                .contains("current repository sources no longer match the published")
        );
        assert_scope_preserved(&c, &scope, "Graph report");
    }

    #[test]
    fn graphify_source_mutation_during_precommit_fence_rolls_back_scope() {
        let (_d, c) = conn();
        let fixture = GraphifyFixture::new(false);
        let scope = fixture.scope();
        ingest_graphify_generation_for_scope(
            &c,
            &fixture.generation_dir,
            GraphifyIngestScope::Corpus,
            &fixture.receipt,
            1_000,
        )
        .unwrap();

        let checks = std::cell::Cell::new(0_u8);
        let error = ingest_graphify_generation_for_scope_guarded(
            &c,
            &fixture.generation_dir,
            GraphifyIngestScope::Corpus,
            &fixture.receipt,
            2_000,
            || {
                if checks.replace(checks.get() + 1) == 1 {
                    fs::write(
                        fixture.repository.path().join("lib.rs"),
                        b"fn mutated_inside_precommit_fence() {}\n",
                    )?;
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("current repository sources no longer match"));
        assert_scope_preserved(&c, &scope, "Graph report");
    }

    #[test]
    fn graphify_non_current_generation_never_revokes_prior_scope() {
        let (_d, c) = conn();
        let fixture = GraphifyFixture::new(false);
        let scope = fixture.scope();
        ingest_graphify_generation_for_scope(
            &c,
            &fixture.generation_dir,
            GraphifyIngestScope::Corpus,
            &fixture.receipt,
            1_000,
        )
        .unwrap();
        let mut current = CurrentGraphifyPointer::from(&fixture.receipt);
        current.generation_id = format!("gen-v1-{}", "f".repeat(64));
        fs::write(
            fixture.corpus_dir.join(CURRENT_POINTER_NAME),
            serde_json::to_vec_pretty(&current).unwrap(),
        )
        .unwrap();

        let error = ingest_graphify_generation_for_scope(
            &c,
            &fixture.generation_dir,
            GraphifyIngestScope::Corpus,
            &fixture.receipt,
            2_000,
        )
        .unwrap_err();
        assert!(error.to_string().contains("no longer names"));
        assert_scope_preserved(&c, &scope, "Graph report");
    }

    #[test]
    fn graphify_current_change_inside_transaction_rolls_back_scope() {
        let (_d, c) = conn();
        let fixture = GraphifyFixture::new(false);
        let scope = fixture.scope();
        ingest_graphify_generation_for_scope(
            &c,
            &fixture.generation_dir,
            GraphifyIngestScope::Corpus,
            &fixture.receipt,
            1_000,
        )
        .unwrap();
        let changed = std::cell::Cell::new(false);
        let statements = vec!["uncommitted replacement".to_owned()];

        let error = ingest_statements_for_scope_guarded(&c, &statements, &scope, 2_000, || {
            ensure_current_graphify_generation(&fixture.corpus_dir, &fixture.receipt)?;
            if !changed.replace(true) {
                let mut newer = CurrentGraphifyPointer::from(&fixture.receipt);
                newer.generation_id = format!("gen-v1-{}", "e".repeat(64));
                fs::write(
                    fixture.corpus_dir.join(CURRENT_POINTER_NAME),
                    serde_json::to_vec_pretty(&newer).unwrap(),
                )
                .unwrap();
            }
            Ok(())
        })
        .unwrap_err();
        assert!(error.to_string().contains("pre-commit fence failed"));
        assert_scope_preserved(&c, &scope, "Graph report");
    }

    #[test]
    fn graphify_empty_artifact_manifest_rejects_before_revoking_prior_scope() {
        let (_d, c) = conn();
        let fixture = GraphifyFixture::new(false);
        let scope = fixture.scope();
        ingest_graphify_generation_for_scope(
            &c,
            &fixture.generation_dir,
            GraphifyIngestScope::Corpus,
            &fixture.receipt,
            1_000,
        )
        .unwrap();

        let mut empty_manifest = fixture.receipt.clone();
        empty_manifest.artifacts.clear();
        let error = ingest_graphify_generation_for_scope(
            &c,
            &fixture.generation_dir,
            GraphifyIngestScope::Corpus,
            &empty_manifest,
            2_000,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("requires exactly GRAPH_REPORT.md and GRAPH_TREE.html")
        );
        assert_scope_preserved(&c, &scope, "Graph report");
    }

    #[test]
    fn public_ingest_rejects_one_artifact_and_preserves_prior_scope() {
        let (_d, c) = conn();
        let fixture = GraphifyFixture::new(false);
        let scope = fixture.scope();
        ingest_graphify_generation_for_scope(
            &c,
            &fixture.generation_dir,
            GraphifyIngestScope::Corpus,
            &fixture.receipt,
            1_000,
        )
        .unwrap();

        let mut partial = fixture.receipt.clone();
        partial.artifacts.truncate(1);
        let error = ingest_graphify_generation_for_scope(
            &c,
            &fixture.generation_dir,
            GraphifyIngestScope::Corpus,
            &partial,
            2_000,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("requires exactly GRAPH_REPORT.md and GRAPH_TREE.html")
        );
        assert_scope_preserved(&c, &scope, "Graph report");
    }

    #[test]
    fn blank_tree_rejects_before_replacing_prior_scope() {
        let (_d, c) = conn();
        let fixture = GraphifyFixture::with_report_and_tree(
            b"# Graph report\n\nverified graph bytes\n".to_vec(),
            b" \r\n\t".to_vec(),
        );
        let scope = fixture.scope();
        ingest_sources_for_scope(
            &c,
            &[src("GRAPH_REPORT", "Prior graph", SourceCategory::Design)],
            &scope,
            1_000,
        )
        .unwrap();

        let error = ingest_graphify_generation_for_scope(
            &c,
            &fixture.generation_dir,
            GraphifyIngestScope::Corpus,
            &fixture.receipt,
            2_000,
        )
        .unwrap_err();
        assert!(error.to_string().contains("empty or whitespace-only"));
        assert_scope_preserved(&c, &scope, "Prior graph");
    }

    #[test]
    fn graphify_mismatched_persisted_receipt_rejects_before_revoking_prior_scope() {
        let (_d, c) = conn();
        let fixture = GraphifyFixture::new(false);
        let scope = fixture.scope();
        ingest_graphify_generation_for_scope(
            &c,
            &fixture.generation_dir,
            GraphifyIngestScope::Corpus,
            &fixture.receipt,
            1_000,
        )
        .unwrap();
        let mut mismatched = fixture.receipt.clone();
        mismatched.native_index_generation = 8;
        mismatched.native_graph_generation = 8;
        let mut mismatched_bytes = serde_json::to_vec_pretty(&mismatched).unwrap();
        mismatched_bytes.push(b'\n');
        fs::write(
            fixture.generation_dir.join(GENERATION_RECEIPT_NAME),
            mismatched_bytes,
        )
        .unwrap();

        let error = ingest_graphify_generation_for_scope(
            &c,
            &fixture.generation_dir,
            GraphifyIngestScope::Corpus,
            &fixture.receipt,
            2_000,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not match the expected receipt")
        );
        assert_scope_preserved(&c, &scope, "Graph report");
    }

    #[test]
    fn graphify_tampered_artifact_rejects_before_revoking_prior_scope() {
        let (_d, c) = conn();
        let fixture = GraphifyFixture::new(false);
        let scope = fixture.scope();
        ingest_graphify_generation_for_scope(
            &c,
            &fixture.generation_dir,
            GraphifyIngestScope::Corpus,
            &fixture.receipt,
            1_000,
        )
        .unwrap();
        fs::write(
            fixture.generation_dir.join(GRAPH_REPORT_NAME),
            b"# forged report\n\nchanged bytes\n",
        )
        .unwrap();

        let error = ingest_graphify_generation_for_scope(
            &c,
            &fixture.generation_dir,
            GraphifyIngestScope::Corpus,
            &fixture.receipt,
            2_000,
        )
        .unwrap_err();
        assert!(error.to_string().contains("differs from its receipt"));
        assert_scope_preserved(&c, &scope, "Graph report");
    }

    #[test]
    fn graphify_missing_artifact_rejects_before_revoking_prior_scope() {
        let (_d, c) = conn();
        let fixture = GraphifyFixture::new(false);
        let scope = fixture.scope();
        ingest_graphify_generation_for_scope(
            &c,
            &fixture.generation_dir,
            GraphifyIngestScope::Corpus,
            &fixture.receipt,
            1_000,
        )
        .unwrap();
        fs::remove_file(fixture.generation_dir.join(GRAPH_REPORT_NAME)).unwrap();

        assert!(
            ingest_graphify_generation_for_scope(
                &c,
                &fixture.generation_dir,
                GraphifyIngestScope::Corpus,
                &fixture.receipt,
                2_000,
            )
            .is_err()
        );
        assert_scope_preserved(&c, &scope, "Graph report");
    }

    #[test]
    fn graphify_non_regular_artifact_rejects_before_revoking_prior_scope() {
        let (_d, c) = conn();
        let fixture = GraphifyFixture::new(false);
        let scope = fixture.scope();
        ingest_graphify_generation_for_scope(
            &c,
            &fixture.generation_dir,
            GraphifyIngestScope::Corpus,
            &fixture.receipt,
            1_000,
        )
        .unwrap();
        let report = fixture.generation_dir.join(GRAPH_REPORT_NAME);
        fs::remove_file(&report).unwrap();
        fs::create_dir(&report).unwrap();

        assert!(
            ingest_graphify_generation_for_scope(
                &c,
                &fixture.generation_dir,
                GraphifyIngestScope::Corpus,
                &fixture.receipt,
                2_000,
            )
            .is_err()
        );
        assert_scope_preserved(&c, &scope, "Graph report");
    }

    #[cfg(unix)]
    #[test]
    fn graphify_fifo_artifact_cannot_block_or_revoke_prior_scope() {
        use std::os::unix::ffi::OsStrExt as _;

        let (_d, c) = conn();
        let fixture = GraphifyFixture::new(false);
        let scope = fixture.scope();
        ingest_graphify_generation_for_scope(
            &c,
            &fixture.generation_dir,
            GraphifyIngestScope::Corpus,
            &fixture.receipt,
            1_000,
        )
        .unwrap();
        let report = fixture.generation_dir.join(GRAPH_REPORT_NAME);
        fs::remove_file(&report).unwrap();
        let path = std::ffi::CString::new(report.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);

        let error = ingest_graphify_generation_for_scope(
            &c,
            &fixture.generation_dir,
            GraphifyIngestScope::Corpus,
            &fixture.receipt,
            2_000,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("not a regular no-follow file"));
        assert_scope_preserved(&c, &scope, "Graph report");
    }

    #[test]
    fn graphify_mismatched_persisted_receipt_preserves_prior_scope() {
        let (_d, c) = conn();
        let fixture = GraphifyFixture::new(false);
        let scope = fixture.scope();
        ingest_graphify_generation_for_scope(
            &c,
            &fixture.generation_dir,
            GraphifyIngestScope::Corpus,
            &fixture.receipt,
            1_000,
        )
        .unwrap();
        let mut observed = fixture.receipt.clone();
        observed.source_fingerprint_sha256 = "e".repeat(64);
        fs::write(
            fixture.generation_dir.join(GENERATION_RECEIPT_NAME),
            serde_json::to_vec_pretty(&observed).unwrap(),
        )
        .unwrap();

        let error = ingest_graphify_generation_for_scope(
            &c,
            &fixture.generation_dir,
            GraphifyIngestScope::Corpus,
            &fixture.receipt,
            2_000,
        )
        .unwrap_err();
        assert!(error.to_string().contains("does not match"));
        assert_scope_preserved(&c, &scope, "Graph report");
    }

    #[test]
    fn graphify_forged_repository_identity_preserves_prior_scope() {
        let (_d, c) = conn();
        let fixture = GraphifyFixture::new(false);
        let scope = fixture.scope();
        ingest_graphify_generation_for_scope(
            &c,
            &fixture.generation_dir,
            GraphifyIngestScope::Corpus,
            &fixture.receipt,
            1_000,
        )
        .unwrap();
        let mut forged = fixture.receipt.clone();
        forged.repo_root_identity_sha256 = "a".repeat(64);

        let error = ingest_graphify_generation_for_scope(
            &c,
            &fixture.generation_dir,
            GraphifyIngestScope::Corpus,
            &forged,
            2_000,
        )
        .unwrap_err();
        assert!(error.to_string().contains("repository identity"));
        assert_scope_preserved(&c, &scope, "Graph report");
    }

    #[test]
    fn graphify_linked_artifact_is_never_followed_or_replaced_in_groundtruth() {
        let (_d, c) = conn();
        let fixture = GraphifyFixture::new(false);
        let scope = fixture.scope();
        ingest_graphify_generation_for_scope(
            &c,
            &fixture.generation_dir,
            GraphifyIngestScope::Corpus,
            &fixture.receipt,
            1_000,
        )
        .unwrap();
        let report = fixture.generation_dir.join(GRAPH_REPORT_NAME);
        let outside = fixture.vault.path().join("outside.md");
        fs::write(&outside, b"# Graph report\n\nverified graph bytes\n").unwrap();
        fs::remove_file(&report).unwrap();
        if !create_file_link(&outside, &report) {
            return;
        }

        assert!(
            ingest_graphify_generation_for_scope(
                &c,
                &fixture.generation_dir,
                GraphifyIngestScope::Corpus,
                &fixture.receipt,
                2_000,
            )
            .is_err()
        );
        assert_scope_preserved(&c, &scope, "Graph report");
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
}
