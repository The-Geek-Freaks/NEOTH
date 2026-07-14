//! KF-03 — operator proof-bundle signing key (ed25519).
//!
//! `neoth wal export --sign` signs a `.neoth-proof` tamper-evidence bundle so
//! a third party can attribute it to THIS operator. The signing key is the
//! operator's OWN per-proof key — a **separate trust root** from the project
//! release key that `updater::sig_verify` (minisign-verify) checks; the two
//! must never be conflated.
//!
//! ## DAU-safe by construction
//!
//! The signing key is auto-generated + persisted on first `--sign` use,
//! mirroring the WAL HMAC key (`wal::compaction::load_or_init_key`) EXACTLY —
//! same `getrandom` entropy, same fail-closed-on-no-RNG contract, same
//! `write_key_securely` (unix mode 0600 / Windows DPAPI-wrap + DACL) + same
//! `maybe_unwrap_dpapi` on read. The operator types nothing, sees no password
//! prompt, installs no tool. This was the unanimous verdict of the Session-34
//! 3-lens DAU-safety gremium (vs. shelling out to the `minisign` binary, which
//! is DAU-hostile + not CI-testable).
//!
//! The scheme is a raw ed25519 detached signature over
//! [`crate::wal::proof_bundle::ProofBundle::canonical_bytes`]; verification is
//! `neoth wal verify-proof` (pure-Rust, no external tool). ed25519 hashes the
//! message internally with SHA-512, so no extra digest dep is needed.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Stable algorithm tag stored in the signed envelope so a future scheme
/// change is unambiguous to a verifier.
pub const SIG_ALGORITHM: &str = "ed25519-raw";

/// Stable schema for the append-only `EXTENDED/proof_key_rotated` audit
/// payload. The transition carries public material only. Both keys sign the
/// same canonical message, proving possession of the retiring and replacement
/// secrets without ever placing either secret in the WAL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofKeyRotationPayload {
    pub schema: u8,
    pub transition_id: String,
    pub old_public_key: String,
    pub new_public_key: String,
    pub archive_file: String,
    pub ts_unix: i64,
    pub old_signature: String,
    pub new_signature: String,
}

impl ProofKeyRotationPayload {
    pub const SCHEMA: u8 = 1;

    /// Canonical bytes signed by both sides of the transition. All string
    /// fields use alphabets that cannot contain `|` (UUID, base64, and a
    /// generated filesystem-safe archive name), so the framing is unambiguous.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        format!(
            "proof-key-rotated-v1|{}|{}|{}|{}|{}",
            self.transition_id,
            self.old_public_key,
            self.new_public_key,
            self.archive_file,
            self.ts_unix,
        )
        .into_bytes()
    }

    /// Validate the complete cryptographic transition, including both detached
    /// signatures and the generated path components used by crash recovery.
    pub fn validate(&self) -> Result<()> {
        if self.schema != Self::SCHEMA {
            anyhow::bail!("unsupported proof-key rotation schema {}", self.schema);
        }
        let transition_id = uuid::Uuid::parse_str(&self.transition_id)
            .context("invalid proof-key transition id")?;
        let canonical_id = transition_id.hyphenated().to_string();
        if self.transition_id != canonical_id
            || canonical_id.as_bytes().get(14).copied() != Some(b'7')
        {
            anyhow::bail!("proof-key transition id must be a canonical UUIDv7");
        }
        if self.old_public_key == self.new_public_key {
            anyhow::bail!("proof-key rotation old and new public keys are identical");
        }
        require_canonical_base64(&self.old_public_key, 32, "old_public_key")?;
        require_canonical_base64(&self.new_public_key, 32, "new_public_key")?;
        require_canonical_base64(&self.old_signature, 64, "old_signature")?;
        require_canonical_base64(&self.new_signature, 64, "new_signature")?;
        if self.ts_unix <= 0 {
            anyhow::bail!("proof-key rotation timestamp must be positive");
        }
        validate_private_sibling_name(&self.archive_file, "archive_file")?;
        let archive_suffix = format!(".archive-{}-{}.key", self.ts_unix, self.transition_id);
        if self
            .archive_file
            .strip_suffix(&archive_suffix)
            .is_none_or(|prefix| prefix.is_empty())
        {
            anyhow::bail!("proof-key rotation archive filename does not match its transition");
        }
        let msg = self.canonical_bytes();
        verify_b64(&self.old_public_key, &self.old_signature, &msg)
            .context("old proof key did not authorise the rotation")?;
        verify_b64(&self.new_public_key, &self.new_signature, &msg)
            .context("new proof key did not countersign the rotation")?;
        Ok(())
    }
}

fn require_canonical_base64(value: &str, expected_len: usize, field: &str) -> Result<()> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value)
        .with_context(|| format!("decode proof-key rotation {field}"))?;
    if decoded.len() != expected_len
        || base64::engine::general_purpose::STANDARD.encode(&decoded) != value
    {
        anyhow::bail!(
            "proof-key rotation {field} must be canonical base64 for exactly {expected_len} bytes"
        );
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingProofKeyRotation {
    payload: ProofKeyRotationPayload,
}

/// Read-only result used by `proof-key rotate --dry-run`.
pub struct ProofKeyRotationPreview {
    pub payload: ProofKeyRotationPayload,
    pub archive_path: PathBuf,
}

/// Prepared key rotation. The cross-process key lock stays held until the
/// caller durably appends the transition and commits (or aborts) the file
/// transaction, preventing a concurrent signer from observing an in-between
/// state.
pub struct PreparedProofKeyRotation {
    key_path: PathBuf,
    journal_path: PathBuf,
    staged_path: PathBuf,
    archive_path: PathBuf,
    new_key: SigningKey,
    payload: ProofKeyRotationPayload,
    _lock: std::fs::File,
}

impl PreparedProofKeyRotation {
    pub fn payload(&self) -> &ProofKeyRotationPayload {
        &self.payload
    }

    pub fn archive_path(&self) -> &Path {
        &self.archive_path
    }

    /// Check the WAL rather than trusting an RPC response. This closes the
    /// response-lost case: if the daemon fsynced the frame and the connection
    /// then died, the key still advances instead of rolling back behind a
    /// durable transition.
    pub fn audit_is_durable(&self) -> Result<bool> {
        let wal_dir = self
            .key_path
            .parent()
            .context("proof signing key has no WAL parent directory")?;
        rotation_event_exists(wal_dir, &self.payload)
    }

    /// Install the staged replacement only after its exact dual-signed audit
    /// frame is durable. Atomic replacement means a crash exposes either the
    /// old complete key or the new complete key, never a torn seed.
    pub fn commit(self) -> Result<ProofKeyRotationPreview> {
        if !self.audit_is_durable()? {
            anyhow::bail!(
                "proof-key rotation audit is not durable; refusing to replace {}",
                self.key_path.display()
            );
        }
        let archived = load_existing_signing_key(&self.archive_path)
            .context("reload retiring proof-key archive")?;
        if pubkey_b64(&archived) != self.payload.old_public_key {
            anyhow::bail!("retiring proof-key archive does not match the audited public key");
        }
        let staged = load_existing_signing_key(&self.staged_path)
            .context("reload staged proof signing key")?;
        if pubkey_b64(&staged) != self.payload.new_public_key {
            anyhow::bail!("staged proof signing key does not match the countersigned public key");
        }
        install_signing_key_atomically(&self.key_path, &self.new_key)
            .context("atomically install replacement proof signing key")?;
        let installed = load_existing_signing_key(&self.key_path)
            .context("verify installed proof signing key")?;
        if pubkey_b64(&installed) != self.payload.new_public_key {
            anyhow::bail!("installed proof signing key does not match the audited replacement");
        }
        remove_if_present(&self.staged_path)?;
        remove_if_present(&self.journal_path)?;
        sync_parent_dir(&self.key_path);
        Ok(ProofKeyRotationPreview {
            payload: self.payload,
            archive_path: self.archive_path,
        })
    }

    /// Abort a prepared rotation only while no matching transition exists in
    /// the WAL. Once audited, rollback would make the local trust root diverge
    /// from its append-only history, so callers must commit/recover instead.
    pub fn abort(self) -> Result<()> {
        if self.audit_is_durable()? {
            anyhow::bail!(
                "proof-key rotation is already audited; refusing rollback behind the WAL"
            );
        }
        remove_if_present(&self.staged_path)?;
        remove_if_present(&self.archive_path)?;
        remove_if_present(&self.journal_path)?;
        sync_parent_dir(&self.key_path);
        Ok(())
    }
}

/// Default signing-key path: `~/.neoth/wal/signing.key` (the 32-byte ed25519
/// seed). Sits next to the WAL HMAC key under the same protected dir.
pub fn default_signing_key_path() -> PathBuf {
    crate::config::FreedomConfig::default_wal_dir().join("signing.key")
}

fn key_lock_path(path: &Path) -> PathBuf {
    sibling_with_suffix(path, ".lock")
}

fn rotation_journal_path(path: &Path) -> PathBuf {
    sibling_with_suffix(path, ".rotation.json")
}

fn sibling_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(suffix);
    path.with_file_name(name)
}

fn validate_private_sibling_name(name: &str, field: &str) -> Result<()> {
    let path = Path::new(name);
    if name.is_empty()
        || path.file_name().and_then(|n| n.to_str()) != Some(name)
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        anyhow::bail!("{field} must be a single filesystem-safe file name");
    }
    Ok(())
}

fn private_sibling(parent: &Path, name: &str, field: &str) -> Result<PathBuf> {
    validate_private_sibling_name(name, field)?;
    Ok(parent.join(name))
}

fn load_existing_signing_key(path: &Path) -> Result<SigningKey> {
    let body =
        std::fs::read(path).with_context(|| format!("read signing key {}", path.display()))?;
    let raw = crate::wal::compaction::maybe_unwrap_dpapi(&body, path)?;
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(raw.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!(
            "signing key at {} is not 32 bytes ({} given) — refusing to use a malformed key",
            path.display(),
            raw.len(),
        )
    })?);
    Ok(SigningKey::from_bytes(&seed))
}

fn fresh_signing_key() -> Result<SigningKey> {
    let mut seed: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(seed.as_mut())
        .context("OS RNG unavailable — refusing to generate weak signing key")?;
    Ok(SigningKey::from_bytes(&seed))
}

#[cfg(windows)]
fn encoded_signing_seed(seed: &[u8; 32]) -> Result<Vec<u8>> {
    crate::wal::dpapi::protect(seed)
        .context("DPAPI wrap unavailable — refusing to persist rotated proof-key material")
}

#[cfg(not(windows))]
fn encoded_signing_seed(seed: &[u8; 32]) -> Result<Vec<u8>> {
    Ok(seed.to_vec())
}

fn install_signing_key_atomically(path: &Path, key: &SigningKey) -> Result<()> {
    let seed = Zeroizing::new(key.to_bytes());
    let encoded = Zeroizing::new(encoded_signing_seed(&seed)?);
    crate::util::atomic_write::atomic_write_private(path, &encoded)
        .with_context(|| format!("atomically write proof signing key {}", path.display()))?;
    #[cfg(windows)]
    crate::wal::win_acl::restrict_to_owner(path)
        .with_context(|| format!("restrict proof signing key ACL {}", path.display()))?;
    Ok(())
}

fn write_new_signing_key_securely(path: &Path, key: &SigningKey, what: &str) -> Result<()> {
    use std::io::Write as _;

    let seed = Zeroizing::new(key.to_bytes());
    let encoded = Zeroizing::new(encoded_signing_seed(&seed)?);
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("create {what} {}", path.display()))?;
    file.write_all(&encoded)
        .with_context(|| format!("write {what} {}", path.display()))?;
    file.flush()
        .with_context(|| format!("flush {what} {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("fsync {what} {}", path.display()))?;
    #[cfg(windows)]
    crate::wal::win_acl::restrict_to_owner(path)
        .with_context(|| format!("restrict {what} ACL {}", path.display()))?;
    Ok(())
}

fn remove_if_present(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("remove {}", path.display())),
    }
}

fn sync_parent_dir(path: &Path) {
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

fn sync_parent_dir_required(path: &Path, what: &str) -> Result<()> {
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)
            .with_context(|| format!("open {what} parent {}", parent.display()))?
            .sync_all()
            .with_context(|| format!("fsync {what} parent {}", parent.display()))?;
    }
    #[cfg(not(unix))]
    let _ = (path, what);
    Ok(())
}

fn sorted_wal_segments(wal_dir: &Path) -> Vec<PathBuf> {
    let mut segments = std::fs::read_dir(wal_dir)
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("wal"))
        .collect::<Vec<_>>();
    segments.sort();
    segments
}

/// Extract every cryptographically valid proof-key transition. Invalid/torn
/// frames grant no trust and are ignored fail-closed.
pub(crate) fn collect_valid_proof_key_rotations(
    segments: &[PathBuf],
) -> Vec<ProofKeyRotationPayload> {
    let mut out = Vec::new();
    for segment in segments {
        let Ok(raw) = std::fs::read(segment) else {
            continue;
        };
        if crate::wal::segment_header::parse_segment_header(&raw).is_err() {
            continue;
        }
        let Ok((header_len, logical)) = crate::wal::compaction::logical_segment_bytes(&raw) else {
            continue;
        };
        let mut cursor = header_len;
        while cursor < logical.len() {
            let Ok(frame) = crate::wal::frame::decode_frame(&logical[cursor..]) else {
                break;
            };
            let total = frame.header.total_len as usize;
            if frame.header.event_type == crate::wal::events::EVENT_TYPE_EXTENDED
                && frame.header.event_subtype
                    == crate::wal::events::ExtendedSubtype::ProofKeyRotated as u8
            {
                if let Ok(payload) =
                    serde_json::from_slice::<ProofKeyRotationPayload>(frame.payload)
                {
                    if payload.validate().is_ok() {
                        out.push(payload);
                    }
                }
            }
            if total == 0 {
                break;
            }
            cursor = cursor.saturating_add(total);
        }
    }
    out
}

fn rotation_event_exists(wal_dir: &Path, expected: &ProofKeyRotationPayload) -> Result<bool> {
    expected.validate()?;
    for segment in sorted_wal_segments(wal_dir) {
        let one = std::slice::from_ref(&segment);
        if !collect_valid_proof_key_rotations(one)
            .iter()
            .any(|payload| payload == expected)
        {
            continue;
        }

        // A readable frame can still be sitting only in the OS page cache
        // after a writer-side fsync error. Force the containing segment to
        // stable storage before calling it durable; if this flush fails the
        // journal/stage remain for retry-based recovery and the active key does
        // not move.
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&segment)
            .with_context(|| format!("open proof-key audit segment {}", segment.display()))?
            .sync_all()
            .with_context(|| format!("fsync proof-key audit segment {}", segment.display()))?;
        sync_parent_dir_required(&segment, "proof-key audit segment")?;
        if collect_valid_proof_key_rotations(one)
            .iter()
            .any(|payload| payload == expected)
        {
            return Ok(true);
        }
        anyhow::bail!(
            "proof-key rotation audit changed while it was being durably verified in {}",
            segment.display()
        );
    }
    Ok(false)
}

/// Current local proof key plus every unique predecessor connected by the
/// dual-signed WAL transition graph. Traversal follows only
/// `transition.new == current_cursor`, so it is independent of the daemon's
/// numeric vs. CLI UUID segment filename namespaces. An ambiguous predecessor
/// fails closed at that point instead of granting either branch trust.
pub(crate) fn trusted_signing_pubkeys(
    segments: &[PathBuf],
    current_key_path: &Path,
) -> BTreeSet<String> {
    let Some(current) = load_signing_pubkey_if_present(current_key_path) else {
        return BTreeSet::new();
    };
    let mut trusted = BTreeSet::from([current.clone()]);
    let mut cursor = current;
    let transitions = collect_valid_proof_key_rotations(segments);
    loop {
        let mut predecessors = transitions
            .iter()
            .filter(|transition| transition.new_public_key == cursor)
            .map(|transition| transition.old_public_key.clone())
            .collect::<BTreeSet<_>>();
        if predecessors.is_empty() {
            break;
        }
        if predecessors.len() != 1 {
            tracing::warn!(
                public_key = %cursor,
                candidates = predecessors.len(),
                "ambiguous proof-key predecessor chain; refusing historical trust"
            );
            break;
        }
        let predecessor = predecessors.pop_first().expect("set length checked");
        if !trusted.insert(predecessor.clone()) {
            tracing::warn!(
                public_key = %predecessor,
                "cyclic proof-key transition chain; refusing further historical trust"
            );
            break;
        }
        cursor = predecessor;
    }
    trusted
}

fn recover_pending_rotation_locked(key_path: &Path) -> Result<Option<ProofKeyRotationPreview>> {
    let journal_path = rotation_journal_path(key_path);
    if !journal_path.exists() {
        return Ok(None);
    }
    let body = std::fs::read(&journal_path)
        .with_context(|| format!("read pending proof-key rotation {}", journal_path.display()))?;
    let pending: PendingProofKeyRotation = serde_json::from_slice(&body).with_context(|| {
        format!(
            "parse pending proof-key rotation {}",
            journal_path.display()
        )
    })?;
    pending.payload.validate()?;
    let parent = key_path
        .parent()
        .context("proof signing key has no parent directory")?;
    let key_name = key_path
        .file_name()
        .and_then(|name| name.to_str())
        .context("proof signing key path has no UTF-8 file name")?;
    let staged_file = format!("{key_name}.rotation-{}.next", pending.payload.transition_id);
    let staged_path = private_sibling(parent, &staged_file, "staged_file")?;
    let expected_archive_file = format!(
        "{key_name}.archive-{}-{}.key",
        pending.payload.ts_unix, pending.payload.transition_id
    );
    if pending.payload.archive_file != expected_archive_file {
        anyhow::bail!("proof-key rotation journal contains an unexpected archive filename");
    }
    let archive_path = private_sibling(parent, &pending.payload.archive_file, "archive_file")?;
    let active_public = if key_path.exists() {
        Some(pubkey_b64(&load_existing_signing_key(key_path).context(
            "read active key during proof-key rotation recovery",
        )?))
    } else {
        None
    };

    if rotation_event_exists(parent, &pending.payload)? {
        let archived = load_existing_signing_key(&archive_path)
            .context("recover audited proof-key rotation archive")?;
        if pubkey_b64(&archived) != pending.payload.old_public_key {
            anyhow::bail!("audited proof-key rotation archive does not match the retiring key");
        }
        if active_public.as_deref() == Some(pending.payload.new_public_key.as_str()) {
            // Crash after the atomic install and staged-file cleanup but before
            // journal cleanup: the audited key is already authoritative.
            remove_if_present(&staged_path)?;
            remove_if_present(&journal_path)?;
            sync_parent_dir(key_path);
            return Ok(Some(ProofKeyRotationPreview {
                payload: pending.payload,
                archive_path,
            }));
        }
        if active_public.is_some()
            && active_public.as_deref() != Some(pending.payload.old_public_key.as_str())
        {
            anyhow::bail!(
                "proof-key rotation journal is stale: active key matches neither side of the audited transition"
            );
        }
        let staged = load_existing_signing_key(&staged_path)
            .context("recover audited proof-key rotation from staged key")?;
        if pubkey_b64(&staged) != pending.payload.new_public_key {
            anyhow::bail!("pending proof-key rotation staged key does not match WAL transition");
        }
        install_signing_key_atomically(key_path, &staged)?;
        remove_if_present(&staged_path)?;
        remove_if_present(&journal_path)?;
        sync_parent_dir(key_path);
        return Ok(Some(ProofKeyRotationPreview {
            payload: pending.payload,
            archive_path,
        }));
    }

    // No durable transition: the old key remains authoritative. Restore it
    // only when the active file is missing; any third key means a stale/replayed
    // journal and must fail closed instead of rolling a newer key backwards.
    if active_public.is_none() {
        let archived = load_existing_signing_key(&archive_path)
            .context("restore uncommitted proof key from rotation archive")?;
        if pubkey_b64(&archived) != pending.payload.old_public_key {
            anyhow::bail!("proof-key rotation archive does not match the retiring public key");
        }
        install_signing_key_atomically(key_path, &archived)?;
    } else if active_public.as_deref() != Some(pending.payload.old_public_key.as_str()) {
        anyhow::bail!(
            "proof-key rotation journal is stale: active key is not the unaudited retiring key"
        );
    }
    remove_if_present(&staged_path)?;
    remove_if_present(&archive_path)?;
    remove_if_present(&journal_path)?;
    sync_parent_dir(key_path);
    Ok(None)
}

/// Resolve an interrupted rotation transaction under the cross-process key
/// lock. An audited transition is completed and returned; an unaudited prepare
/// is rolled back and returns `None`.
pub fn recover_signing_key_rotation(key_path: &Path) -> Result<Option<ProofKeyRotationPreview>> {
    let _lock = crate::util::locked_file::lock_file_blocking(
        &key_lock_path(key_path),
        "proof signing key",
    )?;
    recover_pending_rotation_locked(key_path)
}

fn build_rotation_preview(
    key_path: &Path,
    old_key: &SigningKey,
    new_key: &SigningKey,
) -> Result<ProofKeyRotationPreview> {
    let transition_id = uuid::Uuid::now_v7().to_string();
    let ts_unix = i64::try_from(crate::time::now_unix_secs())
        .context("proof-key rotation timestamp exceeds i64")?;
    let key_name = key_path
        .file_name()
        .and_then(|name| name.to_str())
        .context("proof signing key path has no UTF-8 file name")?;
    let archive_file = format!("{key_name}.archive-{ts_unix}-{transition_id}.key");
    let parent = key_path
        .parent()
        .context("proof signing key has no parent directory")?;
    let mut payload = ProofKeyRotationPayload {
        schema: ProofKeyRotationPayload::SCHEMA,
        transition_id,
        old_public_key: pubkey_b64(old_key),
        new_public_key: pubkey_b64(new_key),
        archive_file: archive_file.clone(),
        ts_unix,
        old_signature: String::new(),
        new_signature: String::new(),
    };
    let msg = payload.canonical_bytes();
    payload.old_signature = sign_b64(old_key, &msg);
    payload.new_signature = sign_b64(new_key, &msg);
    payload.validate()?;
    Ok(ProofKeyRotationPreview {
        payload,
        archive_path: parent.join(archive_file),
    })
}

/// Validate and cryptographically preview a rotation without writing an
/// archive, journal, key, or WAL frame.
pub fn preview_signing_key_rotation(key_path: &Path) -> Result<ProofKeyRotationPreview> {
    let _lock = crate::util::locked_file::lock_file_blocking(
        &key_lock_path(key_path),
        "proof signing key",
    )?;
    if rotation_journal_path(key_path).exists() {
        anyhow::bail!(
            "a pending proof-key rotation must be recovered before a dry run; rerun without --dry-run"
        );
    }
    if !key_path.exists() {
        anyhow::bail!(
            "no proof signing key exists at {} — create one with `neoth wal export --sign` before rotating",
            key_path.display()
        );
    }
    let old_key = load_existing_signing_key(key_path)?;
    let new_key = fresh_signing_key()?;
    build_rotation_preview(key_path, &old_key, &new_key)
}

/// Prepare a crash-recoverable rotation: write a protected old-key archive, a
/// protected staged replacement, and a metadata-only journal while keeping the
/// active key unchanged. The caller must append `payload()` to the WAL and then
/// call [`PreparedProofKeyRotation::commit`].
pub fn prepare_signing_key_rotation(key_path: &Path) -> Result<PreparedProofKeyRotation> {
    let lock = crate::util::locked_file::lock_file_blocking(
        &key_lock_path(key_path),
        "proof signing key",
    )?;
    if recover_pending_rotation_locked(key_path)?.is_some() {
        anyhow::bail!(
            "an interrupted audited proof-key rotation was recovered; retry only if another rotation is intended"
        );
    }
    if !key_path.exists() {
        anyhow::bail!(
            "no proof signing key exists at {} — create one with `neoth wal export --sign` before rotating",
            key_path.display()
        );
    }
    let old_key = load_existing_signing_key(key_path)?;
    let new_key = fresh_signing_key()?;
    let preview = build_rotation_preview(key_path, &old_key, &new_key)?;
    let parent = key_path
        .parent()
        .context("proof signing key has no parent directory")?;
    let key_name = key_path
        .file_name()
        .and_then(|name| name.to_str())
        .context("proof signing key path has no UTF-8 file name")?;
    let staged_file = format!("{key_name}.rotation-{}.next", preview.payload.transition_id);
    let staged_path = parent.join(&staged_file);
    let journal_path = rotation_journal_path(key_path);
    if staged_path.exists() || preview.archive_path.exists() || journal_path.exists() {
        anyhow::bail!(
            "proof-key rotation transaction paths already exist; refusing to overwrite protected state"
        );
    }
    let pending = PendingProofKeyRotation {
        payload: preview.payload.clone(),
    };
    let journal = serde_json::to_vec(&pending).context("serialize proof-key rotation journal")?;

    crate::util::atomic_write::atomic_write_private(&journal_path, &journal).with_context(
        || {
            format!(
                "write proof-key rotation journal {}",
                journal_path.display()
            )
        },
    )?;
    let prepare_result = (|| -> Result<()> {
        write_new_signing_key_securely(
            &preview.archive_path,
            &old_key,
            "retiring proof-key archive",
        )?;
        write_new_signing_key_securely(&staged_path, &new_key, "staged replacement proof key")?;
        let archived = load_existing_signing_key(&preview.archive_path)?;
        let staged = load_existing_signing_key(&staged_path)?;
        if pubkey_b64(&archived) != preview.payload.old_public_key
            || pubkey_b64(&staged) != preview.payload.new_public_key
        {
            anyhow::bail!("proof-key rotation archive/stage verification failed");
        }
        sync_parent_dir_required(key_path, "proof-key rotation files")?;
        Ok(())
    })();
    if let Err(error) = prepare_result {
        let _ = remove_if_present(&staged_path);
        let _ = remove_if_present(&preview.archive_path);
        let _ = remove_if_present(&journal_path);
        return Err(error);
    }

    Ok(PreparedProofKeyRotation {
        key_path: key_path.to_path_buf(),
        journal_path,
        staged_path,
        archive_path: preview.archive_path,
        new_key,
        payload: preview.payload,
        _lock: lock,
    })
}

/// Load the operator's ed25519 signing key, generating + persisting a fresh
/// one on first use. DAU-safe: zero interaction. Mirrors
/// [`crate::wal::compaction::load_or_init_key`] — fail-closed if the OS RNG is
/// unavailable (a weak signing key would make the proof signature worthless).
/// The on-disk form is the raw 32-byte seed (the public key is always derived
/// from it), DPAPI-wrapped on Windows via the shared secure-write path.
pub fn load_or_init_signing_key(path: &Path) -> Result<SigningKey> {
    let _lock =
        crate::util::locked_file::lock_file_blocking(&key_lock_path(path), "proof signing key")?;
    let _ = recover_pending_rotation_locked(path)?;
    if path.exists() {
        return load_existing_signing_key(path);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create signing key parent {}", parent.display()))?;
    }
    // 32-byte ed25519 seed via the OS CSPRNG. **Fail closed** when the OS RNG
    // is unavailable — a predictable signing key undermines the whole
    // attribution story (same contract as the HMAC key).
    let key = fresh_signing_key()?;
    let seed = Zeroizing::new(key.to_bytes());
    crate::wal::compaction::write_key_securely(path, seed.as_ref())?;
    // `seed` drops and zeroes the stack copy of the 32-byte secret here.
    Ok(key)
}

/// Base64 (standard) of the 32-byte ed25519 public key — what lands in the
/// envelope's `signer_pubkey` and what the operator shares with auditors.
pub fn pubkey_b64(key: &SigningKey) -> String {
    base64::engine::general_purpose::STANDARD.encode(key.verifying_key().to_bytes())
}

/// LOAD-ONLY trusted public key: read the operator's signing key if it already
/// exists and return its base64 public key, WITHOUT generating one. Used by
/// `neoth verify` to authenticate redaction/rotation frames against the
/// operator's OWN key — it must never mint a key as a side effect of verifying,
/// and `None` (no key on disk) correctly means "no signed authorisation can be
/// trusted" so the verifier fails closed. Returns `None` on a missing/unreadable
/// /malformed key rather than erroring — a bad trust root simply trusts nothing.
pub fn load_signing_pubkey_if_present(path: &Path) -> Option<String> {
    path.exists()
        .then(|| load_existing_signing_key(path).ok())
        .flatten()
        .map(|key| pubkey_b64(&key))
}

/// Sign `msg`, returning base64 (standard) of the 64-byte detached signature.
pub fn sign_b64(key: &SigningKey, msg: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(key.sign(msg).to_bytes())
}

/// Verify a base64 signature + base64 public key over `msg`. `Ok(())` iff the
/// signature is valid for that key over those exact bytes; a descriptive error
/// otherwise (malformed base64 / wrong key length / signature mismatch).
pub fn verify_b64(pubkey_b64: &str, sig_b64: &str, msg: &[u8]) -> Result<()> {
    let pk_bytes = base64::engine::general_purpose::STANDARD
        .decode(pubkey_b64.trim())
        .context("decode signer public key base64")?;
    let pk_arr: [u8; 32] = pk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("signer public key is not 32 bytes"))?;
    let vk = VerifyingKey::from_bytes(&pk_arr).context("invalid ed25519 public key")?;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(sig_b64.trim())
        .context("decode signature base64")?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("signature is not 64 bytes"))?;
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify(msg, &sig)
        .context("ed25519 signature does not match the claimed public key")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_rotation_segment(
        wal_dir: &Path,
        seq: u64,
        payload: &ProofKeyRotationPayload,
    ) -> PathBuf {
        use crate::wal::builder::HeaderBuilder;
        use crate::wal::events::{EVENT_TYPE_EXTENDED, ExtendedSubtype};
        use crate::wal::frame::encode_frame;
        use crate::wal::segment_header::SegmentHeader;

        std::fs::create_dir_all(wal_dir).unwrap();
        let path = wal_dir.join(format!("{seq:06}.wal"));
        let body = serde_json::to_vec(payload).unwrap();
        let header = HeaderBuilder::new(EVENT_TYPE_EXTENDED, &body)
            .event_subtype(ExtendedSubtype::ProofKeyRotated as u8)
            .build();
        let mut bytes = SegmentHeader::new(0, seq, 0, 0, [0u8; 16])
            .to_le_bytes()
            .to_vec();
        bytes.extend_from_slice(&encode_frame(&header, &body));
        std::fs::write(&path, bytes).unwrap();
        path
    }

    fn private_files(dir: &Path) -> BTreeSet<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn sign_verify_round_trip() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let msg = b"the proof bundle canonical bytes";
        let sig = sign_b64(&key, msg);
        let pk = pubkey_b64(&key);
        assert!(
            verify_b64(&pk, &sig, msg).is_ok(),
            "a freshly-signed message must verify against its own key",
        );
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let sig = sign_b64(&key, b"original bytes");
        let pk = pubkey_b64(&key);
        assert!(
            verify_b64(&pk, &sig, b"tampered bytes").is_err(),
            "a different message must fail verification",
        );
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let signer = SigningKey::from_bytes(&[1u8; 32]);
        let other = SigningKey::from_bytes(&[2u8; 32]);
        let msg = b"bytes";
        let sig = sign_b64(&signer, msg);
        // Verify the real signature against a DIFFERENT public key → reject.
        assert!(verify_b64(&pubkey_b64(&other), &sig, msg).is_err());
    }

    #[test]
    fn verify_rejects_malformed_base64() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let pk = pubkey_b64(&key);
        assert!(verify_b64(&pk, "!!!not base64!!!", b"x").is_err());
        assert!(verify_b64("!!!not base64!!!", &sign_b64(&key, b"x"), b"x").is_err());
        // Valid base64 but wrong length (16 bytes, not 32) → reject, no panic.
        let short = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        assert!(verify_b64(&short, &sign_b64(&key, b"x"), b"x").is_err());
    }

    #[test]
    fn load_or_init_generates_then_is_stable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wal").join("signing.key");
        assert!(!path.exists());
        let k1 = load_or_init_signing_key(&path).expect("first load generates");
        assert!(path.exists(), "key file is persisted on first use");
        let k2 = load_or_init_signing_key(&path).expect("second load reads existing");
        // Same key both times (the public key is deterministic from the seed).
        assert_eq!(
            k1.verifying_key().to_bytes(),
            k2.verifying_key().to_bytes(),
            "second load must return the SAME key, not regenerate",
        );
        // A signature from the reloaded key verifies against the first key's pub.
        let msg = b"persisted-key bytes";
        assert!(verify_b64(&pubkey_b64(&k1), &sign_b64(&k2, msg), msg).is_ok());
    }

    #[test]
    fn load_rejects_malformed_seed_length() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signing.key");
        // 16 bytes (not 32) on disk → load must refuse, not silently truncate.
        std::fs::write(&path, [0u8; 16]).unwrap();
        assert!(load_or_init_signing_key(&path).is_err());
    }

    #[test]
    fn rotation_payload_is_dual_signed_and_rejects_tampering() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("signing.key");
        let old = SigningKey::from_bytes(&[11u8; 32]);
        let new = SigningKey::from_bytes(&[12u8; 32]);
        let preview = build_rotation_preview(&key_path, &old, &new).unwrap();
        let payload = &preview.payload;

        payload.validate().expect("both key signatures are valid");
        let canonical = payload.canonical_bytes();
        verify_b64(&payload.old_public_key, &payload.old_signature, &canonical).unwrap();
        verify_b64(&payload.new_public_key, &payload.new_signature, &canonical).unwrap();

        let mut tampered = payload.clone();
        tampered.archive_file.push_str("-tampered");
        assert!(
            tampered.validate().is_err(),
            "changing any canonical transition field must invalidate both signatures"
        );

        let mut forged_new = payload.clone();
        forged_new.new_signature = sign_b64(&old, &forged_new.canonical_bytes());
        assert!(
            forged_new.validate().is_err(),
            "the retiring key cannot impersonate the replacement countersignature"
        );
    }

    #[test]
    fn rotation_dry_run_leaves_key_and_directory_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("signing.key");
        let old = load_or_init_signing_key(&key_path).unwrap();
        let key_bytes = std::fs::read(&key_path).unwrap();
        let files_before = private_files(dir.path());

        let preview = preview_signing_key_rotation(&key_path).unwrap();

        assert_eq!(preview.payload.old_public_key, pubkey_b64(&old));
        assert_ne!(
            preview.payload.new_public_key,
            preview.payload.old_public_key
        );
        preview.payload.validate().unwrap();
        assert!(!preview.archive_path.exists());
        assert_eq!(std::fs::read(&key_path).unwrap(), key_bytes);
        assert_eq!(private_files(dir.path()), files_before);
    }

    #[test]
    fn rotation_requires_an_existing_key() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("signing.key");

        let preview_error = preview_signing_key_rotation(&key_path)
            .err()
            .expect("missing key must reject preview");
        assert!(
            preview_error
                .to_string()
                .contains("no proof signing key exists")
        );
        let prepare_error = prepare_signing_key_rotation(&key_path)
            .err()
            .expect("missing key must reject prepare");
        assert!(
            prepare_error
                .to_string()
                .contains("no proof signing key exists")
        );
        assert!(
            !key_path.exists(),
            "rotation must never create its trust root"
        );
    }

    #[test]
    fn audited_rotation_commits_and_retains_verified_archive() {
        let dir = tempfile::tempdir().unwrap();
        let wal_dir = dir.path().join("wal");
        let key_path = wal_dir.join("signing.key");
        let old = load_or_init_signing_key(&key_path).unwrap();
        let old_public = pubkey_b64(&old);
        let prepared = prepare_signing_key_rotation(&key_path).unwrap();
        let payload = prepared.payload().clone();
        let archive_path = prepared.archive_path().to_path_buf();

        assert_eq!(
            pubkey_b64(&load_existing_signing_key(&key_path).unwrap()),
            old_public
        );
        assert_eq!(
            pubkey_b64(&load_existing_signing_key(&archive_path).unwrap()),
            old_public
        );
        write_rotation_segment(&wal_dir, 1, &payload);
        let committed = prepared.commit().unwrap();

        assert_eq!(committed.payload, payload);
        assert_eq!(
            pubkey_b64(&load_existing_signing_key(&key_path).unwrap()),
            payload.new_public_key
        );
        assert_eq!(
            pubkey_b64(&load_existing_signing_key(&archive_path).unwrap()),
            old_public,
            "the retiring secret remains available only in its protected archive"
        );
        assert!(!rotation_journal_path(&key_path).exists());
        assert!(
            private_files(&wal_dir)
                .iter()
                .all(|name| !name.ends_with(".next")),
            "the staged secret must be removed after commit"
        );
    }

    #[test]
    fn unaudited_rotation_aborts_without_changing_the_active_key() {
        let dir = tempfile::tempdir().unwrap();
        let wal_dir = dir.path().join("wal");
        let key_path = wal_dir.join("signing.key");
        let old = load_or_init_signing_key(&key_path).unwrap();
        let old_public = pubkey_b64(&old);
        let prepared = prepare_signing_key_rotation(&key_path).unwrap();
        let archive_path = prepared.archive_path().to_path_buf();

        prepared.abort().unwrap();

        assert_eq!(
            pubkey_b64(&load_existing_signing_key(&key_path).unwrap()),
            old_public
        );
        assert!(!archive_path.exists());
        assert!(!rotation_journal_path(&key_path).exists());
        assert!(
            private_files(&wal_dir)
                .iter()
                .all(|name| !name.ends_with(".next"))
        );
    }

    #[test]
    fn pending_rotation_recovers_according_to_durable_audit_state() {
        let dir = tempfile::tempdir().unwrap();
        let wal_dir = dir.path().join("wal");
        let key_path = wal_dir.join("signing.key");
        let old = load_or_init_signing_key(&key_path).unwrap();
        let old_public = pubkey_b64(&old);

        let unaudited = prepare_signing_key_rotation(&key_path).unwrap();
        let unaudited_archive = unaudited.archive_path().to_path_buf();
        drop(unaudited); // Simulate process death before the audit append.
        let recovered_old = load_or_init_signing_key(&key_path).unwrap();
        assert_eq!(pubkey_b64(&recovered_old), old_public);
        assert!(!unaudited_archive.exists());

        let audited = prepare_signing_key_rotation(&key_path).unwrap();
        let payload = audited.payload().clone();
        let archive = audited.archive_path().to_path_buf();
        write_rotation_segment(&wal_dir, 1, &payload);
        drop(audited); // Simulate process death after fsync, before commit.
        let recovered = recover_signing_key_rotation(&key_path)
            .unwrap()
            .expect("durable pending transition is completed, not repeated");
        assert_eq!(recovered.payload, payload);
        let recovered_new = load_or_init_signing_key(&key_path).unwrap();
        assert_eq!(pubkey_b64(&recovered_new), payload.new_public_key);
        assert!(
            archive.exists(),
            "a committed retiring-key archive is retained"
        );
        assert!(!rotation_journal_path(&key_path).exists());
    }

    #[test]
    fn current_key_builds_only_its_ordered_predecessor_trust_chain() {
        let dir = tempfile::tempdir().unwrap();
        let wal_dir = dir.path().join("wal");
        let key_path = wal_dir.join("signing.key");
        let oldest = load_or_init_signing_key(&key_path).unwrap();

        let first = prepare_signing_key_rotation(&key_path).unwrap();
        let first_payload = first.payload().clone();
        write_rotation_segment(&wal_dir, 1, &first_payload);
        first.commit().unwrap();

        let second = prepare_signing_key_rotation(&key_path).unwrap();
        let second_payload = second.payload().clone();
        write_rotation_segment(&wal_dir, 2, &second_payload);
        second.commit().unwrap();

        // A later, otherwise-valid branch from a retired key is not an
        // ancestor of the current local trust root and must grant no trust.
        let attacker = SigningKey::from_bytes(&[99u8; 32]);
        let branch = build_rotation_preview(&key_path, &oldest, &attacker).unwrap();
        write_rotation_segment(&wal_dir, 3, &branch.payload);

        let segments = sorted_wal_segments(&wal_dir);
        let trusted = trusted_signing_pubkeys(&segments, &key_path);
        assert_eq!(trusted.len(), 3);
        assert!(trusted.contains(&first_payload.old_public_key));
        assert!(trusted.contains(&first_payload.new_public_key));
        assert!(trusted.contains(&second_payload.new_public_key));
        assert!(!trusted.contains(&branch.payload.new_public_key));
    }
}
