//! Account-bound Telegram direct-message pairing.
//!
//! This store deliberately has no account-name entrypoint: callers must hold
//! the authenticated [`ChannelRef`] and the current opaque binding generation.
//! A row from an earlier token/policy/sender generation is therefore inert.

use std::{
    ffi::OsStr,
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result};
use cap_std::fs::{Dir, File};
use hmac::{Hmac, Mac};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use sha2::Sha256;

use crate::channels::registry::ChannelRef;

const DOMAIN: &[u8] = b"neoth-dm-pairing-v1\0";
const TTL_SECS: i64 = 60 * 60;
const MAX_PENDING: i64 = 3;
const CODE_LEN: usize = 8;
const CODE_RETRIES: usize = 8;
const CODE_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const PAIRING_NAMESPACE: &str = "channel-pairing";
const PAIRING_KEY: &str = "pairing.key";
const PAIRING_DATABASE: &str = "pairing.sqlite";
const SQLITE_SIDECARS: [&str; 3] = [
    "pairing.sqlite-wal",
    "pairing.sqlite-shm",
    "pairing.sqlite-journal",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Admission {
    PinnedAllowed,
    Approved,
    PairingCode {
        request_id: String,
        code: String,
        newly_created: bool,
    },
    Rejected,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PendingRequest {
    pub(crate) request_id: String,
    pub(crate) created_at: i64,
}

/// The only persistent state used by this feature.  The key is generated once
/// per NEOTH home and remains private; the plaintext pairing code is never a
/// database value, WAL payload, CLI result, or debug field.
#[derive(Clone)]
pub(crate) struct DmPairingStore {
    /// This directory capability is retained for every clone and every
    /// SQLite connection. `path` is only the physical spelling SQLite needs;
    /// it is bracketed by no-follow, handle-relative identity checks.
    namespace: Arc<Dir>,
    path: PathBuf,
    key: Arc<[u8; 32]>,
}

impl DmPairingStore {
    pub(crate) fn open(home: &Path) -> Result<Self> {
        let home_cap = crate::skills::store::open_bound_directory(home, true, "DM pairing home")?
            .context("bind DM pairing home directory")?;
        let namespace_path = home_cap.physical_display_path.join(PAIRING_NAMESPACE);
        let namespace = crate::skills::store::open_or_create_private_child_dir(
            &home_cap.dir,
            OsStr::new(PAIRING_NAMESPACE),
            &namespace_path,
        )
        .context("open private DM pairing namespace")?;
        #[cfg(windows)]
        crate::wal::win_native::set_private_current_user_directory_dacl_bound(
            &namespace_path,
            &namespace,
        )
        .context("set private DM pairing namespace DACL")?;
        ensure_private_directory(&namespace).context("verify private DM pairing namespace")?;
        let namespace = Arc::new(namespace);
        let key = load_or_create_key(&namespace, &namespace_path.join(PAIRING_KEY))?;
        let store = Self {
            namespace,
            path: namespace_path.join(PAIRING_DATABASE),
            key: Arc::new(key),
        };
        store.with_connection(initialise)?;
        Ok(store)
    }

    pub(crate) fn check_or_create(
        &self,
        reference: &ChannelRef,
        binding_tag: &str,
        pinned_operator: u64,
        sender: u64,
        now: i64,
    ) -> Result<Admission> {
        if sender == 0 || binding_tag.is_empty() {
            return Ok(Admission::Rejected);
        }
        if sender == pinned_operator {
            return Ok(Admission::PinnedAllowed);
        }
        self.with_connection(|conn| {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            expire(&tx, reference, binding_tag, now)?;
            if is_approved(&tx, reference, binding_tag, sender)? { tx.commit()?; return Ok(Admission::Approved); }
            if let Some(request_id) = tx.query_row(
                "SELECT request_id FROM pending WHERE channel_id=?1 AND account_id=?2 AND binding_tag=?3 AND sender_id=?4",
                params![reference.channel_id.as_str(), reference.account_id.as_str(), binding_tag, sender as i64], |r| r.get(0)
            ).optional()? { tx.execute("UPDATE pending SET last_seen_at=?5 WHERE channel_id=?1 AND account_id=?2 AND binding_tag=?3 AND sender_id=?4", params![reference.channel_id.as_str(), reference.account_id.as_str(), binding_tag, sender as i64, now])?; tx.commit()?; return Ok(Admission::PairingCode { request_id, code: String::new(), newly_created: false }); }
            let count: i64 = tx.query_row("SELECT COUNT(*) FROM pending WHERE channel_id=?1 AND account_id=?2 AND binding_tag=?3", params![reference.channel_id.as_str(), reference.account_id.as_str(), binding_tag], |r| r.get(0))?;
            if count >= MAX_PENDING { tx.commit()?; return Ok(Admission::Rejected); }
            for _ in 0..CODE_RETRIES {
                let code = random_code()?;
                let commitment = commitment(&self.key, reference, binding_tag, &code);
                let request_id = random_request_id()?;
                match tx.execute("INSERT INTO pending(channel_id,account_id,binding_tag,sender_id,request_id,code_commitment,created_at,last_seen_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?7)", params![reference.channel_id.as_str(), reference.account_id.as_str(), binding_tag, sender as i64, request_id, commitment.as_slice(), now]) {
                    Ok(_) => { tx.commit()?; return Ok(Admission::PairingCode { request_id, code, newly_created: true }); }
                    Err(rusqlite::Error::SqliteFailure(e, _)) if e.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE => continue,
                    Err(e) => return Err(e.into()),
                }
            }
            tx.commit()?;
            Ok(Admission::Rejected)
        })
    }

    pub(crate) fn list(
        &self,
        reference: &ChannelRef,
        binding_tag: &str,
        now: i64,
    ) -> Result<Vec<PendingRequest>> {
        self.with_connection(|conn| { let tx=conn.transaction_with_behavior(TransactionBehavior::Immediate)?; expire(&tx, reference,binding_tag,now)?; let mut stmt=tx.prepare("SELECT request_id, created_at FROM pending WHERE channel_id=?1 AND account_id=?2 AND binding_tag=?3 ORDER BY created_at")?; let rows=stmt.query_map(params![reference.channel_id.as_str(),reference.account_id.as_str(),binding_tag],|r| Ok(PendingRequest{request_id:r.get(0)?,created_at:r.get(1)?}))?.collect::<rusqlite::Result<Vec<_>>>()?; drop(stmt); tx.commit()?; Ok(rows) })
    }

    /// Read-only admission for edits. This never expires, creates, refreshes,
    /// or returns a code, so an edit cannot become a pairing side channel.
    pub(crate) fn is_approved(
        &self,
        reference: &ChannelRef,
        binding_tag: &str,
        sender: u64,
    ) -> Result<bool> {
        if sender == 0 || binding_tag.is_empty() {
            return Ok(false);
        }
        self.with_connection(|conn| {
            Ok(conn.query_row("SELECT 1 FROM approved WHERE channel_id=?1 AND account_id=?2 AND binding_tag=?3 AND sender_id=?4", params![reference.channel_id.as_str(), reference.account_id.as_str(), binding_tag, sender as i64], |_| Ok(())).optional()?.is_some())
        })
    }

    /// Consume exactly one current-generation request.  The unique commitment
    /// constraint makes a plaintext code unambiguous inside this namespace.
    pub(crate) fn approve(
        &self,
        reference: &ChannelRef,
        binding_tag: &str,
        code: &str,
        now: i64,
    ) -> Result<PendingRequest> {
        self.approve_inner(reference, binding_tag, None, code, now)
    }

    /// Consume exactly the caller-selected current request. The expected id
    /// and code commitment are matched in one immediate transaction before
    /// the pending row is deleted or its sender becomes approved.
    pub(crate) fn approve_expected(
        &self,
        reference: &ChannelRef,
        binding_tag: &str,
        expected_request_id: &str,
        code: &str,
        now: i64,
    ) -> Result<PendingRequest> {
        validate_request_id(expected_request_id)?;
        self.approve_inner(reference, binding_tag, Some(expected_request_id), code, now)
    }

    fn approve_inner(
        &self,
        reference: &ChannelRef,
        binding_tag: &str,
        expected_request_id: Option<&str>,
        code: &str,
        now: i64,
    ) -> Result<PendingRequest> {
        validate_code(code)?;
        let digest = commitment(&self.key, reference, binding_tag, code);
        self.with_connection(|conn| {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            expire(&tx, reference, binding_tag, now)?;
            let row = match expected_request_id {
                Some(expected_request_id) => tx
                    .query_row(
                        "SELECT request_id,sender_id,created_at FROM pending WHERE channel_id=?1 AND account_id=?2 AND binding_tag=?3 AND request_id=?4 AND code_commitment=?5",
                        params![reference.channel_id.as_str(), reference.account_id.as_str(), binding_tag, expected_request_id, digest.as_slice()],
                        |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?)),
                    )
                    .optional()?,
                None => tx
                    .query_row(
                        "SELECT request_id,sender_id,created_at FROM pending WHERE channel_id=?1 AND account_id=?2 AND binding_tag=?3 AND code_commitment=?4",
                        params![reference.channel_id.as_str(), reference.account_id.as_str(), binding_tag, digest.as_slice()],
                        |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?)),
                    )
                    .optional()?,
            };
            let Some((request_id, sender_id, created_at)) = row else {
                anyhow::bail!("no current pairing request matches that approval");
            };
            let deleted = tx.execute(
                "DELETE FROM pending WHERE channel_id=?1 AND account_id=?2 AND binding_tag=?3 AND request_id=?4 AND code_commitment=?5",
                params![reference.channel_id.as_str(), reference.account_id.as_str(), binding_tag, request_id, digest.as_slice()],
            )?;
            anyhow::ensure!(deleted == 1, "pairing approval lost its exact pending row");
            tx.execute(
                "INSERT INTO approved(channel_id,account_id,binding_tag,sender_id,approved_at) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(channel_id,account_id,binding_tag,sender_id) DO NOTHING",
                params![reference.channel_id.as_str(), reference.account_id.as_str(), binding_tag, sender_id, now],
            )?;
            tx.commit()?;
            Ok(PendingRequest { request_id, created_at })
        })
    }

    pub(crate) fn dismiss(
        &self,
        reference: &ChannelRef,
        binding_tag: &str,
        request_id: &str,
        now: i64,
    ) -> Result<bool> {
        if request_id.is_empty() {
            return Ok(false);
        };
        self.with_connection(|conn| {let tx=conn.transaction_with_behavior(TransactionBehavior::Immediate)?;expire(&tx,reference,binding_tag,now)?;let n=tx.execute("DELETE FROM pending WHERE channel_id=?1 AND account_id=?2 AND binding_tag=?3 AND request_id=?4",params![reference.channel_id.as_str(),reference.account_id.as_str(),binding_tag,request_id])?;tx.commit()?;Ok(n==1)})
    }

    #[cfg(test)]
    pub(crate) fn pending_last_seen_for_test(
        &self,
        reference: &ChannelRef,
        binding_tag: &str,
        sender: u64,
    ) -> Result<Option<i64>> {
        self.with_connection(|conn| {
            Ok(conn
                .query_row(
                    "SELECT last_seen_at FROM pending WHERE channel_id=?1 AND account_id=?2 AND binding_tag=?3 AND sender_id=?4",
                    params![reference.channel_id.as_str(), reference.account_id.as_str(), binding_tag, sender as i64],
                    |row| row.get(0),
                )
                .optional()?)
        })
    }

    fn with_connection<T>(&self, f: impl FnOnce(&mut Connection) -> Result<T>) -> Result<T> {
        // rusqlite only accepts a path, so hold the parent capability and bind
        // the exact direct child before *and* after its one ambient open.
        // There is no fallback that trusts the path alone.
        let database = prepare_private_database(&self.namespace, &self.path)?;
        prepare_existing_sidecars(&self.namespace, &self.path)?;
        let mut c = Connection::open_with_flags(
            &self.path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .with_context(|| {
            format!(
                "open capability-bound pairing database {}",
                self.path.display()
            )
        })?;
        ensure_bound_file(&database, &self.namespace, PAIRING_DATABASE, &self.path)?;
        harden_and_verify_sidecars(&self.namespace, &self.path)?;
        c.pragma_update(None, "foreign_keys", "ON")?;
        f(&mut c)
    }
}

fn initialise(conn: &mut Connection) -> Result<()> {
    conn.execute_batch("BEGIN IMMEDIATE; CREATE TABLE IF NOT EXISTS schema_meta(version INTEGER NOT NULL); INSERT INTO schema_meta(version) SELECT 1 WHERE NOT EXISTS(SELECT 1 FROM schema_meta); CREATE TABLE IF NOT EXISTS pending(channel_id TEXT NOT NULL,account_id TEXT NOT NULL,binding_tag TEXT NOT NULL,sender_id INTEGER NOT NULL CHECK(sender_id>0),request_id TEXT NOT NULL,code_commitment BLOB NOT NULL,created_at INTEGER NOT NULL,last_seen_at INTEGER NOT NULL,PRIMARY KEY(channel_id,account_id,binding_tag,sender_id),UNIQUE(channel_id,account_id,binding_tag,request_id),UNIQUE(channel_id,account_id,binding_tag,code_commitment)); CREATE TABLE IF NOT EXISTS approved(channel_id TEXT NOT NULL,account_id TEXT NOT NULL,binding_tag TEXT NOT NULL,sender_id INTEGER NOT NULL CHECK(sender_id>0),approved_at INTEGER NOT NULL,PRIMARY KEY(channel_id,account_id,binding_tag,sender_id)); COMMIT;")?;
    Ok(())
}
fn expire(tx: &rusqlite::Transaction<'_>, r: &ChannelRef, b: &str, now: i64) -> Result<()> {
    tx.execute("DELETE FROM pending WHERE channel_id=?1 AND account_id=?2 AND binding_tag=?3 AND created_at < ?4",params![r.channel_id.as_str(),r.account_id.as_str(),b,now-TTL_SECS])?;
    Ok(())
}
fn is_approved(tx: &rusqlite::Transaction<'_>, r: &ChannelRef, b: &str, s: u64) -> Result<bool> {
    Ok(tx.query_row("SELECT 1 FROM approved WHERE channel_id=?1 AND account_id=?2 AND binding_tag=?3 AND sender_id=?4",params![r.channel_id.as_str(),r.account_id.as_str(),b,s as i64],|_|Ok(())).optional()?.is_some())
}
fn commitment(key: &[u8; 32], r: &ChannelRef, b: &str, code: &str) -> [u8; 32] {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("fixed HMAC key");
    for part in [
        DOMAIN,
        r.channel_id.as_str().as_bytes(),
        b"\0",
        r.account_id.as_str().as_bytes(),
        b"\0",
        b.as_bytes(),
        b"\0",
        code.as_bytes(),
    ] {
        m.update(part)
    }
    m.finalize().into_bytes().into()
}
fn random_code() -> Result<String> {
    let mut out = [0u8; CODE_LEN];
    getrandom::getrandom(&mut out).context("OS RNG for pairing code")?;
    Ok(out
        .iter()
        .map(|b| CODE_ALPHABET[(*b as usize) % CODE_ALPHABET.len()] as char)
        .collect())
}
fn random_request_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).context("OS RNG for pairing request")?;
    Ok(hex::encode(bytes))
}
pub(crate) fn validate_code(code: &str) -> Result<()> {
    anyhow::ensure!(
        code.len() == CODE_LEN && code.bytes().all(|b| CODE_ALPHABET.contains(&b)),
        "pairing code is malformed"
    );
    Ok(())
}

pub(crate) fn validate_request_id(request_id: &str) -> Result<()> {
    anyhow::ensure!(
        request_id.len() == 32
            && request_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "pairing request id is malformed"
    );
    Ok(())
}
fn load_or_create_key(namespace: &Dir, path: &Path) -> Result<[u8; 32]> {
    let name = OsStr::new(PAIRING_KEY);
    match namespace.symlink_metadata(name) {
        Ok(_) => {
            let (mut file, binding) =
                crate::skills::store::open_bound_regular_file(namespace, name, path)?;
            verify_private_file(&file)?;
            ensure_bound_file(&binding, namespace, PAIRING_KEY, path)?;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)?;
            anyhow::ensure!(bytes.len() == 32, "pairing key has invalid length");
            let mut key = [0; 32];
            key.copy_from_slice(&bytes);
            Ok(key)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut key = [0; 32];
            getrandom::getrandom(&mut key).context("OS RNG for pairing key")?;
            let (mut file, binding) =
                crate::skills::store::create_private_regular_file_child_create_new(
                    namespace, name, path,
                )?;
            file.write_all(&key)?;
            file.sync_all()?;
            verify_private_file(&file)?;
            ensure_bound_file(&binding, namespace, PAIRING_KEY, path)?;
            Ok(key)
        }
        Err(e) => Err(e).with_context(|| format!("inspect pairing key {}", path.display())),
    }
}

fn prepare_private_database(
    namespace: &Dir,
    path: &Path,
) -> Result<crate::skills::store::BoundChildObject> {
    let name = OsStr::new(PAIRING_DATABASE);
    match namespace.symlink_metadata(name) {
        Ok(_) => {
            let (file, binding) =
                crate::skills::store::open_bound_regular_file(namespace, name, path)?;
            verify_private_file(&file)?;
            ensure_bound_file(&binding, namespace, PAIRING_DATABASE, path)?;
            Ok(binding)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            for sidecar in SQLITE_SIDECARS {
                match namespace.symlink_metadata(OsStr::new(sidecar)) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Ok(_) => anyhow::bail!(
                        "fresh pairing database has a preexisting SQLite sidecar {sidecar}"
                    ),
                    Err(error) => return Err(error.into()),
                }
            }
            let (file, creation_binding) =
                crate::skills::store::create_private_regular_file_child_create_new(
                    namespace, name, path,
                )?;
            verify_private_file(&file)?;
            ensure_bound_file(&creation_binding, namespace, PAIRING_DATABASE, path)?;
            // The private-create handle holds DELETE access. SQLite's Windows
            // VFS opens its database handle without DELETE sharing, so retain
            // an exact read/write identity binding instead before SQLite runs.
            // The second no-follow open shares DELETE with the creation handle;
            // comparing both identities closes that hand-off before the
            // DELETE-capable handles are dropped.
            let (witness, binding) =
                crate::skills::store::open_bound_regular_file_readwrite(namespace, name, path)?;
            verify_private_file(&witness)?;
            anyhow::ensure!(
                binding.identity_token() == creation_binding.identity_token(),
                "fresh pairing database changed while replacing creation binding"
            );
            drop((file, creation_binding));
            ensure_bound_file(&binding, namespace, PAIRING_DATABASE, path)?;
            Ok(binding)
        }
        Err(e) => Err(e).with_context(|| format!("inspect pairing database {}", path.display())),
    }
}

fn prepare_existing_sidecars(namespace: &Dir, path: &Path) -> Result<()> {
    harden_and_verify_sidecars(namespace, path)
}
fn harden_and_verify_sidecars(namespace: &Dir, path: &Path) -> Result<()> {
    for sidecar in SQLITE_SIDECARS {
        let sidecar_path = path.with_file_name(sidecar);
        match namespace.symlink_metadata(OsStr::new(sidecar)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(e).with_context(|| {
                    format!("inspect pairing SQLite sidecar {}", sidecar_path.display())
                });
            }
            Ok(_) => {}
        };
        let (file, binding) = crate::skills::store::open_bound_regular_file_readwrite(
            namespace,
            OsStr::new(sidecar),
            &sidecar_path,
        )?;
        harden_private_file(&file)?;
        verify_private_file(&file)?;
        ensure_bound_file(&binding, namespace, sidecar, &sidecar_path)?;
    }
    Ok(())
}

fn ensure_bound_file(
    binding: &crate::skills::store::BoundChildObject,
    namespace: &Dir,
    name: &str,
    path: &Path,
) -> Result<()> {
    anyhow::ensure!(
        binding.matches_regular_file_child_readonly(namespace, OsStr::new(name), path)?,
        "private pairing object changed while bound: {}",
        path.display()
    );
    Ok(())
}
fn ensure_private_directory(directory: &Dir) -> Result<()> {
    let metadata = directory
        .dir_metadata()
        .context("inspect private pairing directory capability")?;
    anyhow::ensure!(metadata.is_dir(), "DM pairing namespace is not a directory");
    #[cfg(unix)]
    {
        use cap_std::fs::{MetadataExt as _, PermissionsExt as _};
        anyhow::ensure!(
            metadata.uid() == unsafe { libc::geteuid() },
            "DM pairing namespace owner mismatch"
        );
        anyhow::ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "DM pairing namespace is not owner-private"
        );
    }
    #[cfg(windows)]
    {
        crate::wal::win_native::verify_private_directory_handle_dacl(directory)
            .context("verify private DM pairing directory owner and DACL")?;
    }
    Ok(())
}
fn harden_private_file(file: &File) -> Result<()> {
    #[cfg(unix)]
    {
        use cap_std::fs::{Permissions, PermissionsExt as _};
        file.set_permissions(Permissions::from_mode(0o600))
            .context("set private pairing SQLite sidecar mode")?;
    }
    #[cfg(windows)]
    {
        crate::wal::win_native::set_private_current_user_file_handle_dacl(file)
            .context("set private pairing SQLite sidecar DACL")?;
    }
    Ok(())
}
fn verify_private_file(file: &File) -> Result<()> {
    let metadata = file
        .metadata()
        .context("inspect private pairing file capability")?;
    anyhow::ensure!(
        metadata.is_file(),
        "DM pairing object is not a regular file"
    );
    #[cfg(unix)]
    {
        use cap_std::fs::{MetadataExt as _, PermissionsExt as _};
        anyhow::ensure!(
            metadata.uid() == unsafe { libc::geteuid() },
            "DM pairing file owner mismatch"
        );
        anyhow::ensure!(metadata.nlink() == 1, "DM pairing file has hard links");
        anyhow::ensure!(
            metadata.permissions().mode() & 0o077 == 0
                && metadata.permissions().mode() & 0o600 == 0o600,
            "DM pairing file is not owner-private"
        );
    }
    #[cfg(windows)]
    {
        let std_file = file
            .try_clone()
            .context("clone private pairing file capability for DACL verification")?
            .into_std();
        crate::wal::win_native::verify_private_file_handle(&std_file)
            .context("verify private pairing file owner and DACL")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channels::registry::{ChannelAccountId, ChannelId};

    fn reference(account: &str) -> ChannelRef {
        ChannelRef::new(ChannelId::Telegram, ChannelAccountId::new(account).unwrap())
    }
    fn new_code(
        store: &DmPairingStore,
        r: &ChannelRef,
        binding: &str,
        sender: u64,
        now: i64,
    ) -> String {
        match store.check_or_create(r, binding, 99, sender, now).unwrap() {
            Admission::PairingCode {
                code,
                newly_created: true,
                ..
            } => code,
            other => panic!("expected new code, got {other:?}"),
        }
    }

    #[test]
    fn exact_ref_and_generation_isolate_approval_and_expiry_cap() {
        let home = tempfile::tempdir().unwrap();
        let store = DmPairingStore::open(home.path()).unwrap();
        let a = reference("a");
        let b = reference("b");
        let code = new_code(&store, &a, "gen-a", 1, 100);
        assert!(store.approve(&a, "gen-a", &code, 101).is_ok());
        assert!(matches!(
            store.check_or_create(&b, "gen-b", 99, 1, 101).unwrap(),
            Admission::PairingCode {
                newly_created: true,
                ..
            }
        ));
        assert!(matches!(
            store
                .check_or_create(&a, "gen-rotated", 99, 1, 101)
                .unwrap(),
            Admission::PairingCode {
                newly_created: true,
                ..
            }
        ));
        for sender in 2..=4 {
            let _ = new_code(&store, &a, "cap", sender, 100);
        }
        assert!(matches!(
            store.check_or_create(&a, "cap", 99, 5, 100).unwrap(),
            Admission::Rejected
        ));
        assert!(matches!(
            store
                .check_or_create(&a, "cap", 99, 5, 100 + TTL_SECS + 1)
                .unwrap(),
            Admission::PairingCode {
                newly_created: true,
                ..
            }
        ));
    }

    #[test]
    fn duplicate_sender_reuses_request_without_revealing_or_persisting_code() {
        let home = tempfile::tempdir().unwrap();
        let store = DmPairingStore::open(home.path()).unwrap();
        let r = reference("a");
        let code = new_code(&store, &r, "g", 7, 100);
        assert!(
            matches!(store.check_or_create(&r,"g",99,7,101).unwrap(),Admission::PairingCode{newly_created:false,code:ref repeated,..} if repeated.is_empty())
        );
        let raw =
            std::fs::read(home.path().join(PAIRING_NAMESPACE).join(PAIRING_DATABASE)).unwrap();
        assert!(
            !raw.windows(code.len())
                .any(|window| window == code.as_bytes())
        );
    }

    #[test]
    fn unique_commitment_rejects_forced_same_code_second_sender_and_concurrent_approve_has_one_winner()
     {
        let home = tempfile::tempdir().unwrap();
        let store = DmPairingStore::open(home.path()).unwrap();
        let r = reference("a");
        let code = new_code(&store, &r, "g", 7, 100);
        let digest = commitment(&store.key, &r, "g", &code);
        let forced=store.with_connection(|conn| conn.execute("INSERT INTO pending(channel_id,account_id,binding_tag,sender_id,request_id,code_commitment,created_at,last_seen_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?7)",params![r.channel_id.as_str(),r.account_id.as_str(),"g",8_i64,"forced",digest.as_slice(),100_i64]).map(|_|()).map_err(Into::into));
        assert!(
            forced.is_err(),
            "same code commitment may not name a second sender in one generation"
        );
        let left = store.clone();
        let right = store.clone();
        let ra = r.clone();
        let rb = r.clone();
        let ca = code.clone();
        let cb = code.clone();
        let one = std::thread::spawn(move || left.approve(&ra, "g", &ca, 101).is_ok());
        let two = std::thread::spawn(move || right.approve(&rb, "g", &cb, 101).is_ok());
        assert_eq!(
            u8::from(one.join().unwrap()) + u8::from(two.join().unwrap()),
            1,
            "exactly one concurrent approval may consume the pending row"
        );
    }

    #[test]
    fn expected_approval_requires_the_selected_current_request_and_code_together() {
        let home = tempfile::tempdir().unwrap();
        let store = DmPairingStore::open(home.path()).unwrap();
        let reference = reference("ops_b");
        let first_code = new_code(&store, &reference, "generation", 7, 100);
        let second_code = new_code(&store, &reference, "generation", 8, 101);
        let pending = store.list(&reference, "generation", 102).unwrap();
        assert_eq!(pending.len(), 2);
        let first_id = pending[0].request_id.clone();
        let second_id = pending[1].request_id.clone();

        let wrong_pair = store
            .approve_expected(&reference, "generation", &first_id, &second_code, 103)
            .unwrap_err();
        assert!(
            wrong_pair
                .to_string()
                .contains("no current pairing request")
        );
        assert_eq!(
            store.list(&reference, "generation", 103).unwrap().len(),
            2,
            "a valid code for another pending request must consume neither row"
        );
        assert!(!store.is_approved(&reference, "generation", 7).unwrap());
        assert!(!store.is_approved(&reference, "generation", 8).unwrap());

        assert!(
            store
                .approve_expected(&reference, "stale-generation", &first_id, &first_code, 104)
                .is_err()
        );
        let approved = store
            .approve_expected(&reference, "generation", &first_id, &first_code, 105)
            .unwrap();
        assert_eq!(approved.request_id, first_id);
        assert!(store.is_approved(&reference, "generation", 7).unwrap());
        assert!(
            store
                .approve_expected(&reference, "generation", &first_id, &first_code, 106)
                .is_err()
        );
        assert_eq!(
            store.list(&reference, "generation", 106).unwrap(),
            vec![PendingRequest {
                request_id: second_id.clone(),
                created_at: 101,
            }]
        );

        assert!(
            store
                .approve_expected(
                    &reference,
                    "generation",
                    &second_id,
                    &second_code,
                    101 + TTL_SECS + 1,
                )
                .is_err()
        );
        assert!(
            store
                .list(&reference, "generation", 101 + TTL_SECS + 1)
                .unwrap()
                .is_empty()
        );
    }

    #[cfg(unix)]
    #[test]
    fn fresh_database_refuses_a_preexisting_sqlite_sidecar() {
        use std::os::unix::fs::PermissionsExt as _;

        let home = tempfile::tempdir().unwrap();
        let namespace = home.path().join(PAIRING_NAMESPACE);
        std::fs::create_dir(&namespace).unwrap();
        std::fs::set_permissions(&namespace, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(namespace.join("pairing.sqlite-wal"), b"orphaned").unwrap();
        std::fs::set_permissions(
            namespace.join("pairing.sqlite-wal"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(DmPairingStore::open(home.path()).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn fresh_namespace_has_a_private_current_user_dacl() {
        let home = tempfile::tempdir().unwrap();
        let _store = DmPairingStore::open(home.path()).unwrap();
        crate::wal::win_native::verify_private_directory_dacl(&home.path().join(PAIRING_NAMESPACE))
            .unwrap();
    }
}
