//! Private, best-effort account runtime projection. It is never authority.
//!
//! Binding tags are secret-derived equality metadata. They are intentionally
//! opaque here and must never be rendered, logged, or accepted as credentials.

use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::Read as _,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    channels::registry::ChannelRef,
    config::{AuthenticatedSlackAccount, AuthenticatedTelegramAccount},
};

use super::audit_rpc::{DaemonInstanceProof, InstanceCommitment, authenticated_live_instance};

pub const CHANNEL_RUNTIME_HEALTH_FILE: &str = "channel_runtime_health.v1.json";
const SCHEMA_VERSION: u32 = 1;
const MAX_BYTES: u64 = 64 * 1024;
const MAX_AGE: Duration = Duration::from_secs(3);
const BINDING_TAG_DOMAIN: &[u8] = b"neoth/channel-runtime-health-binding/v1";
const SLACK_BINDING_TAG_DOMAIN: &[u8] = b"neoth/channel-runtime-health-slack-binding/v1";

fn update_framed_slack_field(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

/// Private opaque equality metadata. It does not implement Debug, Display, or
/// serde so a caller cannot accidentally include it in operator output.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct BindingTag(String);

impl BindingTag {
    /// Hash the exact validated account bundle. Token bytes remain borrowed;
    /// this makes no raw-token copy or separately assembled credential tuple.
    pub(crate) fn from_authenticated_telegram_account(
        account: &AuthenticatedTelegramAccount,
    ) -> Self {
        Self::from_parts_with_binding(
            account.channel_ref(),
            account.account_binding().as_ref(),
            account.allowed_user_id(),
            account.is_legacy_singleton(),
            account.token().expose_secret().as_bytes(),
            account.inbound_admission(),
        )
    }

    /// Hash one validated Slack account without exposing either capability
    /// secret. The Slack-specific domain separates this equality tag from an
    /// otherwise coincident Telegram account tuple.
    pub(crate) fn from_authenticated_slack_account(account: &AuthenticatedSlackAccount) -> Self {
        let mut digest = Sha256::new();
        digest.update(SLACK_BINDING_TAG_DOMAIN);
        update_framed_slack_field(
            &mut digest,
            serde_json::to_vec(account.channel_ref())
                .expect("validated ChannelRef serialization is infallible")
                .as_slice(),
        );
        match account.account_binding().as_ref() {
            None => digest.update(b"/legacy-singleton"),
            Some(binding) => {
                digest.update(b"/mapped-account/incarnation/");
                update_framed_slack_field(
                    &mut digest,
                    binding
                        .incarnation()
                        .map_or(&b"none"[..], |value| value.as_str().as_bytes()),
                );
            }
        }
        update_framed_slack_field(&mut digest, account.allowed_user_id().as_bytes());
        digest.update([u8::from(account.is_legacy_singleton())]);
        update_framed_slack_field(&mut digest, account.bot_token().expose_secret().as_bytes());
        update_framed_slack_field(&mut digest, account.app_token().expose_secret().as_bytes());
        Self(hex::encode(digest.finalize()))
    }

    fn from_parts_with_binding(
        channel: &ChannelRef,
        account_binding: Option<&crate::config::ChannelAccountBinding>,
        allowed_user_id: u64,
        legacy: bool,
        token: &[u8],
        admission: &crate::config::TelegramInboundAdmission,
    ) -> Self {
        let mut digest = Sha256::new();
        digest.update(BINDING_TAG_DOMAIN);
        digest.update(
            serde_json::to_vec(channel).expect("validated ChannelRef serialization is infallible"),
        );
        match account_binding {
            None => digest.update(b"/legacy-singleton"),
            Some(binding) => {
                digest.update(b"/mapped-account/incarnation/");
                digest.update(
                    binding
                        .incarnation()
                        .map_or(&b"none"[..], |value| value.as_str().as_bytes()),
                );
            }
        }
        digest.update(allowed_user_id.to_be_bytes());
        digest.update([u8::from(legacy)]);
        digest.update(token);
        match admission {
            crate::config::TelegramInboundAdmission::PinnedOperator { .. } => digest.update([0]),
            crate::config::TelegramInboundAdmission::DmPairing { binding_tag, .. } => {
                digest.update([1]);
                digest.update(binding_tag.as_bytes());
            }
        }
        Self(hex::encode(digest.finalize()))
    }

    fn valid(&self) -> bool {
        fixed_lower_hex(&self.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AccountRuntimeState {
    Running,
    ConfiguredNotStarted,
    Failed,
    Inactive,
    CredentialsInvalid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProjectionLifecycle {
    Serving,
    Stopping,
    Stopped,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountRow {
    channel_ref: ChannelRef,
    state: AccountRuntimeState,
    binding_tag: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema_version: u32,
    instance_home: PathBuf,
    daemon_pid: u32,
    instance_commitment: String,
    observed_unix_millis: u64,
    lifecycle: ProjectionLifecycle,
    accounts: Vec<AccountRow>,
}

/// One process-local snapshot lock is held through every private atomic
/// publication, including through writer clones, preventing out-of-order
/// same-process replacements.
#[derive(Clone)]
pub(crate) struct ChannelRuntimeHealthWriter {
    path: PathBuf,
    snapshot: Arc<Mutex<Snapshot>>,
}

impl ChannelRuntimeHealthWriter {
    pub(crate) fn new(
        home: &Path,
        daemon_pid: u32,
        instance_commitment: InstanceCommitment,
    ) -> Result<Self> {
        ensure!(
            fixed_lower_hex(&instance_commitment.0),
            "runtime-health instance commitment has an invalid shape"
        );
        Ok(Self {
            path: home.join(CHANNEL_RUNTIME_HEALTH_FILE),
            snapshot: Arc::new(Mutex::new(Snapshot {
                schema_version: SCHEMA_VERSION,
                instance_home: home.to_path_buf(),
                daemon_pid,
                instance_commitment: instance_commitment.0,
                observed_unix_millis: now_unix_millis(),
                lifecycle: ProjectionLifecycle::Stopped,
                accounts: Vec::new(),
            })),
        })
    }

    /// Replace the projection with a coherent current binding set. BTreeMap
    /// gives the required canonical `ChannelRef` array order on disk.
    pub(crate) fn publish(
        &self,
        lifecycle: ProjectionLifecycle,
        accounts: BTreeMap<ChannelRef, (AccountRuntimeState, BindingTag)>,
    ) -> Result<()> {
        let mut snapshot = self
            .snapshot
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        snapshot.lifecycle = lifecycle;
        snapshot.observed_unix_millis = now_unix_millis();
        snapshot.accounts = accounts
            .into_iter()
            .map(|(channel_ref, (state, binding_tag))| {
                ensure!(
                    binding_tag.valid(),
                    "runtime-health binding tag has an invalid shape"
                );
                Ok(AccountRow {
                    channel_ref,
                    state,
                    binding_tag: binding_tag.0,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let body = serde_json::to_vec(&*snapshot).context("serialize runtime-health projection")?;
        ensure!(
            body.len() as u64 <= MAX_BYTES,
            "runtime-health projection exceeds {MAX_BYTES} bytes"
        );
        crate::util::atomic_write::atomic_write_private(&self.path, &body).with_context(|| {
            format!(
                "atomically publish runtime-health projection at {}",
                self.path.display()
            )
        })
    }
}

/// Read a current live projection. The audit-RPC proof remains the exact
/// synchronous PID-lock/nonce/same-user-health proof; no weaker PID/socket
/// probe is introduced here.
pub(crate) fn read_active(
    home: &Path,
    current_tags: &BTreeMap<ChannelRef, BindingTag>,
) -> Option<BTreeMap<ChannelRef, AccountRuntimeState>> {
    let snapshot = match read_snapshot(home) {
        Ok(Some(snapshot)) => snapshot,
        Ok(None) | Err(_) => return None,
    };
    let now = now_unix_millis();
    if !snapshot_is_current_claim(home, now, &snapshot) {
        return None;
    }
    let proof = match authenticated_live_instance(home) {
        Ok(proof) => proof,
        Err(_) => return None,
    };
    read_active_with_live_proof(home, current_tags, now, Some(&proof), snapshot)
}

/// Kept private as a deterministic proof-injection seam. Production always
/// enters through `read_active`, which obtains this proof from audit-RPC.
fn read_active_with_live_proof(
    home: &Path,
    current_tags: &BTreeMap<ChannelRef, BindingTag>,
    now: u64,
    proof: Option<&DaemonInstanceProof>,
    snapshot: Snapshot,
) -> Option<BTreeMap<ChannelRef, AccountRuntimeState>> {
    if !snapshot_is_current_claim(home, now, &snapshot) {
        return None;
    }
    let proof = proof?;
    if proof.daemon_pid != snapshot.daemon_pid
        || proof.instance_commitment.0 != snapshot.instance_commitment
    {
        return None;
    }
    let rows = snapshot
        .accounts
        .into_iter()
        .map(|row| (row.channel_ref, (row.state, row.binding_tag)))
        .collect::<BTreeMap<_, _>>();
    Some(
        current_tags
            .iter()
            .filter_map(|(reference, tag)| {
                rows.get(reference)
                    .filter(|(_, stored_tag)| stored_tag == &tag.0)
                    .map(|(state, _)| (reference.clone(), *state))
            })
            .collect(),
    )
}

fn snapshot_is_current_claim(home: &Path, now: u64, snapshot: &Snapshot) -> bool {
    snapshot.schema_version == SCHEMA_VERSION
        && snapshot.instance_home == home
        && snapshot.lifecycle == ProjectionLifecycle::Serving
        && now >= snapshot.observed_unix_millis
        && now - snapshot.observed_unix_millis <= MAX_AGE.as_millis() as u64
}

fn read_snapshot(home: &Path) -> Result<Option<Snapshot>> {
    let path = home.join(CHANNEL_RUNTIME_HEALTH_FILE);
    let Some(body) = read_private_regular_file_bounded(&path)? else {
        return Ok(None);
    };
    let snapshot: Snapshot =
        serde_json::from_slice(&body).context("parse runtime-health projection")?;
    validate_snapshot(&snapshot)?;
    Ok(Some(snapshot))
}

/// Validate the opened handle and its bounded length before allocating the
/// byte buffer. Unix O_NOFOLLOW plus O_NONBLOCK / Windows reparse-point
/// opening preserves the private-regular-file contract across the open path
/// too: a FIFO cannot block before its metadata rejects it.
fn read_private_regular_file_bounded(path: &Path) -> Result<Option<Vec<u8>>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("open {}", path.display())),
    };
    let metadata = private_regular_file_metadata(&file, path)?;
    ensure!(
        metadata.len() <= MAX_BYTES,
        "runtime-health projection exceeds {MAX_BYTES} bytes"
    );
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    let mut file = file;
    (&mut file)
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {}", path.display()))?;
    ensure!(
        bytes.len() as u64 == metadata.len() && bytes.len() as u64 <= MAX_BYTES,
        "runtime-health projection changed or exceeded its bound during read"
    );
    Ok(Some(bytes))
}

fn private_regular_file_metadata(file: &File, path: &Path) -> Result<std::fs::Metadata> {
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
        "runtime-health projection is not a regular file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "runtime-health projection is not current-user-only"
        );
    }
    #[cfg(windows)]
    crate::wal::win_native::verify_private_file_handle(file).with_context(|| {
        format!(
            "verify private runtime-health projection {}",
            path.display()
        )
    })?;
    Ok(metadata)
}

fn validate_snapshot(snapshot: &Snapshot) -> Result<()> {
    ensure!(
        fixed_lower_hex(&snapshot.instance_commitment),
        "runtime-health instance commitment has an invalid shape"
    );
    let mut previous: Option<&ChannelRef> = None;
    for row in &snapshot.accounts {
        ensure!(
            fixed_lower_hex(&row.binding_tag),
            "runtime-health binding tag has an invalid shape"
        );
        if let Some(previous) = previous {
            ensure!(
                previous < &row.channel_ref,
                "runtime-health account rows are not strictly canonical"
            );
        }
        previous = Some(&row.channel_ref);
    }
    Ok(())
}

fn now_unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn fixed_lower_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        sync::{Arc, Barrier},
        thread,
    };

    use super::*;
    use crate::{
        channels::registry::{ChannelAccountId, ChannelId},
        secret::SecretString,
    };

    fn reference(id: &str) -> ChannelRef {
        ChannelRef::new(ChannelId::Telegram, ChannelAccountId::new(id).unwrap())
    }
    fn tag(reference: &ChannelRef, user: u64, legacy: bool, token: &str) -> BindingTag {
        let secret = SecretString::new(token.into());
        BindingTag::from_parts_with_binding(
            reference,
            None,
            user,
            legacy,
            secret.expose_secret().as_bytes(),
            &crate::config::TelegramInboundAdmission::PinnedOperator {
                allowed_user_id: user,
            },
        )
    }
    fn commitment(seed: &str) -> InstanceCommitment {
        super::super::audit_rpc::instance_commitment_for_nonce(seed)
    }
    fn proof(pid: u32, commitment: InstanceCommitment) -> DaemonInstanceProof {
        DaemonInstanceProof {
            daemon_pid: pid,
            instance_commitment: commitment,
        }
    }
    fn one(
        reference: ChannelRef,
        state: AccountRuntimeState,
        tag: BindingTag,
    ) -> BTreeMap<ChannelRef, (AccountRuntimeState, BindingTag)> {
        BTreeMap::from([(reference, (state, tag))])
    }
    fn snapshot(
        home: &Path,
        pid: u32,
        commitment: InstanceCommitment,
        rows: BTreeMap<ChannelRef, (AccountRuntimeState, BindingTag)>,
    ) -> Snapshot {
        let writer = ChannelRuntimeHealthWriter::new(home, pid, commitment).unwrap();
        writer.publish(ProjectionLifecycle::Serving, rows).unwrap();
        read_snapshot(home).unwrap().unwrap()
    }

    #[cfg(windows)]
    fn is_windows_sharing_violation(error: &anyhow::Error) -> bool {
        error
            .chain()
            .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
            .any(|source| source.raw_os_error() == Some(32))
    }

    #[test]
    fn injected_live_proof_accepts_only_the_matching_secret_free_row() {
        let home = tempfile::tempdir().unwrap();
        let a = reference("alpha");
        let a_tag = tag(
            &a,
            9_876_543_210,
            false,
            "runtime-test-token-never-serialize",
        );
        let commitment = commitment("boot-one");
        let snapshot = snapshot(
            home.path(),
            41,
            commitment.clone(),
            one(a.clone(), AccountRuntimeState::Running, a_tag.clone()),
        );
        let body = String::from_utf8(
            std::fs::read(home.path().join(CHANNEL_RUNTIME_HEALTH_FILE)).unwrap(),
        )
        .unwrap();
        for forbidden in [
            "runtime-test-token-never-serialize",
            "allowed_user_id",
            "sender",
            "error",
        ] {
            assert!(!body.contains(forbidden));
        }
        let current = BTreeMap::from([(a.clone(), a_tag)]);
        assert_eq!(
            read_active_with_live_proof(
                home.path(),
                &current,
                snapshot.observed_unix_millis,
                Some(&proof(41, commitment)),
                snapshot
            )
            .as_ref()
            .and_then(|rows| rows.get(&a)),
            Some(&AccountRuntimeState::Running)
        );
    }

    #[test]
    fn wrong_home_schema_oversize_stopped_future_and_expired_fail_closed() {
        let home = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let a = reference("alpha");
        let a_tag = tag(&a, 10, false, "token");
        let commitment = commitment("boot-two");
        let current = BTreeMap::from([(a.clone(), a_tag.clone())]);
        let mut base = snapshot(
            home.path(),
            42,
            commitment.clone(),
            one(a.clone(), AccountRuntimeState::Running, a_tag.clone()),
        );
        base.instance_home = other.path().to_path_buf();
        assert!(
            read_active_with_live_proof(
                home.path(),
                &current,
                1,
                Some(&proof(42, commitment.clone())),
                base
            )
            .is_none()
        );
        let mut base = snapshot(
            home.path(),
            42,
            commitment.clone(),
            one(a.clone(), AccountRuntimeState::Running, a_tag.clone()),
        );
        base.schema_version = 2;
        assert!(
            read_active_with_live_proof(
                home.path(),
                &current,
                1,
                Some(&proof(42, commitment.clone())),
                base
            )
            .is_none()
        );
        let mut base = snapshot(
            home.path(),
            42,
            commitment.clone(),
            one(a.clone(), AccountRuntimeState::Running, a_tag.clone()),
        );
        base.lifecycle = ProjectionLifecycle::Stopped;
        assert!(
            read_active_with_live_proof(
                home.path(),
                &current,
                1,
                Some(&proof(42, commitment.clone())),
                base
            )
            .is_none()
        );
        let mut base = snapshot(
            home.path(),
            42,
            commitment.clone(),
            one(a.clone(), AccountRuntimeState::Running, a_tag),
        );
        base.observed_unix_millis = 100;
        assert!(
            read_active_with_live_proof(
                home.path(),
                &current,
                99,
                Some(&proof(42, commitment.clone())),
                base.clone()
            )
            .is_none()
        );
        assert!(
            read_active_with_live_proof(
                home.path(),
                &current,
                100 + MAX_AGE.as_millis() as u64 + 1,
                Some(&proof(42, commitment)),
                base
            )
            .is_none()
        );
        crate::util::atomic_write::atomic_write_private(
            &home.path().join(CHANNEL_RUNTIME_HEALTH_FILE),
            &vec![b'x'; MAX_BYTES as usize + 1],
        )
        .unwrap();
        assert!(read_snapshot(home.path()).is_err());
    }

    #[test]
    fn proof_mismatch_and_a_rotation_do_not_claim_running_or_erase_b() {
        let home = tempfile::tempdir().unwrap();
        let a = reference("alpha");
        let b = reference("beta");
        let old_a = tag(&a, 20, false, "a-old");
        let token_rotated_a = tag(&a, 20, false, "a-new");
        let legacy_rotated_a = tag(&a, 20, true, "a-old");
        let b_tag = tag(&b, 21, false, "b-token");
        let boot_commitment = commitment("boot-three");
        let snapshot = snapshot(
            home.path(),
            43,
            boot_commitment.clone(),
            BTreeMap::from([
                (a.clone(), (AccountRuntimeState::Running, old_a)),
                (b.clone(), (AccountRuntimeState::Failed, b_tag.clone())),
            ]),
        );
        let current = BTreeMap::from([(a.clone(), token_rotated_a), (b.clone(), b_tag.clone())]);
        let observed = read_active_with_live_proof(
            home.path(),
            &current,
            snapshot.observed_unix_millis,
            Some(&proof(43, boot_commitment.clone())),
            snapshot.clone(),
        )
        .unwrap();
        assert_eq!(observed.get(&a), None);
        assert_eq!(observed.get(&b), Some(&AccountRuntimeState::Failed));
        let only_b = BTreeMap::from([(b.clone(), b_tag.clone())]);
        let removed_a = read_active_with_live_proof(
            home.path(),
            &only_b,
            snapshot.observed_unix_millis,
            Some(&proof(43, boot_commitment.clone())),
            snapshot.clone(),
        )
        .unwrap();
        assert_eq!(removed_a.get(&b), Some(&AccountRuntimeState::Failed));
        assert!(
            read_active_with_live_proof(
                home.path(),
                &current,
                snapshot.observed_unix_millis,
                Some(&proof(43, commitment("other-boot"))),
                snapshot.clone()
            )
            .is_none()
        );
        let current = BTreeMap::from([(a.clone(), legacy_rotated_a), (b.clone(), b_tag)]);
        assert!(
            read_active_with_live_proof(
                home.path(),
                &current,
                snapshot.observed_unix_millis,
                Some(&proof(44, boot_commitment)),
                snapshot
            )
            .is_none()
        );
    }

    #[cfg(unix)]
    #[test]
    fn runtime_health_fifo_is_rejected_without_blocking_before_metadata() {
        use std::os::unix::{ffi::OsStrExt as _, fs::OpenOptionsExt as _};

        let home = tempfile::tempdir().unwrap();
        let fifo = home.path().join(CHANNEL_RUNTIME_HEALTH_FILE);
        let fifo_name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: the test owns this NUL-free pathname and supplies a valid mode.
        assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);

        let fifo_for_reader = fifo.clone();
        let (sender, receiver) = std::sync::mpsc::channel();
        let (ready_sender, ready_receiver) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            ready_sender.send(()).unwrap();
            sender
                .send(read_private_regular_file_bounded(&fifo_for_reader))
                .unwrap();
        });
        ready_receiver.recv_timeout(Duration::from_secs(1)).unwrap();

        match receiver.recv_timeout(Duration::from_secs(1)) {
            Ok(result) => {
                assert!(result.is_err(), "FIFO must fail the regular-file gate");
                reader.join().unwrap();
            }
            Err(timeout_error) => {
                // A regressed blocking reader may still be between its ready
                // signal and FIFO open. Retry a nonblocking writer briefly
                // until it has a reader; never let cleanup itself block.
                let cleanup_deadline = std::time::Instant::now() + Duration::from_secs(1);
                let writer = loop {
                    match std::fs::OpenOptions::new()
                        .write(true)
                        .custom_flags(libc::O_NONBLOCK)
                        .open(&fifo)
                    {
                        Ok(writer) => break writer,
                        Err(error)
                            if error.raw_os_error() == Some(libc::ENXIO)
                                && std::time::Instant::now() < cleanup_deadline =>
                        {
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(error) => {
                            panic!("runtime-health FIFO cleanup could not wake the reader: {error}")
                        }
                    }
                };
                match receiver.recv_timeout(Duration::from_secs(1)) {
                    Ok(result) => {
                        assert!(result.is_err(), "FIFO must fail the regular-file gate");
                        drop(writer);
                        reader.join().unwrap();
                        panic!(
                            "runtime-health FIFO open blocked before metadata validation: {timeout_error}"
                        );
                    }
                    Err(error) => {
                        drop(writer);
                        // Do not join here: a regressed blocking reader would
                        // make the regression test itself hang indefinitely.
                        panic!(
                            "runtime-health FIFO open blocked before metadata validation: {timeout_error}; cleanup result: {error}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn duplicate_or_noncanonical_rows_reject_the_whole_projection() {
        let home = tempfile::tempdir().unwrap();
        let a = reference("alpha");
        let b = reference("beta");
        let a_tag = tag(&a, 30, false, "a");
        let b_tag = tag(&b, 31, false, "b");
        let mut snapshot = snapshot(
            home.path(),
            44,
            commitment("boot-four"),
            BTreeMap::from([
                (a, (AccountRuntimeState::Running, a_tag)),
                (b, (AccountRuntimeState::Running, b_tag)),
            ]),
        );
        snapshot.accounts.swap(0, 1);
        crate::util::atomic_write::atomic_write_private(
            &home.path().join(CHANNEL_RUNTIME_HEALTH_FILE),
            &serde_json::to_vec(&snapshot).unwrap(),
        )
        .unwrap();
        assert!(read_snapshot(home.path()).is_err());
        crate::util::atomic_write::atomic_write_private(
            &home.path().join(CHANNEL_RUNTIME_HEALTH_FILE),
            br#"{"schema_version":1,"instance_home":".","daemon_pid":1,"instance_commitment":"0000000000000000000000000000000000000000000000000000000000000000","observed_unix_millis":1,"lifecycle":"serving","accounts":[],"foreign":true}"#,
        )
        .unwrap();
        assert!(read_snapshot(home.path()).is_err());
        snapshot.accounts.swap(0, 1);
        snapshot.accounts.push(snapshot.accounts[0].clone());
        crate::util::atomic_write::atomic_write_private(
            &home.path().join(CHANNEL_RUNTIME_HEALTH_FILE),
            &serde_json::to_vec(&snapshot).unwrap(),
        )
        .unwrap();
        assert!(read_snapshot(home.path()).is_err());
    }

    #[test]
    fn writer_clones_atomically_publish_complete_rows() {
        let home = tempfile::tempdir().unwrap();
        let a = reference("alpha");
        let writer =
            ChannelRuntimeHealthWriter::new(home.path(), 45, commitment("boot-five")).unwrap();
        writer
            .publish(
                ProjectionLifecycle::Serving,
                one(
                    a.clone(),
                    AccountRuntimeState::Running,
                    tag(&a, 40, false, "one"),
                ),
            )
            .unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let worker = writer.clone();
        let worker_a = a.clone();
        let worker_barrier = barrier.clone();
        let writer_thread = thread::spawn(move || {
            worker_barrier.wait();
            for state in [AccountRuntimeState::Failed, AccountRuntimeState::Running]
                .into_iter()
                .cycle()
                .take(32)
            {
                worker
                    .publish(
                        ProjectionLifecycle::Serving,
                        one(worker_a.clone(), state, tag(&worker_a, 40, false, "two")),
                    )
                    .unwrap();
            }
        });
        barrier.wait();
        for _ in 0..32 {
            match read_snapshot(home.path()) {
                Ok(Some(observed)) => {
                    assert_eq!(observed.accounts.len(), 1);
                    assert_eq!(observed.accounts[0].channel_ref, a);
                    assert!(matches!(
                        observed.accounts[0].state,
                        AccountRuntimeState::Running | AccountRuntimeState::Failed
                    ));
                }
                Ok(None) => panic!("atomic publication must not produce a missing snapshot"),
                #[cfg(windows)]
                Err(error) if is_windows_sharing_violation(&error) => {}
                Err(error) => panic!("unexpected runtime-health read failure: {error:#}"),
            }
        }
        writer_thread.join().unwrap();
        let completed = read_snapshot(home.path()).unwrap().unwrap();
        assert_eq!(completed.accounts.len(), 1);
        assert_eq!(completed.accounts[0].channel_ref, a);
        assert_eq!(completed.accounts[0].state, AccountRuntimeState::Running);
        let final_tag = tag(&a, 40, false, "two");
        assert!(
            completed.accounts[0].binding_tag == final_tag.0,
            "last completed publication must retain the final opaque binding"
        );
    }
}
