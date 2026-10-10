//! Closed local microphone-consent authority.
//!
//! Separate from cloud/provider consent: it controls the local capture device.
//! A capability is request/config/home bound, expires, and is consumed before
//! the future capture owner may open a device.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const STATE_FILE: &str = "microphone-consent.json";
const SCHEMA_VERSION: u8 = 1;
const CHALLENGE_TTL_SECS: i64 = 120;
const CAPABILITY_TTL_SECS: i64 = 120;
const MAX_STATE_BYTES: usize = 1024;
static MICROPHONE_STORE_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MicDecision {
    AllowOnce,
    AllowAlways,
    Deny,
}

#[derive(Debug)]
pub(crate) enum MicPreflight {
    Granted { capability: MicStartCapability },
    ConfirmationRequired { challenge: MicChallenge },
}

/// Opaque and intentionally non-cloneable: moving it is the only way to use it.
#[derive(Debug)]
pub(crate) struct MicStartCapability {
    id: String,
}
#[derive(Debug)]
pub(crate) struct MicChallenge {
    id: String,
}

#[derive(Debug)]
pub(crate) struct MicOpenAdmission {
    operation_id: String,
    home_binding: String,
    config_digest: String,
    permission_revision: u64,
    allow_once: bool,
    admitted_at_unix: i64,
}
impl MicOpenAdmission {
    pub(crate) fn operation_id(&self) -> &str {
        &self.operation_id
    }
    pub(crate) fn config_digest(&self) -> &str {
        &self.config_digest
    }
    pub(crate) const fn permission_revision(&self) -> u64 {
        self.permission_revision
    }
    pub(crate) const fn admitted_at_unix(&self) -> i64 {
        self.admitted_at_unix
    }
    pub(crate) const fn allow_once(&self) -> bool {
        self.allow_once
    }
    pub(crate) fn into_parts(self) -> (String, String, String, u64, bool, i64) {
        (
            self.operation_id,
            self.home_binding,
            self.config_digest,
            self.permission_revision,
            self.allow_once,
            self.admitted_at_unix,
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum MicError {
    #[error("microphone_consent_invalid_config_binding")]
    InvalidConfigBinding,
    #[error("microphone_consent_unknown_or_expired_challenge")]
    UnknownOrExpiredChallenge,
    #[error("microphone_consent_unknown_or_expired_capability")]
    UnknownOrExpiredCapability,
    #[error("microphone_consent_capability_already_consumed")]
    Consumed,
    #[error("microphone_consent_config_drift")]
    ConfigDrift,
    #[error("microphone_consent_persistence_failed")]
    Persistence,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedGrant {
    schema_version: u8,
    microphone_allowed: bool,
    revision: u64,
}
struct PendingChallenge {
    config_digest: String,
    expires_at_unix: i64,
    revision: u64,
}
struct PendingCapability {
    config_digest: String,
    expires_at_unix: i64,
    consumed: bool,
    revision: u64,
    allow_once: bool,
}

/// Persistent grant is microphone-only. Challenges and capabilities deliberately
/// die with the process, so a restart can never replay a pending device open.
pub(crate) struct MicConsentStore {
    home: PathBuf,
    persisted: PersistedGrant,
    challenges: BTreeMap<String, PendingChallenge>,
    capabilities: BTreeMap<String, PendingCapability>,
}

impl MicConsentStore {
    pub(crate) fn open(home: &Path) -> Result<Self, MicError> {
        let home = fs::canonicalize(home).map_err(|_| MicError::Persistence)?;
        let mut store = Self {
            home,
            persisted: PersistedGrant {
                schema_version: SCHEMA_VERSION,
                microphone_allowed: false,
                revision: 0,
            },
            challenges: BTreeMap::new(),
            capabilities: BTreeMap::new(),
        };
        store.persisted = store.read_current()?;
        Ok(store)
    }

    pub(crate) fn preflight(
        &mut self,
        config_digest: &str,
        now_unix: i64,
    ) -> Result<MicPreflight, MicError> {
        validate_digest(config_digest)?;
        self.prune(now_unix);
        self.persisted = self.read_current()?;
        if self.persisted.microphone_allowed {
            return Ok(MicPreflight::Granted {
                capability: self.mint(config_digest, now_unix, false)?,
            });
        }
        let id = new_opaque_id();
        self.challenges.insert(
            id.clone(),
            PendingChallenge {
                config_digest: config_digest.to_owned(),
                expires_at_unix: now_unix
                    .checked_add(CHALLENGE_TTL_SECS)
                    .ok_or(MicError::Persistence)?,
                revision: self.persisted.revision,
            },
        );
        Ok(MicPreflight::ConfirmationRequired {
            challenge: MicChallenge { id },
        })
    }

    pub(crate) fn decide(
        &mut self,
        challenge: MicChallenge,
        decision: MicDecision,
        now_unix: i64,
    ) -> Result<Option<MicStartCapability>, MicError> {
        self.prune(now_unix);
        let pending = self
            .challenges
            .remove(&challenge.id)
            .ok_or(MicError::UnknownOrExpiredChallenge)?;
        if pending.expires_at_unix <= now_unix {
            return Err(MicError::UnknownOrExpiredChallenge);
        }
        let current = self.read_current()?;
        if current.revision != pending.revision {
            return Err(MicError::ConfigDrift);
        }
        self.persisted = current;
        match decision {
            MicDecision::Deny => Ok(None),
            MicDecision::AllowOnce => self.mint(&pending.config_digest, now_unix, true).map(Some),
            MicDecision::AllowAlways => {
                let current = self.read_current()?;
                let next = PersistedGrant {
                    schema_version: SCHEMA_VERSION,
                    microphone_allowed: true,
                    revision: current
                        .revision
                        .checked_add(1)
                        .ok_or(MicError::Persistence)?,
                };
                self.commit_state(current.revision, &next)?;
                self.persisted = next;
                self.mint(&pending.config_digest, now_unix, false).map(Some)
            }
        }
    }

    pub(crate) fn revoke(&mut self) -> Result<(), MicError> {
        let current = self.read_current()?;
        let next = PersistedGrant {
            schema_version: SCHEMA_VERSION,
            microphone_allowed: false,
            revision: current
                .revision
                .checked_add(1)
                .ok_or(MicError::Persistence)?,
        };
        self.commit_state(current.revision, &next)?;
        self.persisted = next;
        self.capabilities.clear();
        self.challenges.clear();
        Ok(())
    }

    /// Consume before the MicOpen intent. A failed intent/capture does not make
    /// the token reusable; the caller must issue a fresh consent request.
    pub(crate) fn consume_for_open(
        &mut self,
        capability: MicStartCapability,
        config_digest: &str,
        now_unix: i64,
    ) -> Result<MicOpenAdmission, MicError> {
        validate_digest(config_digest)?;
        self.prune(now_unix);
        let current = self.read_current()?;
        let entry = self
            .capabilities
            .get_mut(&capability.id)
            .ok_or(MicError::UnknownOrExpiredCapability)?;
        if entry.consumed {
            return Err(MicError::Consumed);
        }
        if entry.expires_at_unix <= now_unix {
            return Err(MicError::UnknownOrExpiredCapability);
        }
        if entry.revision != current.revision || (!entry.allow_once && !current.microphone_allowed)
        {
            entry.consumed = true;
            return Err(MicError::ConfigDrift);
        }
        // A presented proof is one-use even when its caller supplied stale
        // configuration; retry must go back through preflight/decision.
        entry.consumed = true;
        if entry.config_digest != config_digest {
            return Err(MicError::ConfigDrift);
        }
        Ok(MicOpenAdmission {
            operation_id: opaque_operation_id(
                &self.home,
                &capability.id,
                config_digest,
                current.revision,
            ),
            home_binding: opaque_home_binding(&self.home),
            config_digest: config_digest.to_owned(),
            permission_revision: current.revision,
            allow_once: entry.allow_once,
            admitted_at_unix: now_unix,
        })
    }

    /// This is intentionally read-only and is called through the writer-issued
    /// terminal authority after a permit wait, immediately before device open.
    pub(crate) fn revalidate_terminal_for_device_open(
        &self,
        home_binding: &str,
        config_digest: &str,
        permission_revision: u64,
        allow_once: bool,
    ) -> Result<(), MicError> {
        validate_digest(config_digest)?;
        if home_binding != opaque_home_binding(&self.home) {
            return Err(MicError::ConfigDrift);
        }
        let current = self.read_current()?;
        if current.revision != permission_revision || (!allow_once && !current.microphone_allowed) {
            Err(MicError::ConfigDrift)
        } else {
            Ok(())
        }
    }
    fn mint(
        &mut self,
        config_digest: &str,
        now_unix: i64,
        allow_once: bool,
    ) -> Result<MicStartCapability, MicError> {
        let id = new_opaque_id();
        self.capabilities.insert(
            id.clone(),
            PendingCapability {
                config_digest: config_digest.to_owned(),
                expires_at_unix: now_unix
                    .checked_add(CAPABILITY_TTL_SECS)
                    .ok_or(MicError::Persistence)?,
                consumed: false,
                revision: self.persisted.revision,
                allow_once,
            },
        );
        Ok(MicStartCapability { id })
    }
    fn prune(&mut self, now_unix: i64) {
        self.challenges
            .retain(|_, item| item.expires_at_unix > now_unix);
        self.capabilities
            .retain(|_, item| item.expires_at_unix > now_unix && !item.consumed);
    }
    fn read_current(&self) -> Result<PersistedGrant, MicError> {
        let bound = crate::skills::store::open_bound_directory(
            &self.home,
            false,
            "microphone consent home",
        )
        .map_err(|_| MicError::Persistence)?
        .ok_or(MicError::Persistence)?;
        let name = OsStr::new(STATE_FILE);
        match bound.dir.symlink_metadata(name) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(PersistedGrant {
                schema_version: SCHEMA_VERSION,
                microphone_allowed: false,
                revision: 0,
            }),
            Err(_) => Err(MicError::Persistence),
            Ok(meta) => {
                if !meta.file_type().is_file() {
                    return Err(MicError::Persistence);
                }
                #[cfg(unix)]
                {
                    use cap_std::fs::PermissionsExt as _;
                    if meta.permissions().mode() & 0o077 != 0 {
                        return Err(MicError::Persistence);
                    }
                }
                let (file, binding) = crate::skills::store::open_bound_regular_file(
                    &bound.dir,
                    name,
                    &self.home.join(STATE_FILE),
                )
                .map_err(|_| MicError::Persistence)?;
                #[cfg(windows)]
                let private_file = file
                    .try_clone()
                    .map_err(|_| MicError::Persistence)?
                    .into_std();
                #[cfg(windows)]
                crate::wal::win_native::verify_private_file_handle(&private_file)
                    .map_err(|_| MicError::Persistence)?;
                if !binding
                    .matches_regular_file_child_readonly(
                        &bound.dir,
                        name,
                        &self.home.join(STATE_FILE),
                    )
                    .map_err(|_| MicError::Persistence)?
                {
                    return Err(MicError::Persistence);
                };
                let mut raw = Vec::new();
                file.take((MAX_STATE_BYTES as u64) + 1)
                    .read_to_end(&mut raw)
                    .map_err(|_| MicError::Persistence)?;
                if raw.len() > MAX_STATE_BYTES {
                    return Err(MicError::Persistence);
                }
                let value: PersistedGrant =
                    serde_json::from_slice(&raw).map_err(|_| MicError::Persistence)?;
                if value.schema_version != SCHEMA_VERSION {
                    Err(MicError::Persistence)
                } else {
                    Ok(value)
                }
            }
        }
    }
    fn commit_state(
        &self,
        expected_revision: u64,
        persisted: &PersistedGrant,
    ) -> Result<(), MicError> {
        let _guard = MICROPHONE_STORE_LOCK
            .lock()
            .map_err(|_| MicError::Persistence)?;
        let bound = crate::skills::store::open_bound_directory(
            &self.home,
            false,
            "microphone consent home",
        )
        .map_err(|_| MicError::Persistence)?
        .ok_or(MicError::Persistence)?;
        let lock_name = OsStr::new(".microphone-consent.lock");
        let lock_path = bound.physical_display_path.join(lock_name);
        let (lock, lock_binding) =
            crate::skills::store::open_or_create_bound_lockfile(&bound.dir, lock_name, &lock_path)
                .map_err(|_| MicError::Persistence)?;
        lock.lock().map_err(|_| MicError::Persistence)?;
        if !lock_binding
            .matches_regular_file_child_readonly(&bound.dir, lock_name, &lock_path)
            .map_err(|_| MicError::Persistence)?
        {
            return Err(MicError::Persistence);
        }
        if self.read_current()?.revision != expected_revision {
            return Err(MicError::ConfigDrift);
        }
        let body = serde_json::to_vec(persisted).map_err(|_| MicError::Persistence)?;
        let bound = crate::skills::store::open_bound_directory(
            &self.home,
            false,
            "microphone consent home",
        )
        .map_err(|_| MicError::Persistence)?
        .ok_or(MicError::Persistence)?;
        crate::skills::store::atomic_write_private_child(
            &bound.dir,
            OsStr::new(STATE_FILE),
            &self.home.join(STATE_FILE),
            &body,
        )
        .map_err(|_| MicError::Persistence)
    }
}

fn validate_digest(value: &str) -> Result<(), MicError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(MicError::InvalidConfigBinding)
    }
}
fn new_opaque_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}
fn opaque_operation_id(home: &Path, cap: &str, digest: &str, revision: u64) -> String {
    let mut hash = Sha256::new();
    hash.update(b"neoth/a2/microphone-open/v1\0");
    hash.update(home.as_os_str().as_encoded_bytes());
    hash.update(cap.as_bytes());
    hash.update(digest.as_bytes());
    hash.update(revision.to_be_bytes());
    hex::encode(hash.finalize())
}
fn opaque_home_binding(home: &Path) -> String {
    let mut hash = Sha256::new();
    hash.update(b"neoth/a2/microphone-home/v1\0");
    hash.update(home.as_os_str().as_encoded_bytes());
    hex::encode(hash.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    #[test]
    fn once_is_config_bound_and_consumed() {
        let home = tempdir().unwrap();
        let mut s = MicConsentStore::open(home.path()).unwrap();
        let MicPreflight::ConfirmationRequired { challenge } = s.preflight(A, 10).unwrap() else {
            panic!()
        };
        let c = s
            .decide(challenge, MicDecision::AllowOnce, 11)
            .unwrap()
            .unwrap();
        assert_eq!(
            s.consume_for_open(c, B, 12).unwrap_err(),
            MicError::ConfigDrift
        );
        let MicPreflight::ConfirmationRequired { challenge } = s.preflight(A, 13).unwrap() else {
            panic!()
        };
        let c = s
            .decide(challenge, MicDecision::AllowOnce, 14)
            .unwrap()
            .unwrap();
        let admission = s.consume_for_open(c, A, 15).unwrap();
        assert_eq!(admission.config_digest(), A);
        assert_eq!(admission.permission_revision(), 0);
        assert_eq!(admission.admitted_at_unix(), 15);
        assert!(admission.allow_once());
        assert_eq!(admission.operation_id().len(), 64);
        assert!(admission.operation_id().bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(matches!(
            s.preflight(A, 16).unwrap(),
            MicPreflight::ConfirmationRequired { .. }
        ));
    }
    #[test]
    fn persistent_grant_mints_distinct_admissions_and_revoke_invalidates_pending_open() {
        let home = tempdir().unwrap();
        let mut store = MicConsentStore::open(home.path()).unwrap();
        let MicPreflight::ConfirmationRequired { challenge } = store.preflight(A, 10).unwrap()
        else {
            panic!("fresh store requires consent");
        };
        let capability = store.decide(challenge, MicDecision::AllowAlways, 11).unwrap().unwrap();
        let first = store.consume_for_open(capability, A, 12).unwrap();
        assert!(!first.allow_once());
        assert_eq!(first.permission_revision(), 1);
        let mut reopened = MicConsentStore::open(home.path()).unwrap();
        let MicPreflight::Granted { capability } = reopened.preflight(A, 13).unwrap() else {
            panic!("persisted consent must grant a fresh capability");
        };
        let second = reopened.consume_for_open(capability, A, 14).unwrap();
        assert!(!second.allow_once());
        assert_eq!(second.permission_revision(), first.permission_revision());
        assert_eq!(second.config_digest(), A);
        assert_eq!(second.admitted_at_unix(), 14);
        assert_ne!(second.operation_id(), first.operation_id());
        let MicPreflight::Granted { capability } = reopened.preflight(A, 15).unwrap() else {
            panic!("grant remains active");
        };
        store.revoke().unwrap();
        assert_eq!(
            reopened.consume_for_open(capability, A, 16).unwrap_err(),
            MicError::ConfigDrift
        );
        assert!(matches!(
            reopened.preflight(A, 17).unwrap(),
            MicPreflight::ConfirmationRequired { .. }
        ));
    }

    #[test]
    fn denial_expiry_and_revoke_fail_closed() {
        let home = tempdir().unwrap();
        let mut s = MicConsentStore::open(home.path()).unwrap();
        let MicPreflight::ConfirmationRequired { challenge } = s.preflight(A, 10).unwrap() else {
            panic!()
        };
        assert!(
            s.decide(challenge, MicDecision::Deny, 11)
                .unwrap()
                .is_none()
        );
        let MicPreflight::ConfirmationRequired { challenge } = s.preflight(A, 12).unwrap() else {
            panic!()
        };
        assert_eq!(
            s.decide(challenge, MicDecision::AllowOnce, 200)
                .unwrap_err(),
            MicError::UnknownOrExpiredChallenge
        );
        let MicPreflight::ConfirmationRequired { challenge } = s.preflight(A, 201).unwrap() else {
            panic!()
        };
        let c = s
            .decide(challenge, MicDecision::AllowAlways, 202)
            .unwrap()
            .unwrap();
        s.revoke().unwrap();
        assert_eq!(
            s.consume_for_open(c, A, 203).unwrap_err(),
            MicError::UnknownOrExpiredCapability
        );
        let mut reopened = MicConsentStore::open(home.path()).unwrap();
        assert!(matches!(
            reopened.preflight(A, 204).unwrap(),
            MicPreflight::ConfirmationRequired { .. }
        ));
    }
    #[test]
    fn independent_store_revoke_invalidates_stale_challenge_and_capability() {
        let home = tempdir().unwrap();
        let mut first = MicConsentStore::open(home.path()).unwrap();
        let mut second = MicConsentStore::open(home.path()).unwrap();
        let MicPreflight::ConfirmationRequired { challenge } = first.preflight(A, 10).unwrap()
        else {
            panic!()
        };
        let cap = first
            .decide(challenge, MicDecision::AllowAlways, 11)
            .unwrap()
            .unwrap();
        second.revoke().unwrap();
        assert_eq!(
            first.consume_for_open(cap, A, 12).unwrap_err(),
            MicError::ConfigDrift
        );
        let MicPreflight::ConfirmationRequired { challenge } = second.preflight(A, 13).unwrap()
        else {
            panic!()
        };
        first.revoke().unwrap();
        assert_eq!(
            second
                .decide(challenge, MicDecision::AllowAlways, 14)
                .unwrap_err(),
            MicError::ConfigDrift
        );
    }
    #[test]
    fn oversized_or_nonregular_persisted_state_fails_closed() {
        let home = tempdir().unwrap();
        std::fs::write(
            home.path().join(STATE_FILE),
            vec![b'x'; MAX_STATE_BYTES + 1],
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(
                home.path().join(STATE_FILE),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        assert!(matches!(
            MicConsentStore::open(home.path()),
            Err(MicError::Persistence)
        ));
        std::fs::remove_file(home.path().join(STATE_FILE)).unwrap();
        std::fs::create_dir(home.path().join(STATE_FILE)).unwrap();
        assert!(matches!(
            MicConsentStore::open(home.path()),
            Err(MicError::Persistence)
        ));
    }
    #[cfg(unix)]
    #[test]
    fn symlinked_persisted_state_fails_closed() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        let home = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let source = outside.path().join("state");
        std::fs::write(
            &source,
            b"{\"schema_version\":1,\"microphone_allowed\":true,\"revision\":7}",
        )
        .unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&source, home.path().join(STATE_FILE)).unwrap();
        assert!(matches!(
            MicConsentStore::open(home.path()),
            Err(MicError::Persistence)
        ));
    }
}
