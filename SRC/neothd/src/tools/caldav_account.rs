//! Instance-bound, revocable CalDAV read-egress grants.
//!
//! The grant contains only an HMAC commitment to the canonical collection URL
//! and exact Basic-auth account. It is unusable when the local WAL HMAC
//! authority is absent, malformed, or has rotated.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context, Result};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq as _;

use crate::secret::SecretString;
use crate::skills::store::{
    atomic_write_private_child, open_bound_directory_from_trusted_anchor,
    read_regular_file_bounded, remove_child_file_if_present, sync_parent_directory,
};

type BindingMac = Hmac<Sha256>;
const DOMAIN: &[u8] = b"neoth.caldav.read.binding.v1";
const GRANT_VERSION: u8 = 1;
const GRANT_NAME: &str = "caldav_read_access.grant";
const MAX_GRANT_BYTES: usize = 1024;

/// A resolved, canonical CalDAV account. `Debug` is intentionally absent so
/// a password can never escape through a diagnostic formatter.
#[derive(Clone)]
pub(crate) struct CaldavAccount {
    pub(crate) url: String,
    pub(crate) username: String,
    pub(crate) password: SecretString,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum GrantStatus {
    Granted,
    Missing,
    Invalid,
    CredentialsUnavailable,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    version: u8,
    binding: String,
}

/// Resolve credentials for one exact NEOTH home. `allow_env` is only for the
/// operator CLI compatibility path; daemon/n8n callers must pass false.
pub(crate) fn resolve_at(home: &Path, allow_env: bool) -> Result<CaldavAccount> {
    let freedom_path = home.join("freedom.yaml");
    // This is the config layer's read-only coherent-pair recovery/lock path.
    // It returns the effective file/keychain credentials from the same
    // generation as freedom.yaml and does not fall back to another home.
    let (_config, credentials) =
        crate::config::load_optional_runtime_config_pair_read_only_with_store_from_path(
            &freedom_path,
            None,
        )
        .with_context(|| format!("load coherent CalDAV instance at {}", freedom_path.display()))?;

    let url = credentials
        .caldav_url
        .filter(|value| !value.is_empty())
        .or_else(|| env_value(allow_env, "NEOTH_CALDAV_URL"))
        .context("missing CalDAV URL")?;
    let username = credentials
        .caldav_username
        .filter(|value| !value.is_empty())
        .or_else(|| env_value(allow_env, "NEOTH_CALDAV_USERNAME"))
        .context("missing CalDAV username")?;
    let password = credentials
        .caldav_password
        .or_else(|| env_value(allow_env, "NEOTH_CALDAV_PASSWORD").map(SecretString::from))
        .context("missing CalDAV password")?;

    Ok(CaldavAccount {
        url: canonical_collection_url(&url)?,
        username,
        password,
    })
}

fn env_value(allow_env: bool, name: &str) -> Option<String> {
    allow_env
        .then(|| std::env::var(name).ok())
        .flatten()
        .filter(|value| !value.is_empty())
}

/// The same canonical collection form accepted by CalDAV transport, narrowed
/// to HTTPS because a read-egress grant must never authorize cleartext Basic
/// authentication.
pub(crate) fn canonical_collection_url(raw: &str) -> Result<String> {
    ensure!(
        !raw.is_empty() && raw.trim() == raw,
        "CalDAV URL must be non-empty and contain no outer whitespace"
    );
    let url = url::Url::parse(raw).context("parse CalDAV collection URL")?;
    ensure!(url.scheme() == "https", "CalDAV read egress requires an HTTPS collection URL");
    ensure!(url.host().is_some(), "CalDAV collection URL must contain a host");
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "CalDAV URL must not contain credentials; use the credential fields"
    );
    ensure!(
        url.query().is_none() && url.fragment().is_none(),
        "CalDAV URL must not contain a query or fragment"
    );
    Ok(url.to_string())
}

fn grant_path(home: &Path) -> PathBuf {
    home.join(GRANT_NAME)
}

fn grant_root(home: &Path, create: bool) -> Result<Option<crate::skills::store::BoundDirectory>> {
    open_bound_directory_from_trusted_anchor(
        home.parent().unwrap_or(home),
        home,
        create,
        "CalDAV read-grant home",
    )
}

fn with_grant_mutation_lock<T>(home: &Path, action: impl FnOnce() -> Result<T>) -> Result<T> {
    // Reuse the home-bound cross-process transaction lock so a revoke cannot
    // race a stale grant publication in the same instance namespace.
    crate::config::credentials::with_coherent_pair_transaction_lock(&home.join("freedom.yaml"), action)
}

fn mac_for_key(key: &[u8], account: &CaldavAccount) -> Result<[u8; 32]> {
    let mut mac = BindingMac::new_from_slice(key).context("load CalDAV grant HMAC authority")?;
    for item in [
        DOMAIN,
        account.url.as_bytes(),
        account.username.as_bytes(),
        account.password.expose().as_bytes(),
    ] {
        mac.update(&(item.len() as u64).to_le_bytes());
        mac.update(item);
    }
    Ok(mac.finalize().into_bytes().into())
}

fn existing_binding(home: &Path, account: &CaldavAccount) -> Result<Option<[u8; 32]>> {
    let key_path = home.join("wal").join("hmac.key");
    let Some(authority) = crate::cli::security::acquire_existing_hmac_writer_authority(home, &key_path)? else {
        return Ok(None);
    };
    authority.validate_namespace_binding()?;
    Ok(Some(mac_for_key(&authority.active_key, account)?))
}

fn load_grant(home: &Path) -> Result<Option<Grant>> {
    let Some(root) = grant_root(home, false)? else {
        return Ok(None);
    };
    let path = grant_path(home);
    let bytes = match read_regular_file_bounded(&root.dir, OsStr::new(GRANT_NAME), &path, MAX_GRANT_BYTES) {
        Ok(bytes) => bytes,
        Err(error) if error.downcast_ref::<std::io::Error>().is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) => return Ok(None),
        Err(error) => return Err(error).context("read CalDAV read grant"),
    };
    let grant: Grant = serde_json::from_slice(&bytes).context("parse CalDAV read grant")?;
    ensure!(grant.version == GRANT_VERSION, "unsupported CalDAV read grant version");
    ensure!(
        grant.binding.len() == 64 && grant.binding.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid CalDAV read grant binding"
    );
    Ok(Some(grant))
}

fn grant_matches(home: &Path, account: &CaldavAccount) -> Result<GrantStatus> {
    let Some(grant) = load_grant(home)? else {
        return Ok(GrantStatus::Missing);
    };
    let Some(expected) = existing_binding(home, account)? else {
        return Ok(GrantStatus::Invalid);
    };
    let actual = hex::decode(grant.binding).context("decode CalDAV read grant binding")?;
    Ok(if actual.ct_eq(expected.as_slice()).into() {
        GrantStatus::Granted
    } else {
        GrantStatus::Invalid
    })
}

/// Persist an exact account grant. This is the only path allowed to initialize
/// the WAL HMAC key, as part of an explicit local grant write.
pub(crate) fn grant_at(home: &Path, account: &CaldavAccount) -> Result<()> {
    with_grant_mutation_lock(home, || {
        let key_path = home.join("wal").join("hmac.key");
        let key = crate::cli::security::recover_and_load_or_initialize_hmac_key(home, &key_path)?;
        let grant = Grant {
            version: GRANT_VERSION,
            binding: hex::encode(mac_for_key(&key, account)?),
        };
        let bytes = serde_json::to_vec(&grant).context("serialize CalDAV read grant")?;
        ensure!(bytes.len() <= MAX_GRANT_BYTES, "CalDAV read grant exceeds its bounded format");
        let root = grant_root(home, true)?.context("create CalDAV read-grant home")?;
        atomic_write_private_child(&root.dir, OsStr::new(GRANT_NAME), &grant_path(home), &bytes)
            .context("atomically write private CalDAV read grant")
    })
}

/// Revoke without resolving credentials: unavailable credentials must never
/// prevent removal of the local grant.
pub(crate) fn revoke_at(home: &Path) -> Result<bool> {
    with_grant_mutation_lock(home, || {
        let Some(root) = grant_root(home, false)? else {
            return Ok(false);
        };
        let removed = remove_child_file_if_present(&root.dir, OsStr::new(GRANT_NAME), &grant_path(home))
            .context("remove CalDAV read grant")?;
        if removed {
            sync_parent_directory(&root.dir, &grant_path(home))
                .context("durably publish CalDAV read-grant revocation")?;
        }
        Ok(removed)
    })
}

/// Read-only status. It never creates or recovers an HMAC key.
pub(crate) fn status_at(home: &Path, allow_env: bool) -> GrantStatus {
    let account = match resolve_at(home, allow_env) {
        Ok(account) => account,
        Err(_) => return GrantStatus::CredentialsUnavailable,
    };
    grant_matches(home, &account).unwrap_or(GrantStatus::Invalid)
}

/// Atomically admit one read against the current coherent configuration and
/// grant. This synchronous scope ends before the caller starts its bounded
/// network request: a revoke denies subsequent admissions but does not force
/// cancellation of a request admitted before the revoke.
pub(crate) fn require_at(
    home: &Path,
    snapshot: &CaldavAccount,
    allow_env: bool,
) -> Result<CaldavAccount> {
    crate::config::credentials::with_coherent_pair_transaction_lock(
        &home.join("freedom.yaml"),
        || {
            // `resolve_at` re-enters this same-home coherent read scope, so
            // the config/credentials pair cannot rotate between reload and
            // the grant comparison. Grant/revoke take this same lock.
            let current = resolve_at(home, allow_env)?;
            ensure!(
                current.url == snapshot.url
                    && current.username == snapshot.username
                    && current.password.expose() == snapshot.password.expose(),
                "CalDAV credentials changed after the read request was admitted; refusing egress"
            );
            ensure!(
                grant_matches(home, &current)? == GrantStatus::Granted,
                "CalDAV read egress is not granted for the current instance credential binding"
            );
            Ok(current)
        },
    )
}

pub(crate) fn redacted_egress_description(account: &CaldavAccount) -> String {
    let parsed = url::Url::parse(&account.url).expect("canonical CalDAV URL parsed earlier");
    let user = account.username.chars().take(2).collect::<String>();
    format!(
        "{}/<CalDAV collection> as {}…",
        parsed.origin().ascii_serialization(),
        user
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(url: &str, user: &str, password: &str) -> CaldavAccount {
        CaldavAccount {
            url: canonical_collection_url(url).unwrap(),
            username: user.into(),
            password: SecretString::from(password),
        }
    }

    fn write_credentials(home: &Path, password: &str) {
        std::fs::write(
            home.join("credentials.yaml"),
            format!(
                "caldav_url: https://calendar.example.test/dav/tasks/\ncaldav_username: alex\ncaldav_password: {password}\n"
            ),
        )
        .unwrap();
    }

    #[test]
    fn grant_roundtrip_revoke_and_rotation_fail_closed() {
        let home = tempfile::tempdir().unwrap();
        let current = account("https://calendar.example.test/dav/tasks/", "alex", "app-password");
        grant_at(home.path(), &current).unwrap();
        assert_eq!(grant_matches(home.path(), &current).unwrap(), GrantStatus::Granted);
        assert_eq!(grant_matches(home.path(), &account("https://calendar.example.test/dav/other/", "alex", "app-password")).unwrap(), GrantStatus::Invalid);
        assert_eq!(grant_matches(home.path(), &account("https://calendar.example.test/dav/tasks/", "sam", "app-password")).unwrap(), GrantStatus::Invalid);
        assert_eq!(grant_matches(home.path(), &account("https://calendar.example.test/dav/tasks/", "alex", "rotated")).unwrap(), GrantStatus::Invalid);
        assert!(revoke_at(home.path()).unwrap());
        assert_eq!(grant_matches(home.path(), &current).unwrap(), GrantStatus::Missing);
    }

    #[test]
    fn malformed_oversized_and_cross_home_grants_fail_closed() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let current = account("https://calendar.example.test/dav/tasks/", "alex", "app-password");
        grant_at(first.path(), &current).unwrap();
        assert_eq!(grant_matches(second.path(), &current).unwrap(), GrantStatus::Missing);
        std::fs::write(grant_path(first.path()), b"{").unwrap();
        assert!(grant_matches(first.path(), &current).is_err());
        std::fs::write(grant_path(first.path()), vec![b'x'; MAX_GRANT_BYTES + 1]).unwrap();
        assert!(grant_matches(first.path(), &current).is_err());
    }

    #[test]
    fn missing_effective_credentials_are_not_granted() {
        let home = tempfile::tempdir().unwrap();
        assert_eq!(status_at(home.path(), false), GrantStatus::CredentialsUnavailable);
    }

    #[test]
    fn require_at_denies_a_snapshot_after_effective_credentials_change() {
        let home = tempfile::tempdir().unwrap();
        write_credentials(home.path(), "first-password");
        let snapshot = resolve_at(home.path(), false).unwrap();
        grant_at(home.path(), &snapshot).unwrap();
        require_at(home.path(), &snapshot, false).unwrap();

        write_credentials(home.path(), "rotated-password");
        let error = require_at(home.path(), &snapshot, false)
            .err()
            .expect("rotated credentials must deny stale snapshot");
        assert!(error.to_string().contains("credentials changed"));
    }

    #[test]
    fn copied_grant_is_rejected_by_an_initialized_second_home() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        write_credentials(first.path(), "app-password");
        write_credentials(second.path(), "app-password");
        let first_account = resolve_at(first.path(), false).unwrap();
        let second_account = resolve_at(second.path(), false).unwrap();
        grant_at(first.path(), &first_account).unwrap();
        // Initialize the second home first; copying a first-home record must
        // not make its independently keyed account usable.
        grant_at(second.path(), &second_account).unwrap();
        std::fs::copy(grant_path(first.path()), grant_path(second.path())).unwrap();
        assert_eq!(
            grant_matches(second.path(), &second_account).unwrap(),
            GrantStatus::Invalid
        );
    }

    #[test]
    fn revoke_denies_the_next_read_admission() {
        let home = tempfile::tempdir().unwrap();
        write_credentials(home.path(), "app-password");
        let snapshot = resolve_at(home.path(), false).unwrap();
        grant_at(home.path(), &snapshot).unwrap();
        require_at(home.path(), &snapshot, false).unwrap();
        assert!(revoke_at(home.path()).unwrap());
        assert!(require_at(home.path(), &snapshot, false).is_err());
    }
}
