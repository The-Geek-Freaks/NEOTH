//! Privacy-preserving provider subject identifiers.
//!
//! The installation-local key in `identity/provider-subject.key` is separate
//! from every WAL/signing key.  A provider receives only a domain-separated
//! HMAC digest, never the configured operator identifier.

use std::ffi::OsStr;
use std::io::{Read, Write};
use std::path::Path;

use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

const KEY_BYTES: usize = 32;
const KEY_FILE: &str = "provider-subject.key";
const SUBJECT_SCHEMA: &[u8] = b"neoth.provider-subject.v1";

/// An opaque subject capability bound to one exact provider domain.
///
/// The value deliberately implements neither `Serialize` nor ordinary
/// `Debug`; it may travel only through NEOTH's in-memory dispatch capability.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ProviderSubjectIdentifier {
    provider: &'static str,
    value: String,
}

impl std::fmt::Debug for ProviderSubjectIdentifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProviderSubjectIdentifier([REDACTED])")
    }
}

impl ProviderSubjectIdentifier {
    /// Reveal the pseudonymous wire value only to the provider domain used
    /// when this capability was derived.
    pub(crate) fn wire_value_for(&self, provider: &str) -> Option<&str> {
        (self.provider == provider).then_some(self.value.as_str())
    }
}

fn validate_private_key_file(file: &cap_std::fs::File, display_path: &Path) -> Result<()> {
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect provider-subject key {}", display_path.display()))?;
    anyhow::ensure!(
        metadata.is_file() && !crate::skills::store::cap_metadata_is_link_like(&metadata),
        "provider-subject key is not a real regular file: {}",
        display_path.display()
    );

    #[cfg(unix)]
    {
        use cap_std::fs::PermissionsExt as _;
        anyhow::ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "provider-subject key is accessible by group or other users: {}",
            display_path.display()
        );
    }
    #[cfg(windows)]
    {
        let std_file = file
            .try_clone()
            .context("clone provider-subject key handle for DACL verification")?
            .into_std();
        crate::wal::win_native::verify_private_file_handle(&std_file).with_context(|| {
            format!(
                "verify private provider-subject key DACL {}",
                display_path.display()
            )
        })?;
    }
    Ok(())
}

fn load_key(
    identity_dir: &crate::skills::store::BoundDirectory,
) -> Result<Zeroizing<[u8; KEY_BYTES]>> {
    let name = OsStr::new(KEY_FILE);
    let display_path = identity_dir.display_path.join(name);
    let (mut file, _binding) =
        crate::skills::store::open_bound_regular_file(&identity_dir.dir, name, &display_path)
            .with_context(|| {
                format!(
                    "open capability-bound provider-subject key {}",
                    display_path.display()
                )
            })?;
    validate_private_key_file(&file, &display_path)?;

    let mut bytes = Zeroizing::new(Vec::with_capacity(KEY_BYTES));
    (&mut file)
        .take((KEY_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read provider-subject key {}", display_path.display()))?;
    anyhow::ensure!(
        bytes.len() == KEY_BYTES,
        "provider-subject key must contain exactly {KEY_BYTES} bytes: {}",
        display_path.display()
    );
    let mut key = Zeroizing::new([0u8; KEY_BYTES]);
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn load_or_create_key(home: &Path) -> Result<Zeroizing<[u8; KEY_BYTES]>> {
    let identity_path = home.join("identity");
    let identity_dir = crate::skills::store::open_bound_directory_from_trusted_anchor(
        home,
        &identity_path,
        true,
        "provider-subject identity directory",
    )?
    .context("provider-subject identity directory was not created")?;
    let name = OsStr::new(KEY_FILE);
    let display_path = identity_dir.display_path.join(name);

    match identity_dir.dir.symlink_metadata(name) {
        Ok(_) => return load_key(&identity_dir),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!("inspect provider-subject key {}", display_path.display())
            });
        }
    }

    let mut generated = Zeroizing::new([0u8; KEY_BYTES]);
    getrandom::getrandom(&mut *generated)
        .map_err(|error| anyhow::anyhow!("mint provider-subject key from OS RNG: {error}"))?;
    match crate::skills::store::create_private_regular_file_child_create_new(
        &identity_dir.dir,
        name,
        &display_path,
    ) {
        Ok((mut file, binding)) => {
            file.write_all(&*generated).with_context(|| {
                format!("write provider-subject key {}", display_path.display())
            })?;
            file.sync_all()
                .with_context(|| format!("sync provider-subject key {}", display_path.display()))?;
            anyhow::ensure!(
                binding.matches_regular_file_child_readonly(
                    &identity_dir.dir,
                    name,
                    &display_path
                )?,
                "provider-subject key changed before durable publication: {}",
                display_path.display()
            );
            crate::skills::store::sync_parent_directory(
                &identity_dir.dir,
                &identity_dir.display_path,
            )
            .context("sync provider-subject identity directory")?;
            drop(file);

            let loaded = load_key(&identity_dir)?;
            anyhow::ensure!(
                *loaded == *generated,
                "provider-subject key readback mismatch after creation"
            );
            Ok(loaded)
        }
        Err(create_error) => {
            // A concurrent process may have won CREATE_NEW. Accept only the
            // fully validated winner; every malformed or link-like winner
            // remains a fail-closed error.
            load_key(&identity_dir).with_context(|| {
                format!(
                    "provider-subject key create failed ({create_error:#}) and no valid concurrent winner exists"
                )
            })
        }
    }
}

fn update_field(mac: &mut Hmac<Sha256>, name: &[u8], value: &[u8]) {
    mac.update(&(name.len() as u64).to_be_bytes());
    mac.update(name);
    mac.update(&(value.len() as u64).to_be_bytes());
    mac.update(value);
}

/// Derive a stable, installation-local identifier for one authenticated
/// principal and one exact upstream provider domain.
pub(crate) fn derive(
    home: &Path,
    provider: &'static str,
    principal: &str,
) -> Result<ProviderSubjectIdentifier> {
    let principal = principal.trim();
    anyhow::ensure!(!provider.is_empty(), "provider subject domain is empty");
    anyhow::ensure!(!principal.is_empty(), "provider subject principal is empty");
    anyhow::ensure!(
        principal.len() <= 4096,
        "provider subject principal exceeds 4096 bytes"
    );

    let key = load_or_create_key(home)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&*key).expect("HMAC-SHA256 accepts 32-byte keys");
    update_field(&mut mac, b"schema", SUBJECT_SCHEMA);
    update_field(&mut mac, b"provider", provider.as_bytes());
    update_field(&mut mac, b"principal", principal.as_bytes());
    let value = hex::encode(mac.finalize().into_bytes());
    debug_assert_eq!(value.len(), 64);
    debug_assert!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    Ok(ProviderSubjectIdentifier { provider, value })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifier_is_stable_private_and_domain_separated() {
        let home = tempfile::tempdir().unwrap();
        let raw = "alice@example.test";
        let first = derive(home.path(), "openai_api", raw).unwrap();
        let second = derive(home.path(), "openai_api", raw).unwrap();
        let other_principal = derive(home.path(), "openai_api", "bob@example.test").unwrap();
        let other_provider = derive(home.path(), "other_provider", raw).unwrap();

        let value = first.wire_value_for("openai_api").unwrap();
        assert_eq!(value, second.wire_value_for("openai_api").unwrap());
        assert_eq!(value.len(), 64);
        assert!(value.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(!value.contains(raw));
        assert_ne!(value, other_principal.wire_value_for("openai_api").unwrap());
        assert_ne!(
            value,
            other_provider.wire_value_for("other_provider").unwrap()
        );
        assert!(first.wire_value_for("openai_api_custom").is_none());
        assert!(!format!("{first:?}").contains(value));
    }

    #[test]
    fn malformed_existing_key_fails_closed_without_replacement() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir(home.path().join("identity")).unwrap();
        let key_path = home.path().join("identity").join(KEY_FILE);
        std::fs::write(&key_path, b"short").unwrap();
        #[cfg(windows)]
        crate::wal::win_native::set_private_current_user_dacl(&key_path).unwrap();
        let before = std::fs::read(&key_path).unwrap();

        let error = derive(home.path(), "openai_api", "alice")
            .unwrap_err()
            .to_string();
        assert!(error.contains("exactly 32 bytes"), "{error}");
        assert_eq!(std::fs::read(key_path).unwrap(), before);
    }
}
