//! Authenticated credential hand-off for a Paperless generation created by a
//! completed purge.  The marker is deliberately secret-free: it authorizes
//! replacing precisely the credential which existed before the new volumes
//! were created, and nothing else.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{
    config::{FreedomConfig, SecretsBackend, credentials::Credentials},
    secret::SecretString,
};

use super::*;

pub(crate) const GENERATION_AUTH_NAME: &str = ".neoth-paperless-generation-auth.v1.json";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum GenerationAuthPhase {
    RotationAuthorized,
    TokenAuthorized,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct GenerationAuthMarker {
    schema_version: u8,
    operation: String,
    phase: GenerationAuthPhase,
    project: String,
    volume_set_id: String,
    snapshot_sha256: String,
    backend: Option<SecretsBackend>,
    origin: Option<String>,
    old_token_sha256: Option<String>,
    new_token_sha256: Option<String>,
}

/// A lifecycle-local capability. It contains only token fingerprints and is
/// valid only while the on-disk marker still validates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FreshGenerationTokenGrant {
    project: String,
    volume_set_id: String,
    snapshot_sha256: String,
    backend: SecretsBackend,
    origin: String,
    old_token_sha256: String,
}

/// Called by generation rotation before it retires the completed journal.
/// A pre-existing completed install receipt proves this is not a fresh
/// generation and is never silently adopted.
pub(crate) fn emit_rotation_marker(
    root: &OwnedPaperlessRoot,
    project: &str,
    volume_set_id: &str,
    snapshot_bytes: &[u8],
) -> Result<(), LifecycleError> {
    if !paperless_staging::valid_volume_set_id(volume_set_id)
        || project != project_name(&root.display)
        || read_optional_auth_child(root, RECEIPT_NAME)?.is_some()
    {
        return Err(LifecycleError::Receipt);
    }
    let snapshot: PaperlessVolumeSetSnapshot =
        serde_json::from_slice(snapshot_bytes).map_err(|_| LifecycleError::Receipt)?;
    validate_volume_set_snapshot(&snapshot, project)?;
    if snapshot.volume_set_id != volume_set_id {
        return Err(LifecycleError::Receipt);
    }
    let marker = GenerationAuthMarker {
        schema_version: 1,
        operation: "paperless.fresh_generation_auth".to_owned(),
        phase: GenerationAuthPhase::RotationAuthorized,
        project: project.to_owned(),
        volume_set_id: volume_set_id.to_owned(),
        snapshot_sha256: sha256_auth(snapshot_bytes),
        backend: None,
        origin: None,
        old_token_sha256: None,
        new_token_sha256: None,
    };
    match read_marker(root)? {
        Some(existing) => {
            validate_marker_snapshot(root, &existing)?;
            if existing.project == marker.project
                && existing.volume_set_id == marker.volume_set_id
                && existing.snapshot_sha256 == marker.snapshot_sha256
            {
                Ok(())
            } else {
                Err(LifecycleError::Receipt)
            }
        }
        None => write_auth_create_new(root, &marker),
    }
}

pub(super) fn has_pending_marker(root: &OwnedPaperlessRoot) -> Result<bool, LifecycleError> {
    match read_marker(root)? {
        Some(marker) => {
            validate_marker_snapshot(root, &marker)?;
            Ok(true)
        }
        None => Ok(false),
    }
}
/// Bind the marker to the effective pre-purge credential immediately before
/// the loopback API is asked for a replacement token.
pub(crate) fn begin_fresh_generation_token(
    root: &OwnedPaperlessRoot,
    backend: SecretsBackend,
    expected_url: Option<&str>,
    origin: &str,
    old_token: Option<&SecretString>,
) -> Result<Option<FreshGenerationTokenGrant>, &'static str> {
    let Some(mut marker) = read_marker(root).map_err(|_| "paperless_generation_auth_receipt")?
    else {
        return Ok(None);
    };
    let origin = canonical_generation_origin(origin)?;
    validate_marker_snapshot(root, &marker).map_err(|_| "paperless_generation_auth_receipt")?;
    if read_optional_auth_child(root, RECEIPT_NAME)
        .map_err(|_| "paperless_generation_auth_receipt")?
        .is_some()
    {
        read_completed_install_for_volume_set(root)
            .map_err(|_| "paperless_generation_auth_receipt")?;
        return Err("paperless_generation_auth_receipt");
    }
    let current_token = old_token.ok_or("paperless_generation_auth_old_token_missing")?;
    if current_token.expose_secret().is_empty() {
        return Err("paperless_generation_auth_old_token_missing");
    }
    if expected_url.is_some_and(|url| url != origin) {
        return Err("paperless_generation_auth_url_changed");
    }
    let current_token_sha256 = sha256_auth(current_token.expose_secret().as_bytes());
    match marker.phase {
        GenerationAuthPhase::RotationAuthorized => {
            marker.phase = GenerationAuthPhase::TokenAuthorized;
            marker.backend = Some(backend);
            marker.origin = Some(origin.clone());
            marker.old_token_sha256 = Some(current_token_sha256.clone());
            write_auth_replace(root, &marker).map_err(|_| "paperless_generation_auth_receipt")?;
        }
        GenerationAuthPhase::TokenAuthorized => {
            if marker.backend != Some(backend)
                || marker.origin.as_deref() != Some(origin.as_str())
                || !fingerprint_is_old_or_new(&marker, &current_token_sha256)
            {
                return Err("paperless_generation_auth_binding_changed");
            }
        }
    }
    Ok(Some(FreshGenerationTokenGrant {
        project: marker.project,
        volume_set_id: marker.volume_set_id,
        snapshot_sha256: marker.snapshot_sha256,
        backend,
        origin,
        old_token_sha256: marker
            .old_token_sha256
            .ok_or("paperless_generation_auth_receipt")?,
    }))
}

/// True when a resumed process has already loaded the token whose fingerprint
/// was recorded before the previous process attempted its credential CAS.
pub(crate) fn token_is_persisted_new(
    root: &OwnedPaperlessRoot,
    grant: &FreshGenerationTokenGrant,
    token: &SecretString,
) -> Result<bool, &'static str> {
    let marker = validated_bound_marker(root, grant)?;
    Ok(marker.new_token_sha256.as_deref()
        == Some(sha256_auth(token.expose_secret().as_bytes()).as_str()))
}

/// Record the replacement fingerprint before touching either credential
/// backend. A retry accepts the same issued token and rejects substitution.
pub(crate) fn record_new_token_fingerprint(
    root: &OwnedPaperlessRoot,
    grant: &FreshGenerationTokenGrant,
    token: &SecretString,
) -> Result<(), &'static str> {
    if token.expose_secret().is_empty() {
        return Err("paperless_generation_auth_token_invalid");
    }
    let mut marker = validated_bound_marker(root, grant)?;
    let fingerprint = sha256_auth(token.expose_secret().as_bytes());
    match marker.new_token_sha256.as_deref() {
        None => {
            marker.new_token_sha256 = Some(fingerprint);
            write_auth_replace(root, &marker).map_err(|_| "paperless_generation_auth_receipt")
        }
        Some(existing) if existing == fingerprint => Ok(()),
        Some(_) => Err("paperless_generation_auth_new_token_changed"),
    }
}

/// CAS-replace the stale token only after its successor was durably bound to
/// the fresh generation marker. File credentials retain every other key;
/// keychain mode reads and writes the same store under config authority.
pub(crate) fn persist_fresh_generation_token_at(
    home: &Path,
    root: &OwnedPaperlessRoot,
    grant: &FreshGenerationTokenGrant,
    new_token: &SecretString,
) -> Result<(), &'static str> {
    let marker = validated_bound_marker(root, grant)?;
    if marker.new_token_sha256.as_deref()
        != Some(sha256_auth(new_token.expose_secret().as_bytes()).as_str())
    {
        return Err("paperless_generation_auth_new_token_unbound");
    }
    match grant.backend {
        SecretsBackend::File => persist_file_generation_token(home, grant, new_token),
        SecretsBackend::Keychain => persist_keychain_generation_token(home, grant, new_token),
    }
}

/// Retire only after the exact locally-written, authenticated lifecycle
/// receipt proves the marker's volume generation reached readiness.
pub(crate) fn retire_after_authenticated_receipt(
    root: &OwnedPaperlessRoot,
    receipt: &PaperlessLifecycleReceipt,
) -> Result<(), LifecycleError> {
    let Some(marker) = read_marker(root)? else {
        return Ok(());
    };
    validate_marker_snapshot(root, &marker)?;
    if marker.phase != GenerationAuthPhase::TokenAuthorized
        || marker.new_token_sha256.is_none()
        || !receipt.authenticated_api_ready
        || receipt.project != marker.project
        || receipt.volume_set_id.as_deref() != Some(marker.volume_set_id.as_str())
    {
        return Err(LifecycleError::Receipt);
    }
    let persisted = read_optional_auth_child(root, RECEIPT_NAME)?.ok_or(LifecycleError::Receipt)?;
    let exact = serde_json::to_vec(receipt).map_err(|_| LifecycleError::Io)?;
    if persisted != exact {
        return Err(LifecycleError::Receipt);
    }
    remove_auth_child(root)
}

/// Recover the narrow crash window after the receipt was committed but before
/// marker retirement. The caller supplies the freshly loaded effective token;
/// an old or third-party value cannot retire the marker.
pub(crate) fn retire_if_completed_receipt_matches(
    root: &OwnedPaperlessRoot,
    current_token: &SecretString,
) -> Result<bool, LifecycleError> {
    let Some(marker) = read_marker(root)? else {
        return Ok(false);
    };
    validate_marker_snapshot(root, &marker)?;
    if marker.phase != GenerationAuthPhase::TokenAuthorized
        || marker.new_token_sha256.as_deref()
            != Some(sha256_auth(current_token.expose_secret().as_bytes()).as_str())
    {
        return Ok(false);
    }
    let Some(receipt) = read_completed_install_for_volume_set(root)? else {
        return Ok(false);
    };
    if !receipt.authenticated_api_ready
        || receipt.project != marker.project
        || receipt.volume_set_id.as_deref() != Some(marker.volume_set_id.as_str())
    {
        return Err(LifecycleError::Receipt);
    }
    remove_auth_child(root)?;
    Ok(true)
}

fn persist_file_generation_token(
    home: &Path,
    grant: &FreshGenerationTokenGrant,
    new_token: &SecretString,
) -> Result<(), &'static str> {
    Credentials::update_raw_freedom_with_credentials_at(
        &home.join("freedom.yaml"),
        &home.join("credentials.yaml"),
        |source, credentials| {
            let backend = source
                .map(serde_yaml::from_str::<FreedomConfig>)
                .transpose()
                .map_err(|_| anyhow::anyhow!("paperless_generation_auth_config_invalid"))?
                .map(|config| config.secrets_backend)
                .unwrap_or(SecretsBackend::File);
            if backend != SecretsBackend::File
                || credentials.paperless_url.as_deref() != Some(&grant.origin)
            {
                return Err(anyhow::anyhow!("paperless_generation_auth_binding_changed"));
            }
            match credentials
                .paperless_token
                .as_ref()
                .map(|current| sha256_auth(current.expose_secret().as_bytes()))
            {
                Some(current) if current == grant.old_token_sha256 => {
                    credentials.paperless_token = Some(new_token.clone());
                }
                Some(current) if current == sha256_auth(new_token.expose_secret().as_bytes()) => {}
                _ => return Err(anyhow::anyhow!("paperless_generation_auth_token_conflict")),
            }
            Ok((None, ()))
        },
    )
    .map_err(map_generation_auth_error)
}

fn persist_keychain_generation_token(
    home: &Path,
    grant: &FreshGenerationTokenGrant,
    new_token: &SecretString,
) -> Result<(), &'static str> {
    let store =
        crate::config::keychain::open_store().map_err(|_| "paperless_generation_auth_keychain")?;
    persist_keychain_generation_token_with_store(home, grant, new_token, store.as_ref())
}

fn persist_keychain_generation_token_with_store(
    home: &Path,
    grant: &FreshGenerationTokenGrant,
    new_token: &SecretString,
    store: &dyn crate::config::keychain::SecretStore,
) -> Result<(), &'static str> {
    crate::config::with_current_freedom_config_authority_locked_with_store(
        &home.join("freedom.yaml"),
        Some(store),
        |config, effective| {
            if config.secrets_backend != SecretsBackend::Keychain
                || effective.paperless_url.as_deref() != Some(&grant.origin)
            {
                return Err(anyhow::anyhow!("paperless_generation_auth_binding_changed"));
            }
            let current = store
                .get("paperless_token")
                .map_err(|_| anyhow::anyhow!("paperless_generation_auth_keychain"))?;
            if effective
                .paperless_token
                .as_ref()
                .map(|token| token.expose_secret())
                != current.as_ref().map(|token| token.expose_secret())
            {
                return Err(anyhow::anyhow!("paperless_generation_auth_binding_changed"));
            }
            match current.map(|token| sha256_auth(token.expose_secret().as_bytes())) {
                Some(current) if current == grant.old_token_sha256 => store
                    .set("paperless_token", new_token)
                    .map_err(|_| anyhow::anyhow!("paperless_generation_auth_keychain")),
                Some(current) if current == sha256_auth(new_token.expose_secret().as_bytes()) => {
                    Ok(())
                }
                _ => Err(anyhow::anyhow!("paperless_generation_auth_token_conflict")),
            }
        },
    )
    .map_err(map_generation_auth_error)
}

fn map_generation_auth_error(error: anyhow::Error) -> &'static str {
    match error.to_string().as_str() {
        "paperless_generation_auth_config_invalid" => "paperless_generation_auth_config_invalid",
        "paperless_generation_auth_binding_changed" => "paperless_generation_auth_binding_changed",
        "paperless_generation_auth_keychain" => "paperless_generation_auth_keychain",
        "paperless_generation_auth_token_conflict" => "paperless_generation_auth_token_conflict",
        _ => "paperless_generation_auth_persist",
    }
}

fn validated_bound_marker(
    root: &OwnedPaperlessRoot,
    grant: &FreshGenerationTokenGrant,
) -> Result<GenerationAuthMarker, &'static str> {
    let marker = read_marker(root)
        .map_err(|_| "paperless_generation_auth_receipt")?
        .ok_or("paperless_generation_auth_receipt")?;
    validate_marker_snapshot(root, &marker).map_err(|_| "paperless_generation_auth_receipt")?;
    if marker.phase != GenerationAuthPhase::TokenAuthorized
        || marker.project != grant.project
        || marker.volume_set_id != grant.volume_set_id
        || marker.snapshot_sha256 != grant.snapshot_sha256
        || marker.backend != Some(grant.backend)
        || marker.origin.as_deref() != Some(grant.origin.as_str())
        || marker.old_token_sha256.as_deref() != Some(grant.old_token_sha256.as_str())
    {
        return Err("paperless_generation_auth_binding_changed");
    }
    Ok(marker)
}

fn validate_marker_snapshot(
    root: &OwnedPaperlessRoot,
    marker: &GenerationAuthMarker,
) -> Result<(), LifecycleError> {
    if marker.schema_version != 1
        || marker.operation != "paperless.fresh_generation_auth"
        || marker.project != project_name(&root.display)
        || !paperless_staging::valid_volume_set_id(&marker.volume_set_id)
        || marker.snapshot_sha256.len() != 64
        || !marker
            .snapshot_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(LifecycleError::Receipt);
    }
    let bytes = read_optional_auth_child(root, VOLUME_SET_NAME)?.ok_or(LifecycleError::Receipt)?;
    let snapshot: PaperlessVolumeSetSnapshot =
        serde_json::from_slice(&bytes).map_err(|_| LifecycleError::Receipt)?;
    validate_volume_set_snapshot(&snapshot, &marker.project)?;
    if snapshot.volume_set_id != marker.volume_set_id
        || sha256_auth(&bytes) != marker.snapshot_sha256
    {
        return Err(LifecycleError::Receipt);
    }
    match marker.phase {
        GenerationAuthPhase::RotationAuthorized => {
            if marker.backend.is_some()
                || marker.origin.is_some()
                || marker.old_token_sha256.is_some()
                || marker.new_token_sha256.is_some()
            {
                return Err(LifecycleError::Receipt);
            }
        }
        GenerationAuthPhase::TokenAuthorized => {
            if marker.backend.is_none()
                || marker
                    .origin
                    .as_deref()
                    .and_then(|origin| canonical_generation_origin(origin).ok())
                    .as_deref()
                    != marker.origin.as_deref()
                || !valid_fingerprint(marker.old_token_sha256.as_deref())
                || marker
                    .new_token_sha256
                    .as_deref()
                    .is_some_and(|value| !valid_fingerprint(Some(value)))
            {
                return Err(LifecycleError::Receipt);
            }
        }
    }
    Ok(())
}

fn valid_fingerprint(value: Option<&str>) -> bool {
    value.is_some_and(|value| {
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}
fn fingerprint_is_old_or_new(marker: &GenerationAuthMarker, current: &str) -> bool {
    marker.old_token_sha256.as_deref() == Some(current)
        || marker.new_token_sha256.as_deref() == Some(current)
}
fn canonical_generation_origin(origin: &str) -> Result<String, &'static str> {
    super::paperless_bootstrap::canonical_bootstrap_origin(origin)
}
fn sha256_auth(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn auth_state(root: &OwnedPaperlessRoot) -> Result<cap_std::fs::Dir, LifecycleError> {
    lifecycle_state_dir(root)
}
fn read_optional_auth_child(
    root: &OwnedPaperlessRoot,
    name: &str,
) -> Result<Option<Vec<u8>>, LifecycleError> {
    let state = auth_state(root)?;
    match crate::skills::store::read_regular_file_bounded(
        &state,
        OsStr::new(name),
        &root.display.join(RECEIPT_DIR).join(name),
        RECEIPT_READ_LIMIT,
    ) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error)
            if error
                .root_cause()
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(_) => Err(LifecycleError::Receipt),
    }
}
fn read_marker(root: &OwnedPaperlessRoot) -> Result<Option<GenerationAuthMarker>, LifecycleError> {
    read_optional_auth_child(root, GENERATION_AUTH_NAME)?
        .map(|bytes| serde_json::from_slice(&bytes).map_err(|_| LifecycleError::Receipt))
        .transpose()
}
fn write_auth_create_new(
    root: &OwnedPaperlessRoot,
    marker: &GenerationAuthMarker,
) -> Result<(), LifecycleError> {
    let state = auth_state(root)?;
    crate::skills::store::atomic_write_private_child_create_new(
        &state,
        OsStr::new(GENERATION_AUTH_NAME),
        &root.display.join(RECEIPT_DIR).join(GENERATION_AUTH_NAME),
        &serde_json::to_vec(marker).map_err(|_| LifecycleError::Io)?,
    )
    .map_err(|_| LifecycleError::Io)?;
    ensure_bound(root)
}
fn write_auth_replace(
    root: &OwnedPaperlessRoot,
    marker: &GenerationAuthMarker,
) -> Result<(), LifecycleError> {
    let state = auth_state(root)?;
    crate::skills::store::atomic_write_private_child(
        &state,
        OsStr::new(GENERATION_AUTH_NAME),
        &root.display.join(RECEIPT_DIR).join(GENERATION_AUTH_NAME),
        &serde_json::to_vec(marker).map_err(|_| LifecycleError::Io)?,
    )
    .map_err(|_| LifecycleError::Io)?;
    ensure_bound(root)
}
fn remove_auth_child(root: &OwnedPaperlessRoot) -> Result<(), LifecycleError> {
    let state = auth_state(root)?;
    crate::skills::store::remove_child_file(
        &state,
        OsStr::new(GENERATION_AUTH_NAME),
        &root.display.join(RECEIPT_DIR).join(GENERATION_AUTH_NAME),
    )
    .map_err(|_| LifecycleError::Io)?;
    ensure_bound(root)
}

#[cfg(test)]
#[path = "paperless_generation_auth_tests.rs"]
mod tests;
