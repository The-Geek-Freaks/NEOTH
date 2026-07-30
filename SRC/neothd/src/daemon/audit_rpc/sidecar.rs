//! AUDIT-RPC-01 — strict V2 discovery for the local audit endpoint.
//!
//! The sidecar contains no TCP address, port, bearer token, or token hint. It
//! advertises only the typed same-user OS endpoint, the owning daemon PID, and
//! the endpoint nonce that binds the transport namespace to this daemon boot.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::token::rpc_token_path;
use super::transport::AuditEndpointV2;

const SIDECAR_SCHEMA_VERSION: u8 = 2;
const SIDECAR_FILE_NAME: &str = "audit_rpc.endpoint.v2.json";
const LEGACY_SIDECAR_FILE_NAME: &str = "audit_rpc.port";
const MAX_SIDECAR_BYTES: usize = 4 * 1024;

/// The validated discovery record returned to audit-RPC clients.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AuditRpcSidecarV2 {
    pub(crate) endpoint: AuditEndpointV2,
    pub(crate) pid: u32,
    pub(crate) endpoint_nonce: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditRpcSidecarWireV2 {
    schema_version: u8,
    daemon_pid: u32,
    endpoint_nonce: String,
    endpoint: AuditEndpointV2,
}

/// `~/.neoth/audit_rpc.endpoint.v2.json`.
pub fn sidecar_path(home: &Path) -> PathBuf {
    home.join(SIDECAR_FILE_NAME)
}

fn validate_endpoint_nonce(endpoint_nonce: &str) -> Result<()> {
    if endpoint_nonce.len() != 32
        || !endpoint_nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        anyhow::bail!("audit-RPC endpoint nonce must be 32 lowercase hex characters");
    }
    Ok(())
}

fn validate_record(
    home: &Path,
    endpoint: &AuditEndpointV2,
    pid: u32,
    endpoint_nonce: &str,
) -> Result<()> {
    if pid == 0 {
        anyhow::bail!("audit-RPC sidecar daemon PID must be non-zero");
    }
    validate_endpoint_nonce(endpoint_nonce)?;
    endpoint
        .validate(home, endpoint_nonce)
        .context("validate typed audit-RPC endpoint")?;
    Ok(())
}

/// Durably publish the daemon's typed local endpoint.
///
/// The private sibling is synced before an atomic replacement. The committed
/// file is then re-opened through the already-bound home-directory capability,
/// compared byte-for-byte, and the namespace commit is synced. An error after
/// the rename therefore means "committed but durability unconfirmed", never a
/// silently successful partial publication.
pub(crate) fn write_sidecar(
    home: &Path,
    endpoint: &AuditEndpointV2,
    pid: u32,
    endpoint_nonce: &str,
) -> Result<()> {
    validate_record(home, endpoint, pid, endpoint_nonce)?;

    let wire = AuditRpcSidecarWireV2 {
        schema_version: SIDECAR_SCHEMA_VERSION,
        daemon_pid: pid,
        endpoint_nonce: endpoint_nonce.to_owned(),
        endpoint: endpoint.clone(),
    };
    let body = serde_json::to_vec(&wire).context("serialize audit-RPC V2 sidecar")?;
    if body.len() > MAX_SIDECAR_BYTES {
        anyhow::bail!(
            "audit-RPC V2 sidecar is {} bytes, exceeding the {MAX_SIDECAR_BYTES}-byte limit",
            body.len()
        );
    }

    let trusted_anchor = home.parent().unwrap_or(home);
    let bound = crate::skills::store::open_bound_directory_from_trusted_anchor(
        trusted_anchor,
        home,
        true,
        "audit-RPC sidecar directory",
    )?
    .context("audit-RPC sidecar directory was not created")?;
    let path = bound.display_path.join(SIDECAR_FILE_NAME);
    crate::skills::store::atomic_write_private_child(
        &bound.dir,
        OsStr::new(SIDECAR_FILE_NAME),
        &path,
        &body,
    )
    .with_context(|| {
        format!(
            "atomically write capability-bound private audit-RPC sidecar {}",
            path.display()
        )
    })?;

    let persisted = crate::skills::store::read_regular_file_bounded(
        &bound.dir,
        OsStr::new(SIDECAR_FILE_NAME),
        &path,
        MAX_SIDECAR_BYTES,
    )
    .context("verify committed audit-RPC sidecar through its bound directory")?;
    if persisted != body {
        anyhow::bail!(
            "audit-RPC sidecar namespace changed during publication at {}",
            path.display()
        );
    }
    crate::skills::store::sync_parent_directory(&bound.dir, &bound.display_path)
        .context("make audit-RPC sidecar namespace commit durable")?;
    Ok(())
}

/// Read and validate the strict V2 discovery record.
///
/// Every path component and the leaf are opened without following links or
/// Windows reparse points. The bounded read happens before JSON parsing, so a
/// FIFO/device or oversized attacker-controlled file cannot consume unbounded
/// memory or block a client. Missing, legacy, downgraded, or extended schemas
/// fail closed.
pub(crate) fn read_sidecar(home: &Path) -> Result<AuditRpcSidecarV2> {
    let bound =
        crate::skills::store::open_bound_directory(home, false, "audit-RPC sidecar directory")?
            .with_context(|| {
                format!(
                    "audit-RPC sidecar directory is absent at {}",
                    home.display()
                )
            })?;
    let path = bound.display_path.join(SIDECAR_FILE_NAME);
    let body = crate::skills::store::read_regular_file_bounded(
        &bound.dir,
        OsStr::new(SIDECAR_FILE_NAME),
        &path,
        MAX_SIDECAR_BYTES,
    )
    .with_context(|| format!("read bounded audit-RPC V2 sidecar {}", path.display()))?;
    let wire: AuditRpcSidecarWireV2 =
        serde_json::from_slice(&body).context("parse strict audit-RPC V2 sidecar JSON")?;
    if wire.schema_version != SIDECAR_SCHEMA_VERSION {
        anyhow::bail!(
            "unsupported audit-RPC sidecar schema {}; expected {SIDECAR_SCHEMA_VERSION}",
            wire.schema_version
        );
    }
    validate_record(home, &wire.endpoint, wire.daemon_pid, &wire.endpoint_nonce)?;
    Ok(AuditRpcSidecarV2 {
        endpoint: wire.endpoint,
        pid: wire.daemon_pid,
        endpoint_nonce: wire.endpoint_nonce,
    })
}

fn remove_discovery_child(
    bound: &crate::skills::store::BoundDirectory,
    name: &str,
) -> Result<bool> {
    let path = bound.display_path.join(name);
    match crate::skills::store::remove_child_file(&bound.dir, OsStr::new(name), &path) {
        Ok(()) => Ok(true),
        Err(error)
            if error.chain().any(|source| {
                source
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
            }) =>
        {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

fn remove_sidecar_inner(home: &Path) -> Result<()> {
    let Some(bound) =
        crate::skills::store::open_bound_directory(home, false, "audit-RPC sidecar directory")?
    else {
        return Ok(());
    };

    // Never parse or trust the obsolete TCP discovery record. Removing the
    // no-follow leaf during startup is the complete one-way migration.
    let current_result = remove_discovery_child(&bound, SIDECAR_FILE_NAME);
    let legacy_result = remove_discovery_child(&bound, LEGACY_SIDECAR_FILE_NAME);
    let removed_any = current_result.as_ref().copied().unwrap_or(false)
        || legacy_result.as_ref().copied().unwrap_or(false);
    let sync_result = if removed_any {
        crate::skills::store::sync_parent_directory(&bound.dir, &bound.display_path)
            .map(|_| ())
            .context("make audit-RPC sidecar removal durable")
    } else {
        Ok(())
    };

    current_result.context("remove current audit-RPC discovery sidecar")?;
    legacy_result.context("remove obsolete audit-RPC TCP discovery sidecar")?;
    sync_result?;
    Ok(())
}

/// Remove only the endpoint sidecar (best effort).
///
/// Bearer-token ownership belongs to the listener lifecycle, not to generic
/// discovery cleanup. [`SidecarGuard`] removes that defense-in-depth token only
/// after it has aborted the listener that could still accept it.
pub fn remove_sidecar(home: &Path) {
    if let Err(error) = remove_sidecar_inner(home) {
        tracing::warn!(
            path = %sidecar_path(home).display(),
            error = %error,
            "failed to remove audit-RPC sidecar"
        );
    }
}

/// RAII guard that stops the listener, then removes discovery and bearer state.
pub struct SidecarGuard {
    home: PathBuf,
    listener_abort: Option<tokio::task::AbortHandle>,
}

impl SidecarGuard {
    pub fn new(home: PathBuf) -> Self {
        Self {
            home,
            listener_abort: None,
        }
    }

    /// Bind discovery cleanup to the listener lifetime. This is used by the
    /// daemon startup path so any later `?` return aborts the already-published
    /// endpoint instead of detaching an undiscoverable task that still owns a
    /// WAL sender.
    pub(crate) fn with_listener(home: PathBuf, listener_abort: tokio::task::AbortHandle) -> Self {
        Self {
            home,
            listener_abort: Some(listener_abort),
        }
    }
}

impl Drop for SidecarGuard {
    fn drop(&mut self) {
        if let Some(abort) = self.listener_abort.take() {
            abort.abort();
        }
        remove_sidecar(&self.home);
        let token_path = rpc_token_path(&self.home);
        if let Err(error) = crate::util::atomic_write::durable_remove_file(&token_path) {
            tracing::warn!(
                path = %token_path.display(),
                error = %error,
                "failed to remove stopped audit-RPC listener token"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::audit_rpc::transport::endpoint_for_home;

    const NONCE_A: &str = "00112233445566778899aabbccddeeff";
    const NONCE_B: &str = "ffeeddccbbaa99887766554433221100";

    fn home_and_endpoint(
        temporary: &tempfile::TempDir,
        endpoint_nonce: &str,
    ) -> (PathBuf, AuditEndpointV2) {
        let home = temporary.path().join(".neoth");
        std::fs::create_dir(&home).expect("create test NEOTH home");
        let endpoint =
            endpoint_for_home(&home, endpoint_nonce).expect("derive typed test endpoint");
        (home, endpoint)
    }

    fn write_raw_sidecar(home: &Path, body: &[u8]) {
        crate::util::atomic_write::atomic_write_private(&sidecar_path(home), body)
            .expect("write raw sidecar fixture");
    }

    fn valid_wire_value(endpoint: &AuditEndpointV2) -> serde_json::Value {
        serde_json::to_value(AuditRpcSidecarWireV2 {
            schema_version: SIDECAR_SCHEMA_VERSION,
            daemon_pid: 42,
            endpoint_nonce: NONCE_A.to_owned(),
            endpoint: endpoint.clone(),
        })
        .expect("serialize valid sidecar fixture")
    }

    fn assert_round_trip_for_platform() {
        let temporary = tempfile::tempdir().expect("create test directory");
        let (home, endpoint) = home_and_endpoint(&temporary, NONCE_A);

        write_sidecar(&home, &endpoint, 42, NONCE_A).expect("publish sidecar");
        let record = read_sidecar(&home).expect("read sidecar");

        assert_eq!(
            record,
            AuditRpcSidecarV2 {
                endpoint,
                pid: 42,
                endpoint_nonce: NONCE_A.to_owned(),
            }
        );
    }

    #[cfg(unix)]
    #[test]
    fn round_trips_unix_socket_variant() {
        assert_round_trip_for_platform();
    }

    #[cfg(windows)]
    #[test]
    fn round_trips_windows_named_pipe_variant() {
        assert_round_trip_for_platform();
    }

    #[test]
    fn rejects_downgraded_unknown_missing_and_legacy_schemas() {
        let temporary = tempfile::tempdir().expect("create test directory");
        let (home, endpoint) = home_and_endpoint(&temporary, NONCE_A);

        let mut downgraded = valid_wire_value(&endpoint);
        downgraded["schema_version"] = serde_json::json!(1);
        write_raw_sidecar(
            &home,
            &serde_json::to_vec(&downgraded).expect("serialize downgrade fixture"),
        );
        assert!(
            format!(
                "{:#}",
                read_sidecar(&home).expect_err("reject schema downgrade")
            )
            .contains("unsupported audit-RPC sidecar schema 1")
        );

        let mut unknown = valid_wire_value(&endpoint);
        unknown
            .as_object_mut()
            .expect("wire fixture is an object")
            .insert("port".to_owned(), serde_json::json!(54321));
        write_raw_sidecar(
            &home,
            &serde_json::to_vec(&unknown).expect("serialize unknown-field fixture"),
        );
        assert!(
            format!(
                "{:#}",
                read_sidecar(&home).expect_err("reject unknown field")
            )
            .contains("unknown field")
        );

        let mut missing = valid_wire_value(&endpoint);
        missing
            .as_object_mut()
            .expect("wire fixture is an object")
            .remove("endpoint");
        write_raw_sidecar(
            &home,
            &serde_json::to_vec(&missing).expect("serialize missing-field fixture"),
        );
        assert!(
            format!(
                "{:#}",
                read_sidecar(&home).expect_err("reject missing field")
            )
            .contains("missing field")
        );

        write_raw_sidecar(
            &home,
            br#"{"port":54321,"pid":42,"endpoint_nonce":"00112233445566778899aabbccddeeff","token_hint":"deadbeef"}"#,
        );
        assert!(
            read_sidecar(&home).is_err(),
            "legacy TCP sidecar was accepted"
        );
    }

    #[test]
    fn rejects_oversized_body_before_json_parsing() {
        let temporary = tempfile::tempdir().expect("create test directory");
        let (home, _) = home_and_endpoint(&temporary, NONCE_A);
        write_raw_sidecar(&home, &vec![b' '; MAX_SIDECAR_BYTES + 1]);

        let error = read_sidecar(&home).expect_err("reject oversized sidecar");
        assert!(
            error
                .chain()
                .filter_map(|source| source.downcast_ref::<std::io::Error>())
                .any(|io| io.kind() == std::io::ErrorKind::InvalidData),
            "unexpected oversize error: {error:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_leaf_without_reading_target() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().expect("create test directory");
        let (home, endpoint) = home_and_endpoint(&temporary, NONCE_A);
        let outside = temporary.path().join("outside.json");
        std::fs::write(
            &outside,
            serde_json::to_vec(&valid_wire_value(&endpoint)).expect("serialize outside fixture"),
        )
        .expect("write outside fixture");
        symlink(&outside, sidecar_path(&home)).expect("create sidecar symlink");

        assert!(
            read_sidecar(&home).is_err(),
            "sidecar reader followed symlink"
        );
    }

    #[cfg(windows)]
    #[test]
    fn rejects_reparse_leaf_without_reading_target_when_supported() {
        use std::os::windows::fs::symlink_file;

        let temporary = tempfile::tempdir().expect("create test directory");
        let (home, endpoint) = home_and_endpoint(&temporary, NONCE_A);
        let outside = temporary.path().join("outside.json");
        std::fs::write(
            &outside,
            serde_json::to_vec(&valid_wire_value(&endpoint)).expect("serialize outside fixture"),
        )
        .expect("write outside fixture");
        match symlink_file(&outside, sidecar_path(&home)) {
            Ok(()) => assert!(
                read_sidecar(&home).is_err(),
                "sidecar reader followed Windows reparse leaf"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {}
            Err(error) => panic!("create Windows reparse fixture: {error}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn sidecar_publish_rejects_a_symlinked_neoth_home() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().expect("create test directory");
        let outside = tempfile::tempdir().expect("create outside directory");
        let home = temporary.path().join(".neoth");
        symlink(outside.path(), &home).expect("create planted NEOTH-home symlink");
        let endpoint = endpoint_for_home(&home, NONCE_A).expect("derive typed test endpoint");

        let error = write_sidecar(&home, &endpoint, 42, NONCE_A)
            .expect_err("explicit trusted anchor must reject a symlinked NEOTH home");

        assert!(format!("{error:#}").contains("audit-RPC sidecar directory"));
        assert!(!outside.path().join(SIDECAR_FILE_NAME).exists());
    }

    #[cfg(windows)]
    #[test]
    fn sidecar_publish_rejects_a_reparse_neoth_home_when_supported() {
        use std::os::windows::fs::symlink_dir;

        let temporary = tempfile::tempdir().expect("create test directory");
        let outside = tempfile::tempdir().expect("create outside directory");
        let home = temporary.path().join(".neoth");
        match symlink_dir(outside.path(), &home) {
            Ok(()) => {
                let endpoint =
                    endpoint_for_home(&home, NONCE_A).expect("derive typed test endpoint");
                let error = write_sidecar(&home, &endpoint, 42, NONCE_A)
                    .expect_err("explicit trusted anchor must reject a reparse NEOTH home");
                assert!(format!("{error:#}").contains("audit-RPC sidecar directory"));
                assert!(!outside.path().join(SIDECAR_FILE_NAME).exists());
            }
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {}
            Err(error) => panic!("create planted Windows NEOTH-home reparse point: {error}"),
        }
    }

    #[test]
    fn sidecar_contains_no_tcp_or_bearer_material() {
        let temporary = tempfile::tempdir().expect("create test directory");
        let (home, endpoint) = home_and_endpoint(&temporary, NONCE_A);
        write_sidecar(&home, &endpoint, 42, NONCE_A).expect("publish sidecar");

        let body = std::fs::read_to_string(sidecar_path(&home)).expect("read raw sidecar");
        assert!(!body.contains("\"port\":"));
        assert!(!body.contains("token_hint"));
        assert!(!body.contains("bearer"));
        assert!(!body.contains("secret"));
        assert!(!body.contains("127.0.0.1"));
        assert!(!sidecar_path(&home).to_string_lossy().contains(".port"));
    }

    #[test]
    fn create_and_replace_are_atomic_private_and_namespace_synced() {
        let temporary = tempfile::tempdir().expect("create test directory");
        let (home, endpoint_a) = home_and_endpoint(&temporary, NONCE_A);
        write_sidecar(&home, &endpoint_a, 41, NONCE_A).expect("create sidecar");
        let endpoint_b = endpoint_for_home(&home, NONCE_B).expect("derive replacement endpoint");
        write_sidecar(&home, &endpoint_b, 42, NONCE_B).expect("replace sidecar");

        assert_eq!(
            read_sidecar(&home).expect("read replacement"),
            AuditRpcSidecarV2 {
                endpoint: endpoint_b,
                pid: 42,
                endpoint_nonce: NONCE_B.to_owned(),
            }
        );
        assert!(
            std::fs::read_dir(&home)
                .expect("enumerate sidecar directory")
                .filter_map(|entry| entry.ok())
                .all(|entry| !entry.file_name().to_string_lossy().ends_with(".tmp")),
            "atomic sidecar publication left a staged sibling"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(sidecar_path(&home))
                    .expect("inspect sidecar mode")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        #[cfg(windows)]
        crate::wal::win_native::verify_private_dacl(&sidecar_path(&home))
            .expect("sidecar DACL must be current-user-only");
    }

    #[test]
    fn namespace_sync_failure_blocks_before_sidecar_publication() {
        let temporary = tempfile::tempdir().expect("create test directory");
        let (home, endpoint) = home_and_endpoint(&temporary, NONCE_A);

        crate::skills::store::force_parent_sync_failure_for_test(true);
        let result = write_sidecar(&home, &endpoint, 42, NONCE_A);
        crate::skills::store::force_parent_sync_failure_for_test(false);

        let error = result.expect_err("required parent sync failure must surface");
        assert!(
            format!("{error:#}")
                .contains("sync parent before using existing audit-RPC sidecar directory")
        );
        assert!(
            !sidecar_path(&home).exists(),
            "sidecar bytes were published below an unconfirmed NEOTH-home namespace"
        );
    }

    #[test]
    fn generic_sidecar_removal_preserves_token_but_guard_removes_it() {
        let temporary = tempfile::tempdir().expect("create test directory");
        let (home, endpoint) = home_and_endpoint(&temporary, NONCE_A);
        write_sidecar(&home, &endpoint, 42, NONCE_A).expect("publish sidecar");
        let legacy_path = home.join(LEGACY_SIDECAR_FILE_NAME);
        std::fs::write(&legacy_path, b"obsolete untrusted TCP discovery")
            .expect("write legacy sidecar fixture");
        let token_path = rpc_token_path(&home);
        std::fs::write(&token_path, b"defense-in-depth bearer").expect("write token fixture");

        remove_sidecar(&home);
        assert!(!sidecar_path(&home).exists());
        assert!(!legacy_path.exists(), "legacy TCP sidecar survived cleanup");
        assert!(
            token_path.exists(),
            "generic discovery cleanup deleted a live bearer token"
        );

        drop(SidecarGuard::new(home));
        assert!(
            !token_path.exists(),
            "listener guard left bearer token behind"
        );
    }

    #[cfg(unix)]
    #[test]
    fn legacy_cleanup_unlinks_symlink_without_touching_target() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().expect("create test directory");
        let (home, _) = home_and_endpoint(&temporary, NONCE_A);
        let outside = temporary.path().join("outside-legacy.json");
        std::fs::write(&outside, b"must survive").expect("write outside legacy target");
        let legacy_path = home.join(LEGACY_SIDECAR_FILE_NAME);
        symlink(&outside, &legacy_path).expect("create legacy sidecar symlink");

        remove_sidecar(&home);

        assert!(!legacy_path.exists(), "legacy symlink survived cleanup");
        assert_eq!(
            std::fs::read(&outside).expect("read outside legacy target"),
            b"must survive"
        );
    }

    #[cfg(windows)]
    #[test]
    fn legacy_cleanup_unlinks_reparse_leaf_without_touching_target_when_supported() {
        use std::os::windows::fs::symlink_file;

        let temporary = tempfile::tempdir().expect("create test directory");
        let (home, _) = home_and_endpoint(&temporary, NONCE_A);
        let outside = temporary.path().join("outside-legacy.json");
        std::fs::write(&outside, b"must survive").expect("write outside legacy target");
        let legacy_path = home.join(LEGACY_SIDECAR_FILE_NAME);
        match symlink_file(&outside, &legacy_path) {
            Ok(()) => {
                remove_sidecar(&home);
                assert!(
                    !legacy_path.exists(),
                    "legacy reparse leaf survived cleanup"
                );
                assert_eq!(
                    std::fs::read(&outside).expect("read outside legacy target"),
                    b"must survive"
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {}
            Err(error) => panic!("create Windows legacy reparse fixture: {error}"),
        }
    }
}
