use std::time::Duration;

use super::*;

const TEST_NONCE: &str = "0123456789abcdef0123456789abcdef";

#[test]
fn transport_sources_have_no_tcp_fallback_surface() {
    let windows_source = include_str!("windows.rs");
    let sources = [
        include_str!("mod.rs"),
        include_str!("unix.rs"),
        windows_source,
    ];
    for forbidden in [
        "TcpStream",
        "TcpListener",
        "TcpSocket",
        "SocketAddr",
        "127.0.0.1",
    ] {
        assert!(
            sources.iter().all(|source| !source.contains(forbidden)),
            "audit-RPC transport must not contain TCP fallback token {forbidden:?}"
        );
    }
    assert!(
        windows_source.contains(".reject_remote_clients(PIPE_REJECT_REMOTE_CLIENTS)"),
        "Windows audit-RPC listener must reject remote named-pipe clients"
    );
}

#[test]
fn endpoint_nonce_is_strict_lowercase_hex() {
    assert!(validate_endpoint_nonce(TEST_NONCE).is_ok());
    assert!(validate_endpoint_nonce("0123456789ABCDEF0123456789ABCDEF").is_err());
    assert!(validate_endpoint_nonce("0123456789abcdef").is_err());
    assert!(validate_endpoint_nonce("g123456789abcdef0123456789abcdef").is_err());
}

#[test]
fn blocking_exchange_bounds_are_strict() {
    let home = tempfile::tempdir().unwrap();
    let endpoint = endpoint_for_home(home.path(), TEST_NONCE).unwrap();
    assert!(
        exchange_blocking(
            &endpoint,
            &vec![0_u8; MAX_BLOCKING_REQUEST_BYTES + 1],
            1,
            Duration::from_secs(1),
        )
        .is_err()
    );
    assert!(
        exchange_blocking(
            &endpoint,
            b"",
            MAX_BLOCKING_RESPONSE_BYTES + 1,
            Duration::from_secs(1),
        )
        .is_err()
    );
    assert!(exchange_blocking(&endpoint, b"", 1, Duration::ZERO).is_err());
}

#[cfg(unix)]
#[test]
fn unix_endpoint_schema_rejects_unknown_fields_and_free_paths() {
    let home = tempfile::tempdir().unwrap();
    let endpoint = endpoint_for_home(home.path(), TEST_NONCE).unwrap();
    endpoint.validate(home.path(), TEST_NONCE).unwrap();

    let mut value = serde_json::to_value(&endpoint).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("unexpected".into(), serde_json::json!(true));
    assert!(serde_json::from_value::<AuditEndpointV2>(value).is_err());

    let AuditEndpointV2::UnixSocket {
        path: _,
        endpoint_nonce,
        home_sha256,
    } = endpoint;
    let forged = AuditEndpointV2::UnixSocket {
        path: home.path().join("attacker.sock"),
        endpoint_nonce,
        home_sha256,
    };
    assert!(forged.validate_shape().is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn unix_round_trip_attests_uid_and_enforces_private_permissions() {
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let home = tempfile::tempdir().unwrap();
    let (mut listener, endpoint) = bind(home.path(), TEST_NONCE).await.unwrap();
    let AuditEndpointV2::UnixSocket { path, .. } = &endpoint;
    let runtime_directory = path.parent().unwrap().to_path_buf();

    let runtime_metadata = std::fs::symlink_metadata(&runtime_directory).unwrap();
    assert!(runtime_metadata.file_type().is_dir());
    assert_eq!(runtime_metadata.mode() & 0o777, 0o700);
    let socket_metadata = std::fs::symlink_metadata(path).unwrap();
    assert!(socket_metadata.file_type().is_socket());
    assert_eq!(socket_metadata.mode() & 0o777, 0o600);

    let client_endpoint = endpoint.clone();
    let client = tokio::spawn(async move {
        let mut stream = connect(&client_endpoint).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut reply = [0_u8; 4];
        stream.read_exact(&mut reply).await.unwrap();
        reply
    });
    let mut server = listener.accept().await.unwrap();
    let mut request = [0_u8; 4];
    server.read_exact(&mut request).await.unwrap();
    assert_eq!(&request, b"ping");
    server.write_all(b"pong").await.unwrap();
    drop(server);
    assert_eq!(&client.await.unwrap(), b"pong");

    drop(listener);
    assert!(!path.exists());
    assert!(!runtime_directory.exists());
}

#[cfg(unix)]
#[tokio::test]
async fn unix_long_canonical_home_uses_bounded_private_runtime_socket_root() {
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::PermissionsExt as _;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let temporary = tempfile::tempdir().unwrap();
    let mut home = temporary.path().to_path_buf();
    for component in 0..8 {
        home.push(format!(
            "long-canonical-home-{component:02}-{}",
            "x".repeat(24)
        ));
        std::fs::create_dir(&home).unwrap();
    }
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
    let canonical_home = std::fs::canonicalize(&home).unwrap();
    assert!(
        canonical_home.as_os_str().as_bytes().len() > 128,
        "fixture must exceed macOS sockaddr_un pathname capacity"
    );

    let endpoint = endpoint_for_home(&canonical_home, TEST_NONCE).unwrap();
    endpoint.validate(&canonical_home, TEST_NONCE).unwrap();
    let AuditEndpointV2::UnixSocket { path, .. } = &endpoint;
    let socket_address = std::mem::MaybeUninit::<libc::sockaddr_un>::zeroed();
    // SAFETY: zeroed sockaddr_un is valid; only the fixed array length is read.
    let socket_capacity = unsafe { socket_address.assume_init_ref() }.sun_path.len();
    assert!(path.as_os_str().as_bytes().len() < socket_capacity);
    assert!(
        !path.starts_with(&canonical_home),
        "the socket path must not inherit the unbounded canonical home"
    );
    assert_eq!(
        path.parent().unwrap().parent().unwrap().parent().unwrap(),
        unix::private_runtime_root().unwrap()
    );

    let (mut listener, endpoint) = bind(&canonical_home, TEST_NONCE).await.unwrap();
    let client_endpoint = endpoint.clone();
    let client = tokio::spawn(async move {
        let mut stream = connect(&client_endpoint).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut reply = [0_u8; 4];
        stream.read_exact(&mut reply).await.unwrap();
        reply
    });
    let mut server = listener.accept().await.unwrap();
    let mut request = [0_u8; 4];
    server.read_exact(&mut request).await.unwrap();
    assert_eq!(&request, b"ping");
    server.write_all(b"pong").await.unwrap();
    drop(server);
    assert_eq!(&client.await.unwrap(), b"pong");
    drop(listener);
    assert!(!path.exists());
}

#[cfg(unix)]
#[test]
fn unix_peer_attestation_accepts_actual_uid_and_rejects_different_uid() {
    let (left, _right) = std::os::unix::net::UnixStream::pair().unwrap();
    // SAFETY: geteuid has no preconditions and cannot fail.
    let actual_uid = unsafe { libc::geteuid() };
    unix::attest_uid(&left, actual_uid).unwrap();
    let different_uid = if actual_uid == libc::uid_t::MAX {
        actual_uid - 1
    } else {
        actual_uid + 1
    };
    assert!(unix::attest_uid(&left, different_uid).is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn unix_bind_refuses_preexisting_runtime_directory() {
    use std::os::unix::fs::DirBuilderExt as _;

    let home = tempfile::tempdir().unwrap();
    let endpoint = endpoint_for_home(home.path(), TEST_NONCE).unwrap();
    let AuditEndpointV2::UnixSocket {
        path, home_sha256, ..
    } = &endpoint;
    unix::ensure_private_home_namespace(path.parent().unwrap().parent().unwrap(), home_sha256)
        .unwrap();
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(path.parent().unwrap()).unwrap();
    assert!(bind(home.path(), TEST_NONCE).await.is_err());
    std::fs::remove_dir(path.parent().unwrap()).unwrap();
    std::fs::remove_dir(path.parent().unwrap().parent().unwrap()).unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn unix_stale_cleanup_never_crosses_canonical_home_namespaces() {
    use std::os::unix::fs::DirBuilderExt as _;

    let home_a = tempfile::tempdir().unwrap();
    let home_b = tempfile::tempdir().unwrap();
    let endpoint_a = endpoint_for_home(home_a.path(), TEST_NONCE).unwrap();
    let AuditEndpointV2::UnixSocket {
        path: path_a,
        home_sha256: home_sha256_a,
        ..
    } = &endpoint_a;
    let namespace_a = path_a.parent().unwrap().parent().unwrap();
    unix::ensure_private_home_namespace(namespace_a, home_sha256_a).unwrap();
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(path_a.parent().unwrap()).unwrap();

    let (listener_b, endpoint_b) = bind(home_b.path(), TEST_NONCE).await.unwrap();
    let AuditEndpointV2::UnixSocket { path: path_b, .. } = &endpoint_b;
    assert_ne!(
        path_a.parent().unwrap().parent().unwrap(),
        path_b.parent().unwrap().parent().unwrap(),
        "distinct canonical homes must receive distinct cleanup namespaces"
    );
    assert!(
        path_a.parent().unwrap().exists(),
        "home B cleanup must not remove home A's pre-bind runtime directory"
    );

    drop(listener_b);
    std::fs::remove_dir(path_a.parent().unwrap()).unwrap();
    std::fs::remove_dir(namespace_a).unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn unix_bind_refuses_permissive_home() {
    use std::os::unix::fs::PermissionsExt as _;

    let home = tempfile::tempdir().unwrap();
    std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(bind(home.path(), TEST_NONCE).await.is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn unix_bind_removes_only_proven_stale_nonce_directories() {
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};

    const STALE_NONCE: &str = "ffeeddccbbaa99887766554433221100";
    let home = tempfile::tempdir().unwrap();
    let stale = endpoint_for_home(home.path(), STALE_NONCE).unwrap();
    let AuditEndpointV2::UnixSocket {
        path: stale_socket,
        home_sha256,
        ..
    } = &stale;
    unix::ensure_private_home_namespace(
        stale_socket.parent().unwrap().parent().unwrap(),
        home_sha256,
    )
    .unwrap();
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(stale_socket.parent().unwrap()).unwrap();
    let stale_listener = std::os::unix::net::UnixListener::bind(stale_socket).unwrap();
    std::fs::set_permissions(stale_socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    drop(stale_listener);

    let (listener, _) = bind(home.path(), TEST_NONCE).await.unwrap();
    assert!(
        !stale_socket.exists(),
        "provably stale socket must be cleaned"
    );
    assert!(
        !stale_socket.parent().unwrap().exists(),
        "empty stale nonce directory must be cleaned"
    );
    drop(listener);
}

#[cfg(unix)]
#[tokio::test]
async fn unix_cleanup_preserves_wrong_socket_type_and_unexpected_children() {
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};

    const WRONG_TYPE_NONCE: &str = "11111111111111111111111111111111";
    const EXTRA_CHILD_NONCE: &str = "22222222222222222222222222222222";
    let home = tempfile::tempdir().unwrap();

    let wrong_type = endpoint_for_home(home.path(), WRONG_TYPE_NONCE).unwrap();
    let AuditEndpointV2::UnixSocket {
        path: wrong_type_path,
        home_sha256,
        ..
    } = &wrong_type;
    unix::ensure_private_home_namespace(
        wrong_type_path.parent().unwrap().parent().unwrap(),
        home_sha256,
    )
    .unwrap();
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(wrong_type_path.parent().unwrap()).unwrap();
    std::fs::write(wrong_type_path, b"not a socket").unwrap();
    std::fs::set_permissions(wrong_type_path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let extra_child = endpoint_for_home(home.path(), EXTRA_CHILD_NONCE).unwrap();
    let AuditEndpointV2::UnixSocket {
        path: extra_child_socket,
        ..
    } = &extra_child;
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(extra_child_socket.parent().unwrap())
        .unwrap();
    std::fs::write(
        extra_child_socket.parent().unwrap().join("unexpected"),
        b"preserve",
    )
    .unwrap();

    let (listener, _) = bind(home.path(), TEST_NONCE).await.unwrap();
    assert!(wrong_type_path.exists());
    assert!(wrong_type_path.parent().unwrap().exists());
    assert!(
        extra_child_socket
            .parent()
            .unwrap()
            .join("unexpected")
            .exists()
    );
    assert!(extra_child_socket.parent().unwrap().exists());
    drop(listener);
    std::fs::remove_file(wrong_type_path).unwrap();
    std::fs::remove_dir(wrong_type_path.parent().unwrap()).unwrap();
    std::fs::remove_file(extra_child_socket.parent().unwrap().join("unexpected")).unwrap();
    std::fs::remove_dir(extra_child_socket.parent().unwrap()).unwrap();
    std::fs::remove_dir(extra_child_socket.parent().unwrap().parent().unwrap()).unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn unix_cleanup_preserves_live_old_nonce_listener() {
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};

    const LIVE_NONCE: &str = "aabbccddeeff00112233445566778899";
    let home = tempfile::tempdir().unwrap();
    let live = endpoint_for_home(home.path(), LIVE_NONCE).unwrap();
    let AuditEndpointV2::UnixSocket {
        path: live_socket,
        home_sha256,
        ..
    } = &live;
    unix::ensure_private_home_namespace(
        live_socket.parent().unwrap().parent().unwrap(),
        home_sha256,
    )
    .unwrap();
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(live_socket.parent().unwrap()).unwrap();
    let live_listener = std::os::unix::net::UnixListener::bind(live_socket).unwrap();
    std::fs::set_permissions(live_socket, std::fs::Permissions::from_mode(0o600)).unwrap();

    let (listener, _) = bind(home.path(), TEST_NONCE).await.unwrap();
    assert!(live_socket.exists(), "live old socket must be preserved");
    assert!(
        live_socket.parent().unwrap().exists(),
        "live old nonce directory must be preserved"
    );
    drop(listener);
    drop(live_listener);
    std::fs::remove_file(live_socket).unwrap();
    std::fs::remove_dir(live_socket.parent().unwrap()).unwrap();
    std::fs::remove_dir(live_socket.parent().unwrap().parent().unwrap()).unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn unix_listener_drop_does_not_remove_replacement_identities() {
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};

    let home = tempfile::tempdir().unwrap();
    let (listener, endpoint) = bind(home.path(), TEST_NONCE).await.unwrap();
    let AuditEndpointV2::UnixSocket { path, .. } = &endpoint;
    let runtime_directory = path.parent().unwrap().to_path_buf();
    let home_namespace = runtime_directory.parent().unwrap().to_path_buf();
    let relocated_original = home_namespace.join("relocated-original-audit-runtime");
    std::fs::rename(&runtime_directory, &relocated_original).unwrap();

    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(&runtime_directory).unwrap();
    let replacement_listener = std::os::unix::net::UnixListener::bind(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();

    drop(listener);
    assert!(
        path.exists(),
        "listener Drop must not unlink a replacement socket identity"
    );
    assert!(
        runtime_directory.exists(),
        "listener Drop must not remove a replacement runtime-directory identity"
    );
    drop(replacement_listener);
    std::fs::remove_file(path).unwrap();
    std::fs::remove_dir(&runtime_directory).unwrap();
    std::fs::remove_file(relocated_original.join("audit.sock")).unwrap();
    std::fs::remove_dir(relocated_original).unwrap();
    std::fs::remove_dir(home_namespace).unwrap();
}

#[cfg(windows)]
#[test]
fn windows_endpoint_name_is_nonce_and_home_bound() {
    let home = tempfile::tempdir().unwrap();
    let endpoint = endpoint_for_home(home.path(), TEST_NONCE).unwrap();
    endpoint.validate(home.path(), TEST_NONCE).unwrap();
    let AuditEndpointV2::WindowsNamedPipe {
        name,
        endpoint_nonce,
        home_sha256,
    } = endpoint;
    assert_eq!(name, windows::pipe_name(&home_sha256, &endpoint_nonce));
    assert!(name.starts_with(r"\\.\pipe\neoth-audit-v2-"));
}

#[cfg(windows)]
#[tokio::test]
async fn windows_round_trip_proves_dacl_sid_revert_and_first_instance() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let home = tempfile::tempdir().unwrap();
    let (mut listener, endpoint) = bind(home.path(), TEST_NONCE).await.unwrap();
    // A second first-instance bind to the same name must fail closed. The
    // first bind also performs an exact protected current-TokenUser DACL
    // read-back before it succeeds.
    assert!(bind(home.path(), TEST_NONCE).await.is_err());
    const { assert!(windows::PIPE_REJECT_REMOTE_CLIENTS) };
    let client_endpoint = endpoint.clone();
    let client = tokio::spawn(async move {
        let mut stream = connect(&client_endpoint).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut reply = [0_u8; 4];
        stream.read_exact(&mut reply).await.unwrap();
        reply
    });
    let mut server = listener.accept().await.unwrap();
    let mut request = [0_u8; 4];
    server.read_exact(&mut request).await.unwrap();
    assert_eq!(&request, b"ping");
    server.write_all(b"pong").await.unwrap();
    drop(server);
    assert_eq!(&client.await.unwrap(), b"pong");
    // A successful accept necessarily traversed
    // ImpersonateNamedPipeClient -> OpenThreadToken -> exact SID compare ->
    // RevertToSelf before the stream was returned.
}

#[cfg(windows)]
#[test]
fn windows_sid_comparison_rejects_mismatch() {
    let sid = windows::current_process_sid().unwrap();
    let mut mismatch = sid.clone();
    *mismatch.last_mut().unwrap() ^= 1;
    assert!(!windows::same_sid(&sid, &mismatch));
}

#[cfg(windows)]
#[test]
fn windows_attestation_core_reverts_on_success_error_and_sid_mismatch() {
    use std::cell::Cell;

    let expected = windows::current_process_sid().unwrap();

    let reverted = Cell::new(false);
    windows::attest_client_sid_with(&expected, || Ok(expected.clone()), || reverted.set(true))
        .unwrap();
    assert!(reverted.get());

    let reverted = Cell::new(false);
    let error = windows::attest_client_sid_with(
        &expected,
        || anyhow::bail!("synthetic TokenUser query failure"),
        || reverted.set(true),
    )
    .unwrap_err();
    assert!(error.to_string().contains("synthetic TokenUser"));
    assert!(
        reverted.get(),
        "query failure must still invoke RevertToSelf"
    );

    let mut mismatch = expected.clone();
    *mismatch.last_mut().unwrap() ^= 1;
    let reverted = Cell::new(false);
    assert!(
        windows::attest_client_sid_with(&expected, || Ok(mismatch), || reverted.set(true),)
            .is_err()
    );
    assert!(
        reverted.get(),
        "SID mismatch must still invoke RevertToSelf"
    );
}
