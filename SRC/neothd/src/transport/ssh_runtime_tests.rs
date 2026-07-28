//! Hermetic `russh` runtime coverage for TERMIX-01/02/04.
//!
//! These tests deliberately use in-process loopback servers rather than an
//! external `sshd`: host-key TOFU, test-fixture-only password auth,
//! direct-tcpip forwarding, and ProxyJump are exercised against the exact
//! `russh` API we ship.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::{
    Arc, Mutex as StdMutex,
    atomic::{AtomicU64, Ordering},
};
use std::time::Duration;

use anyhow::{Context, Result};
use russh::keys::{
    PrivateKey,
    ssh_key::{Cipher, Kdf, PublicKey, private::Ed25519Keypair},
};
use russh::{Channel, client, server};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::timeout;

use crate::secret::SecretString;

use super::ssh_jump::connect_via_jumps;
use super::ssh_tofu::TofuStore;
use super::ssh_tunnel::{
    SshAuth, SshEndpoint, SshTunnelConfig, connect_endpoint, is_fatal_ssh_configuration,
    spawn_tunnel,
};

const PASSWORD: &str = "neoth-insecure-test-fixture:loopback-password";
const ORDINARY_PASSWORD: &str = "ordinary-password-must-not-be-sent";
const USERNAME: &str = "loopback-user";
const TIMEOUT: Duration = Duration::from_secs(10);
const ECDSA_P256_HOST_KEY: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQR8H9hzDOU0V76NkkCY7DZIgw+Sqooj
Y6xlb91FIfpjE+UR8YkbTp5ar44ULQatFaZqQlfz8FHYTooOL5G6gHBHAAAAsB8RBhUfEQ
YVAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHwf2HMM5TRXvo2S
QJjsNkiDD5KqiiNjrGVv3UUh+mMT5RHxiRtOnlqvjhQtBq0VpmpCV/PwUdhOig4vkbqAcE
cAAAAhAMp4pkd0v643EjIkk38DmJYBiXB6ygqGRc60NZxCO6B5AAAAEHVzZXJAZXhhbXBs
ZS5jb20BAgMEBQYH
-----END OPENSSH PRIVATE KEY-----
";
static NEXT_SERVER_KEY_SEED: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
struct PasswordForwardServer {
    events: Arc<StdMutex<Vec<String>>>,
    expected_public_key: Option<Arc<PublicKey>>,
    accepted_public_key: Arc<StdMutex<Option<PublicKey>>>,
}

impl PasswordForwardServer {
    fn record(&self, event: impl Into<String>) {
        self.events
            .lock()
            .expect("test event lock poisoned")
            .push(event.into());
    }
}

impl server::Handler for PasswordForwardServer {
    type Error = anyhow::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<server::Auth> {
        self.record(format!("auth:{user}"));
        if user == USERNAME && password == PASSWORD {
            Ok(server::Auth::Accept)
        } else {
            Ok(server::Auth::reject())
        }
    }

    async fn auth_publickey(&mut self, user: &str, public_key: &PublicKey) -> Result<server::Auth> {
        self.record(format!("auth-publickey:{user}"));
        match self.expected_public_key.as_deref() {
            Some(expected) if user == USERNAME && public_key == expected => {
                *self
                    .accepted_public_key
                    .lock()
                    .expect("accepted public-key lock poisoned") = Some(public_key.clone());
                Ok(server::Auth::Accept)
            }
            _ => Ok(server::Auth::reject()),
        }
    }

    fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<server::Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: server::ChannelOpenHandle,
        _session: &mut server::Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let events = Arc::clone(&self.events);
        let host = host_to_connect.to_owned();
        async move {
            let port = u16::try_from(port_to_connect)
                .context("direct-tcpip destination port outside u16 range")?;
            events
                .lock()
                .expect("test event lock poisoned")
                .push(format!("forward:{host}:{port}"));
            let mut remote = TcpStream::connect((host.as_str(), port))
                .await
                .context("connect direct-tcpip loopback destination")?;
            reply.accept().await;
            let mut stream = channel.into_stream();
            tokio::spawn(async move {
                let _ = tokio::io::copy_bidirectional(&mut stream, &mut remote).await;
            });
            Ok(())
        }
    }
}

struct LoopbackSshServer {
    addr: SocketAddr,
    events: Arc<StdMutex<Vec<String>>>,
    accepted_public_key: Arc<StdMutex<Option<PublicKey>>>,
    task: JoinHandle<()>,
}

impl LoopbackSshServer {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback SSH listener");
        Self::from_listener(listener, next_ed25519_host_key(), None).await
    }

    async fn start_with_public_key(expected_public_key: PublicKey) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind public-key loopback SSH listener");
        Self::from_listener(listener, next_ed25519_host_key(), Some(expected_public_key)).await
    }

    async fn restart_at_with_key(addr: SocketAddr, host_key: PrivateKey) -> Self {
        let listener = TcpListener::bind(addr)
            .await
            .expect("rebind loopback SSH listener");
        Self::from_listener(listener, host_key, None).await
    }

    async fn from_listener(
        listener: TcpListener,
        host_key: PrivateKey,
        expected_public_key: Option<PublicKey>,
    ) -> Self {
        let addr = listener.local_addr().expect("read loopback SSH address");
        let events = Arc::new(StdMutex::new(Vec::new()));
        let accepted_public_key = Arc::new(StdMutex::new(None));
        let server_config = Arc::new(server_config(host_key));
        let handler = PasswordForwardServer {
            events: Arc::clone(&events),
            expected_public_key: expected_public_key.map(Arc::new),
            accepted_public_key: Arc::clone(&accepted_public_key),
        };
        let task = tokio::spawn(async move {
            let mut sessions = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { break };
                        let config = Arc::clone(&server_config);
                        let connection_handler = handler.clone();
                        sessions.spawn(async move {
                            if let Ok(running) = server::run_stream(config, stream, connection_handler).await {
                                let _ = running.await;
                            }
                        });
                    }
                    completed = sessions.join_next(), if !sessions.is_empty() => {
                        let _ = completed;
                    }
                }
            }
            sessions.abort_all();
        });
        Self {
            addr,
            events,
            accepted_public_key,
            task,
        }
    }

    fn endpoint(&self) -> SshEndpoint {
        endpoint(self.addr)
    }

    fn events(&self) -> Vec<String> {
        self.events
            .lock()
            .expect("test event lock poisoned")
            .clone()
    }

    fn accepted_public_key(&self) -> Option<PublicKey> {
        self.accepted_public_key
            .lock()
            .expect("accepted public-key lock poisoned")
            .clone()
    }

    async fn stop(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

struct LoopbackEcho {
    addr: SocketAddr,
    task: JoinHandle<()>,
}

impl LoopbackEcho {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback echo listener");
        let addr = listener.local_addr().expect("read loopback echo address");
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((mut stream, _)) = accepted else { break };
                        connections.spawn(async move {
                            let mut buffer = [0u8; 1024];
                            loop {
                                let n = match stream.read(&mut buffer).await {
                                    Ok(0) | Err(_) => break,
                                    Ok(n) => n,
                                };
                                if stream.write_all(&buffer[..n]).await.is_err() {
                                    break;
                                }
                            }
                        });
                    }
                    completed = connections.join_next(), if !connections.is_empty() => {
                        let _ = completed;
                    }
                }
            }
            connections.abort_all();
        });
        Self { addr, task }
    }

    async fn stop(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

fn next_ed25519_host_key() -> PrivateKey {
    let counter = NEXT_SERVER_KEY_SEED.fetch_add(1, Ordering::Relaxed);
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&counter.to_le_bytes());
    seed[8] = 0xA5;
    PrivateKey::from(Ed25519Keypair::from_seed(&seed))
}

fn ecdsa_p256_host_key() -> PrivateKey {
    PrivateKey::from_openssh(ECDSA_P256_HOST_KEY).expect("parse ECDSA P-256 loopback host key")
}

fn server_config(host_key: PrivateKey) -> server::Config {
    let mut config = server::Config::default();
    config.auth_rejection_time = Duration::from_millis(1);
    config.auth_rejection_time_initial = Some(Duration::from_millis(1));
    config.keys.push(host_key);
    config
}

fn endpoint(addr: SocketAddr) -> SshEndpoint {
    SshEndpoint {
        host: addr.ip().to_string(),
        port: addr.port(),
        username: USERNAME.into(),
        auth: SshAuth::Password(PASSWORD.into()),
    }
}

fn client_config() -> Arc<client::Config> {
    Arc::new(client::Config::default())
}

async fn unused_loopback_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve unused loopback port");
    let port = listener
        .local_addr()
        .expect("read reserved loopback address")
        .port();
    drop(listener);
    port
}

async fn assert_password_tunnel_rejected_before_bind(
    config: SshTunnelConfig,
    password_secret: &str,
) {
    let local_port = config.local_port;
    let tofu = Arc::new(tokio::sync::Mutex::new(
        TofuStore::in_memory().expect("open in-memory TOFU store"),
    ));
    let error = match spawn_tunnel(config, tofu).await {
        Ok(tunnel) => {
            tunnel.shutdown();
            panic!("ordinary SSH password config must fail before listener bind");
        }
        Err(error) => error,
    };
    assert!(
        is_fatal_ssh_configuration(&error),
        "password rejection must be a non-retryable configuration error: {error:#}"
    );
    let message = format!("{error:#}");
    assert!(
        message.contains("configure auth: private_key"),
        "operator message must name the secure replacement: {message}"
    );
    assert!(
        !message.contains(password_secret),
        "password rejection must not expose the configured secret"
    );

    let listener = TcpListener::bind(("127.0.0.1", local_port))
        .await
        .expect("password rejection must leave the configured port unbound");
    drop(listener);
}

#[tokio::test]
async fn connect_endpoint_test_fixture_auth_and_handler_tofu_rejects_cross_algorithm_host_key() {
    let first = LoopbackSshServer::start().await;
    let original_addr = first.addr;
    let endpoint = first.endpoint();
    let tofu = Arc::new(tokio::sync::Mutex::new(
        TofuStore::in_memory().expect("open in-memory TOFU store"),
    ));

    let first_session = timeout(
        TIMEOUT,
        connect_endpoint(&endpoint, Arc::clone(&tofu), client_config()),
    )
    .await
    .expect("first connect_endpoint timed out")
    .expect("first endpoint must password-authenticate and accept its host key");
    drop(first_session);

    let matched_session = timeout(
        TIMEOUT,
        connect_endpoint(&endpoint, Arc::clone(&tofu), client_config()),
    )
    .await
    .expect("matched connect_endpoint timed out")
    .expect("same host key must match the real client Handler TOFU store");
    drop(matched_session);
    assert_eq!(
        first
            .events()
            .iter()
            .filter(|event| event.as_str() == "auth:loopback-user")
            .count(),
        2,
        "both accepted handshakes must use password authentication"
    );
    first.stop().await;

    let changed =
        LoopbackSshServer::restart_at_with_key(original_addr, ecdsa_p256_host_key()).await;
    let rejected = timeout(
        TIMEOUT,
        connect_endpoint(&endpoint, Arc::clone(&tofu), client_config()),
    )
    .await
    .expect("cross-algorithm connect_endpoint timed out");
    let error = match rejected {
        Ok(_) => panic!("a never-pinned host-key algorithm must be rejected"),
        Err(error) => error,
    };
    assert!(
        error.chain().any(|cause| matches!(
            cause.downcast_ref::<russh::Error>(),
            Some(russh::Error::UnknownKey)
        )),
        "cross-algorithm rejection must surface russh::Error::UnknownKey: {error:#}"
    );
    assert!(
        changed.events().is_empty(),
        "host-key rejection must happen before authentication"
    );
    assert_eq!(
        tofu.lock().await.len().expect("count TOFU rows"),
        1,
        "cross-algorithm host key must not add or overwrite a trusted pin"
    );
    changed.stop().await;
}

#[tokio::test]
async fn connect_endpoint_ordinary_password_fails_closed_without_sending_auth() {
    let ssh = LoopbackSshServer::start().await;
    let endpoint = SshEndpoint {
        auth: SshAuth::Password(ORDINARY_PASSWORD.into()),
        ..ssh.endpoint()
    };
    let tofu = Arc::new(tokio::sync::Mutex::new(
        TofuStore::in_memory().expect("open in-memory TOFU store"),
    ));

    let rejected = timeout(
        TIMEOUT,
        connect_endpoint(&endpoint, Arc::clone(&tofu), client_config()),
    )
    .await
    .expect("ordinary-password connect_endpoint timed out");
    let error = match rejected {
        Ok(_) => panic!("ordinary password authentication must be disabled"),
        Err(error) => error,
    };
    assert!(
        is_fatal_ssh_configuration(&error),
        "password rejection must be a typed fatal configuration error: {error:#}"
    );
    let message = format!("{error:#}");
    assert!(
        message.contains("configure auth: private_key"),
        "operator message must direct the user to private-key auth: {message}"
    );
    assert!(
        !message.contains(ORDINARY_PASSWORD),
        "password rejection must never echo the configured secret"
    );
    assert!(
        ssh.events().is_empty(),
        "the loopback server must observe no password-authentication event"
    );
    assert_eq!(
        tofu.lock().await.len().expect("count TOFU rows"),
        1,
        "the recorded host key proves the SSH handshake completed before auth was rejected"
    );
    ssh.stop().await;
}

#[tokio::test]
async fn spawn_tunnel_rejects_password_final_endpoint_before_listener_bind() {
    let local_port = unused_loopback_port().await;
    let config = SshTunnelConfig {
        endpoint: SshEndpoint {
            host: "127.0.0.1".into(),
            port: 22,
            username: "password-final".into(),
            auth: SshAuth::Password(ORDINARY_PASSWORD.into()),
        },
        remote_host: "127.0.0.1".into(),
        remote_port: 1,
        local_port,
        jump_hosts: Vec::new(),
        max_retries: 0,
        retry_delay: Duration::from_millis(1),
    };

    assert_password_tunnel_rejected_before_bind(config, ORDINARY_PASSWORD).await;
}

#[tokio::test]
async fn spawn_tunnel_rejects_password_jump_host_before_listener_bind() {
    const JUMP_PASSWORD: &str = "ordinary-jump-password-must-not-be-sent";

    let local_port = unused_loopback_port().await;
    let config = SshTunnelConfig {
        endpoint: SshEndpoint {
            host: "127.0.0.1".into(),
            port: 22,
            username: "private-key-final".into(),
            auth: SshAuth::PrivateKey {
                path: "never-read-test-private-key".into(),
                passphrase: None,
            },
        },
        remote_host: "127.0.0.1".into(),
        remote_port: 1,
        local_port,
        jump_hosts: vec![SshEndpoint {
            host: "127.0.0.2".into(),
            port: 22,
            username: "password-jump".into(),
            auth: SshAuth::Password(JUMP_PASSWORD.into()),
        }],
        max_retries: 0,
        retry_delay: Duration::from_millis(1),
    };

    assert_password_tunnel_rejected_before_bind(config, JUMP_PASSWORD).await;
}

#[tokio::test]
async fn connect_endpoint_private_key_auth_decrypts_openssh_key_and_accepts_exact_public_key() {
    const KEY_PASSPHRASE: &str = "loopback-ed25519-passphrase";

    let mut client_seed = [0u8; 32];
    client_seed[0] = 0xC1;
    client_seed[31] = 0x7A;
    let client_key = PrivateKey::from(Ed25519Keypair::from_seed(&client_seed));
    let expected_public_key = client_key.public_key().clone();
    let encrypted_key = client_key
        .encrypt_with(
            Cipher::Aes256Ctr,
            Kdf::Bcrypt {
                salt: vec![0x5A; 16],
                rounds: 16,
            },
            0xC0DE_CAFE,
            KEY_PASSPHRASE,
        )
        .expect("encrypt generated Ed25519 client key");
    assert!(encrypted_key.is_encrypted());
    let encoded_key = encrypted_key
        .to_openssh(Default::default())
        .expect("encode encrypted Ed25519 key as OpenSSH");
    let key_file = tempfile::NamedTempFile::new().expect("create temporary private-key file");
    std::fs::write(key_file.path(), encoded_key.as_bytes())
        .expect("write encrypted OpenSSH private key");

    let ssh = LoopbackSshServer::start_with_public_key(expected_public_key.clone()).await;
    let endpoint = SshEndpoint {
        host: ssh.addr.ip().to_string(),
        port: ssh.addr.port(),
        username: USERNAME.into(),
        auth: SshAuth::PrivateKey {
            path: key_file.path().to_path_buf(),
            passphrase: Some(SecretString::from(KEY_PASSPHRASE)),
        },
    };
    assert!(
        !format!("{:?}", endpoint.auth).contains(KEY_PASSPHRASE),
        "SshAuth Debug must redact the private-key passphrase"
    );
    let tofu = Arc::new(tokio::sync::Mutex::new(
        TofuStore::in_memory().expect("open in-memory TOFU store"),
    ));

    let session = timeout(TIMEOUT, connect_endpoint(&endpoint, tofu, client_config()))
        .await
        .expect("private-key connect_endpoint timed out")
        .expect("encrypted Ed25519 key must authenticate through connect_endpoint");
    drop(session);

    assert_eq!(
        ssh.accepted_public_key().as_ref(),
        Some(&expected_public_key),
        "server must accept the exact generated Ed25519 public key"
    );
    let events = ssh.events();
    assert_eq!(
        events,
        vec![format!("auth-publickey:{USERNAME}")],
        "public-key authentication must not fall back to password auth"
    );
    assert!(
        events.iter().all(|event| !event.contains(KEY_PASSPHRASE)),
        "server test events must never expose the private-key passphrase"
    );
    ssh.stop().await;
}

#[tokio::test]
async fn spawn_tunnel_forwards_loopback_bytes_over_real_direct_tcpip() {
    let ssh = LoopbackSshServer::start().await;
    let echo = LoopbackEcho::start().await;
    let tofu = Arc::new(tokio::sync::Mutex::new(
        TofuStore::in_memory().expect("open in-memory TOFU store"),
    ));
    let config = SshTunnelConfig {
        endpoint: ssh.endpoint(),
        remote_host: echo.addr.ip().to_string(),
        remote_port: echo.addr.port(),
        local_port: 0,
        jump_hosts: Vec::new(),
        max_retries: 0,
        retry_delay: Duration::from_millis(1),
    };
    let tunnel = spawn_tunnel(config, tofu)
        .await
        .expect("bind local SSH tunnel listener");
    let mut local = timeout(
        TIMEOUT,
        TcpStream::connect(("127.0.0.1", tunnel.local_port())),
    )
    .await
    .expect("connect local tunnel timed out")
    .expect("connect local tunnel");
    let payload = b"NEOTH russh loopback direct-tcpip";
    let response = timeout(TIMEOUT, async {
        local.write_all(payload).await?;
        local.flush().await?;
        let mut response = vec![0u8; payload.len()];
        local.read_exact(&mut response).await?;
        Result::<Vec<u8>>::Ok(response)
    })
    .await
    .expect("direct-tcpip byte roundtrip timed out")
    .expect("direct-tcpip byte roundtrip");
    assert_eq!(response, payload, "direct-tcpip echo payload differs");

    drop(local);
    tunnel.shutdown();
    ssh.stop().await;
    echo.stop().await;
}

#[tokio::test]
async fn connect_via_jumps_forwards_hops_in_declared_order() {
    let target = LoopbackSshServer::start().await;
    let hop_one = LoopbackSshServer::start().await;
    let hop_zero = LoopbackSshServer::start().await;
    let echo = LoopbackEcho::start().await;
    let tofu = Arc::new(tokio::sync::Mutex::new(
        TofuStore::in_memory().expect("open in-memory TOFU store"),
    ));
    let hop_one_endpoint = hop_one.endpoint();
    let target_endpoint = target.endpoint();

    let final_handle = timeout(
        TIMEOUT,
        connect_via_jumps(
            &[hop_zero.endpoint(), hop_one_endpoint.clone()],
            &target_endpoint,
            tofu,
            client_config(),
        ),
    )
    .await
    .expect("multi-hop SSH connection timed out")
    .expect("multi-hop SSH connection must authenticate through each hop");
    let channel = timeout(
        TIMEOUT,
        final_handle.channel_open_direct_tcpip(
            echo.addr.ip().to_string(),
            u32::from(echo.addr.port()),
            "127.0.0.1",
            0,
        ),
    )
    .await
    .expect("final multi-hop direct-tcpip channel open timed out")
    .expect("final multi-hop handle must open direct-tcpip through both carriers");
    let mut stream = channel.into_stream();
    let payload = b"NEOTH final two-hop handle roundtrip";
    let response = timeout(TIMEOUT, async {
        stream.write_all(payload).await?;
        stream.flush().await?;
        let mut response = vec![0u8; payload.len()];
        stream.read_exact(&mut response).await?;
        Result::<Vec<u8>>::Ok(response)
    })
    .await
    .expect("final multi-hop byte roundtrip timed out")
    .expect("final multi-hop byte roundtrip");
    assert_eq!(
        response, payload,
        "final N-hop handle must round-trip exact bytes through both carriers"
    );
    drop(stream);
    drop(final_handle);

    assert_eq!(
        hop_zero.events(),
        vec![
            format!("auth:{USERNAME}"),
            format!("forward:{}", hop_one_endpoint.host_key()),
        ],
        "first jump must authenticate then forward exclusively to hop one"
    );
    assert_eq!(
        hop_one.events(),
        vec![
            format!("auth:{USERNAME}"),
            format!("forward:{}", target_endpoint.host_key()),
        ],
        "second jump must authenticate then forward exclusively to target"
    );
    assert_eq!(
        target.events(),
        vec![
            format!("auth:{USERNAME}"),
            format!("forward:{}:{}", echo.addr.ip(), echo.addr.port()),
        ],
        "target must remain functional as the final SSH session in the ProxyJump chain"
    );

    hop_zero.stop().await;
    hop_one.stop().await;
    target.stop().await;
    echo.stop().await;
}
