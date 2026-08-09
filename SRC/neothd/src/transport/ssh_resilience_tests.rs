//! Hermetic lifecycle and reconnect coverage for the SSH tunnel supervisor.

use std::future::{Future, pending};
use std::net::{Shutdown, SocketAddr};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use russh::keys::{PrivateKey, ssh_key::private::Ed25519Keypair};
use russh::{Channel, client, server};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::timeout;

use super::ssh_jump::connect_via_jumps_with_timeouts;
use super::ssh_tofu::TofuStore;
use super::ssh_tunnel::{
    MAX_CONCURRENT_FORWARDS, SshAuth, SshEndpoint, SshTunnel, SshTunnelConfig,
    connect_endpoint_with_timeouts, spawn_tunnel,
};

const PASSWORD: &str = "neoth-insecure-test-fixture:resilience-password";
const USERNAME: &str = "resilience-user";
const TEST_TIMEOUT: Duration = Duration::from_secs(10);
const SATURATION_TIMEOUT: Duration = Duration::from_secs(30);
const SHORT_TIMEOUT: Duration = Duration::from_millis(150);
const HOP_TIMEOUT: Duration = Duration::from_millis(500);
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const FIXED_HOST_KEY_SEED: [u8; 32] = [0x5A; 32];

#[derive(Clone)]
struct ForwardServer {
    authentications: Arc<AtomicUsize>,
    active_forwards: Arc<AtomicUsize>,
    reject_next_forward: Arc<AtomicBool>,
    stall_next_forward: Arc<AtomicBool>,
}

impl server::Handler for ForwardServer {
    type Error = anyhow::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<server::Auth> {
        self.authentications.fetch_add(1, Ordering::SeqCst);
        if user == USERNAME && password == PASSWORD {
            Ok(server::Auth::Accept)
        } else {
            Ok(server::Auth::reject())
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
        let active_forwards = Arc::clone(&self.active_forwards);
        let reject_next_forward = Arc::clone(&self.reject_next_forward);
        let stall_next_forward = Arc::clone(&self.stall_next_forward);
        let host = host_to_connect.to_owned();
        async move {
            if reject_next_forward.swap(false, Ordering::SeqCst) {
                reply.reject(russh::ChannelOpenFailure::ConnectFailed).await;
                return Ok(());
            }
            if stall_next_forward.swap(false, Ordering::SeqCst) {
                pending().await
            }
            let port = u16::try_from(port_to_connect)
                .context("direct-tcpip destination port outside u16 range")?;
            let mut remote = TcpStream::connect((host.as_str(), port))
                .await
                .context("connect direct-tcpip destination")?;
            reply.accept().await;
            let mut stream = channel.into_stream();
            active_forwards.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let _guard = ActiveForwardGuard(active_forwards);
                let _ = tokio::io::copy_bidirectional(&mut stream, &mut remote).await;
            });
            Ok(())
        }
    }
}

struct ActiveForwardGuard(Arc<AtomicUsize>);

impl Drop for ActiveForwardGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(Clone)]
struct StalledAuthServer;

impl server::Handler for StalledAuthServer {
    type Error = anyhow::Error;

    async fn auth_password(&mut self, _user: &str, _password: &str) -> Result<server::Auth> {
        pending().await
    }
}

#[derive(Clone)]
struct FlappingServer {
    authentications: Arc<AtomicUsize>,
    authenticated: Arc<tokio::sync::Notify>,
}

impl server::Handler for FlappingServer {
    type Error = anyhow::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<server::Auth> {
        self.authentications.fetch_add(1, Ordering::SeqCst);
        self.authenticated.notify_one();
        if user == USERNAME && password == PASSWORD {
            Ok(server::Auth::Accept)
        } else {
            Ok(server::Auth::reject())
        }
    }
}

struct LoopbackFlappingSshServer {
    addr: SocketAddr,
    authentications: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl LoopbackFlappingSshServer {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind flapping SSH listener");
        let addr = listener
            .local_addr()
            .expect("read flapping SSH listener address");
        let authentications = Arc::new(AtomicUsize::new(0));
        let task_authentications = Arc::clone(&authentications);
        let config = Arc::new(server_config());
        let task = tokio::spawn(async move {
            let mut sessions = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { break };
                        let config = Arc::clone(&config);
                        let authenticated = Arc::new(tokio::sync::Notify::new());
                        let handler = FlappingServer {
                            authentications: Arc::clone(&task_authentications),
                            authenticated: Arc::clone(&authenticated),
                        };
                        sessions.spawn(async move {
                            if let Ok(mut running) = server::run_stream(config, stream, handler).await {
                                let handle = running.handle();
                                tokio::select! {
                                    result = &mut running => {
                                        let _ = result;
                                    }
                                    () = authenticated.notified() => {
                                        // Let the Auth::Accept response reach the client, then
                                        // terminate the otherwise-valid session immediately.
                                        tokio::time::sleep(Duration::from_millis(25)).await;
                                        let _ = handle
                                            .disconnect(
                                                russh::Disconnect::ByApplication,
                                                "flapping test session".to_owned(),
                                                String::new(),
                                            )
                                            .await;
                                        let _ = running.await;
                                    }
                                }
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
            authentications,
            task,
        }
    }

    fn endpoint(&self) -> SshEndpoint {
        endpoint(self.addr)
    }

    async fn stop(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

struct LoopbackSshServer {
    addr: SocketAddr,
    authentications: Arc<AtomicUsize>,
    active_forwards: Arc<AtomicUsize>,
    reject_next_forward: Arc<AtomicBool>,
    stall_next_forward: Arc<AtomicBool>,
    shutdown: tokio::sync::watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl LoopbackSshServer {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback SSH listener");
        Self::from_listener(listener).await
    }

    async fn restart_at(addr: SocketAddr) -> Self {
        let listener = TcpListener::bind(addr)
            .await
            .expect("rebind loopback SSH listener");
        Self::from_listener(listener).await
    }

    async fn from_listener(listener: TcpListener) -> Self {
        let addr = listener.local_addr().expect("read SSH listener address");
        let authentications = Arc::new(AtomicUsize::new(0));
        let active_forwards = Arc::new(AtomicUsize::new(0));
        let reject_next_forward = Arc::new(AtomicBool::new(false));
        let stall_next_forward = Arc::new(AtomicBool::new(false));
        let handler = ForwardServer {
            authentications: Arc::clone(&authentications),
            active_forwards: Arc::clone(&active_forwards),
            reject_next_forward: Arc::clone(&reject_next_forward),
            stall_next_forward: Arc::clone(&stall_next_forward),
        };
        let config = Arc::new(server_config());
        let (shutdown, mut task_shutdown) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move {
            let mut sessions = JoinSet::new();
            loop {
                tokio::select! {
                    changed = task_shutdown.changed() => {
                        if changed.is_err() || *task_shutdown.borrow() {
                            break;
                        }
                    }
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { break };
                        let Ok(control_stream) = stream.into_std() else {
                            continue;
                        };
                        let Ok(session_stream) = control_stream.try_clone() else {
                            continue;
                        };
                        let Ok(stream) = TcpStream::from_std(session_stream) else {
                            continue;
                        };
                        let config = Arc::clone(&config);
                        let handler = handler.clone();
                        let mut session_shutdown = task_shutdown.clone();
                        sessions.spawn(async move {
                            let started = tokio::select! {
                                result = server::run_stream(config, stream, handler) => result,
                                _ = session_shutdown.changed() => return,
                            };
                            let Ok(running) = started else {
                                return;
                            };
                            let handle = running.handle();
                            let mut running_task = tokio::spawn(async move {
                                let _ = running.await;
                            });
                            tokio::select! {
                                result = &mut running_task => {
                                    let _ = result;
                                }
                                changed = session_shutdown.changed() => {
                                    if changed.is_err() || *session_shutdown.borrow() {
                                        let _ = timeout(
                                            Duration::from_millis(100),
                                            handle.disconnect(
                                                russh::Disconnect::ByApplication,
                                                "loopback test server shutdown".to_owned(),
                                                String::new(),
                                            ),
                                        )
                                        .await;
                                        let _ = control_stream.shutdown(Shutdown::Both);
                                        // A peer stalled inside a deliberately adversarial
                                        // channel callback must not make test-server teardown
                                        // unbounded. The socket is already shut down; give the
                                        // russh session task a short grace period, then abort and
                                        // reap it so no detached callback survives the harness.
                                        if timeout(Duration::from_secs(1), &mut running_task)
                                            .await
                                            .is_err()
                                        {
                                            running_task.abort();
                                            let _ = running_task.await;
                                        }
                                    }
                                }
                            }
                        });
                    }
                    completed = sessions.join_next(), if !sessions.is_empty() => {
                        let _ = completed;
                    }
                }
            }
            while let Some(completed) = sessions.join_next().await {
                let _ = completed;
            }
        });
        Self {
            addr,
            authentications,
            active_forwards,
            reject_next_forward,
            stall_next_forward,
            shutdown,
            task,
        }
    }

    fn endpoint(&self) -> SshEndpoint {
        endpoint(self.addr)
    }

    async fn stop(self) {
        let _ = self.shutdown.send(true);
        let _ = self.task.await;
    }
}

struct LoopbackEcho {
    addr: SocketAddr,
    active_connections: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl LoopbackEcho {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback echo listener");
        let addr = listener.local_addr().expect("read echo listener address");
        let active_connections = Arc::new(AtomicUsize::new(0));
        let task_active = Arc::clone(&active_connections);
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((mut stream, _)) = accepted else { break };
                        let active = Arc::clone(&task_active);
                        active.fetch_add(1, Ordering::SeqCst);
                        connections.spawn(async move {
                            let _guard = ActiveForwardGuard(active);
                            let mut buffer = [0u8; 1024];
                            loop {
                                let read = match stream.read(&mut buffer).await {
                                    Ok(0) | Err(_) => break,
                                    Ok(read) => read,
                                };
                                if stream.write_all(&buffer[..read]).await.is_err() {
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
        Self {
            addr,
            active_connections,
            task,
        }
    }

    async fn stop(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

fn server_config() -> server::Config {
    let mut config = server::Config::default();
    config.auth_rejection_time = Duration::from_millis(1);
    config.auth_rejection_time_initial = Some(Duration::from_millis(1));
    config.keys.push(PrivateKey::from(Ed25519Keypair::from_seed(
        &FIXED_HOST_KEY_SEED,
    )));
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

fn tunnel_config(endpoint: SshEndpoint, echo: SocketAddr) -> SshTunnelConfig {
    SshTunnelConfig {
        endpoint,
        remote_host: echo.ip().to_string(),
        remote_port: echo.port(),
        local_port: 0,
        jump_hosts: Vec::new(),
        max_retries: 20,
        retry_delay: Duration::from_millis(25),
    }
}

async fn start_stalled_auth_server() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stalled-auth listener");
    let addr = listener.local_addr().expect("read stalled-auth address");
    let config = Arc::new(server_config());
    let task = tokio::spawn(async move {
        let mut sessions = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else { break };
                    let config = Arc::clone(&config);
                    sessions.spawn(async move {
                        if let Ok(running) =
                            server::run_stream(config, stream, StalledAuthServer).await
                        {
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
    (addr, task)
}

async fn start_stalled_handshake_server() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stalled-handshake listener");
    let addr = listener
        .local_addr()
        .expect("read stalled-handshake address");
    let task = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    (addr, task)
}

async fn roundtrip_once(local_port: u16, payload: &[u8]) -> Result<()> {
    let mut local = timeout(
        Duration::from_millis(750),
        TcpStream::connect(("127.0.0.1", local_port)),
    )
    .await
    .context("local tunnel connect timed out")??;
    timeout(Duration::from_millis(750), async {
        local.write_all(payload).await?;
        local.flush().await?;
        let mut response = vec![0u8; payload.len()];
        local.read_exact(&mut response).await?;
        if response != payload {
            return Err(anyhow!("echo response differed"));
        }
        Result::<()>::Ok(())
    })
    .await
    .context("SSH tunnel byte roundtrip timed out")?
}

async fn roundtrip_eventually(local_port: u16, payload: &[u8]) {
    let deadline = Instant::now() + TEST_TIMEOUT;
    loop {
        if roundtrip_once(local_port, payload).await.is_ok() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "SSH tunnel did not become usable before the test deadline"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

async fn open_forward_eventually(local_port: u16, payload: &[u8]) -> TcpStream {
    timeout(TEST_TIMEOUT, async {
        loop {
            if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", local_port)).await
                && stream.write_all(payload).await.is_ok()
            {
                let mut response = vec![0u8; payload.len()];
                if stream.read_exact(&mut response).await.is_ok() && response == payload {
                    break stream;
                }
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .expect("SSH tunnel did not establish a tracked forward")
}

async fn wait_for_count(counter: &AtomicUsize, expected: usize) {
    timeout(TEST_TIMEOUT, async {
        while counter.load(Ordering::SeqCst) != expected {
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .expect("counter did not reach expected value");
}

async fn wait_until_listener_closed(port: u16) {
    timeout(TEST_TIMEOUT, async {
        loop {
            if TcpStream::connect(("127.0.0.1", port)).await.is_err() {
                return;
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .expect("tunnel listener remained open after tunnel teardown");
}

async fn wait_until_tunnel_finished(tunnel: &SshTunnel) {
    timeout(TEST_TIMEOUT, async {
        while !tunnel.is_finished() {
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .expect("SSH tunnel supervisor did not finish before deadline");
}

#[tokio::test]
async fn ssh_resilience_drop_aborts_root_task_and_closes_listener() {
    let (stalled_addr, stalled_task) = start_stalled_handshake_server().await;
    let echo = LoopbackEcho::start().await;
    let tofu = Arc::new(tokio::sync::Mutex::new(
        TofuStore::in_memory().expect("open in-memory TOFU store"),
    ));
    let tunnel = spawn_tunnel(tunnel_config(endpoint(stalled_addr), echo.addr), tofu)
        .await
        .expect("spawn tunnel against stalled SSH handshake");
    let local_port = tunnel.local_port();

    timeout(TEST_TIMEOUT, TcpStream::connect(("127.0.0.1", local_port)))
        .await
        .expect("connect to bound tunnel listener timed out")
        .expect("tunnel listener must be bound before background SSH connect");

    drop(tunnel);
    wait_until_listener_closed(local_port).await;

    stalled_task.abort();
    let _ = stalled_task.await;
    echo.stop().await;
}

#[tokio::test]
async fn ssh_resilience_flapping_sessions_back_off_and_exhaust_retry_budget() {
    let ssh = LoopbackFlappingSshServer::start().await;
    let echo = LoopbackEcho::start().await;
    let tofu = Arc::new(tokio::sync::Mutex::new(
        TofuStore::in_memory().expect("open in-memory TOFU store"),
    ));
    let retry_delay = Duration::from_millis(50);
    let mut config = tunnel_config(ssh.endpoint(), echo.addr);
    config.max_retries = 2;
    config.retry_delay = retry_delay;
    let started = Instant::now();
    let tunnel = spawn_tunnel(config, tofu)
        .await
        .expect("spawn tunnel against flapping SSH server");
    let local_port = tunnel.local_port();

    wait_until_tunnel_finished(&tunnel).await;
    wait_until_listener_closed(local_port).await;
    let elapsed = started.elapsed();
    assert_eq!(
        ssh.authentications.load(Ordering::SeqCst),
        3,
        "initial session plus exactly max_retries reconnects must authenticate"
    );
    assert!(
        elapsed >= retry_delay + retry_delay.saturating_mul(2),
        "flapping sessions reconnected without exponential backoff: {elapsed:?}"
    );

    tunnel.shutdown();
    ssh.stop().await;
    echo.stop().await;
}

#[tokio::test]
async fn ssh_resilience_shutdown_aborts_and_drains_owned_forward_tasks() {
    let ssh = LoopbackSshServer::start().await;
    let echo = LoopbackEcho::start().await;
    let tofu = Arc::new(tokio::sync::Mutex::new(
        TofuStore::in_memory().expect("open in-memory TOFU store"),
    ));
    let tunnel = spawn_tunnel(tunnel_config(ssh.endpoint(), echo.addr), tofu)
        .await
        .expect("spawn SSH tunnel");
    let local_port = tunnel.local_port();
    let mut local = open_forward_eventually(local_port, b"owned forwarding task").await;
    wait_for_count(&ssh.active_forwards, 1).await;
    wait_for_count(&echo.active_connections, 1).await;

    tunnel.shutdown();

    let mut byte = [0u8; 1];
    let closed = timeout(TEST_TIMEOUT, local.read(&mut byte))
        .await
        .expect("local forward remained parked after tunnel shutdown");
    assert!(
        matches!(closed, Ok(0) | Err(_)),
        "shutdown must close every tunnel-owned local stream"
    );
    wait_for_count(&ssh.active_forwards, 0).await;
    wait_for_count(&echo.active_connections, 0).await;
    wait_until_listener_closed(local_port).await;

    ssh.stop().await;
    echo.stop().await;
}

#[tokio::test]
async fn ssh_resilience_channel_rejection_does_not_abort_healthy_session_or_other_forwards() {
    let ssh = LoopbackSshServer::start().await;
    let echo = LoopbackEcho::start().await;
    let tofu = Arc::new(tokio::sync::Mutex::new(
        TofuStore::in_memory().expect("open in-memory TOFU store"),
    ));
    let tunnel = spawn_tunnel(tunnel_config(ssh.endpoint(), echo.addr), tofu)
        .await
        .expect("spawn SSH tunnel");
    let local_port = tunnel.local_port();
    let mut survivor = open_forward_eventually(local_port, b"survivor-before").await;
    wait_for_count(&ssh.active_forwards, 1).await;
    let authentications_before = ssh.authentications.load(Ordering::SeqCst);

    ssh.reject_next_forward.store(true, Ordering::SeqCst);
    let mut rejected = TcpStream::connect(("127.0.0.1", local_port))
        .await
        .expect("connect local stream for rejected channel");
    rejected
        .write_all(b"rejected")
        .await
        .expect("write rejected local payload");
    let mut byte = [0u8; 1];
    let closed = timeout(TEST_TIMEOUT, rejected.read(&mut byte))
        .await
        .expect("rejected local forward remained parked");
    assert!(
        matches!(closed, Ok(0) | Err(_)),
        "only the rejected local connection must close"
    );

    let payload = b"survivor-after";
    survivor
        .write_all(payload)
        .await
        .expect("write established forward after sibling rejection");
    let mut response = vec![0u8; payload.len()];
    survivor
        .read_exact(&mut response)
        .await
        .expect("established forward was aborted by sibling rejection");
    assert_eq!(response, payload);
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(
        ssh.authentications.load(Ordering::SeqCst),
        authentications_before,
        "healthy SSH session reconnected after a per-channel refusal"
    );
    assert_eq!(ssh.active_forwards.load(Ordering::SeqCst), 1);

    drop(survivor);
    tunnel.shutdown();
    ssh.stop().await;
    echo.stop().await;
}

#[tokio::test]
async fn ssh_resilience_forward_cap_backpressures_without_exceeding_task_limit() {
    let ssh = LoopbackSshServer::start().await;
    let echo = LoopbackEcho::start().await;
    let tofu = Arc::new(tokio::sync::Mutex::new(
        TofuStore::in_memory().expect("open in-memory TOFU store"),
    ));
    let tunnel = spawn_tunnel(tunnel_config(ssh.endpoint(), echo.addr), tofu)
        .await
        .expect("spawn SSH tunnel");
    let local_port = tunnel.local_port();
    roundtrip_eventually(local_port, b"warmup").await;
    wait_for_count(&echo.active_connections, 0).await;

    let mut clients = Vec::with_capacity(MAX_CONCURRENT_FORWARDS);
    timeout(SATURATION_TIMEOUT, async {
        for index in 0..MAX_CONCURRENT_FORWARDS {
            let mut client = TcpStream::connect(("127.0.0.1", local_port))
                .await
                .expect("connect saturation client");
            let payload = [u8::try_from(index).expect("forward cap fits in u8")];
            client
                .write_all(&payload)
                .await
                .expect("write saturation payload");
            let mut response = [0u8; 1];
            client
                .read_exact(&mut response)
                .await
                .expect("read saturation response");
            assert_eq!(response, payload);
            clients.push(client);
        }
    })
    .await
    .expect("did not saturate forwarding cap before deadline");
    wait_for_count(&echo.active_connections, MAX_CONCURRENT_FORWARDS).await;
    assert_eq!(
        ssh.active_forwards.load(Ordering::SeqCst),
        MAX_CONCURRENT_FORWARDS
    );

    let mut overflow = TcpStream::connect(("127.0.0.1", local_port))
        .await
        .expect("overflow connection reaches OS listener backlog");
    overflow
        .write_all(b"x")
        .await
        .expect("write overflow payload into backlog");
    let mut response = [0u8; 1];
    assert!(
        timeout(
            Duration::from_millis(250),
            overflow.read_exact(&mut response)
        )
        .await
        .is_err(),
        "overflow connection was accepted before capacity became available"
    );
    assert_eq!(
        echo.active_connections.load(Ordering::SeqCst),
        MAX_CONCURRENT_FORWARDS,
        "active forwarding tasks exceeded their hard cap"
    );

    drop(clients.pop());
    timeout(TEST_TIMEOUT, overflow.read_exact(&mut response))
        .await
        .expect("overflow did not resume when one forward slot was released")
        .expect("read overflow response after backpressure released");
    assert_eq!(response, [b'x']);
    assert!(
        echo.active_connections.load(Ordering::SeqCst) <= MAX_CONCURRENT_FORWARDS,
        "forward count exceeded cap while handing the released slot to overflow"
    );

    drop(overflow);
    drop(clients);
    tunnel.shutdown();
    ssh.stop().await;
    echo.stop().await;
}

#[tokio::test]
async fn ssh_resilience_stalled_handshake_and_authentication_are_bounded() {
    let tofu = Arc::new(tokio::sync::Mutex::new(
        TofuStore::in_memory().expect("open in-memory TOFU store"),
    ));
    let (handshake_addr, handshake_task) = start_stalled_handshake_server().await;
    let handshake_error = match connect_endpoint_with_timeouts(
        &endpoint(handshake_addr),
        Arc::clone(&tofu),
        Arc::new(client::Config::default()),
        SHORT_TIMEOUT,
        TEST_TIMEOUT,
    )
    .await
    {
        Ok(_) => panic!("silent peer must not park SSH handshake"),
        Err(error) => error,
    };
    assert!(
        handshake_error
            .to_string()
            .contains("connect/handshake timed out"),
        "unexpected stalled-handshake error: {handshake_error:#}"
    );
    handshake_task.abort();
    let _ = handshake_task.await;

    let (auth_addr, auth_task) = start_stalled_auth_server().await;
    let auth_error = match connect_endpoint_with_timeouts(
        &endpoint(auth_addr),
        tofu,
        Arc::new(client::Config::default()),
        TEST_TIMEOUT,
        SHORT_TIMEOUT,
    )
    .await
    {
        Ok(_) => panic!("non-responsive authentication must be bounded"),
        Err(error) => error,
    };
    assert!(
        auth_error.to_string().contains("authentication timed out"),
        "unexpected stalled-auth error: {auth_error:#}"
    );
    auth_task.abort();
    let _ = auth_task.await;
}

#[tokio::test]
async fn ssh_resilience_inner_jump_operations_have_individual_deadlines() {
    let target = endpoint("127.0.0.1:9".parse().expect("parse discard endpoint"));

    let channel_jump = LoopbackSshServer::start().await;
    channel_jump
        .stall_next_forward
        .store(true, Ordering::SeqCst);
    let channel_tofu = Arc::new(tokio::sync::Mutex::new(
        TofuStore::in_memory().expect("open channel-timeout TOFU store"),
    ));
    let channel_error = match connect_via_jumps_with_timeouts(
        &[channel_jump.endpoint()],
        &target,
        channel_tofu,
        Arc::new(client::Config::default()),
        HOP_TIMEOUT,
        TEST_TIMEOUT,
        TEST_TIMEOUT,
    )
    .await
    {
        Ok(_) => panic!("stalled inner direct-tcpip open must time out"),
        Err(error) => error,
    };
    assert!(
        channel_error.to_string().contains("channel open timed out"),
        "unexpected inner channel timeout error: {channel_error:#}"
    );
    channel_jump.stop().await;

    let handshake_jump = LoopbackSshServer::start().await;
    let (handshake_addr, handshake_task) = start_stalled_handshake_server().await;
    let handshake_tofu = Arc::new(tokio::sync::Mutex::new(
        TofuStore::in_memory().expect("open inner-handshake TOFU store"),
    ));
    let handshake_error = match connect_via_jumps_with_timeouts(
        &[handshake_jump.endpoint()],
        &endpoint(handshake_addr),
        handshake_tofu,
        Arc::new(client::Config::default()),
        TEST_TIMEOUT,
        HOP_TIMEOUT,
        TEST_TIMEOUT,
    )
    .await
    {
        Ok(_) => panic!("stalled inner SSH handshake must time out"),
        Err(error) => error,
    };
    assert!(
        handshake_error
            .to_string()
            .contains("jump handshake timed out"),
        "unexpected inner handshake timeout error: {handshake_error:#}"
    );
    handshake_task.abort();
    let _ = handshake_task.await;
    handshake_jump.stop().await;

    let auth_jump = LoopbackSshServer::start().await;
    let (auth_addr, auth_task) = start_stalled_auth_server().await;
    let auth_tofu = Arc::new(tokio::sync::Mutex::new(
        TofuStore::in_memory().expect("open inner-auth TOFU store"),
    ));
    let auth_error = match connect_via_jumps_with_timeouts(
        &[auth_jump.endpoint()],
        &endpoint(auth_addr),
        auth_tofu,
        Arc::new(client::Config::default()),
        TEST_TIMEOUT,
        TEST_TIMEOUT,
        HOP_TIMEOUT,
    )
    .await
    {
        Ok(_) => panic!("stalled inner SSH authentication must time out"),
        Err(error) => error,
    };
    assert!(
        auth_error.to_string().contains("authentication timed out"),
        "unexpected inner auth timeout error: {auth_error:#}"
    );
    auth_task.abort();
    let _ = auth_task.await;
    auth_jump.stop().await;
}

#[tokio::test]
async fn ssh_resilience_dead_session_reconnects_to_replacement_on_same_listener() {
    let first = LoopbackSshServer::start().await;
    let ssh_addr = first.addr;
    let echo = LoopbackEcho::start().await;
    let tofu = Arc::new(tokio::sync::Mutex::new(
        TofuStore::in_memory().expect("open in-memory TOFU store"),
    ));
    let tunnel = spawn_tunnel(tunnel_config(first.endpoint(), echo.addr), tofu)
        .await
        .expect("spawn reconnecting SSH tunnel");
    let local_port = tunnel.local_port();

    roundtrip_eventually(local_port, b"before replacement").await;
    assert!(
        first.authentications.load(Ordering::SeqCst) >= 1,
        "initial server never authenticated the tunnel"
    );
    first.stop().await;

    let replacement = LoopbackSshServer::restart_at(ssh_addr).await;
    timeout(TEST_TIMEOUT, async {
        while replacement.authentications.load(Ordering::SeqCst) < 1 {
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .expect("replacement server never authenticated a reconnected session");
    roundtrip_eventually(local_port, b"after replacement").await;

    tunnel.shutdown();
    replacement.stop().await;
    echo.stop().await;
}
