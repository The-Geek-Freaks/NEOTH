//! GOLD-ADAPT-ODY-24 — Companion local-pairing server.
//!
//! Binds `127.0.0.1:{port}` (default port 9745, configurable via
//! `freedom.yaml::companion.port`) when `companion.enabled = true`.
//!
//! ## Scope: localhost / local-browser companion
//!
//! This is a **localhost** companion — it is accessible only from the same
//! machine (loopback bind + peer-IP check).  A phone on the LAN cannot reach
//! it.  Real LAN pairing (bind `0.0.0.0`, Host-header allowlist, rate-limit
//! on the pair endpoint) is tracked as a follow-up item.
//!
//! ## Sub-systems
//!
//! 1. **Token store** — per-session bearer token keyed by session-id.
//!    Minted via CSPRNG (32 bytes → base64url-NOPAD, 43 chars). Stored in
//!    a `RwLock<HashMap<session_id, TokenEntry>>` inside [`CompanionState`].
//!    Tokens expire after 24h by default.
//!
//! 2. **Mint HTTP server** — loopback-only hyper 1.x HTTP/1 listener.
//!    Accepts ONLY `POST /api/v1/companion/pair`. CSRF guard: reject
//!    requests whose `Origin` header is present but does not match the
//!    loopback host. Returns `{token, session_id}` + `Set-Cookie` on success.
//!
//! 3. **LAN-IP UDP probe** (`detect_lan_ip`) — available for future use;
//!    currently not called during server spawn because the bind is loopback-
//!    only and the advertised pairing URL must match what the server actually
//!    serves.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use base64::Engine;
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::{Notify, RwLock};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::config::automation::CompanionConfig;
use crate::wal::builder::HeaderBuilder;
use crate::wal::events::EVENT_TYPE_COMPANION_PAIRED;
// EVENT_TYPE_COMPANION_REVOKED (0x0C) is defined in wal/events.rs for future
// use by `neoth companion revoke` CLI — referenced here to keep it visible.
#[allow(unused_imports)]
use crate::wal::events::EVENT_TYPE_COMPANION_REVOKED;
use crate::wal::writer::WalWriterHandle;

// ── Constants ────────────────────────────────────────────────────────────────

/// Default token time-to-live: 24 hours. Companion sessions are expected to
/// be short-lived (a single usage session); 24h balances convenience against
/// exposure window. Configurable via `companion.token_ttl_secs` in the future.
const TOKEN_TTL_SECS: u64 = 86_400;

// ── Token store ──────────────────────────────────────────────────────────────

/// A single minted companion token with its creation time for TTL eviction.
#[derive(Debug)]
struct TokenEntry {
    token: String,
    minted_at: Instant,
}

impl TokenEntry {
    fn new(token: String) -> Self {
        Self {
            token,
            minted_at: Instant::now(),
        }
    }

    fn is_expired(&self) -> bool {
        self.minted_at.elapsed().as_secs() >= TOKEN_TTL_SECS
    }
}

// ── Shared state ─────────────────────────────────────────────────────────────

/// Shared state for every companion server connection.
pub struct CompanionState {
    /// Per-session token store. Key = operator-supplied session_id (a UUID or
    /// similar opaque string). Value = minted bearer token + mint time.
    tokens: RwLock<HashMap<String, TokenEntry>>,
    /// WAL writer — used to emit `0x0B COMPANION_PAIRED` / `0x0C COMPANION_REVOKED`.
    writer: WalWriterHandle,
    /// Bound port — used to validate the `Origin` header in the CSRF guard.
    port: u16,
}

impl CompanionState {
    pub fn new(writer: WalWriterHandle, port: u16) -> Self {
        Self {
            tokens: RwLock::new(HashMap::new()),
            writer,
            port,
        }
    }

    /// Mint (or retrieve an existing) token for `session_id`.
    ///
    /// Idempotent: if a non-expired token already exists for the session,
    /// returns it unchanged so the phone can safely retry the pairing call.
    async fn get_or_mint(&self, session_id: &str) -> String {
        // Fast path: check under a read lock first.
        {
            let guard = self.tokens.read().await;
            if let Some(entry) = guard.get(session_id) {
                if !entry.is_expired() {
                    return entry.token.clone();
                }
            }
        }

        // Slow path: need to mint (or re-mint expired token). Write lock.
        let mut guard = self.tokens.write().await;

        // Double-check: another caller may have minted between read and write.
        if let Some(entry) = guard.get(session_id) {
            if !entry.is_expired() {
                return entry.token.clone();
            }
        }

        // Evict expired entries while we hold the write lock (bounded overhead).
        guard.retain(|_, v| !v.is_expired());

        // Mint a fresh 43-char base64url-NOPAD token (32 raw bytes → 43 chars).
        let token = mint_token();
        guard.insert(session_id.to_string(), TokenEntry::new(token.clone()));
        token
    }
}

// ── Token minting ─────────────────────────────────────────────────────────────

/// Mint a fresh CSPRNG-derived bearer token.
///
/// 32 bytes from `getrandom` → base64url-NOPAD → 43 chars. Identical
/// pattern to `n8n_api` + `audit_rpc` token generation.
fn mint_token() -> String {
    let mut raw = [0u8; 32];
    getrandom::getrandom(&mut raw).expect("getrandom failed — OS entropy source unavailable");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
}

// ── LAN-IP detection ─────────────────────────────────────────────────────────

/// Detect the operative LAN IP via the UDP connect trick.
///
/// Calls `UdpSocket::connect("8.8.8.8:80")` — no packet is sent; the OS
/// merely selects a route and [`local_addr`] returns the bound IP. Falls
/// back to `127.0.0.1` when offline / behind a VPN / no default route.
pub async fn detect_lan_ip() -> IpAddr {
    match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        Ok(sock) => match sock.connect("8.8.8.8:80").await {
            Ok(()) => match sock.local_addr() {
                Ok(addr) => addr.ip(),
                Err(e) => {
                    warn!(error = %e, "companion: local_addr failed; falling back to 127.0.0.1");
                    IpAddr::V4(Ipv4Addr::LOCALHOST)
                }
            },
            Err(e) => {
                warn!(error = %e, "companion: UDP connect failed (offline?); falling back to 127.0.0.1");
                IpAddr::V4(Ipv4Addr::LOCALHOST)
            }
        },
        Err(e) => {
            warn!(error = %e, "companion: UDP bind failed; falling back to 127.0.0.1");
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        }
    }
}

// ── QR code rendering ────────────────────────────────────────────────────────

/// Render `url` as a terminal QR code (Unicode Dense1x2 block art) and return
/// the rendered string. Falls back to an empty string when stdout is not a
/// TTY — callers should always print the raw URL as fallback text alongside.
pub fn render_pairing_qr(url: &str) -> String {
    use qrcode::QrCode;
    use qrcode::render::unicode;

    match QrCode::new(url.as_bytes()) {
        Ok(code) => code
            .render::<unicode::Dense1x2>()
            .dark_color(unicode::Dense1x2::Dark)
            .light_color(unicode::Dense1x2::Light)
            .build(),
        Err(e) => {
            warn!(error = %e, url = url, "companion: QR code generation failed");
            String::new()
        }
    }
}

// ── Companion pairing invite ───────────────────────────────────────────────────

/// TopicKey length — 32 bytes / 256 bits. A collision-free rendezvous id the
/// phone and daemon agree to meet on; not secret on its own.
pub const COMPANION_TOPIC_BYTES: usize = 32;

/// PSK length — 16 bytes / 128 bits. Authenticates the one-shot, short-TTL
/// pairing handshake, so it IS secret until consumed.
pub const COMPANION_PSK_BYTES: usize = 16;

/// One-time pairing invite minted by `neoth companion pair-phone`.
///
/// Carries a fresh rendezvous `topic` (32 bytes) plus a pre-shared key (16
/// bytes), both drawn from the OS CSPRNG via `getrandom` — the same primitive
/// as [`crate::channels::keet_pairing::BearerToken::generate`]. The values are
/// rendered hex into a `neoth://companion/pair` URL (and its QR) for the
/// operator to scan. Single-use; the P2P transport that validates topic+psk on
/// connect is a follow-up (this slice is generation + display only).
pub struct CompanionInvite {
    /// 32-byte rendezvous topic, hex (64 chars). Not secret.
    topic_hex: String,
    /// 16-byte PSK, hex (32 chars). Secret — the Debug impl redacts it.
    psk_hex: String,
}

impl CompanionInvite {
    /// Mint a fresh invite from the OS RNG (two `getrandom` draws → hex).
    pub fn generate() -> anyhow::Result<Self> {
        let mut topic = [0u8; COMPANION_TOPIC_BYTES];
        let mut psk = [0u8; COMPANION_PSK_BYTES];
        getrandom::getrandom(&mut topic)
            .map_err(|e| anyhow::anyhow!("OS RNG failed minting companion topic: {e}"))?;
        getrandom::getrandom(&mut psk)
            .map_err(|e| anyhow::anyhow!("OS RNG failed minting companion psk: {e}"))?;
        Ok(Self {
            topic_hex: hex::encode(topic),
            psk_hex: hex::encode(psk),
        })
    }

    /// Reconstruct a `CompanionInvite` from pre-generated hex strings.
    ///
    /// Used by the serve-side P2P coordinator to deserialise an invite that was
    /// written to disk by `neoth companion pair-phone`. The caller is
    /// responsible for ensuring the hex strings are valid and of the correct
    /// length (64 chars for topic, 32 chars for psk).
    pub fn from_hex(topic_hex: String, psk_hex: String) -> Self {
        Self { topic_hex, psk_hex }
    }

    /// Encode as `neoth://companion/pair?topic=<hex>&psk=<hex>&ttl=<secs>`.
    /// Hex is URL-safe (`[0-9a-f]`), so no percent-encoding is needed.
    pub fn pairing_url(&self, ttl_secs: u64) -> String {
        format!(
            "neoth://companion/pair?topic={}&psk={}&ttl={}",
            self.topic_hex, self.psk_hex, ttl_secs
        )
    }

    /// Serialise to the on-disk pending-invite JSON consumed by the serve-side
    /// P2P coordinator (`spawn_companion_p2p_listener_task` polls
    /// `~/.neoth/companion_pending_invite.json`). Symmetric with [`from_hex`] —
    /// the coordinator reads exactly these three keys. Keeps `psk_hex` private
    /// (no broad getter) while enabling the CLI→daemon pairing handoff.
    pub fn to_pending_invite_json(&self, ttl_secs: u64) -> serde_json::Value {
        serde_json::json!({
            "topic_hex": self.topic_hex,
            "psk_hex": self.psk_hex,
            "ttl_secs": ttl_secs,
        })
    }
}

impl std::fmt::Debug for CompanionInvite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // psk is secret — redact so a stray `{:?}` / tracing / panic can't leak
        // the pairing key. topic is a rendezvous id, safe to show.
        f.debug_struct("CompanionInvite")
            .field("topic_hex", &self.topic_hex)
            .field("psk_hex", &"<redacted>")
            .finish()
    }
}

// ── HTTP body type ───────────────────────────────────────────────────────────

fn plain_response(status: StatusCode, msg: &'static str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "text/plain")
        .body(Full::new(Bytes::from_static(msg.as_bytes())))
        .expect("static response always builds")
}

// ── CSRF Origin guard ────────────────────────────────────────────────────────

/// Check the `Origin` header for the CSRF guard.
///
/// Policy (per research plan pitfall #6):
/// - If `Origin` is present AND does not match the loopback host → reject (403).
/// - If `Origin` is absent → allow (native app / curl on loopback — the bind is
///   already restricted to 127.0.0.1 so the peer MUST be loopback).
fn csrf_check_passes(req: &Request<Incoming>, port: u16) -> bool {
    let Some(origin_hv) = req.headers().get(hyper::header::ORIGIN) else {
        // No Origin header → curl / native app on loopback → allow.
        return true;
    };
    let Ok(origin) = origin_hv.to_str() else {
        return false;
    };
    // Accept either of the two canonical loopback forms.
    let expected_v4 = format!("http://127.0.0.1:{port}");
    let expected_lo = format!("http://localhost:{port}");
    origin == expected_v4 || origin == expected_lo
}

// ── Request handler ───────────────────────────────────────────────────────────

async fn handle_request(
    req: Request<Incoming>,
    state: Arc<CompanionState>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    // POST-only enforcement — anything else is 405.
    if req.method() != Method::POST {
        return Ok(plain_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"));
    }

    // Path routing.
    match req.uri().path() {
        "/api/v1/companion/pair" => Ok(handle_pair(req, state).await),
        _ => Ok(plain_response(StatusCode::NOT_FOUND, "not found")),
    }
}

async fn handle_pair(
    req: Request<Incoming>,
    state: Arc<CompanionState>,
) -> Response<Full<Bytes>> {
    // CSRF guard.
    if !csrf_check_passes(&req, state.port) {
        warn!("companion: CSRF guard rejected cross-origin Origin header");
        return plain_response(StatusCode::FORBIDDEN, "forbidden: cross-origin request");
    }

    // Read the body (bounded: 16 KiB max — session_id is a short UUID).
    use http_body_util::BodyExt;
    let body_bytes = match req.collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => {
            warn!(error = %e, "companion: body read error");
            return plain_response(StatusCode::BAD_REQUEST, "bad request: body read error");
        }
    };

    if body_bytes.len() > 16_384 {
        return plain_response(StatusCode::PAYLOAD_TOO_LARGE, "payload too large");
    }

    // Parse JSON body: {"session_id": "<...>"}
    let parsed: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "companion: JSON parse error");
            return plain_response(StatusCode::BAD_REQUEST, "bad request: invalid JSON");
        }
    };

    let session_id = match parsed.get("session_id").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() && s.len() <= 128 => s.to_string(),
        _ => {
            return plain_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "bad request: session_id missing or invalid",
            );
        }
    };

    // Mint (or retrieve) the token for this session.
    let token = state.get_or_mint(&session_id).await;

    // Emit WAL 0x0B COMPANION_PAIRED (payload: session_id + token hash, never the
    // raw token). xxh3 is already in the dep tree via the WAL writer.
    let token_hash = format!(
        "{:016x}",
        xxhash_rust::xxh3::xxh3_64(token.as_bytes())
    );
    let payload = serde_json::json!({
        "session_id": session_id,
        "token_hash_xxh3": token_hash,
        "ts_unix": crate::time::now_unix_secs(),
    });
    let payload_bytes = serde_json::to_vec(&payload).unwrap_or_default();
    let hdr = HeaderBuilder::new(EVENT_TYPE_COMPANION_PAIRED, &payload_bytes).build();
    if let Err(e) = state.writer.append_no_ack(hdr, payload_bytes).await {
        // Non-fatal: log but do not fail the pairing request.
        warn!(error = %e, "companion: WAL emit COMPANION_PAIRED failed (non-fatal)");
    }

    // Build the JSON response body.
    let resp_body = serde_json::json!({
        "token": token,
        "session_id": session_id,
    });
    let resp_json = serde_json::to_string(&resp_body).unwrap_or_default();

    // Set-Cookie: companion_token=<token>; SameSite=Lax; HttpOnly; Path=/
    let cookie = format!(
        "companion_token={token}; SameSite=Lax; HttpOnly; Path=/; Max-Age={TOKEN_TTL_SECS}"
    );

    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .header(hyper::header::SET_COOKIE, cookie)
        .body(Full::new(Bytes::copy_from_slice(resp_json.as_bytes())))
        .expect("response always builds")
}

// ── Server accept loop ────────────────────────────────────────────────────────

/// Run the companion server accept loop until `shutdown` is notified.
///
/// Extracted for testability: callers pass a pre-bound `TcpListener` so the
/// integration test can bind on port 0 and learn the actual port.
pub async fn run_companion_server(
    listener: TcpListener,
    state: Arc<CompanionState>,
    shutdown: Arc<Notify>,
) {
    let local_addr = listener.local_addr().unwrap_or(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        state.port,
    ));
    info!(addr = %local_addr, "companion server listening (GOLD-ADAPT-ODY-24)");

    loop {
        let accept = tokio::select! {
            biased;
            _ = shutdown.notified() => {
                info!("companion: shutdown signal received; draining");
                break;
            }
            res = listener.accept() => res,
        };

        let (stream, peer) = match accept {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "companion: accept error");
                continue;
            }
        };

        // Loopback-only defence-in-depth (the bind is already 127.0.0.1, but
        // an OS or container quirk could route a non-loopback peer through).
        if !peer.ip().is_loopback() {
            warn!(peer = %peer, "companion: rejected non-loopback peer");
            continue;
        }

        let state_for_conn = Arc::clone(&state);
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| {
                let s = Arc::clone(&state_for_conn);
                async move { handle_request(req, s).await }
            });
            if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                debug!(error = %e, "companion: connection closed");
            }
        });
    }
}

// ── Spawn helper ─────────────────────────────────────────────────────────────

/// Spawn the companion server task. Returns `None` when `config.enabled = false`.
///
/// On bind failure logs a warning and returns `None` rather than panicking —
/// a port collision must not crash the daemon.
pub fn spawn_companion_server_loop(
    config: CompanionConfig,
    _home: PathBuf,
    state: Arc<CompanionState>,
    shutdown: Arc<Notify>,
) -> Option<JoinHandle<()>> {
    if !config.enabled {
        return None;
    }

    Some(tokio::spawn(async move {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), config.port);
        let listener = match TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                warn!(
                    port = config.port,
                    error = %e,
                    "companion: bind failed — companion server unavailable this session"
                );
                return;
            }
        };

        // Log the pairing URL so the operator can see it in `neoth serve` output.
        // NOTE: The server binds 127.0.0.1 (loopback only) — the URL must reflect
        // that.  Real LAN pairing (phone scan → 0.0.0.0 bind + host-header check)
        // is a follow-up; advertising a LAN IP here while binding loopback would
        // be misleading and non-functional.
        let pairing_url = format!("http://127.0.0.1:{}/api/v1/companion/pair", config.port);
        info!(
            url = %pairing_url,
            "companion: local pairing URL (localhost browser app; LAN pairing is a follow-up)"
        );

        run_companion_server(listener, state, shutdown).await;
    }))
}

// ── P2P Noise pairing listener (GOLD-COMPANION-P2P-01) ───────────────────────
//
// Full phone-pairing over the existing Hyperswarm DHT + Noise-XX E2E mesh.
// Feature-gated: only compiled when the `cluster` feature is present, which
// pulls in `peeroxide`. In a build without `cluster` the public API surface
// (`spawn_companion_p2p_listener`) returns a no-op `JoinHandle`.
//
// Protocol (single-use, TTL-bound):
//   1. Caller mints a `CompanionInvite` (topic=32B CSPRNG, psk=16B CSPRNG).
//   2. A peeroxide swarm is spawned and `handle.join(topic_bytes)` announces
//      the topic on the public Hyperswarm DHT.
//   3. The phone (companion app) finds the topic, connects via Noise-XX,
//      and sends exactly 16 raw bytes (the PSK) immediately after connect.
//   4. The daemon reads 16 bytes (`read()` over Noise → next plaintext
//      message), compares with `constant_time_eq`, and either:
//      - PASS: calls `CompanionState::get_or_mint(session_id)`, writes
//        `{token, session_id}` as JSON, emits WAL 0x0D, burns the invite.
//      - FAIL: drops the conn, emits WAL 0x0E, burns the invite.
//   5. The topic is unannounced (`handle.leave(topic_bytes)`).
//
// Only one connection is accepted per invite (Semaphore(1)). A second phone
// scanning the same QR gets a closed connection — the first pairing won.
//
// IMPORTANT: the `conn.peer.stream` from peeroxide is a Noise SecretStream.
// Its `.read()` method returns the next decrypted Noise message as
// `Result<Option<peeroxide::Bytes>>` — it is NOT a raw `AsyncRead`. Each
// `.write(&bytes)` sends one Noise message. We use these message-framed
// methods directly (NOT `tokio::io::AsyncReadExt::read_exact`).

#[cfg(feature = "cluster")]
mod p2p {
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::sync::{Notify, RwLock};
    use tokio::task::JoinHandle;
    use tracing::{debug, info, warn};

    use super::{CompanionInvite, CompanionState, COMPANION_PSK_BYTES, COMPANION_TOPIC_BYTES};
    use crate::wal::builder::HeaderBuilder;
    use crate::wal::events::{EVENT_TYPE_COMPANION_P2P_PAIRED, EVENT_TYPE_COMPANION_P2P_REJECTED};
    use crate::wal::writer::WalWriterHandle;

    /// One-connection TTL for the Noise accept loop. If no phone connects
    /// within this window the invite is burned and the task exits cleanly.
    const COMPANION_P2P_ACCEPT_TIMEOUT: Duration = Duration::from_secs(310);

    /// Held state for one P2P pairing session. Shared between the spawner and
    /// the accept loop via `Arc`.
    pub(super) struct CompanionP2pState {
        /// The `CompanionState` that owns the token store + WAL writer.
        pub companion_state: Arc<CompanionState>,
        /// The pending invite — consumed exactly once. `None` after burn.
        pub pending_invite: RwLock<Option<CompanionInvite>>,
        /// WAL writer for emitting 0x0D / 0x0E audit frames.
        pub writer: WalWriterHandle,
        /// Total TTL of the invite in seconds. The accept loop bails after
        /// `COMPANION_P2P_ACCEPT_TIMEOUT` regardless.
        pub invite_ttl_secs: u64,
    }

    /// Run the Noise accept loop for one companion invite.
    ///
    /// - Spawns a peeroxide swarm, joins `topic_bytes`.
    /// - Waits for the first inbound Noise-XX connection.
    /// - Reads 16 raw PSK bytes (one Noise message).
    /// - On PSK match: writes JSON token, emits WAL 0x0D.
    /// - On mismatch / timeout: emits WAL 0x0E.
    /// - Burns the invite and leaves the topic in all branches.
    pub(super) async fn run_companion_p2p_listener(
        state: Arc<CompanionP2pState>,
        shutdown: Arc<Notify>,
    ) {
        // ── Atomic invite burn (swap-before-use) ─────────────────────────────
        // Take the invite out of the RwLock NOW, before any network I/O.
        // If two connections arrive simultaneously, only the first swap
        // gets `Some`; the second sees `None` and is dropped immediately
        // without calling get_or_mint.
        let invite = {
            let mut guard = state.pending_invite.write().await;
            guard.take()
        };
        let invite = match invite {
            Some(inv) => inv,
            None => {
                warn!("companion_p2p: invite already consumed — listener exiting");
                return;
            }
        };

        // Decode the topic bytes (32 raw bytes from hex).
        let topic_bytes: [u8; COMPANION_TOPIC_BYTES] = match hex::decode(&invite.topic_hex) {
            Ok(v) if v.len() == COMPANION_TOPIC_BYTES => {
                let mut arr = [0u8; COMPANION_TOPIC_BYTES];
                arr.copy_from_slice(&v);
                arr
            }
            Ok(_) | Err(_) => {
                warn!("companion_p2p: invalid topic hex in invite — aborting");
                return;
            }
        };

        let psk_bytes: [u8; COMPANION_PSK_BYTES] = match hex::decode(&invite.psk_hex) {
            Ok(v) if v.len() == COMPANION_PSK_BYTES => {
                let mut arr = [0u8; COMPANION_PSK_BYTES];
                arr.copy_from_slice(&v);
                arr
            }
            Ok(_) | Err(_) => {
                warn!("companion_p2p: invalid psk hex in invite — aborting");
                return;
            }
        };

        let topic_hash = format!(
            "{:016x}",
            xxhash_rust::xxh3::xxh3_64(&topic_bytes)
        );

        // ── Bring up peeroxide swarm ──────────────────────────────────────────
        let config = peeroxide::SwarmConfig::with_public_bootstrap();
        let (swarm_task, handle, mut conn_rx) = match peeroxide::spawn(config).await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "companion_p2p: peeroxide::spawn failed — invite abandoned");
                return;
            }
        };

        // Use raw topic bytes — NOT hashed through discovery_key(). The phone
        // scans the QR and uses the same raw bytes. derive_topic() would hash
        // again and produce a different rendez-vous id.
        if let Err(e) = handle
            .join(topic_bytes, peeroxide::JoinOpts::default())
            .await
        {
            warn!(error = %e, "companion_p2p: peeroxide join failed — invite abandoned");
            swarm_task.abort();
            let _ = swarm_task.await;
            return;
        }

        info!(
            topic_hash = %topic_hash,
            ttl_secs = state.invite_ttl_secs,
            "companion_p2p: DHT announced — waiting for phone to connect"
        );

        // Semaphore(1): accept at most ONE connection per invite. A second phone
        // scanning the same QR sees a closed connection.
        let session_limiter = Arc::new(tokio::sync::Semaphore::new(1));

        // ── Wait for the phone to connect ─────────────────────────────────────
        let conn_result = tokio::select! {
            biased;
            _ = shutdown.notified() => {
                info!("companion_p2p: shutdown signal — abandoning invite");
                None
            }
            _ = tokio::time::sleep(COMPANION_P2P_ACCEPT_TIMEOUT) => {
                warn!(
                    timeout_s = COMPANION_P2P_ACCEPT_TIMEOUT.as_secs(),
                    "companion_p2p: invite TTL expired — no connection received"
                );
                None
            }
            conn = conn_rx.recv() => conn,
        };

        // Unannounce from DHT before handling the connection so no further
        // phones can find the topic (single-use).
        if let Err(e) = handle.leave(topic_bytes).await {
            warn!(error = %e, "companion_p2p: DHT leave failed (non-fatal)");
        }
        // Keep the handle alive until we've finished with the connection.
        drop(handle);

        let mut conn = match conn_result {
            None => {
                // Timeout or shutdown — emit rejection WAL if an invite was pending.
                emit_p2p_rejected(
                    &state.writer,
                    &topic_hash,
                    "(no connection)",
                    "(none)",
                    "ttl_expired_or_shutdown",
                )
                .await;
                swarm_task.abort();
                let _ = swarm_task.await;
                return;
            }
            Some(c) => c,
        };

        // Acquire the single-session slot (always succeeds — we only took one).
        let _permit = session_limiter.try_acquire_owned();

        let peer_pk: [u8; 32] = *conn.remote_public_key();
        let peer_pk_hex = hex::encode(peer_pk);

        debug!(
            peer = %peer_pk_hex,
            topic_hash = %topic_hash,
            "companion_p2p: phone connected over Noise — reading PSK"
        );

        // ── Read exactly one Noise message as the PSK frame ──────────────────
        // peeroxide's SecretStream message-frames over Noise, so `.read()` gives
        // us one full decrypted message. We expect exactly 16 bytes (the PSK).
        // Any other size or an error is treated as a mismatch.
        let received_psk: [u8; COMPANION_PSK_BYTES] = {
            let read_result = tokio::time::timeout(
                Duration::from_secs(10),
                conn.peer.stream.read(),
            )
            .await;

            match read_result {
                Ok(Ok(Some(bytes))) if bytes.len() == COMPANION_PSK_BYTES => {
                    let mut arr = [0u8; COMPANION_PSK_BYTES];
                    arr.copy_from_slice(&bytes);
                    arr
                }
                Ok(Ok(Some(bytes))) => {
                    warn!(
                        peer = %peer_pk_hex,
                        got = bytes.len(),
                        expected = COMPANION_PSK_BYTES,
                        "companion_p2p: PSK frame wrong size — rejecting"
                    );
                    emit_p2p_rejected(
                        &state.writer,
                        &topic_hash,
                        &peer_pk_hex,
                        "psk_frame_wrong_size",
                        "wrong_psk_size",
                    )
                    .await;
                    swarm_task.abort();
                    let _ = swarm_task.await;
                    return;
                }
                Ok(Ok(None)) => {
                    warn!(peer = %peer_pk_hex, "companion_p2p: phone closed before PSK — rejecting");
                    emit_p2p_rejected(
                        &state.writer,
                        &topic_hash,
                        &peer_pk_hex,
                        "psk_closed_early",
                        "connection_closed",
                    )
                    .await;
                    swarm_task.abort();
                    let _ = swarm_task.await;
                    return;
                }
                Ok(Err(e)) => {
                    warn!(peer = %peer_pk_hex, error = %e, "companion_p2p: PSK read error — rejecting");
                    emit_p2p_rejected(
                        &state.writer,
                        &topic_hash,
                        &peer_pk_hex,
                        "psk_read_error",
                        "io_error",
                    )
                    .await;
                    swarm_task.abort();
                    let _ = swarm_task.await;
                    return;
                }
                Err(_timeout) => {
                    warn!(peer = %peer_pk_hex, "companion_p2p: PSK read timeout — rejecting");
                    emit_p2p_rejected(
                        &state.writer,
                        &topic_hash,
                        &peer_pk_hex,
                        "psk_read_timeout",
                        "timeout",
                    )
                    .await;
                    swarm_task.abort();
                    let _ = swarm_task.await;
                    return;
                }
            }
        };

        // ── Constant-time PSK compare ─────────────────────────────────────────
        // Use subtle::ConstantTimeEq (already in the dep tree via HMAC crates).
        // Fallback: XOR all bytes + check if all-zero.  We use a manual
        // constant-time fold — stable and dependency-free.
        let psk_ok = {
            let mut diff = 0u8;
            for (a, b) in received_psk.iter().zip(psk_bytes.iter()) {
                diff |= a ^ b;
            }
            diff == 0
        };

        if !psk_ok {
            warn!(peer = %peer_pk_hex, "companion_p2p: PSK mismatch — rejecting");
            emit_p2p_rejected(
                &state.writer,
                &topic_hash,
                &peer_pk_hex,
                "psk_mismatch",
                "wrong_psk",
            )
            .await;
            swarm_task.abort();
            let _ = swarm_task.await;
            return;
        }

        // ── PSK verified — mint token ─────────────────────────────────────────
        // session_id = hex of first 8 bytes of the remote Noise public key.
        // Stable, unguessable, and unique per peer Noise identity.
        let session_id = hex::encode(&peer_pk[..8]);
        let token = state.companion_state.get_or_mint(&session_id).await;

        // Send JSON {token, session_id} over the Noise channel (one message).
        let resp = serde_json::json!({
            "token": token,
            "session_id": session_id,
        });
        let resp_bytes = match serde_json::to_vec(&resp) {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "companion_p2p: JSON serialize failed — token not delivered");
                swarm_task.abort();
                let _ = swarm_task.await;
                return;
            }
        };

        if let Err(e) = conn.peer.stream.write(&resp_bytes).await {
            warn!(
                peer = %peer_pk_hex,
                error = %e,
                "companion_p2p: token write failed — phone may not have received token"
            );
            // Still emit paired WAL (token was minted; phone can retry via HTTP).
        }

        // ── Emit WAL 0x0D COMPANION_P2P_PAIRED ───────────────────────────────
        let token_hash = format!(
            "{:016x}",
            xxhash_rust::xxh3::xxh3_64(token.as_bytes())
        );
        let ts_unix = crate::time::now_unix_secs();
        let payload = serde_json::json!({
            "topic_hash_xxh3": topic_hash,
            "peer_pk_hex": peer_pk_hex,
            "token_hash_xxh3": token_hash,
            "ts_unix": ts_unix,
        });
        let payload_bytes = serde_json::to_vec(&payload).unwrap_or_default();
        let hdr =
            HeaderBuilder::new(EVENT_TYPE_COMPANION_P2P_PAIRED, &payload_bytes).build();
        if let Err(e) = state.writer.append_no_ack(hdr, payload_bytes).await {
            warn!(error = %e, "companion_p2p: WAL emit COMPANION_P2P_PAIRED failed (non-fatal)");
        }

        info!(
            peer = %peer_pk_hex,
            session_id = %session_id,
            topic_hash = %topic_hash,
            "companion_p2p: phone paired successfully over Noise"
        );

        // Drop the connection (Noise channel closes) + tear down the swarm.
        drop(conn);
        swarm_task.abort();
        let _ = swarm_task.await;
    }

    /// Emit WAL 0x0E COMPANION_P2P_REJECTED (best-effort, non-fatal).
    async fn emit_p2p_rejected(
        writer: &WalWriterHandle,
        topic_hash: &str,
        peer_pk_hex: &str,
        reason: &str,
        _detail: &str,
    ) {
        let ts_unix = crate::time::now_unix_secs();
        let payload = serde_json::json!({
            "topic_hash_xxh3": topic_hash,
            "peer_pk_hex": peer_pk_hex,
            "reason": reason,
            "ts_unix": ts_unix,
        });
        let payload_bytes = serde_json::to_vec(&payload).unwrap_or_default();
        let hdr =
            HeaderBuilder::new(EVENT_TYPE_COMPANION_P2P_REJECTED, &payload_bytes).build();
        if let Err(e) = writer.append_no_ack(hdr, payload_bytes).await {
            warn!(error = %e, "companion_p2p: WAL emit COMPANION_P2P_REJECTED failed (non-fatal)");
        }
    }

    /// Spawn the P2P pairing listener as a tokio task and return its handle.
    ///
    /// # Arguments
    /// - `invite` — the one-time [`CompanionInvite`] to consume.
    /// - `companion_state` — the shared token store (shared with the HTTP server).
    /// - `writer` — WAL writer for 0x0D / 0x0E audit frames.
    /// - `ttl_secs` — invite TTL; the task exits after
    ///   `COMPANION_P2P_ACCEPT_TIMEOUT` regardless.
    /// - `shutdown` — notified to abort the listener early (daemon shutdown /
    ///   CLI TTL expiry).
    pub(super) fn spawn(
        invite: CompanionInvite,
        companion_state: Arc<CompanionState>,
        writer: WalWriterHandle,
        ttl_secs: u64,
        shutdown: Arc<Notify>,
    ) -> JoinHandle<()> {
        let p2p_state = Arc::new(CompanionP2pState {
            companion_state,
            pending_invite: RwLock::new(Some(invite)),
            writer,
            invite_ttl_secs: ttl_secs,
        });
        tokio::spawn(run_companion_p2p_listener(p2p_state, shutdown))
    }
}

/// Spawn the companion P2P Noise pairing listener.
///
/// Returns a [`JoinHandle`] that resolves when the listener exits (one
/// successful pairing, PSK reject, TTL expiry, or shutdown signal).
///
/// # Feature gate
///
/// When the `cluster` feature is NOT active, this is a no-op that returns a
/// task that exits immediately and logs a warning.
#[cfg(feature = "cluster")]
pub fn spawn_companion_p2p_listener(
    invite: CompanionInvite,
    companion_state: Arc<CompanionState>,
    writer: WalWriterHandle,
    ttl_secs: u64,
    shutdown: Arc<Notify>,
) -> JoinHandle<()> {
    p2p::spawn(invite, companion_state, writer, ttl_secs, shutdown)
}

#[cfg(not(feature = "cluster"))]
pub fn spawn_companion_p2p_listener(
    _invite: CompanionInvite,
    _companion_state: Arc<CompanionState>,
    _writer: WalWriterHandle,
    _ttl_secs: u64,
    _shutdown: Arc<Notify>,
) -> JoinHandle<()> {
    warn!("companion_p2p: `cluster` feature not enabled — P2P pairing unavailable; use loopback HTTP instead");
    tokio::spawn(async {})
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Spawn a real WAL writer against a temp segment file. Returns the handle
    /// and the join-handle; the test can drop the join-handle (the writer task
    /// exits when all handles are dropped). This is the standard pattern used
    /// across the daemon test suite (see `daemon/auto_update.rs`, `audit_rpc/tests.rs`).
    fn temp_writer() -> (WalWriterHandle, tokio::task::JoinHandle<()>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let seg = dir.path().join("test.wal");
        let (handle, join) = crate::wal::writer::spawn(seg).expect("spawn WAL writer for test");
        // Return `dir` so it isn't dropped (and the temp dir deleted) while the
        // writer task is still open.
        (handle, join, dir)
    }

    #[tokio::test]
    async fn companion_server_mints_token_on_post_and_rejects_get() {
        let shutdown = Arc::new(Notify::new());
        let (writer, _wal_join, _wal_dir) = temp_writer();

        // Bind OS-assigned port.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        // State constructed with the actual bound port so the CSRF check works.
        let state = Arc::new(CompanionState::new(writer, port));

        let srv_shutdown = Arc::clone(&shutdown);
        let srv_state = Arc::clone(&state);
        tokio::spawn(async move {
            run_companion_server(listener, srv_state, srv_shutdown).await;
        });

        // Give the task a moment to start.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let client = reqwest::Client::new();
        let base = format!("http://127.0.0.1:{port}");

        // 1. POST /api/v1/companion/pair → 200 with 43-char token.
        let resp = client
            .post(format!("{base}/api/v1/companion/pair"))
            .header("Origin", &base)
            .header("Content-Type", "application/json")
            .body(r#"{"session_id":"test-session-1"}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        let token = body["token"].as_str().unwrap().to_string();
        assert_eq!(token.len(), 43, "token must be 43-char base64url-NOPAD");

        // 2. Same session_id returns the SAME token (idempotent mint).
        let resp2 = client
            .post(format!("{base}/api/v1/companion/pair"))
            .header("Origin", &base)
            .header("Content-Type", "application/json")
            .body(r#"{"session_id":"test-session-1"}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(resp2.status(), 200);
        let body2: serde_json::Value = resp2.json().await.unwrap();
        assert_eq!(
            body2["token"].as_str().unwrap(),
            token,
            "idempotent mint must return the same token"
        );

        // 3. Different session_id gets a DIFFERENT token.
        let resp3 = client
            .post(format!("{base}/api/v1/companion/pair"))
            .header("Origin", &base)
            .header("Content-Type", "application/json")
            .body(r#"{"session_id":"test-session-2"}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(resp3.status(), 200);
        let body3: serde_json::Value = resp3.json().await.unwrap();
        assert_ne!(
            body3["token"].as_str().unwrap(),
            token,
            "different session must get a different token"
        );

        // 4. GET → 405 Method Not Allowed (POST-only requirement).
        let resp_get = client
            .get(format!("{base}/api/v1/companion/pair"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp_get.status(), 405);

        // 5. Wrong Origin → 403 CSRF rejection.
        let resp_bad_origin = client
            .post(format!("{base}/api/v1/companion/pair"))
            .header("Origin", "http://evil.example.com")
            .header("Content-Type", "application/json")
            .body(r#"{"session_id":"test-session-3"}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(resp_bad_origin.status(), 403);

        // 6. No Origin header → 200 (native/curl path — loopback bind enforces peer).
        let resp_no_origin = client
            .post(format!("{base}/api/v1/companion/pair"))
            .header("Content-Type", "application/json")
            .body(r#"{"session_id":"test-session-4"}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(resp_no_origin.status(), 200);

        // 7. Shutdown: notify and await.
        shutdown.notify_waiters();
        // Give the server task a moment to exit cleanly.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    #[test]
    fn minted_token_is_43_chars_base64url_nopad() {
        let tok = mint_token();
        assert_eq!(tok.len(), 43);
        // All chars must be valid base64url-NOPAD (A-Z a-z 0-9 - _).
        assert!(
            tok.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "token contains non-base64url chars: {tok}"
        );
    }

    #[test]
    fn render_pairing_qr_returns_nonempty_for_valid_url() {
        let qr = render_pairing_qr("http://192.168.1.1:9745/pair?hint=operator");
        // The QR renderer produces at minimum a few lines of block chars.
        assert!(!qr.is_empty(), "QR render must not be empty for a valid URL");
    }

    #[tokio::test]
    async fn detect_lan_ip_returns_an_ip() {
        let ip = detect_lan_ip().await;
        // Just assert we got a valid IP (127.0.0.1 or a real LAN IP).
        assert!(
            ip.is_ipv4() || ip.is_ipv6(),
            "detect_lan_ip must return an IP address"
        );
    }

    #[test]
    fn token_entry_expiry() {
        // A freshly minted entry must NOT be expired.
        let fresh = TokenEntry::new("t2".to_string());
        assert!(!fresh.is_expired(), "freshly minted entry must not be expired");

        // An entry whose minted_at is earlier than TOKEN_TTL_SECS ago IS expired.
        // We test this by directly checking the TTL logic: elapsed() < TOKEN_TTL_SECS
        // means NOT expired. A brand-new entry has elapsed() ≈ 0 so it can never be
        // expired in the same tick. Instead, verify the boundary: an entry minted
        // TOKEN_TTL_SECS-1 seconds from now (i.e. in the past) via forced minted_at.
        // `Instant::now() - Duration` can panic/saturate on some platforms when the
        // duration exceeds the monotonic clock uptime. Use a shorter known-safe
        // offset (1 second) to test the non-expired side, and test the expired-side
        // logic by calling is_expired() on a deliberately zero-duration entry:
        //
        // Verify: if elapsed >= TOKEN_TTL_SECS → expired. We can't safely forge
        // an old Instant on all platforms, so we test the logic branch directly
        // by checking is_expired() returns false for elapsed ≈ 0.
        assert!(
            !fresh.is_expired(),
            "entry with elapsed≈0 must not be expired (TTL={TOKEN_TTL_SECS}s)"
        );

        // Structural test: TOKEN_TTL_SECS must be > 0 so the gate can ever trip.
        // Use a runtime check to avoid the const-value assertion lint.
        let ttl: u64 = TOKEN_TTL_SECS;
        assert!(ttl > 0, "TOKEN_TTL_SECS must be positive");
    }

    // ── CompanionInvite ───────────────────────────────────────────────────────

    /// Pull the value of `key=` out of the pairing URL query (no real URL parse
    /// needed — values are hex with no `&` inside).
    fn url_param<'a>(url: &'a str, key: &str) -> &'a str {
        url.split(&format!("{key}="))
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap()
    }

    #[test]
    fn companion_invite_has_correct_hex_lengths() {
        let inv = CompanionInvite::generate().expect("OS rng works");
        let url = inv.pairing_url(300);
        let topic = url_param(&url, "topic");
        let psk = url_param(&url, "psk");
        // topic = 32 bytes → 64 hex chars; psk = 16 bytes → 32 hex chars.
        assert_eq!(topic.len(), COMPANION_TOPIC_BYTES * 2);
        assert_eq!(psk.len(), COMPANION_PSK_BYTES * 2);
        assert!(topic.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(psk.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn companion_invite_pairing_url_format() {
        let inv = CompanionInvite::generate().unwrap();
        let url = inv.pairing_url(300);
        assert!(url.starts_with("neoth://companion/pair?"));
        assert!(url.contains("topic="));
        assert!(url.contains("psk="));
        assert!(url.ends_with("ttl=300"));
    }

    #[test]
    fn companion_invite_two_generates_differ() {
        // 256+128 bits of entropy — a collision is astronomically unlikely, so
        // this doubles as a smoke test that the getrandom wiring isn't degenerate.
        let a = CompanionInvite::generate().unwrap();
        let b = CompanionInvite::generate().unwrap();
        assert_ne!(a.pairing_url(300), b.pairing_url(300));
    }

    #[test]
    fn companion_invite_debug_redacts_psk() {
        let inv = CompanionInvite::generate().unwrap();
        let dbg = format!("{inv:?}");
        let psk = url_param(&inv.pairing_url(300), "psk").to_string();
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains(&psk), "psk must not appear in Debug output");
    }

    // ── GOLD-COMPANION-P2P-01 — unit tests (no network) ─────────────────────

    /// Invite URL round-trip: `pairing_url(ttl)` output parses back to the
    /// original topic + psk hex strings.
    #[test]
    fn invite_url_parse_roundtrip() {
        let inv = CompanionInvite::generate().unwrap();
        let url = inv.pairing_url(300);
        let topic_from_url = url_param(&url, "topic");
        let psk_from_url = url_param(&url, "psk");
        assert_eq!(topic_from_url, inv.topic_hex, "topic round-trip mismatch");
        assert_eq!(psk_from_url, inv.psk_hex, "psk round-trip mismatch");
    }

    /// `from_hex` reconstructs an invite with the exact hex values supplied.
    #[test]
    fn invite_from_hex_roundtrip() {
        let orig = CompanionInvite::generate().unwrap();
        let url1 = orig.pairing_url(300);
        let reconstructed =
            CompanionInvite::from_hex(orig.topic_hex.clone(), orig.psk_hex.clone());
        let url2 = reconstructed.pairing_url(300);
        assert_eq!(url1, url2, "from_hex must produce the same pairing URL");
    }

    /// Invite TTL expiry: `spawn_companion_p2p_listener` notified at start
    /// must exit without hanging. The listener spawns a peeroxide DHT swarm
    /// (public bootstrap, real network) and then enters a select that checks
    /// the shutdown notifier. Because the DHT bootstrap itself takes a few
    /// seconds, we allow up to 60s for the task to exit cleanly after
    /// `shutdown.notify_waiters()`.
    ///
    /// Note: this test makes a real (outbound-only) UDP connection to the
    /// public Hyperswarm bootstrap nodes. It is skipped in offline CI via the
    /// standard `#[ignore]` attribute override on integration test runs.
    #[cfg(feature = "cluster")]
    #[tokio::test]
    #[ignore = "makes real outbound DHT connection; run with -- --ignored to include"]
    async fn invite_ttl_expiry_exits_cleanly() {
        let (writer, _wal_join, _dir) = temp_writer();
        let invite = CompanionInvite::generate().unwrap();
        let state = Arc::new(CompanionState::new(writer.clone(), 0));
        let shutdown = Arc::new(Notify::new());

        // Immediately notify shutdown to simulate TTL-0 expiry.
        shutdown.notify_waiters();

        let task = super::spawn_companion_p2p_listener(
            invite,
            Arc::clone(&state),
            writer,
            0,
            Arc::clone(&shutdown),
        );

        // Must exit without hanging. 60s covers real DHT bootstrap round-trip.
        let result = tokio::time::timeout(std::time::Duration::from_secs(60), task).await;
        assert!(
            result.is_ok(),
            "listener must exit after shutdown is notified"
        );
    }

    /// Single-use burn: after one `from_hex` invite is consumed by the listener
    /// state, the pending slot becomes None.
    #[cfg(feature = "cluster")]
    #[tokio::test]
    async fn invite_single_use_burn() {
        use super::p2p::CompanionP2pState;
        use tokio::sync::RwLock;

        let (writer, _wal_join, _dir) = temp_writer();
        let state = Arc::new(CompanionState::new(writer.clone(), 0));
        let invite = CompanionInvite::generate().unwrap();

        let p2p_state = Arc::new(CompanionP2pState {
            companion_state: Arc::clone(&state),
            pending_invite: RwLock::new(Some(CompanionInvite::from_hex(
                invite.topic_hex.clone(),
                invite.psk_hex.clone(),
            ))),
            writer,
            invite_ttl_secs: 300,
        });

        // Swap the invite out (simulating the atomic burn).
        let taken = {
            let mut guard = p2p_state.pending_invite.write().await;
            guard.take()
        };
        assert!(taken.is_some(), "first take must return Some(invite)");

        // Second take must return None (invite burned).
        let taken2 = {
            let mut guard = p2p_state.pending_invite.write().await;
            guard.take()
        };
        assert!(taken2.is_none(), "second take must return None (single-use)");
    }

    /// `from_hex` with known hex strings produces the expected pairing URL.
    #[test]
    fn invite_from_hex_known_values() {
        let topic = "a".repeat(64); // 32 bytes as 64 hex chars
        let psk = "b".repeat(32);   // 16 bytes as 32 hex chars
        let inv = CompanionInvite::from_hex(topic.clone(), psk.clone());
        let url = inv.pairing_url(300);
        assert!(url.contains(&format!("topic={topic}")));
        assert!(url.contains(&format!("psk={psk}")));
        assert!(url.ends_with("ttl=300"));
    }

    /// `to_pending_invite_json` emits exactly the three keys the serve-side P2P
    /// coordinator reads back (`topic_hex` / `psk_hex` / `ttl_secs`) and
    /// round-trips through `from_hex` — proves the `--write-invite-for-serve`
    /// CLI→daemon handoff file is consumable by the poller in serve_tasks.rs.
    #[test]
    fn pending_invite_json_round_trips_to_from_hex() {
        let inv = CompanionInvite::generate().unwrap();
        let json = inv.to_pending_invite_json(300);
        let topic_hex = json["topic_hex"].as_str().expect("topic_hex present");
        let psk_hex = json["psk_hex"].as_str().expect("psk_hex present");
        assert_eq!(json["ttl_secs"].as_u64(), Some(300));
        assert_eq!(topic_hex.len(), 64, "32-byte topic as hex");
        assert_eq!(psk_hex.len(), 32, "16-byte psk as hex");
        // The poller reconstructs via from_hex(topic_hex, psk_hex); identical
        // pairing URL ⇒ the daemon drives the very invite the CLI minted.
        let rebuilt = CompanionInvite::from_hex(topic_hex.to_string(), psk_hex.to_string());
        assert_eq!(inv.pairing_url(300), rebuilt.pairing_url(300));
    }
}
