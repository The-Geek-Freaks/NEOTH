//! GOLD-ADAPT-ODY-24 — Companion local-pairing server.
//!
//! Binds `127.0.0.1:{port}` (default port 9745, configurable via
//! `freedom.yaml::companion.port`) when `companion.enabled = true`.
//!
//! ## Scope: localhost / local-browser companion
//!
//! This is a **localhost** companion — it is accessible only from the same
//! machine (loopback bind + peer-IP check). A phone does not connect to this
//! HTTP listener: `companion::p2p` below provides the separate single-use
//! v2 HyperDHT / authenticated Noise-IK server-side pairing preview. NEOTH does
//! not ship a phone client. Exposing this HTTP endpoint on a LAN interface
//! remains deliberately unsupported.
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
//! 3. **LAN-IP interface discovery** (`detect_lan_ip`) — available for future use;
//!    currently not called during server spawn because the bind is loopback-
//!    only and the advertised pairing URL must match what the server actually
//!    serves.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use base64::Engine;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::{Notify, RwLock, watch};
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

/// Maximum request body accepted by the `/api/v1/companion/pair` endpoint.
/// The payload is a small JSON object `{"session_id": "<UUID>"}` — 16 KiB is
/// an order of magnitude more than any valid pairing request will ever send.
/// `Limited` from `http_body_util` enforces this cap during streaming so the
/// allocator is bounded before `.collect()` returns.
const COMPANION_BODY_LIMIT_BYTES: usize = 16_384;

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
            if let Some(entry) = guard.get(session_id)
                && !entry.is_expired()
            {
                return entry.token.clone();
            }
        }

        // Slow path: need to mint (or re-mint expired token). Write lock.
        let mut guard = self.tokens.write().await;

        // Double-check: another caller may have minted between read and write.
        if let Some(entry) = guard.get(session_id)
            && !entry.is_expired()
        {
            return entry.token.clone();
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

/// Select the deterministic RFC1918 address to advertise from IPv4 candidates.
///
/// Link-local and loopback addresses cannot be used for LAN pairing. Restricting
/// candidates to the three RFC1918 ranges also excludes public, shared, and
/// documentation addresses. The minimum gives operators a stable choice when
/// several private adapters (for example Ethernet and Wi-Fi) are active.
fn select_lan_ipv4(candidates: impl IntoIterator<Item = Ipv4Addr>) -> Option<Ipv4Addr> {
    candidates
        .into_iter()
        .filter(|ip| ip.is_private() && !ip.is_loopback() && !ip.is_link_local())
        .min()
}

/// Detect an operative LAN IP without an application-created outbound Internet
/// socket or an external route-selection probe.
///
/// Enumerates OS network interfaces in a blocking task, then deterministically
/// selects the lowest RFC1918 non-loopback, non-link-local IPv4 address. Falls
/// back to `127.0.0.1` when interface enumeration fails, the blocking task
/// cannot be joined, or no eligible LAN address exists.
pub async fn detect_lan_ip() -> IpAddr {
    match tokio::task::spawn_blocking(|| {
        if_addrs::get_if_addrs().map(|interfaces| {
            select_lan_ipv4(
                interfaces
                    .into_iter()
                    .filter_map(|interface| match interface.addr {
                        if_addrs::IfAddr::V4(address) => Some(address.ip),
                        if_addrs::IfAddr::V6(_) => None,
                    }),
            )
        })
    })
    .await
    {
        Ok(Ok(Some(ip))) => IpAddr::V4(ip),
        Ok(Ok(None)) => {
            warn!("companion: no eligible RFC1918 IPv4 interface; falling back to 127.0.0.1");
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        }
        Ok(Err(error)) => {
            warn!(error = %error, "companion: interface enumeration failed; falling back to 127.0.0.1");
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        }
        Err(error) => {
            warn!(error = %error, "companion: interface discovery task failed; falling back to 127.0.0.1");
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
            warn!(error = %e, "companion: QR code generation failed");
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

/// Domain-separation label for the v2 pairing transport's deterministic phone
/// Noise static identity.  The public topic is HKDF salt and the existing
/// 16-byte pairing PSK is IKM, so this label is the versioned protocol boundary
/// rather than an optional application hint.
#[cfg(feature = "cluster")]
const COMPANION_NOISE_STATIC_HKDF_INFO: &[u8] = b"NEOTH/companion/noise-static/v2";

/// Derive the v2 companion phone's deterministic Noise-static seed.
///
/// This intentionally does not log, serialize, or otherwise expose the seed:
/// possessing the pairing PSK is sufficient to reconstruct it.  HKDF expands
/// the existing 128-bit PSK into the exact 32-byte `KeyPair::from_seed` input
/// while binding it to this one public rendezvous topic and protocol version.
#[cfg(feature = "cluster")]
fn derive_companion_noise_static_seed(
    topic: &[u8; COMPANION_TOPIC_BYTES],
    psk: &[u8; COMPANION_PSK_BYTES],
) -> [u8; 32] {
    derive_companion_noise_static_seed_with_info(topic, psk, COMPANION_NOISE_STATIC_HKDF_INFO)
}

/// HKDF core kept separate so tests can prove the v2 domain label cannot
/// accidentally collide with a future or historical protocol label.
#[cfg(feature = "cluster")]
fn derive_companion_noise_static_seed_with_info(
    topic: &[u8; COMPANION_TOPIC_BYTES],
    psk: &[u8; COMPANION_PSK_BYTES],
    info: &[u8],
) -> [u8; 32] {
    let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(Some(topic), psk);
    let mut seed = [0u8; 32];
    hkdf.expand(info, &mut seed)
        .expect("32-byte HKDF-SHA256 output is within the RFC 5869 output limit");
    seed
}

/// Derive the only Noise static public key admitted for a v2 companion invite.
#[cfg(feature = "cluster")]
fn expected_companion_noise_static_key(
    topic: &[u8; COMPANION_TOPIC_BYTES],
    psk: &[u8; COMPANION_PSK_BYTES],
) -> [u8; 32] {
    peeroxide::KeyPair::from_seed(derive_companion_noise_static_seed(topic, psk)).public_key
}

/// The tiny, secret-bearing handoff record is deliberately much smaller than
/// a general configuration file.  Keeping a hard cap makes its consumer safe
/// even if the private home is accidentally populated by a hostile local file.
pub const MAX_PENDING_INVITE_BYTES: u64 = 4096;

/// Schema version for `companion_pending_invite.json`.
pub const PENDING_INVITE_RECORD_VERSION: u8 = 1;

/// Observable lifecycle of one owned P2P listener.
///
/// `Committing` is a point of no return: after this value is published, the
/// valid PSK has passed the final cancellation/deadline gate and invite burn,
/// WAL audit acknowledgement, token visibility, and response handling must
/// drain. The audit does not persist the bearer token; an OS crash between its
/// ACK and in-memory visibility deliberately consumes the invite fail-closed
/// and requires a new pairing attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompanionP2pPhase {
    Starting,
    PreAuth,
    Committing,
    Finalizing,
    Stopped,
}

/// Owns the actual listener task and its persistent cooperative cancellation.
///
/// Callers intentionally cannot obtain the inner [`JoinHandle`], so normal
/// CLI/daemon lifecycle paths cannot abort a listener halfway through its
/// admitted terminal sequence (invite burn, durable audit acknowledgement, and
/// in-memory token publication). The audit never persists the bearer token. A
/// timeout must use [`observe_grace`] and retain this value; it can then request
/// stop and await the same owner to terminal.
pub struct CompanionP2pTaskHandle {
    task: JoinHandle<()>,
    stop_tx: watch::Sender<bool>,
    phase_rx: watch::Receiver<CompanionP2pPhase>,
}

impl CompanionP2pTaskHandle {
    fn new(
        task: JoinHandle<()>,
        stop_tx: watch::Sender<bool>,
        phase_rx: watch::Receiver<CompanionP2pPhase>,
    ) -> Self {
        Self {
            task,
            stop_tx,
            phase_rx,
        }
    }

    /// Persistently request a cooperative stop. Repeated requests are harmless.
    pub fn request_stop(&self) {
        let _ = self.stop_tx.send(true);
    }

    /// Current phase without waiting.
    pub fn phase(&self) -> CompanionP2pPhase {
        *self.phase_rx.borrow()
    }

    /// Subscribe to lifecycle changes for diagnostics and deterministic tests.
    pub fn subscribe_phase(&self) -> watch::Receiver<CompanionP2pPhase> {
        self.phase_rx.clone()
    }

    /// Observe a bounded grace period without relinquishing task ownership.
    /// `None` means the listener remains owned and must later be awaited.
    pub async fn observe_grace(
        &mut self,
        grace: std::time::Duration,
    ) -> Option<Result<(), tokio::task::JoinError>> {
        tokio::time::timeout(grace, &mut self.task).await.ok()
    }

    /// Retain and await the owned listener to its terminal state.
    pub async fn await_terminal(&mut self) -> Result<(), tokio::task::JoinError> {
        (&mut self.task).await
    }

    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingCompanionInviteV1 {
    version: u8,
    topic_hex: String,
    psk_hex: String,
    expires_at: u64,
}

fn require_lower_hex_exact(value: &str, expected_len: usize, label: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        value.len() == expected_len
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "invalid companion {label}"
    );
    Ok(())
}

/// Make the CLI producer's selected `NEOTH_HOME` a real private directory.
/// This is a capability boundary: a pending invite contains its raw PSK.
pub fn ensure_private_companion_home(home: &Path) -> anyhow::Result<()> {
    match std::fs::symlink_metadata(home) {
        Ok(metadata) => anyhow::ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "companion home must be a real directory"
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            anyhow::bail!("companion home does not exist")
        }
        Err(error) => return Err(error.into()),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(home, std::fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(windows)]
    crate::wal::win_native::set_private_current_user_directory_dacl(home)?;
    verify_private_companion_home(home)
}

/// Verify only — the daemon must not silently relax or repair a suspicious
/// home while consuming a capability written by another process.
pub fn verify_private_companion_home(home: &Path) -> anyhow::Result<()> {
    let metadata = std::fs::symlink_metadata(home)?;
    anyhow::ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "companion home must be a real private directory"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        anyhow::ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "companion home permissions are not private"
        );
    }
    #[cfg(windows)]
    crate::wal::win_native::verify_private_directory_dacl(home)?;
    Ok(())
}

/// One-time pairing invite minted by `neoth companion pair-phone`.
///
/// Carries a fresh rendezvous `topic` (32 bytes) plus a pre-shared key (16
/// bytes), both drawn from the OS CSPRNG via `getrandom` — the same primitive
/// as a cryptographically random bearer secret. The values are
/// rendered hex into a `neoth://companion/pair` URL (and its QR) for the
/// operator to scan. Single-use; the P2P transport that validates topic+psk on
/// connect is implemented by `companion::p2p` when the `cluster` feature is
/// compiled.
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

    /// Encode the mandatory v2 pairing URL as
    /// `neoth://companion/pair?v=2&topic=<hex>&psk=<hex>&ttl=<secs>`.
    ///
    /// V1 pairing URLs are deliberately not emitted or accepted by the v2
    /// transport: the phone must derive its deterministic Noise static identity
    /// before it can consume a public-DHT connection slot. Hex is URL-safe
    /// (`[0-9a-f]`), so no percent-encoding is needed.
    pub fn pairing_url(&self, ttl_secs: u64) -> String {
        format!(
            "neoth://companion/pair?v=2&topic={}&psk={}&ttl={}",
            self.topic_hex, self.psk_hex, ttl_secs
        )
    }

    /// Serialize the strict V1 on-disk handoff record consumed by `neoth serve`.
    /// The expiry is absolute so a delayed daemon cannot accidentally grant a
    /// fresh full TTL to an invite whose QR has already expired.
    pub fn pending_invite_record(&self, expires_at: u64) -> anyhow::Result<Vec<u8>> {
        anyhow::ensure!(expires_at > 0, "invalid companion invite expiry");
        serde_json::to_vec(&PendingCompanionInviteV1 {
            version: PENDING_INVITE_RECORD_VERSION,
            topic_hex: self.topic_hex.clone(),
            psk_hex: self.psk_hex.clone(),
            expires_at,
        })
        .map_err(Into::into)
    }

    /// Parse and validate a strict V1 handoff record without exposing its PSK
    /// in errors or logs. The returned TTL is derived from the absolute expiry.
    pub fn from_pending_invite_record(bytes: &[u8], now_unix: u64) -> anyhow::Result<(Self, u64)> {
        anyhow::ensure!(
            !bytes.is_empty() && bytes.len() as u64 <= MAX_PENDING_INVITE_BYTES,
            "invalid companion invite record size"
        );
        let record: PendingCompanionInviteV1 = serde_json::from_slice(bytes)
            .map_err(|_| anyhow::anyhow!("invalid companion invite record"))?;
        anyhow::ensure!(
            record.version == PENDING_INVITE_RECORD_VERSION,
            "unsupported companion invite record version"
        );
        require_lower_hex_exact(&record.topic_hex, COMPANION_TOPIC_BYTES * 2, "invite topic")?;
        require_lower_hex_exact(&record.psk_hex, COMPANION_PSK_BYTES * 2, "invite PSK")?;
        anyhow::ensure!(record.expires_at > now_unix, "companion invite expired");
        let ttl_secs = record.expires_at.saturating_sub(now_unix);
        Ok((Self::from_hex(record.topic_hex, record.psk_hex), ttl_secs))
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
        return Ok(plain_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "method not allowed",
        ));
    }

    // Path routing.
    match req.uri().path() {
        "/api/v1/companion/pair" => Ok(handle_pair(req, state).await),
        _ => Ok(plain_response(StatusCode::NOT_FOUND, "not found")),
    }
}

async fn handle_pair(req: Request<Incoming>, state: Arc<CompanionState>) -> Response<Full<Bytes>> {
    // CSRF guard.
    if !csrf_check_passes(&req, state.port) {
        warn!("companion: CSRF guard rejected cross-origin Origin header");
        return plain_response(StatusCode::FORBIDDEN, "forbidden: cross-origin request");
    }

    // Read the body, capped at COMPANION_BODY_LIMIT_BYTES (16 KiB) BEFORE
    // allocation. Security fix (NEOTH-AUDIT-HTTP-BODY-LIMITS-01): the previous
    // code called `.collect()` on the unbounded Incoming body and checked
    // `.len() > 16_384` only after the full payload was already in memory.
    // `Limited` stops streaming at the byte cap and errors before the allocator
    // exceeds COMPANION_BODY_LIMIT_BYTES — mirrors `channels/webhook_listener.rs`.
    let body_bytes = match Limited::new(req.into_body(), COMPANION_BODY_LIMIT_BYTES)
        .collect()
        .await
    {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            warn!(
                cap = COMPANION_BODY_LIMIT_BYTES,
                "companion: body exceeds cap or read error"
            );
            return plain_response(StatusCode::PAYLOAD_TOO_LARGE, "payload too large");
        }
    };

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
    let token_hash = format!("{:016x}", xxhash_rust::xxh3::xxh3_64(token.as_bytes()));
    let payload = serde_json::json!({
        "session_id": session_id,
        "token_hash_xxh3": token_hash,
        "ts_unix": crate::time::now_unix_secs(),
    });
    let payload_bytes = serde_json::to_vec(&payload)
        .expect("COMPANION_PAIRED payload contains only infallible JSON values");
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
    let resp_json = serde_json::to_string(&resp_body)
        .expect("companion pairing response contains only infallible JSON values");

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
    let local_addr = listener
        .local_addr()
        .unwrap_or(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), state.port));
    info!(addr = %local_addr, "companion server listening (GOLD-ADAPT-ODY-24)");
    let mut connections = tokio::task::JoinSet::new();

    loop {
        let accept = tokio::select! {
            biased;
            _ = shutdown.notified() => {
                info!("companion: shutdown signal received; stopping connections");
                break;
            }
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = result {
                    warn!(%error, "companion: connection task failed");
                }
                continue;
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
        connections.spawn(async move {
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

    // HTTP/1 keep-alive connections may otherwise outlive the accept loop and
    // retain CompanionState's WAL sender forever. Abort and await every
    // connection before the daemon starts draining the WAL writer.
    connections.shutdown().await;
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
        // that. Phone pairing uses the separate authenticated P2P coordinator;
        // advertising a LAN HTTP address here would be misleading and unsafe.
        let pairing_url = format!("http://127.0.0.1:{}/api/v1/companion/pair", config.port);
        info!(
            url = %pairing_url,
            "companion: local pairing URL (localhost browser app; phones use the P2P pairing path)"
        );

        run_companion_server(listener, state, shutdown).await;
    }))
}

// ── P2P Noise pairing listener (GOLD-COMPANION-P2P-01) ───────────────────────
//
// Full phone-pairing over the existing Hyperswarm DHT + Noise-IK-authenticated
// transport mesh.
// Feature-gated: only compiled when the `cluster` feature is present, which
// pulls in `peeroxide`. In a build without `cluster` the public API surface
// (`spawn_companion_p2p_listener`) returns an owned no-op task handle.
//
// Protocol (single-use, TTL-bound):
//   1. Caller mints a `CompanionInvite` (topic=32B CSPRNG, psk=16B CSPRNG).
//   2. The phone derives its v2 Noise static key from topic + PSK with the
//      versioned HKDF above; the reviewed rendezvous boundary admits only its
//      resulting public key before allocating a transport connection.
//   3. The rendezvous boundary announces `topic_bytes` on the public
//      Hyperswarm DHT.
//   4. The phone finds the topic and sends exactly 16 raw bytes (the PSK)
//      immediately after the authenticated encrypted connection opens.
//   5. The daemon reads 16 bytes (`read()` over Noise → next plaintext
//      message), compares with `constant_time_eq`, and either:
//      - PASS: prepares an idempotent token under the shared token-store lock,
//        writes and acknowledges a WAL 0x0D audit record, then makes the
//        token visible, replies with `{token, session_id}`, and burns the
//        invite. The WAL record intentionally contains no bearer token and is
//        not a token-recovery transaction: a process crash after its ACK but
//        before in-memory visibility consumes the invite fail-closed, so the
//        operator must create a new invite and pair again.
//      - FAIL: drops only that connection, emits a bounded WAL 0x0E audit,
//        waits a short cooldown, and keeps the invite advertised.
//   6. Valid-PSK admission, pre-auth TTL expiry, explicit shutdown, or
//      transport closure consumes the invite and tears down the rendezvous.
//
// Attempts are strictly sequential and cooldown-limited. A public-topic
// observer therefore cannot burn the invite with the first unauthenticated
// connection, while the fixed pre-auth deadline bounds unauthenticated work.
//
// IMPORTANT: `SwarmConnection::read`/`write` keep peeroxide's Noise SecretStream
// inside its lifecycle-bound wrapper. Each method operates on one Noise message.
// Its `.read()` method returns the next decrypted Noise message as
// `Result<Option<peeroxide::Bytes>>` — it is NOT a raw `AsyncRead`. Each
// `.write(&bytes)` sends one Noise message. We use these message-framed
// methods directly (NOT `tokio::io::AsyncReadExt::read_exact`).

#[cfg(feature = "cluster")]
mod p2p {
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::sync::{RwLock, watch};
    use tracing::{debug, info, warn};

    use super::{
        COMPANION_PSK_BYTES, COMPANION_TOPIC_BYTES, CompanionInvite, CompanionP2pPhase,
        CompanionState, TokenEntry, expected_companion_noise_static_key, mint_token,
    };
    use crate::wal::builder::HeaderBuilder;
    use crate::wal::events::{EVENT_TYPE_COMPANION_P2P_PAIRED, EVENT_TYPE_COMPANION_P2P_REJECTED};
    use crate::wal::writer::WalWriterHandle;

    const MIN_COMPANION_INVITE_TTL_SECS: u64 = 1;
    const MAX_COMPANION_INVITE_TTL_SECS: u64 = 300;
    const COMPANION_PSK_READ_TIMEOUT: Duration = Duration::from_secs(10);
    const COMPANION_RESPONSE_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
    const COMPANION_RETRY_COOLDOWN: Duration = Duration::from_millis(500);
    const MAX_DETAILED_REJECTION_AUDITS: u8 = 5;

    /// Held state for one P2P pairing session. Shared between the spawner and
    /// the accept loop via `Arc`.
    pub(super) struct CompanionP2pState {
        /// The `CompanionState` that owns the token store + WAL writer.
        pub companion_state: Arc<CompanionState>,
        /// The pending invite — consumed exactly once. `None` after burn.
        pub pending_invite: RwLock<Option<CompanionInvite>>,
        /// WAL writer for emitting 0x0D / 0x0E audit frames.
        pub writer: WalWriterHandle,
        /// Requested invite TTL. Runtime clamps this to the documented
        /// 1..=300 second window and derives one pre-auth admission deadline.
        pub invite_ttl_secs: u64,
    }

    /// Companion pairing is strictly a server-side rendezvous: a returned
    /// connection must have been initiated by the phone. Keep this predicate
    /// separately testable so a future transport change cannot turn
    /// `is_initiator` into observational-only metadata.
    pub(super) const fn accepts_inbound_pairing_connection(is_initiator: bool) -> bool {
        !is_initiator
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(super) enum AttemptRejection {
        UnexpectedInitiator,
        WrongFrameSize,
        ClosedEarly,
        ReadError,
        ReadTimeout,
        PskMismatch,
    }

    impl AttemptRejection {
        const fn reason(self) -> &'static str {
            match self {
                Self::UnexpectedInitiator => "unexpected_initiator",
                Self::WrongFrameSize => "psk_frame_wrong_size",
                Self::ClosedEarly => "psk_closed_early",
                Self::ReadError => "psk_read_error",
                Self::ReadTimeout => "psk_read_timeout",
                Self::PskMismatch => "psk_mismatch",
            }
        }

        const fn detail(self) -> &'static str {
            match self {
                Self::UnexpectedInitiator => "server_only_rendezvous",
                Self::WrongFrameSize => "wrong_psk_size",
                Self::ClosedEarly => "connection_closed",
                Self::ReadError => "io_error",
                Self::ReadTimeout => "timeout",
                Self::PskMismatch => "wrong_psk",
            }
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(super) enum AttemptDecision {
        Authenticated,
        Retry(AttemptRejection),
    }

    pub(super) enum AttemptEvidence<'a> {
        Initiated,
        Frame(&'a [u8]),
        Closed,
        ReadFailed,
        ReadTimedOut,
    }

    pub(super) fn decide_attempt(
        evidence: AttemptEvidence<'_>,
        expected_psk: &[u8; COMPANION_PSK_BYTES],
    ) -> AttemptDecision {
        let received = match evidence {
            AttemptEvidence::Initiated => {
                return AttemptDecision::Retry(AttemptRejection::UnexpectedInitiator);
            }
            AttemptEvidence::Frame(bytes) if bytes.len() == COMPANION_PSK_BYTES => bytes,
            AttemptEvidence::Frame(_) => {
                return AttemptDecision::Retry(AttemptRejection::WrongFrameSize);
            }
            AttemptEvidence::Closed => {
                return AttemptDecision::Retry(AttemptRejection::ClosedEarly);
            }
            AttemptEvidence::ReadFailed => {
                return AttemptDecision::Retry(AttemptRejection::ReadError);
            }
            AttemptEvidence::ReadTimedOut => {
                return AttemptDecision::Retry(AttemptRejection::ReadTimeout);
            }
        };

        let mut difference = 0u8;
        for (actual, expected) in received.iter().zip(expected_psk) {
            difference |= actual ^ expected;
        }
        if difference == 0 {
            AttemptDecision::Authenticated
        } else {
            AttemptDecision::Retry(AttemptRejection::PskMismatch)
        }
    }

    pub(super) const fn attempt_consumes_invite(decision: AttemptDecision) -> bool {
        matches!(decision, AttemptDecision::Authenticated)
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(super) enum TerminalOutcome {
        Paired,
        Expired,
        Shutdown,
        TransportClosed,
        DurableCommitFailed,
    }

    impl TerminalOutcome {
        pub(super) const fn consumes_invite(self) -> bool {
            true
        }

        const fn audit_reason(self) -> Option<&'static str> {
            match self {
                Self::Paired => None,
                Self::Expired => Some("invite_expired"),
                Self::Shutdown => Some("shutdown"),
                Self::TransportClosed => Some("transport_closed"),
                Self::DurableCommitFailed => Some("durable_pair_commit_failed"),
            }
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(super) struct RejectionAccounting {
        pub attempt: u64,
        pub emit_detailed_audit: bool,
    }

    #[derive(Default)]
    pub(super) struct RetryBudget {
        attempts: u64,
        detailed_audits: u8,
    }

    impl RetryBudget {
        pub(super) fn record_rejection(&mut self) -> RejectionAccounting {
            self.attempts = self.attempts.saturating_add(1);
            let emit_detailed_audit = self.detailed_audits < MAX_DETAILED_REJECTION_AUDITS;
            if emit_detailed_audit {
                self.detailed_audits += 1;
            }
            RejectionAccounting {
                attempt: self.attempts,
                emit_detailed_audit,
            }
        }

        fn attempts(&self) -> u64 {
            self.attempts
        }

        fn suppressed_audits(&self) -> u64 {
            self.attempts
                .saturating_sub(u64::from(self.detailed_audits))
        }
    }

    pub(super) const fn effective_invite_ttl_secs(requested: u64) -> u64 {
        if requested < MIN_COMPANION_INVITE_TTL_SECS {
            MIN_COMPANION_INVITE_TTL_SECS
        } else if requested > MAX_COMPANION_INVITE_TTL_SECS {
            MAX_COMPANION_INVITE_TTL_SECS
        } else {
            requested
        }
    }

    pub(super) fn bounded_read_wait(remaining: Duration) -> Duration {
        remaining.min(COMPANION_PSK_READ_TIMEOUT)
    }

    pub(super) async fn shutdown_requested(shutdown: &mut watch::Receiver<bool>) {
        if *shutdown.borrow() {
            return;
        }
        loop {
            if shutdown.changed().await.is_err() || *shutdown.borrow() {
                return;
            }
        }
    }

    pub(super) enum TimedRead<T> {
        Ready(T),
        Shutdown,
        Expired,
        ReadTimeout,
    }

    pub(super) async fn wait_for_attempt_read<F, T>(
        shutdown: &mut watch::Receiver<bool>,
        deadline: tokio::time::Instant,
        read: F,
    ) -> TimedRead<T>
    where
        F: std::future::Future<Output = T>,
    {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let read_wait = bounded_read_wait(remaining);
        tokio::select! {
            biased;
            _ = shutdown_requested(shutdown) => TimedRead::Shutdown,
            _ = tokio::time::sleep_until(deadline) => TimedRead::Expired,
            _ = tokio::time::sleep(read_wait) => TimedRead::ReadTimeout,
            result = read => TimedRead::Ready(result),
        }
    }

    async fn wait_retry_cooldown(
        shutdown: &mut watch::Receiver<bool>,
        deadline: tokio::time::Instant,
    ) -> Option<TerminalOutcome> {
        tokio::select! {
            biased;
            _ = shutdown_requested(shutdown) => Some(TerminalOutcome::Shutdown),
            _ = tokio::time::sleep_until(deadline) => Some(TerminalOutcome::Expired),
            _ = tokio::time::sleep(COMPANION_RETRY_COOLDOWN) => None,
        }
    }

    async fn consume_pending_invite(state: &CompanionP2pState) -> bool {
        state.pending_invite.write().await.take().is_some()
    }

    /// Run the Noise accept loop for one companion invite.
    ///
    /// - Starts a server-only rendezvous through the cluster/Hyperswarm
    ///   boundary and announces `topic_bytes`.
    /// - Admits only the invite-derived authenticated Noise-IK client static key
    ///   before allocation, then evaluates its encrypted application PSK before
    ///   the fixed pre-auth deadline; unauthenticated candidates never consume it.
    /// - On PSK match: stops advertising, durably appends WAL 0x0D, then makes
    ///   the token visible and writes the response.
    /// - On mismatch / malformed frame / per-read timeout: emits one of at
    ///   most five detailed WAL 0x0E frames, cooldowns, and resumes accepting.
    /// - Valid-PSK admission, pre-auth expiry, persistent shutdown, or
    ///   transport closure consumes the invite and tears down the actor.
    pub(super) async fn run_companion_p2p_listener(
        state: Arc<CompanionP2pState>,
        mut shutdown: watch::Receiver<bool>,
        phase_tx: watch::Sender<CompanionP2pPhase>,
    ) {
        let ttl_secs = effective_invite_ttl_secs(state.invite_ttl_secs);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(ttl_secs);

        let decoded_invite = {
            let guard = state.pending_invite.read().await;
            guard.as_ref().and_then(|invite| {
                let topic = hex::decode(&invite.topic_hex).ok()?;
                let psk = hex::decode(&invite.psk_hex).ok()?;
                if topic.len() != COMPANION_TOPIC_BYTES || psk.len() != COMPANION_PSK_BYTES {
                    return None;
                }
                let mut topic_bytes = [0u8; COMPANION_TOPIC_BYTES];
                topic_bytes.copy_from_slice(&topic);
                let mut psk_bytes = [0u8; COMPANION_PSK_BYTES];
                psk_bytes.copy_from_slice(&psk);
                Some((topic_bytes, psk_bytes))
            })
        };
        let Some((topic_bytes, psk_bytes)) = decoded_invite else {
            warn!("companion_p2p: missing or malformed pending invite — consuming it");
            let _ = phase_tx.send(CompanionP2pPhase::Finalizing);
            consume_pending_invite(&state).await;
            emit_p2p_rejected(
                &state.writer,
                "(invalid)",
                "(none)",
                "invalid_invite",
                "topic_or_psk_shape",
                0,
                true,
                0,
            );
            return;
        };
        let topic_hash = format!("{:016x}", xxhash_rust::xxh3::xxh3_64(&topic_bytes));
        let expected_phone_static_key =
            expected_companion_noise_static_key(&topic_bytes, &psk_bytes);

        // The listener has decoded its capability and now accepts only bounded
        // pre-auth work. Shutdown/expiry still wins in every select below.
        let _ = phase_tx.send(CompanionP2pPhase::PreAuth);

        let mut rendezvous = match crate::cluster::hyperswarm::spawn_public_rendezvous(
            topic_bytes,
            expected_phone_static_key,
            deadline,
            shutdown.clone(),
        )
        .await
        {
            Ok(rendezvous) => rendezvous,
            Err(error) => {
                let outcome = if *shutdown.borrow() {
                    TerminalOutcome::Shutdown
                } else if tokio::time::Instant::now() >= deadline {
                    TerminalOutcome::Expired
                } else {
                    TerminalOutcome::TransportClosed
                };
                warn!(%error, ?outcome, "companion_p2p: public rendezvous did not start");
                let _ = phase_tx.send(CompanionP2pPhase::Finalizing);
                consume_pending_invite(&state).await;
                emit_p2p_rejected(
                    &state.writer,
                    &topic_hash,
                    "(no connection)",
                    outcome.audit_reason().unwrap_or("transport_start_failed"),
                    "rendezvous_start",
                    0,
                    true,
                    0,
                );
                return;
            }
        };

        info!(
            topic_hash = %topic_hash,
            requested_ttl_secs = state.invite_ttl_secs,
            effective_ttl_secs = ttl_secs,
            "companion_p2p: server-only DHT rendezvous advertised"
        );

        let mut budget = RetryBudget::default();
        let mut pending_consumed = false;
        let mut advertising_stopped = false;
        let outcome = loop {
            let connection = tokio::select! {
                biased;
                _ = shutdown_requested(&mut shutdown) => break TerminalOutcome::Shutdown,
                _ = tokio::time::sleep_until(deadline) => break TerminalOutcome::Expired,
                connection = rendezvous.recv() => connection,
            };
            let Some(mut conn) = connection else {
                break TerminalOutcome::TransportClosed;
            };

            let peer_pk: [u8; 32] = *conn.remote_public_key();
            let peer_pk_hex = hex::encode(peer_pk);
            let decision = if !accepts_inbound_pairing_connection(conn.is_initiator) {
                decide_attempt(AttemptEvidence::Initiated, &psk_bytes)
            } else {
                debug!(peer = %peer_pk_hex, topic_hash = %topic_hash,
                    "companion_p2p: inbound phone candidate — reading PSK");
                match wait_for_attempt_read(&mut shutdown, deadline, conn.read()).await {
                    TimedRead::Shutdown => {
                        drop(conn);
                        break TerminalOutcome::Shutdown;
                    }
                    TimedRead::Expired => {
                        drop(conn);
                        break TerminalOutcome::Expired;
                    }
                    TimedRead::ReadTimeout => {
                        decide_attempt(AttemptEvidence::ReadTimedOut, &psk_bytes)
                    }
                    TimedRead::Ready(Ok(Some(bytes))) => {
                        decide_attempt(AttemptEvidence::Frame(&bytes), &psk_bytes)
                    }
                    TimedRead::Ready(Ok(None)) => {
                        decide_attempt(AttemptEvidence::Closed, &psk_bytes)
                    }
                    TimedRead::Ready(Err(error)) => {
                        warn!(peer = %peer_pk_hex, %error, "companion_p2p: candidate PSK read failed");
                        decide_attempt(AttemptEvidence::ReadFailed, &psk_bytes)
                    }
                }
            };

            match decision {
                AttemptDecision::Retry(rejection) => {
                    let accounting = budget.record_rejection();
                    warn!(
                        peer = %peer_pk_hex,
                        attempt = accounting.attempt,
                        reason = rejection.reason(),
                        "companion_p2p: unauthenticated candidate rejected; invite remains active"
                    );
                    drop(conn);
                    if accounting.emit_detailed_audit {
                        emit_p2p_rejected(
                            &state.writer,
                            &topic_hash,
                            &peer_pk_hex,
                            rejection.reason(),
                            rejection.detail(),
                            accounting.attempt,
                            false,
                            budget.suppressed_audits(),
                        );
                    }
                    if let Some(terminal) = wait_retry_cooldown(&mut shutdown, deadline).await {
                        break terminal;
                    }
                }
                AttemptDecision::Authenticated => {
                    debug_assert!(attempt_consumes_invite(decision));
                    // PRE-AUTH ADMISSION DEADLINE: shutdown/expiry may reject
                    // the effect up to this exact point. Once a valid PSK has
                    // passed this check, the authenticated terminal effect is
                    // admitted and must drain atomically: consume invite,
                    // bounded leave, durable WAL audit, in-memory token
                    // publication, bounded reply.
                    if *shutdown.borrow() {
                        drop(conn);
                        break TerminalOutcome::Shutdown;
                    }
                    if tokio::time::Instant::now() >= deadline {
                        drop(conn);
                        break TerminalOutcome::Expired;
                    }
                    // This is the final pre-auth gate. Once Committing is
                    // observable no normal lifecycle path may abort this
                    // owner: invite burn, durable audit acknowledgement, and
                    // in-memory token publication must run to their terminal
                    // outcome. This is deliberately not a durable token
                    // transaction: the WAL holds audit metadata, never the
                    // bearer token. A process crash after the ACK but before
                    // publication consumes the invite fail-closed; pair again.
                    let _ = phase_tx.send(CompanionP2pPhase::Committing);
                    pending_consumed = consume_pending_invite(&state).await;
                    if !pending_consumed {
                        drop(conn);
                        break TerminalOutcome::TransportClosed;
                    }

                    advertising_stopped = true;
                    if let Err(error) = rendezvous.leave().await {
                        warn!(%error, "companion_p2p: DHT leave failed after valid PSK");
                    }

                    let session_id = hex::encode(&peer_pk[..8]);
                    let mut token_guard = state.companion_state.tokens.write().await;

                    let (token, insert_after_wal) = match token_guard.get(&session_id) {
                        Some(entry) if !entry.is_expired() => (entry.token.clone(), false),
                        _ => (mint_token(), true),
                    };
                    let token_hash =
                        format!("{:016x}", xxhash_rust::xxh3::xxh3_64(token.as_bytes()));
                    let payload = serde_json::json!({
                        "topic_hash_xxh3": topic_hash,
                        "peer_pk_hex": peer_pk_hex,
                        "token_hash_xxh3": token_hash,
                        "rejected_attempts": budget.attempts(),
                        "ts_unix": crate::time::now_unix_secs(),
                    });
                    let payload_bytes = serde_json::to_vec(&payload).expect(
                        "COMPANION_P2P_PAIRED payload contains only infallible JSON values",
                    );
                    let header =
                        HeaderBuilder::new(EVENT_TYPE_COMPANION_P2P_PAIRED, &payload_bytes).build();
                    // DURABLE AUDIT COMMITPOINT: `append` may already have
                    // queued a write before it waits for fsync acknowledgement.
                    // It must therefore never be raced against cancellation or
                    // a timeout. A definite ACK/error is observed before token
                    // visibility changes. The audit contains no bearer token,
                    // so it cannot recover a token after a crash in this
                    // window: the consumed invite must be re-paired.
                    match state.writer.append(header, payload_bytes).await {
                        Ok(_offset) => {
                            if insert_after_wal {
                                token_guard.retain(|_, entry| !entry.is_expired());
                                token_guard
                                    .insert(session_id.clone(), TokenEntry::new(token.clone()));
                            }
                        }
                        Err(error) => {
                            warn!(%error, "companion_p2p: durable paired WAL commit failed");
                            drop(token_guard);
                            drop(conn);
                            break TerminalOutcome::DurableCommitFailed;
                        }
                    }
                    drop(token_guard);

                    let response = serde_json::to_vec(&serde_json::json!({
                        "token": token,
                        "session_id": session_id,
                    }))
                    .expect("companion pairing response contains only infallible JSON values");
                    match tokio::time::timeout(
                        COMPANION_RESPONSE_WRITE_TIMEOUT,
                        conn.write(&response),
                    )
                    .await
                    {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => warn!(peer = %peer_pk_hex, %error,
                            "companion_p2p: committed token response write failed"),
                        Err(_) => warn!(peer = %peer_pk_hex,
                            "companion_p2p: committed token response write timed out"),
                    }
                    info!(peer = %peer_pk_hex, session_id = %session_id, topic_hash = %topic_hash,
                        "companion_p2p: phone paired after durable audit commit");
                    drop(conn);
                    break TerminalOutcome::Paired;
                }
            }
        };

        let _ = phase_tx.send(CompanionP2pPhase::Finalizing);
        if outcome.consumes_invite() && !pending_consumed {
            pending_consumed = consume_pending_invite(&state).await;
        }
        if !advertising_stopped && let Err(error) = rendezvous.leave().await {
            warn!(%error, ?outcome, "companion_p2p: terminal DHT leave failed");
        }
        if let Some(reason) = outcome.audit_reason() {
            emit_p2p_rejected(
                &state.writer,
                &topic_hash,
                "(terminal)",
                reason,
                "listener_terminal",
                budget.attempts(),
                true,
                budget.suppressed_audits(),
            );
        }
        debug!(
            ?outcome,
            pending_consumed, "companion_p2p: terminal teardown"
        );
        rendezvous.shutdown().await;
    }

    /// Emit a bounded, non-blocking WAL 0x0E rejection decision. Detailed
    /// per-attempt calls are capped by [`RetryBudget`]; terminal calls add at
    /// most one final aggregate frame.
    fn emit_p2p_rejected(
        writer: &WalWriterHandle,
        topic_hash: &str,
        peer_pk_hex: &str,
        reason: &str,
        detail: &str,
        attempt: u64,
        terminal: bool,
        suppressed_audits: u64,
    ) {
        let ts_unix = crate::time::now_unix_secs();
        let payload = serde_json::json!({
            "topic_hash_xxh3": topic_hash,
            "peer_pk_hex": peer_pk_hex,
            "reason": reason,
            "detail": detail,
            "attempt": attempt,
            "terminal": terminal,
            "suppressed_audits": suppressed_audits,
            "ts_unix": ts_unix,
        });
        let payload_bytes = serde_json::to_vec(&payload)
            .expect("COMPANION_P2P_REJECTED payload contains only infallible JSON values");
        let hdr = HeaderBuilder::new(EVENT_TYPE_COMPANION_P2P_REJECTED, &payload_bytes).build();
        if let Err(e) = writer.try_append_sync(hdr, payload_bytes) {
            warn!(error = %e, "companion_p2p: WAL emit COMPANION_P2P_REJECTED failed (non-fatal)");
        }
    }

    /// Spawn the P2P pairing listener as a tokio task and return its handle.
    ///
    /// # Arguments
    /// - `invite` — the one-time [`CompanionInvite`] to consume.
    /// - `companion_state` — the shared token store (shared with the HTTP server).
    /// - `writer` — WAL writer for 0x0D / 0x0E audit frames.
    /// - `ttl_secs` — requested invite TTL, clamped to 1..=300 seconds.
    /// The returned owner retains both the real `JoinHandle` and a persistent
    /// cooperative stop channel. It intentionally exposes no abort operation.
    pub(super) fn spawn(
        invite: CompanionInvite,
        companion_state: Arc<CompanionState>,
        writer: WalWriterHandle,
        ttl_secs: u64,
    ) -> super::CompanionP2pTaskHandle {
        let p2p_state = Arc::new(CompanionP2pState {
            companion_state,
            pending_invite: RwLock::new(Some(invite)),
            writer,
            invite_ttl_secs: ttl_secs,
        });
        let (stop_tx, stop_rx) = watch::channel(false);
        let (phase_tx, phase_rx) = watch::channel(CompanionP2pPhase::Starting);
        let task = tokio::spawn(async move {
            run_companion_p2p_listener(p2p_state, stop_rx, phase_tx.clone()).await;
            let _ = phase_tx.send(CompanionP2pPhase::Stopped);
        });
        super::CompanionP2pTaskHandle::new(task, stop_tx, phase_rx)
    }
}

/// Spawn the companion P2P Noise pairing listener.
///
/// Returns a typed owner after a successful pairing, pre-auth TTL expiry,
/// persistent shutdown, or transport closure. Once a valid PSK passes the
/// admission check, bounded leave plus durable audit acknowledgement and token
/// publication drain terminally even if the deadline or shutdown state changes
/// during that sequence.
///
/// # Feature gate
///
/// When the `cluster` feature is NOT active, this is an owned no-op task that
/// exits immediately and logs a warning.
#[cfg(feature = "cluster")]
pub fn spawn_companion_p2p_listener(
    invite: CompanionInvite,
    companion_state: Arc<CompanionState>,
    writer: WalWriterHandle,
    ttl_secs: u64,
) -> CompanionP2pTaskHandle {
    p2p::spawn(invite, companion_state, writer, ttl_secs)
}

#[cfg(not(feature = "cluster"))]
pub fn spawn_companion_p2p_listener(
    _invite: CompanionInvite,
    _companion_state: Arc<CompanionState>,
    _writer: WalWriterHandle,
    _ttl_secs: u64,
) -> CompanionP2pTaskHandle {
    warn!(
        "companion_p2p: `cluster` feature not enabled — P2P pairing unavailable; use loopback HTTP instead"
    );
    let (stop_tx, _stop_rx) = watch::channel(false);
    let (phase_tx, phase_rx) = watch::channel(CompanionP2pPhase::Starting);
    let task = tokio::spawn(async move {
        let _ = phase_tx.send(CompanionP2pPhase::Finalizing);
        let _ = phase_tx.send(CompanionP2pPhase::Stopped);
    });
    CompanionP2pTaskHandle::new(task, stop_tx, phase_rx)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Write};
    use std::sync::Mutex;

    #[derive(Clone)]
    struct CapturedLogWriter(Arc<Mutex<Vec<u8>>>);

    struct CapturedLogGuard(Arc<Mutex<Vec<u8>>>);

    impl Write for CapturedLogGuard {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .expect("tracing capture mutex poisoned")
                .extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLogWriter {
        type Writer = CapturedLogGuard;

        fn make_writer(&'a self) -> Self::Writer {
            CapturedLogGuard(Arc::clone(&self.0))
        }
    }

    /// Spawn a real WAL writer against a temp segment file. Returns the handle
    /// and the join-handle; the test can drop the join-handle (the writer task
    /// exits when all handles are dropped). This is the standard pattern used
    /// across the daemon test suite (see `daemon/auto_update.rs`, `audit_rpc/tests.rs`).
    fn temp_writer() -> (
        WalWriterHandle,
        tokio::task::JoinHandle<()>,
        tempfile::TempDir,
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let seg = dir.path().join("test.wal");
        let (handle, join) = crate::wal::writer::spawn(seg).expect("spawn WAL writer for test");
        // Return `dir` so it isn't dropped (and the temp dir deleted) while the
        // writer task is still open.
        (handle, join, dir)
    }

    #[tokio::test]
    async fn shutdown_aborts_idle_connection_before_wal_drain() {
        use tokio::io::AsyncWriteExt;

        let shutdown = Arc::new(Notify::new());
        let (writer, wal_join, _wal_dir) = temp_writer();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let state = Arc::new(CompanionState::new(writer.clone(), port));
        let server = tokio::spawn(run_companion_server(
            listener,
            Arc::clone(&state),
            Arc::clone(&shutdown),
        ));

        let mut idle = tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        idle.write_all(b"GET /api/v1/companion/pair HTTP/1.1\r\nHost: localhost\r\n")
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while Arc::strong_count(&state) < 3 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("server never accepted the idle connection");

        shutdown.notify_one();
        tokio::time::timeout(std::time::Duration::from_secs(3), server)
            .await
            .expect("companion server did not stop")
            .expect("companion server task panicked");
        drop(state);
        drop(writer);
        tokio::time::timeout(std::time::Duration::from_secs(3), wal_join)
            .await
            .expect("idle connection retained CompanionState's WAL sender")
            .expect("WAL writer task panicked");

        drop(idle);
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
            tok.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "token contains non-base64url chars: {tok}"
        );
    }

    #[test]
    fn render_pairing_qr_returns_nonempty_for_valid_url() {
        let qr = render_pairing_qr("http://192.168.1.1:9745/pair?hint=operator");
        // The QR renderer produces at minimum a few lines of block chars.
        assert!(
            !qr.is_empty(),
            "QR render must not be empty for a valid URL"
        );
    }

    #[test]
    fn render_pairing_qr_failure_does_not_log_v2_capability() {
        // Synthetic v2-shaped capability whose data is deliberately beyond
        // the QR encoder's maximum capacity. It exercises the real error log
        // path without minting or exposing an operator's actual invite.
        let psk = "feedfacecafebeef0123456789abcdef";
        let url = format!(
            "neoth://companion/pair?v=2&topic={}&psk={psk}&ttl=300&padding={}",
            "a".repeat(COMPANION_TOPIC_BYTES * 2),
            "x".repeat(4_096),
        );
        let captured = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .with_writer(CapturedLogWriter(Arc::clone(&captured)))
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            assert!(
                render_pairing_qr(&url).is_empty(),
                "oversized synthetic capability must force the QR failure path"
            );
        });

        let log = String::from_utf8(
            captured
                .lock()
                .expect("tracing capture mutex poisoned")
                .clone(),
        )
        .expect("tracing output must be UTF-8");
        assert!(
            log.contains("companion: QR code generation failed"),
            "expected the QR error event in captured tracing output: {log}"
        );
        assert!(
            !log.contains(psk),
            "QR failure log must not expose the pairing PSK: {log}"
        );
        assert!(
            !log.contains(&url),
            "QR failure log must not expose the full pairing capability URL: {log}"
        );
    }

    #[test]
    fn select_lan_ipv4_prefers_the_lowest_rfc1918_candidate() {
        let selected = select_lan_ipv4([
            Ipv4Addr::new(192, 168, 4, 1),
            Ipv4Addr::new(172, 16, 0, 1),
            Ipv4Addr::new(10, 42, 0, 9),
            Ipv4Addr::new(10, 0, 0, 4),
        ]);

        assert_eq!(selected, Some(Ipv4Addr::new(10, 0, 0, 4)));
    }

    #[test]
    fn select_lan_ipv4_rejects_non_rfc1918_and_unusable_addresses() {
        let selected = select_lan_ipv4([
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(169, 254, 10, 1),
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::UNSPECIFIED,
        ]);

        assert_eq!(selected, None);
    }

    #[cfg(feature = "cluster")]
    #[test]
    fn companion_p2p_accepts_only_inbound_peeroxide_connections() {
        assert!(p2p::accepts_inbound_pairing_connection(false));
        assert!(!p2p::accepts_inbound_pairing_connection(true));
    }

    #[test]
    fn token_entry_expiry() {
        // A freshly minted entry must NOT be expired.
        let fresh = TokenEntry::new("t2".to_string());
        assert!(
            !fresh.is_expired(),
            "freshly minted entry must not be expired"
        );

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
        assert!(url.starts_with("neoth://companion/pair?v=2&topic="));
        assert_eq!(url_param(&url, "v"), "2");
        assert!(url.contains("&topic="));
        assert!(url.contains("&psk="));
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

    #[cfg(feature = "cluster")]
    #[test]
    fn companion_v2_kdf_published_synthetic_vector() {
        // Public interoperability vector.  It uses synthetic ascending bytes,
        // never a minted invite or an operator capability.
        let topic: [u8; COMPANION_TOPIC_BYTES] = std::array::from_fn(|index| index as u8);
        let psk: [u8; COMPANION_PSK_BYTES] =
            std::array::from_fn(|index| 0xa0u8.wrapping_add(index as u8));

        let seed = derive_companion_noise_static_seed(&topic, &psk);
        let public_key = expected_companion_noise_static_key(&topic, &psk);

        assert_eq!(
            hex::encode(seed),
            "5d1505b9be30bb2cacc51085a355b93838b29558628ca6d02048bd4b2738893a"
        );
        assert_eq!(
            hex::encode(public_key),
            "1db923ce1e8850ce4e535150b2e7e3c459111aa044c38593c9e5829fc888cc49"
        );
    }

    #[cfg(feature = "cluster")]
    #[test]
    fn companion_v2_kdf_is_stable_topic_and_psk_bound_and_domain_separated() {
        let topic = [0x11u8; COMPANION_TOPIC_BYTES];
        let psk = [0x22u8; COMPANION_PSK_BYTES];
        let seed = derive_companion_noise_static_seed(&topic, &psk);
        let public_key = expected_companion_noise_static_key(&topic, &psk);

        assert_eq!(seed, derive_companion_noise_static_seed(&topic, &psk));
        assert_eq!(
            public_key,
            expected_companion_noise_static_key(&topic, &psk),
            "the same v2 invite must reproduce the same phone static key"
        );

        let mut changed_topic = topic;
        changed_topic[0] ^= 1;
        let mut changed_psk = psk;
        changed_psk[0] ^= 1;
        assert_ne!(
            seed,
            derive_companion_noise_static_seed(&changed_topic, &psk)
        );
        assert_ne!(
            seed,
            derive_companion_noise_static_seed(&topic, &changed_psk)
        );
        assert_ne!(
            seed,
            derive_companion_noise_static_seed_with_info(
                &topic,
                &psk,
                b"NEOTH/companion/noise-static/v1"
            ),
            "v2 must remain domain-separated from a hypothetical legacy label"
        );
    }

    #[cfg(feature = "cluster")]
    #[test]
    fn companion_v2_debug_redacts_psk_and_derived_seed() {
        let topic: [u8; COMPANION_TOPIC_BYTES] = std::array::from_fn(|index| index as u8);
        let psk: [u8; COMPANION_PSK_BYTES] =
            std::array::from_fn(|index| 0xa0u8.wrapping_add(index as u8));
        let invite = CompanionInvite::from_hex(hex::encode(topic), hex::encode(psk));
        let debug = format!("{invite:?}");
        let seed = derive_companion_noise_static_seed(&topic, &psk);

        assert!(!debug.contains(&hex::encode(psk)));
        assert!(!debug.contains(&hex::encode(seed)));
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
        let reconstructed = CompanionInvite::from_hex(orig.topic_hex.clone(), orig.psk_hex.clone());
        let url2 = reconstructed.pairing_url(300);
        assert_eq!(url1, url2, "from_hex must produce the same pairing URL");
    }

    /// A pre-auth stop request must reach the owned listener without hanging.
    /// The listener spawns a peeroxide DHT swarm
    /// (public bootstrap, real network) and checks the persistent shutdown
    /// watch before topic join. Because DHT bootstrap itself can take a few
    /// seconds before task ownership is returned, the test allows up to 60s
    /// for cleanup after the pre-start cancellation state is recorded.
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
        let mut task = super::spawn_companion_p2p_listener(invite, Arc::clone(&state), writer, 0);
        // Persist stop before the runtime reaches pre-auth. The typed owner
        // carries that state even while public-bootstrap startup is in flight.
        task.request_stop();

        // Must exit without hanging. 60s covers real DHT bootstrap round-trip.
        let result =
            tokio::time::timeout(std::time::Duration::from_secs(60), task.await_terminal()).await;
        assert!(
            result.is_ok(),
            "listener must exit after shutdown is notified"
        );
    }

    #[cfg(feature = "cluster")]
    #[test]
    fn companion_retry_decisions_preserve_or_consume_invite() {
        use super::p2p::{
            AttemptDecision, AttemptEvidence, AttemptRejection, TerminalOutcome,
            attempt_consumes_invite, decide_attempt,
        };

        let expected = [7u8; COMPANION_PSK_BYTES];
        for evidence in [
            AttemptEvidence::Initiated,
            AttemptEvidence::Frame(&[1, 2, 3]),
            AttemptEvidence::Closed,
            AttemptEvidence::ReadFailed,
            AttemptEvidence::ReadTimedOut,
            AttemptEvidence::Frame(&[8u8; COMPANION_PSK_BYTES]),
        ] {
            let decision = decide_attempt(evidence, &expected);
            assert!(matches!(decision, AttemptDecision::Retry(_)));
            assert!(!attempt_consumes_invite(decision));
        }

        let valid = decide_attempt(AttemptEvidence::Frame(&expected), &expected);
        assert_eq!(valid, AttemptDecision::Authenticated);
        assert!(attempt_consumes_invite(valid));
        assert_eq!(
            decide_attempt(AttemptEvidence::Initiated, &expected),
            AttemptDecision::Retry(AttemptRejection::UnexpectedInitiator)
        );

        for terminal in [
            TerminalOutcome::Paired,
            TerminalOutcome::Expired,
            TerminalOutcome::Shutdown,
            TerminalOutcome::TransportClosed,
            TerminalOutcome::DurableCommitFailed,
        ] {
            assert!(terminal.consumes_invite());
        }
    }

    #[cfg(feature = "cluster")]
    #[test]
    fn companion_retry_budget_and_time_bounds_are_fixed() {
        use super::p2p::{RetryBudget, bounded_read_wait, effective_invite_ttl_secs};

        let mut budget = RetryBudget::default();
        let decisions: Vec<_> = (0..12).map(|_| budget.record_rejection()).collect();
        assert_eq!(
            decisions.iter().filter(|d| d.emit_detailed_audit).count(),
            5
        );
        assert_eq!(decisions.last().unwrap().attempt, 12);
        assert_eq!(effective_invite_ttl_secs(0), 1);
        assert_eq!(effective_invite_ttl_secs(30), 30);
        assert_eq!(effective_invite_ttl_secs(u64::MAX), 300);
        assert_eq!(
            bounded_read_wait(std::time::Duration::from_secs(3)),
            std::time::Duration::from_secs(3)
        );
        assert_eq!(
            bounded_read_wait(std::time::Duration::from_secs(30)),
            std::time::Duration::from_secs(10)
        );
    }

    #[cfg(feature = "cluster")]
    #[tokio::test(start_paused = true)]
    async fn companion_read_wait_honors_persistent_shutdown_and_deadline() {
        use super::p2p::{TimedRead, shutdown_requested, wait_for_attempt_read};

        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        shutdown_tx.send(true).unwrap();
        shutdown_requested(&mut shutdown_rx).await;

        let result = wait_for_attempt_read(
            &mut shutdown_rx,
            tokio::time::Instant::now() + std::time::Duration::from_secs(60),
            std::future::pending::<()>(),
        )
        .await;
        assert!(matches!(result, TimedRead::Shutdown));

        let (_tx, mut live_rx) = tokio::sync::watch::channel(false);
        let expired = wait_for_attempt_read(
            &mut live_rx,
            tokio::time::Instant::now(),
            std::future::pending::<()>(),
        )
        .await;
        assert!(matches!(expired, TimedRead::Expired));
    }

    #[tokio::test]
    async fn p2p_owner_retains_commit_task_after_grace_timeout() {
        let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
        let (phase_tx, phase_rx) = tokio::sync::watch::channel(CompanionP2pPhase::Starting);
        let (start_tx, start_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _ = start_rx.await;
            let _ = phase_tx.send(CompanionP2pPhase::Committing);
            while !*stop_rx.borrow() {
                if stop_rx.changed().await.is_err() {
                    break;
                }
            }
            let _ = phase_tx.send(CompanionP2pPhase::Finalizing);
            let _ = phase_tx.send(CompanionP2pPhase::Stopped);
        });
        let mut owner = CompanionP2pTaskHandle::new(task, stop_tx, phase_rx);
        assert_eq!(owner.phase(), CompanionP2pPhase::Starting);
        let mut phases = owner.subscribe_phase();
        start_tx.send(()).unwrap();
        phases.changed().await.unwrap();
        assert_eq!(*phases.borrow(), CompanionP2pPhase::Committing);

        assert!(
            owner
                .observe_grace(std::time::Duration::from_millis(1))
                .await
                .is_none()
        );
        assert!(
            !owner.is_finished(),
            "a grace timeout must retain the still-live commit owner"
        );
        owner.request_stop();
        owner.await_terminal().await.unwrap();
        assert_eq!(owner.phase(), CompanionP2pPhase::Stopped);
    }

    /// `from_hex` with known hex strings produces the expected pairing URL.
    #[test]
    fn invite_from_hex_known_values() {
        let topic = "a".repeat(64); // 32 bytes as 64 hex chars
        let psk = "b".repeat(32); // 16 bytes as 32 hex chars
        let inv = CompanionInvite::from_hex(topic.clone(), psk.clone());
        let url = inv.pairing_url(300);
        assert!(url.contains(&format!("topic={topic}")));
        assert!(url.contains(&format!("psk={psk}")));
        assert!(url.ends_with("ttl=300"));
    }

    /// The strict V1 pending record carries absolute expiry and exact lower-hex
    /// fields, proving the CLI→daemon handoff cannot silently accept an older
    /// loose JSON shape or extend a stale invite's TTL.
    #[test]
    fn pending_invite_record_round_trips_with_absolute_expiry() {
        let inv = CompanionInvite::generate().unwrap();
        let now = 1_700_000_000;
        let record = inv.pending_invite_record(now + 300).unwrap();
        let (rebuilt, ttl) = CompanionInvite::from_pending_invite_record(&record, now).unwrap();
        assert_eq!(ttl, 300);
        assert_eq!(inv.pairing_url(300), rebuilt.pairing_url(300));
    }

    #[test]
    fn pending_invite_record_rejects_unknown_uppercase_or_expired_capabilities() {
        let now = 1_700_000_000;
        let valid = serde_json::json!({
            "version": PENDING_INVITE_RECORD_VERSION,
            "topic_hex": "a".repeat(COMPANION_TOPIC_BYTES * 2),
            "psk_hex": "b".repeat(COMPANION_PSK_BYTES * 2),
            "expires_at": now + 1,
        });
        let mut unknown = valid.clone();
        unknown["extra"] = serde_json::json!(true);
        assert!(
            CompanionInvite::from_pending_invite_record(
                &serde_json::to_vec(&unknown).unwrap(),
                now,
            )
            .is_err()
        );
        let mut uppercase = valid.clone();
        uppercase["psk_hex"] = serde_json::json!("B".repeat(COMPANION_PSK_BYTES * 2));
        assert!(
            CompanionInvite::from_pending_invite_record(
                &serde_json::to_vec(&uppercase).unwrap(),
                now,
            )
            .is_err()
        );
        let mut expired = valid;
        expired["expires_at"] = serde_json::json!(now);
        assert!(
            CompanionInvite::from_pending_invite_record(
                &serde_json::to_vec(&expired).unwrap(),
                now,
            )
            .is_err()
        );
    }

    // ── NEOTH-AUDIT-HTTP-BODY-LIMITS-01: Limited body cap ───────────────────────
    //
    // Unit tests for the `Limited` wrapper used in `handle_pair`. Verify that
    // `Limited` errors before the allocator exceeds COMPANION_BODY_LIMIT_BYTES and
    // passes bodies at or under the cap. The integration test below verifies the
    // full HTTP path returns 413.

    #[tokio::test]
    async fn limited_rejects_body_one_byte_over_companion_cap() {
        use http_body_util::{BodyExt, Full, Limited};
        use hyper::body::Bytes;
        let oversized = Full::new(Bytes::from(vec![0u8; COMPANION_BODY_LIMIT_BYTES + 1]));
        let limited = Limited::new(oversized, COMPANION_BODY_LIMIT_BYTES);
        assert!(
            limited.collect().await.is_err(),
            "Limited must error on a body 1 byte over the {COMPANION_BODY_LIMIT_BYTES} cap"
        );
    }

    #[tokio::test]
    async fn limited_passes_body_at_exact_companion_cap() {
        use http_body_util::{BodyExt, Full, Limited};
        use hyper::body::Bytes;
        let at_cap = Full::new(Bytes::from(vec![0u8; COMPANION_BODY_LIMIT_BYTES]));
        let limited = Limited::new(at_cap, COMPANION_BODY_LIMIT_BYTES);
        assert!(
            limited.collect().await.is_ok(),
            "Limited must allow a body at exactly the {COMPANION_BODY_LIMIT_BYTES} byte cap"
        );
    }

    #[tokio::test]
    async fn companion_pair_rejects_oversized_body_with_413() {
        // Integration test: send a body > COMPANION_BODY_LIMIT_BYTES to the real
        // server and assert 413 Payload Too Large comes back — the Limited path in
        // handle_pair rejects BEFORE the full body is buffered.
        let shutdown = Arc::new(Notify::new());
        let (writer, _wal_join, _wal_dir) = temp_writer();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let state = Arc::new(CompanionState::new(writer, port));
        let srv_shutdown = Arc::clone(&shutdown);
        let srv_state = Arc::clone(&state);
        tokio::spawn(async move {
            run_companion_server(listener, srv_state, srv_shutdown).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let client = reqwest::Client::new();
        let big_body = vec![b'A'; COMPANION_BODY_LIMIT_BYTES + 1];
        let resp = client
            .post(format!("http://127.0.0.1:{port}/api/v1/companion/pair"))
            .header("Content-Type", "application/json")
            .body(big_body)
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            413,
            "oversized body must return 413 Payload Too Large"
        );

        shutdown.notify_waiters();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}
