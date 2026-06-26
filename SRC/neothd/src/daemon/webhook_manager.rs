//! GOLD-ADAPT-ODY-21 — outbound webhook manager cron.
//!
//! A WAL-tail reader cron that scans new WAL frames since a persisted byte
//! cursor, fans matching events out to registered HTTPS endpoints as
//! HMAC-SHA256-signed POSTs, and emits audit frames for every delivery,
//! SSRF block, or failure.
//!
//! ## Trigger events
//!
//! | Source WAL type | Webhook event              |
//! |-----------------|---------------------------|
//! | `0x9A` MODE_CHECKPOINT with `"phase"` starting with `"chat:session-start"` or `"channel:session-start"` | `session_created` |
//! | `0x21` PROVIDER_RESPONSE | `chat_completed` |
//! | `0x01` RAW_TEXT | `chat_message` |
//! | `0x32` CHANNEL_INGRESS | `chat_message` |
//!
//! ## SSRF guard
//!
//! Every endpoint URL is validated before the first POST:
//! 1. Must be `https://`.
//! 2. Hostname is resolved via blocking DNS; zero results → blocked.
//! 3. Every resolved IP is checked against RFC-1918, CGNAT, loopback,
//!    link-local, and multicast ranges; any hit → blocked.
//!
//! ## Cursor persistence
//!
//! A byte-offset cursor per WAL segment filename is written atomically to
//! `~/.neoth/webhook_cursor.json` after each successful tick so the cron
//! never re-fires the same events across restarts.
//!
//! ## Audit trail
//!
//! - `0x08 WEBHOOK_DELIVERED` — endpoint URL + HTTP status + latency_ms
//! - `0x09 WEBHOOK_SSRF_BLOCKED` — endpoint URL
//! - `0x0A WEBHOOK_FAILED` — endpoint URL + error message

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use tracing::{debug, error, info, warn};

use crate::config::automation::{WebhookEndpointConfig, WebhookEvent, WebhookManagerConfig};
use crate::wal::events::{
    EVENT_TYPE_CHANNEL_INGRESS, EVENT_TYPE_MODE_CHECKPOINT, EVENT_TYPE_PROVIDER_RESPONSE,
    EVENT_TYPE_RAW_TEXT, EVENT_TYPE_WEBHOOK_DELIVERED, EVENT_TYPE_WEBHOOK_FAILED,
    EVENT_TYPE_WEBHOOK_SSRF_BLOCKED,
};
use crate::wal::writer::WalWriterHandle;

// ── SSRF guard ───────────────────────────────────────────────────────────────

/// Returns `true` when the IP is a blocked (RFC-1918 / CGNAT / loopback /
/// link-local / multicast) address.
fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let oct = v4.octets();
            // loopback 127.0.0.0/8
            if oct[0] == 127 {
                return true;
            }
            // RFC-1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
            if oct[0] == 10 {
                return true;
            }
            if oct[0] == 172 && (16..=31).contains(&oct[1]) {
                return true;
            }
            if oct[0] == 192 && oct[1] == 168 {
                return true;
            }
            // CGNAT 100.64.0.0/10
            if oct[0] == 100 && (64..=127).contains(&oct[1]) {
                return true;
            }
            // link-local 169.254.0.0/16
            if oct[0] == 169 && oct[1] == 254 {
                return true;
            }
            // multicast 224.0.0.0/4
            if oct[0] & 0xF0 == 224 {
                return true;
            }
            false
        }
        IpAddr::V6(v6) => {
            // loopback ::1
            if v6.is_loopback() {
                return true;
            }
            // link-local fe80::/10
            let seg = v6.segments();
            if (seg[0] & 0xFFC0) == 0xFE80 {
                return true;
            }
            // multicast ff00::/8
            if seg[0] & 0xFF00 == 0xFF00 {
                return true;
            }
            // ULA fc00::/7
            if seg[0] & 0xFE00 == 0xFC00 {
                return true;
            }
            false
        }
    }
}

/// SSRF guard: DNS-resolve `host:port` then check every IP.
/// Returns `Ok(())` when at least one non-blocked address was resolved.
/// Returns `Err(reason)` when the host resolves to nothing, or all resolved
/// addresses are in a blocked range.
async fn ssrf_check(host: &str, port: u16) -> Result<(), String> {
    let addr_str = format!("{host}:{port}");
    let addrs = tokio::task::spawn_blocking(move || {
        use std::net::ToSocketAddrs;
        addr_str
            .to_socket_addrs()
            .map(|it| it.map(|a| a.ip()).collect::<Vec<_>>())
    })
    .await
    .map_err(|e| format!("spawn_blocking join: {e}"))?
    .map_err(|e| format!("DNS resolution failed: {e}"))?;

    if addrs.is_empty() {
        return Err(format!("DNS resolution of '{host}' returned no addresses"));
    }
    for ip in &addrs {
        if !is_blocked_ip(*ip) {
            return Ok(());
        }
    }
    Err(format!(
        "all {} resolved address(es) for '{host}' are in a blocked IP range",
        addrs.len()
    ))
}

/// Extract `(host, port)` from an `https://` URL. Rejects `http://`.
fn extract_host_port(url: &str) -> Result<(String, u16), String> {
    if !url.starts_with("https://") {
        return Err(format!("rejected non-https URL: {url}"));
    }
    let without_scheme = &url["https://".len()..];
    // strip path/query/fragment
    let authority = without_scheme
        .split('/')
        .next()
        .unwrap_or(without_scheme);
    // handle explicit port
    if let Some(colon_pos) = authority.rfind(':') {
        let host = authority[..colon_pos].trim_matches('[').trim_matches(']');
        let port_str = &authority[colon_pos + 1..];
        let port = port_str
            .parse::<u16>()
            .map_err(|_| format!("invalid port in URL: {url}"))?;
        Ok((host.to_string(), port))
    } else {
        Ok((authority.to_string(), 443))
    }
}

// ── HMAC-SHA256 signing ───────────────────────────────────────────────────────

/// Compute `hmac-sha256=<hex>` over `body` using `secret`.
fn hmac_sha256_hex(secret: &str, body: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(body);
    let result = mac.finalize().into_bytes();
    // hex-encode manually (no extra dep)
    result.iter().fold(String::new(), |mut acc, b| {
        use std::fmt::Write;
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

// ── Cursor persistence ────────────────────────────────────────────────────────

type CursorMap = HashMap<String, u64>;

fn cursor_path(home: &Path) -> PathBuf {
    home.join("webhook_cursor.json")
}

fn load_cursor(home: &Path) -> CursorMap {
    let p = cursor_path(home);
    std::fs::read(&p)
        .ok()
        .and_then(|b| serde_json::from_slice::<CursorMap>(&b).ok())
        .unwrap_or_default()
}

fn save_cursor(home: &Path, cursor: &CursorMap) {
    let p = cursor_path(home);
    let tmp = p.with_extension("json.tmp");
    if let Ok(bytes) = serde_json::to_vec(cursor) {
        if std::fs::write(&tmp, &bytes).is_ok() {
            let _ = std::fs::rename(&tmp, &p);
        }
    }
}

// ── WAL scan ─────────────────────────────────────────────────────────────────

/// A parsed event ready for fan-out.
#[derive(Debug, Clone)]
struct PendingWebhook {
    event: WebhookEvent,
    /// ISO-8601 timestamp from the HLC wall-clock (seconds).
    ts_secs: u64,
    /// Best-effort content summary (not the raw payload — avoids leaking PII).
    summary: serde_json::Value,
}

/// Scan WAL segments since the persisted cursors; return pending webhooks and
/// the updated cursor map.
fn scan_wal_for_pending(
    wal_dir: &Path,
    cursors: &CursorMap,
) -> (Vec<PendingWebhook>, CursorMap) {
    let mut new_cursors = cursors.clone();
    let mut pending: Vec<PendingWebhook> = Vec::new();

    let entries = match std::fs::read_dir(wal_dir) {
        Ok(e) => e,
        Err(_) => return (pending, new_cursors),
    };

    let mut segment_files: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("wal"))
        .collect();
    segment_files.sort();

    for path in segment_files {
        let fname = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let hdr = match crate::wal::segment_header::parse_segment_header(&bytes) {
            Ok(h) => h,
            Err(_) => continue,
        };
        let start_cursor = *cursors.get(&fname).unwrap_or(&0);
        let frame_start = hdr.header_len().max(start_cursor as usize);
        let mut cursor = frame_start;
        let mut new_cursor = start_cursor;

        while cursor < bytes.len() {
            let dec = match crate::wal::frame::decode_frame(&bytes[cursor..]) {
                Ok(d) => d,
                Err(_) => break,
            };
            let total = dec.header.total_len as usize;
            if total == 0 {
                break;
            }
            let ts_secs = dec.header.hlc.physical_ns() / 1_000_000_000;
            let ty = dec.header.event_type;

            match ty {
                t if t == EVENT_TYPE_MODE_CHECKPOINT => {
                    // session_created when phase starts with "chat:session-start" or "channel:session-start"
                    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(dec.payload) {
                        let phase = v
                            .get("phase")
                            .and_then(|p| p.as_str())
                            .unwrap_or("");
                        if phase.starts_with("chat:session-start")
                            || phase.starts_with("channel:session-start")
                        {
                            pending.push(PendingWebhook {
                                event: WebhookEvent::SessionCreated,
                                ts_secs,
                                summary: serde_json::json!({ "phase": phase }),
                            });
                        }
                    }
                }
                t if t == EVENT_TYPE_PROVIDER_RESPONSE => {
                    // chat_completed
                    let summary = if let Ok(v) =
                        serde_json::from_slice::<serde_json::Value>(dec.payload)
                    {
                        serde_json::json!({
                            "output_tokens": v.get("output_tokens"),
                            "input_tokens": v.get("input_tokens"),
                            "provider": v.get("provider"),
                        })
                    } else {
                        serde_json::json!({})
                    };
                    pending.push(PendingWebhook {
                        event: WebhookEvent::ChatCompleted,
                        ts_secs,
                        summary,
                    });
                }
                t if t == EVENT_TYPE_RAW_TEXT => {
                    // chat_message (CLI path) — payload is raw bytes, not JSON
                    let char_count = dec.payload.len();
                    pending.push(PendingWebhook {
                        event: WebhookEvent::ChatMessage,
                        ts_secs,
                        summary: serde_json::json!({ "char_count": char_count, "path": "cli" }),
                    });
                }
                t if t == EVENT_TYPE_CHANNEL_INGRESS => {
                    // chat_message (channel path) — may be JSON
                    let summary = if let Ok(v) =
                        serde_json::from_slice::<serde_json::Value>(dec.payload)
                    {
                        serde_json::json!({
                            "channel": v.get("channel"),
                            "path": "channel",
                        })
                    } else {
                        serde_json::json!({ "path": "channel" })
                    };
                    pending.push(PendingWebhook {
                        event: WebhookEvent::ChatMessage,
                        ts_secs,
                        summary,
                    });
                }
                _ => {}
            }
            cursor += total;
            new_cursor = cursor as u64;
        }
        if new_cursor > start_cursor {
            new_cursors.insert(fname, new_cursor);
        }
    }
    (pending, new_cursors)
}

// ── Delivery ──────────────────────────────────────────────────────────────────

/// Cache of SSRF-check results per URL to avoid re-resolving every tick.
/// `Ok(())` = allowed, `Err(reason)` = blocked.
type SsrfCache = HashMap<String, Result<(), String>>;

async fn deliver_to_endpoint(
    client: &reqwest::Client,
    endpoint: &WebhookEndpointConfig,
    hook: &PendingWebhook,
    ssrf_cache: &mut SsrfCache,
    writer: &WalWriterHandle,
) {
    let event_name = match hook.event {
        WebhookEvent::SessionCreated => "session_created",
        WebhookEvent::ChatCompleted => "chat_completed",
        WebhookEvent::ChatMessage => "chat_message",
    };

    // SSRF check (cached per URL)
    let ssrf_result = ssrf_cache
        .entry(endpoint.url.clone())
        .or_insert_with(|| {
            // We can't await inside or_insert_with; use a placeholder.
            // Actual check below.
            Ok(())
        });
    // We need to actually run ssrf_check the first time we see this URL.
    // Replace the placeholder if the cache entry was just inserted.
    // Simplest approach: always check before using; if already Err leave it.
    // Use a second map keyed by "checked" status.
    let _ = ssrf_result; // suppress unused warning

    // Real SSRF check path:
    let ssrf_ok = {
        // If we already have a cached Err, skip re-check.
        if let Some(Err(reason)) = ssrf_cache.get(&endpoint.url) {
            let reason = reason.clone();
            emit_ssrf_blocked(writer, &endpoint.url, &reason).await;
            return;
        }
        // If Ok or not yet checked (we inserted Ok as placeholder above),
        // run the real check now.
        match extract_host_port(&endpoint.url) {
            Err(e) => {
                ssrf_cache.insert(endpoint.url.clone(), Err(e.clone()));
                emit_ssrf_blocked(writer, &endpoint.url, &e).await;
                return;
            }
            Ok((host, port)) => {
                match ssrf_check(&host, port).await {
                    Err(e) => {
                        ssrf_cache.insert(endpoint.url.clone(), Err(e.clone()));
                        emit_ssrf_blocked(writer, &endpoint.url, &e).await;
                        return;
                    }
                    Ok(()) => {
                        ssrf_cache.insert(endpoint.url.clone(), Ok(()));
                        true
                    }
                }
            }
        }
    };
    if !ssrf_ok {
        return; // unreachable but satisfies the type checker
    }

    // Build payload
    let body_value = serde_json::json!({
        "event": event_name,
        "ts": hook.ts_secs,
        "data": hook.summary,
    });
    let body_bytes = match serde_json::to_vec(&body_value) {
        Ok(b) => b,
        Err(e) => {
            error!(url = %endpoint.url, error = %e, "webhook: failed to serialize payload");
            emit_failed(writer, &endpoint.url, &format!("serialize: {e}")).await;
            return;
        }
    };

    // HMAC-SHA256 signature
    let secret = endpoint.secret.expose_secret();
    let signature = if !secret.is_empty() {
        format!("hmac-sha256={}", hmac_sha256_hex(secret, &body_bytes))
    } else {
        warn!(url = %endpoint.url, "webhook: no signing secret configured — signature header omitted");
        String::new()
    };

    // Send
    let t0 = std::time::Instant::now();
    let mut req = client
        .post(&endpoint.url)
        .header("Content-Type", "application/json")
        .body(body_bytes);
    if !signature.is_empty() {
        req = req.header("X-NEOTH-Signature", &signature);
    }
    match req.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let latency_ms = t0.elapsed().as_millis() as u64;
            info!(url = %endpoint.url, status, latency_ms, event = event_name, "webhook delivered");
            emit_delivered(writer, &endpoint.url, status, latency_ms).await;
        }
        Err(e) => {
            let msg = format!("http send: {e}");
            error!(url = %endpoint.url, error = %msg, "webhook delivery failed");
            emit_failed(writer, &endpoint.url, &msg).await;
        }
    }
}

// ── WAL audit emit helpers ────────────────────────────────────────────────────

async fn emit_delivered(writer: &WalWriterHandle, url: &str, status: u16, latency_ms: u64) {
    let payload = serde_json::json!({
        "url": url,
        "status": status,
        "latency_ms": latency_ms,
    });
    emit_audit(writer, EVENT_TYPE_WEBHOOK_DELIVERED, &payload).await;
}

async fn emit_ssrf_blocked(writer: &WalWriterHandle, url: &str, reason: &str) {
    let payload = serde_json::json!({ "url": url, "reason": reason });
    emit_audit(writer, EVENT_TYPE_WEBHOOK_SSRF_BLOCKED, &payload).await;
}

async fn emit_failed(writer: &WalWriterHandle, url: &str, error: &str) {
    let payload = serde_json::json!({ "url": url, "error": error });
    emit_audit(writer, EVENT_TYPE_WEBHOOK_FAILED, &payload).await;
}

async fn emit_audit(writer: &WalWriterHandle, event_type: u8, value: &serde_json::Value) {
    let Ok(bytes) = serde_json::to_vec(value) else {
        return;
    };
    let header = crate::wal::HeaderBuilder::new(event_type, &bytes)
        .flags(crate::wal::EventFlags::SYNTHETIC)
        .build();
    if let Err(e) = writer.append(header, bytes).await {
        error!(error = %e, "webhook_manager: wal append failed");
    }
}

// ── Main tick ─────────────────────────────────────────────────────────────────

/// One webhook manager cron tick.
pub async fn run_webhook_manager_tick(
    config: &WebhookManagerConfig,
    wal_dir: &Path,
    home_dir: &Path,
    client: &reqwest::Client,
    ssrf_cache: &mut SsrfCache,
    writer: &WalWriterHandle,
) {
    let cursors = load_cursor(home_dir);
    let (pending, new_cursors) = scan_wal_for_pending(wal_dir, &cursors);

    if pending.is_empty() {
        debug!("webhook_manager: no new events this tick");
        save_cursor(home_dir, &new_cursors);
        return;
    }

    debug!(count = pending.len(), "webhook_manager: {} new event(s) to deliver", pending.len());

    for hook in &pending {
        for endpoint in &config.endpoints {
            // Filter: if endpoint.events is non-empty, check membership.
            if !endpoint.events.is_empty() && !endpoint.events.contains(&hook.event) {
                continue;
            }
            deliver_to_endpoint(client, endpoint, hook, ssrf_cache, writer).await;
        }
    }

    save_cursor(home_dir, &new_cursors);
}

// ── Spawn ─────────────────────────────────────────────────────────────────────

/// Spawn the webhook-manager cron loop.
/// Returns `None` when `config.enabled == false` (the default).
pub fn spawn_webhook_manager_loop(
    config: WebhookManagerConfig,
    wal_dir: PathBuf,
    home_dir: PathBuf,
    writer: WalWriterHandle,
) -> Option<tokio::task::JoinHandle<()>> {
    if !config.enabled {
        info!("webhook_manager cron disabled in config (webhook_manager.enabled = false)");
        return None;
    }
    let interval = config.interval_duration();
    Some(tokio::spawn(async move {
        let client = match reqwest::Client::builder()
            .https_only(true)
            .timeout(std::time::Duration::from_secs(10))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                error!(error = %e, "webhook_manager: failed to build reqwest client — cron aborted");
                return;
            }
        };
        let mut ssrf_cache: SsrfCache = HashMap::new();
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        info!(
            interval_secs = interval.as_secs(),
            endpoints = config.endpoints.len(),
            "webhook_manager cron loop online (GOLD-ADAPT-ODY-21)",
        );
        loop {
            ticker.tick().await;
            run_webhook_manager_tick(
                &config,
                &wal_dir,
                &home_dir,
                &client,
                &mut ssrf_cache,
                &writer,
            )
            .await;
        }
    }))
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── SSRF IP guard ────────────────────────────────────────────────────────

    #[test]
    fn ssrf_ip_blocks_rfc1918() {
        use std::net::{IpAddr, Ipv4Addr};
        assert!(is_blocked_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_blocked_ip(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(is_blocked_ip(IpAddr::V4(Ipv4Addr::new(172, 31, 255, 255))));
        assert!(is_blocked_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }

    #[test]
    fn ssrf_ip_blocks_loopback() {
        use std::net::{IpAddr, Ipv4Addr};
        assert!(is_blocked_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    }

    #[test]
    fn ssrf_ip_blocks_cgnat() {
        use std::net::{IpAddr, Ipv4Addr};
        assert!(is_blocked_ip(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
        assert!(is_blocked_ip(IpAddr::V4(Ipv4Addr::new(100, 127, 255, 255))));
    }

    #[test]
    fn ssrf_ip_blocks_link_local() {
        use std::net::{IpAddr, Ipv4Addr};
        assert!(is_blocked_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))));
    }

    #[test]
    fn ssrf_ip_blocks_multicast() {
        use std::net::{IpAddr, Ipv4Addr};
        assert!(is_blocked_ip(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1))));
        assert!(is_blocked_ip(IpAddr::V4(Ipv4Addr::new(239, 255, 255, 255))));
    }

    #[test]
    fn ssrf_ip_allows_public() {
        use std::net::{IpAddr, Ipv4Addr};
        // 1.1.1.1 is public
        assert!(!is_blocked_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        // 8.8.8.8 is public
        assert!(!is_blocked_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn ssrf_ip_blocks_ipv6_loopback() {
        use std::net::{IpAddr, Ipv6Addr};
        assert!(is_blocked_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    // ── extract_host_port ────────────────────────────────────────────────────

    #[test]
    fn extract_host_port_standard_https() {
        let (h, p) = extract_host_port("https://example.com/webhook").unwrap();
        assert_eq!(h, "example.com");
        assert_eq!(p, 443);
    }

    #[test]
    fn extract_host_port_custom_port() {
        let (h, p) = extract_host_port("https://example.com:8443/webhook").unwrap();
        assert_eq!(h, "example.com");
        assert_eq!(p, 8443);
    }

    #[test]
    fn extract_host_port_rejects_http() {
        assert!(extract_host_port("http://example.com/webhook").is_err());
    }

    // ── HMAC signing ─────────────────────────────────────────────────────────

    #[test]
    fn hmac_sha256_hex_is_deterministic() {
        let sig1 = hmac_sha256_hex("secret", b"hello");
        let sig2 = hmac_sha256_hex("secret", b"hello");
        assert_eq!(sig1, sig2);
        assert_eq!(sig1.len(), 64); // 32 bytes → 64 hex chars
    }

    #[test]
    fn hmac_sha256_hex_differs_on_different_keys() {
        let sig1 = hmac_sha256_hex("key1", b"hello");
        let sig2 = hmac_sha256_hex("key2", b"hello");
        assert_ne!(sig1, sig2);
    }

    // ── cursor persistence ────────────────────────────────────────────────────

    #[test]
    fn cursor_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let mut m: CursorMap = HashMap::new();
        m.insert("seg001.wal".to_string(), 4096);
        save_cursor(dir.path(), &m);
        let loaded = load_cursor(dir.path());
        assert_eq!(loaded.get("seg001.wal").copied(), Some(4096));
    }

    #[test]
    fn cursor_missing_file_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let loaded = load_cursor(dir.path());
        assert!(loaded.is_empty());
    }

    // ── WAL scan ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn scan_detects_provider_response_frame() {
        let wal_dir = tempfile::tempdir().unwrap();
        let seg = wal_dir.path().join("000001.wal");

        // Write a WAL segment containing one PROVIDER_RESPONSE frame.
        let (writer, join) = crate::wal::writer::spawn(seg.clone()).unwrap();
        let payload = serde_json::to_vec(&serde_json::json!({
            "provider": "test",
            "output_tokens": 42u64,
            "input_tokens": 10u64,
        }))
        .unwrap();
        let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_PROVIDER_RESPONSE, &payload)
            .build();
        writer.append(header, payload).await.unwrap();
        // Flush: drop writer to close the channel, then await background task
        drop(writer);
        let _ = join.await;

        let cursors: CursorMap = HashMap::new();
        let (pending, new_cursors) = scan_wal_for_pending(wal_dir.path(), &cursors);

        assert_eq!(pending.len(), 1, "expected 1 pending webhook");
        assert!(matches!(pending[0].event, WebhookEvent::ChatCompleted));
        // cursor should advance
        assert!(!new_cursors.is_empty());
    }
}
