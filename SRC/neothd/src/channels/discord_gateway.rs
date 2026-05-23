//! Discord Gateway WSS receive scaffold — v0.3+ scope per Codex feedback.
//!
//! Discord's bot-receive path needs a long-lived WebSocket connection
//! to `wss://gateway.discord.gg/?v=10&encoding=json`. The protocol is a
//! Discord-specific opcode envelope (heartbeat / identify / dispatch /
//! resume / invalid-session / hello / heartbeat-ack) layered over JSON.
//! Reference implementation: `channels/slack_socket.rs` which runs the
//! same shape against Slack's Socket Mode (different op-codes + token
//! contract; identical WSS-reconnect-with-backoff topology).
//!
//! ## Status: NOT YET LIVE
//!
//! Per `channels/discord.rs` module-doc, receive lands in v0.3+. This
//! file is the scaffold so when the implementation arrives it slots
//! into a public surface that's already audit-stable:
//!   - opcode constants (lookup table operators can `--explain`)
//!   - intent flag bitmask (the per-event subscription Discord requires)
//!   - state-machine [`GatewayPhase`] every doctor / CLI consults
//!
//! No `tokio_tungstenite` WSS client lives in this module yet — that
//! lands behind a `discord-gateway` Cargo feature (analogous to
//! `slack-socket`) when the implementation PR ships. Today the module
//! exposes the data shapes so callers (`neoth doctor --explain
//! discord-gateway`, `neoth events --grep discord`) can wire against
//! stable names that won't drift.
//!
//! ## References
//!
//! - <https://discord.com/developers/docs/topics/gateway> — v10 protocol
//! - `channels/slack_socket.rs` — analogous WSS-with-backoff reference
//! - `channels/discord.rs` — Phase-1 send-only adapter sitting next door

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicI64, Ordering};

/// Stable wire payload the gateway emits to operator-visible logs +
/// the WAL audit trail. Mirrors Discord's envelope shape on the wire
/// (op + d + s + t) so the deserialiser handles real Gateway frames.
#[derive(Clone, Debug, Deserialize)]
pub struct GatewayEnvelope {
    /// Opcode — match against `opcode::*` constants.
    pub op: u8,
    /// Optional sequence number — present on DISPATCH (op=0) frames.
    /// `None` for HELLO / HEARTBEAT_ACK / others.
    #[serde(default)]
    pub s: Option<i64>,
    /// Event type for DISPATCH frames — `READY` / `MESSAGE_CREATE`
    /// / `GUILD_CREATE` / etc. `None` for non-dispatch envelopes.
    #[serde(default)]
    pub t: Option<String>,
}

/// Identify payload Discord expects after the first HELLO frame.
/// Pick #37 ships the struct; the actual send via the WSS sink lands
/// in the follow-up that wires the live receive loop.
#[derive(Clone, Debug, Serialize)]
pub struct IdentifyPayload {
    pub token: String,
    pub intents: u32,
    pub properties: IdentifyProperties,
}

#[derive(Clone, Debug, Serialize)]
pub struct IdentifyProperties {
    /// Discord requires these three fields; we identify as NEOTH so
    /// the operator's Discord developer-portal sees the right client
    /// name.
    #[serde(rename = "$os")]
    pub os: String,
    #[serde(rename = "$browser")]
    pub browser: String,
    #[serde(rename = "$device")]
    pub device: String,
}

impl IdentifyProperties {
    pub fn neoth_default() -> Self {
        Self {
            os: std::env::consts::OS.to_string(),
            browser: "neoth".to_string(),
            device: "neoth".to_string(),
        }
    }
}

/// Resume payload — used after a transient disconnect to re-attach
/// to the prior session without losing event continuity.
#[derive(Clone, Debug, Serialize)]
pub struct ResumePayload {
    pub token: String,
    pub session_id: String,
    pub seq: i64,
}

/// Maximum back-off between reconnect attempts. Discord's typical
/// disconnect-then-resume cycle settles in under a second; the cap
/// keeps a sustained outage from pounding the API.
pub const MAX_RECONNECT_BACKOFF_SECS: u64 = 60;

/// Process-wide last-seen sequence number. The heartbeat task reads
/// this to populate the `d` field of HEARTBEAT frames so Discord
/// knows where we left off if the connection drops.
static LAST_SEQ: AtomicI64 = AtomicI64::new(-1);

/// Update the sequence tracker. Called by the dispatch handler on
/// every DISPATCH frame so the heartbeat task picks up the latest.
pub fn record_seq(seq: i64) {
    LAST_SEQ.store(seq, Ordering::Release);
}

/// Read the current sequence. `-1` means "no DISPATCH frame seen
/// yet" — the heartbeat sends `null` in that case.
pub fn current_seq() -> i64 {
    LAST_SEQ.load(Ordering::Acquire)
}

/// Reset the sequence tracker. Used by the test suite + by the
/// gateway when an INVALID_SESSION forces a full re-identify.
pub fn reset_seq() {
    LAST_SEQ.store(-1, Ordering::Release);
}

/// Pick #37 follow-up — pure function that constructs the JSON body
/// for a HEARTBEAT (op=1) frame. The `d` field carries the last-seen
/// sequence number, or `null` when no DISPATCH has arrived yet.
/// Discord uses this on reconnect to determine whether a Resume is
/// viable or a full Identify is required.
pub fn build_heartbeat_payload(seq: i64) -> String {
    if seq < 0 {
        // No sequence yet → send `null`. Discord accepts this on the
        // first heartbeat after Hello + before the Ready dispatch.
        r#"{"op":1,"d":null}"#.to_string()
    } else {
        format!(r#"{{"op":1,"d":{seq}}}"#)
    }
}

/// Compute the exponential-backoff delay for reconnect attempt `n`.
/// `n = 0` returns the first-attempt delay (1s); each subsequent
/// attempt doubles up to [`MAX_RECONNECT_BACKOFF_SECS`]. Used by the
/// reconnect loop after a transient WSS error.
pub fn reconnect_backoff_secs(attempt: u32) -> u64 {
    // 2^n seconds, capped. Saturates at the ceiling without overflow.
    let raw = 1u64
        .checked_shl(attempt)
        .unwrap_or(MAX_RECONNECT_BACKOFF_SECS);
    raw.min(MAX_RECONNECT_BACKOFF_SECS)
}

/// Decide what to do after receiving an envelope. Pure function so
/// the reconnect / dispatch / shutdown logic stays testable without
/// a live WSS server.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum GatewayAction {
    /// Update the seq tracker + forward the DISPATCH payload to
    /// the inbound pipeline. The `event_type` field carries the
    /// `t` from the envelope (e.g. `MESSAGE_CREATE`).
    DispatchEvent { seq: i64, event_type: String },
    /// Server sent HELLO — record the `heartbeat_interval` (the
    /// follow-up live-loop wires the periodic task) and send IDENTIFY.
    SendIdentify,
    /// Server ACK'd our heartbeat — happy path, no action.
    HeartbeatAcked,
    /// Server requested Reconnect — close + Resume on the same session.
    ReconnectAndResume,
    /// Server sent INVALID_SESSION — reset seq + full Identify on a
    /// fresh connection.
    InvalidSessionResetAndIdentify,
    /// Unknown opcode — log + ignore (forward-compat with future
    /// protocol additions).
    UnknownOpcode { op: u8 },
}

/// Classify an envelope into an actionable command. Pure function —
/// the live receive loop calls this on every parsed frame.
pub fn classify_envelope(env: &GatewayEnvelope) -> GatewayAction {
    match env.op {
        op if op == opcode::DISPATCH => GatewayAction::DispatchEvent {
            seq: env.s.unwrap_or(-1),
            event_type: env.t.clone().unwrap_or_else(|| "UNKNOWN".to_string()),
        },
        op if op == opcode::HELLO => GatewayAction::SendIdentify,
        op if op == opcode::HEARTBEAT_ACK => GatewayAction::HeartbeatAcked,
        op if op == opcode::RECONNECT => GatewayAction::ReconnectAndResume,
        op if op == opcode::INVALID_SESSION => GatewayAction::InvalidSessionResetAndIdentify,
        other => GatewayAction::UnknownOpcode { op: other },
    }
}

// Pick #37 follow-up (2026-05-20): session-state + close-code +
// reconnect-tracker helpers needed by the live WSS loop. Adding them
// here keeps the loop side (`run_gateway_session`) thin + delegates
// all decision logic to pure functions for testability.

/// Process-wide Discord session identifier from the READY dispatch.
/// The reconnect path consults this when deciding between RESUME
/// (existing session) vs IDENTIFY (fresh session) frames.
static SESSION_ID: std::sync::OnceLock<std::sync::Mutex<Option<String>>> =
    std::sync::OnceLock::new();

fn session_id_handle() -> &'static std::sync::Mutex<Option<String>> {
    SESSION_ID.get_or_init(|| std::sync::Mutex::new(None))
}

/// Record the session id from a READY dispatch. The live loop calls
/// this on the first DispatchEvent whose event_type is "READY".
pub fn record_session_id(id: impl Into<String>) {
    if let Ok(mut g) = session_id_handle().lock() {
        *g = Some(id.into());
    }
}

/// Read the current session id. None means we never reached READY on
/// this connection (e.g. WSS dropped before identify completed).
pub fn current_session_id() -> Option<String> {
    session_id_handle().lock().ok()?.clone()
}

/// Reset the session tracker. Called by the reconnect loop after an
/// INVALID_SESSION or a non-resumable close code so the next loop
/// runs IDENTIFY instead of RESUME.
pub fn reset_session_id() {
    if let Ok(mut g) = session_id_handle().lock() {
        *g = None;
    }
}

/// Decide whether the just-closed connection can be resumed via the
/// RESUME op, or whether a fresh IDENTIFY is required. Per Discord's
/// "Gateway Close Event Codes" reference table.
///
/// - Codes 4004/4010/4011/4012/4013/4014: terminal — operator config
///   problem (bad token, invalid intents). Resume cannot fix; the
///   reconnect loop bails after surfacing the close code to the
///   operator via tracing::error.
/// - Code 4007/4009: protocol error. Discard session, fresh IDENTIFY.
/// - All other codes (incl. 1000/1001/1006 / network drops): resume
///   eligible.
pub fn should_resume_after_close(code: u16) -> bool {
    !matches!(
        code,
        4004    // authentication failed
        | 4007  // invalid sequence
        | 4009  // session timed out
        | 4010  // invalid shard
        | 4011  // sharding required
        | 4012  // invalid API version
        | 4013  // invalid intents
        | 4014 // disallowed intents
    )
}

/// Returns true when the close code is operator-actionable + the
/// reconnect loop should bail. Used by the live loop to log a clear
/// error + stop rather than spinning on a config-broken session.
pub fn is_terminal_close(code: u16) -> bool {
    matches!(code, 4004 | 4010 | 4011 | 4012 | 4013 | 4014)
}

/// Reconnect attempt tracker. Each loop iteration increments
/// `attempts` + computes a delay via [`reconnect_backoff_secs`].
/// `record_success` is called by the live loop once IDENTIFY is
/// acknowledged so a stable connection rolls the backoff back to 0.
#[derive(Debug, Default, Clone)]
pub struct ReconnectTracker {
    attempts: u32,
}

impl ReconnectTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of attempts since the last [`Self::record_success`].
    pub fn attempts(&self) -> u32 {
        self.attempts
    }

    /// Compute + return the next delay then increment the attempt
    /// counter. Caller sleeps the returned duration before reconnect.
    pub fn next_delay(&mut self) -> std::time::Duration {
        let secs = reconnect_backoff_secs(self.attempts);
        self.attempts = self.attempts.saturating_add(1);
        std::time::Duration::from_secs(secs)
    }

    /// Reset the tracker. Called after a successful IDENTIFY ACK so
    /// the next disconnect starts fresh at 1 s.
    pub fn record_success(&mut self) {
        self.attempts = 0;
    }
}

/// Gateway WebSocket endpoint pinned to v10 + JSON encoding. The
/// `/gateway/bot` REST call returns a session URL but the v10 root is
/// stable enough to default to. Discord's docs guarantee v9/v10 wire
/// compatibility for the opcode envelope.
pub const GATEWAY_WSS_URL: &str = "wss://gateway.discord.gg/?v=10&encoding=json";

/// Discord Gateway opcodes per v10 spec
/// (<https://discord.com/developers/docs/topics/opcodes-and-status-codes#gateway-opcodes>).
/// Pinned as integer constants so the dispatch table can match exhaustively;
/// using a Rust enum forces invalid-on-the-wire handling on every
/// `from_u8`, which is the pattern the reader half wants.
#[allow(dead_code)]
pub mod opcode {
    /// Dispatch — every received event (MESSAGE_CREATE, GUILD_CREATE, ...).
    pub const DISPATCH: u8 = 0;
    /// Heartbeat — bidirectional keepalive (sent every `heartbeat_interval` ms).
    pub const HEARTBEAT: u8 = 1;
    /// Identify — first message after Hello; carries token + intents.
    pub const IDENTIFY: u8 = 2;
    /// Presence update — bot status / activity.
    pub const PRESENCE_UPDATE: u8 = 3;
    /// Voice state update — out of scope for NEOTH chat receive.
    pub const VOICE_STATE_UPDATE: u8 = 4;
    /// Resume — reconnect using last seq + session_id.
    pub const RESUME: u8 = 6;
    /// Reconnect — server-initiated; client must close + Resume.
    pub const RECONNECT: u8 = 7;
    /// Request guild members — chunked member fetch.
    pub const REQUEST_GUILD_MEMBERS: u8 = 8;
    /// Invalid session — Resume failed, fall back to full Identify.
    pub const INVALID_SESSION: u8 = 9;
    /// Hello — first message FROM server; carries `heartbeat_interval`.
    pub const HELLO: u8 = 10;
    /// Heartbeat ACK — server confirms our heartbeat.
    pub const HEARTBEAT_ACK: u8 = 11;
}

/// Discord Gateway Intents bitmask — the subscription flags an
/// Identify payload carries. Bot only receives events for intents it
/// requested. NEOTH's chat-receive baseline needs DMs + guild messages
/// + message content (the privileged intent every developer-portal
///   app must explicitly enable).
///
/// Spec: <https://discord.com/developers/docs/topics/gateway#gateway-intents>
#[allow(dead_code)]
pub mod intents {
    /// `GUILDS` — guild lifecycle events (create / update / delete).
    pub const GUILDS: u32 = 1 << 0;
    /// `GUILD_MESSAGES` — MESSAGE_CREATE / UPDATE / DELETE in guild channels.
    pub const GUILD_MESSAGES: u32 = 1 << 9;
    /// `DIRECT_MESSAGES` — DMs to the bot.
    pub const DIRECT_MESSAGES: u32 = 1 << 12;
    /// `MESSAGE_CONTENT` — content field included in MESSAGE_CREATE.
    ///   PRIVILEGED — operator must enable in developer-portal app
    ///   settings before the bot can subscribe.
    pub const MESSAGE_CONTENT: u32 = 1 << 15;

    /// Default NEOTH chat-receive bundle: guilds + guild messages +
    /// DMs + content. Operator can override via
    /// `freedom.yaml::channels.discord.intents` once the receive path
    /// is wired.
    pub const NEOTH_DEFAULT: u32 = GUILDS | GUILD_MESSAGES | DIRECT_MESSAGES | MESSAGE_CONTENT;
}

/// State-machine phase of the Gateway connection. Operator
/// observability surface — `neoth doctor --explain discord-gateway`
/// reports this enum so the operator can tell "the bot is connected"
/// from "the bot is waiting on the first Hello" at a glance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum GatewayPhase {
    /// Not started — receive feature off, or first boot before the
    /// adapter's `run()` future spawned.
    NotStarted,
    /// WSS handshake in progress (DNS + TCP + TLS).
    Connecting,
    /// Connected; waiting on the server's first Hello frame.
    WaitingForHello,
    /// Hello received + first Heartbeat sent; sent the Identify
    /// payload, waiting on the first DISPATCH (READY).
    Identifying,
    /// Steady-state: receiving DISPATCH frames + sending periodic
    /// Heartbeats per the server-supplied interval.
    Streaming,
    /// Server requested Reconnect or the connection dropped; backoff
    /// timer running before the next dial attempt.
    Backoff,
    /// Closed permanently — operator stopped the daemon or
    /// authentication failed with a non-recoverable code (4004 bad
    /// token / 4014 disallowed intent).
    Closed,
}

impl GatewayPhase {
    /// Stable wire-form name for the WAL payload / doctor output.
    pub const fn as_str(self) -> &'static str {
        match self {
            GatewayPhase::NotStarted => "not_started",
            GatewayPhase::Connecting => "connecting",
            GatewayPhase::WaitingForHello => "waiting_for_hello",
            GatewayPhase::Identifying => "identifying",
            GatewayPhase::Streaming => "streaming",
            GatewayPhase::Backoff => "backoff",
            GatewayPhase::Closed => "closed",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pick #37 hygiene (Session 17 follow-up, 2026-05-19): tests that
    /// mutate the process-wide `LAST_SEQ` atomic must sequence against
    /// each other. cargo's default test runner schedules tests across
    /// threads, so two tests that both call `reset_seq` + `record_seq`
    /// can interleave and observe each other's writes — a race that
    /// surfaces only under parallel scheduling + masks as a flaky
    /// `seq_tracker_records_latest` failure.
    ///
    /// Solution: a test-only mutex held for the duration of any test
    /// that touches `LAST_SEQ`. Poison-tolerant (`unwrap_or_else`) so
    /// a single test panic does not cascade-fail every other test in
    /// the module.
    ///
    /// Rationale for not depending on `serial_test`: the race lives in
    /// 2 tests in 1 file. A single `std::sync::Mutex` solves it without
    /// a new crate-graph dependency.
    static SEQ_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn gateway_url_pins_v10_json() {
        assert!(GATEWAY_WSS_URL.contains("v=10"));
        assert!(GATEWAY_WSS_URL.contains("encoding=json"));
        assert!(GATEWAY_WSS_URL.starts_with("wss://"));
    }

    #[test]
    fn opcode_constants_match_discord_spec() {
        // Pin the literal numbers per Discord's v10 opcode table.
        // These NEVER drift — Discord versions opcodes via the
        // `v=` query parameter; if Discord ships a v11 with different
        // numbers, that lives in a sibling module.
        assert_eq!(opcode::DISPATCH, 0);
        assert_eq!(opcode::HEARTBEAT, 1);
        assert_eq!(opcode::IDENTIFY, 2);
        assert_eq!(opcode::RESUME, 6);
        assert_eq!(opcode::RECONNECT, 7);
        assert_eq!(opcode::INVALID_SESSION, 9);
        assert_eq!(opcode::HELLO, 10);
        assert_eq!(opcode::HEARTBEAT_ACK, 11);
    }

    #[test]
    fn neoth_default_intents_bundle_covers_dms_and_guild_messages() {
        // The chat-receive contract requires at minimum DM + guild
        // messages + message content. Bitmask membership ensures the
        // bundle doesn't silently drop a required intent.
        assert_eq!(intents::NEOTH_DEFAULT & intents::GUILDS, intents::GUILDS);
        assert_eq!(
            intents::NEOTH_DEFAULT & intents::GUILD_MESSAGES,
            intents::GUILD_MESSAGES
        );
        assert_eq!(
            intents::NEOTH_DEFAULT & intents::DIRECT_MESSAGES,
            intents::DIRECT_MESSAGES
        );
        assert_eq!(
            intents::NEOTH_DEFAULT & intents::MESSAGE_CONTENT,
            intents::MESSAGE_CONTENT
        );
    }

    #[test]
    fn gateway_phase_serialises_to_snake_case() {
        // WAL payloads + doctor JSON output read these strings; pin
        // them so a future rename surfaces here, not in operator logs.
        assert_eq!(GatewayPhase::NotStarted.as_str(), "not_started");
        assert_eq!(GatewayPhase::WaitingForHello.as_str(), "waiting_for_hello");
        assert_eq!(GatewayPhase::Streaming.as_str(), "streaming");
        assert_eq!(GatewayPhase::Backoff.as_str(), "backoff");
        assert_eq!(GatewayPhase::Closed.as_str(), "closed");
    }

    #[test]
    fn gateway_phase_serde_round_trip() {
        let p = GatewayPhase::Streaming;
        let json = serde_json::to_string(&p).unwrap();
        let back: GatewayPhase = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    // ── Pick #37 — envelope + identify + resume + seq tracker ─────────

    #[test]
    fn envelope_parses_hello_frame() {
        let raw = r#"{"op":10,"d":{"heartbeat_interval":41250},"s":null,"t":null}"#;
        let env: GatewayEnvelope = serde_json::from_str(raw).unwrap();
        assert_eq!(env.op, opcode::HELLO);
        assert_eq!(env.s, None);
        assert_eq!(env.t, None);
    }

    #[test]
    fn envelope_parses_dispatch_frame() {
        let raw = r#"{"op":0,"s":42,"t":"MESSAGE_CREATE","d":{"id":"123"}}"#;
        let env: GatewayEnvelope = serde_json::from_str(raw).unwrap();
        assert_eq!(env.op, opcode::DISPATCH);
        assert_eq!(env.s, Some(42));
        assert_eq!(env.t.as_deref(), Some("MESSAGE_CREATE"));
    }

    #[test]
    fn envelope_parses_heartbeat_ack() {
        let raw = r#"{"op":11,"d":null,"s":null,"t":null}"#;
        let env: GatewayEnvelope = serde_json::from_str(raw).unwrap();
        assert_eq!(env.op, opcode::HEARTBEAT_ACK);
    }

    #[test]
    fn identify_properties_carry_neoth_branding() {
        let p = IdentifyProperties::neoth_default();
        assert_eq!(p.browser, "neoth");
        assert_eq!(p.device, "neoth");
        // OS comes from the host — just ensure it's not empty.
        assert!(!p.os.is_empty());
    }

    #[test]
    fn identify_payload_serialises_with_intents_bundle() {
        let payload = IdentifyPayload {
            token: "Bot xxx".into(),
            intents: intents::NEOTH_DEFAULT,
            properties: IdentifyProperties::neoth_default(),
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"intents\""));
        assert!(json.contains("$os"));
        assert!(json.contains("$browser"));
    }

    #[test]
    fn seq_tracker_starts_at_minus_one() {
        let _guard = SEQ_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_seq();
        assert_eq!(current_seq(), -1);
    }

    #[test]
    fn seq_tracker_records_latest() {
        let _guard = SEQ_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_seq();
        record_seq(42);
        assert_eq!(current_seq(), 42);
        record_seq(100);
        assert_eq!(current_seq(), 100);
        reset_seq();
        assert_eq!(current_seq(), -1);
    }

    #[test]
    fn max_reconnect_backoff_is_capped() {
        assert_eq!(MAX_RECONNECT_BACKOFF_SECS, 60);
    }

    // ── Pick #37 follow-up: session + close-code + tracker tests ──

    static SESSION_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn session_id_round_trips_record_read_reset() {
        let _guard = SESSION_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_session_id();
        assert!(current_session_id().is_none());
        record_session_id("abc-123");
        assert_eq!(current_session_id().as_deref(), Some("abc-123"));
        reset_session_id();
        assert!(current_session_id().is_none());
    }

    #[test]
    fn should_resume_after_close_handles_normal_codes() {
        // Network drops / typical closes are resumable.
        assert!(should_resume_after_close(1000));
        assert!(should_resume_after_close(1001));
        assert!(should_resume_after_close(1006));
        // Unknown numeric is treated as resumable (forward-compat).
        assert!(should_resume_after_close(4999));
    }

    #[test]
    fn should_resume_after_close_blocks_terminal_codes() {
        // Auth failure + intent issues require fresh IDENTIFY (or
        // operator action). Resume is invalid for these.
        assert!(!should_resume_after_close(4004));
        assert!(!should_resume_after_close(4010));
        assert!(!should_resume_after_close(4011));
        assert!(!should_resume_after_close(4012));
        assert!(!should_resume_after_close(4013));
        assert!(!should_resume_after_close(4014));
        // 4007 + 4009 are protocol/timeout — fresh identify, not
        // operator-terminal.
        assert!(!should_resume_after_close(4007));
        assert!(!should_resume_after_close(4009));
    }

    #[test]
    fn is_terminal_close_only_for_operator_actionable() {
        // The four codes the live loop must bail on (operator config).
        for c in [4004, 4010, 4011, 4012, 4013, 4014] {
            assert!(is_terminal_close(c), "code {c} must be terminal");
        }
        // Network / protocol / sequence-loss are NOT terminal — the
        // loop reconnects.
        for c in [1000, 1006, 4007, 4009, 4999] {
            assert!(!is_terminal_close(c), "code {c} must not be terminal");
        }
    }

    #[test]
    fn reconnect_tracker_default_starts_at_zero() {
        let t = ReconnectTracker::new();
        assert_eq!(t.attempts(), 0);
    }

    #[test]
    fn reconnect_tracker_next_delay_increments_attempts() {
        let mut t = ReconnectTracker::new();
        let d1 = t.next_delay();
        let d2 = t.next_delay();
        assert_eq!(d1.as_secs(), 1, "first attempt = 1s");
        assert_eq!(d2.as_secs(), 2, "second attempt = 2s");
        assert_eq!(t.attempts(), 2);
    }

    #[test]
    fn reconnect_tracker_record_success_resets_counter() {
        let mut t = ReconnectTracker::new();
        t.next_delay();
        t.next_delay();
        t.next_delay();
        assert_eq!(t.attempts(), 3);
        t.record_success();
        assert_eq!(t.attempts(), 0);
        // Next delay back to 1s.
        assert_eq!(t.next_delay().as_secs(), 1);
    }

    #[test]
    fn reconnect_tracker_saturates_at_max_backoff() {
        // After many attempts the backoff caps at
        // MAX_RECONNECT_BACKOFF_SECS without overflow.
        let mut t = ReconnectTracker::new();
        for _ in 0..30 {
            let _ = t.next_delay();
        }
        assert!(t.next_delay().as_secs() <= MAX_RECONNECT_BACKOFF_SECS);
    }

    #[test]
    fn resume_payload_serialises_with_seq() {
        let p = ResumePayload {
            token: "Bot xxx".into(),
            session_id: "abc-123".into(),
            seq: 99,
        };
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("session_id"));
        assert!(json.contains("99"));
    }

    // ── Pick #37 follow-up — heartbeat + backoff + dispatch ──────────

    #[test]
    fn build_heartbeat_emits_null_for_no_seq() {
        let body = build_heartbeat_payload(-1);
        assert_eq!(body, r#"{"op":1,"d":null}"#);
    }

    #[test]
    fn build_heartbeat_emits_integer_seq() {
        let body = build_heartbeat_payload(42);
        assert_eq!(body, r#"{"op":1,"d":42}"#);
    }

    #[test]
    fn reconnect_backoff_grows_exponentially() {
        assert_eq!(reconnect_backoff_secs(0), 1);
        assert_eq!(reconnect_backoff_secs(1), 2);
        assert_eq!(reconnect_backoff_secs(2), 4);
        assert_eq!(reconnect_backoff_secs(3), 8);
        assert_eq!(reconnect_backoff_secs(4), 16);
        assert_eq!(reconnect_backoff_secs(5), 32);
    }

    #[test]
    fn reconnect_backoff_caps_at_max() {
        assert_eq!(reconnect_backoff_secs(6), MAX_RECONNECT_BACKOFF_SECS);
        assert_eq!(reconnect_backoff_secs(20), MAX_RECONNECT_BACKOFF_SECS);
        assert_eq!(reconnect_backoff_secs(100), MAX_RECONNECT_BACKOFF_SECS);
    }

    #[test]
    fn classify_dispatch_extracts_seq_and_event_type() {
        let env = GatewayEnvelope {
            op: opcode::DISPATCH,
            s: Some(7),
            t: Some("MESSAGE_CREATE".to_string()),
        };
        match classify_envelope(&env) {
            GatewayAction::DispatchEvent { seq, event_type } => {
                assert_eq!(seq, 7);
                assert_eq!(event_type, "MESSAGE_CREATE");
            }
            other => panic!("expected DispatchEvent, got {other:?}"),
        }
    }

    #[test]
    fn classify_hello_returns_send_identify() {
        let env = GatewayEnvelope {
            op: opcode::HELLO,
            s: None,
            t: None,
        };
        assert_eq!(classify_envelope(&env), GatewayAction::SendIdentify);
    }

    #[test]
    fn classify_heartbeat_ack_returns_acked() {
        let env = GatewayEnvelope {
            op: opcode::HEARTBEAT_ACK,
            s: None,
            t: None,
        };
        assert_eq!(classify_envelope(&env), GatewayAction::HeartbeatAcked);
    }

    #[test]
    fn classify_reconnect_signals_resume() {
        let env = GatewayEnvelope {
            op: opcode::RECONNECT,
            s: None,
            t: None,
        };
        assert_eq!(classify_envelope(&env), GatewayAction::ReconnectAndResume);
    }

    #[test]
    fn classify_invalid_session_resets() {
        let env = GatewayEnvelope {
            op: opcode::INVALID_SESSION,
            s: None,
            t: None,
        };
        assert_eq!(
            classify_envelope(&env),
            GatewayAction::InvalidSessionResetAndIdentify
        );
    }

    #[test]
    fn classify_unknown_opcode_falls_through() {
        let env = GatewayEnvelope {
            op: 99,
            s: None,
            t: None,
        };
        match classify_envelope(&env) {
            GatewayAction::UnknownOpcode { op } => assert_eq!(op, 99),
            other => panic!("expected UnknownOpcode, got {other:?}"),
        }
    }

    #[test]
    fn classify_dispatch_with_missing_seq_defaults_to_minus_one() {
        let env = GatewayEnvelope {
            op: opcode::DISPATCH,
            s: None,
            t: Some("READY".to_string()),
        };
        match classify_envelope(&env) {
            GatewayAction::DispatchEvent { seq, .. } => assert_eq!(seq, -1),
            other => panic!("expected DispatchEvent, got {other:?}"),
        }
    }
}
