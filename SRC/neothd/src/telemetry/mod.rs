//! E-18 — `neoth telemetry on` opt-in anonymous version-check.
//!
//! v0.1 telemetry posture: **completely off by default**. Operator
//! must explicitly run `neoth telemetry on` to enable. When on,
//! NEOTH POSTs a minimal anonymised payload to the version-check
//! endpoint once per daemon boot:
//!
//! ```json
//! {
//!   "neoth_version": "0.1.0",
//!   "os": "linux",
//!   "arch": "x86_64",
//!   "anonymous_id": "<sha256 of operator-id, truncated to 16 hex>"
//! }
//! ```
//!
//! What's NOT sent:
//!   - Operator id verbatim (anonymous_id is sha256-prefixed).
//!   - Provider keys, chat content, memory tier sizes, WAL counts.
//!   - Configured channels / cluster peers / install paths.
//!   - Any IP-identifying header beyond what TLS reveals at
//!     connect-time (the daemon doesn't include extra headers).
//!
//! Workstream N (Session 22) closeout: this module now ships the
//! opt-in gate + payload builder AS WELL AS the real HTTPS POST
//! impl in `http.rs`. The CLI surface lives at `cli/telemetry.rs`
//! (`neoth telemetry on/off/preview/send-now/status`).

pub mod http;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Canonical telemetry endpoint URL. Pinned in a const so operators
/// auditing the source see exactly where their opt-in pings land.
/// Operators can override via `freedom.yaml::telemetry.endpoint`
/// when running a self-hosted relay (e.g. enterprise privacy
/// requirements pointing at an internal log sink).
pub const DEFAULT_TELEMETRY_ENDPOINT: &str = "https://telemetry.neoth.dev/v1/ping";

/// Operator's telemetry preference. Stored in
/// `freedom.yaml::telemetry`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TelemetryConfig {
    /// Default: false. Operator opts-in via `neoth telemetry on`.
    pub enabled: bool,
    /// Operator override for [`DEFAULT_TELEMETRY_ENDPOINT`]. `None`
    /// = use the canonical endpoint. Validated as HTTPS at send-time
    /// (HTTP is rejected) so a misconfigured endpoint can't
    /// silently downgrade an opt-in operator from TLS.
    #[serde(default)]
    pub endpoint: Option<String>,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        // E-18 hard requirement: telemetry OFF by default.
        Self {
            enabled: false,
            endpoint: None,
        }
    }
}

impl TelemetryConfig {
    /// Resolve the effective endpoint URL: operator override OR the
    /// canonical default. Caller passes the result to
    /// [`http::send_payload`].
    pub fn effective_endpoint(&self) -> &str {
        self.endpoint
            .as_deref()
            .unwrap_or(DEFAULT_TELEMETRY_ENDPOINT)
    }
}

/// Payload sent to the version-check endpoint. Operator-readable
/// via `neoth telemetry preview` so they can audit exactly what
/// goes on the wire BEFORE opting in.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TelemetryPayload {
    pub neoth_version: String,
    pub os: String,
    pub arch: String,
    pub anonymous_id: String,
}

/// Build the anonymous-id from the operator's id by SHA-256 then
/// truncating to the first 16 hex chars. 16 chars = 64 bits of
/// entropy — enough to distinguish daily-unique opt-in operators
/// without re-identifying anyone.
pub fn anonymous_id_from_operator(operator_id: &str) -> String {
    let digest = Sha256::digest(operator_id.as_bytes());
    let mut hex = String::with_capacity(16);
    for b in digest.iter().take(8) {
        hex.push_str(&format!("{b:02x}"));
    }
    hex
}

/// Build the payload. Caller wraps in JSON + POSTs to the
/// endpoint when [`should_send`] returns true.
pub fn build_payload(neoth_version: impl Into<String>, operator_id: &str) -> TelemetryPayload {
    TelemetryPayload {
        neoth_version: neoth_version.into(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        anonymous_id: anonymous_id_from_operator(operator_id),
    }
}

/// True ⇔ the operator has opted in. Pure gate the daemon's boot
/// path consults BEFORE constructing the payload.
pub fn should_send(config: &TelemetryConfig) -> bool {
    config.enabled
}

/// Operator-facing preview text. CLI surface (`neoth telemetry
/// preview`) prints this so the operator sees exactly what would
/// be sent. Honesty-first: every field is operator-readable, no
/// surprises after opt-in.
pub fn preview_for_operator(payload: &TelemetryPayload) -> String {
    format!(
        "If telemetry is enabled, NEOTH will POST once per daemon boot:\n\
         \n\
         neoth_version : {}\n\
         os            : {}\n\
         arch          : {}\n\
         anonymous_id  : {}\n\
         \n\
         Nothing else. No operator id verbatim. No provider keys. \
         No chat content. No memory contents. No cluster peers. \
         No install paths. Default is OFF — opt-in only via \
         `neoth telemetry on`.",
        payload.neoth_version, payload.os, payload.arch, payload.anonymous_id,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Default OFF ─────────────────────────────────────────────

    #[test]
    fn default_config_is_off() {
        // E-18 hard requirement — drift guard against accidentally
        // shipping with telemetry on by default.
        let c = TelemetryConfig::default();
        assert!(!c.enabled);
        assert!(!should_send(&c));
    }

    #[test]
    fn enabled_config_sends() {
        let c = TelemetryConfig {
            enabled: true,
            endpoint: None,
        };
        assert!(should_send(&c));
    }

    // ── Endpoint resolution ─────────────────────────────────────

    #[test]
    fn default_endpoint_is_pinned_https() {
        // Drift guard — if someone bumps the default to http://
        // operators downgrade silently from TLS.
        assert!(DEFAULT_TELEMETRY_ENDPOINT.starts_with("https://"));
        assert_eq!(
            DEFAULT_TELEMETRY_ENDPOINT,
            "https://telemetry.neoth.dev/v1/ping"
        );
    }

    #[test]
    fn effective_endpoint_falls_back_to_default_when_none() {
        let c = TelemetryConfig::default();
        assert_eq!(c.effective_endpoint(), DEFAULT_TELEMETRY_ENDPOINT);
    }

    #[test]
    fn effective_endpoint_honours_operator_override() {
        let c = TelemetryConfig {
            enabled: true,
            endpoint: Some("https://internal.example.com/log".to_string()),
        };
        assert_eq!(c.effective_endpoint(), "https://internal.example.com/log");
    }

    // ── anonymous_id_from_operator ──────────────────────────────

    #[test]
    fn anonymous_id_is_16_lowercase_hex() {
        let id = anonymous_id_from_operator("sam");
        assert_eq!(id.len(), 16);
        assert!(
            id.chars()
                .all(|c| c.is_ascii_hexdigit() && (c.is_ascii_digit() || c.is_ascii_lowercase()))
        );
    }

    #[test]
    fn anonymous_id_deterministic() {
        let a = anonymous_id_from_operator("sam");
        let b = anonymous_id_from_operator("sam");
        assert_eq!(a, b);
    }

    #[test]
    fn anonymous_id_differs_per_operator() {
        let a = anonymous_id_from_operator("sam");
        let b = anonymous_id_from_operator("bob");
        assert_ne!(a, b);
    }

    #[test]
    fn anonymous_id_does_not_leak_operator_string() {
        // Operator id "sam" must NOT appear anywhere in the
        // anonymous_id output. Pin so a future refactor that
        // accidentally returns the operator id verbatim surfaces.
        let id = anonymous_id_from_operator("sam");
        assert!(!id.contains("sam"));
    }

    // ── build_payload ───────────────────────────────────────────

    #[test]
    fn payload_carries_required_fields() {
        let p = build_payload("0.1.0", "sam");
        assert_eq!(p.neoth_version, "0.1.0");
        assert!(!p.os.is_empty());
        assert!(!p.arch.is_empty());
        assert_eq!(p.anonymous_id.len(), 16);
    }

    #[test]
    fn payload_serde_round_trips() {
        let p = build_payload("0.1.0", "sam");
        let s = serde_json::to_string(&p).unwrap();
        let back: TelemetryPayload = serde_json::from_str(&s).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn payload_has_no_operator_id_field() {
        // Drift guard — a future refactor that adds an
        // `operator_id` field would leak the unhashed id.
        let p = build_payload("0.1.0", "sam");
        let v: serde_json::Value = serde_json::to_value(&p).unwrap();
        assert!(v.get("operator_id").is_none());
        assert!(v.get("user_id").is_none());
        assert!(v.get("operator").is_none());
    }

    // ── preview_for_operator ────────────────────────────────────

    #[test]
    fn preview_mentions_every_payload_field() {
        let p = build_payload("0.1.0", "sam");
        let text = preview_for_operator(&p);
        assert!(text.contains("0.1.0"));
        assert!(text.contains(&p.os));
        assert!(text.contains(&p.arch));
        assert!(text.contains(&p.anonymous_id));
    }

    #[test]
    fn preview_explicitly_states_opt_in_default_off() {
        let p = build_payload("0.1.0", "sam");
        let text = preview_for_operator(&p).to_lowercase();
        assert!(text.contains("opt-in"));
        assert!(text.contains("off"));
    }

    #[test]
    fn preview_lists_what_is_not_sent() {
        let p = build_payload("0.1.0", "sam");
        let text = preview_for_operator(&p).to_lowercase();
        assert!(text.contains("no chat content"));
        assert!(text.contains("no provider keys"));
    }

    // ── TelemetryConfig serde ───────────────────────────────────

    #[test]
    fn telemetry_config_serde_round_trips() {
        let c = TelemetryConfig {
            enabled: true,
            endpoint: Some("https://example.com/x".into()),
        };
        let s = serde_yaml::to_string(&c).unwrap();
        let back: TelemetryConfig = serde_yaml::from_str(&s).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn telemetry_config_deserialises_legacy_without_endpoint() {
        // Operators on freedom.yaml that predates Workstream N have
        // only `telemetry: { enabled: false }` — the missing endpoint
        // field MUST round-trip as `None` instead of failing the
        // load.
        let yaml = "enabled: false\n";
        let c: TelemetryConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(!c.enabled);
        assert!(c.endpoint.is_none());
    }
}
