//! Cluster Phase 5 — Hysteria transport scaffolding.
//!
//! Architect verdict (Session 21): the relay is a separate binary,
//! TLS via **Hysteria** (a QUIC-based UDP obfuscation transport)
//! is the production hardening path for restricted networks. This
//! module ships the **config types + bind contract** the v1 wire
//! will need; the actual `hysteria` daemon plumbing is multi-week
//! and runs as a sibling process (per the architect's "do not fork
//! Hysteria" verdict).
//!
//! v0.1 deployment shape:
//!   1. Operator runs `hysteria server -c hysteria.yaml` on the
//!      same host as `neoth-relay`.
//!   2. Hysteria listens on the public UDP port (e.g. 443/udp)
//!      and forwards plain TCP to `neoth-relay`'s loopback bind
//!      (`127.0.0.1:8443` by default).
//!   3. `neoth-relay --bind 127.0.0.1:8443` sees a normal TCP
//!      connection; Hysteria handles the QUIC + auth + obfuscation
//!      on the public side.
//!
//! The `HysteriaTransportConfig` here is **metadata only** in v0.1
//! — the relay daemon reads it for status / doctor output so
//! operators can verify their Hysteria sidecar is configured
//! correctly. v2 (post-O-7 Hysteria-embedded build) flips
//! `connect_via_hysteria` from `bail` to a real implementation.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

/// Operator-supplied Hysteria sidecar config metadata. v1 reads
/// this for status surfaces only — the actual QUIC socket is
/// owned by the operator's standalone `hysteria` daemon.
///
/// Wire shape mirrors Hysteria's own YAML so operators can copy-
/// paste between the two configs (e.g. `listen`, `auth.type`).
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct HysteriaTransportConfig {
    /// Public-facing Hysteria listen address (e.g. `:443`). Empty
    /// = operator hasn't configured a Hysteria sidecar; the relay
    /// runs in plain-TCP mode behind whatever bind it picked.
    pub listen: String,
    /// Loopback target the Hysteria sidecar forwards plain TCP to.
    /// Defaults to `127.0.0.1:8443` (matches the relay's default
    /// `--bind`). Operators changing the relay's bind via
    /// `neoth-relay serve --bind 127.0.0.1:9000` MUST update this
    /// too — there's no auto-discovery between the two daemons.
    pub forward_to: String,
    /// Auth scheme name (`password` / `userpass` / `none`). The
    /// actual credential lives in `hysteria.yaml` (the sidecar's
    /// own config); we surface only the scheme name here for
    /// `neoth doctor` to verify the operator picked something
    /// stronger than `none`.
    pub auth_scheme: String,
    /// Operator-readable note about the deployment (e.g. "Tailscale
    /// peer-only" / "public Cloudflare WARP+"). Free-form, surfaces
    /// in status output for human inspection.
    pub note: String,
}

impl HysteriaTransportConfig {
    /// True ⇔ operator has configured a Hysteria sidecar. Used by
    /// the `neoth-relay status` command + the future `neoth doctor
    /// cluster relay` check to surface "running plain TCP" vs
    /// "behind Hysteria sidecar".
    pub fn is_configured(&self) -> bool {
        !self.listen.trim().is_empty()
    }

    /// Operator-facing one-line summary of the configured deployment.
    /// Returns a stable string the relay's `status` command prints.
    pub fn summary(&self) -> String {
        if !self.is_configured() {
            return "plain TCP (no Hysteria sidecar configured)".to_string();
        }
        format!(
            "Hysteria sidecar: listen={} → forward_to={} auth_scheme={}{}",
            if self.listen.is_empty() { "(unset)" } else { &self.listen },
            if self.forward_to.is_empty() {
                "(unset)"
            } else {
                &self.forward_to
            },
            if self.auth_scheme.is_empty() {
                "(unset)"
            } else {
                &self.auth_scheme
            },
            if self.note.is_empty() {
                String::new()
            } else {
                format!(" -- {}", self.note)
            },
        )
    }

    /// Defensive validation — flags the operator-painful misconfigs
    /// `neoth doctor` should surface before the relay daemon is
    /// even told to start.
    ///
    /// Returns `Vec<String>` of human-readable warnings; empty
    /// means the config looks plausible (or is fully empty —
    /// plain-TCP mode). Caller decides whether to halt on warnings
    /// or just log them.
    pub fn validate(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        if !self.is_configured() {
            return warnings;
        }
        if self.forward_to.trim().is_empty() {
            warnings.push(
                "Hysteria listen set but forward_to is empty — operator must \
                 explicitly point the sidecar at the relay's loopback bind \
                 (default `127.0.0.1:8443`)"
                    .to_string(),
            );
        }
        if self.auth_scheme.trim().is_empty() {
            warnings.push(
                "Hysteria auth_scheme is empty — operator should set \
                 `password` or `userpass` to prevent unauthenticated peer \
                 registration via the public listener"
                    .to_string(),
            );
        }
        if self.auth_scheme.eq_ignore_ascii_case("none") {
            warnings.push(
                "Hysteria auth_scheme is `none` — every device that can \
                 reach the public listener can register peers. Strongly \
                 recommend `password` or `userpass`."
                    .to_string(),
            );
        }
        warnings
    }
}

/// v1 stub for the future Hysteria-embedded build (post-O-7). The
/// architect verdict pinned that v1 ships the relay binary
/// alongside a standalone Hysteria daemon (operator owns both
/// processes); future work may embed Hysteria as a Rust library
/// (`quinn` + the `hysteria-rs` crate) so a single binary handles
/// both sides.
///
/// Returns `Err` in v1 — the bind contract is documented but the
/// QUIC socket is the operator's standalone `hysteria` daemon's
/// responsibility. Callers (the relay's serve loop) get the
/// "deferred" message so a misconfigured operator who points
/// `--bind` at a Hysteria URL gets a clear error instead of a
/// silent fall-through.
pub fn connect_via_hysteria(_cfg: &HysteriaTransportConfig) -> Result<()> {
    Err(anyhow!(
        "Hysteria-embedded transport deferred to post-O-7 work. \
         v1 deployment: run `hysteria server` alongside this binary + \
         point its `forward_to` at the relay's loopback bind (default \
         127.0.0.1:8443)."
    ))
}

// ── HW-1..HW-4 — Hysteria wizard screen scaffolding ──────────────
//
// The Cluster Phase 5 scaffolding above (HysteriaTransportConfig +
// validate + connect stub) ships the operator-tweakable knob; the
// HW-* items wrap that knob in the WIZARD-FACING UX layer the
// future Slint screens consume. Pure data + helpers so both the
// CLI wizard step + the Slint screen render identical text.

/// HW-1 — operator-facing "Why tunnel?" copy. One paragraph, three
/// concrete threats, decline-friendly framing. Slint pulls this
/// verbatim so a copy edit lands in one place.
pub const WHY_TUNNEL_COPY: &str =
    "A Hysteria tunnel hides which servers NEOTH talks to and \
     when from anyone watching the network between you and the \
     relay. Three concrete cases it defends against: (1) a coffee-\
     shop network operator profiling your cluster pairings; (2) \
     an ISP throttling or fingerprinting your peer traffic; (3) a \
     state actor blocking direct connections to your relay host. \
     If none of those apply to you, decline this step — your \
     channels and cluster still work bareback, just less private.";

/// HW-2 — the two onboarding paths + the always-available decline.
/// `Skip` returns no Hysteria config (relay runs plain TCP); the
/// other two land at the same `HysteriaTransportConfig` shape but
/// the wizard collects different inputs from the operator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HysteriaOnboardingPath {
    /// Self-host one-click setup. Wizard asks for VPS address plus
    /// bearer token, runs ACME (via the standalone `hysteria` daemon)
    /// for TLS, writes a sane default Hysteria config. Multi-day
    /// implementation — VPS provisioning + ACME + config write all
    /// defer to a focused session.
    SelfHost,
    /// Paste existing config. Operator already runs Hysteria
    /// elsewhere; wizard just records the `forward_to` + auth scheme
    /// so `neoth doctor cluster relay` surfaces the deployment
    /// correctly.
    BringExisting,
    /// Decline gracefully. Relay stays plain-TCP behind `--bind`.
    /// Channels + cluster still work; just no QUIC obfuscation.
    Skip,
}

impl HysteriaOnboardingPath {
    /// Stable string for the wizard log + freedom.yaml round-trip
    /// (operator may flip later via `neoth init --force`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SelfHost => "self_host",
            Self::BringExisting => "bring_existing",
            Self::Skip => "skip",
        }
    }

    /// One-line operator-facing description shown in the wizard
    /// path-picker (HW-2 screen).
    pub fn description(self) -> &'static str {
        match self {
            Self::SelfHost => {
                "Set up a new Hysteria server on a VPS I control (asks for \
                 VPS address + bearer token; runs ACME for TLS)"
            }
            Self::BringExisting => {
                "I already run Hysteria; let me paste my forward-to + auth \
                 scheme so the relay records it correctly"
            }
            Self::Skip => {
                "Skip Hysteria for now — relay runs plain TCP behind --bind"
            }
        }
    }
}

/// HW-3 — health-check helper. Pings the local SOCKS5 listener
/// (when the operator picked SelfHost or BringExisting) by
/// attempting a TCP connect to `forward_to` with a short timeout.
/// Reports specific failure modes so the wizard surfaces an
/// actionable hint ("Hysteria sidecar isn't running" vs "wrong
/// forward_to address" vs "TLS / auth handshake refused").
///
/// v1 ships the SHAPE of the check — actual SOCKS5 protocol
/// handshake defers to the multi-day Hysteria-embedded work.
/// Today the check is a plain TCP-connect probe; that's enough
/// to catch the typical "operator misconfigured forward_to"
/// failure mode.
pub async fn check_hysteria_listener(cfg: &HysteriaTransportConfig) -> HealthCheckOutcome {
    use std::time::Duration;
    use tokio::net::TcpStream;

    if !cfg.is_configured() {
        return HealthCheckOutcome::NotConfigured;
    }
    if cfg.forward_to.trim().is_empty() {
        return HealthCheckOutcome::MissingForwardTo;
    }
    let addr = cfg.forward_to.trim();
    let timeout = Duration::from_secs(3);
    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(_)) => HealthCheckOutcome::Ok,
        Ok(Err(e)) => HealthCheckOutcome::ConnectionRefused(e.to_string()),
        Err(_) => HealthCheckOutcome::Timeout,
    }
}

/// Outcome of [`check_hysteria_listener`]. Operator-visible — the
/// wizard renders one of these as the green/yellow/red status
/// before allowing the operator to continue past the screen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HealthCheckOutcome {
    /// Listener accepted the TCP connect — sidecar is up.
    Ok,
    /// Operator picked `Skip`; nothing to check.
    NotConfigured,
    /// `listen` is set but `forward_to` is empty — wizard caught
    /// this before the operator hit Continue.
    MissingForwardTo,
    /// Connect refused (sidecar down, wrong port, firewall).
    /// Carries the raw error for the wizard's "show details" panel.
    ConnectionRefused(String),
    /// Connect didn't complete inside the 3s window — likely
    /// network reach issue or Hysteria mid-handshake.
    Timeout,
}

impl HealthCheckOutcome {
    /// True ⇔ wizard can proceed without warning the operator.
    /// `NotConfigured` passes (operator explicitly chose Skip).
    pub fn is_passable(&self) -> bool {
        matches!(self, Self::Ok | Self::NotConfigured)
    }

    /// Operator-readable summary for the wizard's status line.
    pub fn summary(&self) -> String {
        match self {
            Self::Ok => "Hysteria sidecar reachable on forward_to".to_string(),
            Self::NotConfigured => "Hysteria skipped (plain TCP mode)".to_string(),
            Self::MissingForwardTo => {
                "forward_to is empty — point it at the relay's loopback bind".to_string()
            }
            Self::ConnectionRefused(reason) => {
                format!("Hysteria forward_to refused TCP connect: {reason}")
            }
            Self::Timeout => {
                "Hysteria forward_to didn't respond inside 3s (sidecar down? wrong port?)".to_string()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_fixture() -> HysteriaTransportConfig {
        HysteriaTransportConfig {
            listen: ":443".into(),
            forward_to: "127.0.0.1:8443".into(),
            auth_scheme: "password".into(),
            note: "Cloudflare WARP+ public listener".into(),
        }
    }

    #[test]
    fn default_is_plain_tcp_mode() {
        let cfg = HysteriaTransportConfig::default();
        assert!(!cfg.is_configured());
        assert!(cfg.summary().contains("plain TCP"));
    }

    #[test]
    fn is_configured_reads_listen_field() {
        let cfg_set = HysteriaTransportConfig {
            listen: ":443".into(),
            ..Default::default()
        };
        assert!(cfg_set.is_configured());
        let cfg_blank = HysteriaTransportConfig {
            listen: "   ".into(),
            ..Default::default()
        };
        assert!(
            !cfg_blank.is_configured(),
            "whitespace-only listen = unconfigured"
        );
    }

    #[test]
    fn summary_renders_full_deployment_string() {
        let s = full_fixture().summary();
        assert!(s.contains("Hysteria sidecar"));
        assert!(s.contains(":443"));
        assert!(s.contains("127.0.0.1:8443"));
        assert!(s.contains("password"));
        assert!(s.contains("Cloudflare WARP+"));
    }

    #[test]
    fn summary_handles_partial_config_with_unset_markers() {
        let cfg = HysteriaTransportConfig {
            listen: ":443".into(),
            forward_to: String::new(),
            auth_scheme: String::new(),
            note: String::new(),
        };
        let s = cfg.summary();
        assert!(s.contains(":443"));
        assert!(s.contains("forward_to=(unset)"));
        assert!(s.contains("auth_scheme=(unset)"));
    }

    #[test]
    fn validate_empty_config_returns_no_warnings() {
        let cfg = HysteriaTransportConfig::default();
        assert!(cfg.validate().is_empty());
    }

    #[test]
    fn validate_full_config_returns_no_warnings() {
        let cfg = full_fixture();
        assert!(cfg.validate().is_empty());
    }

    #[test]
    fn validate_warns_on_missing_forward_to() {
        let cfg = HysteriaTransportConfig {
            listen: ":443".into(),
            forward_to: String::new(),
            auth_scheme: "password".into(),
            note: String::new(),
        };
        let warnings = cfg.validate();
        assert!(warnings.iter().any(|w| w.contains("forward_to")));
    }

    #[test]
    fn validate_warns_on_empty_auth_scheme() {
        let cfg = HysteriaTransportConfig {
            listen: ":443".into(),
            forward_to: "127.0.0.1:8443".into(),
            auth_scheme: String::new(),
            note: String::new(),
        };
        let warnings = cfg.validate();
        assert!(warnings.iter().any(|w| w.contains("auth_scheme is empty")));
    }

    #[test]
    fn validate_warns_on_none_auth_scheme() {
        let cfg = HysteriaTransportConfig {
            listen: ":443".into(),
            forward_to: "127.0.0.1:8443".into(),
            auth_scheme: "none".into(),
            note: String::new(),
        };
        let warnings = cfg.validate();
        assert!(warnings.iter().any(|w| w.contains("`none`")));
        // Case-insensitive — `NONE` also surfaces the warning.
        let cfg_upper = HysteriaTransportConfig {
            auth_scheme: "NONE".into(),
            ..cfg
        };
        assert!(cfg_upper.validate().iter().any(|w| w.contains("`none`")));
    }

    #[test]
    fn connect_via_hysteria_bails_in_v1_with_actionable_message() {
        let cfg = full_fixture();
        let err = connect_via_hysteria(&cfg).unwrap_err();
        let msg = err.to_string();
        // Operator must see WHERE to look for the v1 deployment story.
        assert!(msg.contains("deferred") || msg.contains("v1 deployment"));
        assert!(msg.contains("hysteria server") || msg.contains("127.0.0.1:8443"));
    }

    #[test]
    fn serde_round_trip_via_yaml() {
        let original = full_fixture();
        let yaml = serde_yaml::to_string(&original).unwrap();
        let back: HysteriaTransportConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(original, back);
    }

    #[test]
    fn serde_omits_absent_fields_when_using_defaults() {
        let empty = HysteriaTransportConfig::default();
        let yaml = serde_yaml::to_string(&empty).unwrap();
        let back: HysteriaTransportConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(empty, back);
    }

    // ── HW-1..HW-4 wizard scaffolding tests ─────────────────────

    #[test]
    fn hw1_why_tunnel_copy_mentions_three_concrete_threats() {
        // Pin the operator-facing copy mentions specific defenses
        // (coffee-shop / ISP / state) so a copy-edit doesn't
        // silently drop one of the three concrete cases.
        let c = WHY_TUNNEL_COPY.to_lowercase();
        assert!(c.contains("coffee-shop"));
        assert!(c.contains("isp"));
        assert!(c.contains("state"));
        // Decline-friendly framing.
        assert!(c.contains("decline"));
    }

    #[test]
    fn hw2_onboarding_path_wire_form_pinned() {
        assert_eq!(HysteriaOnboardingPath::SelfHost.as_str(), "self_host");
        assert_eq!(HysteriaOnboardingPath::BringExisting.as_str(), "bring_existing");
        assert_eq!(HysteriaOnboardingPath::Skip.as_str(), "skip");
    }

    #[test]
    fn hw2_descriptions_distinct_per_path() {
        let a = HysteriaOnboardingPath::SelfHost.description();
        let b = HysteriaOnboardingPath::BringExisting.description();
        let c = HysteriaOnboardingPath::Skip.description();
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }

    #[tokio::test]
    async fn hw3_health_check_returns_not_configured_for_empty_config() {
        let cfg = HysteriaTransportConfig::default();
        let outcome = check_hysteria_listener(&cfg).await;
        assert_eq!(outcome, HealthCheckOutcome::NotConfigured);
        assert!(outcome.is_passable(), "decline path must allow continue");
    }

    #[tokio::test]
    async fn hw3_health_check_flags_missing_forward_to() {
        let cfg = HysteriaTransportConfig {
            listen: ":443".into(),
            forward_to: "".into(),
            auth_scheme: "password".into(),
            note: String::new(),
        };
        let outcome = check_hysteria_listener(&cfg).await;
        assert_eq!(outcome, HealthCheckOutcome::MissingForwardTo);
        assert!(!outcome.is_passable());
    }

    #[tokio::test]
    async fn hw3_health_check_refused_on_dead_loopback_port() {
        // Loopback :1 is the lowest port number; reserved by IANA
        // and never bound by user processes → TCP-connect refuses
        // immediately. Cross-platform deterministic for the
        // ConnectionRefused branch test.
        let cfg = HysteriaTransportConfig {
            listen: ":443".into(),
            forward_to: "127.0.0.1:1".into(),
            auth_scheme: "password".into(),
            note: String::new(),
        };
        let outcome = check_hysteria_listener(&cfg).await;
        assert!(
            matches!(
                outcome,
                HealthCheckOutcome::ConnectionRefused(_) | HealthCheckOutcome::Timeout
            ),
            "dead loopback port must surface as Refused or Timeout, got {outcome:?}"
        );
    }

    #[tokio::test]
    async fn hw3_health_check_succeeds_on_live_loopback_listener() {
        // Bind a real TCP listener on an ephemeral port + check.
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg = HysteriaTransportConfig {
            listen: ":443".into(),
            forward_to: addr.to_string(),
            auth_scheme: "password".into(),
            note: String::new(),
        };
        let outcome = check_hysteria_listener(&cfg).await;
        assert_eq!(outcome, HealthCheckOutcome::Ok);
        assert!(outcome.is_passable());
    }

    #[test]
    fn health_check_outcome_summary_renders_each_variant() {
        for outcome in [
            HealthCheckOutcome::Ok,
            HealthCheckOutcome::NotConfigured,
            HealthCheckOutcome::MissingForwardTo,
            HealthCheckOutcome::ConnectionRefused("refused".into()),
            HealthCheckOutcome::Timeout,
        ] {
            let s = outcome.summary();
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn hw4_skip_path_is_always_passable() {
        // Operator who picks Skip MUST be able to continue the
        // wizard regardless — the relay falls back to plain TCP.
        assert!(HealthCheckOutcome::NotConfigured.is_passable());
    }
}
