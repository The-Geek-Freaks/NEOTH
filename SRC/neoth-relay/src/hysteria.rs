//! External-Hysteria deployment contract for `neoth-relay`.
//!
//! Hysteria is intentionally a separate, operator-managed process. NEOTH does
//! not embed, fork, download, provision, or supervise it. The production
//! boundary is:
//!
//!   1. Operator runs `hysteria server -c hysteria.yaml` on the
//!      same host as `neoth-relay`.
//!   2. Hysteria listens on the public UDP port (e.g. 443/udp)
//!      and forwards plain TCP to `neoth-relay`'s loopback bind
//!      (`127.0.0.1:8443` by default).
//!   3. `neoth-relay --bind 127.0.0.1:8443` sees a normal TCP
//!      connection; Hysteria handles the QUIC + auth + obfuscation
//!      on the public side.
//!
//! [`HysteriaTransportConfig`] records that boundary. `serve` validates the
//! configured `forward_to` against its actual loopback bind before accepting
//! traffic. `status` and `doctor` probe the relay-side TCP target. They cannot
//! prove that the sidecar's public QUIC listener or authentication works; that
//! must be checked with Hysteria's own tooling.

use std::net::SocketAddr;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// Operator-supplied Hysteria sidecar deployment contract. The actual QUIC
/// socket and credentials are owned by the standalone `hysteria` daemon.
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
    /// `neoth-relay doctor` to verify the operator declared something
    /// stronger than `none`.
    pub auth_scheme: String,
    /// Operator-readable note about the deployment (e.g. "Tailscale
    /// peer-only" / "public Cloudflare WARP+"). Free-form, surfaces
    /// in status output for human inspection.
    pub note: String,
}

impl HysteriaTransportConfig {
    /// True ⇔ operator has configured a Hysteria sidecar. Used by
    /// `neoth-relay status` and `doctor` use this to distinguish direct TCP
    /// from an explicitly configured external sidecar.
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
            if self.listen.is_empty() {
                "(unset)"
            } else {
                &self.listen
            },
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

    /// Validate the external-sidecar boundary against the address this relay
    /// will actually bind. Supplying `--hysteria-config` is an explicit request
    /// for sidecar mode, so every mismatch is fatal rather than a warning.
    pub fn validate_for_relay_bind(&self, relay_bind: SocketAddr) -> Result<()> {
        if !self.is_configured() {
            bail!(
                "Hysteria config was supplied but `listen` is empty; remove \
                 --hysteria-config for direct TCP mode or declare the external \
                 sidecar's public listen address"
            );
        }

        if let Some(warning) = self.validate().into_iter().next() {
            bail!("invalid Hysteria sidecar contract: {warning}");
        }

        let forward_to: SocketAddr =
            self.forward_to.trim().parse().with_context(|| {
                format!("parse Hysteria forward_to `{}`", self.forward_to.trim())
            })?;

        if !relay_bind.ip().is_loopback() {
            bail!(
                "Hysteria sidecar mode requires a loopback relay bind; got {relay_bind}. \
                 Bind neoth-relay to 127.0.0.1 (or ::1) and expose only the \
                 sidecar's authenticated QUIC listener"
            );
        }
        if !forward_to.ip().is_loopback() {
            bail!(
                "Hysteria forward_to must be loopback in sidecar mode; got {forward_to}. \
                 A non-loopback plaintext hop bypasses the intended transport boundary"
            );
        }
        if forward_to != relay_bind {
            bail!(
                "Hysteria forward_to {forward_to} does not match neoth-relay --bind \
                 {relay_bind}; the sidecar would forward to a different service"
            );
        }
        Ok(())
    }
}

// ── Hysteria operator guidance ────────────────────────────────────

/// Operator-facing "Why tunnel?" copy. One paragraph, three concrete threats,
/// and the exact scope of what the sidecar protects.
pub const WHY_TUNNEL_COPY: &str = "A Hysteria sidecar protects the connection to your NEOTH \
     relay; it does not tunnel unrelated provider or channel traffic. \
     Three concrete cases it helps with: (1) a coffee-shop network \
     operator profiling relay connections; (2) an ISP throttling or \
     fingerprinting relay traffic; (3) a state actor blocking direct \
     connections to your relay host. If none apply, use direct TCP on \
     a private network. Never expose an unauthenticated relay publicly.";

/// The two sidecar onboarding paths plus the direct-TCP option.
/// `Skip` returns no Hysteria config (relay runs plain TCP); the
/// other two land at the same [`HysteriaTransportConfig`] shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HysteriaOnboardingPath {
    /// Deploy a new standalone sidecar. NEOTH prints the required bind and
    /// forward contract; the operator provisions the host, certificate,
    /// credentials, and Hysteria config with Hysteria's own tooling.
    SelfHost,
    /// Record an existing external sidecar's public listener, loopback relay
    /// target, and declared auth scheme for validation and diagnostics.
    BringExisting,
    /// Run the relay directly. This is appropriate only on loopback or a
    /// trusted private network; a public bind still requires relay bearer auth.
    Skip,
}

impl HysteriaOnboardingPath {
    /// Stable identifier printed by `neoth-relay doctor`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SelfHost => "self_host",
            Self::BringExisting => "bring_existing",
            Self::Skip => "skip",
        }
    }

    /// One-line operator-facing deployment description.
    pub fn description(self) -> &'static str {
        match self {
            Self::SelfHost => {
                "Deploy a standalone Hysteria sidecar; NEOTH validates its \
                 loopback forward target but does not provision VPS/TLS/config"
            }
            Self::BringExisting => {
                "Record an existing Hysteria sidecar's listener, loopback \
                 forward target, and declared auth scheme"
            }
            Self::Skip => {
                "Use direct TCP on loopback/private networking; public binds require bearer auth"
            }
        }
    }
}

/// Probe the plaintext relay target that the external Hysteria sidecar forwards
/// to. Success proves only that `neoth-relay` is accepting TCP at `forward_to`;
/// it does not probe the sidecar's public QUIC listener, TLS, or authentication.
pub async fn check_relay_forward_target(cfg: &HysteriaTransportConfig) -> HealthCheckOutcome {
    use std::time::Duration;
    use tokio::net::TcpStream;

    if !cfg.is_configured() {
        return HealthCheckOutcome::NotConfigured;
    }
    if cfg.forward_to.trim().is_empty() {
        return HealthCheckOutcome::MissingForwardTo;
    }
    let addr = match cfg.forward_to.trim().parse::<SocketAddr>() {
        Ok(addr) if addr.ip().is_loopback() => addr,
        Ok(addr) => {
            return HealthCheckOutcome::InvalidForwardTarget(format!(
                "{addr} is not a loopback address"
            ));
        }
        Err(error) => return HealthCheckOutcome::InvalidForwardTarget(error.to_string()),
    };
    let timeout = Duration::from_secs(3);
    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(_)) => HealthCheckOutcome::Ok,
        Ok(Err(e)) => HealthCheckOutcome::ConnectionRefused(e.to_string()),
        Err(_) => HealthCheckOutcome::Timeout,
    }
}

/// Outcome of [`check_relay_forward_target`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HealthCheckOutcome {
    /// The relay's loopback TCP listener accepted the connection.
    Ok,
    /// No external sidecar was configured; nothing to probe.
    NotConfigured,
    /// `listen` is set but `forward_to` is empty.
    MissingForwardTo,
    /// `forward_to` is not a loopback `SocketAddr`.
    InvalidForwardTarget(String),
    /// Connect refused (relay down or wrong target port).
    ConnectionRefused(String),
    /// Connect didn't complete inside the 3s window.
    Timeout,
}

impl HealthCheckOutcome {
    /// True when the configured relay target is reachable or sidecar mode was
    /// explicitly not configured.
    pub fn is_passable(&self) -> bool {
        matches!(self, Self::Ok | Self::NotConfigured)
    }

    /// Operator-readable diagnostic summary.
    pub fn summary(&self) -> String {
        match self {
            Self::Ok => {
                "relay forward target reachable (public Hysteria QUIC/auth not probed)".to_string()
            }
            Self::NotConfigured => "Hysteria skipped (plain TCP mode)".to_string(),
            Self::MissingForwardTo => {
                "forward_to is empty — point it at the relay's loopback bind".to_string()
            }
            Self::InvalidForwardTarget(reason) => {
                format!("invalid Hysteria forward_to: {reason}")
            }
            Self::ConnectionRefused(reason) => {
                format!("relay forward target refused TCP connect: {reason}")
            }
            Self::Timeout => {
                "relay forward target didn't respond inside 3s (relay down or wrong port?)"
                    .to_string()
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
    fn relay_bind_contract_accepts_exact_loopback_target() {
        full_fixture()
            .validate_for_relay_bind("127.0.0.1:8443".parse().unwrap())
            .unwrap();
    }

    #[test]
    fn relay_bind_contract_rejects_mismatch() {
        let error = full_fixture()
            .validate_for_relay_bind("127.0.0.1:9000".parse().unwrap())
            .unwrap_err()
            .to_string();
        assert!(error.contains("does not match"));
    }

    #[test]
    fn relay_bind_contract_rejects_public_plaintext_hop() {
        let mut cfg = full_fixture();
        cfg.forward_to = "192.0.2.10:8443".into();
        let error = cfg
            .validate_for_relay_bind("127.0.0.1:8443".parse().unwrap())
            .unwrap_err()
            .to_string();
        assert!(error.contains("must be loopback"));
    }

    #[test]
    fn relay_bind_contract_rejects_declared_no_auth() {
        let mut cfg = full_fixture();
        cfg.auth_scheme = "none".into();
        let error = cfg
            .validate_for_relay_bind("127.0.0.1:8443".parse().unwrap())
            .unwrap_err()
            .to_string();
        assert!(error.contains("auth_scheme"));
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

    // ── Operator guidance tests ──────────────────────────────────

    #[test]
    fn hw1_why_tunnel_copy_mentions_three_concrete_threats() {
        // Pin the operator-facing copy mentions specific defenses
        // (coffee-shop / ISP / state) so a copy-edit doesn't
        // silently drop one of the three concrete cases.
        let c = WHY_TUNNEL_COPY.to_lowercase();
        assert!(c.contains("coffee-shop"));
        assert!(c.contains("isp"));
        assert!(c.contains("state"));
        // Direct-mode boundary is explicit.
        assert!(c.contains("direct tcp"));
        assert!(c.contains("does not tunnel unrelated"));
    }

    #[test]
    fn hw2_onboarding_path_wire_form_pinned() {
        assert_eq!(HysteriaOnboardingPath::SelfHost.as_str(), "self_host");
        assert_eq!(
            HysteriaOnboardingPath::BringExisting.as_str(),
            "bring_existing"
        );
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
    async fn health_check_returns_not_configured_for_empty_config() {
        let cfg = HysteriaTransportConfig::default();
        let outcome = check_relay_forward_target(&cfg).await;
        assert_eq!(outcome, HealthCheckOutcome::NotConfigured);
        assert!(outcome.is_passable(), "decline path must allow continue");
    }

    #[tokio::test]
    async fn health_check_flags_missing_forward_to() {
        let cfg = HysteriaTransportConfig {
            listen: ":443".into(),
            forward_to: "".into(),
            auth_scheme: "password".into(),
            note: String::new(),
        };
        let outcome = check_relay_forward_target(&cfg).await;
        assert_eq!(outcome, HealthCheckOutcome::MissingForwardTo);
        assert!(!outcome.is_passable());
    }

    #[tokio::test]
    async fn health_check_rejects_non_loopback_target_without_dialing() {
        let cfg = HysteriaTransportConfig {
            listen: ":443".into(),
            forward_to: "192.0.2.10:8443".into(),
            auth_scheme: "password".into(),
            note: String::new(),
        };
        let outcome = check_relay_forward_target(&cfg).await;
        assert!(matches!(
            outcome,
            HealthCheckOutcome::InvalidForwardTarget(_)
        ));
    }

    #[tokio::test]
    async fn health_check_refused_on_dead_loopback_port() {
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
        let outcome = check_relay_forward_target(&cfg).await;
        assert!(
            matches!(
                outcome,
                HealthCheckOutcome::ConnectionRefused(_) | HealthCheckOutcome::Timeout
            ),
            "dead loopback port must surface as Refused or Timeout, got {outcome:?}"
        );
    }

    #[tokio::test]
    async fn health_check_succeeds_on_live_loopback_listener() {
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
        let outcome = check_relay_forward_target(&cfg).await;
        assert_eq!(outcome, HealthCheckOutcome::Ok);
        assert!(outcome.is_passable());
    }

    #[test]
    fn health_check_outcome_summary_renders_each_variant() {
        for outcome in [
            HealthCheckOutcome::Ok,
            HealthCheckOutcome::NotConfigured,
            HealthCheckOutcome::MissingForwardTo,
            HealthCheckOutcome::InvalidForwardTarget("not-loopback".into()),
            HealthCheckOutcome::ConnectionRefused("refused".into()),
            HealthCheckOutcome::Timeout,
        ] {
            let s = outcome.summary();
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn direct_tcp_path_is_passable_without_sidecar_config() {
        assert!(HealthCheckOutcome::NotConfigured.is_passable());
    }
}
