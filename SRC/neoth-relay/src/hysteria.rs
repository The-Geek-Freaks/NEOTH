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
}
