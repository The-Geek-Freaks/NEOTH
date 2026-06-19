//! OH-02 — `neoth onboarding-status` subcommand.
//!
//! Loads `FreedomConfig` and renders a compact markdown snapshot covering:
//!   - provider/auth configured (yes/no)
//!   - which channels are enabled (Telegram, WhatsApp, …)
//!   - key autonomy flags
//!   - device tier (OH-04 `detect_device_profile` + `recommend_tier`)
//!   - overall `Ready: yes/no` with top reason when not ready
//!
//! The snapshot assembly is factored into a pure `render_status` function
//! so it can be unit-tested without touching the real filesystem.

use anyhow::Result;
use clap::Args;
use serde::Serialize;

use crate::cli::device_profile::{detect_device_profile, recommend_tier};
use crate::config::FreedomConfig;

// ---------------------------------------------------------------------------
// Args
// ---------------------------------------------------------------------------

/// GOLD-ADAPT-OH-02 — compact onboarding readiness snapshot.
#[derive(Args, Debug)]
pub struct OnboardingStatusArgs {
    /// Emit JSON instead of markdown.
    #[arg(long)]
    pub json: bool,
}

// ---------------------------------------------------------------------------
// Snapshot data model
// ---------------------------------------------------------------------------

/// Pure, filesystem-free representation of onboarding state.
/// Built from `FreedomConfig` + `DeviceProfile`; passed to `render_status`.
#[derive(Debug, Serialize)]
pub struct OnboardingSnapshot {
    pub operator_id: Option<String>,
    pub provider_configured: bool,
    pub provider_auth_present: bool,
    pub telegram_enabled: bool,
    pub whatsapp_enabled: bool,
    pub autonomy_level: String,
    pub review_gate_enabled: bool,
    /// Device tier label (from OH-04).
    pub device_tier: String,
    /// One-line rationale for the tier.
    pub device_tier_rationale: String,
    /// Total host RAM in GiB (rounded to 1 decimal).
    pub total_ram_gb: f64,
    pub cpu_cores: usize,
    pub gpu_detected: bool,
    pub ready: bool,
    /// Non-empty when `ready = false`; holds the top blocker reason.
    pub not_ready_reason: String,
}

impl OnboardingSnapshot {
    /// Build a snapshot from `FreedomConfig`.  Calls OH-04 for device data.
    pub fn from_config(cfg: &FreedomConfig) -> Self {
        // ── Provider ──────────────────────────────────────────────────────
        let provider_configured = cfg.provider_kind.is_some();
        // // neoth: `provider_key` is a SecretString; we can only check
        // // presence, not the actual value.  `provider_binary` covers
        // // claude-cli / local-binary paths that need no API key.
        let provider_auth_present = cfg.provider_key.is_some() || cfg.provider_binary.is_some();

        // ── Channels ──────────────────────────────────────────────────────
        let telegram_enabled = cfg.telegram_token.is_some();
        let whatsapp_enabled = cfg.whatsapp_webhook_port.is_some();

        // ── Autonomy ──────────────────────────────────────────────────────
        let autonomy_level = format!("{:?}", cfg.autonomy);

        // ── Device (OH-04 wiring) ─────────────────────────────────────────
        let profile = detect_device_profile();
        let tier = recommend_tier(profile.total_ram_gb, profile.gpu_present);
        let total_ram_gb = (profile.total_ram_gb * 10.0).round() / 10.0;

        // ── Readiness gate ────────────────────────────────────────────────
        let (ready, not_ready_reason) = if !provider_configured {
            (false, "No provider configured — run `neoth init`.".to_string())
        } else if !telegram_enabled && !whatsapp_enabled {
            (
                false,
                "No channel enabled — configure Telegram or WhatsApp via `neoth init`.".to_string(),
            )
        } else {
            (true, String::new())
        };

        Self {
            operator_id: cfg.operator_id.clone(),
            provider_configured,
            provider_auth_present,
            telegram_enabled,
            whatsapp_enabled,
            autonomy_level,
            review_gate_enabled: cfg.review_gate_enabled,
            device_tier: tier.as_str().to_string(),
            device_tier_rationale: tier.rationale().to_string(),
            total_ram_gb,
            cpu_cores: profile.cpu_cores,
            gpu_detected: profile.gpu_present,
            ready,
            not_ready_reason,
        }
    }
}

// ---------------------------------------------------------------------------
// Pure renderer (unit-testable, no I/O)
// ---------------------------------------------------------------------------

/// Render `snapshot` as a compact markdown string (or JSON via `--json`).
///
/// Extracted as a pure function so tests can verify output without touching
/// the filesystem.
pub fn render_status(snapshot: &OnboardingSnapshot) -> String {
    let ready_str = if snapshot.ready { "yes" } else { "no" };
    let provider_str = if snapshot.provider_configured {
        "yes"
    } else {
        "no"
    };
    let auth_str = if snapshot.provider_auth_present {
        "yes"
    } else {
        "no (no API key or binary path set)"
    };

    let mut channels: Vec<&str> = Vec::new();
    if snapshot.telegram_enabled {
        channels.push("Telegram");
    }
    if snapshot.whatsapp_enabled {
        channels.push("WhatsApp");
    }
    let channels_str = if channels.is_empty() {
        "none".to_string()
    } else {
        channels.join(", ")
    };

    let operator_str = snapshot
        .operator_id
        .as_deref()
        .unwrap_or("(not set)");

    let mut out = format!(
        "## NEOTH Onboarding Status\n\
         \n\
         | Field | Value |\n\
         |---|---|\n\
         | Operator | {operator_str} |\n\
         | Provider configured | {provider_str} |\n\
         | Provider auth present | {auth_str} |\n\
         | Channels enabled | {channels_str} |\n\
         | Autonomy level | {autonomy} |\n\
         | Review gate | {review_gate} |\n\
         \n\
         ### Device\n\
         \n\
         | Field | Value |\n\
         |---|---|\n\
         | RAM | {ram:.1} GB |\n\
         | CPU cores | {cores} |\n\
         | GPU detected | {gpu} |\n\
         | AI tier | {tier} |\n\
         | Tier rationale | {rationale} |\n\
         \n\
         **Ready: {ready}**\n",
        operator_str = operator_str,
        provider_str = provider_str,
        auth_str = auth_str,
        channels_str = channels_str,
        autonomy = snapshot.autonomy_level,
        review_gate = if snapshot.review_gate_enabled { "enabled" } else { "disabled" },
        ram = snapshot.total_ram_gb,
        cores = snapshot.cpu_cores,
        gpu = if snapshot.gpu_detected { "yes" } else { "no" },
        tier = snapshot.device_tier,
        rationale = snapshot.device_tier_rationale,
        ready = ready_str,
    );

    if !snapshot.not_ready_reason.is_empty() {
        out.push_str(&format!(
            "\n> **Blocker:** {}\n",
            snapshot.not_ready_reason
        ));
    }

    out
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Entry point called from the `Commands` dispatch match.
pub async fn run_onboarding_status(args: OnboardingStatusArgs) -> Result<()> {
    let cfg = FreedomConfig::load_from_default_path()?;
    let snapshot = OnboardingSnapshot::from_config(&cfg);

    if args.json {
        let json = serde_json::to_string_pretty(&snapshot)
            .unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"));
        println!("{json}");
    } else {
        print!("{}", render_status(&snapshot));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn fully_configured_snapshot() -> OnboardingSnapshot {
        OnboardingSnapshot {
            operator_id: Some("alice".to_string()),
            provider_configured: true,
            provider_auth_present: true,
            telegram_enabled: true,
            whatsapp_enabled: false,
            autonomy_level: "Standard".to_string(),
            review_gate_enabled: false,
            device_tier: "local-capable".to_string(),
            device_tier_rationale: "RAM ≥16 GB or GPU detected.".to_string(),
            total_ram_gb: 32.0,
            cpu_cores: 16,
            gpu_detected: true,
            ready: true,
            not_ready_reason: String::new(),
        }
    }

    fn no_channel_snapshot() -> OnboardingSnapshot {
        OnboardingSnapshot {
            operator_id: None,
            provider_configured: true,
            provider_auth_present: true,
            telegram_enabled: false,
            whatsapp_enabled: false,
            autonomy_level: "Standard".to_string(),
            review_gate_enabled: false,
            device_tier: "cloud-first".to_string(),
            device_tier_rationale: "RAM <8 GB.".to_string(),
            total_ram_gb: 4.0,
            cpu_cores: 4,
            gpu_detected: false,
            ready: false,
            not_ready_reason: "No channel enabled — configure Telegram or WhatsApp via `neoth init`."
                .to_string(),
        }
    }

    fn no_provider_snapshot() -> OnboardingSnapshot {
        OnboardingSnapshot {
            operator_id: None,
            provider_configured: false,
            provider_auth_present: false,
            telegram_enabled: true,
            whatsapp_enabled: false,
            autonomy_level: "Standard".to_string(),
            review_gate_enabled: false,
            device_tier: "hybrid".to_string(),
            device_tier_rationale: "RAM 8–15 GB.".to_string(),
            total_ram_gb: 12.0,
            cpu_cores: 8,
            gpu_detected: false,
            ready: false,
            not_ready_reason: "No provider configured — run `neoth init`.".to_string(),
        }
    }

    #[test]
    fn render_fully_configured_contains_ready_yes() {
        let out = render_status(&fully_configured_snapshot());
        assert!(
            out.contains("**Ready: yes**"),
            "expected 'Ready: yes' in:\n{out}"
        );
        assert!(!out.contains("Blocker:"), "unexpected blocker in:\n{out}");
    }

    #[test]
    fn render_no_channel_shows_ready_no_and_blocker() {
        let out = render_status(&no_channel_snapshot());
        assert!(
            out.contains("**Ready: no**"),
            "expected 'Ready: no' in:\n{out}"
        );
        assert!(
            out.contains("Blocker:"),
            "expected blocker line in:\n{out}"
        );
        assert!(
            out.contains("channel"),
            "expected channel mention in blocker:\n{out}"
        );
    }

    #[test]
    fn render_no_provider_shows_ready_no_and_provider_blocker() {
        let out = render_status(&no_provider_snapshot());
        assert!(out.contains("**Ready: no**"));
        assert!(out.contains("provider"));
    }

    #[test]
    fn render_shows_device_tier() {
        let out = render_status(&fully_configured_snapshot());
        assert!(out.contains("local-capable"), "missing tier in:\n{out}");
        assert!(out.contains("32.0 GB"), "missing RAM in:\n{out}");
    }

    #[test]
    fn render_channels_none_when_both_disabled() {
        let out = render_status(&no_channel_snapshot());
        assert!(out.contains("none"), "expected 'none' for channels:\n{out}");
    }

    #[test]
    fn render_channels_telegram_when_enabled() {
        let out = render_status(&fully_configured_snapshot());
        assert!(
            out.contains("Telegram"),
            "expected Telegram in channels:\n{out}"
        );
    }
}
