//! L-08 — `neoth privacy audit` CLI.
//!
//! Per `PLAN/QUELLEN_ADOPT_academic_2026-05-21.md` BATCH-5 + the
//! local-Qwen P2 audit (R2-P2-2). Reports the operator's privacy
//! posture in one place so they see — before sending a prompt —
//! whether the next chat will hit a cloud provider, whether profile
//! learning is active, whether channel adapters carry inbound
//! receive loops, and whether WAL frames carry redaction.
//!
//! Pure read-only: loads `~/.neoth/freedom.yaml` + `credentials.yaml`,
//! classifies provider kinds, reports findings. No network call,
//! no mutation.
//!
//! Output respects the global `--output` flag.

use std::path::Path;

use anyhow::{Context, Result};
use clap::Args;
use serde::Serialize;

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::config::credentials::Credentials;
use crate::wal::compress::decompress_frames;
use crate::wal::events::{
    EVENT_TYPE_CHANNEL_EGRESS, EVENT_TYPE_PROFILE_DELTA, EVENT_TYPE_PROFILE_REINFORCED,
    EVENT_TYPE_PROVIDER_REQUEST, EVENT_TYPE_PROVIDER_RESPONSE,
};
use crate::wal::frame::decode_frame;
use crate::wal::segment_header::parse_segment_header;

#[derive(Args, Debug, Clone)]
pub struct PrivacyArgs {
    /// Show sensitive WAL events in the last window — provider calls,
    /// channel egress, profile extractions — e.g. `--last 30d`, `7d`,
    /// `24h`, `1h`, `30m`. Omit for the config-posture-only view. This is
    /// the durable answer to "what actually left my device recently?".
    #[arg(long, value_name = "DURATION")]
    pub last: Option<String>,
    /// Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

/// One privacy finding the audit surfaces. `severity` = info | warn |
/// pii — operator-facing colour coding.
#[derive(Clone, Debug, Serialize)]
pub struct PrivacyFinding {
    pub category: &'static str,
    pub severity: &'static str,
    pub status: String,
    pub detail: String,
}

pub async fn run_privacy(args: PrivacyArgs) -> Result<()> {
    let cfg = FreedomConfig::load_from_default_path()
        .context("load freedom.yaml — run `neoth init` first")?;
    let cred_path = crate::config::credentials::default_path();
    // B17: classify the credential store. An invalid/unreadable store is a
    // critical privacy finding — audit_posture must not derive posture from
    // fabricated-empty creds, and the operator needs to know the file is bad.
    let mut cred_status = Credentials::credential_store_status(&cred_path);
    let creds = match cred_status {
        crate::config::credentials::CredentialStoreStatus::Ok
        | crate::config::credentials::CredentialStoreStatus::Missing => {
            // B17: a mid-command corruption race downgrades to Invalid so the
            // critical privacy finding below still fires (never a healthy view).
            match Credentials::load_or_default(&cred_path) {
                Ok(c) => c,
                Err(_) => {
                    cred_status = crate::config::credentials::CredentialStoreStatus::Invalid;
                    Credentials::default()
                }
            }
        }
        _ => Credentials::default(),
    };
    let mut findings = audit_posture(&cfg, &creds);
    // Inject a critical finding when the credential store is in a bad state.
    if !matches!(
        cred_status,
        crate::config::credentials::CredentialStoreStatus::Ok
            | crate::config::credentials::CredentialStoreStatus::Missing
    ) {
        findings.insert(
            0,
            PrivacyFinding {
                category: "credential-store",
                severity: "critical",
                status: cred_status.as_str().to_string(),
                detail: format!(
                    "{} exists but cannot be loaded ({}) — channel and provider posture \
                     below is derived from an empty store and may be inaccurate; \
                     repair the file or restore the keychain key",
                    cred_path.display(),
                    cred_status.as_str()
                ),
            },
        );
    }

    // `--last <window>`: scan the WAL for the sensitive events that
    // actually fired in the window (the static posture above says what
    // CAN happen; this says what DID). Best-effort: a WAL read issue
    // surfaces as an error on the window only, never blocks the posture.
    let window: Option<WalWindowSummary> = match args.last.as_deref() {
        Some(spec) => {
            let secs = parse_duration(spec)?;
            let home = FreedomConfig::default_neoth_home();
            Some(scan_sensitive_window(&home.join("wal"), secs))
        }
        None => None,
    };

    match args.output {
        OutputFormat::Json => {
            let obj = serde_json::json!({ "findings": findings, "window": window });
            println!("{}", serde_json::to_string_pretty(&obj)?);
        }
        OutputFormat::Jsonl => {
            for f in &findings {
                println!("{}", serde_json::to_string(f)?);
            }
            if let Some(w) = &window {
                println!("{}", serde_json::to_string(w)?);
            }
        }
        OutputFormat::Table => {
            println!("# `neoth privacy audit` — operator privacy posture\n");
            for f in &findings {
                println!("[{}] {}:", f.severity.to_uppercase(), f.category);
                println!("    {}", f.status);
                if !f.detail.is_empty() {
                    for line in f.detail.lines() {
                        println!("    {line}");
                    }
                }
                println!();
            }
            if let Some(w) = &window {
                render_window_table(w);
            }
            println!("Run `neoth glossary --term <name>` for any term above you don't recognise.");
        }
    }
    Ok(())
}

/// Sensitive events that actually fired in the `--last` window. Counts
/// only (the audit needs "how much left, and of what kind", not the
/// payloads); the frame header carries the event type + timestamp, so no
/// payload decode is needed.
#[derive(Clone, Debug, Default, Serialize)]
pub struct WalWindowSummary {
    pub window_secs: u64,
    pub frames_scanned: usize,
    /// Provider request/response frames (`0x20`/`0x21`) — cloud calls.
    pub provider_calls: usize,
    /// Channel egress frames (`0x33`) — messages NEOTH sent outbound.
    pub channel_egress: usize,
    /// Profile delta/reinforce frames (`0xB0`/`0xB1`) — memory writes.
    pub profile_extractions: usize,
}

/// Parse a duration spec like `30d` / `7d` / `24h` / `90m` / `45s` into
/// seconds. A bare number is treated as seconds. Rejects empty / unknown
/// suffixes loudly so a typo'd window can't silently scan nothing.
pub fn parse_duration(spec: &str) -> Result<u64> {
    let s = spec.trim();
    if s.is_empty() {
        anyhow::bail!("empty --last duration (try 30d / 7d / 24h / 30m)");
    }
    let (num, mult) = match s.chars().last().unwrap() {
        'd' | 'D' => (&s[..s.len() - 1], 86_400),
        'h' | 'H' => (&s[..s.len() - 1], 3_600),
        'm' | 'M' => (&s[..s.len() - 1], 60),
        's' | 'S' => (&s[..s.len() - 1], 1),
        c if c.is_ascii_digit() => (s, 1),
        other => anyhow::bail!(
            "unknown --last unit `{other}` in `{spec}` — use d / h / m / s (e.g. 30d, 24h, 30m)"
        ),
    };
    let n: u64 = num
        .trim()
        .parse()
        .with_context(|| format!("`{spec}` is not a valid duration (try 30d / 24h / 30m)"))?;
    n.checked_mul(mult)
        .ok_or_else(|| anyhow::anyhow!("--last duration `{spec}` overflows"))
}

/// Scan every `*.wal` segment for the sensitive event types whose
/// timestamp falls within the last `window_secs`. Robust v1/v2 + zstd
/// read (mirrors `neoth wal show`); a missing dir / torn segment is
/// tolerated (skips rather than errors — a partial WAL still yields a
/// correct count of the frames it CAN read).
pub fn scan_sensitive_window(wal_dir: &Path, window_secs: u64) -> WalWindowSummary {
    let mut summary = WalWindowSummary {
        window_secs,
        ..Default::default()
    };
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(u64::MAX);
    let cutoff_ns = now_ns.saturating_sub(window_secs.saturating_mul(1_000_000_000));

    let mut segments: Vec<std::path::PathBuf> = match std::fs::read_dir(wal_dir) {
        Ok(it) => it
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("wal"))
            .collect(),
        Err(_) => return summary,
    };
    segments.sort();

    for seg in segments {
        let Ok(bytes) = std::fs::read(&seg) else {
            continue;
        };
        let Ok(hdr) = parse_segment_header(&bytes) else {
            continue;
        };
        let header_len = hdr.header_len();
        if bytes.len() <= header_len {
            continue;
        }
        let body = &bytes[header_len..];
        let decompressed;
        let frames: &[u8] = if hdr.is_compressed() {
            match decompress_frames(body) {
                Ok(d) => {
                    decompressed = d;
                    &decompressed
                }
                Err(_) => continue,
            }
        } else {
            body
        };
        let mut cursor = 0usize;
        while cursor < frames.len() {
            let dec = match decode_frame(&frames[cursor..]) {
                Ok(d) => d,
                Err(_) => break,
            };
            summary.frames_scanned += 1;
            if dec.header.hlc.physical_ns() >= cutoff_ns {
                match dec.header.event_type {
                    EVENT_TYPE_PROVIDER_REQUEST | EVENT_TYPE_PROVIDER_RESPONSE => {
                        summary.provider_calls += 1
                    }
                    EVENT_TYPE_CHANNEL_EGRESS => summary.channel_egress += 1,
                    EVENT_TYPE_PROFILE_DELTA | EVENT_TYPE_PROFILE_REINFORCED => {
                        summary.profile_extractions += 1
                    }
                    _ => {}
                }
            }
            let total = dec.header.total_len as usize;
            if total == 0 {
                break;
            }
            cursor = cursor.saturating_add(total);
        }
    }
    summary
}

fn render_window_table(w: &WalWindowSummary) {
    let days = w.window_secs as f64 / 86_400.0;
    println!("[INFO] last-window activity (what actually left this device):");
    println!(
        "    window: {} ({:.1} days), {} frames scanned",
        humanize_secs(w.window_secs),
        days,
        w.frames_scanned
    );
    println!(
        "    provider calls (cloud/LLM): {}    channel egress: {}    profile writes: {}",
        w.provider_calls, w.channel_egress, w.profile_extractions
    );
    println!(
        "    Drill in: `neoth wal show --type provider_request --last 50`, \
         `--type channel_egress`, `--type profile_delta`."
    );
    println!();
}

fn humanize_secs(secs: u64) -> String {
    if secs.is_multiple_of(86_400) {
        format!("{}d", secs / 86_400)
    } else if secs.is_multiple_of(3_600) {
        format!("{}h", secs / 3_600)
    } else if secs.is_multiple_of(60) {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

/// L-08 pure-function audit. Takes the loaded config + creds and
/// returns the list of findings. Pure so it's straightforward to
/// test against synthetic configs.
pub fn audit_posture(cfg: &FreedomConfig, creds: &Credentials) -> Vec<PrivacyFinding> {
    let mut out = Vec::new();

    // ── Provider ──────────────────────────────────────────────────────
    // COR-13: ProviderKind::as_str() is the canonical wire slug (== serde),
    // replacing the prior serde_json round-trip workaround.
    let provider = cfg
        .provider_kind
        .map(|p| p.as_str())
        .unwrap_or("local_qwen");
    let cloud_provider = !crate::providers::is_local_provider(provider);
    out.push(PrivacyFinding {
        category: "provider",
        severity: if cloud_provider { "warn" } else { "info" },
        status: format!(
            "Default provider: `{}` ({})",
            provider,
            if cloud_provider {
                "CLOUD"
            } else {
                "LOCAL ONLY"
            }
        ),
        detail: if cloud_provider {
            format!(
                "Every chat call posts your prompt to `{provider}`'s servers. \
                 Re-run `neoth init` and pick `local_qwen` for an offline-only path."
            )
        } else {
            "Every chat call stays on this machine — no network egress for inference.".into()
        },
    });

    // ── Profile learning ──────────────────────────────────────────────
    let learn_enabled = cfg.profile.learn_enabled;
    let learn_provider = cfg.profile.learn_provider.as_deref().unwrap_or(provider);
    let learn_is_cloud = !crate::providers::is_local_provider(learn_provider);
    out.push(PrivacyFinding {
        category: "profile-learning",
        severity: if !learn_enabled {
            "info"
        } else if learn_is_cloud {
            "warn"
        } else {
            "info"
        },
        status: format!(
            "Profile learning: {} (provider: `{}`)",
            if learn_enabled { "ENABLED" } else { "DISABLED" },
            learn_provider,
        ),
        detail: if learn_enabled && learn_is_cloud {
            format!(
                "Each chat reply triggers a Stage-3 extract LLM call to `{learn_provider}`. \
                 That's a SECOND cloud call per reply. Set `profile.learn_provider: local_qwen` \
                 to keep this offline, or `profile.learn_enabled: false` to disable entirely."
            )
        } else if learn_enabled {
            "Stage-3 extract runs on local_qwen — no cloud touches.".into()
        } else {
            "No automatic profile extraction. Operator-facts only grow via explicit \
             `neoth groundtruth add` calls."
                .into()
        },
    });

    // ── Cloud fallback ────────────────────────────────────────────────
    if cfg.profile.allow_cloud_fallback {
        out.push(PrivacyFinding {
            category: "cloud-fallback",
            severity: "warn",
            status: "Profile-learn cloud fallback: ENABLED (L-07 `allow_cloud_fallback: true`)"
                .to_string(),
            detail: "When the configured `learn_provider` is unavailable (local weights \
                     missing / hardware issue), NEOTH falls back to your main provider — \
                     which posts the prompt to a cloud endpoint. Flip to false to fail \
                     closed instead."
                .into(),
        });
    }

    // ── Channel credentials ────────────────────────────────────────────
    let mut channels: Vec<&'static str> = Vec::new();
    if creds.telegram_token.is_some() {
        channels.push("telegram");
    }
    if creds.slack_bot_token.is_some() || creds.slack_app_token.is_some() {
        channels.push("slack");
    }
    if creds.whatsapp_token.is_some() {
        channels.push("whatsapp");
    }
    out.push(PrivacyFinding {
        category: "channels",
        severity: if channels.is_empty() { "info" } else { "warn" },
        status: format!(
            "Configured channels: {}",
            if channels.is_empty() {
                "none".to_string()
            } else {
                channels.join(", ")
            }
        ),
        detail: if channels.is_empty() {
            "Daemon runs in CLI-only mode. No third-party messenger sees your prompts.".into()
        } else {
            format!(
                "Each configured channel relays your messages to a third-party server \
                 ({}). Run `neoth doctor` to see which channels are LIVE inbound \
                 vs OUTBOUND-ONLY. Tokens live at `~/.neoth/credentials.yaml` (mode 0600).",
                channels.join(" / ")
            )
        },
    });

    // ── WAL audit + redaction ─────────────────────────────────────────
    out.push(PrivacyFinding {
        category: "audit-trail",
        severity: "info",
        status: "WAL at `~/.neoth/wal/*.wal` records every action (HMAC-SHA256 sealed)".into(),
        detail: "Operator-private — file mode 0600 on unix, owner-only DACL on Windows. \
                 `neoth wal show` to inspect. Credentials in `PRE_MUTATION_SNAPSHOT` \
                 frames are redacted (K-Sec-5) — `provider_key: sk-...` becomes \
                 `[REDACTED:openai_key]` before bytes touch disk."
            .into(),
    });

    // ── HMAC key DPAPI wrap (Windows-only) ────────────────────────────
    #[cfg(windows)]
    out.push(PrivacyFinding {
        category: "wal-tamper-evidence",
        severity: "info",
        status: "HMAC key DPAPI-wrapped on Windows (K-Sec-4)".into(),
        detail: "`~/.neoth/wal/hmac.key` is wrapped via CryptProtectData, bound to your \
                 Windows user account. A copy of the file lifted off the box is useless \
                 outside your session — attackers can't forge `0x15 COMPACTION_MARKER` \
                 frames."
            .into(),
    });

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::credentials::Credentials;
    use crate::secret::SecretString;

    fn cfg_with(
        provider: &str,
        learn_enabled: bool,
        learn_provider: Option<&str>,
    ) -> FreedomConfig {
        use crate::cli::init::ProviderKind;
        let mut cfg = FreedomConfig::default();
        cfg.provider_kind = Some(match provider {
            "local_qwen" => ProviderKind::LocalQwen,
            "local_ouro" => ProviderKind::LocalOuro,
            "openai_api" => ProviderKind::OpenaiApi,
            _ => ProviderKind::LocalQwen,
        });
        cfg.profile.learn_enabled = learn_enabled;
        cfg.profile.learn_provider = learn_provider.map(|s| s.to_string());
        cfg
    }

    #[test]
    fn audit_reports_local_only_when_provider_is_local_qwen() {
        let cfg = cfg_with("local_qwen", false, Some("local_qwen"));
        let creds = Credentials::default();
        let findings = audit_posture(&cfg, &creds);
        let provider_finding = findings.iter().find(|f| f.category == "provider").unwrap();
        assert_eq!(provider_finding.severity, "info");
        assert!(provider_finding.status.contains("LOCAL ONLY"));
    }

    #[test]
    fn audit_reports_local_only_when_provider_is_local_ouro() {
        // GR-17 (Session 30): local_ouro is on-device inference — it must
        // classify LOCAL ONLY / info, never CLOUD / warn. Before the
        // canonical `is_local_provider` helper, the `!= "local_qwen"` guard
        // mislabelled it CLOUD with a false "posts your prompt to
        // local_ouro's servers" privacy warning.
        let cfg = cfg_with("local_ouro", false, Some("local_ouro"));
        let creds = Credentials::default();
        let findings = audit_posture(&cfg, &creds);
        let provider_finding = findings.iter().find(|f| f.category == "provider").unwrap();
        assert_eq!(provider_finding.severity, "info");
        assert!(provider_finding.status.contains("LOCAL ONLY"));
    }

    #[test]
    fn audit_info_when_profile_learn_uses_local_ouro() {
        let cfg = cfg_with("openai_api", true, Some("local_ouro"));
        let creds = Credentials::default();
        let findings = audit_posture(&cfg, &creds);
        let pf = findings
            .iter()
            .find(|f| f.category == "profile-learning")
            .unwrap();
        assert_eq!(
            pf.severity, "info",
            "local_ouro learn provider is on-device"
        );
    }

    #[test]
    fn audit_warns_when_provider_is_cloud() {
        let cfg = cfg_with("openai_api", false, None);
        let creds = Credentials::default();
        let findings = audit_posture(&cfg, &creds);
        let provider_finding = findings.iter().find(|f| f.category == "provider").unwrap();
        assert_eq!(provider_finding.severity, "warn");
        assert!(provider_finding.status.contains("CLOUD"));
    }

    #[test]
    fn audit_warns_when_profile_learn_uses_cloud() {
        let cfg = cfg_with("local_qwen", true, Some("openai_api"));
        let creds = Credentials::default();
        let findings = audit_posture(&cfg, &creds);
        let pf = findings
            .iter()
            .find(|f| f.category == "profile-learning")
            .unwrap();
        assert_eq!(pf.severity, "warn");
        assert!(pf.status.contains("openai_api"));
    }

    #[test]
    fn audit_info_when_profile_learn_uses_local() {
        let cfg = cfg_with("openai_api", true, Some("local_qwen"));
        let creds = Credentials::default();
        let findings = audit_posture(&cfg, &creds);
        let pf = findings
            .iter()
            .find(|f| f.category == "profile-learning")
            .unwrap();
        assert_eq!(pf.severity, "info");
        assert!(pf.status.contains("local_qwen"));
    }

    #[test]
    fn audit_lists_no_channels_when_credentials_empty() {
        let cfg = cfg_with("local_qwen", false, None);
        let creds = Credentials::default();
        let findings = audit_posture(&cfg, &creds);
        let ch = findings.iter().find(|f| f.category == "channels").unwrap();
        assert_eq!(ch.severity, "info");
        assert!(ch.status.contains("none"));
    }

    #[test]
    fn audit_warns_and_lists_configured_channels() {
        let cfg = cfg_with("local_qwen", false, None);
        let creds = Credentials {
            telegram_token: Some(SecretString::from("123:abc")),
            slack_bot_token: Some(SecretString::from("xoxb-test")),
            ..Default::default()
        };
        let findings = audit_posture(&cfg, &creds);
        let ch = findings.iter().find(|f| f.category == "channels").unwrap();
        assert_eq!(ch.severity, "warn");
        assert!(ch.status.contains("telegram"));
        assert!(ch.status.contains("slack"));
    }

    #[test]
    fn audit_surfaces_cloud_fallback_when_enabled() {
        let mut cfg = cfg_with("local_qwen", true, Some("local_qwen"));
        cfg.profile.allow_cloud_fallback = true;
        let creds = Credentials::default();
        let findings = audit_posture(&cfg, &creds);
        assert!(findings.iter().any(|f| f.category == "cloud-fallback"));
    }

    #[test]
    fn audit_omits_cloud_fallback_finding_when_disabled() {
        let cfg = cfg_with("local_qwen", true, Some("local_qwen"));
        let creds = Credentials::default();
        let findings = audit_posture(&cfg, &creds);
        assert!(!findings.iter().any(|f| f.category == "cloud-fallback"));
    }

    #[test]
    fn audit_always_includes_wal_audit_trail_row() {
        let cfg = cfg_with("local_qwen", false, None);
        let creds = Credentials::default();
        let findings = audit_posture(&cfg, &creds);
        assert!(findings.iter().any(|f| f.category == "audit-trail"));
    }

    // ── --last window (the IMPLEMENT decision) ────────────────────────

    #[test]
    fn parse_duration_handles_units_and_rejects_garbage() {
        assert_eq!(parse_duration("30d").unwrap(), 30 * 86_400);
        assert_eq!(parse_duration("24h").unwrap(), 24 * 3_600);
        assert_eq!(parse_duration("90m").unwrap(), 90 * 60);
        assert_eq!(parse_duration("45s").unwrap(), 45);
        assert_eq!(parse_duration("100").unwrap(), 100); // bare = seconds
        assert_eq!(parse_duration(" 7d ").unwrap(), 7 * 86_400);
        assert!(parse_duration("").is_err());
        assert!(parse_duration("5x").is_err());
        assert!(parse_duration("abc").is_err());
    }

    fn write_window_segment(dir: &std::path::Path) -> std::path::PathBuf {
        use crate::wal::HeaderBuilder;
        use crate::wal::events::EVENT_TYPE_RAW_TEXT;
        use crate::wal::frame::encode_frame;
        use crate::wal::header::EventHeaderV2;
        use crate::wal::segment_header::SegmentHeader;
        let path = dir.join("000001.wal");
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&SegmentHeader::new(0, 1, 0, 0, [0u8; 16]).to_le_bytes());
        // 2 provider calls + 1 egress + 1 profile write + 1 non-sensitive,
        // all stamped "now" by HeaderBuilder (so a 1h window includes them).
        for code in [
            EVENT_TYPE_PROVIDER_REQUEST,
            EVENT_TYPE_PROVIDER_RESPONSE,
            EVENT_TYPE_CHANNEL_EGRESS,
            EVENT_TYPE_PROFILE_DELTA,
            EVENT_TYPE_RAW_TEXT,
        ] {
            let payload = b"x".to_vec();
            let header: EventHeaderV2 = HeaderBuilder::new(code, &payload).build();
            bytes.extend_from_slice(&encode_frame(&header, &payload));
        }
        std::fs::write(&path, &bytes).unwrap();
        path
    }

    #[test]
    fn scan_window_counts_sensitive_types_in_window() {
        let dir = tempfile::tempdir().unwrap();
        write_window_segment(dir.path());
        let s = scan_sensitive_window(dir.path(), 3_600); // 1h — includes "now" frames
        assert_eq!(s.frames_scanned, 5);
        assert_eq!(s.provider_calls, 2, "0x20 + 0x21");
        assert_eq!(s.channel_egress, 1, "0x33");
        assert_eq!(s.profile_extractions, 1, "0xB0");
        // RAW_TEXT is not sensitive → not categorised.
    }

    #[test]
    fn scan_window_zero_window_excludes_past_frames() {
        // A 0-second window's cutoff is "now"; frames written microseconds
        // earlier are strictly in the past → none counted. Proves the
        // timestamp cutoff actually gates (not just the type filter).
        let dir = tempfile::tempdir().unwrap();
        write_window_segment(dir.path());
        let s = scan_sensitive_window(dir.path(), 0);
        assert_eq!(s.frames_scanned, 5, "all frames are still walked");
        assert_eq!(s.provider_calls, 0);
        assert_eq!(s.channel_egress, 0);
        assert_eq!(s.profile_extractions, 0);
    }

    #[test]
    fn scan_window_missing_dir_is_zeroed_not_error() {
        let dir = tempfile::tempdir().unwrap();
        let s = scan_sensitive_window(&dir.path().join("nope"), 86_400);
        assert_eq!(s.frames_scanned, 0);
        assert_eq!(s.provider_calls, 0);
    }
}
