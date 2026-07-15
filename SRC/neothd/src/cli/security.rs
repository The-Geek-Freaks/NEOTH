//! Round-3 v0.4 SC-04 — `neoth security audit` operator-facing
//! one-shot security report.
//!
//! Aggregates the existing security primitives scattered across
//! `permissions::audit`, `memory::drift`, `wal::*` into a single
//! pass + prints a checklist-style report. Each check is
//! independent: one failing check doesn't abort the others, so the
//! operator sees the full posture in one invocation rather than
//! discovering issues piecemeal across `neoth doctor` /
//! `neoth permissions audit` / `neoth memory drift` calls.
//!
//! ## Checks today
//!
//! | Check                               | What it surfaces                          |
//! |-------------------------------------|-------------------------------------------|
//! | HMAC compaction key                 | file presence + permissions/DACL          |
//! | WAL segment health                  | latest segment exists + non-empty         |
//! | Permission decisions (last 24h)     | grant / deny / consent counts             |
//! | Memory drift (Hippocampus)          | imminent + at-risk row counts             |
//! | Consent state (cloud providers)     | per-provider granted/denied flags         |
//!
//! ## Output format
//!
//! Per-check line with one of three status markers:
//! - `[ OK ]` — green-path; the check passed.
//! - `[WARN]` — caller-visible signal (e.g. drift queue non-empty)
//!   that doesn't break security but needs attention.
//! - `[FAIL]` — a security primitive is missing / mis-configured /
//!   reports an integrity error. Operator should fix before next
//!   sensitive operation.
//!
//! The report exits non-zero iff any check is `[FAIL]`. Non-fatal
//! warnings don't change the exit code (matches the operator's
//! `neoth doctor` exit-code semantics).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;

#[derive(Args, Debug, Clone)]
pub struct SecurityArgs {
    #[command(subcommand)]
    pub command: SecurityCommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum SecurityCommand {
    /// One-shot security posture report — runs every available
    /// check + prints a pass/warn/fail checklist. Exit code 0 on
    /// all-clear, 1 if any check FAILed (warnings don't change
    /// exit). Matches the `neoth doctor` semantics.
    Audit(AuditArgs),
    /// SC-09 (Session 28) — export the WAL HMAC compaction key to
    /// `<output>` in plaintext for disaster-recovery purposes
    /// (machine swap, Windows reinstall, DPAPI unwrap failure).
    ///
    /// **What this is for**: per `PLAN/RUNBOOK_dpapi_hmac_recovery.md`,
    /// the WAL HMAC key on Windows is DPAPI-wrapped + bound to the
    /// current user account + machine identity. When any of those
    /// three change (machine swap / Windows reinstall in place /
    /// MS-account ↔ local-account switch), CryptUnprotectData fails
    /// + the operator's compaction-marker audit chain can't be
    /// verified. A plaintext backup taken BEFORE such an event lets
    /// the operator re-wrap the key on the new identity (Tier 1
    /// recovery — full audit-chain continuity preserved).
    ///
    /// **What this is NOT for**: routine use. The plaintext file
    /// loses the per-user DACL + DPAPI binding the in-place key has.
    /// The runbook warns operators to store the backup in their
    /// password manager / hardware token / sealed vault — NOT on the
    /// same disk as `~/.neoth`.
    BackupHmacKey(BackupHmacKeyArgs),
    /// SC-09 Tier-1 recovery — re-wrap a plaintext HMAC key backup for
    /// THIS machine/user and install it, OVERWRITING the current key.
    ///
    /// **When to run**: after a machine swap / Windows reinstall /
    /// account switch, `neoth verify` fails because the DPAPI-wrapped
    /// key can no longer be unwrapped (CryptUnprotectData error). Feed
    /// the plaintext backup taken via `neoth security backup-hmac-key`
    /// on the old host to this command — it DPAPI-re-wraps the key for
    /// the new identity (Windows) / writes it mode-0600 (Unix), so the
    /// existing compaction-marker audit chain verifies again. Stop the
    /// daemon before running. See `PLAN/RUNBOOK_dpapi_hmac_recovery.md`.
    RewrapHmacKey(RewrapHmacKeyArgs),
    /// CRYPTO-04e — export the WAL/config AEAD master key as a portable RAW
    /// backup (NOT DPAPI-wrapped, so it survives a reinstall). Store it OFFLINE:
    /// losing it makes every encrypted sealed segment + credentials permanently
    /// unreadable.
    BackupMasterKey(BackupMasterKeyArgs),
    /// CRYPTO-04e — re-bind a RAW master-key backup to THIS machine (DPAPI-wrap
    /// on Windows / mode-0600 elsewhere), overwriting the current key. Stop the
    /// daemon first.
    RestoreMasterKey(RestoreMasterKeyArgs),
    /// GR-10 — single-glance view of the active safety RAILS: which
    /// protective defaults are ENGAGED vs which the operator has RELAXED
    /// (autonomy, private inference, proactive/cluster transport, OS-tool
    /// allowlists, plugin signatures, model downloads). Read-only — the
    /// single source of truth for "what is protecting me right now"
    /// without spelunking `freedom.yaml`. Always exits 0 (it is a status
    /// view, not a pass/fail gate).
    SafeMode(SafeModeArgs),
    /// Mutate a named security-policy control through the canonical config
    /// writer. These commands are intentionally explicit and scriptable; JSON
    /// output is a typed acknowledgement for GUI and automation callers.
    Set(SecuritySetArgs),
}

#[derive(Args, Debug, Clone)]
pub struct SecuritySetArgs {
    #[command(subcommand)]
    pub command: SecuritySetCommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum SecuritySetCommand {
    /// Toggle the global Smart-Approve master switch. Individual MCP servers
    /// must still opt in separately; this never relaxes their local policy.
    #[command(name = "smart-approve")]
    SmartApprove {
        #[arg(long, conflicts_with = "disable")]
        enable: bool,
        #[arg(long, conflicts_with = "enable")]
        disable: bool,
    },
}

#[derive(Args, Debug, Clone)]
pub struct SafeModeArgs {
    /// Override the `~/.neoth` home dir (mostly for tests).
    #[arg(long, value_name = "DIR")]
    pub home: Option<PathBuf>,
    /// Emit JSON instead of the human-readable table.
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug, Clone)]
pub struct RewrapHmacKeyArgs {
    /// Path to the plaintext HMAC key backup (produced by
    /// `neoth security backup-hmac-key`). Its bytes are re-wrapped for
    /// the current machine/user and installed over the live key.
    #[arg(long, value_name = "PATH")]
    pub source: PathBuf,
    /// Override the `~/.neoth` home dir (mostly for tests). Defaults
    /// to the operator's actual `~/.neoth`.
    #[arg(long, value_name = "DIR")]
    pub home: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub struct BackupMasterKeyArgs {
    /// Raw portable destination path (written mode-0600 on Unix). Refused if it
    /// exists unless `--force`.
    #[arg(long, value_name = "PATH")]
    pub output: PathBuf,
    /// Overwrite `--output` if it already exists.
    #[arg(long)]
    pub force: bool,
    /// Override the `~/.neoth` home dir (mostly for tests).
    #[arg(long, value_name = "DIR")]
    pub home: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub struct RestoreMasterKeyArgs {
    /// Path to the raw master-key backup (from `backup-master-key`). Re-bound to
    /// this machine and installed over the current key.
    #[arg(long, value_name = "PATH")]
    pub source: PathBuf,
    /// Override the `~/.neoth` home dir (mostly for tests).
    #[arg(long, value_name = "DIR")]
    pub home: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub struct BackupHmacKeyArgs {
    /// Plaintext destination path outside the NEOTH home. The file is written
    /// mode-0600 (Unix) / owner-DACL restricted (Windows). Refused
    /// if the path resolves inside `~/.neoth`, or already exists unless
    /// `--force` is also passed (defence against a false disaster-recovery copy
    /// and silent overwrite of an older backup).
    #[arg(long, value_name = "PATH")]
    pub output: PathBuf,
    /// Overwrite `--output` if it already exists. Without this flag
    /// the command fails fast — accidentally re-running this command
    /// with the same `--output` shouldn't blow away an older backup
    /// taken at a different rotation.
    #[arg(long)]
    pub force: bool,
    /// Override the `~/.neoth` home dir (mostly for tests). Defaults
    /// to the operator's actual `~/.neoth`.
    #[arg(long, value_name = "DIR")]
    pub home: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub struct AuditArgs {
    /// Override the `~/.neoth` home dir (mostly for tests).
    #[arg(long, value_name = "DIR")]
    pub home: Option<PathBuf>,

    /// Lookback window for the permission-decisions check, in
    /// hours. Default 24h covers operator's last day of activity.
    #[arg(long, value_name = "HOURS", default_value_t = 24)]
    pub permissions_lookback_hours: u64,

    /// Cap on drifting-row display per severity bucket. Doesn't
    /// affect the summary counts.
    #[arg(long, value_name = "N", default_value_t = 10)]
    pub drift_display_cap: usize,
}

/// Severity marker for a single audit check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStatus {
    Ok,
    Warn,
    Fail,
}

impl CheckStatus {
    fn marker(self) -> &'static str {
        match self {
            CheckStatus::Ok => "[ OK ]",
            CheckStatus::Warn => "[WARN]",
            CheckStatus::Fail => "[FAIL]",
        }
    }
}

/// One row in the audit report. `detail` is the human-readable
/// one-line summary printed alongside the status marker.
#[derive(Debug, Clone)]
pub struct CheckResult {
    pub name: &'static str,
    pub status: CheckStatus,
    pub detail: String,
}

/// Full audit report. `exit_code()` returns 1 iff any check FAILed.
#[derive(Debug, Clone, Default)]
pub struct AuditReport {
    pub checks: Vec<CheckResult>,
}

impl AuditReport {
    pub fn push(&mut self, name: &'static str, status: CheckStatus, detail: impl Into<String>) {
        self.checks.push(CheckResult {
            name,
            status,
            detail: detail.into(),
        });
    }

    pub fn exit_code(&self) -> i32 {
        if self
            .checks
            .iter()
            .any(|c| matches!(c.status, CheckStatus::Fail))
        {
            1
        } else {
            0
        }
    }

    /// Per-status counts for the operator's tail summary.
    pub fn counts(&self) -> (usize, usize, usize) {
        let mut ok = 0;
        let mut warn = 0;
        let mut fail = 0;
        for c in &self.checks {
            match c.status {
                CheckStatus::Ok => ok += 1,
                CheckStatus::Warn => warn += 1,
                CheckStatus::Fail => fail += 1,
            }
        }
        (ok, warn, fail)
    }
}

pub async fn run_security(args: SecurityArgs, output: OutputFormat) -> Result<()> {
    match args.command {
        SecurityCommand::Audit(a) => {
            let report = run_audit_collect(&a)?;
            print_report(&report);
            let code = report.exit_code();
            if code != 0 {
                std::process::exit(code);
            }
            Ok(())
        }
        SecurityCommand::BackupHmacKey(a) => run_backup_hmac_key(&a),
        SecurityCommand::RewrapHmacKey(a) => run_rewrap_hmac_key(&a).await,
        SecurityCommand::BackupMasterKey(a) => run_backup_master_key(&a),
        SecurityCommand::RestoreMasterKey(a) => run_restore_master_key(&a),
        SecurityCommand::SafeMode(a) => run_safe_mode(&a),
        SecurityCommand::Set(a) => run_security_set(a, output),
    }
}

fn run_security_set(args: SecuritySetArgs, output: OutputFormat) -> Result<()> {
    match args.command {
        SecuritySetCommand::SmartApprove { enable, disable } => {
            if enable == disable {
                anyhow::bail!("pass exactly one of --enable or --disable");
            }
            let path = FreedomConfig::default_path();
            let changed =
                FreedomConfig::update_at(&path, |cfg| Ok(apply_smart_approve(cfg, enable)))
                    .context("persist security.smart_approve to freedom.yaml")?;
            match output {
                OutputFormat::Json | OutputFormat::Jsonl => println!(
                    "{}",
                    serde_json::json!({
                        "ok": true,
                        "action": "set_smart_approve",
                        "smart_approve": enable,
                        "changed": changed,
                    })
                ),
                OutputFormat::Table => println!(
                    "security.smart_approve -> {}{}",
                    if enable { "enabled" } else { "disabled" },
                    if changed { "" } else { " (unchanged)" },
                ),
            }
            Ok(())
        }
    }
}

fn apply_smart_approve(cfg: &mut FreedomConfig, enabled: bool) -> bool {
    let changed = cfg.security.smart_approve != enabled;
    cfg.security.smart_approve = enabled;
    changed
}

// ── GR-10: unified safe-mode / rails status surface ──────────────────

/// One safety rail's current posture. `engaged == true` means the
/// protective default is ON (locked down); `false` means the operator
/// has RELAXED it (opened the surface). `detail` is the one-line reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rail {
    pub name: &'static str,
    pub engaged: bool,
    pub detail: String,
}

/// GR-10 — derive the active safety rails from the live config. Pure
/// over `cfg`: every rail is a config read, so this is the single
/// source of truth for the operator's protection posture. Never fails
/// (a status view), so callers can always render it.
pub fn collect_rails(cfg: &FreedomConfig) -> Vec<Rail> {
    use crate::permissions::AutonomyLevel;
    let mut rails: Vec<Rail> = Vec::new();

    // Autonomy gate — Strict/Standard gate sensitive actions; Elevated/
    // Full auto-allow; Custom is operator-defined per action.
    let (engaged, detail) = match cfg.autonomy {
        AutonomyLevel::Strict => (true, "strict — sensitive actions denied".to_string()),
        AutonomyLevel::Standard => (
            true,
            "standard — sensitive actions need confirmation".to_string(),
        ),
        AutonomyLevel::Elevated => (false, "elevated — most actions auto-allowed".to_string()),
        AutonomyLevel::Full => (
            false,
            "full — actions auto-allowed (highest trust)".to_string(),
        ),
        AutonomyLevel::Custom => (false, "custom — per-action operator policy".to_string()),
    };
    rails.push(Rail {
        name: "autonomy_gate",
        engaged,
        detail,
    });

    // Private inference — profile extraction stays on-device unless the
    // operator opted into a cloud fallback.
    rails.push(Rail {
        name: "private_inference",
        engaged: !cfg.profile.allow_cloud_fallback,
        detail: if cfg.profile.allow_cloud_fallback {
            "cloud fallback ALLOWED — profile extraction may reach a cloud provider".to_string()
        } else {
            "cloud fallback denied — profile extraction stays on-device".to_string()
        },
    });

    // Proactive messaging — the daemon never messages unprompted unless
    // enabled.
    rails.push(Rail {
        name: "proactive_messaging",
        engaged: !cfg.proactive.enabled,
        detail: if cfg.proactive.enabled {
            "enabled — the daemon may message you unprompted".to_string()
        } else {
            "disabled — no unprompted outbound messages".to_string()
        },
    });

    // Cluster transport — no peer transport / DHT announce unless enabled.
    rails.push(Rail {
        name: "cluster_transport",
        engaged: !cfg.cluster.enabled,
        detail: if cfg.cluster.enabled {
            "enabled — peer transport active (DHT / mDNS)".to_string()
        } else {
            "disabled — no peer transport, no public DHT announce".to_string()
        },
    });

    // OS file tools — empty allowlists = deny-all.
    let reads = cfg.tools.os.allowed_paths.len();
    let writes = cfg.tools.os.allowed_write_paths.len();
    rails.push(Rail {
        name: "os_file_tools",
        engaged: reads == 0 && writes == 0,
        detail: format!(
            "{reads} read path(s), {writes} write path(s) allowlisted (empty = deny-all)"
        ),
    });

    // OS app-launch (PC-01 app-launch slice) — its OWN rail, separate from
    // os_file_tools: a readable/writable path is not runnable, so the exec
    // surface can be open while file tools are still locked (and vice-versa).
    // Empty allowed_exec_paths = deny-all = engaged.
    let execs = cfg.tools.os.allowed_exec_paths.len();
    rails.push(Rail {
        name: "os_app_launch",
        engaged: execs == 0,
        detail: format!("{execs} executable(s) allowlisted (empty = deny-all program launch)"),
    });

    // Plugin signatures — engaged only when an author key is set AND
    // signatures are required.
    let has_key = cfg.plugins.wasm.author_pubkey.is_some();
    let require_sig = cfg.plugins.wasm.require_signature;
    rails.push(Rail {
        name: "plugin_signatures",
        engaged: has_key && require_sig,
        detail: if !has_key {
            "no author key configured — plugin signature checking off".to_string()
        } else if require_sig {
            "author key set + signatures required".to_string()
        } else {
            "author key set but signatures NOT required".to_string()
        },
    });

    // Model downloads — air-gapped unless HF downloads allowed.
    rails.push(Rail {
        name: "model_downloads",
        engaged: !cfg.updater.allow_huggingface_downloads,
        detail: if cfg.updater.allow_huggingface_downloads {
            "Hugging Face downloads allowed".to_string()
        } else {
            "Hugging Face downloads blocked (air-gapped)".to_string()
        },
    });

    // PL-05b email LLM tie-breaker — engaged (off) means no LLM ever sees an
    // inbound mail; relaxed (on) spends an LLM call per borderline email.
    rails.push(Rail {
        name: "email_llm_tiebreak",
        engaged: !cfg.email.llm_tiebreak,
        detail: if cfg.email.llm_tiebreak {
            "ON — an LLM second-opinion classifies borderline inbound mail".to_string()
        } else {
            "off — deterministic rules only; no LLM sees your mail".to_string()
        },
    });

    // PL-05b email downgrade — the DANGEROUS direction: a benign LLM verdict
    // overriding the rules to auto-DELIVER a flagged email. Engaged = denied.
    rails.push(Rail {
        name: "email_downgrade_allowed",
        engaged: !cfg.email.llm_tiebreak_allow_downgrade,
        detail: if cfg.email.llm_tiebreak_allow_downgrade {
            "ALLOWED — a benign LLM verdict may auto-DELIVER a flagged email (dangerous; \
             an LLM false-negative could let phishing reach auto-action)"
                .to_string()
        } else {
            "denied — the LLM may only hold/quarantine, never auto-deliver".to_string()
        },
    });

    // OMI ingest can carry everyday conversation and native media, so it gets
    // its own rail. The detail must describe the selected trust boundary rather
    // than repeating the old (and now false) blanket local-only claim.
    rails.push(Rail {
        name: "omi_ingest",
        engaged: !cfg.omi.enabled,
        detail: if cfg.omi.enabled {
            match cfg.omi.mode {
                crate::config::OmiIngestMode::DeveloperApi => format!(
                    "ENABLED — Developer API {} ({})",
                    cfg.omi.endpoint,
                    if cfg.omi.allow_cloud_api {
                        "public HTTPS explicitly allowed"
                    } else {
                        "local/private endpoint only"
                    }
                ),
                crate::config::OmiIngestMode::NativeIngest => format!(
                    "ENABLED — authenticated native listener {} (private bind)",
                    cfg.omi.listen_addr
                ),
                crate::config::OmiIngestMode::Both => format!(
                    "ENABLED — Developer API {} ({}) + authenticated native listener {}",
                    cfg.omi.endpoint,
                    if cfg.omi.allow_cloud_api {
                        "public HTTPS explicitly allowed"
                    } else {
                        "local/private endpoint only"
                    },
                    cfg.omi.listen_addr
                ),
                crate::config::OmiIngestMode::LegacyMemories => format!(
                    "ENABLED — legacy local/private /v1/memories feed {}",
                    cfg.omi.endpoint
                ),
            }
        } else {
            "off — no OMI conversation or native media ingest".to_string()
        },
    });

    // EM-02b calendar writes — external network mutation surface. Engaged (off)
    // = `neoth calendar add` refuses fail-closed.
    rails.push(Rail {
        name: "calendar_writes",
        engaged: !cfg.calendar.writes_enabled,
        detail: if cfg.calendar.writes_enabled {
            "enabled — `neoth calendar add` may write to your CalDAV calendar \
             (still autonomy-gated + audited 0xCA CALENDAR_WRITE)"
                .to_string()
        } else {
            "off — calendar writes refuse fail-closed".to_string()
        },
    });

    // SPEC-11 live-delivery edits — outbound message edit-in-place surface.
    // Engaged (off) = send-only (never edits), the safest posture for a
    // rate-limit-sensitive channel.
    rails.push(Rail {
        name: "live_delivery_edits",
        engaged: !cfg.live_delivery.edits_enabled,
        detail: if cfg.live_delivery.edits_enabled {
            format!(
                "enabled — in-place edits rate-limited to 1 per {}ms, max {} per message \
                 (final edit always lands)",
                cfg.live_delivery.min_edit_interval_ms, cfg.live_delivery.max_edits_per_message
            )
        } else {
            "off — send-only, never edits a delivered message".to_string()
        },
    });

    // F4-01 ecology scheduler — the self-adaptation auto-scheduler. Engaged
    // (off) = it never fires (the read-only `neoth ecology` diagnostics still
    // work). Even ON it only STAGES review-gated proposals, never auto-applies.
    rails.push(Rail {
        name: "ecology_scheduler",
        engaged: !cfg.ecology.enabled,
        detail: if cfg.ecology.enabled {
            "ENABLED — experimental, review-gated: the scheduler STAGES self-dev \
             proposals (never auto-applies) + emits 0x4C"
                .to_string()
        } else {
            "off — no auto-scheduler (read-only ecology diagnostics still work)".to_string()
        },
    });

    // KF-05 channel-weight learning scope — whose replies move the recall
    // ranking. Engaged = the safe `operator_only` scope (no non-operator can
    // poison the ranking).
    let scope = cfg.channel_weights.learn_scope;
    rails.push(Rail {
        name: "channel_weight_learning",
        engaged: matches!(scope, crate::config::ChannelLearnScope::OperatorOnly),
        detail: match scope {
            crate::config::ChannelLearnScope::OperatorOnly => {
                "operator_only — only YOUR replies move the recall ranking".to_string()
            }
            crate::config::ChannelLearnScope::Allowlisted => {
                "allowlisted — you + allowlisted senders move the ranking".to_string()
            }
            crate::config::ChannelLearnScope::AllTiny => {
                "all_tiny — everyone moves the ranking; non-operators only a tiny fraction"
                    .to_string()
            }
        },
    });

    // MM-01b/02b/03b cloud-media rails — audio/image/video are more sensitive
    // than text. Engaged (off) = the media NEVER leaves the device for a cloud
    // provider; relaxed (on) = the operator accepted that it does. Each says so
    // plainly so "this media leaves your device" is never hidden.
    // B20 — 5-state rail reflecting actual provider + flag combination.
    rails.push(Rail {
        name: "cloud_stt_enabled",
        // engaged=true (safe) only when cloud_stt_enabled=false OR (primary is local
        // AND no cloud fallback exists).  A local primary with a cloud fallback and
        // cloud_stt_enabled=true can still egress on retryable failure → not safe.
        engaged: !cfg.media.cloud_stt_enabled
            || (cfg.media.stt.primary.is_local()
                && !cfg
                    .media
                    .stt
                    .fallback
                    .map(|f| !f.is_local())
                    .unwrap_or(false)),
        detail: {
            let primary = cfg.media.stt.primary;
            let cloud_on = cfg.media.cloud_stt_enabled;
            let has_fallback_cloud = cfg
                .media
                .stt
                .fallback
                .map(|f| !f.is_local())
                .unwrap_or(false);
            if primary.is_local() && !cloud_on && !has_fallback_cloud {
                // (1) off — local primary, no cloud anywhere
                format!(
                    "off — STT stays on-device ({} / faster-whisper); no audio leaves",
                    primary.as_str()
                )
            } else if !primary.is_local() && !cloud_on {
                // (2) configured-but-blocked
                format!(
                    "CONFIGURED-but-BLOCKED — cloud STT provider '{}' selected in \
                     media.stt but cloud_stt_enabled=false; audio will NOT be sent \
                     until you flip the flag",
                    primary.as_str()
                )
            } else if !primary.is_local() && cloud_on {
                // (3) cloud active as primary
                format!(
                    "ON — your AUDIO leaves the device to {}; \
                     audited 0xCC STT_TRANSCRIBED (metadata only)",
                    primary.as_str()
                )
            } else if primary.is_local() && cloud_on && has_fallback_cloud {
                // (4) local primary + cloud fallback consented
                format!(
                    "fallback-active — primary is local ({}), cloud fallback '{}' \
                     enabled; audio sent to cloud ONLY on retryable primary failure; \
                     audited 0xCC STT_TRANSCRIBED (metadata only)",
                    primary.as_str(),
                    cfg.media.stt.fallback.map(|f| f.as_str()).unwrap_or("none")
                )
            } else {
                "off — speech-to-text stays on-device; no audio leaves".to_string()
            }
        },
    });
    rails.push(Rail {
        name: "cloud_tts_enabled",
        engaged: !cfg.media.cloud_tts_enabled,
        detail: if cfg.media.cloud_tts_enabled {
            "ON — your TEXT leaves the device to a cloud TTS provider \
             (Azure / ElevenLabs). Audited 0xCD TTS_SYNTHESIZED (input HASH only)."
                .to_string()
        } else {
            "off — text-to-speech stays on-device (system voice); no text leaves".to_string()
        },
    });
    rails.push(Rail {
        name: "cloud_vision_enabled",
        engaged: !cfg.media.cloud_vision_enabled,
        detail: if cfg.media.cloud_vision_enabled {
            "ON — your IMAGES leave the device to a cloud vision model \
             (Anthropic / OpenAI / Gemini). Audited 0xC9 VIDEO_FRAME_SYNTHESIZED \
             (provider + counts + prompt HASH; never the pixels or prompt text)."
                .to_string()
        } else {
            "off — no images sent to a cloud vision model".to_string()
        },
    });
    rails.push(Rail {
        name: "video_frame_upload_enabled",
        engaged: !cfg.media.video_frame_upload_enabled,
        detail: if cfg.media.video_frame_upload_enabled {
            "ON — decoded VIDEO FRAMES are uploaded to a cloud vision model (a \
             sampled sequence — far more than a single still). Audited 0xC9."
                .to_string()
        } else {
            "off — no video frames uploaded to the cloud".to_string()
        },
    });

    rails
}

/// Render the rails as an operator-readable table. `[ENGAGED]` =
/// protective default on; `[RELAXED]` = operator opened the surface.
pub fn render_rails(rails: &[Rail]) -> String {
    let engaged = rails.iter().filter(|r| r.engaged).count();
    let mut out = String::new();
    out.push_str("# NEOTH safety rails (GR-10)\n");
    out.push_str(&format!(
        "  {engaged} of {} rails engaged (relaxed rails are operator-opened surfaces)\n\n",
        rails.len()
    ));
    for r in rails {
        let marker = if r.engaged { "[ENGAGED]" } else { "[RELAXED]" };
        out.push_str(&format!("  {marker}  {:<20} {}\n", r.name, r.detail));
    }
    out
}

fn run_safe_mode(args: &SafeModeArgs) -> Result<()> {
    let cfg = match &args.home {
        Some(dir) => FreedomConfig::load_from_path_or_default(&dir.join("freedom.yaml"))?,
        None => FreedomConfig::load_from_default_path_or_default()?,
    };
    let rails = collect_rails(&cfg);
    if args.json {
        let body = serde_json::json!({
            "rails": rails.iter().map(|r| serde_json::json!({
                "name": r.name,
                "engaged": r.engaged,
                "detail": r.detail,
            })).collect::<Vec<_>>(),
            "engaged_count": rails.iter().filter(|r| r.engaged).count(),
            "total": rails.len(),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&body).expect("security rails report is infallible JSON")
        );
    } else {
        print!("{}", render_rails(&rails));
    }
    Ok(())
}

/// SC-09 Tier-1 recovery: re-wrap a plaintext HMAC key backup for this
/// machine + install it over the live key. Overwrites by design — the
/// existing key is the broken/unreadable one the operator is replacing.
/// Loud stderr so the operator sees exactly what happened.
pub async fn run_rewrap_hmac_key(args: &RewrapHmacKeyArgs) -> Result<()> {
    let home = args
        .home
        .clone()
        .unwrap_or_else(crate::config::FreedomConfig::default_neoth_home);

    if !args.source.exists() {
        anyhow::bail!(
            "no plaintext key backup at {} — point --source at the file written by \
             `neoth security backup-hmac-key` on the original machine",
            args.source.display()
        );
    }
    let raw = std::fs::read(&args.source)
        .map_err(|e| anyhow::anyhow!("read key backup {}: {e}", args.source.display()))?;

    let key_path = home.join("wal").join("hmac.key");
    // Stage the machine-local wrapping first, durably append the signed 0xD9
    // boundary, then atomically install it. A rerun recovers either side of an
    // interrupted transaction before it can start another rotation.
    let rotation = rotate_hmac_key_with_audit(&home, &key_path, &raw, "rewrap", None).await?;

    eprintln!();
    eprintln!("[neoth security] HMAC KEY RE-WRAPPED FOR THIS MACHINE");
    eprintln!("[neoth security]   source:  {}", args.source.display());
    eprintln!("[neoth security]   key:     {}", key_path.display());
    eprintln!(
        "[neoth security]   bytes:   {} ({})",
        raw.len(),
        if rotation.replaced() {
            "replaced the existing key"
        } else {
            "installed (no prior key present)"
        }
    );
    if rotation.recovered {
        eprintln!("[neoth security]   state:   recovered interrupted audited rotation");
    }
    eprintln!("[neoth security]");
    eprintln!("[neoth security] The key is now bound to the current user/machine (DPAPI on");
    eprintln!("[neoth security] Windows, mode-0600 on Unix). Run `neoth verify` to confirm the");
    eprintln!("[neoth security] compaction-marker audit chain verifies again.");
    eprintln!("[neoth security] After verification, unmount/remove the working copy and return");
    eprintln!("[neoth security] the recovery backup to its protected offline storage.");
    eprintln!("[neoth security] Interrupted rotations are recovered transactionally on rerun.");

    println!("hmac key re-wrapped: {}", key_path.display());
    Ok(())
}

/// Canonical bytes for legacy v1 rotation events. Kept so existing WAL history
/// remains verifiable after the crash-safe v2 transaction shipped.
pub(crate) fn rotation_authorisation_message(
    new_key_sha256: &str,
    replaced: bool,
    reason: &str,
    ts_unix: i64,
) -> Vec<u8> {
    format!("hmac-key-rotated-v1|{new_key_sha256}|{replaced}|{reason}|{ts_unix}").into_bytes()
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HmacKeyRotatedPayload {
    schema: u8,
    rotation_id: String,
    new_key_sha256: String,
    previous_key_storage_sha256: Option<String>,
    replaced: bool,
    reason: String,
    ts_unix: i64,
    signer_pubkey: String,
    sig: String,
}

impl HmacKeyRotatedPayload {
    const SCHEMA: u8 = 2;

    fn canonical_bytes(&self) -> Vec<u8> {
        format!(
            "hmac-key-rotated-v2|{}|{}|{}|{}|{}|{}",
            self.rotation_id,
            self.new_key_sha256,
            self.previous_key_storage_sha256.as_deref().unwrap_or(""),
            self.replaced,
            self.reason,
            self.ts_unix,
        )
        .into_bytes()
    }

    fn validate(&self) -> Result<()> {
        if self.schema != Self::SCHEMA {
            anyhow::bail!("unsupported HMAC-key rotation schema {}", self.schema);
        }
        let rotation_id =
            uuid::Uuid::parse_str(&self.rotation_id).context("invalid HMAC-key rotation id")?;
        let canonical_id = rotation_id.hyphenated().to_string();
        if self.rotation_id != canonical_id
            || canonical_id.as_bytes().get(14).copied() != Some(b'7')
        {
            anyhow::bail!("HMAC-key rotation id must be a canonical UUIDv7");
        }
        require_sha256_hex(&self.new_key_sha256, "new_key_sha256")?;
        if let Some(previous) = &self.previous_key_storage_sha256 {
            require_sha256_hex(previous, "previous_key_storage_sha256")?;
        }
        if self.replaced != self.previous_key_storage_sha256.is_some() {
            anyhow::bail!("HMAC-key rotation replaced flag must match previous-key hash presence");
        }
        if !matches!(self.reason.as_str(), "rotate" | "rewrap") {
            anyhow::bail!("unsupported HMAC-key rotation reason {:?}", self.reason);
        }
        if self.ts_unix <= 0 {
            anyhow::bail!("HMAC-key rotation timestamp must be positive");
        }
        crate::wal::signing::verify_b64(&self.signer_pubkey, &self.sig, &self.canonical_bytes())
            .context("HMAC-key rotation signature is invalid")
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingHmacKeyRotation {
    schema: u8,
    payload: HmacKeyRotatedPayload,
    staged_file: String,
    archive_file: Option<String>,
}

impl PendingHmacKeyRotation {
    const SCHEMA: u8 = 1;

    fn validate(&self) -> Result<()> {
        if self.schema != Self::SCHEMA {
            anyhow::bail!(
                "unsupported pending HMAC-key rotation schema {}",
                self.schema
            );
        }
        self.payload.validate()?;
        validate_private_sibling_name(&self.staged_file, "staged_file")?;
        let expected_stage = format!("hmac.key.rotation-{}.next", self.payload.rotation_id);
        if self.staged_file != expected_stage {
            anyhow::bail!("pending HMAC-key rotation staged filename is inconsistent");
        }
        if let Some(archive) = &self.archive_file {
            validate_private_sibling_name(archive, "archive_file")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub(crate) struct HmacKeyRotationResult {
    pub(crate) payload: HmacKeyRotatedPayload,
    pub(crate) archive_path: Option<PathBuf>,
    pub(crate) recovered: bool,
}

impl HmacKeyRotationResult {
    pub(crate) fn ts_unix(&self) -> i64 {
        self.payload.ts_unix
    }

    fn replaced(&self) -> bool {
        self.payload.replaced
    }
}

fn require_sha256_hex(value: &str, field: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        anyhow::bail!("HMAC-key rotation {field} must be 64 lowercase hex characters");
    }
    Ok(())
}

fn validate_private_sibling_name(value: &str, field: &str) -> Result<()> {
    let path = Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || path
            .parent()
            .is_some_and(|parent| !parent.as_os_str().is_empty())
        || path.file_name().and_then(|name| name.to_str()) != Some(value)
    {
        anyhow::bail!("pending HMAC-key rotation {field} is not a safe sibling filename");
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn hmac_rotation_lock_path(key_path: &Path) -> PathBuf {
    key_path.with_file_name(format!(
        "{}.rotation.lock",
        key_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("hmac.key")
    ))
}

fn hmac_rotation_journal_path(key_path: &Path) -> PathBuf {
    key_path.with_file_name(format!(
        "{}.rotation.json",
        key_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("hmac.key")
    ))
}

fn current_key_storage_hash(key_path: &Path) -> Result<Option<String>> {
    match std::fs::read(key_path) {
        Ok(body) => Ok(Some(sha256_hex(&body))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("read HMAC key storage at {}", key_path.display()))
        }
    }
}

fn remove_rotation_file(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("remove {}", path.display())),
    }
}

fn sync_rotation_parent(path: &Path) -> Result<()> {
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)
            .with_context(|| format!("open HMAC-key rotation parent {}", parent.display()))?
            .sync_all()
            .with_context(|| format!("fsync HMAC-key rotation parent {}", parent.display()))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn sorted_wal_segments(wal_dir: &Path) -> Vec<PathBuf> {
    let mut segments = std::fs::read_dir(wal_dir)
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("wal"))
        .collect::<Vec<_>>();
    segments.sort();
    segments
}

/// Validate either a legacy v1 or crash-safe v2 HMAC rotation event against
/// the operator proof-key trust chain. This is the single trust decision used
/// by both transaction recovery and `verify --since-rotation`.
pub(crate) fn hmac_rotation_payload_is_trusted(
    payload: &[u8],
    trusted_pubkeys: &std::collections::BTreeSet<String>,
) -> bool {
    if trusted_pubkeys.is_empty() {
        return false;
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(payload) else {
        return false;
    };
    if value.get("schema").is_some() {
        let Ok(v2) = serde_json::from_value::<HmacKeyRotatedPayload>(value) else {
            return false;
        };
        return trusted_pubkeys.contains(&v2.signer_pubkey) && v2.validate().is_ok();
    }
    let new_key_sha256 = value["new_key_sha256"].as_str().unwrap_or("");
    let replaced = value["replaced"].as_bool().unwrap_or(false);
    let reason = value["reason"].as_str().unwrap_or("");
    let ts_unix = value["ts_unix"].as_i64().unwrap_or(0);
    let signer_pubkey = value["signer_pubkey"].as_str().unwrap_or("");
    let sig = value["sig"].as_str().unwrap_or("");
    let msg = rotation_authorisation_message(new_key_sha256, replaced, reason, ts_unix);
    trusted_pubkeys.contains(signer_pubkey)
        && crate::wal::signing::verify_b64(signer_pubkey, sig, &msg).is_ok()
}

fn hmac_rotation_event_is_durable(
    home: &Path,
    expected_payload: &[u8],
    signing_key_path: &Path,
) -> Result<bool> {
    let wal_dir = home.join("wal");
    let segments = sorted_wal_segments(&wal_dir);
    let trusted = crate::wal::signing::trusted_signing_pubkeys(&segments, signing_key_path);
    for segment in segments {
        let raw = match std::fs::read(&segment) {
            Ok(raw) => raw,
            Err(_) => continue,
        };
        let Ok((header_len, logical)) = crate::wal::compaction::logical_segment_bytes(&raw) else {
            continue;
        };
        let mut cursor = header_len;
        let mut found = false;
        while cursor < logical.len() {
            let Ok(frame) = crate::wal::frame::decode_frame(&logical[cursor..]) else {
                break;
            };
            let total = frame.header.total_len as usize;
            if frame.header.event_type == crate::wal::events::EVENT_TYPE_HMAC_KEY_ROTATED
                && frame.payload == expected_payload
                && hmac_rotation_payload_is_trusted(frame.payload, &trusted)
            {
                found = true;
                break;
            }
            if total == 0 {
                break;
            }
            cursor = cursor.saturating_add(total);
        }
        if !found {
            continue;
        }
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&segment)
            .with_context(|| format!("open HMAC-key rotation segment {}", segment.display()))?
            .sync_all()
            .with_context(|| format!("fsync HMAC-key rotation segment {}", segment.display()))?;
        sync_rotation_parent(&segment)?;
        return Ok(true);
    }
    Ok(false)
}

async fn append_hmac_key_rotated(home: &Path, daemon_live: bool, payload: &[u8]) -> Result<()> {
    if daemon_live {
        crate::daemon::audit_rpc::try_post_audit_frame(
            home,
            crate::wal::events::EVENT_TYPE_HMAC_KEY_ROTATED,
            payload,
        )
        .await
        .map_err(anyhow::Error::new)
        .context("running daemon refused the required HMAC-key rotation audit")?;
        return Ok(());
    }
    let wal_dir = home.join("wal");
    std::fs::create_dir_all(&wal_dir)
        .with_context(|| format!("create WAL directory {}", wal_dir.display()))?;
    let segment = crate::wal::writer::unique_standalone_segment_path(&wal_dir, "hmac-key-rotate");
    let (writer, join) = crate::wal::writer::spawn(segment)
        .context("spawn one-shot HMAC-key rotation WAL writer")?;
    let header =
        crate::wal::HeaderBuilder::new(crate::wal::events::EVENT_TYPE_HMAC_KEY_ROTATED, payload)
            .build();
    let append = writer
        .append(header, payload.to_vec())
        .await
        .context("append required HMAC-key rotation audit");
    drop(writer);
    join.await
        .context("join one-shot HMAC-key rotation WAL writer")?;
    append.map(|_| ())
}

fn load_pending_hmac_rotation(key_path: &Path) -> Result<Option<PendingHmacKeyRotation>> {
    let journal_path = hmac_rotation_journal_path(key_path);
    if !journal_path.exists() {
        return Ok(None);
    }
    let body = std::fs::read(&journal_path)
        .with_context(|| format!("read pending HMAC-key rotation {}", journal_path.display()))?;
    let pending: PendingHmacKeyRotation = serde_json::from_slice(&body)
        .with_context(|| format!("parse pending HMAC-key rotation {}", journal_path.display()))?;
    pending.validate()?;
    Ok(Some(pending))
}

fn pending_rotation_paths(
    key_path: &Path,
    pending: &PendingHmacKeyRotation,
) -> Result<(PathBuf, Option<PathBuf>)> {
    let parent = key_path
        .parent()
        .context("HMAC key path has no parent directory")?;
    Ok((
        parent.join(&pending.staged_file),
        pending.archive_file.as_ref().map(|name| parent.join(name)),
    ))
}

fn abort_pending_hmac_rotation(key_path: &Path, pending: &PendingHmacKeyRotation) -> Result<()> {
    let (staged_path, _) = pending_rotation_paths(key_path, pending)?;
    remove_rotation_file(&staged_path)?;
    remove_rotation_file(&hmac_rotation_journal_path(key_path))?;
    sync_rotation_parent(key_path)
}

fn commit_pending_hmac_rotation(
    key_path: &Path,
    pending: PendingHmacKeyRotation,
    recovered: bool,
) -> Result<HmacKeyRotationResult> {
    pending.validate()?;
    let (staged_path, archive_path) = pending_rotation_paths(key_path, &pending)?;
    let current_storage = current_key_storage_hash(key_path)?;
    if key_path.exists()
        && let Ok(current) = crate::wal::compaction::load_or_init_key(key_path)
        && sha256_hex(&current) == pending.payload.new_key_sha256
    {
        if let Some(archive) = &archive_path {
            let expected = pending
                .payload
                .previous_key_storage_sha256
                .as_deref()
                .context("committed HMAC archive has no signed predecessor hash")?;
            let archived = std::fs::read(archive).with_context(|| {
                format!("read committed HMAC key archive {}", archive.display())
            })?;
            if sha256_hex(&archived) != expected {
                anyhow::bail!(
                    "committed HMAC key archive {} does not match the signed predecessor",
                    archive.display()
                );
            }
        }
        remove_rotation_file(&staged_path)?;
        remove_rotation_file(&hmac_rotation_journal_path(key_path))?;
        sync_rotation_parent(key_path)?;
        return Ok(HmacKeyRotationResult {
            payload: pending.payload,
            archive_path,
            recovered: true,
        });
    }
    if current_storage != pending.payload.previous_key_storage_sha256 {
        anyhow::bail!(
            "pending HMAC-key rotation is stale: active key matches neither side of the signed transition"
        );
    }
    if !staged_path.exists() {
        anyhow::bail!(
            "pending HMAC-key rotation is audited but staged key {} is missing",
            staged_path.display()
        );
    }
    let staged = crate::wal::compaction::load_or_init_key(&staged_path)
        .context("load staged HMAC replacement key")?;
    if sha256_hex(&staged) != pending.payload.new_key_sha256 {
        anyhow::bail!("staged HMAC replacement key does not match the signed transition");
    }
    if let Some(archive) = &archive_path {
        let previous_hash = pending
            .payload
            .previous_key_storage_sha256
            .as_deref()
            .context("HMAC archive requested without a previous key")?;
        if archive.exists() {
            let existing = std::fs::read(archive)
                .with_context(|| format!("read HMAC key archive {}", archive.display()))?;
            if sha256_hex(&existing) != previous_hash {
                anyhow::bail!(
                    "HMAC key archive {} exists with unexpected contents",
                    archive.display()
                );
            }
        } else {
            let active = std::fs::read(key_path)
                .with_context(|| format!("read retiring HMAC key {}", key_path.display()))?;
            crate::util::atomic_write::atomic_write_private(archive, &active)
                .with_context(|| format!("write HMAC key archive {}", archive.display()))?;
        }
    }
    crate::wal::compaction::rewrap_key(key_path, &staged)
        .context("atomically install audited HMAC replacement key")?;
    let installed = crate::wal::compaction::load_or_init_key(key_path)
        .context("verify installed HMAC replacement key")?;
    if sha256_hex(&installed) != pending.payload.new_key_sha256 {
        anyhow::bail!("installed HMAC replacement key does not match the signed transition");
    }
    remove_rotation_file(&staged_path)?;
    remove_rotation_file(&hmac_rotation_journal_path(key_path))?;
    sync_rotation_parent(key_path)?;
    Ok(HmacKeyRotationResult {
        payload: pending.payload,
        archive_path,
        recovered,
    })
}

fn recover_pending_hmac_rotation_locked(
    home: &Path,
    key_path: &Path,
) -> Result<Option<HmacKeyRotationResult>> {
    let Some(pending) = load_pending_hmac_rotation(key_path)? else {
        return Ok(None);
    };
    let signing_key_path = home.join("wal").join("signing.key");
    let payload = serde_json::to_vec(&pending.payload)
        .context("serialize pending HMAC-key rotation payload")?;
    if hmac_rotation_event_is_durable(home, &payload, &signing_key_path)? {
        return commit_pending_hmac_rotation(key_path, pending, true).map(Some);
    }
    if key_path.exists()
        && crate::wal::compaction::load_or_init_key(key_path)
            .is_ok_and(|active| sha256_hex(&active) == pending.payload.new_key_sha256)
    {
        anyhow::bail!(
            "active HMAC key matches a pending replacement whose signed 0xD9 boundary is missing — refusing to erase recovery state"
        );
    }
    if current_key_storage_hash(key_path)? != pending.payload.previous_key_storage_sha256 {
        anyhow::bail!(
            "pending unaudited HMAC-key rotation is stale: active key no longer matches its signed predecessor"
        );
    }
    abort_pending_hmac_rotation(key_path, &pending)?;
    Ok(None)
}

/// Recover an interrupted HMAC rotation before a WAL writer loads the active
/// key. This prevents a restarted daemon from emitting an old-key compaction
/// marker after an already-durable 0xD9 boundary.
pub(crate) fn recover_hmac_key_rotation(
    home: &Path,
    key_path: &Path,
) -> Result<Option<HmacKeyRotationResult>> {
    let _lock = crate::util::locked_file::lock_file_blocking(
        &hmac_rotation_lock_path(key_path),
        "HMAC-key rotation",
    )?;
    recover_pending_hmac_rotation_locked(home, key_path)
}

/// Crash-recoverable HMAC key rotation shared by `keys rotate` and
/// `security rewrap-hmac-key`. The active key stays unchanged until the exact
/// signed 0xD9 transition is durable; a rerun completes an audited pending swap
/// or removes an unaudited stage before starting another rotation.
pub(crate) async fn rotate_hmac_key_with_audit(
    home: &Path,
    key_path: &Path,
    new_key: &[u8],
    reason: &str,
    archive_path: Option<PathBuf>,
) -> Result<HmacKeyRotationResult> {
    if new_key.len() < 16 {
        anyhow::bail!(
            "refusing to install HMAC key shorter than 16 bytes ({} given) — a weak key undermines WAL tamper-evidence",
            new_key.len()
        );
    }
    let _lock = crate::util::locked_file::lock_file_blocking(
        &hmac_rotation_lock_path(key_path),
        "HMAC-key rotation",
    )?;
    let daemon_live = match crate::daemon::pidfile::live_daemon_pid(&home.join("neothd.pid")) {
        Ok(Some(_)) => true,
        Ok(None) => false,
        Err(error) => anyhow::bail!(
            "cannot determine whether the daemon owns the WAL ({error}) — refusing HMAC-key rotation"
        ),
    };
    if daemon_live {
        anyhow::bail!(
            "a running daemon holds the current HMAC key in memory — stop it before rotating so no old-key compaction marker can land after the 0xD9 boundary"
        );
    }
    if let Some(recovered) = recover_pending_hmac_rotation_locked(home, key_path)? {
        return Ok(recovered);
    }
    let signing_key_path = home.join("wal").join("signing.key");
    let previous_key_storage_sha256 = current_key_storage_hash(key_path)?;
    let replaced = previous_key_storage_sha256.is_some();
    if archive_path.is_some() && !replaced {
        anyhow::bail!("cannot archive an HMAC key that does not exist");
    }
    if let Some(archive) = &archive_path {
        let parent = key_path
            .parent()
            .context("HMAC key path has no parent directory")?;
        if archive.parent() != Some(parent) {
            anyhow::bail!("HMAC key archive must be a sibling of the active key");
        }
        let name = archive
            .file_name()
            .and_then(|value| value.to_str())
            .context("HMAC key archive path has no UTF-8 filename")?;
        validate_private_sibling_name(name, "archive_file")?;
        if archive.exists() {
            anyhow::bail!("HMAC key archive already exists at {}", archive.display());
        }
    }
    let signing_key = crate::wal::signing::load_or_init_signing_key(&signing_key_path)
        .context("load operator signing key for HMAC-key rotation")?;
    let mut payload = HmacKeyRotatedPayload {
        schema: HmacKeyRotatedPayload::SCHEMA,
        rotation_id: uuid::Uuid::now_v7().hyphenated().to_string(),
        new_key_sha256: sha256_hex(new_key),
        previous_key_storage_sha256,
        replaced,
        reason: reason.to_owned(),
        ts_unix: crate::time::now_unix_i64(),
        signer_pubkey: crate::wal::signing::pubkey_b64(&signing_key),
        sig: String::new(),
    };
    payload.sig = crate::wal::signing::sign_b64(&signing_key, &payload.canonical_bytes());
    payload.validate()?;
    let parent = key_path
        .parent()
        .context("HMAC key path has no parent directory")?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("create HMAC key parent {}", parent.display()))?;
    let staged_file = format!("hmac.key.rotation-{}.next", payload.rotation_id);
    let staged_path = parent.join(&staged_file);
    let pending = PendingHmacKeyRotation {
        schema: PendingHmacKeyRotation::SCHEMA,
        payload,
        staged_file,
        archive_file: archive_path
            .as_ref()
            .and_then(|path| path.file_name())
            .and_then(|name| name.to_str())
            .map(str::to_owned),
    };
    pending.validate()?;
    let journal_path = hmac_rotation_journal_path(key_path);
    if staged_path.exists() || journal_path.exists() {
        anyhow::bail!("HMAC-key rotation transaction paths already exist");
    }
    let journal =
        serde_json::to_vec(&pending).context("serialize pending HMAC-key rotation journal")?;
    crate::util::atomic_write::atomic_write_private(&journal_path, &journal)
        .with_context(|| format!("write HMAC-key rotation journal {}", journal_path.display()))?;
    if let Err(error) = crate::wal::compaction::write_key_securely(&staged_path, new_key)
        .context("write staged HMAC replacement key")
    {
        let _ = remove_rotation_file(&journal_path);
        return Err(error);
    }
    sync_rotation_parent(key_path)?;
    let payload_bytes =
        serde_json::to_vec(&pending.payload).context("serialize HMAC-key rotation audit")?;
    if let Err(audit_error) = append_hmac_key_rotated(home, daemon_live, &payload_bytes).await
        && !hmac_rotation_event_is_durable(home, &payload_bytes, &signing_key_path)?
    {
        abort_pending_hmac_rotation(key_path, &pending)?;
        return Err(audit_error);
    }
    if !hmac_rotation_event_is_durable(home, &payload_bytes, &signing_key_path)? {
        anyhow::bail!("HMAC-key rotation audit append returned success but is not durable");
    }
    commit_pending_hmac_rotation(key_path, pending, false)
}

/// SC-09 (Session 28) — write the operator's WAL HMAC compaction key
/// to `args.output` in plaintext. Handles the DPAPI unwrap on Windows
/// (via `wal::compaction::load_or_init_key`); the operator sees the
/// raw bytes regardless of how they're stored on disk.
///
/// **Operator-visible warnings are deliberate**: this path is the
/// ONE place NEOTH legitimately emits a plaintext copy of the
/// HMAC key. Every line of stderr is one the operator should read.
pub(crate) fn resolve_hmac_backup_destination(home: &Path, output: &Path) -> Result<PathBuf> {
    if output.as_os_str().is_empty() || output.file_name().is_none() {
        anyhow::bail!("backup destination must name a file");
    }
    if output
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        anyhow::bail!(
            "backup destination must not contain `..`; enter the normalized destination path"
        );
    }

    let absolute = if output.is_absolute() {
        output.to_path_buf()
    } else {
        std::env::current_dir()
            .context("resolve current directory for HMAC backup destination")?
            .join(output)
    };
    let resolved_output = resolve_existing_path_prefix(&absolute)?;
    let resolved_home = resolve_existing_path_prefix(home)?;

    if resolved_output.starts_with(&resolved_home) {
        anyhow::bail!(
            "backup destination {} resolves inside NEOTH home {}; choose an offline/external path outside NEOTH home",
            output.display(),
            home.display()
        );
    }
    if resolved_output.is_dir() {
        anyhow::bail!(
            "backup destination {} is a directory; enter a file path",
            output.display()
        );
    }
    Ok(resolved_output)
}

/// Resolve symlinks/junctions in the deepest existing prefix while preserving a
/// not-yet-created filename or directory suffix. This lets destination checks
/// fail closed before creating the operator-selected backup directory.
fn resolve_existing_path_prefix(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("resolve current directory for path validation")?
            .join(path)
    };
    let mut existing = absolute;
    let mut missing = Vec::new();
    while !existing.exists() {
        let name = existing.file_name().ok_or_else(|| {
            anyhow::anyhow!("cannot resolve an existing ancestor for {}", path.display())
        })?;
        missing.push(name.to_os_string());
        if !existing.pop() {
            anyhow::bail!("cannot resolve an existing ancestor for {}", path.display());
        }
    }
    let mut resolved = std::fs::canonicalize(&existing)
        .with_context(|| format!("canonicalize path prefix {}", existing.display()))?;
    for component in missing.iter().rev() {
        resolved.push(component);
    }
    Ok(resolved)
}

pub fn run_backup_hmac_key(args: &BackupHmacKeyArgs) -> Result<()> {
    let home = args
        .home
        .clone()
        .unwrap_or_else(crate::config::FreedomConfig::default_neoth_home);
    let output = resolve_hmac_backup_destination(&home, &args.output)?;

    // Refuse overwrite unless --force. Catches the muscle-memory
    // mistake of re-running the same command (which would silently
    // replace an older backup that referred to a different key
    // rotation epoch).
    if output.exists() && !args.force {
        anyhow::bail!(
            "refusing to overwrite existing backup at {}; pass --force to replace",
            output.display()
        );
    }

    let key_path = home.join("wal").join("hmac.key");
    if !key_path.exists() {
        anyhow::bail!(
            "no HMAC key at {} — run `neoth init` first or wait for the first WAL frame to be written",
            key_path.display()
        );
    }
    let key_bytes = crate::wal::compaction::load_or_init_key(&key_path)?;

    // Ensure the parent dir exists so a fresh `--output ~/safe/key`
    // works without the operator pre-mkdiring.
    if let Some(parent) = output.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|e| anyhow::anyhow!("create backup parent {}: {e}", parent.display()))?;
    }

    write_backup_file(&output, &key_bytes, args.force)?;

    // stderr-only warnings — stdout is reserved for the operator-
    // visible success line so scripts that capture stdout get a
    // clean confirmation.
    eprintln!();
    eprintln!("[neoth security] PLAINTEXT BACKUP WRITTEN");
    eprintln!("[neoth security]   path:    {}", output.display());
    eprintln!(
        "[neoth security]   bytes:   {} (mode-0600 on Unix; owner DACL on Windows)",
        key_bytes.len()
    );
    eprintln!("[neoth security]");
    eprintln!("[neoth security] This file is the unwrapped HMAC key that protects your");
    eprintln!("[neoth security] WAL compaction markers. Anyone with read access can forge");
    eprintln!("[neoth security] historical audit-chain checkpoints.");
    eprintln!("[neoth security]");
    eprintln!("[neoth security] Recommended: move to a password manager / hardware token");
    eprintln!("[neoth security]   immediately; do NOT leave on the same disk as ~/.neoth.");
    eprintln!("[neoth security]   See PLAN/RUNBOOK_dpapi_hmac_recovery.md for the full recovery");
    eprintln!("[neoth security]   playbook (Tier 1 — re-wrap on new machine).");

    println!("backup written: {}", output.display());
    Ok(())
}

/// CRYPTO-04e — export the WAL/config AEAD master key as a portable RAW backup.
pub fn run_backup_master_key(args: &BackupMasterKeyArgs) -> Result<()> {
    let home = args
        .home
        .clone()
        .unwrap_or_else(crate::config::FreedomConfig::default_neoth_home);
    if args.output.exists() && !args.force {
        anyhow::bail!(
            "refusing to overwrite existing backup at {}; pass --force to replace",
            args.output.display()
        );
    }
    let src = crate::wal::master_key::master_key_path(&home);
    if !src.exists() {
        anyhow::bail!(
            "no master key at {} — WAL/config encryption is not enabled \
             (set freedom.yaml::wal.encryption: aes256_gcm_siv)",
            src.display()
        );
    }
    crate::wal::master_key::backup_master_key(&src, &args.output)?;
    eprintln!();
    eprintln!("[neoth security] MASTER-KEY BACKUP WRITTEN (raw, portable)");
    eprintln!("[neoth security]   path: {}", args.output.display());
    eprintln!("[neoth security] This is the AEAD master key for WAL + credentials at rest.");
    eprintln!("[neoth security] Store it OFFLINE (password manager / hardware token) — NOT on");
    eprintln!("[neoth security] the same disk as ~/.neoth. Losing it makes encrypted segments");
    eprintln!("[neoth security] + credentials PERMANENTLY unreadable.");
    println!("master-key backup written: {}", args.output.display());
    Ok(())
}

/// CRYPTO-04e — restore a RAW master-key backup, re-binding it to this machine.
pub fn run_restore_master_key(args: &RestoreMasterKeyArgs) -> Result<()> {
    let home = args
        .home
        .clone()
        .unwrap_or_else(crate::config::FreedomConfig::default_neoth_home);
    let raw = std::fs::read(&args.source)
        .map_err(|e| anyhow::anyhow!("read master-key backup {}: {e}", args.source.display()))?;
    let dst = crate::wal::master_key::master_key_path(&home);
    crate::wal::master_key::restore_master_key(&raw, &dst)?;
    eprintln!(
        "[neoth security] master key restored + re-bound to this machine: {}",
        dst.display()
    );
    eprintln!(
        "[neoth security] Restart the daemon — encrypted segments/credentials are readable again."
    );
    println!("master-key restored: {}", dst.display());
    Ok(())
}

/// Write the plaintext key with the canonical private-file helper (mode 0600 on
/// Unix; DACL-restricted temp on Windows). A zero-byte exclusive reservation
/// closes the no-force check/write race without ever exposing secret bytes.
fn write_backup_file(path: &Path, bytes: &[u8], force: bool) -> Result<()> {
    let reserved = if force {
        false
    } else {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    anyhow::anyhow!(
                        "refusing to overwrite existing backup at {}; pass --force to replace",
                        path.display()
                    )
                } else {
                    anyhow::anyhow!("reserve backup path {}: {e}", path.display())
                }
            })?;
        true
    };

    let result = crate::config::credentials::write_mode_0600(path, bytes)
        .with_context(|| format!("write private HMAC backup {}", path.display()));
    if result.is_err() && reserved {
        let _ = std::fs::remove_file(path);
    }
    result
}

/// Collect the audit report without printing — pure-fn variant so
/// tests can assert on `AuditReport` without parsing stdout.
pub fn run_audit_collect(args: &AuditArgs) -> Result<AuditReport> {
    let home = args
        .home
        .clone()
        .unwrap_or_else(FreedomConfig::default_neoth_home);
    let mut report = AuditReport::default();
    check_hmac_key(&home, &mut report);
    check_wal_segment(&home, &mut report);
    check_memory_drift(&home, args.drift_display_cap, &mut report);
    check_credential_files(&home, &mut report);
    check_permission_decisions(&home, args.permissions_lookback_hours, &mut report);
    Ok(report)
}

/// 5th check (SC-04 follow-on): summarise the operator's permission
/// decisions in the last `lookback_hours`. Always INFORMATIONAL — a
/// DENY is the fail-closed gate working, not a failure — but surfacing
/// the counts (+ the most-denied actions) puts "what did NEOTH refuse or
/// allow lately" one command away, on the verifiable-loyalty wedge.
/// Scans the latest WAL segment via `permissions::audit::audit_segment`.
fn check_permission_decisions(home: &Path, lookback_hours: u64, report: &mut AuditReport) {
    use crate::permissions::audit::{AuditDecision, audit_segment};
    let wal_dir = home.join("wal");
    let Some(segment) = latest_wal_segment(&wal_dir) else {
        report.push(
            "Permission decisions",
            CheckStatus::Ok,
            format!("no WAL segment yet (last {lookback_hours}h) — nothing decided"),
        );
        return;
    };
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(i64::MAX);
    let from_ns = now_ns.saturating_sub(
        (lookback_hours as i64)
            .saturating_mul(3_600)
            .saturating_mul(1_000_000_000),
    );
    let rep = match audit_segment(&segment, from_ns, now_ns, 5) {
        Ok(r) => r,
        Err(e) => {
            report.push(
                // GR-fix: fail loud. audit.rs contracts "a security audit MUST fail
                // loud on a corrupt segment rather than silently report a clean
                // trail" — a Warn let `neoth doctor` stay green on an unreadable
                // permission audit. Fail aligns the caller with that contract.
                "Permission decisions",
                CheckStatus::Fail,
                format!(
                    "could not read permission audit from {}: {e}",
                    segment.display()
                ),
            );
            return;
        }
    };
    let count = |d: AuditDecision| rep.by_decision.get(&d).copied().unwrap_or(0);
    let mut detail = format!(
        "last {lookback_hours}h: {} granted, {} denied, {} consent-allow, {} consent-deny",
        count(AuditDecision::Granted),
        count(AuditDecision::Denied),
        count(AuditDecision::ConsentAllow),
        count(AuditDecision::ConsentDeny),
    );
    if !rep.top_denied_actions.is_empty() {
        let top = rep
            .top_denied_actions
            .iter()
            .map(|(a, n)| format!("{a}×{n}"))
            .collect::<Vec<_>>()
            .join(", ");
        detail.push_str(&format!("\nmost-denied: {top}"));
    }
    detail.push_str(
        "\nFull trail: `neoth permissions audit` — denials are the fail-closed gate working.",
    );
    report.push("Permission decisions", CheckStatus::Ok, detail);
}

/// Lexically-latest `*.wal` in `wal_dir` (zero-padded segment names sort
/// chronologically). `None` when the dir is missing or empty.
fn latest_wal_segment(wal_dir: &Path) -> Option<PathBuf> {
    let mut latest: Option<PathBuf> = None;
    for entry in std::fs::read_dir(wal_dir).ok()?.flatten() {
        let p = entry.path();
        if p.extension().and_then(|s| s.to_str()) != Some("wal") {
            continue;
        }
        if latest.as_ref().map(|l| &p > l).unwrap_or(true) {
            latest = Some(p);
        }
    }
    latest
}

fn check_hmac_key(home: &Path, report: &mut AuditReport) {
    // The HMAC key lives at `~/.neoth/wal/hmac.key` (see
    // `compaction::default_key_path`, `doctor::check_hmac_key`,
    // backup/rewrap). The audit previously looked at a flat
    // `wal_hmac_key` path that never exists on a real install → it
    // always reported a false FAIL for the tamper-evidence key.
    let key_path = home.join("wal").join("hmac.key");
    if !key_path.exists() {
        report.push(
            "HMAC compaction key",
            CheckStatus::Fail,
            format!("missing at {}", key_path.display()),
        );
        return;
    }
    let metadata = match std::fs::metadata(&key_path) {
        Ok(m) => m,
        Err(e) => {
            report.push(
                "HMAC compaction key",
                CheckStatus::Fail,
                format!("stat failed at {}: {e}", key_path.display()),
            );
            return;
        }
    };
    if metadata.len() == 0 {
        report.push(
            "HMAC compaction key",
            CheckStatus::Fail,
            format!("zero-length file at {}", key_path.display()),
        );
        return;
    }
    // Unix perm check — readable to owner only (mode 0600). On
    // Windows the DACL check ships in SC-08 (K-Sec-4 already restricts
    // via SetNamedSecurityInfoW); audit here just confirms presence.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            report.push(
                "HMAC compaction key",
                CheckStatus::Fail,
                format!("permissions {mode:o} too permissive (need 0600 or stricter)"),
            );
            return;
        }
        report.push(
            "HMAC compaction key",
            CheckStatus::Ok,
            format!(
                "{} ({} bytes, mode {:o})",
                key_path.display(),
                metadata.len(),
                mode
            ),
        );
    }
    #[cfg(not(unix))]
    {
        report.push(
            "HMAC compaction key",
            CheckStatus::Ok,
            format!(
                "{} ({} bytes; Windows DACL check via K-Sec-4)",
                key_path.display(),
                metadata.len()
            ),
        );
    }
}

fn check_wal_segment(home: &Path, report: &mut AuditReport) {
    let wal_dir = home.join("wal");
    if !wal_dir.exists() {
        report.push(
            "WAL segment health",
            CheckStatus::Warn,
            format!(
                "no WAL directory yet at {} (fresh install)",
                wal_dir.display()
            ),
        );
        return;
    }
    let mut latest: Option<(PathBuf, u64)> = None;
    let read_dir = match std::fs::read_dir(&wal_dir) {
        Ok(d) => d,
        Err(e) => {
            report.push(
                "WAL segment health",
                CheckStatus::Fail,
                format!("read_dir failed at {}: {e}", wal_dir.display()),
            );
            return;
        }
    };
    for entry in read_dir.flatten() {
        let p = entry.path();
        if p.extension().and_then(|s| s.to_str()) != Some("wal") {
            continue;
        }
        let size = match entry.metadata() {
            Ok(m) => m.len(),
            Err(_) => continue,
        };
        if latest.as_ref().map(|(lp, _)| &p > lp).unwrap_or(true) {
            latest = Some((p, size));
        }
    }
    match latest {
        None => report.push(
            "WAL segment health",
            CheckStatus::Warn,
            format!("no .wal files in {} yet", wal_dir.display()),
        ),
        Some((p, 0)) => report.push(
            "WAL segment health",
            CheckStatus::Warn,
            format!("latest segment {} is empty", p.display()),
        ),
        Some((p, size)) => report.push(
            "WAL segment health",
            CheckStatus::Ok,
            format!("latest segment {} ({} bytes)", p.display(), size),
        ),
    }
}

fn check_memory_drift(home: &Path, display_cap: usize, report: &mut AuditReport) {
    let views_path = home.join("views.db");
    if !views_path.exists() {
        report.push(
            "Memory drift (Hippocampus)",
            CheckStatus::Warn,
            format!(
                "no views.db at {} yet (fresh install / no episodes)",
                views_path.display()
            ),
        );
        return;
    }
    let conn = match crate::memory::store::open(&views_path) {
        Ok(c) => c,
        Err(e) => {
            report.push(
                "Memory drift (Hippocampus)",
                CheckStatus::Fail,
                format!("views.db open failed: {e}"),
            );
            return;
        }
    };
    let drift = match crate::memory::drift::drift_report(&conn, display_cap) {
        Ok(r) => r,
        Err(e) => {
            report.push(
                "Memory drift (Hippocampus)",
                CheckStatus::Fail,
                format!("drift query failed: {e}"),
            );
            return;
        }
    };
    let detail = format!(
        "imminent={} at_risk={} stable={}",
        drift.imminent_count, drift.at_risk_count, drift.stable_count
    );
    let status = if drift.imminent_count > 0 {
        CheckStatus::Warn
    } else {
        CheckStatus::Ok
    };
    report.push("Memory drift (Hippocampus)", status, detail);
}

fn check_credential_files(home: &Path, report: &mut AuditReport) {
    // Look for the optional credential-import sidecar files the
    // wizard's step-6g writes. Their presence isn't a failure —
    // they should be transient (consumed by the daemon's next
    // boot). A stale sidecar > 7 days suggests the daemon never
    // started + the operator's credential import is in limbo.
    let mut found_sidecar = false;
    let mut stale_count = 0usize;
    if let Ok(entries) = std::fs::read_dir(home) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with("credentials_import_") || !name.ends_with(".json") {
                continue;
            }
            found_sidecar = true;
            if let Ok(meta) = entry.metadata()
                && let Ok(modified) = meta.modified()
                && let Ok(age) = modified.elapsed()
                && age.as_secs() > 7 * 24 * 3600
            {
                stale_count += 1;
            }
        }
    }
    if !found_sidecar {
        report.push(
            "Credential import sidecars",
            CheckStatus::Ok,
            "no pending sidecars (all clean)".to_string(),
        );
        return;
    }
    if stale_count > 0 {
        report.push(
            "Credential import sidecars",
            CheckStatus::Warn,
            format!("{stale_count} sidecar(s) > 7 days old — daemon may not be running"),
        );
    } else {
        report.push(
            "Credential import sidecars",
            CheckStatus::Ok,
            "sidecar(s) present + recent (daemon should consume on next boot)".to_string(),
        );
    }
}

fn print_report(report: &AuditReport) {
    println!("== neoth security audit ==");
    println!();
    for c in &report.checks {
        println!("{}  {}  — {}", c.status.marker(), c.name, c.detail);
    }
    let (ok, warn, fail) = report.counts();
    println!();
    println!("Summary: {ok} ok / {warn} warn / {fail} fail");
    if fail > 0 {
        println!();
        println!("Exit code 1 — at least one check FAILed.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;
    use tempfile::TempDir;

    #[test]
    fn smart_approve_cli_contract_uses_the_canonical_security_path() {
        for flag in ["--enable", "--disable"] {
            assert!(
                crate::cli::Cli::try_parse_from([
                    "neoth",
                    "--output",
                    "json",
                    "security",
                    "set",
                    "smart-approve",
                    flag,
                ])
                .is_ok(),
                "canonical Smart-Approve command rejected {flag}"
            );
        }
        assert!(
            crate::cli::Cli::try_parse_from([
                "neoth",
                "security",
                "set",
                "smart-approve",
                "--enable",
                "--disable",
            ])
            .is_err(),
            "mutually exclusive policy states must not parse together"
        );
    }

    #[test]
    fn smart_approve_setter_reports_change_and_preserves_other_policy() {
        let mut cfg = FreedomConfig::default();
        let baseline = cfg.security.clone();

        assert!(apply_smart_approve(&mut cfg, true));
        assert!(cfg.security.smart_approve);
        let mut normalized = cfg.security.clone();
        normalized.smart_approve = baseline.smart_approve;
        assert_eq!(normalized, baseline, "only the master switch may change");

        assert!(
            !apply_smart_approve(&mut cfg, true),
            "idempotent enable must report unchanged"
        );
        assert!(apply_smart_approve(&mut cfg, false));
        assert!(!cfg.security.smart_approve);
    }

    // ── GR-10 safe-mode rails ─────────────────────────────────────────

    fn rail<'a>(rails: &'a [Rail], name: &str) -> &'a Rail {
        rails
            .iter()
            .find(|r| r.name == name)
            .unwrap_or_else(|| panic!("rail `{name}` missing"))
    }

    #[test]
    fn safe_mode_default_config_engages_protective_rails() {
        // A fresh install's protective defaults must read as ENGAGED.
        let cfg = FreedomConfig::default();
        let rails = collect_rails(&cfg);
        assert_eq!(rails.len(), 19, "all rails surfaced");
        for name in [
            "autonomy_gate",              // default Standard = gated
            "private_inference",          // default no cloud fallback
            "proactive_messaging",        // default off
            "cluster_transport",          // default off
            "os_file_tools",              // default empty allowlists = deny-all
            "os_app_launch",              // default empty exec allowlist = deny-all
            "email_llm_tiebreak",         // default off = no LLM sees mail
            "email_downgrade_allowed",    // default denied = no LLM auto-deliver
            "omi_ingest",                 // default off = no passive ingest
            "ecology_scheduler",          // default off = no auto-scheduler
            "channel_weight_learning",    // default operator_only = poison-resistant
            "cloud_stt_enabled",          // default off = audio stays on-device
            "cloud_tts_enabled",          // default off = text stays on-device
            "cloud_vision_enabled",       // default off = no images to cloud
            "video_frame_upload_enabled", // default off = no frames to cloud
        ] {
            assert!(
                rail(&rails, name).engaged,
                "{name} must be engaged on a default install"
            );
        }
        // These two power surfaces ship OPEN (usable) by default — the rail
        // makes that VISIBLE rather than hiding it in freedom.yaml. They are
        // still autonomy-gated + audited; the rail is the at-a-glance signal.
        for name in ["calendar_writes", "live_delivery_edits"] {
            assert!(
                !rail(&rails, name).engaged,
                "{name} ships open by default (visible, not hidden)"
            );
        }
    }

    #[test]
    fn omi_rail_reports_the_selected_network_boundary_truthfully() {
        let mut cfg = FreedomConfig::default();
        cfg.omi.enabled = true;
        cfg.omi.endpoint = "https://api.omi.me".to_string();
        cfg.omi.allow_cloud_api = true;
        let rails = collect_rails(&cfg);
        let detail = &rail(&rails, "omi_ingest").detail;
        assert!(detail.contains("Developer API https://api.omi.me"));
        assert!(detail.contains("public HTTPS explicitly allowed"));
        assert!(!detail.contains("LOCAL-only"));

        cfg.omi.mode = crate::config::OmiIngestMode::NativeIngest;
        cfg.omi.listen_addr = "127.0.0.1:8003".to_string();
        let rails = collect_rails(&cfg);
        let detail = &rail(&rails, "omi_ingest").detail;
        assert!(detail.contains("authenticated native listener 127.0.0.1:8003"));
        assert!(!detail.contains(&cfg.omi.endpoint));
    }

    #[test]
    fn safe_mode_email_downgrade_relaxes_when_allowed() {
        // The DANGEROUS switch must read as RELAXED when the operator opts in,
        // so it's visible in the security surface.
        let mut cfg = FreedomConfig::default();
        cfg.email.llm_tiebreak = true;
        cfg.email.llm_tiebreak_allow_downgrade = true;
        let rails = collect_rails(&cfg);
        assert!(!rail(&rails, "email_llm_tiebreak").engaged);
        let downgrade = rail(&rails, "email_downgrade_allowed");
        assert!(!downgrade.engaged, "downgrade-allowed must read RELAXED");
        assert!(downgrade.detail.to_lowercase().contains("auto-deliver"));
    }

    #[test]
    fn safe_mode_full_autonomy_relaxes_the_gate() {
        let mut cfg = FreedomConfig::default();
        cfg.autonomy = crate::permissions::AutonomyLevel::Full;
        let rails = collect_rails(&cfg);
        assert!(
            !rail(&rails, "autonomy_gate").engaged,
            "full autonomy relaxes the gate"
        );
        assert!(rail(&rails, "autonomy_gate").detail.contains("full"));
    }

    #[test]
    fn safe_mode_cloud_fallback_relaxes_private_inference() {
        let mut cfg = FreedomConfig::default();
        cfg.profile.allow_cloud_fallback = true;
        let rails = collect_rails(&cfg);
        assert!(!rail(&rails, "private_inference").engaged);
        assert!(
            rail(&rails, "private_inference")
                .detail
                .contains("cloud fallback ALLOWED")
        );
    }

    #[test]
    fn safe_mode_os_tools_relax_when_paths_allowlisted() {
        let mut cfg = FreedomConfig::default();
        cfg.tools
            .os
            .allowed_paths
            .push(std::path::PathBuf::from("/tmp/ok"));
        let rails = collect_rails(&cfg);
        assert!(
            !rail(&rails, "os_file_tools").engaged,
            "a non-empty allowlist relaxes the deny-all rail"
        );
    }

    #[test]
    fn safe_mode_exec_rail_relaxes_when_binary_allowlisted() {
        // The exec rail is independent of the file rails: allowlisting an
        // executable relaxes os_app_launch while os_file_tools stays engaged.
        let mut cfg = FreedomConfig::default();
        cfg.tools
            .os
            .allowed_exec_paths
            .push(std::path::PathBuf::from("/usr/bin/firefox"));
        let rails = collect_rails(&cfg);
        assert!(
            !rail(&rails, "os_app_launch").engaged,
            "a non-empty exec allowlist relaxes the launch rail"
        );
        assert!(
            rail(&rails, "os_file_tools").engaged,
            "file tools stay deny-all — exec allowlist must not relax them"
        );
    }

    #[test]
    fn safe_mode_render_marks_engaged_and_relaxed() {
        let mut cfg = FreedomConfig::default();
        cfg.autonomy = crate::permissions::AutonomyLevel::Full; // one relaxed
        let out = render_rails(&collect_rails(&cfg));
        assert!(out.contains("[ENGAGED]"), "engaged rails rendered");
        assert!(out.contains("[RELAXED]"), "relaxed rails rendered");
        assert!(out.contains("rails engaged"), "summary line present");
        assert!(out.contains("autonomy_gate"));
    }

    fn write_file(path: &Path, contents: &[u8]) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, contents).unwrap();
    }

    fn empty_audit_args(home: &Path) -> AuditArgs {
        AuditArgs {
            home: Some(home.to_path_buf()),
            permissions_lookback_hours: 24,
            drift_display_cap: 10,
        }
    }

    #[test]
    fn check_status_markers_canonical() {
        assert_eq!(CheckStatus::Ok.marker(), "[ OK ]");
        assert_eq!(CheckStatus::Warn.marker(), "[WARN]");
        assert_eq!(CheckStatus::Fail.marker(), "[FAIL]");
    }

    #[test]
    fn empty_report_exit_zero() {
        let r = AuditReport::default();
        assert_eq!(r.exit_code(), 0);
        assert_eq!(r.counts(), (0, 0, 0));
    }

    #[test]
    fn report_with_only_ok_exits_zero() {
        let mut r = AuditReport::default();
        r.push("a", CheckStatus::Ok, "ok");
        r.push("b", CheckStatus::Ok, "ok");
        assert_eq!(r.exit_code(), 0);
        assert_eq!(r.counts(), (2, 0, 0));
    }

    #[test]
    fn report_with_warn_still_exits_zero() {
        let mut r = AuditReport::default();
        r.push("a", CheckStatus::Ok, "ok");
        r.push("b", CheckStatus::Warn, "fyi");
        assert_eq!(r.exit_code(), 0, "warn must NOT trigger non-zero exit");
        assert_eq!(r.counts(), (1, 1, 0));
    }

    #[test]
    fn report_with_fail_exits_one() {
        let mut r = AuditReport::default();
        r.push("a", CheckStatus::Ok, "ok");
        r.push("b", CheckStatus::Fail, "broken");
        assert_eq!(r.exit_code(), 1);
        assert_eq!(r.counts(), (1, 0, 1));
    }

    // ── check_hmac_key ────────────────────────────────────────────

    #[test]
    fn hmac_key_missing_fails() {
        let tmp = TempDir::new().unwrap();
        let mut report = AuditReport::default();
        check_hmac_key(tmp.path(), &mut report);
        let c = &report.checks[0];
        assert_eq!(c.status, CheckStatus::Fail);
        assert!(c.detail.contains("missing"));
    }

    #[test]
    fn hmac_key_empty_fails() {
        let tmp = TempDir::new().unwrap();
        write_file(&tmp.path().join("wal").join("hmac.key"), b"");
        let mut report = AuditReport::default();
        check_hmac_key(tmp.path(), &mut report);
        let c = &report.checks[0];
        assert_eq!(c.status, CheckStatus::Fail);
        assert!(c.detail.contains("zero-length"));
    }

    #[cfg(unix)]
    #[test]
    fn hmac_key_with_secure_mode_passes() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("wal").join("hmac.key");
        write_file(&path, b"0123456789abcdef");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut report = AuditReport::default();
        check_hmac_key(tmp.path(), &mut report);
        let c = &report.checks[0];
        assert_eq!(c.status, CheckStatus::Ok);
    }

    #[cfg(unix)]
    #[test]
    fn hmac_key_world_readable_fails() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("wal").join("hmac.key");
        write_file(&path, b"0123456789abcdef");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let mut report = AuditReport::default();
        check_hmac_key(tmp.path(), &mut report);
        let c = &report.checks[0];
        assert_eq!(c.status, CheckStatus::Fail);
        assert!(c.detail.contains("too permissive"));
    }

    #[cfg(windows)]
    #[test]
    fn hmac_key_with_content_passes_on_windows() {
        let tmp = TempDir::new().unwrap();
        write_file(
            &tmp.path().join("wal").join("hmac.key"),
            b"0123456789abcdef",
        );
        let mut report = AuditReport::default();
        check_hmac_key(tmp.path(), &mut report);
        let c = &report.checks[0];
        assert_eq!(c.status, CheckStatus::Ok);
        assert!(c.detail.contains("Windows DACL"));
    }

    // ── check_wal_segment ─────────────────────────────────────────

    #[test]
    fn wal_segment_no_dir_warns() {
        let tmp = TempDir::new().unwrap();
        let mut report = AuditReport::default();
        check_wal_segment(tmp.path(), &mut report);
        let c = &report.checks[0];
        assert_eq!(c.status, CheckStatus::Warn);
        assert!(c.detail.contains("fresh install"));
    }

    #[test]
    fn wal_segment_empty_dir_warns() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("wal")).unwrap();
        let mut report = AuditReport::default();
        check_wal_segment(tmp.path(), &mut report);
        let c = &report.checks[0];
        assert_eq!(c.status, CheckStatus::Warn);
        assert!(c.detail.contains("no .wal files"));
    }

    #[test]
    fn wal_segment_zero_length_warns() {
        let tmp = TempDir::new().unwrap();
        write_file(&tmp.path().join("wal").join("000001.wal"), b"");
        let mut report = AuditReport::default();
        check_wal_segment(tmp.path(), &mut report);
        let c = &report.checks[0];
        assert_eq!(c.status, CheckStatus::Warn);
        assert!(c.detail.contains("empty"));
    }

    #[test]
    fn wal_segment_with_content_passes() {
        let tmp = TempDir::new().unwrap();
        write_file(
            &tmp.path().join("wal").join("000001.wal"),
            b"some-bytes-here",
        );
        let mut report = AuditReport::default();
        check_wal_segment(tmp.path(), &mut report);
        let c = &report.checks[0];
        assert_eq!(c.status, CheckStatus::Ok);
        assert!(c.detail.contains("15 bytes"));
    }

    // ── check_credential_files ────────────────────────────────────

    #[test]
    fn credential_sidecars_none_passes() {
        let tmp = TempDir::new().unwrap();
        let mut report = AuditReport::default();
        check_credential_files(tmp.path(), &mut report);
        let c = &report.checks[0];
        assert_eq!(c.status, CheckStatus::Ok);
        assert!(c.detail.contains("no pending"));
    }

    #[test]
    fn credential_sidecars_recent_passes() {
        let tmp = TempDir::new().unwrap();
        write_file(
            &tmp.path().join("credentials_import_1700000000.json"),
            b"{}",
        );
        let mut report = AuditReport::default();
        check_credential_files(tmp.path(), &mut report);
        let c = &report.checks[0];
        assert_eq!(c.status, CheckStatus::Ok);
        assert!(c.detail.contains("present"));
    }

    // ── end-to-end run_audit_collect ──────────────────────────────

    #[test]
    fn run_audit_collect_on_empty_home_produces_expected_count() {
        let tmp = TempDir::new().unwrap();
        let args = empty_audit_args(tmp.path());
        let report = run_audit_collect(&args).unwrap();
        assert_eq!(report.checks.len(), 5, "5 checks ship in this revision");
        // On an empty home: HMAC missing (Fail), WAL absent (Warn),
        // drift absent (Warn), sidecars none (Ok), permission decisions
        // none (Ok). Exit code 1 due to the HMAC fail.
        assert_eq!(report.exit_code(), 1);
    }

    #[test]
    fn permission_decisions_check_is_wired_and_ok_on_empty_home() {
        // SC-04 5th check: present in the report, and on a fresh install
        // (no WAL) it is Ok with "nothing decided" — never a false FAIL.
        let tmp = TempDir::new().unwrap();
        let report = run_audit_collect(&empty_audit_args(tmp.path())).unwrap();
        let pd = report
            .checks
            .iter()
            .find(|c| c.name == "Permission decisions")
            .expect("the permission-decisions check must be wired");
        assert!(matches!(pd.status, CheckStatus::Ok));
        assert!(pd.detail.contains("nothing decided"), "got: {}", pd.detail);
    }

    #[test]
    fn latest_wal_segment_picks_lexically_latest() {
        let tmp = TempDir::new().unwrap();
        let wal = tmp.path().join("wal");
        std::fs::create_dir_all(&wal).unwrap();
        assert_eq!(latest_wal_segment(&wal), None, "empty dir → None");
        std::fs::write(wal.join("000001.wal"), b"a").unwrap();
        std::fs::write(wal.join("000007.wal"), b"b").unwrap();
        std::fs::write(wal.join("notes.txt"), b"c").unwrap();
        assert_eq!(latest_wal_segment(&wal), Some(wal.join("000007.wal")));
    }

    // ── SC-09 backup-hmac-key ─────────────────────────────────────

    fn seed_hmac_key(home: &Path) -> std::path::PathBuf {
        // Generate a real key via load_or_init_key so the test
        // exercises the unwrap path the operator would hit.
        let key_path = home.join("wal").join("hmac.key");
        crate::wal::compaction::load_or_init_key(&key_path).unwrap();
        key_path
    }

    #[test]
    fn backup_refuses_when_no_hmac_key_present() {
        let home = TempDir::new().unwrap();
        let out = TempDir::new().unwrap();
        let args = BackupHmacKeyArgs {
            output: out.path().join("missing.key"),
            force: false,
            home: Some(home.path().to_path_buf()),
        };
        let err = run_backup_hmac_key(&args).unwrap_err();
        assert!(
            err.to_string().contains("no HMAC key at"),
            "expected missing-key error; got {err}"
        );
        assert!(
            !args.output.exists(),
            "no backup file may be created when source missing"
        );
    }

    #[test]
    fn backup_writes_plaintext_key_when_source_present() {
        let home = TempDir::new().unwrap();
        seed_hmac_key(home.path());
        let out = TempDir::new().unwrap();
        let dest = out.path().join("backup.key");
        let args = BackupHmacKeyArgs {
            output: dest.clone(),
            force: false,
            home: Some(home.path().to_path_buf()),
        };
        run_backup_hmac_key(&args).unwrap();
        assert!(dest.exists(), "backup file must be created");
        let bytes = std::fs::read(&dest).unwrap();
        // load_or_init_key returns ≥16 bytes (the under-16 check
        // refuses weak keys); a fresh key is exactly 32.
        assert!(bytes.len() >= 16, "key must be at least 16 bytes");
    }

    #[test]
    fn backup_refuses_to_overwrite_existing_without_force() {
        let home = TempDir::new().unwrap();
        seed_hmac_key(home.path());
        let out = TempDir::new().unwrap();
        let dest = out.path().join("backup.key");
        // Pre-create a sentinel file at the destination.
        std::fs::write(&dest, b"older-backup-sentinel").unwrap();
        let args = BackupHmacKeyArgs {
            output: dest.clone(),
            force: false,
            home: Some(home.path().to_path_buf()),
        };
        let err = run_backup_hmac_key(&args).unwrap_err();
        assert!(
            err.to_string().contains("refusing to overwrite"),
            "expected overwrite-refusal; got {err}"
        );
        // Sentinel must still be there — no clobber.
        let body = std::fs::read(&dest).unwrap();
        assert_eq!(body, b"older-backup-sentinel");
    }

    #[test]
    fn backup_overwrites_with_force_flag() {
        let home = TempDir::new().unwrap();
        seed_hmac_key(home.path());
        let out = TempDir::new().unwrap();
        let dest = out.path().join("backup.key");
        std::fs::write(&dest, b"older-backup").unwrap();
        let args = BackupHmacKeyArgs {
            output: dest.clone(),
            force: true,
            home: Some(home.path().to_path_buf()),
        };
        run_backup_hmac_key(&args).unwrap();
        let body = std::fs::read(&dest).unwrap();
        assert_ne!(body, b"older-backup", "old content must be replaced");
        assert!(body.len() >= 16, "new content is the real key bytes");
    }

    #[test]
    fn backup_round_trip_matches_load_or_init_key() {
        // Backup bytes MUST equal what `load_or_init_key` returns —
        // proves an operator can later import the backup back via
        // the shipped `rewrap-hmac-key` path. Drift guard against any
        // accidental transformation in write_backup_file (e.g.
        // line-ending munging).
        let home = TempDir::new().unwrap();
        let key_path = seed_hmac_key(home.path());
        let expected = crate::wal::compaction::load_or_init_key(&key_path).unwrap();
        let out = TempDir::new().unwrap();
        let dest = out.path().join("backup.key");
        let args = BackupHmacKeyArgs {
            output: dest.clone(),
            force: false,
            home: Some(home.path().to_path_buf()),
        };
        run_backup_hmac_key(&args).unwrap();
        let backup_bytes = std::fs::read(&dest).unwrap();
        assert_eq!(
            backup_bytes, expected,
            "backup bytes must match unwrapped HMAC key bytes round-trip"
        );
    }

    #[test]
    fn backup_creates_missing_parent_directory() {
        let home = TempDir::new().unwrap();
        seed_hmac_key(home.path());
        let out = TempDir::new().unwrap();
        // Destination two dirs deep — parent doesn't exist yet.
        let dest = out.path().join("nested").join("sub").join("k.key");
        let args = BackupHmacKeyArgs {
            output: dest.clone(),
            force: false,
            home: Some(home.path().to_path_buf()),
        };
        run_backup_hmac_key(&args).unwrap();
        assert!(dest.exists(), "parent dirs must be created on demand");
    }

    #[cfg(unix)]
    #[test]
    fn backup_file_is_mode_0600_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let home = TempDir::new().unwrap();
        seed_hmac_key(home.path());
        let out = TempDir::new().unwrap();
        let dest = out.path().join("backup.key");
        let args = BackupHmacKeyArgs {
            output: dest.clone(),
            force: false,
            home: Some(home.path().to_path_buf()),
        };
        run_backup_hmac_key(&args).unwrap();
        let meta = std::fs::metadata(&dest).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "backup file MUST be mode-0600 (operator-only); got {mode:o}"
        );
    }

    // ── SC-09: rewrap-hmac-key (Tier-1 recovery) ──────────────────────

    #[tokio::test]
    async fn rewrap_refuses_missing_source() {
        let home = TempDir::new().unwrap();
        let out = TempDir::new().unwrap();
        let args = RewrapHmacKeyArgs {
            source: out.path().join("absent.key"),
            home: Some(home.path().to_path_buf()),
        };
        let err = run_rewrap_hmac_key(&args).await.unwrap_err();
        assert!(
            err.to_string().contains("no plaintext key backup"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn rewrap_refuses_weak_source_key() {
        let home = TempDir::new().unwrap();
        let out = TempDir::new().unwrap();
        let src = out.path().join("weak.key");
        write_file(&src, b"short"); // < 16 bytes
        let args = RewrapHmacKeyArgs {
            source: src,
            home: Some(home.path().to_path_buf()),
        };
        let err = run_rewrap_hmac_key(&args).await.unwrap_err();
        assert!(
            err.to_string().contains("shorter than 16 bytes"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn rewrap_installs_and_roundtrips_via_load() {
        let home = TempDir::new().unwrap();
        let out = TempDir::new().unwrap();
        let src = out.path().join("backup.key");
        let raw = vec![5u8; 32];
        write_file(&src, &raw);
        let args = RewrapHmacKeyArgs {
            source: src,
            home: Some(home.path().to_path_buf()),
        };
        run_rewrap_hmac_key(&args).await.unwrap();
        let key_path = home.path().join("wal").join("hmac.key");
        let loaded = crate::wal::compaction::load_or_init_key(&key_path).unwrap();
        assert_eq!(
            loaded, raw,
            "re-wrapped key must load back to the backup bytes"
        );
    }

    #[tokio::test]
    async fn rewrap_overwrites_existing_live_key() {
        let home = TempDir::new().unwrap();
        seed_hmac_key(home.path()); // existing (different) key on disk
        let out = TempDir::new().unwrap();
        let src = out.path().join("backup.key");
        let raw = vec![3u8; 32];
        write_file(&src, &raw);
        let args = RewrapHmacKeyArgs {
            source: src,
            home: Some(home.path().to_path_buf()),
        };
        run_rewrap_hmac_key(&args).await.unwrap();
        let key_path = home.path().join("wal").join("hmac.key");
        let loaded = crate::wal::compaction::load_or_init_key(&key_path).unwrap();
        assert_eq!(loaded, raw, "rewrap must overwrite the prior live key");
    }

    #[tokio::test]
    async fn rewrap_emits_hmac_key_rotated_frame() {
        // SC-09-A: a successful rewrap (no daemon) records a 0xD9 boundary frame
        // carrying the SHA-256 of the installed key — never the raw bytes.
        use sha2::{Digest, Sha256};
        let home = TempDir::new().unwrap();
        let out = TempDir::new().unwrap();
        let src = out.path().join("backup.key");
        let raw = vec![7u8; 32];
        write_file(&src, &raw);
        let args = RewrapHmacKeyArgs {
            source: src,
            home: Some(home.path().to_path_buf()),
        };
        run_rewrap_hmac_key(&args).await.unwrap();

        let mut found = None;
        let wal_dir = home.path().join("wal");
        let segments = sorted_wal_segments(&wal_dir);
        let trusted =
            crate::wal::signing::trusted_signing_pubkeys(&segments, &wal_dir.join("signing.key"));
        for segment in &segments {
            let bytes = std::fs::read(segment).expect("read 0xD9 segment");
            let (mut cur, logical) = crate::wal::compaction::logical_segment_bytes(&bytes).unwrap();
            while cur < logical.len() {
                let Ok(f) = crate::wal::frame::decode_frame(&logical[cur..]) else {
                    break;
                };
                if f.header.event_type == crate::wal::events::EVENT_TYPE_HMAC_KEY_ROTATED {
                    assert!(hmac_rotation_payload_is_trusted(f.payload, &trusted));
                    found = Some(serde_json::from_slice::<serde_json::Value>(f.payload).unwrap());
                }
                let total = f.header.total_len as usize;
                if total == 0 {
                    break;
                }
                cur = cur.saturating_add(total);
            }
        }
        let p = found.expect("a 0xD9 HMAC_KEY_ROTATED frame must be present");
        let expected: String = Sha256::digest(&raw)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(p["new_key_sha256"].as_str().unwrap(), expected);
        assert_eq!(p["reason"].as_str().unwrap(), "rewrap");
        // The raw key must NOT appear anywhere in the payload.
        assert!(!p.to_string().contains(&"07".repeat(8)));
    }

    #[tokio::test]
    async fn audited_pending_hmac_rotation_recovers_without_rotating_twice() {
        let home = TempDir::new().unwrap();
        let wal_dir = home.path().join("wal");
        std::fs::create_dir_all(&wal_dir).unwrap();
        let key_path = wal_dir.join("hmac.key");
        crate::wal::compaction::rewrap_key(&key_path, &[0x31; 32]).unwrap();
        let previous_key_storage_sha256 = current_key_storage_hash(&key_path).unwrap();
        let replacement = [0x72; 32];
        let signing_key =
            crate::wal::signing::load_or_init_signing_key(&wal_dir.join("signing.key")).unwrap();
        let mut payload = HmacKeyRotatedPayload {
            schema: HmacKeyRotatedPayload::SCHEMA,
            rotation_id: uuid::Uuid::now_v7().hyphenated().to_string(),
            new_key_sha256: sha256_hex(&replacement),
            previous_key_storage_sha256,
            replaced: true,
            reason: "rotate".to_owned(),
            ts_unix: crate::time::now_unix_i64(),
            signer_pubkey: crate::wal::signing::pubkey_b64(&signing_key),
            sig: String::new(),
        };
        payload.sig = crate::wal::signing::sign_b64(&signing_key, &payload.canonical_bytes());
        let staged_file = format!("hmac.key.rotation-{}.next", payload.rotation_id);
        let archive_file = "hmac.key.1700000000.archive".to_owned();
        let pending = PendingHmacKeyRotation {
            schema: PendingHmacKeyRotation::SCHEMA,
            payload,
            staged_file: staged_file.clone(),
            archive_file: Some(archive_file.clone()),
        };
        let journal = serde_json::to_vec(&pending).unwrap();
        crate::util::atomic_write::atomic_write_private(
            &hmac_rotation_journal_path(&key_path),
            &journal,
        )
        .unwrap();
        crate::wal::compaction::write_key_securely(&wal_dir.join(&staged_file), &replacement)
            .unwrap();
        let event = serde_json::to_vec(&pending.payload).unwrap();
        append_hmac_key_rotated(home.path(), false, &event)
            .await
            .unwrap();

        let result = rotate_hmac_key_with_audit(
            home.path(),
            &key_path,
            &[0x99; 32],
            "rotate",
            Some(wal_dir.join("unused.archive")),
        )
        .await
        .unwrap();

        assert!(result.recovered);
        assert_eq!(
            result.archive_path,
            Some(wal_dir.join(archive_file)),
            "recovery must use the archive bound in the pending transaction"
        );
        assert_eq!(
            crate::wal::compaction::load_or_init_key(&key_path).unwrap(),
            replacement,
            "recovery installs the already-audited staged key, not the caller's fresh candidate"
        );
        assert!(!hmac_rotation_journal_path(&key_path).exists());
        assert!(!wal_dir.join(staged_file).exists());
    }
}
