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

use anyhow::Result;
use clap::{Args, Subcommand};

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
    /// GR-10 — single-glance view of the active safety RAILS: which
    /// protective defaults are ENGAGED vs which the operator has RELAXED
    /// (autonomy, private inference, proactive/cluster transport, OS-tool
    /// allowlists, plugin signatures, model downloads). Read-only — the
    /// single source of truth for "what is protecting me right now"
    /// without spelunking `freedom.yaml`. Always exits 0 (it is a status
    /// view, not a pass/fail gate).
    SafeMode(SafeModeArgs),
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
pub struct BackupHmacKeyArgs {
    /// Plaintext destination path. The file is written mode-0600
    /// (Unix) so it's only readable by the operator account. Refused
    /// if the path already exists unless `--force` is also passed
    /// (defence against silent overwrite of an older backup).
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

pub async fn run_security(args: SecurityArgs) -> Result<()> {
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
        SecurityCommand::SafeMode(a) => run_safe_mode(&a),
    }
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
        detail: format!("{reads} read path(s), {writes} write path(s) allowlisted (empty = deny-all)"),
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

    // OM-01 OMI ingest — passive transcript ingest is the most sensitive power
    // surface (it can mirror everyday conversation), so it gets its own rail.
    // Engaged (off) = nothing is ingested. Even ON, the SC-14 startup gate
    // refuses any non-local endpoint.
    rails.push(Rail {
        name: "omi_ingest",
        engaged: !cfg.omi.enabled,
        detail: if cfg.omi.enabled {
            format!(
                "ENABLED — polling {} (LOCAL-only; SC-14 refuses a cloud endpoint at startup)",
                cfg.omi.endpoint
            )
        } else {
            "off — no passive transcript ingest".to_string()
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
        Some(dir) => FreedomConfig::load_from_path(&dir.join("freedom.yaml")).unwrap_or_default(),
        None => FreedomConfig::load_from_default_path().unwrap_or_default(),
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
        println!("{}", serde_json::to_string_pretty(&body).unwrap_or_default());
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
    let replaced = key_path.exists();

    // compaction::rewrap_key validates the 16-byte floor + DPAPI-wraps
    // (Windows) / writes mode-0600 (Unix), overwriting any existing key.
    crate::wal::compaction::rewrap_key(&key_path, &raw)?;

    // SC-09: record the rotation BOUNDARY so `neoth wal verify --since-rotation`
    // can skip compaction markers signed with the old key. Best-effort, audit
    // metadata only (SHA-256 of the new key — never the raw bytes).
    emit_hmac_key_rotated(&home, &raw, replaced, "rewrap").await;

    eprintln!();
    eprintln!("[neoth security] HMAC KEY RE-WRAPPED FOR THIS MACHINE");
    eprintln!("[neoth security]   source:  {}", args.source.display());
    eprintln!("[neoth security]   key:     {}", key_path.display());
    eprintln!(
        "[neoth security]   bytes:   {} ({})",
        raw.len(),
        if replaced {
            "replaced the existing key"
        } else {
            "installed (no prior key present)"
        }
    );
    eprintln!("[neoth security]");
    eprintln!("[neoth security] The key is now bound to the current user/machine (DPAPI on");
    eprintln!("[neoth security] Windows, mode-0600 on Unix). Run `neoth verify` to confirm the");
    eprintln!("[neoth security] compaction-marker audit chain verifies again.");
    eprintln!("[neoth security] Delete the plaintext --source backup once verification passes.");
    eprintln!("[neoth security] (If this command had failed mid-write, the key file could be");
    eprintln!("[neoth security]  absent — just re-run with the same --source to restore it.)");

    println!("hmac key re-wrapped: {}", key_path.display());
    Ok(())
}

/// `0xD9 HMAC_KEY_ROTATED` audit — the rotation boundary for
/// `wal verify --since-rotation`. When a daemon owns the WAL, FORWARD over
/// audit-RPC; otherwise open a one-shot writer. Metadata only — the SHA-256 of
/// the NEW key (never the raw bytes). Best-effort: an audit gap never fails the
/// rewrap (the operator's recovery already succeeded).
async fn emit_hmac_key_rotated(home: &std::path::Path, new_key: &[u8], replaced: bool, reason: &str) {
    use sha2::{Digest, Sha256};
    let new_key_sha256: String = Sha256::digest(new_key)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let payload = serde_json::to_vec(&serde_json::json!({
        "new_key_sha256": new_key_sha256,
        "replaced": replaced,
        "reason": reason,
        "ts_unix": now,
    }))
    .unwrap_or_default();

    let daemon_live = matches!(
        crate::daemon::pidfile::live_daemon_pid(&crate::daemon::pidfile::default_pidfile()),
        Ok(Some(_))
    );
    if daemon_live {
        if let Err(e) = crate::daemon::audit_rpc::try_post_audit_frame(
            home,
            crate::wal::events::EVENT_TYPE_HMAC_KEY_ROTATED,
            &payload,
        )
        .await
        {
            tracing::debug!(error = %e, "security: 0xD9 forward skipped (daemon listener unreachable)");
        }
        return;
    }
    let segment = home.join("wal").join("000001.wal");
    if let Some(p) = segment.parent() {
        let _ = std::fs::create_dir_all(p);
    }
    let (writer, join) = match crate::wal::writer::spawn(segment) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "security: WAL writer spawn failed; 0xD9 not recorded");
            return;
        }
    };
    let header =
        crate::wal::HeaderBuilder::new(crate::wal::events::EVENT_TYPE_HMAC_KEY_ROTATED, &payload)
            .build();
    if let Err(e) = writer.try_append_sync(header, payload) {
        tracing::warn!(error = %e, "security: 0xD9 frame append failed (audit gap)");
    }
    // Drop the handle so the writer task drains + flushes, then await it — the
    // rotation boundary must be durable before the command reports success.
    drop(writer);
    let _ = join.await;
}

/// SC-09 (Session 28) — write the operator's WAL HMAC compaction key
/// to `args.output` in plaintext. Handles the DPAPI unwrap on Windows
/// (via `wal::compaction::load_or_init_key`); the operator sees the
/// raw bytes regardless of how they're stored on disk.
///
/// **Operator-visible warnings are deliberate**: this path is the
/// ONE place NEOTH legitimately emits a plaintext copy of the
/// HMAC key. Every line of stderr is one the operator should read.
pub fn run_backup_hmac_key(args: &BackupHmacKeyArgs) -> Result<()> {
    let home = args
        .home
        .clone()
        .unwrap_or_else(crate::config::FreedomConfig::default_neoth_home);

    // Refuse overwrite unless --force. Catches the muscle-memory
    // mistake of re-running the same command (which would silently
    // replace an older backup that referred to a different key
    // rotation epoch).
    if args.output.exists() && !args.force {
        anyhow::bail!(
            "refusing to overwrite existing backup at {}; pass --force to replace",
            args.output.display()
        );
    }

    let key_path = home.join("wal").join("hmac.key");
    if !key_path.exists() {
        anyhow::bail!(
            "no HMAC key at {} — run `neothd init` first or wait for the first WAL frame to be written",
            key_path.display()
        );
    }
    let key_bytes = crate::wal::compaction::load_or_init_key(&key_path)?;

    // Ensure the parent dir exists so a fresh `--output ~/safe/key`
    // works without the operator pre-mkdiring.
    if let Some(parent) = args.output.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| anyhow::anyhow!("create backup parent {}: {e}", parent.display()))?;
        }
    }

    write_backup_file(&args.output, &key_bytes)?;

    // stderr-only warnings — stdout is reserved for the operator-
    // visible success line so scripts that capture stdout get a
    // clean confirmation.
    eprintln!();
    eprintln!("[neoth security] PLAINTEXT BACKUP WRITTEN");
    eprintln!("[neoth security]   path:    {}", args.output.display());
    eprintln!(
        "[neoth security]   bytes:   {} (mode-0600 on Unix)",
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

    println!("backup written: {}", args.output.display());
    Ok(())
}

/// Write the plaintext key bytes mode-0600 on Unix. Windows DACL
/// tightening would mirror the SC-08 plan and is deferred — for
/// now the operator gets the default ACL on the destination,
/// which matches what they get for any other plaintext file
/// they create. The stderr warning above tells them to move it.
fn write_backup_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;

    // Open with write-only + create + truncate semantics. mode-0600
    // applied via OpenOptions on Unix; the `mode()` call is a no-op
    // on non-Unix targets but compiles via the cfg.
    let mut open = std::fs::OpenOptions::new();
    open.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open.mode(0o600);
    }
    let mut f = open
        .open(path)
        .map_err(|e| anyhow::anyhow!("open backup path {}: {e}", path.display()))?;
    f.write_all(bytes)
        .map_err(|e| anyhow::anyhow!("write backup bytes to {}: {e}", path.display()))?;
    f.flush()
        .map_err(|e| anyhow::anyhow!("flush backup file {}: {e}", path.display()))?;
    Ok(())
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
                "Permission decisions",
                CheckStatus::Warn,
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
            if let Ok(meta) = entry.metadata() {
                if let Ok(modified) = meta.modified() {
                    if let Ok(age) = modified.elapsed() {
                        if age.as_secs() > 7 * 24 * 3600 {
                            stale_count += 1;
                        }
                    }
                }
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
    use tempfile::TempDir;

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
        assert_eq!(rails.len(), 15, "all rails surfaced");
        for name in [
            "autonomy_gate",          // default Standard = gated
            "private_inference",      // default no cloud fallback
            "proactive_messaging",    // default off
            "cluster_transport",      // default off
            "os_file_tools",          // default empty allowlists = deny-all
            "os_app_launch",          // default empty exec allowlist = deny-all
            "email_llm_tiebreak",     // default off = no LLM sees mail
            "email_downgrade_allowed", // default denied = no LLM auto-deliver
            "omi_ingest",             // default off = no passive ingest
            "ecology_scheduler",      // default off = no auto-scheduler
            "channel_weight_learning", // default operator_only = poison-resistant
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
        // a future `rewrap-hmac-key` slice. Drift guard against any
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

        let seg = home.path().join("wal").join("000001.wal");
        let bytes = std::fs::read(&seg).expect("0xD9 segment written");
        let mut cur = crate::wal::segment_header::SEGMENT_HEADER_LEN;
        let mut found = None;
        while cur < bytes.len() {
            let Ok(f) = crate::wal::frame::decode_frame(&bytes[cur..]) else {
                break;
            };
            if f.header.event_type == crate::wal::events::EVENT_TYPE_HMAC_KEY_ROTATED {
                found = Some(serde_json::from_slice::<serde_json::Value>(f.payload).unwrap());
            }
            let total = f.header.total_len as usize;
            if total == 0 {
                break;
            }
            cur = cur.saturating_add(total);
        }
        let p = found.expect("a 0xD9 HMAC_KEY_ROTATED frame must be present");
        let expected: String = Sha256::digest(&raw).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(p["new_key_sha256"].as_str().unwrap(), expected);
        assert_eq!(p["reason"].as_str().unwrap(), "rewrap");
        // The raw key must NOT appear anywhere in the payload.
        assert!(!p.to_string().contains(&"07".repeat(8)));
    }
}
