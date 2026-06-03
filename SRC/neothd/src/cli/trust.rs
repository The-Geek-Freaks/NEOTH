//! `neoth trust` — GR-03 unifying trust surface.
//!
//! The three Gremium-identified differentiators (Trust Ledger + Autonomy
//! Gradients + Recovery-first UX) already ship as separate commands —
//! `neoth verify`/`wal show`/`wal export`, `neoth autonomy`, and
//! `neoth recover`/`rollback`/`undo`/`security`. This command is the
//! READ-ONLY surface that ties them into one operator view so the
//! posture is legible at a glance:
//!
//! 1. **Autonomy** — the live level + what it gates + how boundary asks resolve.
//! 2. **Trust Ledger** — the HMAC-chained WAL size + integrity pointer
//!    (or an inline chain check with `--verify-chain`).
//! 3. **Recovery** — which recovery levers are armed RIGHT NOW (HMAC-key
//!    backup readiness, proof signing key) + the commands to pull them.
//!
//! It is deliberately non-theater: every number is read from already-shipped
//! state (`collect_stats` over the real segments, the live `FreedomConfig`,
//! on-disk key presence). It mints no new WAL frame and mutates nothing.

use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Args;

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::permissions::AutonomyLevel;

#[derive(Args, Debug, Clone)]
pub struct TrustArgs {
    /// Override the WAL directory (mostly for tests).
    #[arg(long, value_name = "DIR")]
    pub wal_dir: Option<PathBuf>,
    /// Override the NEOTH home (key-presence probes; mostly for tests).
    #[arg(long, value_name = "DIR")]
    pub home: Option<PathBuf>,
    /// Also run the full HMAC chain verification inline (heavier — walks
    /// every compaction marker, like `neoth verify`). Off by default; the
    /// surface otherwise reports ledger SIZE + a pointer to `neoth verify`.
    #[arg(long)]
    pub verify_chain: bool,
    /// Output format. Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

/// What an autonomy level means for boundary actions — pure, derived from
/// the `permissions::evaluate` semantics so the surface never drifts from
/// the gate it describes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutonomyPosture {
    pub level: &'static str,
    /// One-line behaviour summary for boundary asks.
    pub behavior: &'static str,
    /// Representative actions the level gates (Confirm/Deny rather than
    /// silently Allow). Illustrative, not exhaustive.
    pub gated_examples: Vec<&'static str>,
}

/// Map an [`AutonomyLevel`] to its operator-readable posture. Mirrors the
/// arms in `permissions::evaluate` (Strict denies boundary asks; Standard
/// confirms; Elevated allows most but still confirms the highest-blast-
/// radius ones; Full allows but `SelfBinaryReplace` stays Confirm-always).
pub fn autonomy_posture(level: AutonomyLevel) -> AutonomyPosture {
    let gated_examples = vec![
        "ExternalTaskWrite (todo add/close)",
        "OsAppLaunch / fs write",
        "ProactiveChannelSend",
        "SelfBinaryReplace (Confirm even at Full)",
    ];
    let behavior = match level {
        AutonomyLevel::Strict => "boundary asks are DENIED outright — the agent acts only inside safe rails",
        AutonomyLevel::Standard => "boundary asks require Confirm (--yes / interactive prompt)",
        AutonomyLevel::Elevated => "most boundary asks Allow; the highest-blast-radius ones still Confirm",
        AutonomyLevel::Full => "boundary asks Allow; only SelfBinaryReplace still Confirms",
        AutonomyLevel::Custom => "per-action policy from your custom autonomy map",
    };
    AutonomyPosture {
        level: level.as_str(),
        behavior,
        gated_examples,
    }
}

/// Aggregated, integrity-relevant view of the WAL ledger. Built from
/// [`crate::cli::wal::collect_stats`] over every segment — no chain crypto
/// here (that is the `--verify-chain` / `neoth verify` path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerSummary {
    pub segments: usize,
    pub total_frames: usize,
    pub bad_frames: usize,
    pub size_bytes: u64,
}

/// Summarise the ledger from per-segment stats. Pure — the caller does the
/// IO (`collect_stats`) so this stays unit-testable. `bad_frames > 0` means
/// at least one segment has a torn tail (recoverable, but worth surfacing).
pub fn summarize_ledger(stats: &[crate::cli::wal::SegmentStats]) -> LedgerSummary {
    LedgerSummary {
        segments: stats.len(),
        total_frames: stats.iter().map(|s| s.frame_count).sum(),
        bad_frames: stats.iter().map(|s| s.bad_frames).sum(),
        size_bytes: stats.iter().map(|s| s.size_bytes).sum(),
    }
}

/// Which recovery levers are armed right now. Pure-data over on-disk
/// presence so the operator sees, at a glance, whether a machine-swap /
/// key-loss would be recoverable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryReadiness {
    /// The WAL HMAC key exists on disk (the chain can be verified locally).
    pub hmac_key_present: bool,
    /// The ed25519 proof signing key exists (`wal export --sign` is ready).
    pub proof_key_present: bool,
    /// The X25519 transfer receiving key exists (`transfer import` is ready).
    pub transfer_key_present: bool,
}

/// Probe recovery readiness from the on-disk key paths in the WAL dir
/// (`hmac.key` / `signing.key` / `transfer.key` all live there — confirmed
/// against `compaction::default_key_path` / `signing::default_signing_key_path`
/// / `transfer_bundle::default_transfer_key_path`). Read-only `Path::exists`
/// checks — never reads or unwraps the key bytes.
pub fn recovery_readiness(wal_dir: &Path) -> RecoveryReadiness {
    RecoveryReadiness {
        hmac_key_present: wal_dir.join("hmac.key").exists(),
        proof_key_present: wal_dir.join("signing.key").exists(),
        transfer_key_present: wal_dir.join("transfer.key").exists(),
    }
}

pub async fn run_trust(args: TrustArgs) -> Result<()> {
    let cfg = FreedomConfig::load_from_default_path().unwrap_or_default();
    let home = args
        .home
        .clone()
        .unwrap_or_else(FreedomConfig::default_neoth_home);
    let wal_dir = args.wal_dir.clone().unwrap_or_else(|| home.join("wal"));

    let posture = autonomy_posture(cfg.autonomy);
    let stats = collect_ledger_stats(&wal_dir);
    let ledger = summarize_ledger(&stats);
    let recovery = recovery_readiness(&wal_dir);
    let switches = PrivacySwitches {
        email_llm_tiebreak: cfg.email.llm_tiebreak,
        email_tiebreak_allow_downgrade: cfg.email.llm_tiebreak_allow_downgrade,
    };

    // Optional inline chain check — honest: only claim VERIFIED when run.
    let chain_status: Option<bool> = if args.verify_chain {
        Some(run_chain_check(&wal_dir).await)
    } else {
        None
    };

    match args.output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            render_json(&posture, &ledger, &recovery, &switches, chain_status)
        }
        OutputFormat::Table => render_table(&posture, &ledger, &recovery, &switches, chain_status),
    }
    Ok(())
}

/// Cost/privacy-sensitive switches that should never be buried in a YAML file —
/// surfaced here so an operator can see at a glance whether NEOTH may spend an
/// LLM call on their inbound mail, and whether an LLM verdict may auto-deliver
/// a flagged email.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivacySwitches {
    /// PL-05b — is the email threat tie-breaker on (an LLM call per borderline
    /// email; a cost + privacy decision)?
    pub email_llm_tiebreak: bool,
    /// PL-05b — may a benign LLM verdict DEMOTE a flagged email to auto-deliver?
    pub email_tiebreak_allow_downgrade: bool,
}

/// Glob the WAL dir for `*.wal` segments and `collect_stats` each. Missing
/// dir / unreadable segment ⇒ that segment is skipped (an empty ledger is a
/// valid "fresh install" state, not an error).
fn collect_ledger_stats(wal_dir: &Path) -> Vec<crate::cli::wal::SegmentStats> {
    let mut segs: Vec<PathBuf> = match std::fs::read_dir(wal_dir) {
        Ok(rd) => rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "wal"))
            .collect(),
        Err(_) => Vec::new(),
    };
    segs.sort();
    segs.iter()
        .filter_map(|p| crate::cli::wal::collect_stats(p).ok())
        .collect()
}

/// Run the real HMAC chain verification (the `neoth verify` core) inline.
/// Returns `true` on a clean pass, `false` on any failure (incl. a key that
/// can't be loaded) — the surface reports the boolean, never panics.
async fn run_chain_check(wal_dir: &Path) -> bool {
    let args = crate::cli::verify::VerifyArgs {
        wal_dir: Some(wal_dir.to_path_buf()),
        key: None,
        segment: None,
        since_rotation: false,
        output: OutputFormat::Json,
    };
    crate::cli::verify::run_verify(args).await.is_ok()
}

fn render_json(
    posture: &AutonomyPosture,
    ledger: &LedgerSummary,
    recovery: &RecoveryReadiness,
    switches: &PrivacySwitches,
    chain_status: Option<bool>,
) {
    let value = serde_json::json!({
        "autonomy": {
            "level": posture.level,
            "behavior": posture.behavior,
            "gated_examples": posture.gated_examples,
        },
        "trust_ledger": {
            "segments": ledger.segments,
            "total_frames": ledger.total_frames,
            "bad_frames": ledger.bad_frames,
            "size_bytes": ledger.size_bytes,
            "chain_verified": chain_status,
        },
        "recovery": {
            "hmac_key_present": recovery.hmac_key_present,
            "proof_key_present": recovery.proof_key_present,
            "transfer_key_present": recovery.transfer_key_present,
        },
        "privacy_switches": {
            "email_llm_tiebreak": switches.email_llm_tiebreak,
            "email_tiebreak_allow_downgrade": switches.email_tiebreak_allow_downgrade,
        },
    });
    println!("{value}");
}

fn render_table(
    posture: &AutonomyPosture,
    ledger: &LedgerSummary,
    recovery: &RecoveryReadiness,
    switches: &PrivacySwitches,
    chain_status: Option<bool>,
) {
    println!("AUTONOMY      {}", posture.level);
    println!("  {}", posture.behavior);
    println!("  gated: {}", posture.gated_examples.join(", "));
    println!();

    println!(
        "TRUST LEDGER  {} frame(s) across {} segment(s) ({} bytes)",
        ledger.total_frames, ledger.segments, ledger.size_bytes
    );
    match chain_status {
        Some(true) => println!("  chain integrity: VERIFIED (HMAC markers checked)"),
        Some(false) => println!(
            "  chain integrity: FAILED — run `neoth verify` for the offending segment/offset"
        ),
        None => println!("  chain integrity: run `neoth verify` (or `neoth trust --verify-chain`)"),
    }
    if ledger.bad_frames > 0 {
        println!(
            "  note: {} torn/undecodable frame(s) at a segment tail (recoverable)",
            ledger.bad_frames
        );
    }
    println!("  inspect: neoth wal show --type <event>  ·  export: neoth wal export --sign");
    println!();

    println!("RECOVERY      undo · rollback <id> · recover");
    println!(
        "  HMAC key:    {}",
        readiness_line(
            recovery.hmac_key_present,
            "present (chain verifiable) — back up via `neoth security backup-hmac-key`",
            "absent (generated on first daemon start)"
        )
    );
    println!(
        "  proof key:   {}",
        readiness_line(
            recovery.proof_key_present,
            "present (`wal export --sign` ready)",
            "absent (generated on first `wal export --sign`)"
        )
    );
    println!(
        "  transfer key:{}",
        readiness_line(
            recovery.transfer_key_present,
            " present (`transfer import` ready)",
            " absent (generated on first transfer use)"
        )
    );
    println!();

    // Cost/privacy switches that must not stay buried in freedom.yaml.
    println!("PRIVACY/RISK");
    println!(
        "  email LLM tie-break:  {}  ({})",
        on_off(switches.email_llm_tiebreak),
        if switches.email_llm_tiebreak {
            "an LLM call per borderline email"
        } else {
            "no LLM sees your mail (deterministic rules only)"
        }
    );
    println!(
        "  └ downgrade allowed:  {}  ({})",
        on_off(switches.email_tiebreak_allow_downgrade),
        if switches.email_tiebreak_allow_downgrade {
            "a benign LLM verdict may auto-DELIVER a flagged email"
        } else {
            "the LLM may only hold/quarantine, never auto-deliver"
        }
    );
}

fn on_off(b: bool) -> &'static str {
    if b { "ON" } else { "off" }
}

fn readiness_line(present: bool, yes: &str, no: &str) -> String {
    if present {
        format!("✓ {yes}")
    } else {
        format!("· {no}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::wal::SegmentStats;
    use std::collections::BTreeMap;

    fn stat(frames: usize, bad: usize, size: u64) -> SegmentStats {
        SegmentStats {
            path: PathBuf::from("000001.wal"),
            size_bytes: size,
            segment_seq: Some(1),
            header_ok: true,
            header_error: None,
            frame_count: frames,
            bad_frames: bad,
            per_event: BTreeMap::new(),
        }
    }

    #[test]
    fn posture_distinguishes_every_level() {
        // Each level must produce a distinct behaviour line (no copy-paste
        // collapse) and carry the SelfBinaryReplace caveat in its examples.
        let levels = [
            AutonomyLevel::Strict,
            AutonomyLevel::Standard,
            AutonomyLevel::Elevated,
            AutonomyLevel::Full,
            AutonomyLevel::Custom,
        ];
        let mut behaviors = std::collections::HashSet::new();
        for l in levels {
            let p = autonomy_posture(l);
            assert_eq!(p.level, l.as_str());
            assert!(behaviors.insert(p.behavior), "behaviour line must be unique per level");
            assert!(p.gated_examples.iter().any(|e| e.contains("SelfBinaryReplace")));
        }
    }

    #[test]
    fn strict_denies_full_confirms_only_self_replace() {
        assert!(autonomy_posture(AutonomyLevel::Strict).behavior.contains("DENIED"));
        assert!(autonomy_posture(AutonomyLevel::Full).behavior.contains("SelfBinaryReplace"));
    }

    #[test]
    fn summarize_ledger_sums_across_segments() {
        let stats = vec![stat(100, 0, 4096), stat(50, 1, 2048), stat(0, 0, 64)];
        let s = summarize_ledger(&stats);
        assert_eq!(s.segments, 3);
        assert_eq!(s.total_frames, 150);
        assert_eq!(s.bad_frames, 1);
        assert_eq!(s.size_bytes, 6208);
    }

    #[test]
    fn summarize_ledger_empty_is_zero_not_panic() {
        let s = summarize_ledger(&[]);
        assert_eq!(s.segments, 0);
        assert_eq!(s.total_frames, 0);
        assert_eq!(s.size_bytes, 0);
    }

    #[test]
    fn recovery_readiness_reports_present_and_absent() {
        let dir = tempfile::tempdir().unwrap();
        let wal = dir.path().join("wal");
        std::fs::create_dir_all(&wal).unwrap();
        // Only the HMAC key exists.
        std::fs::write(wal.join("hmac.key"), b"x").unwrap();
        let r = recovery_readiness(&wal);
        assert!(r.hmac_key_present);
        assert!(!r.proof_key_present);
        assert!(!r.transfer_key_present);

        std::fs::write(wal.join("signing.key"), b"y").unwrap();
        std::fs::write(wal.join("transfer.key"), b"z").unwrap();
        let r2 = recovery_readiness(&wal);
        assert!(r2.proof_key_present);
        assert!(r2.transfer_key_present);
    }

    #[test]
    fn recovery_readiness_missing_dir_is_all_absent() {
        let dir = tempfile::tempdir().unwrap();
        let r = recovery_readiness(&dir.path().join("does-not-exist"));
        assert!(!r.hmac_key_present);
        assert!(!r.proof_key_present);
        assert!(!r.transfer_key_present);
    }
}
