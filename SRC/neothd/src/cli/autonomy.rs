//! `neoth autonomy` — view + set the operator autonomy level in freedom.yaml.
//!
//! Autonomy (`strict | standard | elevated | full | custom`) gates EVERY tool
//! and provider call via [`crate::permissions::evaluate`]. It is picked at
//! onboarding (`neoth init --autonomy <level>`) and inspected by
//! `neoth permissions show`; this command is the post-onboarding setter/getter
//! so operators retune WITHOUT re-running the wizard or hand-editing YAML.
//!
//! `set` persists through [`crate::config::FreedomConfig::save_public_to_default_path`]
//! — the same atomic, 0600, secrets-stripped write `neoth hemispheres set`
//! already uses, so it never leaks keys into freedom.yaml.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::permissions::AutonomyLevel;

#[derive(Args, Debug, Clone)]
pub struct AutonomyArgs {
    #[command(subcommand)]
    pub action: AutonomyAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum AutonomyAction {
    /// Print the current autonomy level + operating mode (read from freedom.yaml).
    Show,
    /// Set the raw autonomy level in freedom.yaml (advanced / power-user path).
    /// Persists immediately; takes effect on the next command / daemon reload.
    /// Does NOT change the skill-library breadth — use `gated` / `full-auto`
    /// for the headline operating-mode switch.
    Set {
        /// One of: `strict` | `standard` | `elevated` | `full` | `custom`.
        level: String,
    },
    /// GATED operating mode (the safe default): autonomy `standard` + the
    /// curated skill set. NEOTH asks before shell commands, channel sends,
    /// out-of-home writes, and costly calls. Clears `skills.enable_all_bundled`.
    Gated,
    /// FULL-AUTO operating mode: autonomy `full` + the ENTIRE bundled skill
    /// library force-enabled (all 98 skills route proactively) + the router
    /// confidence floor raised so generic triggers can't false-activate. NEOTH
    /// acts without asking. The irreducible security floor still holds
    /// (self-replace / patch-apply / dangerous targets stay Confirm; revoked &
    /// invalid-signature plugins stay refused; `proactive.enabled`,
    /// `trust_all_tools` and unsigned-plugin trust are NOT flipped — each needs
    /// its own opt-in). Same effect as `neoth sudomode`.
    #[command(name = "full-auto")]
    FullAuto,
}

/// Pure core of `set`: validate `level`, return the config with the new
/// autonomy applied plus the PREVIOUS level. Separated from disk I/O so the
/// validation + mutation are hermetically testable. Rejects unknown levels
/// with the canonical list in the message.
fn apply_level(cfg: FreedomConfig, level: &str) -> Result<(FreedomConfig, AutonomyLevel)> {
    let parsed = AutonomyLevel::from_str(&level.trim().to_ascii_lowercase()).ok_or_else(|| {
        anyhow::anyhow!(
            "invalid autonomy level `{level}` — expected one of: strict, standard, elevated, full, custom"
        )
    })?;
    let previous = cfg.autonomy;
    let mut next = cfg;
    next.autonomy = parsed;
    Ok((next, previous))
}

/// Pure core of the headline operating-mode switch. `full_auto = true` sets
/// autonomy `Full` + force-enables the whole bundled skill library
/// (`skills.enable_all_bundled = true`); `false` is gated mode = autonomy
/// `Standard` + curated set (`enable_all_bundled = false`). Returns the config
/// with the mode applied plus the PREVIOUS autonomy level (for the audit
/// elevation/derogation decision). Touches ONLY `autonomy` +
/// `skills.enable_all_bundled` — never the dangerous toggles (proactive,
/// trust_all_tools, unsigned-plugin trust) the security floor keeps separate.
fn apply_mode(cfg: FreedomConfig, full_auto: bool) -> (FreedomConfig, AutonomyLevel) {
    let previous = cfg.autonomy;
    let mut next = cfg;
    next.autonomy = if full_auto {
        AutonomyLevel::Full
    } else {
        AutonomyLevel::Standard
    };
    next.skills.enable_all_bundled = full_auto;
    (next, previous)
}

/// Human label for the current operating mode, derived from the
/// (autonomy, enable_all_bundled) pair. `full-auto` is the exact full-auto
/// combination; a bare `autonomy: full` WITHOUT the skill-breadth flag reads as
/// `advanced` (a power user chose Full but kept the curated set), so the label
/// never overclaims.
fn mode_label(cfg: &FreedomConfig) -> &'static str {
    match (cfg.autonomy, cfg.skills.enable_all_bundled) {
        (AutonomyLevel::Full, true) => "full-auto",
        (AutonomyLevel::Standard, false) => "gated",
        _ => "advanced",
    }
}

/// Monotonic rank for the autonomy levels so a `set` can tell whether the
/// change RAISED or LOWERED autonomy (→ `0xA2 LEVEL_ELEVATED` vs
/// `0xA3 LEVEL_DEROGATED`). `custom` is operator-defined and can grant broad
/// powers, so it ranks highest — a move to/from `custom` therefore reads as an
/// elevation/derogation, the conservative forensic bias for a security event.
fn autonomy_rank(level: AutonomyLevel) -> u8 {
    match level {
        AutonomyLevel::Strict => 0,
        AutonomyLevel::Standard => 1,
        AutonomyLevel::Elevated => 2,
        AutonomyLevel::Full => 3,
        AutonomyLevel::Custom => 4,
    }
}

/// The audit event a `previous → next` change should record. `None` when the
/// level is unchanged (no frame).
fn change_event(previous: AutonomyLevel, next: AutonomyLevel) -> Option<u8> {
    use crate::wal::events::{EVENT_TYPE_LEVEL_DEROGATED, EVENT_TYPE_LEVEL_ELEVATED};
    if previous == next {
        None
    } else if autonomy_rank(next) >= autonomy_rank(previous) {
        Some(EVENT_TYPE_LEVEL_ELEVATED)
    } else {
        Some(EVENT_TYPE_LEVEL_DEROGATED)
    }
}

/// Record the autonomy change in the WAL — a security-relevant config mutation
/// must be forensically visible. Best-effort: when the daemon owns the writer
/// the frame is FORWARDED over audit-RPC (AUDIT-RPC-01); otherwise a one-shot
/// writer appends it. Payload `{previous, next, source:"cli"}`.
async fn emit_autonomy_change(
    previous: AutonomyLevel,
    next: AutonomyLevel,
    mode: Option<&str>,
    daemon_live: bool,
    home: &std::path::Path,
) {
    // Pick the event from the level delta. Special case: a switch INTO full-auto
    // widens authority (the whole skill library goes live + the gate opens to
    // Full) even when the level was already Full — record that as an elevation
    // so "the operator dropped the gate at time T" always has a WAL anchor.
    let event_type = match change_event(previous, next) {
        Some(e) => e,
        None if mode == Some("full-auto") => crate::wal::events::EVENT_TYPE_LEVEL_ELEVATED,
        None => return,
    };
    let payload = serde_json::to_vec(&serde_json::json!({
        "previous": previous.as_str(),
        "next": next.as_str(),
        "mode": mode,
        "source": "cli",
    }))
    .unwrap_or_else(|_| b"{}".to_vec());

    if daemon_live {
        // Daemon owns the single WAL writer → forward over the loopback
        // audit-RPC channel (0xA2/0xA3 are allowlisted there).
        if let Err(e) =
            crate::daemon::audit_rpc::try_post_audit_frame(home, event_type, &payload).await
        {
            tracing::debug!(error = %e, "autonomy-change audit forward failed (best-effort)");
        }
    } else {
        // No daemon → open a one-shot writer and append directly.
        let segment = home.join("wal").join("000001.wal");
        if let Some(parent) = segment.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok((writer, join)) = crate::wal::spawn(segment) {
            let header = crate::wal::HeaderBuilder::new(event_type, &payload).build();
            let _ = writer.append(header, payload).await;
            drop(writer);
            let _ = join.await;
        }
    }
}

pub async fn run_autonomy(args: AutonomyArgs, output: OutputFormat) -> Result<()> {
    match args.action {
        AutonomyAction::Show => run_show(output),
        AutonomyAction::Set { level } => run_set(&level, output).await,
        AutonomyAction::Gated => run_set_mode(false, output).await,
        AutonomyAction::FullAuto => run_set_mode(true, output).await,
    }
}

fn run_show(output: OutputFormat) -> Result<()> {
    let cfg = FreedomConfig::load_from_default_path().context(
        "load freedom.yaml (run `neoth init` first if this is a fresh install)",
    )?;
    let mode = mode_label(&cfg);
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!(
            "{}",
            serde_json::json!({
                "mode": mode,
                "autonomy": cfg.autonomy.as_str(),
                "skills_enable_all_bundled": cfg.skills.enable_all_bundled,
            })
        ),
        OutputFormat::Table => {
            println!("mode:     {mode}");
            println!("autonomy: {}", cfg.autonomy.as_str());
            match mode {
                "full-auto" => println!(
                    "          NEOTH acts without asking; the entire skill library routes proactively."
                ),
                "gated" => println!(
                    "          NEOTH asks before sensitive actions; curated skill set. (switch: neoth autonomy full-auto)"
                ),
                _ => println!(
                    "          advanced: raw autonomy level set directly. (headline modes: neoth autonomy gated | full-auto)"
                ),
            }
        }
    }
    Ok(())
}

/// Headline operating-mode switch: `gated` (safe default) or `full-auto`.
/// Persists `autonomy` + `skills.enable_all_bundled` atomically, audits the
/// authority change, and (for full-auto) prints the consequence up front.
async fn run_set_mode(full_auto: bool, output: OutputFormat) -> Result<()> {
    let cfg = FreedomConfig::load_from_default_path().context(
        "load freedom.yaml (run `neoth init` first if this is a fresh install)",
    )?;
    let required = cfg.audit_rpc.required_for_oneshot_permission_events;
    let home = FreedomConfig::default_neoth_home();
    let pidfile = crate::daemon::pidfile::default_pidfile();
    let daemon_live = matches!(
        crate::daemon::pidfile::live_daemon_pid(&pidfile),
        Ok(Some(_))
    );
    crate::daemon::audit_rpc::enforce_required_audit(required, daemon_live, &home)?;
    let (next, previous) = apply_mode(cfg, full_auto);
    let applied = next.autonomy;
    let mode = if full_auto { "full-auto" } else { "gated" };
    next.save_public_to_default_path()
        .context("persist the operating mode to freedom.yaml")?;
    emit_autonomy_change(previous, applied, Some(mode), daemon_live, &home).await;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!(
            "{}",
            serde_json::json!({
                "mode": mode,
                "autonomy": applied.as_str(),
                "previous": previous.as_str(),
                "skills_enable_all_bundled": full_auto,
            })
        ),
        OutputFormat::Table => {
            if full_auto {
                println!("operating mode: FULL-AUTO (saved to freedom.yaml)");
                println!("  autonomy: {} -> full", previous.as_str());
                println!("  skills:   entire bundled library enabled + routed proactively");
                println!(
                    "  ⚠ NEOTH now acts WITHOUT asking — shell commands, channel sends, writes,"
                );
                println!(
                    "    and token spend happen automatically. Self-replace, patch-apply, dangerous"
                );
                println!(
                    "    targets and unsigned/revoked plugins remain blocked. Switch back: neoth autonomy gated"
                );
            } else {
                println!("operating mode: GATED (saved to freedom.yaml)");
                println!("  autonomy: {} -> standard", previous.as_str());
                println!("  skills:   curated set (run `neoth skill enable <id>` for individual extras)");
                println!("  NEOTH asks before sensitive actions.");
            }
        }
    }
    Ok(())
}

async fn run_set(level: &str, output: OutputFormat) -> Result<()> {
    let cfg = FreedomConfig::load_from_default_path().context(
        "load freedom.yaml (run `neoth init` first if this is a fresh install)",
    )?;
    let required = cfg.audit_rpc.required_for_oneshot_permission_events;
    let home = FreedomConfig::default_neoth_home();
    let pidfile = crate::daemon::pidfile::default_pidfile();
    let daemon_live = matches!(
        crate::daemon::pidfile::live_daemon_pid(&pidfile),
        Ok(Some(_))
    );
    // AUDIT-RPC-01 #1: under a required-audit posture, refuse to change autonomy
    // if the daemon owns the WAL but its audit-RPC listener is unreachable — a
    // security-relevant change must never land without an audit record. Checked
    // BEFORE the persist so a refused change leaves freedom.yaml untouched.
    crate::daemon::audit_rpc::enforce_required_audit(required, daemon_live, &home)?;
    let (next, previous) = apply_level(cfg, level)?;
    let applied = next.autonomy;
    next.save_public_to_default_path()
        .context("persist the new autonomy level to freedom.yaml")?;
    // Forensic audit of the security-relevant change (best-effort, after the
    // persist so a recorded frame always reflects what's on disk). No mode label
    // — this is the raw level setter, not the headline-mode switch.
    emit_autonomy_change(previous, applied, None, daemon_live, &home).await;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!(
            "{}",
            serde_json::json!({
                "autonomy": applied.as_str(),
                "previous": previous.as_str(),
                "changed": applied != previous,
            })
        ),
        OutputFormat::Table => {
            if applied == previous {
                println!("autonomy unchanged: {} (already set)", applied.as_str());
            } else {
                println!(
                    "autonomy: {} -> {} (saved to freedom.yaml)",
                    previous.as_str(),
                    applied.as_str()
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_level_accepts_every_level_and_reports_previous() {
        for (s, expected) in [
            ("strict", AutonomyLevel::Strict),
            ("standard", AutonomyLevel::Standard),
            ("elevated", AutonomyLevel::Elevated),
            ("full", AutonomyLevel::Full),
            ("custom", AutonomyLevel::Custom),
        ] {
            let cfg = FreedomConfig::default(); // default autonomy = Standard
            let (next, prev) = apply_level(cfg, s).expect("valid level");
            assert_eq!(next.autonomy, expected, "level {s} must apply");
            assert_eq!(prev, AutonomyLevel::Standard, "previous is the default");
        }
    }

    #[test]
    fn apply_level_is_case_and_whitespace_insensitive() {
        let (next, _) = apply_level(FreedomConfig::default(), "  ELEVATED  ").expect("normalized");
        assert_eq!(next.autonomy, AutonomyLevel::Elevated);
    }

    #[test]
    fn apply_level_rejects_unknown_with_canonical_list() {
        let err = apply_level(FreedomConfig::default(), "yolo").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("invalid autonomy level"), "got: {msg}");
        assert!(msg.contains("strict") && msg.contains("full"), "lists valid levels: {msg}");
    }

    #[test]
    fn change_event_picks_elevated_derogated_or_none() {
        use crate::wal::events::{EVENT_TYPE_LEVEL_DEROGATED, EVENT_TYPE_LEVEL_ELEVATED};
        // Upward → elevated.
        assert_eq!(
            change_event(AutonomyLevel::Standard, AutonomyLevel::Full),
            Some(EVENT_TYPE_LEVEL_ELEVATED)
        );
        // Downward → derogated.
        assert_eq!(
            change_event(AutonomyLevel::Full, AutonomyLevel::Strict),
            Some(EVENT_TYPE_LEVEL_DEROGATED)
        );
        // To custom (ranks highest) → elevated.
        assert_eq!(
            change_event(AutonomyLevel::Standard, AutonomyLevel::Custom),
            Some(EVENT_TYPE_LEVEL_ELEVATED)
        );
        // Unchanged → no frame.
        assert_eq!(change_event(AutonomyLevel::Elevated, AutonomyLevel::Elevated), None);
    }

    #[test]
    fn apply_mode_full_auto_sets_full_and_enables_all() {
        let cfg = FreedomConfig::default(); // Standard + enable_all_bundled=false
        assert!(!cfg.skills.enable_all_bundled);
        let (next, prev) = apply_mode(cfg, true);
        assert_eq!(prev, AutonomyLevel::Standard);
        assert_eq!(next.autonomy, AutonomyLevel::Full);
        assert!(
            next.skills.enable_all_bundled,
            "full-auto must force-enable the whole bundled library"
        );
        assert_eq!(mode_label(&next), "full-auto");
    }

    #[test]
    fn apply_mode_gated_sets_standard_and_disables_all() {
        let mut cfg = FreedomConfig::default();
        cfg.autonomy = AutonomyLevel::Full;
        cfg.skills.enable_all_bundled = true; // start in full-auto
        let (next, prev) = apply_mode(cfg, false);
        assert_eq!(prev, AutonomyLevel::Full);
        assert_eq!(next.autonomy, AutonomyLevel::Standard);
        assert!(!next.skills.enable_all_bundled, "gated curates the skill set");
        assert_eq!(mode_label(&next), "gated");
    }

    #[test]
    fn mode_label_reports_full_auto_gated_advanced() {
        let mut cfg = FreedomConfig::default();
        assert_eq!(mode_label(&cfg), "gated");
        cfg.autonomy = AutonomyLevel::Full;
        cfg.skills.enable_all_bundled = true;
        assert_eq!(mode_label(&cfg), "full-auto");
        // Power user: Full autonomy but curated skills → advanced, never overclaims.
        cfg.skills.enable_all_bundled = false;
        assert_eq!(mode_label(&cfg), "advanced");
        // Elevated with all-skills is also advanced (not a headline mode).
        cfg.autonomy = AutonomyLevel::Elevated;
        cfg.skills.enable_all_bundled = true;
        assert_eq!(mode_label(&cfg), "advanced");
    }

    #[test]
    fn apply_mode_touches_only_autonomy_and_skill_breadth() {
        // The security floor depends on full-auto NOT silently flipping the
        // dangerous toggles (proactive.enabled, trust_all_tools, unsigned-plugin
        // trust). Pin that apply_mode changes ONLY autonomy + enable_all_bundled.
        let baseline = FreedomConfig::default();
        let (next, _) = apply_mode(baseline.clone(), true);
        let mut normalized = next.clone();
        normalized.autonomy = baseline.autonomy;
        normalized.skills.enable_all_bundled = baseline.skills.enable_all_bundled;
        assert_eq!(
            serde_yaml::to_string(&normalized).unwrap(),
            serde_yaml::to_string(&baseline).unwrap(),
            "full-auto may change ONLY autonomy + skills.enable_all_bundled — \
             no dangerous toggle (proactive / trust_all_tools / plugin trust) may flip"
        );
    }

    #[test]
    fn apply_level_does_not_touch_other_fields() {
        // Only `autonomy` changes — a regression here would silently reset
        // operator config on every `autonomy set`.
        let mut cfg = FreedomConfig::default();
        cfg.autonomy = AutonomyLevel::Strict;
        let baseline = cfg.clone();
        let (next, _) = apply_level(cfg, "full").expect("valid");
        assert_eq!(next.autonomy, AutonomyLevel::Full);
        // Everything except autonomy is identical.
        let mut next_normalized = next.clone();
        next_normalized.autonomy = baseline.autonomy;
        assert_eq!(
            serde_yaml::to_string(&next_normalized).unwrap(),
            serde_yaml::to_string(&baseline).unwrap(),
            "no field other than autonomy may change"
        );
    }
}
