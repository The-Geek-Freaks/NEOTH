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
    /// GR-RESID-D34 — mint a single-use, short-TTL FULL-AUTO token from the
    /// running daemon and print it (bare token on stdout). The NEOTH GUI runs
    /// this after its confirm dialog, then passes the token to `full-auto
    /// --gui-token <t>`. Hidden — not an operator-facing command; requires a live
    /// daemon (errors otherwise).
    #[command(name = "mint-fullauto-token", hide = true)]
    MintFullautoToken,
    /// FULL-AUTO operating mode: autonomy `full` + the ENTIRE bundled skill
    /// library force-enabled (all 98 skills route proactively) + the router
    /// confidence floor raised so generic triggers can't false-activate. NEOTH
    /// acts without asking. The irreducible security floor still holds
    /// (self-replace / patch-apply / dangerous targets stay Confirm; revoked &
    /// invalid-signature plugins stay refused; `proactive.enabled`,
    /// `trust_all_tools` and unsigned-plugin trust are NOT flipped — each needs
    /// its own opt-in). Same effect as `neoth sudomode`.
    #[command(name = "full-auto")]
    FullAuto {
        /// Internal: the NEOTH GUI's own explicit two-step confirm dialog
        /// already obtained operator consent → skip the interactive TTY y/N.
        /// The consequence banner is still printed and the 0xDD
        /// SUDOMODE_PRESET_APPLIED audit frame still fires; the security floor is
        /// unchanged. Hidden so the bare `neoth autonomy full-auto` path stays
        /// interactive + fail-closed (GR-101 accident-protection).
        #[arg(long, hide = true)]
        gui_confirmed: bool,
        /// GR-RESID-D34 — the single-use, short-TTL token the GUI minted from the
        /// daemon (via `audit_rpc::mint_fullauto_token`) right after its confirm
        /// dialog. Required alongside `--gui-confirmed` for the TTY bypass; a
        /// stale/absent token is refused (it can't be baked into a script).
        #[arg(long, hide = true)]
        gui_token: Option<String>,
    },
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
pub(crate) fn operating_mode_label(cfg: &FreedomConfig) -> &'static str {
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

/// GOLD-FEAT-01c — record `0xDD SUDOMODE_PRESET_APPLIED` when the full-auto
/// preset is applied (autonomy → Full + the whole bundled skill library): a
/// dedicated forensic anchor distinct from the generic LEVEL_ELEVATED that
/// `emit_autonomy_change` already records, so a reader can pinpoint the gate
/// being dropped via the full-auto/sudomode preset specifically. Same
/// best-effort daemon-forward-else-one-shot path. Payload `{previous, source,
/// ts_unix}`.
async fn emit_sudomode_preset_applied(
    previous: AutonomyLevel,
    daemon_live: bool,
    home: &std::path::Path,
) {
    let payload = serde_json::to_vec(&serde_json::json!({
        "previous": previous.as_str(),
        "source": "cli",
        "ts_unix": crate::time::now_unix_secs(),
    }))
    .unwrap_or_else(|_| b"{}".to_vec());
    let event_type = crate::wal::events::EVENT_TYPE_SUDOMODE_PRESET_APPLIED;
    if daemon_live {
        if let Err(e) =
            crate::daemon::audit_rpc::try_post_audit_frame(home, event_type, &payload).await
        {
            tracing::debug!(error = %e, "sudomode-preset audit forward failed (best-effort)");
        }
    } else {
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
        AutonomyAction::Gated => run_set_mode(false, false, None, output).await,
        AutonomyAction::MintFullautoToken => run_mint_fullauto_token(output).await,
        AutonomyAction::FullAuto {
            gui_confirmed,
            gui_token,
        } => run_set_mode(true, gui_confirmed, gui_token, output).await,
    }
}

fn run_show(output: OutputFormat) -> Result<()> {
    let cfg = FreedomConfig::load_from_default_path()
        .context("load freedom.yaml (run `neoth init` first if this is a fresh install)")?;
    let mode = operating_mode_label(&cfg);
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
/// GR-RESID-D34 — mint a FULL-AUTO token at the running daemon + print it. The
/// GUI captures the bare-token stdout, then spawns `neoth autonomy full-auto
/// --gui-confirmed --gui-token <t>`. Errors (non-zero exit) when no daemon is
/// reachable — FULL-AUTO via the GUI requires the daemon; the operator can
/// always enable it at a TTY with `neoth sudomode`.
async fn run_mint_fullauto_token(output: OutputFormat) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    match crate::daemon::audit_rpc::mint_fullauto_token(&home).await {
        Some(token) => {
            match output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    println!("{}", serde_json::json!({ "token": token }))
                }
                _ => println!("{token}"),
            }
            Ok(())
        }
        None => anyhow::bail!(
            "could not mint a FULL-AUTO token — is the daemon running? The GUI FULL-AUTO bypass \
             needs a live daemon; otherwise enable it at a TTY with `neoth sudomode`."
        ),
    }
}

async fn run_set_mode(
    full_auto: bool,
    gui_confirmed: bool,
    gui_token: Option<String>,
    output: OutputFormat,
) -> Result<()> {
    let cfg = FreedomConfig::load_from_default_path()
        .context("load freedom.yaml (run `neoth init` first if this is a fresh install)")?;
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
    // GR-101 / GR-RESID-D34 — FULL-AUTO is the most permissive mode (NEOTH acts
    // WITHOUT asking: shell, channel sends, writes, token spend). Require an
    // explicit confirmation BEFORE persisting it. The default un-flagged CLI path
    // fails closed off a TTY, so `neoth autonomy full-auto` from a script/cron
    // can't silently flip it. The GUI passes `--gui-confirmed` AND a
    // `--gui-token` the daemon minted (single-use, short-TTL) right after the
    // GUI's confirm dialog; we CONSUME it here. Flag presence alone no longer
    // bypasses — a stale/absent token fails the gate — so the bypass can't be
    // baked into a script. Switching back to GATED needs no confirmation.
    if full_auto {
        let token_ok = match (gui_confirmed, gui_token.as_deref()) {
            (true, Some(t)) => crate::daemon::audit_rpc::consume_fullauto_token(&home, t).await,
            _ => false,
        };
        confirm_full_auto(gui_confirmed, token_ok)?;
    }
    next.save_public_to_default_path()
        .context("persist the operating mode to freedom.yaml")?;
    emit_autonomy_change(previous, applied, Some(mode), daemon_live, &home).await;
    // GOLD-FEAT-01c — a dedicated forensic anchor for the full-auto/sudomode
    // preset, distinct from the generic LEVEL_ELEVATED above: records that the
    // operator dropped the gate specifically via the full-auto preset.
    if full_auto {
        emit_sudomode_preset_applied(previous, daemon_live, &home).await;
    }
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
                println!(
                    "  skills:   curated set (run `neoth skill enable <id>` for individual extras)"
                );
                println!("  NEOTH asks before sensitive actions.");
            }
        }
    }
    Ok(())
}

async fn run_set(level: &str, output: OutputFormat) -> Result<()> {
    let cfg = FreedomConfig::load_from_default_path()
        .context("load freedom.yaml (run `neoth init` first if this is a fresh install)")?;
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
    // GR-101 — escalating to the most-permissive Full level via `neoth autonomy
    // set full` needs the same explicit confirmation as `sudomode` (fail closed
    // when stdin is not a TTY). A no-op (already Full) or a de-escalation needs
    // no confirmation.
    if applied == AutonomyLevel::Full && previous != AutonomyLevel::Full {
        // The raw `neoth autonomy set full` path stays interactive (no GUI
        // pre-confirm, no token) — pass false/false so it fails closed without
        // a TTY.
        confirm_full_auto(false, false)?;
    }
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

/// GR-101 / GR-RESID-D34 — confirm enabling the most-permissive FULL autonomy
/// before it is persisted. Prints the consequence, then requires an interactive
/// y/N. The default (un-flagged) path fails closed when stdin is not a terminal,
/// so the bare CLI can't enable FULL-AUTO unattended / from a script. The GUI
/// path (`--gui-confirmed`) bypasses the TTY check ONLY when `token_ok` — i.e.
/// the caller already CONSUMED a daemon-minted, single-use, short-TTL token
/// (`--gui-token`) at the daemon. Flag presence alone is NO LONGER enough: a
/// `--gui-confirmed` without a valid fresh token is refused, so the bypass can't
/// be baked into a script/cron.
fn confirm_full_auto(pre_confirmed: bool, token_ok: bool) -> Result<()> {
    use std::io::{IsTerminal, Write};
    eprintln!(
        "  ⚠ FULL-AUTO lets NEOTH act WITHOUT asking — shell commands, channel sends, writes,\n\
         \x20   and token spend happen automatically (self-replace / patch-apply / dangerous\n\
         \x20   targets / unsigned plugins stay blocked)."
    );
    // GR-RESID-D34 — the GUI bypass now requires a CONSUMED daemon token, not
    // just the flag. The consequence banner above still printed and the 0xDD
    // audit frame still fires downstream.
    if pre_confirmed {
        if token_ok {
            return Ok(());
        }
        anyhow::bail!(
            "--gui-confirmed now requires a fresh daemon-minted --gui-token (single-use, \
             short-TTL); the NEOTH GUI mints one after its confirm dialog. A bare \
             --gui-confirmed no longer bypasses the TTY gate. Run `neoth sudomode` at a TTY, \
             or enable FULL-AUTO from the GUI."
        );
    }
    if !std::io::stdin().is_terminal() {
        anyhow::bail!(
            "refusing to enable FULL-AUTO without an interactive confirmation (stdin is not a \
             terminal). Run `neoth sudomode` at a TTY, or stay gated with `neoth autonomy gated`."
        );
    }
    eprint!("  Enable FULL-AUTO? [y/N]: ");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("read FULL-AUTO confirmation")?;
    let ans = line.trim().to_ascii_lowercase();
    if ans == "y" || ans == "yes" {
        Ok(())
    } else {
        anyhow::bail!("aborted: FULL-AUTO not enabled");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// GOLD-FEAT-01c: applying the full-auto preset writes a dedicated
    /// `0xDD SUDOMODE_PRESET_APPLIED` forensic frame (one-shot path, no daemon).
    #[tokio::test]
    async fn sudomode_preset_emits_0xdd_wal_frame() {
        let tmp = tempfile::TempDir::new().unwrap();
        let segment = tmp.path().join("wal").join("000001.wal");
        // daemon_live=false → deterministic one-shot writer path.
        emit_sudomode_preset_applied(AutonomyLevel::Standard, false, tmp.path()).await;
        let bytes = std::fs::read(&segment).expect("wal segment written");
        let mut found = 0usize;
        let _ = crate::wal::scan::for_each_frame(&bytes, |_, dec| {
            if dec.header.event_type == crate::wal::events::EVENT_TYPE_SUDOMODE_PRESET_APPLIED {
                found += 1;
            }
            Ok(())
        });
        assert_eq!(
            found, 1,
            "full-auto preset must write one 0xDD SUDOMODE_PRESET_APPLIED frame"
        );
    }

    /// GR-RESID-D34: a GUI call bypasses the TTY gate ONLY with a consumed
    /// daemon token (`token_ok=true`); flag presence alone no longer suffices.
    #[test]
    fn confirm_full_auto_bypasses_only_with_consumed_token() {
        confirm_full_auto(true, true).expect("gui-confirmed + valid token must bypass");
    }

    #[test]
    fn confirm_full_auto_gui_flag_without_token_is_refused() {
        // GR-RESID-D34: a bare --gui-confirmed (no fresh daemon token) must be
        // REFUSED — closes the "bake the flag into a script/cron" bypass.
        let err = confirm_full_auto(true, false).unwrap_err();
        assert!(
            err.to_string().contains("--gui-token"),
            "must demand a daemon-minted token: {err}"
        );
    }

    #[test]
    fn confirm_full_auto_fails_closed_when_not_a_tty() {
        // GR-101: enabling FULL-AUTO from a non-interactive stdin (the test
        // harness has no TTY) must be REFUSED, never silently persisted.
        let err = confirm_full_auto(false, false).unwrap_err();
        assert!(
            err.to_string().contains("not a terminal"),
            "must fail closed without a TTY: {err}"
        );
    }

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
        assert!(
            msg.contains("strict") && msg.contains("full"),
            "lists valid levels: {msg}"
        );
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
        assert_eq!(
            change_event(AutonomyLevel::Elevated, AutonomyLevel::Elevated),
            None
        );
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
        assert_eq!(operating_mode_label(&next), "full-auto");
    }

    #[test]
    fn apply_mode_gated_sets_standard_and_disables_all() {
        let mut cfg = FreedomConfig::default();
        cfg.autonomy = AutonomyLevel::Full;
        cfg.skills.enable_all_bundled = true; // start in full-auto
        let (next, prev) = apply_mode(cfg, false);
        assert_eq!(prev, AutonomyLevel::Full);
        assert_eq!(next.autonomy, AutonomyLevel::Standard);
        assert!(
            !next.skills.enable_all_bundled,
            "gated curates the skill set"
        );
        assert_eq!(operating_mode_label(&next), "gated");
    }

    #[test]
    fn mode_label_reports_full_auto_gated_advanced() {
        let mut cfg = FreedomConfig::default();
        assert_eq!(operating_mode_label(&cfg), "gated");
        cfg.autonomy = AutonomyLevel::Full;
        cfg.skills.enable_all_bundled = true;
        assert_eq!(operating_mode_label(&cfg), "full-auto");
        // Power user: Full autonomy but curated skills → advanced, never overclaims.
        cfg.skills.enable_all_bundled = false;
        assert_eq!(operating_mode_label(&cfg), "advanced");
        // Elevated with all-skills is also advanced (not a headline mode).
        cfg.autonomy = AutonomyLevel::Elevated;
        cfg.skills.enable_all_bundled = true;
        assert_eq!(operating_mode_label(&cfg), "advanced");
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
