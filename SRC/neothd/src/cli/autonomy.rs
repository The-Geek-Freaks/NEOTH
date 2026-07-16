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
    /// GOLD-ADAPT-JV-MODE-02 — SOVEREIGN-BUDDY operating mode: full-auto PLUS
    /// `proactive.enabled = true` (NEOTH sends unsolicited proactive messages).
    ///
    /// This is the maximum-autonomy preset. It requires:
    ///   • `autonomy: Full` (same as full-auto)
    ///   • `sovereign_buddy: true` (this flag, set only here)
    ///   • `proactive.enabled: true` (forced ON at activation time)
    ///
    /// The irreducible security floor is unchanged (DangerousTarget /
    /// PatchApplyToRepo / SelfBinaryReplace → Confirm; CSAM/bioweapon/WMD
    /// hard-block never lifted). No GUI bypass — TTY-only, no token path.
    ///
    /// Activation requires typing the exact phrase `sovereign` at the prompt
    /// (not y/N). Deactivation (`--disable`) needs no ceremony.
    ///
    /// WAL audit: `0xA2 LEVEL_ELEVATED` + `0xDD SUDOMODE_PRESET_APPLIED` +
    /// `0xD0 CONFIG_RELOADED` (with `sovereign_buddy` in changed_fields).
    /// No new WAL event code — byte space is exhausted (255/256 assigned).
    #[command(name = "sovereign")]
    Sovereign {
        /// Enable sovereign-buddy mode (requires the typed-phrase ceremony).
        #[arg(long, conflicts_with = "disable")]
        enable: bool,
        /// Disable sovereign-buddy mode (no ceremony required).
        #[arg(long, conflicts_with = "enable")]
        disable: bool,
        /// Print current sovereign-buddy status without changing anything.
        #[arg(long)]
        status: bool,
    },
}

/// Pure core of `set`: validate `level`, return the config with the new
/// autonomy applied plus the PREVIOUS level. Separated from disk I/O so the
/// validation + mutation are hermetically testable. Rejects unknown levels
/// with the canonical list in the message.
#[cfg(test)]
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
///
/// GOLD-ADAPT-JV-MODE-02: switching away from full-auto or to gated CLEARS
/// `sovereign_buddy` (returning to a non-sovereign state). This is intentional:
/// sovereign mode is a step BEYOND full-auto; dropping back to gated/full-auto
/// also exits sovereign.
fn apply_mode(cfg: FreedomConfig, full_auto: bool) -> (FreedomConfig, AutonomyLevel) {
    let previous = cfg.autonomy;
    let mut next = cfg;
    next.autonomy = if full_auto {
        AutonomyLevel::Full
    } else {
        AutonomyLevel::Standard
    };
    next.skills.enable_all_bundled = full_auto;
    // Sovereign mode is above full-auto; switching modes always exits it.
    next.sovereign_buddy = false;
    (next, previous)
}

/// GOLD-ADAPT-JV-MODE-02 — pure core of the sovereign-buddy activation.
///
/// Sets `autonomy = Full`, `skills.enable_all_bundled = true`,
/// `sovereign_buddy = true`, and `proactive.enabled = true`.
/// Returns `(updated_config, previous_autonomy_level)`.
///
/// **Does NOT perform the consent ceremony** — that lives in `confirm_sovereign`.
/// **Does NOT touch dangerous toggles** (trust_all_tools, unsigned-plugin trust).
/// The security floor (DangerousTarget / PatchApplyToRepo / SelfBinaryReplace
/// remain Confirm; CSAM/bioweapon/WMD hard-block is never lifted) is unchanged.
fn apply_sovereign_mode(cfg: FreedomConfig) -> (FreedomConfig, AutonomyLevel) {
    let previous = cfg.autonomy;
    let mut next = cfg;
    next.autonomy = AutonomyLevel::Full;
    next.skills.enable_all_bundled = true;
    next.sovereign_buddy = true;
    // Force proactive master switch ON — sovereign = proactive-unattended is the point.
    // This is the only place that deliberately flips proactive.enabled; all other
    // operating-mode switches leave it untouched per the security-floor contract.
    next.proactive.enabled = true;
    (next, previous)
}

/// GOLD-ADAPT-JV-MODE-02 — pure core of the sovereign-buddy deactivation.
///
/// Clears `sovereign_buddy` and drops `proactive.enabled` back to `false`.
/// Does NOT change `autonomy` or `skills.enable_all_bundled` — the operator
/// stays at whatever level they had; only the sovereign flag is lowered.
/// No ceremony required for disable (consent-first only applies to activation).
fn apply_sovereign_disable(cfg: FreedomConfig) -> (FreedomConfig, AutonomyLevel) {
    let previous = cfg.autonomy;
    let mut next = cfg;
    next.sovereign_buddy = false;
    // Proactive was force-enabled by sovereign activation; clear it on exit.
    // Operators who had proactive.enabled=true BEFORE entering sovereign should
    // re-enable it manually — we can't distinguish that case from the force-ON.
    next.proactive.enabled = false;
    (next, previous)
}

/// Human label for the current operating mode, derived from the
/// (autonomy, enable_all_bundled, sovereign_buddy) triple.
///
/// `sovereign-buddy` is the highest label and wins when `sovereign_active()`
/// returns true. `full-auto` is the next tier. A bare `autonomy: full` WITHOUT
/// the skill-breadth flag reads as `advanced` (power user, never overclaims).
///
/// GOLD-ADAPT-JV-MODE-02: sovereign-buddy is a distinct label so tooling
/// and the operator can tell it apart from plain full-auto at a glance.
pub(crate) fn operating_mode_label(cfg: &FreedomConfig) -> &'static str {
    if cfg.sovereign_active() {
        return "sovereign-buddy";
    }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MutationAuditPhase {
    Intent,
    Committed,
    Aborted,
}

impl MutationAuditPhase {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Intent => "intent",
            Self::Committed => "committed",
            Self::Aborted => "aborted",
        }
    }
}

/// Immutable binding shared by every phase of one config publication. The
/// target hash makes an intent reviewable without pretending the publication
/// already happened; only the matching `committed` phase makes that claim.
#[derive(Clone, Debug)]
pub(crate) struct ConfigAuditBinding {
    operation_id: String,
    source_existed: bool,
    source_sha256: String,
    target_sha256: String,
}

impl ConfigAuditBinding {
    pub(crate) fn new(source_existed: bool, source_sha256: String, target_sha256: String) -> Self {
        Self {
            operation_id: uuid::Uuid::now_v7().to_string(),
            source_existed,
            source_sha256,
            target_sha256,
        }
    }

    pub(crate) fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub(crate) fn source_existed(&self) -> bool {
        self.source_existed
    }

    pub(crate) fn source_sha256(&self) -> &str {
        &self.source_sha256
    }

    pub(crate) fn target_sha256(&self) -> &str {
        &self.target_sha256
    }
}

/// Record one phase of an autonomy config transaction. Required posture is
/// based on the actual daemon ACK/local fsynced append, never sidecar reachability.
async fn emit_autonomy_change(
    previous: AutonomyLevel,
    next: AutonomyLevel,
    mode: Option<&str>,
    home: &std::path::Path,
    binding: &ConfigAuditBinding,
    phase: MutationAuditPhase,
    required: bool,
) -> Result<()> {
    // Pick the event from the level delta. Special case: a switch INTO full-auto
    // widens authority (the whole skill library goes live + the gate opens to
    // Full) even when the level was already Full — record that as an elevation
    // so "the operator dropped the gate at time T" always has a WAL anchor.
    let event_type = match change_event(previous, next) {
        Some(e) => e,
        None if mode == Some("full-auto") => crate::wal::events::EVENT_TYPE_LEVEL_ELEVATED,
        None => return Ok(()),
    };
    let payload = serde_json::to_vec(&serde_json::json!({
        "previous": previous.as_str(),
        "next": next.as_str(),
        "mode": mode,
        "source": "cli",
        "operation_id": binding.operation_id(),
        "phase": phase.as_str(),
        "source_existed": binding.source_existed(),
        "source_config_sha256": binding.source_sha256(),
        "target_config_sha256": binding.target_sha256(),
        "ts_unix": crate::time::now_unix_secs(),
    }))
    .context("serialize autonomy mutation audit")?;
    crate::cli::todo::emit_oneshot_audit_at(home, event_type, payload, "AUTONOMY_CHANGE", required)
        .await
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
    home: &std::path::Path,
    binding: &ConfigAuditBinding,
    phase: MutationAuditPhase,
    required: bool,
) -> Result<()> {
    let payload = serde_json::to_vec(&serde_json::json!({
        "previous": previous.as_str(),
        "source": "cli",
        "operation_id": binding.operation_id(),
        "phase": phase.as_str(),
        "source_existed": binding.source_existed(),
        "source_config_sha256": binding.source_sha256(),
        "target_config_sha256": binding.target_sha256(),
        "ts_unix": crate::time::now_unix_secs(),
    }))
    .context("serialize FULL-AUTO mutation audit")?;
    let event_type = crate::wal::events::EVENT_TYPE_SUDOMODE_PRESET_APPLIED;
    crate::cli::todo::emit_oneshot_audit_at(
        home,
        event_type,
        payload,
        "SUDOMODE_PRESET_APPLIED",
        required,
    )
    .await
}

/// Emit both forensic facets of a FULL-AUTO publication under one operation
/// binding. Preset application reuses this instead of independently inventing
/// an authority audit path.
pub(crate) async fn emit_full_auto_audit_phase(
    previous: AutonomyLevel,
    mode: &str,
    home: &std::path::Path,
    binding: &ConfigAuditBinding,
    phase: MutationAuditPhase,
    required: bool,
) -> Result<()> {
    emit_autonomy_change(
        previous,
        AutonomyLevel::Full,
        Some(mode),
        home,
        binding,
        phase,
        required,
    )
    .await?;
    emit_sudomode_preset_applied(previous, home, binding, phase, required).await
}

async fn emit_mode_audit_phase(
    full_auto: bool,
    previous: AutonomyLevel,
    applied: AutonomyLevel,
    mode: &str,
    home: &std::path::Path,
    binding: &ConfigAuditBinding,
    phase: MutationAuditPhase,
    required: bool,
) -> Result<()> {
    if full_auto {
        emit_full_auto_audit_phase(previous, mode, home, binding, phase, required).await
    } else {
        emit_autonomy_change(
            previous,
            applied,
            Some(mode),
            home,
            binding,
            phase,
            required,
        )
        .await
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
        AutonomyAction::Sovereign {
            enable,
            disable,
            status,
        } => run_sovereign(enable, disable, status, output).await,
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
                "sovereign-buddy" => {
                    println!(
                        "          NEOTH acts without asking AND sends unsolicited proactive messages."
                    );
                    println!(
                        "          Deactivate: neoth autonomy sovereign --disable  |  neoth autonomy gated"
                    );
                }
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
    let home = FreedomConfig::default_neoth_home();
    run_set_mode_at(&home, full_auto, gui_confirmed, gui_token, output).await
}

/// Validate/consume the FULL-AUTO ceremony for one exact instance without
/// mutating freedom.yaml. Preset application calls this before its single
/// CAS-bound publication.
pub(crate) async fn authorize_full_auto_at(
    home: &std::path::Path,
    gui_confirmed: bool,
    gui_token: Option<String>,
) -> Result<()> {
    let token_ok = match (gui_confirmed, gui_token.as_deref()) {
        (true, Some(token)) => crate::daemon::audit_rpc::consume_fullauto_token(home, token).await,
        _ => false,
    };
    confirm_full_auto(gui_confirmed, token_ok)
}

async fn run_set_mode_at(
    home: &std::path::Path,
    full_auto: bool,
    gui_confirmed: bool,
    gui_token: Option<String>,
    output: OutputFormat,
) -> Result<()> {
    let path = home.join("freedom.yaml");
    // Validate the exact instance before consuming a one-time GUI token. This
    // read has no mutation; the later prepared publication is independently
    // bound to the exact source bytes it reviews.
    FreedomConfig::load_from_path(&path)
        .context("load freedom.yaml (run `neoth init` first if this is a fresh install)")?;
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
        authorize_full_auto_at(home, gui_confirmed, gui_token).await?;
    }

    let (update, (previous, applied, required_audit)) =
        FreedomConfig::prepare_update_at(&path, |current| {
            let (next, previous) = apply_mode(current.clone(), full_auto);
            let applied = next.autonomy;
            let required = current.audit_rpc.required_for_oneshot_permission_events;
            *current = next;
            Ok((previous, applied, required))
        })
        .context("prepare the operating-mode publication")?;
    let binding = ConfigAuditBinding::new(
        update.source_existed(),
        update.source_sha256(),
        update.target_sha256(),
    );

    emit_mode_audit_phase(
        full_auto,
        previous,
        applied,
        mode,
        home,
        &binding,
        MutationAuditPhase::Intent,
        required_audit,
    )
    .await
    .context("FULL-AUTO/GATED audit intent was not durable; config was not changed")?;
    if let Err(error) = update.commit() {
        let _ = emit_mode_audit_phase(
            full_auto,
            previous,
            applied,
            mode,
            home,
            &binding,
            MutationAuditPhase::Aborted,
            false,
        )
        .await;
        return Err(error).context("operating-mode CAS publication failed; config was not changed");
    }
    emit_mode_audit_phase(
        full_auto,
        previous,
        applied,
        mode,
        home,
        &binding,
        MutationAuditPhase::Committed,
        required_audit,
    )
    .await
    .context("operating mode was published, but its required committed audit failed")?;
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
    let home = FreedomConfig::default_neoth_home();
    let (previous, applied) = set_level_at(&home, &FreedomConfig::default_path(), level).await?;
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

/// Canonical raw-level setter shared by the CLI and slash dispatcher. The
/// mutation reloads freedom.yaml under the cross-process lock, enforces the
/// required-audit posture against that exact snapshot, and atomically writes
/// only the autonomy field.
pub(crate) async fn set_level_at(
    home: &std::path::Path,
    path: &std::path::Path,
    level: &str,
) -> Result<(AutonomyLevel, AutonomyLevel)> {
    let parsed = AutonomyLevel::from_str(&level.trim().to_ascii_lowercase()).ok_or_else(|| {
        anyhow::anyhow!(
            "invalid autonomy level `{level}` — expected one of: strict, standard, elevated, full, custom"
        )
    })?;
    let snapshot = FreedomConfig::load_from_path(path)
        .context("load freedom.yaml (run `neoth init` first if this is a fresh install)")?;
    let full_confirmation =
        if parsed == AutonomyLevel::Full && snapshot.autonomy != AutonomyLevel::Full {
            confirm_full_auto(false, false)?;
            true
        } else {
            false
        };
    let (update, (previous, applied, required_audit)) =
        FreedomConfig::prepare_update_at(path, |cfg| {
            if parsed == AutonomyLevel::Full
                && cfg.autonomy != AutonomyLevel::Full
                && !full_confirmation
            {
                anyhow::bail!(
                    "autonomy changed concurrently before Full confirmation; retry the command"
                );
            }
            let previous = cfg.autonomy;
            let required = cfg.audit_rpc.required_for_oneshot_permission_events;
            cfg.autonomy = parsed;
            Ok((previous, parsed, required))
        })
        .context("prepare the new autonomy level")?;
    let binding = ConfigAuditBinding::new(
        update.source_existed(),
        update.source_sha256(),
        update.target_sha256(),
    );
    emit_autonomy_change(
        previous,
        applied,
        None,
        home,
        &binding,
        MutationAuditPhase::Intent,
        required_audit,
    )
    .await
    .context("autonomy audit intent was not durable; config was not changed")?;
    if let Err(error) = update.commit() {
        let _ = emit_autonomy_change(
            previous,
            applied,
            None,
            home,
            &binding,
            MutationAuditPhase::Aborted,
            false,
        )
        .await;
        return Err(error).context("autonomy CAS publication failed; target was not published");
    }
    emit_autonomy_change(
        previous,
        applied,
        None,
        home,
        &binding,
        MutationAuditPhase::Committed,
        required_audit,
    )
    .await
    .context("autonomy was published, but its required committed audit failed")?;
    Ok((previous, applied))
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
         \x20   targets stay blocked; every plugin still requires an exact approval-bound enable)."
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

/// GOLD-ADAPT-JV-MODE-02 — typed-phrase consent ceremony for sovereign-buddy mode.
///
/// Prints the full consequence list, then requires the operator to type the
/// exact phrase `sovereign` (case-insensitive) before activation is allowed.
/// Deliberately stricter than `confirm_full_auto`:
///   • NO GUI bypass path (no `--gui-confirmed` / `--gui-token` equivalent)
///   • Typed phrase, not y/N — reduces accident-activation risk
///   • Fails closed when stdin is not a TTY with no override
///
/// Called ONLY by `run_sovereign` when `--enable` is requested.
fn confirm_sovereign() -> Result<()> {
    use std::io::{IsTerminal, Write};
    eprintln!("  ⚠  SOVEREIGN-BUDDY MODE — what this enables:");
    eprintln!("     • All Full-Auto actions (shell, writes, channel, token spend) — no confirm");
    eprintln!("     • proactive.enabled = ON — NEOTH sends unsolicited messages autonomously");
    eprintln!("     • Entire bundled skill library enabled and routed proactively");
    eprintln!("     • PC-01 OS tools, cluster task delegation — no per-action confirm");
    eprintln!("  Non-negotiable floor (UNCHANGED — not lifted by this mode):");
    eprintln!("     • WAL audit always-on + non-bypassable (every action logged)");
    eprintln!("     • DangerousTarget / PatchApplyToRepo / SelfBinaryReplace → still Confirm");
    eprintln!("     • CSAM / bioweapon / WMD hard block — never lifted");
    eprintln!("  To deactivate at any time (no ceremony required):");
    eprintln!("     neoth autonomy sovereign --disable");
    eprintln!("     neoth autonomy gated");
    // TTY-only — no GUI bypass for sovereign (deliberately stricter than full-auto).
    if !std::io::stdin().is_terminal() {
        anyhow::bail!(
            "refusing to enable SOVEREIGN-BUDDY without an interactive TTY. \
             This mode has NO GUI bypass — run `neoth autonomy sovereign --enable` at a terminal."
        );
    }
    eprint!("  Type `sovereign` to confirm, or anything else to abort: ");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("read SOVEREIGN-BUDDY confirmation phrase")?;
    if line.trim().eq_ignore_ascii_case("sovereign") {
        Ok(())
    } else {
        anyhow::bail!("aborted: SOVEREIGN-BUDDY not enabled (phrase mismatch)");
    }
}

/// GOLD-ADAPT-JV-MODE-02 — handler for `neoth autonomy sovereign`.
///
/// --enable  : run consent ceremony → apply_sovereign_mode → save → WAL audit
/// --disable : apply_sovereign_disable → save → WAL audit (no ceremony)
/// --status  : print current sovereign status and exit
/// (no flags) : print usage hint
///
/// WAL audit on enable: `0xA2 LEVEL_ELEVATED` + `0xDD SUDOMODE_PRESET_APPLIED`.
/// The subsequent `0xD0 CONFIG_RELOADED` fires automatically when the daemon
/// hot-reloads freedom.yaml and sees `sovereign_buddy` in `changed_fields`.
/// No new WAL event code — byte space is exhausted (255/256 codes assigned).
async fn run_sovereign(
    enable: bool,
    disable: bool,
    status: bool,
    output: OutputFormat,
) -> Result<()> {
    if status || (!enable && !disable) {
        // Status-only path (or bare `neoth autonomy sovereign` with no flags).
        let cfg = FreedomConfig::load_from_default_path()
            .context("load freedom.yaml (run `neoth init` first if this is a fresh install)")?;
        let active = cfg.sovereign_active();
        let mode = operating_mode_label(&cfg);
        match output {
            OutputFormat::Json | OutputFormat::Jsonl => println!(
                "{}",
                serde_json::json!({
                    "mode": mode,
                    "sovereign_buddy": cfg.sovereign_buddy,
                    "sovereign_active": active,
                    "autonomy": cfg.autonomy.as_str(),
                })
            ),
            OutputFormat::Table => {
                println!(
                    "sovereign-buddy: {}",
                    if active { "ACTIVE" } else { "inactive" }
                );
                println!("  sovereign_buddy flag: {}", cfg.sovereign_buddy);
                println!("  autonomy:            {}", cfg.autonomy.as_str());
                println!("  mode:                {mode}");
                if cfg.sovereign_buddy && !active {
                    println!(
                        "  note: flag is set but autonomy is not Full \
                         → sovereign_active() = false. Use `neoth autonomy full-auto` first, \
                         or re-enable with `neoth autonomy sovereign --enable`."
                    );
                }
            }
        }
        return Ok(());
    }

    let home = FreedomConfig::default_neoth_home();
    let path = FreedomConfig::default_path();

    if enable {
        // Consent ceremony — TTY-only, typed phrase, no GUI bypass.
        confirm_sovereign()?;
        let (update, (previous, applied, required_audit)) =
            FreedomConfig::prepare_update_at(&path, |cfg| {
                let required = cfg.audit_rpc.required_for_oneshot_permission_events;
                let (next, previous) = apply_sovereign_mode(cfg.clone());
                let applied = next.autonomy;
                *cfg = next;
                Ok((previous, applied, required))
            })
            .context("prepare sovereign-buddy mode")?;
        let binding = ConfigAuditBinding::new(
            update.source_existed(),
            update.source_sha256(),
            update.target_sha256(),
        );
        emit_full_auto_audit_phase(
            previous,
            "sovereign-buddy",
            &home,
            &binding,
            MutationAuditPhase::Intent,
            required_audit,
        )
        .await
        .context("sovereign audit intent was not durable; config was not changed")?;
        if let Err(error) = update.commit() {
            let _ = emit_full_auto_audit_phase(
                previous,
                "sovereign-buddy",
                &home,
                &binding,
                MutationAuditPhase::Aborted,
                false,
            )
            .await;
            return Err(error)
                .context("sovereign CAS publication failed; target was not published");
        }
        // WAL audit: 0xA2 LEVEL_ELEVATED + 0xDD SUDOMODE_PRESET_APPLIED.
        // The 0xD0 CONFIG_RELOADED fires automatically on next daemon hot-reload
        // when it sees sovereign_buddy in changed_fields. Three-frame sequence
        // provides equivalent forensic coverage to a dedicated event code
        // (byte space is exhausted — no new code possible).
        emit_full_auto_audit_phase(
            previous,
            "sovereign-buddy",
            &home,
            &binding,
            MutationAuditPhase::Committed,
            required_audit,
        )
        .await
        .context("sovereign mode was published, but its required committed audit failed")?;
        match output {
            OutputFormat::Json | OutputFormat::Jsonl => println!(
                "{}",
                serde_json::json!({
                    "mode": "sovereign-buddy",
                    "autonomy": applied.as_str(),
                    "previous": previous.as_str(),
                    "sovereign_buddy": true,
                    "proactive_enabled": true,
                })
            ),
            OutputFormat::Table => {
                println!("operating mode: SOVEREIGN-BUDDY (saved to freedom.yaml)");
                println!("  autonomy:         {} -> full", previous.as_str());
                println!("  sovereign_buddy:  true");
                println!("  proactive:        enabled");
                println!(
                    "  ⚠ NEOTH now acts WITHOUT asking AND sends unsolicited proactive messages."
                );
                println!(
                    "    Security floor unchanged (DangerousTarget / PatchApplyToRepo / WMD stay blocked)."
                );
                println!("  Deactivate: neoth autonomy sovereign --disable");
            }
        }
    } else {
        // Disable path — no ceremony.
        let (update, (previous, mode_after)) = FreedomConfig::prepare_update_at(&path, |cfg| {
            let (next, previous) = apply_sovereign_disable(cfg.clone());
            let mode_after = operating_mode_label(&next);
            *cfg = next;
            Ok((previous, mode_after))
        })
        .context("prepare sovereign-buddy disable")?;
        update
            .commit()
            .context("persist sovereign-buddy disable to freedom.yaml")?;
        match output {
            OutputFormat::Json | OutputFormat::Jsonl => println!(
                "{}",
                serde_json::json!({
                    "mode": mode_after,
                    "sovereign_buddy": false,
                    "previous_autonomy": previous.as_str(),
                })
            ),
            OutputFormat::Table => {
                println!("sovereign-buddy: DISABLED (saved to freedom.yaml)");
                println!("  proactive.enabled cleared to false");
                println!("  autonomy unchanged: {}", previous.as_str());
                println!("  To return to full-auto without sovereign: neoth autonomy full-auto");
            }
        }
    }
    Ok(())
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
        let binding = ConfigAuditBinding::new(false, "a".repeat(64), "b".repeat(64));
        emit_sudomode_preset_applied(
            AutonomyLevel::Standard,
            tmp.path(),
            &binding,
            MutationAuditPhase::Committed,
            true,
        )
        .await
        .unwrap();
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

    // -----------------------------------------------------------------------
    // GOLD-ADAPT-JV-MODE-02 — sovereign-buddy tests
    // -----------------------------------------------------------------------

    #[test]
    fn apply_sovereign_mode_sets_full_and_proactive_and_flag() {
        let cfg = FreedomConfig::default();
        assert!(!cfg.sovereign_buddy);
        assert!(!cfg.proactive.enabled);
        let (next, prev) = apply_sovereign_mode(cfg);
        assert_eq!(prev, AutonomyLevel::Standard);
        assert_eq!(next.autonomy, AutonomyLevel::Full);
        assert!(
            next.skills.enable_all_bundled,
            "full skill set must be enabled"
        );
        assert!(next.sovereign_buddy, "sovereign_buddy flag must be set");
        assert!(
            next.proactive.enabled,
            "proactive.enabled must be forced ON"
        );
    }

    #[test]
    fn sovereign_active_requires_both_flag_and_full_autonomy() {
        // Flag set but autonomy not Full → inactive.
        let mut cfg = FreedomConfig::default();
        cfg.sovereign_buddy = true;
        cfg.autonomy = AutonomyLevel::Elevated;
        assert!(
            !cfg.sovereign_active(),
            "sovereign_active must be false when autonomy < Full"
        );
        // Full autonomy but flag not set → inactive.
        cfg.sovereign_buddy = false;
        cfg.autonomy = AutonomyLevel::Full;
        assert!(
            !cfg.sovereign_active(),
            "sovereign_active must be false when flag is not set"
        );
        // Both set → active.
        cfg.sovereign_buddy = true;
        assert!(
            cfg.sovereign_active(),
            "sovereign_active must be true when flag=true AND autonomy=Full"
        );
    }

    #[test]
    fn operating_mode_label_sovereign_takes_precedence_over_full_auto() {
        let mut cfg = FreedomConfig::default();
        cfg.autonomy = AutonomyLevel::Full;
        cfg.skills.enable_all_bundled = true;
        // Without sovereign flag: full-auto.
        assert_eq!(operating_mode_label(&cfg), "full-auto");
        // With sovereign flag: sovereign-buddy (distinct label).
        cfg.sovereign_buddy = true;
        assert_eq!(operating_mode_label(&cfg), "sovereign-buddy");
    }

    #[test]
    fn apply_mode_clears_sovereign_buddy_on_any_switch() {
        // Start in sovereign state.
        let mut cfg = FreedomConfig::default();
        cfg.sovereign_buddy = true;
        cfg.autonomy = AutonomyLevel::Full;
        cfg.skills.enable_all_bundled = true;
        // Switch to gated → sovereign_buddy cleared.
        let (next, _) = apply_mode(cfg.clone(), false);
        assert!(
            !next.sovereign_buddy,
            "gated switch must clear sovereign_buddy"
        );
        // Switch to full-auto → sovereign_buddy still cleared.
        let (next2, _) = apply_mode(cfg, true);
        assert!(
            !next2.sovereign_buddy,
            "full-auto switch must also clear sovereign_buddy"
        );
    }

    #[test]
    fn apply_sovereign_disable_clears_flag_and_proactive() {
        let mut cfg = FreedomConfig::default();
        cfg.sovereign_buddy = true;
        cfg.autonomy = AutonomyLevel::Full;
        cfg.proactive.enabled = true;
        let (next, prev) = apply_sovereign_disable(cfg);
        assert_eq!(prev, AutonomyLevel::Full);
        assert!(!next.sovereign_buddy, "flag must be cleared on disable");
        assert!(
            !next.proactive.enabled,
            "proactive.enabled must be cleared on disable"
        );
        // autonomy is NOT changed by disable.
        assert_eq!(
            next.autonomy,
            AutonomyLevel::Full,
            "disable must not touch autonomy level"
        );
    }

    #[test]
    fn apply_sovereign_mode_does_not_flip_dangerous_toggles() {
        // Sovereign mode may only change autonomy, skills.enable_all_bundled,
        // sovereign_buddy, and proactive.enabled. It must NOT touch trust_all_tools
        // or any unsigned-plugin trust field.
        let baseline = FreedomConfig::default();
        let (next, _) = apply_sovereign_mode(baseline.clone());
        // Normalize the fields that ARE expected to change.
        let mut normalized = next.clone();
        normalized.autonomy = baseline.autonomy;
        normalized.skills.enable_all_bundled = baseline.skills.enable_all_bundled;
        normalized.sovereign_buddy = baseline.sovereign_buddy;
        normalized.proactive.enabled = baseline.proactive.enabled;
        assert_eq!(
            serde_yaml::to_string(&normalized).unwrap(),
            serde_yaml::to_string(&baseline).unwrap(),
            "apply_sovereign_mode must change ONLY autonomy + skills.enable_all_bundled \
             + sovereign_buddy + proactive.enabled — no other field may flip"
        );
    }

    #[test]
    fn confirm_sovereign_fails_closed_when_not_a_tty() {
        // Sovereign ceremony must refuse when stdin is not a terminal —
        // same pattern as confirm_full_auto_fails_closed_when_not_a_tty.
        let err = confirm_sovereign().unwrap_err();
        assert!(
            err.to_string().contains("interactive TTY"),
            "must fail closed without a TTY: {err}"
        );
    }

    #[test]
    fn sovereign_buddy_default_is_false() {
        // The field must default to false so existing freedom.yaml files
        // that predate this field are unaffected.
        let cfg = FreedomConfig::default();
        assert!(
            !cfg.sovereign_buddy,
            "sovereign_buddy must default to false"
        );
        assert!(
            !cfg.sovereign_active(),
            "sovereign_active must be false by default"
        );
    }

    #[test]
    fn operating_mode_label_unchanged_for_full_auto_without_sovereign() {
        // Regression: sovereign_buddy=false must not change the full-auto label.
        let mut cfg = FreedomConfig::default();
        cfg.autonomy = AutonomyLevel::Full;
        cfg.skills.enable_all_bundled = true;
        cfg.sovereign_buddy = false;
        assert_eq!(
            operating_mode_label(&cfg),
            "full-auto",
            "full-auto label must not regress when sovereign_buddy is false"
        );
    }
}
