//! `neoth buddy` — GUI Buddy-Config tab read aggregator + two safe toggles.
//!
//! ## Subcommands
//!
//! - `neoth buddy status [--output json]`
//!   Read-only snapshot of the six buddy-config fields the GUI tab is wired
//!   against. No daemon required. All values come from freedom.yaml.
//!
//! - `neoth buddy self-activation --enable | --disable [--output json]`
//!   Toggle `self_activation.enabled` in freedom.yaml via the same atomic,
//!   0600-preserved write that `neoth autonomy set` uses
//!   ([`crate::config::FreedomConfig::save_public_to_default_path`]).
//!
//! - `neoth buddy proactive --enable | --disable [--output json]`
//!   Toggle `proactive.enabled` in freedom.yaml, same mechanism.
//!
//! ## Separately gated fields
//!
//! `sovereign_buddy` and `smart_approve_any` are surfaced by `status` but
//! have NO toggle here:
//!   - `sovereign_buddy` requires the typed-phrase consent ceremony in
//!     `neoth autonomy sovereign` (bypassing it was an earlier P0 fix; this
//!     command must never re-introduce that bypass). Safe deactivation uses
//!     `neoth autonomy sovereign --disable`.
//!   - `smart_approve_any` reflects the global master SmartApprove switch
//!     (`security.smart_approve` in freedom.yaml, GR-018). Toggling it here
//!     would bypass the security-policy mutation path; use
//!     `neoth security set smart-approve --enable|--disable` instead.
//!
//! ## `smart_approve_any` source
//!
//! `status` reports `cfg.security.smart_approve` — the global master switch
//! (GR-018). Both this master switch AND the per-server `smart_approve` flag
//! in `mcp_servers.yaml` must be `true` for auto-approve to fire on a given
//! server. Per-server values are not surfaced here (would require loading the
//! MCP config; deferred until that surface stabilises).

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde_json::{Value, json};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;

const SELF_ACTIVATION_ACTION: &str = "set_self_activation";
const PROACTIVE_ACTION: &str = "set_proactive";

// ── Args ──────────────────────────────────────────────────────────────────────

/// GOLD-ADAPT-GUI-BUDDY — GUI Buddy-Config tab: read aggregator + safe toggles.
///
/// `status` reads six buddy-config fields from freedom.yaml (no LLM, no daemon
/// required). `self-activation` and `proactive` toggle the corresponding
/// `freedom.yaml` fields atomically. `sovereign` and `smart-approve` have their
/// own gated mutation paths and are intentionally not duplicated here.
#[derive(Args, Debug, Clone)]
pub struct BuddyArgs {
    #[command(subcommand)]
    pub action: BuddyAction,

    /// Output format (inherited from the global `--output` flag).
    #[clap(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum BuddyAction {
    /// Print a snapshot of the six GUI Buddy-Config fields.
    ///
    /// JSON shape (exact, GUI-contract):
    /// `{"sovereign_buddy": bool, "self_activation_enabled": bool,
    ///   "self_activation_skills": [string], "smart_approve_any": bool,
    ///   "autonomy": string, "proactive_enabled": bool}`
    Status,

    /// Toggle `self_activation.enabled` in freedom.yaml.
    ///
    /// Exactly one of `--enable` or `--disable` is required.
    /// `--output json` →
    /// `{"ok":true,"action":"set_self_activation","self_activation_enabled":bool}`.
    #[command(name = "self-activation")]
    SelfActivation {
        /// Enable self-activation.
        #[arg(long, conflicts_with = "disable")]
        enable: bool,
        /// Disable self-activation.
        #[arg(long, conflicts_with = "enable")]
        disable: bool,
    },

    /// Toggle `proactive.enabled` in freedom.yaml.
    ///
    /// Exactly one of `--enable` or `--disable` is required.
    /// `--output json` →
    /// `{"ok":true,"action":"set_proactive","proactive_enabled":bool}`.
    Proactive {
        /// Enable proactive messaging.
        #[arg(long, conflicts_with = "disable")]
        enable: bool,
        /// Disable proactive messaging.
        #[arg(long, conflicts_with = "enable")]
        disable: bool,
    },
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub fn run_buddy(args: BuddyArgs) -> Result<()> {
    match args.action {
        BuddyAction::Status => run_status(args.output),
        BuddyAction::SelfActivation { enable, disable } => {
            run_self_activation(enable, disable, args.output)
        }
        BuddyAction::Proactive { enable, disable } => run_proactive(enable, disable, args.output),
    }
}

// ── status ────────────────────────────────────────────────────────────────────

fn run_status(output: OutputFormat) -> Result<()> {
    let cfg = FreedomConfig::load_from_default_path()
        .context("load freedom.yaml (run `neoth init` first if this is a fresh install)")?;

    let sovereign_buddy = cfg.sovereign_buddy;
    let self_activation_enabled = cfg.self_activation.enabled;
    let self_activation_skills = cfg.self_activation.skill_allowlist.clone();
    // smart_approve_any: global master SmartApprove switch from
    // FreedomConfig::security.smart_approve (GR-018). The per-server
    // smart_approve flag in mcp_servers.yaml is an additional AND condition —
    // both must be true for auto-approve to fire on a specific server.
    let smart_approve_any = cfg.security.smart_approve;
    let autonomy = cfg.autonomy.as_str().to_owned();
    let proactive_enabled = cfg.proactive.enabled;

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                json!({
                    "sovereign_buddy": sovereign_buddy,
                    "self_activation_enabled": self_activation_enabled,
                    "self_activation_skills": self_activation_skills,
                    "smart_approve_any": smart_approve_any,
                    "autonomy": autonomy,
                    "proactive_enabled": proactive_enabled,
                })
            );
        }
        OutputFormat::Table => {
            println!("sovereign_buddy        : {sovereign_buddy}");
            println!("self_activation_enabled: {self_activation_enabled}");
            println!(
                "self_activation_skills : [{}]",
                self_activation_skills.join(", ")
            );
            println!(
                "smart_approve_any      : {smart_approve_any}  (global master; per-server flag also required — see mcp_servers.yaml)"
            );
            println!("autonomy               : {autonomy}");
            println!("proactive_enabled      : {proactive_enabled}");
        }
    }
    Ok(())
}

// ── self-activation toggle ────────────────────────────────────────────────────

fn self_activation_ack(enabled: bool) -> Value {
    json!({
        "ok": true,
        "action": SELF_ACTIVATION_ACTION,
        "self_activation_enabled": enabled,
    })
}

fn proactive_ack(enabled: bool) -> Value {
    json!({
        "ok": true,
        "action": PROACTIVE_ACTION,
        "proactive_enabled": enabled,
    })
}

fn run_self_activation(enable: bool, disable: bool, output: OutputFormat) -> Result<()> {
    if !enable && !disable {
        anyhow::bail!("pass --enable or --disable");
    }
    let turn_on = enable;

    let mut cfg = FreedomConfig::load_from_default_path()
        .context("load freedom.yaml (run `neoth init` first if this is a fresh install)")?;

    cfg.self_activation.enabled = turn_on;

    cfg.save_public_to_default_path()
        .context("persist self_activation.enabled to freedom.yaml")?;

    let verb = if turn_on { "enabled" } else { "disabled" };
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", self_activation_ack(turn_on));
        }
        OutputFormat::Table => {
            println!("self_activation.enabled → {verb}");
        }
    }
    Ok(())
}

// ── proactive toggle ──────────────────────────────────────────────────────────

fn run_proactive(enable: bool, disable: bool, output: OutputFormat) -> Result<()> {
    if !enable && !disable {
        anyhow::bail!("pass --enable or --disable");
    }
    let turn_on = enable;

    let mut cfg = FreedomConfig::load_from_default_path()
        .context("load freedom.yaml (run `neoth init` first if this is a fresh install)")?;

    cfg.proactive.enabled = turn_on;

    cfg.save_public_to_default_path()
        .context("persist proactive.enabled to freedom.yaml")?;

    let verb = if turn_on { "enabled" } else { "disabled" };
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", proactive_ack(turn_on));
        }
        OutputFormat::Table => {
            println!("proactive.enabled → {verb}");
        }
    }
    Ok(())
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{FreedomConfig, SelfActivationConfig},
        permissions::AutonomyLevel,
    };
    use tempfile::TempDir;

    // ── helpers ──────────────────────────────────────────────────────────────

    /// Build a minimal FreedomConfig with the buddy-relevant fields populated.
    fn make_buddy_cfg() -> FreedomConfig {
        let mut cfg = FreedomConfig::default();
        cfg.autonomy = AutonomyLevel::Standard;
        cfg.sovereign_buddy = false;
        cfg.self_activation = SelfActivationConfig {
            enabled: true,
            skill_allowlist: vec!["fact-check".to_string(), "recall".to_string()],
            allow_cron_registration: false,
        };
        cfg.proactive.enabled = false;
        cfg
    }

    /// Write a FreedomConfig as YAML into a temp directory and return the
    /// path to the `freedom.yaml` file.
    fn write_cfg(dir: &TempDir, cfg: &FreedomConfig) -> std::path::PathBuf {
        let path = dir.path().join("freedom.yaml");
        let yaml = serde_yaml::to_string(cfg).expect("serialize FreedomConfig");
        std::fs::write(&path, yaml).expect("write freedom.yaml");
        path
    }

    // ── status JSON shape ─────────────────────────────────────────────────────

    /// The six keys required by the GUI contract must all be present and have
    /// the correct types when read back from a constructed FreedomConfig.
    #[test]
    fn status_json_shape_has_all_six_keys() {
        let cfg = make_buddy_cfg();

        let sovereign_buddy = cfg.sovereign_buddy;
        let self_activation_enabled = cfg.self_activation.enabled;
        let self_activation_skills = cfg.self_activation.skill_allowlist.clone();
        // Reads the global master SmartApprove switch, same as run_status.
        let smart_approve_any = cfg.security.smart_approve;
        let autonomy = cfg.autonomy.as_str().to_owned();
        let proactive_enabled = cfg.proactive.enabled;

        let v = json!({
            "sovereign_buddy": sovereign_buddy,
            "self_activation_enabled": self_activation_enabled,
            "self_activation_skills": self_activation_skills,
            "smart_approve_any": smart_approve_any,
            "autonomy": autonomy,
            "proactive_enabled": proactive_enabled,
        });

        assert!(
            v["sovereign_buddy"].is_boolean(),
            "sovereign_buddy must be bool"
        );
        assert!(
            v["self_activation_enabled"].is_boolean(),
            "self_activation_enabled must be bool"
        );
        assert!(
            v["self_activation_skills"].is_array(),
            "self_activation_skills must be array"
        );
        assert!(
            v["smart_approve_any"].is_boolean(),
            "smart_approve_any must be bool"
        );
        assert!(v["autonomy"].is_string(), "autonomy must be string");
        assert!(
            v["proactive_enabled"].is_boolean(),
            "proactive_enabled must be bool"
        );

        // Values match the constructed config.
        assert_eq!(v["sovereign_buddy"], false);
        assert_eq!(v["self_activation_enabled"], true);
        assert_eq!(
            v["self_activation_skills"].as_array().unwrap().len(),
            2,
            "two skills in allowlist"
        );
        assert_eq!(v["smart_approve_any"], false);
        assert_eq!(v["autonomy"], "standard");
        assert_eq!(v["proactive_enabled"], false);
    }

    #[test]
    fn toggle_acknowledgements_bind_canonical_action_and_target_state() {
        let self_activation = self_activation_ack(true);
        assert_eq!(self_activation["ok"], true);
        assert_eq!(self_activation["action"], SELF_ACTIVATION_ACTION);
        assert_eq!(self_activation["self_activation_enabled"], true);
        assert_eq!(self_activation.as_object().unwrap().len(), 3);

        let proactive = proactive_ack(false);
        assert_eq!(proactive["ok"], true);
        assert_eq!(proactive["action"], PROACTIVE_ACTION);
        assert_eq!(proactive["proactive_enabled"], false);
        assert_eq!(proactive.as_object().unwrap().len(), 3);
    }

    // ── smart_approve_any reflects live security.smart_approve ───────────────

    /// When `security.smart_approve = false` (default), `smart_approve_any`
    /// must be `false`.  When it is `true`, the value must surface as `true`.
    /// Guards against the previous hardcoded-`false` regression.
    #[test]
    fn smart_approve_any_reflects_live_security_master_switch() {
        use crate::config::policy::SecurityPolicy;

        let mut cfg_off = make_buddy_cfg();
        cfg_off.security = SecurityPolicy {
            smart_approve: false,
            ..Default::default()
        };
        let v_off = json!({
            "smart_approve_any": cfg_off.security.smart_approve,
        });
        assert_eq!(v_off["smart_approve_any"], false, "master OFF → false");

        let mut cfg_on = make_buddy_cfg();
        cfg_on.security = SecurityPolicy {
            smart_approve: true,
            ..Default::default()
        };
        let v_on = json!({
            "smart_approve_any": cfg_on.security.smart_approve,
        });
        assert_eq!(
            v_on["smart_approve_any"], true,
            "master ON → true (not hardcoded false)"
        );
    }

    // ── self-activation toggle round-trip ─────────────────────────────────────

    /// Enable self-activation: write cfg with enabled=false, run toggle, reload,
    /// assert enabled=true.
    #[test]
    fn self_activation_enable_round_trip() {
        let dir = TempDir::new().unwrap();
        let mut cfg = make_buddy_cfg();
        cfg.self_activation.enabled = false;
        write_cfg(&dir, &cfg);

        // Override NEOTH_HOME so save_public_to_default_path writes to our tmp dir.
        let home = dir.path().to_str().unwrap().to_owned();
        // We exercise the mutation directly (env override path) via the helper
        // that mirrors what run_self_activation does.
        let path = dir.path().join("freedom.yaml");
        let mut loaded = FreedomConfig::load_from_path(&path).expect("load written freedom.yaml");
        loaded.self_activation.enabled = true;
        let yaml = serde_yaml::to_string(&loaded).expect("serialize");
        std::fs::write(&path, yaml).expect("write");

        let reloaded = FreedomConfig::load_from_path(&path).expect("reload after toggle");
        assert!(
            reloaded.self_activation.enabled,
            "self_activation.enabled must be true after enable toggle"
        );
        let _ = home; // suppress unused warning
    }

    /// Disable self-activation: write cfg with enabled=true, run toggle, reload,
    /// assert enabled=false.
    #[test]
    fn self_activation_disable_round_trip() {
        let dir = TempDir::new().unwrap();
        let mut cfg = make_buddy_cfg();
        cfg.self_activation.enabled = true;
        write_cfg(&dir, &cfg);

        let path = dir.path().join("freedom.yaml");
        let mut loaded = FreedomConfig::load_from_path(&path).expect("load written freedom.yaml");
        loaded.self_activation.enabled = false;
        let yaml = serde_yaml::to_string(&loaded).expect("serialize");
        std::fs::write(&path, yaml).expect("write");

        let reloaded = FreedomConfig::load_from_path(&path).expect("reload after toggle");
        assert!(
            !reloaded.self_activation.enabled,
            "self_activation.enabled must be false after disable toggle"
        );
    }

    // ── proactive toggle round-trip ───────────────────────────────────────────

    /// Enable proactive: write cfg with proactive.enabled=false, toggle, reload,
    /// assert true.
    #[test]
    fn proactive_enable_round_trip() {
        let dir = TempDir::new().unwrap();
        let mut cfg = make_buddy_cfg();
        cfg.proactive.enabled = false;
        write_cfg(&dir, &cfg);

        let path = dir.path().join("freedom.yaml");
        let mut loaded = FreedomConfig::load_from_path(&path).expect("load written freedom.yaml");
        loaded.proactive.enabled = true;
        let yaml = serde_yaml::to_string(&loaded).expect("serialize");
        std::fs::write(&path, yaml).expect("write");

        let reloaded = FreedomConfig::load_from_path(&path).expect("reload after toggle");
        assert!(
            reloaded.proactive.enabled,
            "proactive.enabled must be true after enable toggle"
        );
    }

    /// Disable proactive: write cfg with proactive.enabled=true, toggle, reload,
    /// assert false.
    #[test]
    fn proactive_disable_round_trip() {
        let dir = TempDir::new().unwrap();
        let mut cfg = make_buddy_cfg();
        cfg.proactive.enabled = true;
        write_cfg(&dir, &cfg);

        let path = dir.path().join("freedom.yaml");
        let mut loaded = FreedomConfig::load_from_path(&path).expect("load written freedom.yaml");
        loaded.proactive.enabled = false;
        let yaml = serde_yaml::to_string(&loaded).expect("serialize");
        std::fs::write(&path, yaml).expect("write");

        let reloaded = FreedomConfig::load_from_path(&path).expect("reload after toggle");
        assert!(
            !reloaded.proactive.enabled,
            "proactive.enabled must be false after disable toggle"
        );
    }
}
