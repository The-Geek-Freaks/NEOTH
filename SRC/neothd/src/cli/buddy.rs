//! `neoth buddy` — GUI Buddy-Config tab read aggregator + two safe toggles.
//!
//! ## Subcommands
//!
//! - `neoth buddy status [--output json]`
//!   Read-only snapshot of the buddy-config fields plus admitted Skill caps
//!   against. No daemon required. All values come from freedom.yaml.
//!
//! - `neoth buddy self-activation --enable | --disable [--output json]`
//!   Toggle `self_activation.enabled` in freedom.yaml via the same atomic,
//!   lossless locked update that `neoth autonomy set` uses
//!   ([`crate::config::FreedomConfig::update_at`]).
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

use std::path::PathBuf;

use anyhow::{Context, Result};
#[cfg(feature = "cluster")]
use clap::ValueEnum;
use clap::{Args, Subcommand};
#[cfg(feature = "cluster")]
use serde::Serialize;
use serde_json::{Value, json};

use crate::cli::OutputFormat;
use crate::cli::models::EmbeddingModelsAction;
use crate::config::FreedomConfig;
use crate::daemon::local_models_ipc::LocalModelsIpcClient;
use crate::daemon::vault_mirror;
use crate::self_improve::passive;

const SELF_ACTIVATION_ACTION: &str = "set_self_activation";
const PROACTIVE_ACTION: &str = "set_proactive";
const VAULT_MIRROR_REPAIR_ACTION: &str = "vault_mirror_repair";

// ── Args ──────────────────────────────────────────────────────────────────────

/// GOLD-ADAPT-GUI-BUDDY — GUI Buddy-Config tab: read aggregator + safe toggles.
///
/// `status` reads buddy-config fields plus local authority-admitted Skill caps
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
    /// Print a snapshot of the GUI Buddy-Config fields plus admitted Skill caps.
    ///
    /// JSON shape (exact, GUI-contract):
    /// `{"sovereign_buddy": bool, "self_activation_enabled": bool,
    ///   "self_activation_skills": [string], "smart_approve_any": bool,
    ///   "autonomy": string, "proactive_enabled": bool,
    ///   "skill_autonomy_caps": [{"id": string, "configured": object,
    ///   "effective_cap": object, "origin": string}],
    ///   "local_models": LocalModelsSnapshot | {"kind":"unavailable"}}`
    Status,

    /// Inspect or explicitly operate the selected local embedding model using
    /// the same lifecycle owner as `neoth models embedding`.
    /// `--config` binds the operation to that exact instance home.
    Embedding {
        #[arg(long, value_name = "PATH")]
        config: Option<PathBuf>,
        #[command(subcommand)]
        action: EmbeddingModelsAction,
    },

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

    /// Read or reconcile the same private vault-mirror service used by
    /// `neoth backup mirror`; this surface has no policy bypass.
    #[command(name = "vault-mirror")]
    VaultMirror {
        #[command(subcommand)]
        action: BuddyVaultMirrorAction,
    },

    /// Membership pairing and revocation through the same daemon/offline
    /// authority controller used by `neoth cluster`.
    #[cfg(feature = "cluster")]
    Cluster {
        #[command(subcommand)]
        action: BuddyClusterAction,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum BuddyVaultMirrorAction {
    /// Read the mirror receipt without starting Git.
    Status,
    /// Reconcile only a durable ambiguous push receipt against its exact ref.
    Repair,
}

#[cfg(feature = "cluster")]
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum BuddyClusterCarrier {
    Peeroxide,
    Iroh,
}

#[cfg(feature = "cluster")]
impl From<BuddyClusterCarrier> for crate::cluster::membership::CarrierKind {
    fn from(value: BuddyClusterCarrier) -> Self {
        match value {
            BuddyClusterCarrier::Peeroxide => Self::Peeroxide,
            BuddyClusterCarrier::Iroh => Self::Iroh,
        }
    }
}

#[cfg(feature = "cluster")]
#[derive(Subcommand, Debug, Clone)]
pub enum BuddyClusterAction {
    /// Summarize the versioned membership-authority snapshot.
    Status,
    /// Issue a short-lived, carrier-bound one-time enrollment invite.
    Invite {
        #[arg(long)]
        stable_node_id: String,
        #[arg(long)]
        signing_public_key: String,
        #[arg(long, value_enum)]
        carrier: BuddyClusterCarrier,
        #[arg(long)]
        transport_identity: String,
        #[arg(long)]
        endpoint: String,
        #[arg(long)]
        label: String,
        #[arg(long, default_value_t = 300)]
        ttl_secs: u64,
    },
    /// Confirm an invite with the peer's signed EndpointAttestation JSON.
    Confirm {
        #[arg(long)]
        invite_id: String,
        #[arg(long)]
        attestation: PathBuf,
        #[arg(long, value_enum)]
        carrier: BuddyClusterCarrier,
        #[arg(long)]
        transport_identity: String,
        #[arg(long)]
        endpoint: String,
    },
    /// Permanently revoke the current membership incarnation.
    Revoke { stable_node_id: String },
    /// Read one durable UUIDv7 revocation request and its recovery state.
    RevokeStatus { request_id: String },
    /// List authoritative durable Pending and Indeterminate revocation requests.
    RevokeUnresolved,
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub async fn run_buddy(args: BuddyArgs) -> Result<()> {
    match args.action {
        BuddyAction::Status => run_status(args.output).await,
        BuddyAction::Embedding { config, action } => {
            crate::cli::models::run_embedding_models(action, config.as_deref(), &args.output)
                .await
        }
        BuddyAction::SelfActivation { enable, disable } => {
            run_self_activation(enable, disable, args.output)
        }
        BuddyAction::Proactive { enable, disable } => run_proactive(enable, disable, args.output),
        BuddyAction::VaultMirror { action } => run_vault_mirror(action, args.output).await,
        #[cfg(feature = "cluster")]
        BuddyAction::Cluster { action } => run_cluster(action, args.output).await,
    }
}

#[cfg(feature = "cluster")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct BuddyClusterSummary {
    active: usize,
    pending: usize,
    revoked: usize,
    live: usize,
    pending_outbox: u64,
}

#[cfg(feature = "cluster")]
fn summarize_buddy_cluster(
    envelope: &crate::cluster::membership::MembershipSnapshotEnvelope,
    now: i64,
) -> Result<BuddyClusterSummary> {
    envelope.validate()?;
    let snapshot = &envelope.snapshot;
    let active = snapshot
        .members
        .iter()
        .filter(|member| member.state == crate::cluster::membership::MembershipState::Active)
        .count();
    let pending = snapshot
        .members
        .iter()
        .filter(|member| member.state == crate::cluster::membership::MembershipState::Pending)
        .count();
    let revoked = snapshot
        .members
        .iter()
        .filter(|member| member.state == crate::cluster::membership::MembershipState::Revoked)
        .count();
    let live = snapshot
        .members
        .iter()
        .filter(|member| {
            member.state == crate::cluster::membership::MembershipState::Active
                && member
                    .bindings
                    .iter()
                    .any(|binding| binding.expires_at_unix.is_none_or(|expiry| expiry > now))
        })
        .count();
    Ok(BuddyClusterSummary {
        active,
        pending,
        revoked,
        live,
        pending_outbox: snapshot.pending_outbox,
    })
}

#[cfg(feature = "cluster")]
fn render_typed<T: Serialize>(value: &T, output: OutputFormat) -> Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(value)?),
        OutputFormat::Jsonl => println!("{}", serde_json::to_string(value)?),
        OutputFormat::Table => println!("{}", serde_json::to_string_pretty(value)?),
    }
    Ok(())
}

#[cfg(feature = "cluster")]
async fn run_cluster(action: BuddyClusterAction, output: OutputFormat) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    match action {
        BuddyClusterAction::Status => {
            let envelope = crate::cli::cluster::load_membership_snapshot_envelope(&home).await?;
            let summary = summarize_buddy_cluster(&envelope, crate::time::now_unix_i64())?;
            match output {
                OutputFormat::Table => {
                    println!(
                        "membership v{}: active={} pending={} revoked={} live={} outbox={}",
                        envelope.snapshot_version,
                        summary.active,
                        summary.pending,
                        summary.revoked,
                        summary.live,
                        summary.pending_outbox
                    );
                    if let Some(health) = crate::cluster::membership::inspect_authority_read_only(
                        &home,
                        crate::time::now_unix_i64(),
                    )? {
                        println!(
                            "revocations: pending={} indeterminate={}",
                            health.pending_revocations, health.indeterminate_revocations
                        );
                    }
                    Ok(())
                }
                _ => render_typed(&envelope, output),
            }
        }
        BuddyClusterAction::Invite {
            stable_node_id,
            signing_public_key,
            carrier,
            transport_identity,
            endpoint,
            label,
            ttl_secs,
        } => {
            anyhow::ensure!(
                (1..=300).contains(&ttl_secs),
                "invite TTL must be between 1 and 300 seconds"
            );
            let now = crate::time::now_unix_i64();
            let request = crate::cluster::membership::MembershipInviteRequest {
                stable_node_id: crate::cluster::membership::StableNodeId::parse(stable_node_id)?,
                signing_public_key_hex: signing_public_key,
                carrier: carrier.into(),
                transport_identity: crate::cluster::membership::TransportIdentity::parse(
                    transport_identity,
                )?,
                endpoint,
                label,
                expires_at_unix: now.saturating_add(i64::try_from(ttl_secs)?),
            };
            let receipt = crate::cli::cluster::create_membership_invite(&home, request).await?;
            render_typed(
                &json!({"progress":"invite_issued","receipt":receipt}),
                output,
            )
        }
        BuddyClusterAction::Confirm {
            invite_id,
            attestation,
            carrier,
            transport_identity,
            endpoint,
        } => {
            let bytes = std::fs::read(&attestation)
                .with_context(|| format!("read endpoint attestation {}", attestation.display()))?;
            let attestation = serde_json::from_slice(&bytes)
                .with_context(|| format!("parse endpoint attestation {}", attestation.display()))?;
            let request = crate::cluster::membership::MembershipConfirmRequest {
                invite_id,
                attestation,
                carrier: carrier.into(),
                authenticated_transport: crate::cluster::membership::TransportIdentity::parse(
                    transport_identity,
                )?,
                endpoint,
            };
            let receipt = crate::cli::cluster::confirm_membership_invite(&home, request).await?;
            render_typed(
                &json!({"progress":"membership_active","receipt":receipt}),
                output,
            )
        }
        BuddyClusterAction::Revoke { stable_node_id } => {
            let receipt =
                crate::cli::cluster::revoke_membership_receipt(&home, &stable_node_id).await?;
            render_typed(&receipt, output)
        }
        BuddyClusterAction::RevokeStatus { request_id } => {
            let status =
                crate::cli::cluster::membership_revocation_status_receipt(&home, &request_id)
                    .await?;
            render_typed(&status, output)
        }
        BuddyClusterAction::RevokeUnresolved => {
            let health = crate::cli::cluster::membership_runtime_health(&home).await?;
            render_typed(&health, output)
        }
    }
}

// ── status ────────────────────────────────────────────────────────────────────

async fn run_status(output: OutputFormat) -> Result<()> {
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
    let home = FreedomConfig::default_neoth_home();
    let vault_mirror =
        crate::cli::backup::mirror_status_wire(&vault_mirror::status(&home, &cfg.vault_mirror));
    let local_models = buddy_local_models_status(&home).await;
    let self_improve_quality = passive::quality_snapshot(&home);
    let path = FreedomConfig::default_path();
    let mut skill_autonomy_caps = Vec::new();
    for (skill_id, configured) in &cfg.custom_autonomy.skill_overrides {
        let inventory =
            crate::cli::autonomy::skill_inventory_status(&home, &path, cfg.clone(), skill_id)
                .await?;
        if inventory.admitted {
            skill_autonomy_caps.push(json!({
                "id": skill_id.as_str(),
                "configured": configured,
                "effective_cap": configured,
                "origin": inventory.origin,
            }));
        }
    }

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
                    "skill_autonomy_caps": skill_autonomy_caps,
                    "self_improve_quality": self_improve_quality,
                    "vault_mirror": vault_mirror,
                    "local_models": local_models,
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
            println!(
                "skill_autonomy_caps     : {}",
                serde_json::to_string(&skill_autonomy_caps)?
            );
            println!(
                "self_improve_quality    : {}",
                serde_json::to_string(&self_improve_quality)?
            );
            println!("vault_mirror            : {}", vault_mirror);
            println!("local_models            : {}", local_models);
        }
    }
    Ok(())
}

/// Buddy stays available when `neoth serve` is down. A successful value is the
/// exact daemon snapshot; the fallback deliberately has no invented readiness.
async fn buddy_local_models_status(home: &std::path::Path) -> Value {
    let Ok(client) = LocalModelsIpcClient::discover(home) else {
        return json!({"kind": "unavailable", "detail": "local-model daemon IPC unavailable"});
    };
    match client.status().await {
        Ok(snapshot) => crate::cli::models::local_models_snapshot_wire(&snapshot),
        Err(_) => json!({"kind": "unavailable", "detail": "local-model daemon IPC unavailable"}),
    }
}

async fn run_vault_mirror(action: BuddyVaultMirrorAction, output: OutputFormat) -> Result<()> {
    let cfg = FreedomConfig::load_from_default_path().context(
        "load freedom.yaml for vault mirror (run `neoth init` first if this is a fresh install)",
    )?;
    let home = FreedomConfig::default_neoth_home();
    let is_repair = matches!(action, BuddyVaultMirrorAction::Repair);
    let status = match action {
        BuddyVaultMirrorAction::Status => vault_mirror::status(&home, &cfg.vault_mirror),
        BuddyVaultMirrorAction::Repair => vault_mirror::repair(&home, &cfg.vault_mirror).await,
    };
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            if is_repair {
                println!("{}", vault_mirror_repair_ack(&status));
            } else {
                println!("{}", crate::cli::backup::mirror_status_wire(&status));
            }
        }
        OutputFormat::Table => crate::cli::backup::render_mirror_status(&status, output)?,
    }
    Ok(())
}

/// A reconciliation is successful only when the core reports no remaining
/// action.  Blocked and indeterminate outcomes retain their exact status for
/// the caller and never receive a misleading success acknowledgement.
fn vault_mirror_repair_ack(status: &vault_mirror::VaultMirrorStatus) -> Value {
    json!({
        "ok": matches!(&status.repair, vault_mirror::MirrorRepairAdvice::NoAction),
        "action": VAULT_MIRROR_REPAIR_ACTION,
        "vault_mirror": crate::cli::backup::mirror_status_wire(status),
    })
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

    let path = FreedomConfig::default_path();
    set_self_activation_at(&path, turn_on)?;

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

fn set_self_activation_at(path: &std::path::Path, enabled: bool) -> Result<()> {
    FreedomConfig::update_at(path, |config| {
        config.self_activation.enabled = enabled;
        Ok(())
    })
    .context("persist self_activation.enabled to freedom.yaml")
}

// ── proactive toggle ──────────────────────────────────────────────────────────

fn run_proactive(enable: bool, disable: bool, output: OutputFormat) -> Result<()> {
    if !enable && !disable {
        anyhow::bail!("pass --enable or --disable");
    }
    let turn_on = enable;

    let path = FreedomConfig::default_path();
    set_proactive_at(&path, turn_on)?;

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

fn set_proactive_at(path: &std::path::Path, enabled: bool) -> Result<()> {
    FreedomConfig::update_at(path, |config| {
        config.proactive.enabled = enabled;
        Ok(())
    })
    .context("persist proactive.enabled to freedom.yaml")
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{FreedomConfig, SelfActivationConfig},
        permissions::AutonomyLevel,
    };
    use clap::Parser;
    use tempfile::TempDir;

    #[derive(Debug, Parser)]
    struct BuddyCli {
        #[command(flatten)]
        args: BuddyArgs,
    }

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

    /// The seven keys required by the GUI contract must all be present and have
    /// the correct types when read back from a constructed FreedomConfig.
    #[test]
    fn status_json_shape_has_all_seven_keys() {
        let cfg = make_buddy_cfg();

        let sovereign_buddy = cfg.sovereign_buddy;
        let self_activation_enabled = cfg.self_activation.enabled;
        let self_activation_skills = cfg.self_activation.skill_allowlist.clone();
        // Reads the global master SmartApprove switch, same as run_status.
        let smart_approve_any = cfg.security.smart_approve;
        let autonomy = cfg.autonomy.as_str().to_owned();
        let proactive_enabled = cfg.proactive.enabled;
        let skill_autonomy_caps = Vec::<Value>::new();

        let v = json!({
            "sovereign_buddy": sovereign_buddy,
            "self_activation_enabled": self_activation_enabled,
            "self_activation_skills": self_activation_skills,
            "smart_approve_any": smart_approve_any,
            "autonomy": autonomy,
            "proactive_enabled": proactive_enabled,
            "skill_autonomy_caps": skill_autonomy_caps,
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
        assert!(
            v["skill_autonomy_caps"].is_array(),
            "skill_autonomy_caps must be array"
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
        assert!(v["skill_autonomy_caps"].as_array().unwrap().is_empty());
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

    #[test]
    fn vault_mirror_surface_parses_status_and_repair_without_a_bypass_flag() {
        let status = BuddyCli::try_parse_from(["buddy", "vault-mirror", "status"])
            .expect("vault-mirror status parses");
        assert!(matches!(
            status.args.action,
            BuddyAction::VaultMirror {
                action: BuddyVaultMirrorAction::Status
            }
        ));
        let repair = BuddyCli::try_parse_from(["buddy", "vault-mirror", "repair"])
            .expect("vault-mirror repair parses");
        assert!(matches!(
            repair.args.action,
            BuddyAction::VaultMirror {
                action: BuddyVaultMirrorAction::Repair
            }
        ));
    }

    #[test]
    fn buddy_embedding_parses_all_actions_and_rejects_unknown_action() {
        for action in ["list", "status", "probe", "pull", "repair", "prune"] {
            let cli = BuddyCli::try_parse_from([
                "buddy",
                "embedding",
                "--config",
                "C:/instances/blue/freedom.yaml",
                action,
            ])
            .expect("embedding action parses");
            let parsed = match cli.args.action {
                BuddyAction::Embedding {
                    config: Some(_),
                    action,
                } => action,
                _ => panic!("expected configured embedding action"),
            };
            assert!(matches!(
                (action, parsed),
                ("list", EmbeddingModelsAction::List)
                    | ("status", EmbeddingModelsAction::Status)
                    | ("probe", EmbeddingModelsAction::Probe)
                    | ("pull", EmbeddingModelsAction::Pull)
                    | ("repair", EmbeddingModelsAction::Repair)
                    | ("prune", EmbeddingModelsAction::Prune)
            ));
        }

        let select = BuddyCli::try_parse_from([
            "buddy",
            "embedding",
            "--config",
            "C:/instances/blue/freedom.yaml",
            "select",
            "bge_m3",
        ])
        .expect("embedding select parses");
        assert!(matches!(
            select.args.action,
            BuddyAction::Embedding {
                config: Some(_),
                action: EmbeddingModelsAction::Select { .. },
            }
        ));
        assert!(BuddyCli::try_parse_from(["buddy", "embedding", "refresh"]).is_err());
    }

    #[tokio::test]
    async fn buddy_embedding_select_mutates_only_supplied_config_and_preserves_unknown_fields() {
        let home = tempfile::tempdir().expect("temp home");
        let path = home.path().join("operator-blue.yaml");
        let yaml = serde_yaml::to_string(&FreedomConfig::default()).expect("serialize config");
        std::fs::write(&path, format!("{yaml}buddy_extension: retain-me\n"))
            .expect("write custom config");

        run_buddy(BuddyArgs {
            action: BuddyAction::Embedding {
                config: Some(path.clone()),
                action: EmbeddingModelsAction::Select {
                    model: crate::cli::models::EmbeddingModelArg::BgeM3,
                },
            },
            output: OutputFormat::Json,
        })
        .await
        .expect("custom-config embedding select succeeds");

        let readback = FreedomConfig::load_from_path(&path).expect("read selected config");
        assert_eq!(
            readback.embed.model,
            crate::config::embedding::EmbeddingModel::BgeM3
        );
        assert!(std::fs::read_to_string(&path)
            .expect("read custom config")
            .contains("buddy_extension: retain-me"));
        assert!(
            !home.path().join("freedom.yaml").exists(),
            "selection must not create or mutate a sibling default config"
        );
    }

    #[tokio::test]
    async fn buddy_embedding_qwen_actions_fail_before_lifecycle_side_effects() {
        let home = tempfile::tempdir().expect("temp home");
        let path = write_cfg(&home, &FreedomConfig::default());
        let before = std::fs::read(&path).expect("read config before refusal");

        for action in [
            EmbeddingModelsAction::Probe,
            EmbeddingModelsAction::Pull,
            EmbeddingModelsAction::Repair,
            EmbeddingModelsAction::Prune,
        ] {
            let error = run_buddy(BuddyArgs {
                action: BuddyAction::Embedding {
                    config: Some(path.clone()),
                    action,
                },
                output: OutputFormat::Json,
            })
            .await
            .expect_err("Qwen action must be rejected before lifecycle work");
            assert!(error.to_string().contains("Qwen") || error.to_string().contains("qwen"));
        }

        assert_eq!(
            std::fs::read(&path).expect("read config after refusal"),
            before,
            "rejected Qwen actions must not mutate the supplied config"
        );
        assert!(
            !home.path().join("models").exists(),
            "rejected Qwen actions must not create a model cache"
        );
    }

    #[test]
    fn unresolved_vault_mirror_repair_ack_is_not_success() {
        let status = vault_mirror::VaultMirrorStatus {
            config: vault_mirror::MirrorConfigStatus::Blocked,
            receipt: None,
            repair: vault_mirror::MirrorRepairAdvice::RunVerification,
        };
        let ack = vault_mirror_repair_ack(&status);
        assert_eq!(ack["ok"], false);
        assert_eq!(ack["action"], VAULT_MIRROR_REPAIR_ACTION);
        assert_eq!(ack["vault_mirror"]["repair"], "run_verification");
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

        let path = dir.path().join("freedom.yaml");
        set_self_activation_at(&path, true).expect("enable self activation");

        let reloaded = FreedomConfig::load_from_path(&path).expect("reload after toggle");
        assert!(
            reloaded.self_activation.enabled,
            "self_activation.enabled must be true after enable toggle"
        );
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
        set_self_activation_at(&path, false).expect("disable self activation");

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
        let mut source = std::fs::read_to_string(&path).expect("read fixture");
        source.push_str("future_buddy_extension:\n  keep: true\n");
        std::fs::write(&path, source).expect("seed future field");
        set_proactive_at(&path, true).expect("enable proactive mode");

        let reloaded = FreedomConfig::load_from_path(&path).expect("reload after toggle");
        assert!(
            reloaded.proactive.enabled,
            "proactive.enabled must be true after enable toggle"
        );
        let raw: serde_yaml::Value =
            serde_yaml::from_slice(&std::fs::read(&path).expect("read updated fixture"))
                .expect("parse updated fixture");
        assert_eq!(raw["future_buddy_extension"]["keep"].as_bool(), Some(true));
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
        set_proactive_at(&path, false).expect("disable proactive mode");

        let reloaded = FreedomConfig::load_from_path(&path).expect("reload after toggle");
        assert!(
            !reloaded.proactive.enabled,
            "proactive.enabled must be false after disable toggle"
        );
    }

    #[cfg(feature = "cluster")]
    #[test]
    fn buddy_cluster_summary_derives_from_shared_validated_envelope() {
        let snapshot = crate::cluster::membership::MembershipSnapshot {
            version: crate::cluster::membership::MEMBERSHIP_SNAPSHOT_VERSION,
            authority_path: PathBuf::from("authority.db"),
            authority_epoch: crate::cluster::membership::MembershipEpoch::new(4).unwrap(),
            revocation_floor: crate::cluster::membership::MembershipEpoch::new(3).unwrap(),
            pending_outbox: 2,
            members: Vec::new(),
        };
        let envelope = snapshot.clone().into_envelope().unwrap();
        let summary = summarize_buddy_cluster(&envelope, 1_700_000_000).unwrap();
        assert_eq!(envelope.snapshot, snapshot);
        assert_eq!(
            envelope.operation,
            crate::cluster::membership::MEMBERSHIP_SNAPSHOT_OPERATION
        );
        assert_eq!(summary.pending_outbox, snapshot.pending_outbox);
        assert_eq!(
            serde_json::to_value(&envelope).unwrap()["snapshot_digest"],
            snapshot.canonical_digest().unwrap()
        );
    }

    #[cfg(feature = "cluster")]
    #[test]
    fn buddy_cluster_is_only_a_thin_shared_controller_orchestrator() {
        let source = include_str!("buddy.rs");
        let cluster = source
            .split("async fn run_cluster")
            .nth(1)
            .expect("Buddy cluster action block")
            .split("// ── status")
            .next()
            .expect("end of Buddy cluster action block");
        for forbidden in [
            "MembershipStore::",
            "rusqlite::",
            "cluster-membership.db",
            "MembershipController::",
        ] {
            assert!(
                !cluster.contains(forbidden),
                "Buddy must not create an alternate membership store path: {forbidden}"
            );
        }
        for shared in [
            "load_membership_snapshot_envelope",
            "create_membership_invite",
            "confirm_membership_invite",
            "revoke_membership_receipt",
            "membership_revocation_status_receipt",
            "membership_runtime_health",
        ] {
            assert!(
                cluster.contains(shared),
                "Buddy action does not delegate to shared cluster path: {shared}"
            );
        }
    }

    #[cfg(feature = "cluster")]
    #[test]
    fn buddy_revoke_uses_the_exact_cluster_receipt_schema() {
        let shared = crate::cli::cluster::MembershipRevokeCommandReceipt {
            operation: "cluster.membership.revoke".into(),
            requested_peer: "a".repeat(64),
            request_id: crate::cluster::membership::new_revocation_request_id(),
            matched: false,
            receipt: None,
        };
        let cluster_bytes = serde_json::to_vec(&shared).unwrap();
        let buddy_bytes = serde_json::to_vec(&shared).unwrap();
        assert_eq!(buddy_bytes, cluster_bytes);
    }

    #[cfg(feature = "cluster")]
    #[test]
    fn buddy_revoke_status_uses_the_exact_shared_core_envelope() {
        let request_id = crate::cluster::membership::new_revocation_request_id();
        let shared = crate::cluster::membership::MembershipRevocationStatusEnvelope::new(
            request_id.clone(),
            None,
        )
        .unwrap();
        let buddy: crate::cli::cluster::MembershipRevocationStatusCommandReceipt = shared.clone();
        assert_eq!(buddy.operation, "cluster.membership.revoke_status");
        assert_eq!(buddy.request_id, request_id);
        assert!(!buddy.found);
        assert_eq!(
            serde_json::to_vec(&buddy).unwrap(),
            serde_json::to_vec(&shared).unwrap()
        );

        let health = crate::cluster::membership::MembershipRuntimeHealth {
            wire_version: crate::cluster::membership::MEMBERSHIP_RUNTIME_HEALTH_WIRE_VERSION,
            live_generations: Vec::new(),
            invalid_live_generations: Vec::new(),
            unresolved_revocations: Vec::new(),
        };
        health.validate().unwrap();
        let buddy_health: crate::cluster::membership::MembershipRuntimeHealth =
            serde_json::from_slice(&serde_json::to_vec(&health).unwrap()).unwrap();
        assert_eq!(buddy_health, health);
    }
}
