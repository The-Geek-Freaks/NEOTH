//! Permission gating — bridge between `neoth-plugin-sdk`'s sealed
//! typestate machinery and the daemon's runtime decision logic.
//!
//! Phase 33b SP-3 — re-exports the SDK types and adds the `Action` /
//! `AutonomyLevel` / `Decision` triad that Phase 28b R-23 will dispatch on.
//!
//! ## Layering
//!
//! - **Compile time** (`neoth-plugin-sdk::permission`): `PermissionToken<L>`
//!   is zero-sized, sealed, and only `mint()`-able with the `_host` feature.
//!   Tools require `&PermissionToken<L>` so plugin authors cannot bypass
//!   typestate.
//! - **Runtime** (this module): the daemon picks an [`AutonomyLevel`] at
//!   onboarding (R-23) and consults [`evaluate`] before minting a token.
//!   Decisions are `Allow` / `Confirm(reason)` / `Deny(reason)`.
//!
//! Until R-23 lands, `evaluate` is conservative: it returns `Allow` for
//! reads, `Confirm` for writes / shell / paid provider calls, `Deny` for
//! dangerous targets. That matches the `standard` level NEOTH will default
//! to when the wizard is added.

pub mod audit;
pub mod confirm;
pub mod gate;
pub mod lease;
pub mod tier_classifier;

pub use gate::{ConfirmStrategy, Gate};

// SP-3 bridge: re-export the SDK's sealed-typestate primitives so daemon code
// can refer to `crate::permissions::PermissionToken<Read>` without coupling
// callers to the plugin SDK crate name. allow(unused_imports) because the
// non-test code paths reach these via fully-qualified SDK paths today;
// the bridge is for the R-23 wizard + permission tests.
#[allow(unused_imports)]
pub use neoth_plugin_sdk::permission::{
    Dangerous, Execute, FreedomGrant, None as NoPermission, PermissionLevel, PermissionToken,
    ReadOnly, UnauthorizedLevel,
};

/// Classifies what NEOTH is about to do, independent of how the action
/// arrived (CLI / channel / cron / hook).
///
/// `Eq` deliberately not derived: `PaidProviderCall { eur_estimate: f32 }`
/// holds a float and `f32: !Eq`. Comparing two `Action`s via `==` works
/// (via `PartialEq`) and is intentionally NaN-sensitive — two distinct
/// NaN payloads should not collapse into one decision.
#[derive(Clone, Debug, PartialEq)]
pub enum Action {
    /// Read-only query against the views db / archive / config. No mutation,
    /// no network, no shell.
    Read,
    /// Write to a file inside `~/.neoth/`. Mutates daemon state.
    WriteNeothHome,
    /// Write to a file outside `~/.neoth/`. Touches operator's filesystem.
    WriteOutsideHome,
    /// Spawn a shell process inside `~/.neoth/scripts/`.
    ExecScripts,
    /// Spawn a shell process anywhere else on the filesystem.
    ExecArbitrary,
    /// Outbound provider call with an estimated cost in EUR. The threshold
    /// at which this becomes "confirm" or "deny" is autonomy-level-dependent.
    PaidProviderCall { eur_estimate: f32 },
    /// Send a message through a channel adapter (Telegram / Keet / ...).
    ChannelSend,
    /// Hit explicitly listed in `policy.yaml::dangerous_targets`.
    /// Always confirms at `full`, always denies at `standard` and below.
    DangerousTarget(String),
    /// Invocation of an external MCP server tool. CDX-03 security gate.
    /// Even an allowlisted tool routes through the autonomy gate so
    /// the operator can require Confirm before any external-tool
    /// effect lands. Payload includes the server id so per-server
    /// policy refinement is possible.
    McpToolInvocation { server_id: String, tool: String },
    /// Pick #6 Phase 4 (2026-05-21): apply a worker-produced
    /// patch into a task-scoped git worktree under
    /// `<repo_parent>/.neoth-task-<id>/`. Chorus chat
    /// `019E49EAC4EACB805644D020B8F74A03` Q1a verdict: require
    /// explicit operator confirm at EVERY autonomy level except
    /// Strict (which denies outright — Strict means agent must
    /// never mutate operator checkouts).
    ///
    /// `repo_root` lets a future per-repo policy override the
    /// default (e.g. operator marks `~/code/sandbox/` as
    /// auto-allow + `~/code/prod/` as always-confirm).
    PatchApplyToRepo {
        repo_root: std::path::PathBuf,
        task_id: u64,
    },
    /// Cluster auto-discovery (SPEC `cluster_auto_discovery_2026-05-22`)
    /// per-peer pairing decision. A peer's `pub_key` has authenticated
    /// via the cluster_key HMAC; the autonomy gate decides whether to
    /// auto-add OR require operator confirm OR deny outright. Matches
    /// the `PatchApplyToRepo` precedent: Strict denies (cluster makes
    /// no autonomous topology changes), Standard/Elevated confirm
    /// (operator confirms each new peer once), Full allows (operator
    /// opted into autonomous behaviour).
    ClusterPeerPairing {
        /// Lowercase-hex 32-byte ed25519 pub key of the candidate peer.
        pub_key_hex: String,
        /// Transport that surfaced the peer (`"mdns"`, `"tailscale"`,
        /// `"hysteria_relay"`, `"manual"`).
        discovered_via: String,
    },
    /// MV-01b Option-A prereq (senior-dev panel 2026-05-29): replace the
    /// running `neoth` daemon's OWN binary with a freshly-downloaded
    /// release. The highest-blast-radius action NEOTH can take — a
    /// compromised replacement is unrestricted RCE as the operator's
    /// user (WAL, secrets, DPAPI creds, all provider keys). Therefore it
    /// requires explicit confirm at EVERY level except Strict (which
    /// denies outright), mirroring + exceeding the `PatchApplyToRepo`
    /// precedent — even `Full` must confirm a self-replace. The
    /// operator-initiated `neoth update --self --apply` path is the human
    /// in the loop; the unattended daemon path must surface this gate
    /// before any swap.
    SelfBinaryReplace {
        /// Currently-running version.
        from: String,
        /// Version being installed.
        to: String,
        /// GitHub `owner/repo` slug the release came from.
        repo: String,
    },
    /// G-01 (Session 28d, 4-lens gremium): the daemon, ON ITS OWN
    /// INITIATIVE (no inbound prompt), sends an unsolicited message OUT
    /// to a messaging channel. Distinct from [`Action::ChannelSend`]
    /// (which is the REPLY path — operator just messaged, daemon answers,
    /// implicitly allowed at Standard). Daemon-initiated outbound has a
    /// fundamentally higher blast radius, so it gets a STRICTER gate than
    /// the reply path: Strict denies outright, Standard requires confirm
    /// (and the daemon has no TTY, so Standard effectively suppresses —
    /// matching the MV-01b Option-A "auto-actions only at Elevated/Full"
    /// policy), Elevated/Full allow. The `proactive.enabled` master switch
    /// (default OFF) is checked BEFORE this gate; this is the second layer.
    ProactiveChannelSend {
        /// Channel family the message targets ("telegram", "keet", ...).
        channel: String,
    },
}

/// Five autonomy levels per R-23 spec. Picked once at onboarding; stored on
/// `FreedomConfig.autonomy`. Phase 28b wires the wizard step + serde.
///
/// `Custom` is intentionally unmodelled here: when selected, the resolver
/// consults a per-category override map on `FreedomConfig`. That map
/// doesn't exist yet — the variant is reserved so future code can match
/// exhaustively without churn.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutonomyLevel {
    Strict,
    #[default]
    Standard,
    Elevated,
    Full,
    Custom,
}

impl AutonomyLevel {
    /// Stable lower-snake-case string used by CLI flags + WAL audit events.
    pub fn as_str(self) -> &'static str {
        match self {
            AutonomyLevel::Strict => "strict",
            AutonomyLevel::Standard => "standard",
            AutonomyLevel::Elevated => "elevated",
            AutonomyLevel::Full => "full",
            AutonomyLevel::Custom => "custom",
        }
    }

    /// Parse from a CLI flag value.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "strict" => Some(Self::Strict),
            "standard" => Some(Self::Standard),
            "elevated" => Some(Self::Elevated),
            "full" => Some(Self::Full),
            "custom" => Some(Self::Custom),
            _ => None,
        }
    }
}

/// Per-action permission resolution. Tools receive this from `evaluate`
/// before they dispatch; `Confirm` triggers a TTY / channel / fail-closed
/// confirmation handshake (Phase 28b AU-4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Confirm(String),
    Deny(String),
}

impl Decision {
    /// Short tag used in logs / WAL audit events.
    pub fn tag(&self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Confirm(_) => "confirm",
            Decision::Deny(_) => "deny",
        }
    }
}

impl Decision {
    pub fn is_allow(&self) -> bool {
        matches!(self, Decision::Allow)
    }
    pub fn is_deny(&self) -> bool {
        matches!(self, Decision::Deny(_))
    }
}

/// SL-01a-b — map a concrete [`Action`] to the [`lease::LeaseScope`] a
/// capability lease would need to cover it, or `None` when the action is
/// **unleasable**: no lease may ever pre-authorise it and the autonomy
/// gate always runs its normal `Deny`/`Confirm` path.
///
/// This is the seam between the fine-grained `Action` and the deliberately
/// coarse `LeaseScope`. The match is exhaustive **on purpose** — no `_`
/// wildcard — so adding a new `Action` variant forces a conscious
/// leasability decision at compile time instead of silently defaulting to
/// "leasable" (fail-open) or "unleasable" (silent feature gap).
///
/// Unleasable by hard rule (always `None`):
/// - [`Action::DangerousTarget`] — the absolute floor; operator confirms live.
/// - [`Action::SelfBinaryReplace`] — highest blast radius (RCE surface),
///   confirmed at every level including `Full`.
/// - [`Action::PatchApplyToRepo`] — Chorus Q1a explicit-confirm-at-every-level.
/// - [`Action::ProactiveChannelSend`] — daemon-INITIATED outbound. Deliberately
///   NOT mapped to [`lease::LeaseScope::ChannelSend`]: that scope is the REPLY
///   path, and conflating them would let a `channel_send` lease silently
///   unlock unsolicited daemon messages (blast-radius escalation). Proactive
///   stays gated by autonomy level + the `proactive.enabled` master switch;
///   it is a first-party decision, not a cross-entity delegation, so a lease
///   (which authenticates a *subject*) is the wrong instrument for it.
///
/// Unleasable for now (no `LeaseScope` variant models them yet — `None` until
/// a deliberate scope is added with its own CLI controls):
/// - [`Action::WriteOutsideHome`], [`Action::ExecScripts`],
///   [`Action::ExecArbitrary`], [`Action::PaidProviderCall`],
///   [`Action::ClusterPeerPairing`].
pub fn lease_scope_for(action: &Action) -> Option<lease::LeaseScope> {
    use lease::LeaseScope;
    match action {
        // Coverable — a lease maps to the matching coarse scope.
        Action::Read => Some(LeaseScope::Read),
        Action::WriteNeothHome => Some(LeaseScope::WriteNeothHome),
        Action::ChannelSend => Some(LeaseScope::ChannelSend),
        Action::McpToolInvocation { server_id, tool } => {
            // Qualified `server_id:tool` id — matches the CLI grant form
            // `neoth lease grant <plugin> mcp_tool:<server_id>:<tool>`.
            Some(LeaseScope::McpTool(format!("{server_id}:{tool}")))
        }
        // Unleasable by hard rule — see fn doc.
        Action::DangerousTarget(_)
        | Action::SelfBinaryReplace { .. }
        | Action::PatchApplyToRepo { .. }
        | Action::ProactiveChannelSend { .. } => None,
        // Unleasable for now — no scope variant models these yet.
        Action::WriteOutsideHome
        | Action::ExecScripts
        | Action::ExecArbitrary
        | Action::PaidProviderCall { .. }
        | Action::ClusterPeerPairing { .. } => None,
    }
}

/// Decide whether `action` may proceed under `level`. Conservative default
/// while R-23 wizard is unimplemented — see module docs.
///
/// The `Custom` level currently delegates to `Standard`. Phase 28b extends
/// the signature to accept a per-category override map.
pub fn evaluate(action: &Action, level: AutonomyLevel) -> Decision {
    match level {
        AutonomyLevel::Strict => evaluate_strict(action),
        AutonomyLevel::Standard | AutonomyLevel::Custom => evaluate_standard(action),
        AutonomyLevel::Elevated => evaluate_elevated(action),
        AutonomyLevel::Full => evaluate_full(action),
    }
}

fn evaluate_strict(action: &Action) -> Decision {
    match action {
        Action::Read => Decision::Allow,
        Action::WriteNeothHome
        | Action::WriteOutsideHome
        | Action::ExecScripts
        | Action::ExecArbitrary
        | Action::ChannelSend => Decision::Confirm(format!("strict: confirm {:?}", action)),
        Action::PaidProviderCall { .. } => {
            Decision::Confirm("strict: every paid provider call requires confirm".into())
        }
        Action::McpToolInvocation { server_id, tool } => Decision::Confirm(format!(
            "strict: MCP tool `{server_id}::{tool}` requires confirm"
        )),
        Action::DangerousTarget(t) => Decision::Deny(format!("strict: dangerous target '{t}'")),
        Action::PatchApplyToRepo { task_id, .. } => Decision::Deny(format!(
            "strict: agent MUST NOT mutate operator checkouts — task {task_id} apply denied"
        )),
        Action::ClusterPeerPairing { pub_key_hex, .. } => Decision::Deny(format!(
            "strict: cluster makes no autonomous topology changes — peer {} denied",
            &pub_key_hex[..16.min(pub_key_hex.len())]
        )),
        Action::SelfBinaryReplace { from, to, .. } => Decision::Deny(format!(
            "strict: daemon self-replace ({from} -> {to}) denied — agent never replaces its own binary"
        )),
        Action::ProactiveChannelSend { channel } => Decision::Deny(format!(
            "strict: daemon never sends unsolicited messages — proactive send to '{channel}' denied"
        )),
    }
}

fn evaluate_standard(action: &Action) -> Decision {
    match action {
        Action::Read | Action::ChannelSend => Decision::Allow,
        Action::WriteNeothHome => Decision::Allow,
        Action::WriteOutsideHome => {
            Decision::Confirm("standard: write outside ~/.neoth/ requires confirm".into())
        }
        Action::ExecScripts | Action::ExecArbitrary => {
            Decision::Confirm("standard: shell exec requires confirm".into())
        }
        Action::PaidProviderCall { eur_estimate } => {
            check_paid_call(*eur_estimate, 0.50, "standard")
        }
        Action::McpToolInvocation { server_id, tool } => Decision::Confirm(format!(
            "standard: MCP tool `{server_id}::{tool}` requires confirm — external server effects"
        )),
        Action::DangerousTarget(t) => Decision::Deny(format!("standard: dangerous target '{t}'")),
        Action::PatchApplyToRepo { task_id, repo_root } => Decision::Confirm(format!(
            "standard: task {task_id} patch apply to {} requires confirm",
            repo_root.display()
        )),
        Action::ClusterPeerPairing {
            pub_key_hex,
            discovered_via,
        } => Decision::Confirm(format!(
            "standard: peer {} (via {discovered_via}) requires confirm before pairing",
            &pub_key_hex[..16.min(pub_key_hex.len())]
        )),
        Action::SelfBinaryReplace { from, to, repo } => Decision::Confirm(format!(
            "standard: daemon self-replace {from} -> {to} from {repo} requires confirm"
        )),
        Action::ProactiveChannelSend { channel } => Decision::Confirm(format!(
            "standard: unsolicited proactive send to '{channel}' requires confirm \
             (no TTY in daemon ⇒ effectively suppressed until Elevated)"
        )),
    }
}

fn evaluate_elevated(action: &Action) -> Decision {
    match action {
        Action::Read
        | Action::ChannelSend
        | Action::WriteNeothHome
        | Action::WriteOutsideHome
        | Action::ExecScripts => Decision::Allow,
        Action::ExecArbitrary => Decision::Confirm(
            "elevated: shell exec outside ~/.neoth/scripts/ requires confirm".into(),
        ),
        Action::PaidProviderCall { eur_estimate } => {
            check_paid_call(*eur_estimate, 5.0, "elevated")
        }
        Action::McpToolInvocation { .. } => Decision::Allow,
        Action::DangerousTarget(t) => {
            Decision::Confirm(format!("elevated: dangerous target '{t}' requires confirm"))
        }
        // Per Chorus chat 019E49EAC4EACB805644D020B8F74A03 Q1a:
        // patch apply at Elevated MUST confirm — the boundary
        // where "agent may materially mutate a checkout" is too
        // broad to treat as implicit even with otherwise wide
        // latitude.
        Action::PatchApplyToRepo { task_id, repo_root } => Decision::Confirm(format!(
            "elevated: task {task_id} patch apply to {} requires confirm (Chorus Q1a)",
            repo_root.display()
        )),
        // Same precedent as patch apply at Elevated: topology
        // changes (new cluster peer = read+write access to
        // memory + WAL + usage budget) are material enough to
        // require explicit confirm even at Elevated latitude.
        Action::ClusterPeerPairing {
            pub_key_hex,
            discovered_via,
        } => Decision::Confirm(format!(
            "elevated: peer {} (via {discovered_via}) requires confirm — topology change",
            &pub_key_hex[..16.min(pub_key_hex.len())]
        )),
        // Self-replace is the highest-blast-radius action (RCE surface).
        // Even at Elevated it requires explicit confirm — same precedent
        // as patch-apply + cluster-pairing, but stricter intent.
        Action::SelfBinaryReplace { from, to, repo } => Decision::Confirm(format!(
            "elevated: daemon self-replace {from} -> {to} from {repo} requires confirm"
        )),
        // Elevated/Full is where the operator opted into autonomous
        // behaviour — proactive outbound is allowed (the `proactive.enabled`
        // master switch is the operator's explicit opt-in upstream).
        Action::ProactiveChannelSend { .. } => Decision::Allow,
    }
}

/// Pick #32 (Session 14, type-design audit-fix) — NaN-safe paid-call
/// guard. `f32::NAN > x` is always `false`, so a previous `if
/// *eur_estimate > threshold` branch let non-finite estimates fall
/// through to `Decision::Allow`. This helper centralises the
/// validation:
///
///   - non-finite (NaN / ±Inf) → `Confirm` (cost predictor broken)
///   - negative → `Confirm` (cost predictor broken)
///   - finite + above threshold → `Confirm` (operator-set cap)
///   - finite + below threshold → `Allow`
///
/// The "broken-estimate" Confirm path is louder than silent Allow so
/// the operator sees the cost-predictor regression instead of being
/// billed silently.
fn check_paid_call(eur_estimate: f32, threshold: f32, level_name: &str) -> Decision {
    if !eur_estimate.is_finite() {
        return Decision::Confirm(format!(
            "{level_name}: paid provider with non-finite EUR estimate ({eur_estimate}) — \
             cost predictor likely broken; refusing to silently allow"
        ));
    }
    if eur_estimate < 0.0 {
        return Decision::Confirm(format!(
            "{level_name}: paid provider with negative EUR estimate ({eur_estimate}) — \
             cost predictor likely broken; refusing to silently allow"
        ));
    }
    if eur_estimate > threshold {
        return Decision::Confirm(format!(
            "{level_name}: paid provider €{eur_estimate:.2} > €{threshold:.2} limit"
        ));
    }
    Decision::Allow
}

fn evaluate_full(action: &Action) -> Decision {
    match action {
        Action::DangerousTarget(t) => {
            Decision::Confirm(format!("full: dangerous target '{t}' requires confirm"))
        }
        // Pick #6 Phase 4 / Chorus Q1a: even at Full, agent must
        // not materially mutate operator checkouts without an
        // explicit per-task confirm. Conservative for the v0.2
        // ship target; raise to Allow once the failure-taxonomy
        // + audit chain prove the loop in v0.3.
        Action::PatchApplyToRepo { task_id, repo_root } => Decision::Confirm(format!(
            "full: task {task_id} patch apply to {} requires confirm (Chorus Q1a v0.2-conservative)",
            repo_root.display()
        )),
        // Cluster Phase-1 architect verdict: Full operator opted
        // into autonomous behaviour → auto-pair on matching
        // cluster_key. The HMAC check upstream is the gate.
        Action::ClusterPeerPairing { .. } => Decision::Allow,
        // Senior-dev panel 2026-05-29: daemon self-replace is the single
        // highest-blast-radius action NEOTH can take (a compromised
        // replacement = unrestricted RCE as the operator's user). It is
        // NEVER auto-allowed — Confirm even at Full, exceeding the
        // PatchApplyToRepo precedent. The unattended updater must surface
        // this gate before any swap; an operator who wants hands-off
        // self-update confirms once with `--remember`.
        Action::SelfBinaryReplace { from, to, repo } => Decision::Confirm(format!(
            "full: daemon self-replace {from} -> {to} from {repo} requires confirm — \
             highest blast radius (RCE surface), never auto-allowed"
        )),
        // Full = trust the operator's other gates (policy.yaml allowlist,
        // hardware-2FA at level-set time). Everything else allowed.
        _ => Decision::Allow,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proactive_channel_send_strict_denies() {
        let action = Action::ProactiveChannelSend {
            channel: "telegram".into(),
        };
        assert!(matches!(
            evaluate(&action, AutonomyLevel::Strict),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn proactive_channel_send_standard_confirms() {
        // Standard ⇒ Confirm; the daemon has no TTY so this effectively
        // suppresses proactive sends until the operator raises to Elevated.
        let action = Action::ProactiveChannelSend {
            channel: "telegram".into(),
        };
        assert!(matches!(
            evaluate(&action, AutonomyLevel::Standard),
            Decision::Confirm(_)
        ));
        // Custom routes through the standard evaluator too.
        assert!(matches!(
            evaluate(&action, AutonomyLevel::Custom),
            Decision::Confirm(_)
        ));
    }

    #[test]
    fn proactive_channel_send_elevated_and_full_allow() {
        let action = Action::ProactiveChannelSend {
            channel: "keet".into(),
        };
        assert!(evaluate(&action, AutonomyLevel::Elevated).is_allow());
        assert!(evaluate(&action, AutonomyLevel::Full).is_allow());
    }

    #[test]
    fn proactive_channel_send_is_stricter_than_reply_channel_send() {
        // The whole point of the distinct variant: at Standard the REPLY
        // path (ChannelSend) is allowed, but the daemon-INITIATED path
        // (ProactiveChannelSend) must NOT be silently allowed.
        assert!(evaluate(&Action::ChannelSend, AutonomyLevel::Standard).is_allow());
        let proactive = Action::ProactiveChannelSend {
            channel: "telegram".into(),
        };
        assert!(!evaluate(&proactive, AutonomyLevel::Standard).is_allow());
    }

    #[test]
    fn cluster_peer_pairing_strict_denies() {
        let action = Action::ClusterPeerPairing {
            pub_key_hex: "abcdef0123456789".repeat(4),
            discovered_via: "mdns".into(),
        };
        assert!(matches!(
            evaluate(&action, AutonomyLevel::Strict),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn cluster_peer_pairing_standard_and_elevated_confirm() {
        let action = Action::ClusterPeerPairing {
            pub_key_hex: "abcdef0123456789".repeat(4),
            discovered_via: "tailscale".into(),
        };
        assert!(matches!(
            evaluate(&action, AutonomyLevel::Standard),
            Decision::Confirm(_)
        ));
        assert!(matches!(
            evaluate(&action, AutonomyLevel::Elevated),
            Decision::Confirm(_)
        ));
    }

    #[test]
    fn cluster_peer_pairing_full_allows() {
        let action = Action::ClusterPeerPairing {
            pub_key_hex: "ab".repeat(32),
            discovered_via: "manual".into(),
        };
        assert!(evaluate(&action, AutonomyLevel::Full).is_allow());
    }

    #[test]
    fn cluster_peer_pairing_detail_carries_pub_key_prefix_and_via() {
        let action = Action::ClusterPeerPairing {
            pub_key_hex: "deadbeef".to_string() + &"00".repeat(28),
            discovered_via: "hysteria_relay".into(),
        };
        let dec = evaluate(&action, AutonomyLevel::Standard);
        let msg = match dec {
            Decision::Confirm(s) => s,
            other => panic!("expected Confirm, got {other:?}"),
        };
        // Prefix of the pub_key + the via tag should both surface
        // so a confirm prompt renders meaningful operator context.
        assert!(msg.contains("deadbeef"));
        assert!(msg.contains("hysteria_relay"));
    }

    #[test]
    fn strict_confirms_writes_and_exec() {
        assert!(matches!(
            evaluate(&Action::WriteNeothHome, AutonomyLevel::Strict),
            Decision::Confirm(_)
        ));
        assert!(matches!(
            evaluate(&Action::ExecScripts, AutonomyLevel::Strict),
            Decision::Confirm(_)
        ));
    }

    #[test]
    fn standard_allows_neoth_home_writes_but_confirms_outside() {
        assert!(evaluate(&Action::WriteNeothHome, AutonomyLevel::Standard).is_allow());
        assert!(matches!(
            evaluate(&Action::WriteOutsideHome, AutonomyLevel::Standard),
            Decision::Confirm(_)
        ));
    }

    #[test]
    fn standard_paid_provider_threshold_is_fifty_cents() {
        let cheap = evaluate(
            &Action::PaidProviderCall { eur_estimate: 0.10 },
            AutonomyLevel::Standard,
        );
        assert!(cheap.is_allow());
        let pricey = evaluate(
            &Action::PaidProviderCall { eur_estimate: 0.99 },
            AutonomyLevel::Standard,
        );
        assert!(matches!(pricey, Decision::Confirm(_)));
    }

    #[test]
    fn elevated_paid_provider_threshold_is_five_eur() {
        let mid = evaluate(
            &Action::PaidProviderCall { eur_estimate: 2.50 },
            AutonomyLevel::Elevated,
        );
        assert!(mid.is_allow());
        let high = evaluate(
            &Action::PaidProviderCall { eur_estimate: 9.99 },
            AutonomyLevel::Elevated,
        );
        assert!(matches!(high, Decision::Confirm(_)));
    }

    // ── Pick #32 (Session 14, type-design audit-fix) — NaN-safe ──────
    //
    // `f32::NAN > 0.50` is false in Rust. Pre-fix, the autonomy gate
    // silently fell through to Decision::Allow on a NaN cost estimate
    // — bypassing the cost ceiling. These regression tests pin the
    // fix: every non-finite or negative estimate Confirms (which under
    // FailClosed becomes Deny) so a broken cost predictor cannot
    // silently authorise spend.

    #[test]
    fn standard_paid_call_with_nan_estimate_confirms_not_allows() {
        let action = Action::PaidProviderCall {
            eur_estimate: f32::NAN,
        };
        let d = evaluate(&action, AutonomyLevel::Standard);
        match d {
            Decision::Confirm(reason) => {
                assert!(
                    reason.contains("non-finite"),
                    "NaN must surface as non-finite Confirm; got: {reason}"
                );
            }
            other => panic!("NaN must Confirm, never Allow; got {other:?}"),
        }
    }

    #[test]
    fn standard_paid_call_with_infinity_confirms_not_allows() {
        for v in [f32::INFINITY, f32::NEG_INFINITY] {
            let d = evaluate(
                &Action::PaidProviderCall { eur_estimate: v },
                AutonomyLevel::Standard,
            );
            assert!(
                matches!(d, Decision::Confirm(_)),
                "{v} estimate must Confirm; got {d:?}"
            );
        }
    }

    #[test]
    fn standard_paid_call_with_negative_estimate_confirms() {
        let d = evaluate(
            &Action::PaidProviderCall {
                eur_estimate: -0.01,
            },
            AutonomyLevel::Standard,
        );
        match d {
            Decision::Confirm(reason) => {
                assert!(
                    reason.contains("negative"),
                    "negative estimate must surface as Confirm; got: {reason}"
                );
            }
            other => panic!("negative must Confirm; got {other:?}"),
        }
    }

    #[test]
    fn elevated_paid_call_with_nan_estimate_confirms_not_allows() {
        let d = evaluate(
            &Action::PaidProviderCall {
                eur_estimate: f32::NAN,
            },
            AutonomyLevel::Elevated,
        );
        assert!(
            matches!(d, Decision::Confirm(_)),
            "NaN on Elevated must Confirm; got {d:?}"
        );
    }

    #[test]
    fn full_paid_call_with_nan_is_allowed_documented_choice() {
        // Pick #34 (Session 14, test-gap audit-fix): pin the Full
        // behaviour as a deliberate design choice — operators on
        // `autonomy=full` opted out of cost gating, including the
        // "is the predictor sane" check. A NaN estimate on Full
        // returns Allow. If a future maintainer decides Full SHOULD
        // also Confirm on non-finite, this test fails + forces a
        // conscious design conversation.
        let d = evaluate(
            &Action::PaidProviderCall {
                eur_estimate: f32::NAN,
            },
            AutonomyLevel::Full,
        );
        assert!(
            d.is_allow(),
            "Full opted out of cost gating; NaN must still Allow as documented; got {d:?}"
        );
    }

    #[test]
    fn dangerous_target_is_deny_until_elevated_then_confirm_at_full() {
        let target = Action::DangerousTarget("100.68.210.50".into());
        assert!(evaluate(&target, AutonomyLevel::Strict).is_deny());
        assert!(evaluate(&target, AutonomyLevel::Standard).is_deny());
        assert!(matches!(
            evaluate(&target, AutonomyLevel::Elevated),
            Decision::Confirm(_)
        ));
        assert!(matches!(
            evaluate(&target, AutonomyLevel::Full),
            Decision::Confirm(_)
        ));
    }

    #[test]
    fn full_allows_arbitrary_exec_and_outside_writes() {
        assert!(evaluate(&Action::ExecArbitrary, AutonomyLevel::Full).is_allow());
        assert!(evaluate(&Action::WriteOutsideHome, AutonomyLevel::Full).is_allow());
    }

    // ── SL-01a-b lease_scope_for mapping (panel-pinned security floor) ──

    #[test]
    fn lease_scope_maps_coverable_actions() {
        use lease::LeaseScope;
        assert_eq!(lease_scope_for(&Action::Read), Some(LeaseScope::Read));
        assert_eq!(
            lease_scope_for(&Action::WriteNeothHome),
            Some(LeaseScope::WriteNeothHome)
        );
        assert_eq!(
            lease_scope_for(&Action::ChannelSend),
            Some(LeaseScope::ChannelSend)
        );
        assert_eq!(
            lease_scope_for(&Action::McpToolInvocation {
                server_id: "fs".into(),
                tool: "read_file".into()
            }),
            Some(LeaseScope::McpTool("fs:read_file".into()))
        );
    }

    /// Round-trip test: the scope produced by `lease_scope_for()` for
    /// `McpToolInvocation` must equal the scope produced by `parse()` with
    /// the CLI grant token `mcp_tool:<server_id>:<tool>` (single colon).
    /// If `lease_scope_for` formats with `::` and `parse` stores `:`, this
    /// test fails — which is the exact separator-mismatch bug.
    #[test]
    fn mcp_tool_lease_scope_round_trip() {
        let parsed = lease::LeaseScope::parse("mcp_tool:fs:read_file").unwrap();
        let from_action = lease_scope_for(&Action::McpToolInvocation {
            server_id: "fs".into(),
            tool: "read_file".into(),
        })
        .unwrap();
        assert_eq!(
            parsed, from_action,
            "CLI grant token `mcp_tool:fs:read_file` must produce the same \
             LeaseScope as lease_scope_for(McpToolInvocation{{\"fs\",\"read_file\"}}). \
             If this fails, the separator in lease_scope_for() mismatches parse()."
        );
    }

    #[test]
    fn lease_scope_is_none_for_hard_floor_actions() {
        // The whole point of SL-01a-b's safety: no lease may EVER
        // pre-authorise these. If a refactor maps any of them to Some, this
        // test fails and forces a security conversation.
        assert_eq!(
            lease_scope_for(&Action::DangerousTarget("cube".into())),
            None
        );
        assert_eq!(
            lease_scope_for(&Action::SelfBinaryReplace {
                from: "0.2".into(),
                to: "0.3".into(),
                repo: "x/y".into()
            }),
            None
        );
        assert_eq!(
            lease_scope_for(&Action::PatchApplyToRepo {
                repo_root: std::path::PathBuf::from("/r"),
                task_id: 1
            }),
            None
        );
    }

    #[test]
    fn proactive_channel_send_is_not_lease_coverable() {
        // Lens 3+4 (SL-01a-b panel): ProactiveChannelSend must NOT map to
        // LeaseScope::ChannelSend — a reply-path lease must never silently
        // unlock daemon-initiated unsolicited sends.
        assert_eq!(
            lease_scope_for(&Action::ProactiveChannelSend {
                channel: "telegram".into()
            }),
            None,
            "proactive (daemon-initiated) is not lease-delegable; it is a \
             first-party decision gated by autonomy + proactive.enabled"
        );
        // The reply path, by contrast, IS coverable.
        assert!(lease_scope_for(&Action::ChannelSend).is_some());
    }

    #[test]
    fn custom_delegates_to_standard_for_now() {
        // Until Phase 28b adds the per-category override map, Custom matches
        // Standard exactly. Locks the behaviour so a future regression is
        // visible.
        for action in [
            Action::Read,
            Action::WriteNeothHome,
            Action::WriteOutsideHome,
            Action::ExecScripts,
            Action::ChannelSend,
        ] {
            assert_eq!(
                evaluate(&action, AutonomyLevel::Custom),
                evaluate(&action, AutonomyLevel::Standard),
                "Custom must match Standard until override map lands; action {:?}",
                action,
            );
        }
    }

    // ── Pick #6 Phase 4 PatchApplyToRepo gate (Chorus Q1a) ──────────

    fn patch_apply_action(task_id: u64) -> Action {
        Action::PatchApplyToRepo {
            repo_root: std::path::PathBuf::from("/home/alice/myrepo"),
            task_id,
        }
    }

    #[test]
    fn patch_apply_strict_denies() {
        let d = evaluate(&patch_apply_action(1), AutonomyLevel::Strict);
        assert!(d.is_deny(), "strict must DENY agent mutating checkouts");
        if let Decision::Deny(msg) = d {
            assert!(msg.contains("strict"));
            assert!(msg.contains("task 1"));
        }
    }

    #[test]
    fn patch_apply_standard_confirms() {
        let d = evaluate(&patch_apply_action(2), AutonomyLevel::Standard);
        assert!(matches!(d, Decision::Confirm(_)), "standard must confirm");
    }

    #[test]
    fn patch_apply_elevated_confirms_per_chorus_q1a() {
        // Boundary case: Elevated normally allows WriteOutsideHome
        // implicitly, but Chorus Q1a flagged this specific action
        // as "too broad to treat as implicit". Pin via test so a
        // future refactor that flips it to Allow surfaces here.
        let d = evaluate(&patch_apply_action(3), AutonomyLevel::Elevated);
        assert!(
            matches!(d, Decision::Confirm(_)),
            "elevated MUST confirm patch apply per Chorus Q1a"
        );
        if let Decision::Confirm(msg) = d {
            assert!(msg.contains("Chorus Q1a"));
        }
    }

    #[test]
    fn patch_apply_full_confirms_v02_conservative() {
        // Full normally allows everything bar DangerousTarget;
        // v0.2 ship conservatively confirms patch apply per
        // Chorus verdict. Lift this to Allow in v0.3 once the
        // failure taxonomy + WAL audit prove the loop.
        let d = evaluate(&patch_apply_action(4), AutonomyLevel::Full);
        assert!(
            matches!(d, Decision::Confirm(_)),
            "full MUST confirm patch apply for v0.2 (Chorus Q1a conservative)"
        );
    }

    #[test]
    fn patch_apply_custom_inherits_standard() {
        // Custom delegates to Standard until per-category
        // overrides ship. Pin so a future refactor that adds an
        // override path knows to flip this assertion.
        let d = evaluate(&patch_apply_action(5), AutonomyLevel::Custom);
        assert!(matches!(d, Decision::Confirm(_)));
    }

    #[test]
    fn patch_apply_confirm_message_names_repo_path() {
        // Operator-facing prompt must surface the repo path so
        // a multi-repo workflow can tell which checkout is
        // about to mutate.
        let d = evaluate(&patch_apply_action(6), AutonomyLevel::Standard);
        if let Decision::Confirm(msg) = d {
            assert!(msg.contains("/home/alice/myrepo"));
        } else {
            panic!("expected Confirm, got {d:?}");
        }
    }

    // ── MV-01b SelfBinaryReplace gate (senior-dev panel 2026-05-29) ──

    fn self_replace_action() -> Action {
        Action::SelfBinaryReplace {
            from: "0.2.1".into(),
            to: "0.3.0".into(),
            repo: "The-Geek-Freaks/NEOTH".into(),
        }
    }

    #[test]
    fn self_replace_strict_denies() {
        let d = evaluate(&self_replace_action(), AutonomyLevel::Strict);
        assert!(d.is_deny(), "strict must DENY daemon self-replace");
    }

    #[test]
    fn self_replace_confirms_at_standard_elevated_and_full() {
        // The whole point: self-replace is NEVER auto-allowed — Confirm
        // at every non-Strict level, INCLUDING Full (exceeds the
        // PatchApplyToRepo precedent). If a refactor ever flips Full to
        // Allow, this test fails + forces a security conversation.
        for level in [
            AutonomyLevel::Standard,
            AutonomyLevel::Elevated,
            AutonomyLevel::Full,
        ] {
            let d = evaluate(&self_replace_action(), level);
            assert!(
                matches!(d, Decision::Confirm(_)),
                "self-replace at {level:?} MUST Confirm, never Allow; got {d:?}"
            );
        }
    }

    #[test]
    fn self_replace_confirm_message_names_versions_and_repo() {
        let d = evaluate(&self_replace_action(), AutonomyLevel::Full);
        if let Decision::Confirm(msg) = d {
            assert!(msg.contains("0.2.1"), "from-version must surface: {msg}");
            assert!(msg.contains("0.3.0"), "to-version must surface: {msg}");
            assert!(
                msg.contains("The-Geek-Freaks/NEOTH"),
                "repo must surface: {msg}"
            );
        } else {
            panic!("expected Confirm, got {d:?}");
        }
    }

    #[test]
    fn self_replace_custom_inherits_standard_confirm() {
        let d = evaluate(&self_replace_action(), AutonomyLevel::Custom);
        assert!(matches!(d, Decision::Confirm(_)));
    }

    #[test]
    fn sdk_types_are_reachable_through_re_exports() {
        // Compile-time check: the re-exports work and `mint()` is reachable
        // (because neothd enables the `_host` Cargo feature).
        let _ro: PermissionToken<ReadOnly> = PermissionToken::mint();
        let _exec: PermissionToken<Execute> = PermissionToken::mint();
        let _none: PermissionToken<NoPermission> = PermissionToken::mint();
        let _grant: FreedomGrant<Execute> = FreedomGrant::issue();
    }
}
