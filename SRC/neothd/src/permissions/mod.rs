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
pub mod confirm_bus;
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
    /// PC-01: read a file on the operator's OS through the gated OS-tool
    /// surface. The `path` is the POST-canonicalization resolved path — the
    /// allowlist gate (`os_tools`) has already confirmed it falls under a
    /// `freedom.yaml::tools.os.allowed_paths` prefix (default empty =
    /// deny-all) BEFORE this autonomy gate runs. So the autonomy decision
    /// here is only the second layer: Strict confirms (show the operator
    /// every external read), Standard/Elevated/Full allow (the allowlist is
    /// the operator's explicit opt-in). NO registry / system-paths /
    /// process-kill — those are not representable as an `OsFileRead`.
    OsFileRead {
        /// Canonical, allowlist-validated path being read.
        path: std::path::PathBuf,
    },
    /// PC-01 (write slice): write a file on the operator's OS through the gated
    /// OS-tool surface. The `path` is the POST-resolution target — the
    /// write-allowlist gate (`os_tools`, canonical PARENT under
    /// `freedom.yaml::tools.os.allowed_write_paths`, default empty = deny-all)
    /// has already passed BEFORE this autonomy gate. A WRITE mutates the
    /// operator's filesystem (higher blast radius than a read), so this gate is
    /// one notch STRICTER than `OsFileRead`: Strict denies, Standard confirms
    /// (no TTY ⇒ effectively suppressed until Elevated), Elevated/Full allow —
    /// the write-allowlist is the operator's explicit opt-in.
    OsFileWrite {
        /// Canonical, write-allowlist-validated target path.
        path: std::path::PathBuf,
    },
    /// PC-01 (app-launch slice): launch an operator-allowlisted program on the
    /// OS through the gated OS-tool surface. The `program` is the
    /// POST-resolution canonical path — the exec-allowlist gate (`os_tools`,
    /// the target must canonicalize to EXACTLY one
    /// `freedom.yaml::tools.os.allowed_exec_paths` entry — an exact match, NOT
    /// a directory prefix, so allowlisting `/usr/bin/firefox` does not expose
    /// the rest of `/usr/bin`) has already passed BEFORE this autonomy gate.
    /// Launching a program is arbitrary code execution (the highest blast
    /// radius of the OS-tool surface), so this gate is STRICTER than
    /// `OsFileWrite`: Strict denies, Standard AND Elevated confirm (no TTY ⇒
    /// effectively suppressed until Full), only Full allows. The launch carries
    /// NO arguments and uses NO shell (direct `argv[0]`), so an allowlisted
    /// binary can't be turned into a different command via injected args.
    OsAppLaunch {
        /// Canonical, exec-allowlist-validated program path.
        program: std::path::PathBuf,
    },
    /// PC-01 (clipboard slice): READ the OS clipboard through the gated OS-tool
    /// surface. Unlike `OsFileRead`, the clipboard has NO path-allowlist to
    /// scope it — it is an ambient secret store, so any read can capture the
    /// most-recent password/token the operator copied. It is therefore gated
    /// STRICTER than `OsFileRead` (Standard=Allow): Strict denies, Standard AND
    /// Elevated confirm (no TTY ⇒ fail-closed), only Full allows — the same
    /// posture as `OsAppLaunch`. The `tools.os.clipboard.{enabled,read_enabled}`
    /// runtime kill-switches gate it further upstream (in `os_tools::gate`).
    OsClipboardRead,
    /// PC-01 (clipboard slice): WRITE the OS clipboard through the gated OS-tool
    /// surface. A clipboard write is a PASSIVE INJECTION vector (pastejacking):
    /// the operator may paste attacker-chosen content into a shell WITHOUT
    /// inspecting it, so a malicious write is a direct shell-command-injection
    /// analogue. It is gated STRICTER than `OsAppLaunch`: Strict AND Standard
    /// deny (a passive injection needs no per-write confirm to be dangerous),
    /// Elevated confirms (no TTY ⇒ fail-closed), only Full allows. The gate also
    /// structurally rejects newline-bearing content (the terminal auto-execute
    /// precondition) unless `tools.os.clipboard.allow_newlines_in_write`.
    OsClipboardWrite,
    /// SL-01: accept a task DELEGATED by a cluster master and run it through
    /// this node's local provider. The peer has already authenticated (Noise +
    /// cluster_key proof) and been operator-paired; this gate is the autonomy
    /// floor on top. Strict denies (no unattended delegation); Standard
    /// **confirms** so a standing `LeaseScope::ClusterTaskAccept` lease for the
    /// peer UPGRADES it to Allow (the operator's explicit, TTL-bounded
    /// delegation grant — exactly the SL-01a lease semantics) while a bare
    /// Standard node with no lease stays fail-closed (no TTY); Elevated/Full
    /// allow. Maps to `LeaseScope::ClusterTaskAccept` in `lease_scope_for`.
    ClusterTaskAccept,
    /// TD-02: write (create/complete) a task on an EXTERNAL task service
    /// (CalDAV / Todoist / Google Tasks) through the operator's OWN
    /// credentials. An outbound network MUTATION — lower blast radius than
    /// exec/file-write (it touches the operator's own task list, not the local
    /// machine), but it leaves the device + changes remote state, so it gates:
    /// Strict + Standard **confirm** (the operator OKs each external write,
    /// `--yes` or a TTY satisfies it), Elevated + Full **allow** (the operator
    /// opted into autonomous behaviour; the creds are theirs). Unleasable for
    /// now (no coarse scope models it).
    ExternalTaskWrite {
        /// Backend family — `"caldav"` / `"todoist"` / `"google"`.
        provider: String,
        /// `"add"` or `"close"`.
        action: String,
    },
    /// GOLD-ADAPT-JV-MODE-04 — NEOTH toggles one of its own skills (enable
    /// or disable) under sovereign mode. Gate table:
    ///
    /// | Level          | Decision                                                  |
    /// |----------------|-----------------------------------------------------------|
    /// | Strict         | Deny — agents never self-modify skills below Elevated     |
    /// | Standard       | Deny                                                      |
    /// | Elevated       | Confirm — operator reviews each self-toggle               |
    /// | Full (no sov)  | Confirm — sovereign_active() must be true for Allow       |
    /// | Full + sov, allowlist hit  | Allow                                         |
    /// | Full + sov, allowlist miss | Confirm                                       |
    ///
    /// Never leasable: `lease_scope_for` returns `None`. No batch
    /// self-enable scripts may bypass the per-skill operator gate.
    SelfSkillToggle {
        /// Lowercase skill id, as stored in `freedom.yaml::skills.enabled/disabled`.
        skill_id: String,
        /// `true` = enable, `false` = disable.
        enable: bool,
    },
    /// GOLD-ADAPT-JV-MODE-04 — NEOTH registers a new cron job under sovereign
    /// mode. Stricter than `SelfSkillToggle`: cron registration fires on a
    /// schedule without further confirmation, so its blast radius is higher.
    ///
    /// Gate table:
    ///
    /// | Level           | Decision                                               |
    /// |-----------------|--------------------------------------------------------|
    /// | Strict          | Deny                                                   |
    /// | Standard        | Deny                                                   |
    /// | Elevated        | Confirm                                                |
    /// | Full (any)      | Confirm — NEVER auto-Allow for cron, even at Full sov  |
    ///
    /// Never leasable. The CLI additionally requires `--confirm-cron` on
    /// every invocation as a second-layer gate (enforced in `cli::self_activate`).
    SelfCronRegister {
        /// The `id` field of the job being registered.
        job_id: String,
    },
    /// GOLD-FEAT-05 — propose a source-code edit against NEOTH's OWN source
    /// tree via `neoth self-edit --diff <file>`.
    ///
    /// Highest blast-radius source-mutation action: a compromised diff applied
    /// to the live tree is unrestricted modification of the running daemon's
    /// own code. Gate table:
    ///
    /// | Level    | Decision                                                      |
    /// |----------|---------------------------------------------------------------|
    /// | Strict   | Deny — source edits never permitted below Elevated            |
    /// | Standard | Deny                                                          |
    /// | Elevated | Confirm — operator must ack each self-edit                    |
    /// | Full     | Confirm — NEVER auto-Allow (mirrors SelfBinaryReplace policy) |
    ///
    /// **Never leasable** — no lease may pre-authorise a self-source edit;
    /// each call must pass the per-call autonomy gate.
    ///
    /// The five-layer gate stack in `coding::self_source_gate` runs BEFORE
    /// this action reaches `evaluate`; this action represents the autonomy
    /// (Layer 3) decision only. Layers 1, 2, 4, 5 are enforced by the gate.
    SelfSourceEdit {
        /// Paths the diff touches (relative to source root, stripped of `a/`/`b/`
        /// unified-diff prefixes). Non-empty; the gate validates this.
        target_paths: Vec<String>,
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

    /// Monotonic rank of the four linear levels. `Custom` is unmodelled (no
    /// override map yet) so it ranks as `Standard` — deliberately low, so a
    /// `Custom` operator never *implicitly* satisfies an Elevated/Full gate.
    fn rank(self) -> u8 {
        match self {
            Self::Strict => 0,
            Self::Standard | Self::Custom => 1,
            Self::Elevated => 2,
            Self::Full => 3,
        }
    }

    /// GOLD-ADAPT-CCS-02 — does the operator's current level satisfy a server's
    /// `autonomy_gate` (minimum required) level? Fail-closed: a `Custom`
    /// *required* gate is satisfied only by `Full`, since the override map that
    /// would resolve `Custom` does not exist yet.
    pub fn meets_gate(self, required: AutonomyLevel) -> bool {
        if matches!(required, AutonomyLevel::Custom) {
            return matches!(self, AutonomyLevel::Full);
        }
        self.rank() >= required.rank()
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
        // An OS file read is a read capability — the operator can delegate it
        // to a subject (plugin / peer) under the Read lease scope.
        Action::OsFileRead { .. } => Some(LeaseScope::Read),
        Action::WriteNeothHome => Some(LeaseScope::WriteNeothHome),
        Action::ChannelSend => Some(LeaseScope::ChannelSend),
        Action::McpToolInvocation { server_id, tool } => {
            // Qualified `server_id:tool` id — matches the CLI grant form
            // `neoth lease grant <plugin> mcp_tool:<server_id>:<tool>`.
            Some(LeaseScope::McpTool(format!("{server_id}:{tool}")))
        }
        // SL-01: the lease IS the cross-entity delegation grant here — an
        // operator grants a specific cluster peer the standing right to
        // delegate tasks for a bounded TTL. This is the consumer of the
        // long-dormant `LeaseScope::ClusterTaskAccept`.
        Action::ClusterTaskAccept => Some(LeaseScope::ClusterTaskAccept),
        // Unleasable by hard rule — see fn doc.
        Action::DangerousTarget(_)
        | Action::SelfBinaryReplace { .. }
        | Action::PatchApplyToRepo { .. }
        | Action::ProactiveChannelSend { .. } => None,
        // Unleasable for now — no scope variant models these yet. `OsFileWrite`
        // is an arbitrary-OS-write (like `WriteOutsideHome`): no coarse scope
        // models it, and it's high-blast-radius, so it stays gate-only.
        Action::WriteOutsideHome
        | Action::ExecScripts
        | Action::ExecArbitrary
        | Action::PaidProviderCall { .. }
        | Action::ClusterPeerPairing { .. }
        | Action::OsFileWrite { .. }
        // An app launch is arbitrary code execution (like `ExecArbitrary`): no
        // coarse scope models it and the blast radius is the whole machine, so
        // it stays gate-only and is never lease-unlockable.
        | Action::OsAppLaunch { .. }
        // PC-01 clipboard: an UNSCOPED ambient store (read) + a passive injection
        // sink (write) — no coarse lease scope models either, and a `Read` lease
        // must NEVER silently unlock arbitrary clipboard content for a delegated
        // plugin/peer. Gate-only, never lease-unlockable.
        | Action::OsClipboardRead
        | Action::OsClipboardWrite
        // TD-02 external task write: no coarse lease scope models it yet; the
        // operator confirms each (or runs at Elevated+) — gate-only for now.
        | Action::ExternalTaskWrite { .. }
        // JV-MODE-04 self-activation: never leasable — no batch self-enable
        // scripts may pre-authorise a skill or cron toggle; every self-toggle
        // must pass through the per-call operator gate.
        | Action::SelfSkillToggle { .. }
        | Action::SelfCronRegister { .. }
        // GOLD-FEAT-05: never leasable — each self-source edit must pass the
        // per-call autonomy gate. No lease may pre-authorise editing NEOTH's
        // own source code (blast-radius equivalent to SelfBinaryReplace).
        | Action::SelfSourceEdit { .. } => None,
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
        Action::OsFileRead { path } => Decision::Confirm(format!(
            "strict: OS file read of {} requires confirm",
            path.display()
        )),
        Action::ClusterTaskAccept => {
            Decision::Deny("strict: no unattended cluster-delegated task execution".into())
        }
        Action::OsFileWrite { path } => Decision::Deny(format!(
            "strict: OS file write of {} denied (writes mutate the operator FS)",
            path.display()
        )),
        Action::OsAppLaunch { program } => Decision::Deny(format!(
            "strict: launching {} denied (arbitrary program execution)",
            program.display()
        )),
        Action::OsClipboardRead => Decision::Deny(
            "strict: OS clipboard read denied (unscoped ambient secret store)".into(),
        ),
        Action::OsClipboardWrite => Decision::Deny(
            "strict: OS clipboard write denied (pastejacking injection vector)".into(),
        ),
        Action::ExternalTaskWrite {
            provider,
            action: act,
        } => Decision::Confirm(format!(
            "strict: external task {act} on {provider} requires confirm"
        )),
        // JV-MODE-04: agents below Elevated may never self-modify skills or
        // register crons — deny outright (no confirm path; this is a hard floor).
        Action::SelfSkillToggle { skill_id, enable } => Decision::Deny(format!(
            "strict: self-toggle skill '{skill_id}' {} denied — self-activation requires Elevated+",
            if *enable { "enable" } else { "disable" }
        )),
        Action::SelfCronRegister { job_id } => Decision::Deny(format!(
            "strict: self-register cron '{job_id}' denied — self-activation requires Elevated+"
        )),
        // GOLD-FEAT-05: strict is the floor — source edits denied outright.
        // Editing NEOTH's own code requires at minimum Elevated.
        Action::SelfSourceEdit { target_paths } => Decision::Deny(format!(
            "strict: self-source edit of {} path(s) denied — requires Elevated or Full autonomy",
            target_paths.len()
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
        // The allowlist (default deny-all) is the operator's explicit opt-in;
        // a path that reaches here already passed it, so Standard+ allows.
        Action::OsFileRead { .. } => Decision::Allow,
        // Confirm — so a standing ClusterTaskAccept lease for the peer upgrades
        // it to Allow (the SL-01a lease semantics), while a bare Standard node
        // with no lease stays fail-closed (no TTY ⇒ effectively suppressed).
        Action::ClusterTaskAccept => Decision::Confirm(
            "standard: accept cluster-delegated task requires confirm \
             (a ClusterTaskAccept lease for the peer upgrades this to allow)"
                .into(),
        ),
        // One notch stricter than OsFileRead (Standard=Allow): a WRITE mutates
        // the FS, so Standard confirms (no TTY ⇒ blocked until Elevated).
        Action::OsFileWrite { path } => Decision::Confirm(format!(
            "standard: OS file write of {} requires confirm",
            path.display()
        )),
        // Stricter than OsFileWrite (which Elevated allows): launching a
        // program is arbitrary code execution, so it confirms at Standard AND
        // Elevated (no TTY ⇒ suppressed) and only auto-allows at Full.
        Action::OsAppLaunch { program } => Decision::Confirm(format!(
            "standard: launching {} requires confirm (program execution)",
            program.display()
        )),
        // Stricter than OsFileRead (Standard=Allow): the clipboard has NO
        // path-allowlist to scope it, so a read at Standard could silently
        // capture a just-copied secret. Confirm ⇒ no TTY ⇒ suppressed until Full.
        Action::OsClipboardRead => Decision::Confirm(
            "standard: OS clipboard read requires confirm (unscoped secret-capture risk; \
             no TTY ⇒ suppressed until Full)"
                .into(),
        ),
        // Stricter than OsAppLaunch (Standard=Confirm): pastejacking is a PASSIVE
        // injection — the operator may paste without inspecting — so a clipboard
        // write is denied outright at Standard, not merely confirm-gated.
        Action::OsClipboardWrite => Decision::Deny(
            "standard: OS clipboard write denied (passive pastejacking injection \
             vector — stricter than program launch)"
                .into(),
        ),
        // The creds are the operator's own + they typed the command, but a
        // network MUTATION still confirms at Standard (a TTY prompt or `--yes`
        // satisfies it) so an accidental write to the wrong list is caught.
        Action::ExternalTaskWrite {
            provider,
            action: act,
        } => Decision::Confirm(format!(
            "standard: external task {act} on {provider} requires confirm"
        )),
        // JV-MODE-04: Standard denies self-activation (same as Strict floor).
        Action::SelfSkillToggle { skill_id, enable } => Decision::Deny(format!(
            "standard: self-toggle skill '{skill_id}' {} denied — self-activation requires Elevated+",
            if *enable { "enable" } else { "disable" }
        )),
        Action::SelfCronRegister { job_id } => Decision::Deny(format!(
            "standard: self-register cron '{job_id}' denied — self-activation requires Elevated+"
        )),
        // GOLD-FEAT-05: Standard denied — same floor as Strict for self-source
        // edits. Modifying NEOTH's own source requires Elevated+.
        Action::SelfSourceEdit { target_paths } => Decision::Deny(format!(
            "standard: self-source edit of {} path(s) denied — requires Elevated or Full autonomy",
            target_paths.len()
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
        Action::OsFileRead { .. } => Decision::Allow,
        // Elevated is the operator's autonomous-behaviour opt-in; a
        // paired+leased peer's delegated task runs. (is_paired + lease are
        // separate checkpoints in the cluster gate; this is the autonomy floor.)
        Action::ClusterTaskAccept => Decision::Allow,
        // Elevated+ : the write-allowlist (default deny-all) is the explicit
        // opt-in; once a path is allowlisted + the operator is at Elevated,
        // gated writes proceed.
        Action::OsFileWrite { .. } => Decision::Allow,
        // Program execution is the highest-blast-radius OS-tool action — even
        // at Elevated it confirms (no TTY ⇒ suppressed); only Full auto-allows
        // (handled by the evaluate_full catch-all). Mirrors ExecArbitrary's
        // Confirm-at-Elevated precedent.
        Action::OsAppLaunch { program } => Decision::Confirm(format!(
            "elevated: launching {} requires confirm (program execution)",
            program.display()
        )),
        // The clipboard is UNSCOPED: an operator at Elevated has not thereby
        // granted scoped clipboard consent the way an allowed_path grants scoped
        // file-read. So both directions still Confirm at Elevated (no TTY ⇒
        // suppressed until Full) — mirroring OsAppLaunch's highest-blast-radius
        // caution. Read = secret-capture, Write = pastejacking.
        Action::OsClipboardRead => Decision::Confirm(
            "elevated: OS clipboard read requires confirm (unscoped secret-capture; \
             no TTY ⇒ suppressed until Full)"
                .into(),
        ),
        Action::OsClipboardWrite => Decision::Confirm(
            "elevated: OS clipboard write requires confirm (pastejacking injection; \
             no TTY ⇒ suppressed until Full)"
                .into(),
        ),
        // Elevated = the operator opted into autonomous behaviour; writing to
        // their own task service proceeds (the creds are the operator's).
        Action::ExternalTaskWrite { .. } => Decision::Allow,
        // JV-MODE-04: Elevated gets Confirm for both (operator reviews each
        // self-toggle). Full + sovereign is required for Allow.
        Action::SelfSkillToggle { skill_id, enable } => Decision::Confirm(format!(
            "elevated: self-toggle skill '{skill_id}' {} requires confirm — \
             Full + sovereign mode required for auto-allow",
            if *enable { "enable" } else { "disable" }
        )),
        Action::SelfCronRegister { job_id } => Decision::Confirm(format!(
            "elevated: self-register cron '{job_id}' requires confirm — \
             cron registration always requires explicit confirm"
        )),
        // GOLD-FEAT-05: Elevated → Confirm. The operator must ack each
        // self-source edit individually; no auto-allow path at Elevated.
        // This mirrors SelfBinaryReplace: high blast radius → always confirm.
        Action::SelfSourceEdit { target_paths } => Decision::Confirm(format!(
            "elevated: self-source edit of {} path(s) requires confirm — \
             this modifies NEOTH's own source code (requires explicit operator ack)",
            target_paths.len()
        )),
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
        // PC-01 clipboard: EXPLICIT (not via the wildcard) per this fn's own
        // "add an arm when in doubt" guidance — clipboard write is a pastejacking
        // vector. At Full the operator opted into unattended autonomy; the runtime
        // kill-switches (`tools.os.clipboard.{enabled,read_enabled,write_enabled}`)
        // + the structural newline guard are the remaining gates in `os_tools::gate`.
        Action::OsClipboardRead | Action::OsClipboardWrite => Decision::Allow,
        // Full = trust the operator's other gates (policy.yaml allowlist,
        // hardware-2FA at level-set time). Everything else is allowed —
        // INCLUDING the exec-capable actions that confirm at every lower level
        // (`OsAppLaunch`, `ExecArbitrary`): at Full the operator has opted into
        // unattended autonomy and the exec-allowlist (default deny-all) is the
        // explicit per-binary opt-in.
        //
        // GOLD-COR-05 / A-05: this arm is EXPLICITLY ENUMERATED, not a wildcard
        // `_`. The old `_ => Allow` silently auto-allowed any NEW `Action`
        // variant at Full — including a high-blast-radius one — until someone
        // remembered to add an arm. Listing every variant makes the match
        // exhaustive, so adding a variant to the `Action` enum is now a COMPILE
        // ERROR here (and in the other three `evaluate_*` fns, which were
        // already exhaustive), forcing a deliberate Full-level gate decision.
        Action::Read
        | Action::WriteNeothHome
        | Action::WriteOutsideHome
        | Action::ExecScripts
        | Action::ExecArbitrary
        | Action::ChannelSend
        | Action::PaidProviderCall { .. }
        | Action::McpToolInvocation { .. }
        | Action::OsFileRead { .. }
        | Action::OsFileWrite { .. }
        | Action::OsAppLaunch { .. }
        | Action::ClusterTaskAccept
        | Action::ProactiveChannelSend { .. }
        | Action::ExternalTaskWrite { .. } => Decision::Allow,
        // JV-MODE-04 — self-skill toggle: at Full the permissions gate alone
        // signals Allow; the CALLER (`cli::self_activate::run_self_activate`)
        // is responsible for checking `sovereign_active()` and the
        // `skill_allowlist` BEFORE calling `evaluate`, so this arm is the
        // post-gate path. If the caller did NOT check those preconditions and
        // calls `evaluate` directly, it gets Allow here — the caller contract
        // is the firewall. Tests in `cli::self_activate` cover the full chain.
        //
        // Rationale for putting the sovereign/allowlist check in the CALLER:
        // `evaluate` takes only an `Action` + `AutonomyLevel`; it has no
        // access to `FreedomConfig`. The caller must gate on
        // `cfg.sovereign_active()` and `cfg.self_activation.skill_allowed(id)`
        // BEFORE dispatching — otherwise fall back to Confirm.
        Action::SelfSkillToggle { .. } => Decision::Allow,
        // JV-MODE-04 — cron registration: NEVER auto-Allow even at Full +
        // sovereign. Higher blast radius (fires on schedule without further
        // confirmation); the CLI additionally requires `--confirm-cron`.
        Action::SelfCronRegister { job_id } => Decision::Confirm(format!(
            "full: self-register cron '{job_id}' requires confirm — \
             cron registration is never auto-allowed (use --confirm-cron)"
        )),
        // GOLD-FEAT-05: NEVER auto-Allow even at Full. Mirrors SelfBinaryReplace
        // — a compromised diff applied to the live source tree is unrestricted
        // source-level RCE. The operator confirms each self-edit explicitly;
        // no amount of autonomy level removes this gate (per the spec: "gate
        // results in Confirm at Elevated and Full; NEVER Allow at any level").
        Action::SelfSourceEdit { target_paths } => Decision::Confirm(format!(
            "full: self-source edit of {} path(s) requires confirm — \
             modifies NEOTH's own source code; never auto-allowed at any level \
             (same policy as SelfBinaryReplace)",
            target_paths.len()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_task_write_gates_by_autonomy() {
        let a = Action::ExternalTaskWrite {
            provider: "caldav".into(),
            action: "add".into(),
        };
        // Strict + Standard confirm a network mutation; Elevated + Full allow.
        assert!(matches!(
            evaluate(&a, AutonomyLevel::Strict),
            Decision::Confirm(_)
        ));
        assert!(matches!(
            evaluate(&a, AutonomyLevel::Standard),
            Decision::Confirm(_)
        ));
        assert!(matches!(
            evaluate(&a, AutonomyLevel::Elevated),
            Decision::Allow
        ));
        assert!(matches!(evaluate(&a, AutonomyLevel::Full), Decision::Allow));
        // Unleasable for now (gate-only).
        assert!(lease_scope_for(&a).is_none());
    }

    // ── PC-01 clipboard autonomy mapping ─────────────────────────────────────

    #[test]
    fn clipboard_read_ladder() {
        let a = Action::OsClipboardRead;
        assert!(matches!(
            evaluate(&a, AutonomyLevel::Strict),
            Decision::Deny(_)
        ));
        assert!(matches!(
            evaluate(&a, AutonomyLevel::Standard),
            Decision::Confirm(_)
        ));
        assert!(matches!(
            evaluate(&a, AutonomyLevel::Elevated),
            Decision::Confirm(_)
        ));
        assert!(matches!(evaluate(&a, AutonomyLevel::Full), Decision::Allow));
    }

    #[test]
    fn clipboard_write_ladder() {
        let a = Action::OsClipboardWrite;
        assert!(matches!(
            evaluate(&a, AutonomyLevel::Strict),
            Decision::Deny(_)
        ));
        // Stricter than write/launch: Standard DENIES (not Confirm) — pastejacking.
        assert!(matches!(
            evaluate(&a, AutonomyLevel::Standard),
            Decision::Deny(_)
        ));
        assert!(matches!(
            evaluate(&a, AutonomyLevel::Elevated),
            Decision::Confirm(_)
        ));
        assert!(matches!(evaluate(&a, AutonomyLevel::Full), Decision::Allow));
    }

    #[test]
    fn clipboard_read_is_stricter_than_file_read() {
        // OsFileRead Allows at Standard (the allowlist is the scoped opt-in);
        // the unscoped clipboard read only Confirms (fail-closed) at Standard.
        assert!(matches!(
            evaluate(&Action::OsClipboardRead, AutonomyLevel::Standard),
            Decision::Confirm(_)
        ));
        assert!(matches!(
            evaluate(
                &Action::OsFileRead {
                    path: std::path::PathBuf::from("/x")
                },
                AutonomyLevel::Standard
            ),
            Decision::Allow
        ));
    }

    #[test]
    fn clipboard_write_stricter_than_app_launch_at_standard() {
        // App-launch Confirms at Standard; clipboard write DENIES (pastejacking
        // is a passive injection that needs no confirm to be dangerous).
        assert!(matches!(
            evaluate(&Action::OsClipboardWrite, AutonomyLevel::Standard),
            Decision::Deny(_)
        ));
        assert!(matches!(
            evaluate(
                &Action::OsAppLaunch {
                    program: std::path::PathBuf::from("/x")
                },
                AutonomyLevel::Standard
            ),
            Decision::Confirm(_)
        ));
    }

    #[test]
    fn clipboard_actions_are_unleasable() {
        // A Read lease must NEVER silently unlock the unscoped clipboard.
        assert!(lease_scope_for(&Action::OsClipboardRead).is_none());
        assert!(lease_scope_for(&Action::OsClipboardWrite).is_none());
    }

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
            pub_key_hex: "deadbeef".to_string() + "00".repeat(28).as_str(),
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
        let target = Action::DangerousTarget("192.0.2.1".into());
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

    #[test]
    fn full_explicit_enumeration_preserves_wildcard_allow_behaviour() {
        // GOLD-COR-05 / A-05: `evaluate_full` was refactored from a catch-all
        // `_ => Allow` to an EXPLICIT enumeration (so a new `Action` variant is
        // a compile error, not a silent auto-allow). This pins that the refactor
        // changed NO behaviour: every variant that the wildcard used to allow
        // still resolves to Allow at Full. The Confirm/Deny variants
        // (PatchApplyToRepo, SelfBinaryReplace, DangerousTarget) are covered by
        // their own tests above.
        use std::path::PathBuf;
        let allow_at_full = [
            Action::Read,
            Action::WriteNeothHome,
            Action::WriteOutsideHome,
            Action::ExecScripts,
            Action::ExecArbitrary,
            Action::ChannelSend,
            Action::PaidProviderCall {
                eur_estimate: 999.0,
            },
            Action::McpToolInvocation {
                server_id: "s".into(),
                tool: "t".into(),
            },
            Action::OsFileRead {
                path: PathBuf::from("/tmp/x"),
            },
            Action::OsFileWrite {
                path: PathBuf::from("/tmp/x"),
            },
            Action::OsAppLaunch {
                program: PathBuf::from("/usr/bin/x"),
            },
            Action::ClusterTaskAccept,
            Action::ProactiveChannelSend {
                channel: "telegram".into(),
            },
            Action::ExternalTaskWrite {
                provider: "caldav".into(),
                action: "add".into(),
            },
        ];
        for a in &allow_at_full {
            assert!(
                evaluate(a, AutonomyLevel::Full).is_allow(),
                "Full must allow {a:?} (preserved from the prior wildcard arm)"
            );
        }
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
            lease_scope_for(&Action::DangerousTarget("home-server".into())),
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
    fn os_file_read_gate_and_lease_scope() {
        use lease::LeaseScope;
        let a = Action::OsFileRead {
            path: std::path::PathBuf::from("/x/y"),
        };
        // Strict confirms (operator sees every external read); Standard+ allow
        // (the allowlist that already validated the path is the opt-in).
        assert!(matches!(
            evaluate(&a, AutonomyLevel::Strict),
            Decision::Confirm(_)
        ));
        assert!(evaluate(&a, AutonomyLevel::Standard).is_allow());
        assert!(evaluate(&a, AutonomyLevel::Elevated).is_allow());
        assert!(evaluate(&a, AutonomyLevel::Full).is_allow());
        // Lease-coverable under the Read scope.
        assert_eq!(lease_scope_for(&a), Some(LeaseScope::Read));
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
    fn cluster_task_accept_autonomy_mapping() {
        let a = Action::ClusterTaskAccept;
        // Strict denies unattended delegation outright.
        assert!(matches!(
            evaluate(&a, AutonomyLevel::Strict),
            Decision::Deny(_)
        ));
        // Standard confirms — so a ClusterTaskAccept lease can upgrade it to
        // Allow; bare Standard (no TTY) stays fail-closed.
        assert!(matches!(
            evaluate(&a, AutonomyLevel::Standard),
            Decision::Confirm(_)
        ));
        // Custom mirrors Standard.
        assert!(matches!(
            evaluate(&a, AutonomyLevel::Custom),
            Decision::Confirm(_)
        ));
        // Elevated + Full allow.
        assert!(matches!(
            evaluate(&a, AutonomyLevel::Elevated),
            Decision::Allow
        ));
        assert!(matches!(evaluate(&a, AutonomyLevel::Full), Decision::Allow));
    }

    #[test]
    fn os_file_write_is_stricter_than_read_and_unleasable() {
        let w = Action::OsFileWrite {
            path: std::path::PathBuf::from("/tmp/x"),
        };
        // One notch stricter than OsFileRead (Strict confirm / Standard allow):
        // a WRITE mutates the FS.
        assert!(matches!(
            evaluate(&w, AutonomyLevel::Strict),
            Decision::Deny(_)
        ));
        assert!(matches!(
            evaluate(&w, AutonomyLevel::Standard),
            Decision::Confirm(_)
        ));
        assert!(matches!(
            evaluate(&w, AutonomyLevel::Elevated),
            Decision::Allow
        ));
        assert!(matches!(evaluate(&w, AutonomyLevel::Full), Decision::Allow));
        // A raw-OS write must NEVER be unlockable by a lease.
        assert_eq!(lease_scope_for(&w), None);
    }

    #[test]
    fn cluster_task_accept_is_lease_scoped_not_hard_floor() {
        // The lease IS the cross-entity delegation grant — it must map to a
        // scope (not None), else checkpoint-2 could never pass.
        assert_eq!(
            lease_scope_for(&Action::ClusterTaskAccept),
            Some(lease::LeaseScope::ClusterTaskAccept)
        );
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

    #[test]
    fn meets_gate_respects_linear_order() {
        use AutonomyLevel::*;
        // A level meets its own gate and every lower one.
        assert!(Full.meets_gate(Elevated));
        assert!(Full.meets_gate(Strict));
        assert!(Elevated.meets_gate(Standard));
        assert!(Standard.meets_gate(Standard));
        // …but never a higher one.
        assert!(!Standard.meets_gate(Elevated));
        assert!(!Strict.meets_gate(Standard));
    }

    #[test]
    fn meets_gate_is_fail_closed_for_custom() {
        use AutonomyLevel::*;
        // Custom is unmodelled: as a CURRENT level it never satisfies an
        // Elevated/Full gate (ranks as Standard).
        assert!(!Custom.meets_gate(Elevated));
        assert!(Custom.meets_gate(Standard));
        // As a REQUIRED gate, only Full satisfies it (override map absent).
        assert!(Full.meets_gate(Custom));
        assert!(!Elevated.meets_gate(Custom));
        assert!(!Custom.meets_gate(Custom));
    }

    // ── JV-MODE-04 self-activation permission gate ────────────────────────────

    #[test]
    fn self_skill_toggle_strict_denies() {
        let a = Action::SelfSkillToggle {
            skill_id: "my-skill".into(),
            enable: true,
        };
        assert!(evaluate(&a, AutonomyLevel::Strict).is_deny());
    }

    #[test]
    fn self_skill_toggle_standard_denies() {
        let a = Action::SelfSkillToggle {
            skill_id: "my-skill".into(),
            enable: false,
        };
        assert!(evaluate(&a, AutonomyLevel::Standard).is_deny());
    }

    #[test]
    fn self_skill_toggle_elevated_confirms() {
        let a = Action::SelfSkillToggle {
            skill_id: "my-skill".into(),
            enable: true,
        };
        assert!(matches!(
            evaluate(&a, AutonomyLevel::Elevated),
            Decision::Confirm(_)
        ));
    }

    #[test]
    fn self_skill_toggle_full_allows_post_caller_gate() {
        // At Full the permissions gate returns Allow; the CALLER
        // (`run_self_activate`) is responsible for the sovereign_active +
        // allowlist check BEFORE invoking evaluate.
        let a = Action::SelfSkillToggle {
            skill_id: "my-skill".into(),
            enable: true,
        };
        assert!(evaluate(&a, AutonomyLevel::Full).is_allow());
    }

    #[test]
    fn self_skill_toggle_is_not_lease_coverable() {
        let a = Action::SelfSkillToggle {
            skill_id: "my-skill".into(),
            enable: true,
        };
        assert_eq!(
            lease_scope_for(&a),
            None,
            "SelfSkillToggle must never be pre-authorised by a lease"
        );
    }

    #[test]
    fn self_cron_register_strict_denies() {
        let a = Action::SelfCronRegister {
            job_id: "morning-brief".into(),
        };
        assert!(evaluate(&a, AutonomyLevel::Strict).is_deny());
    }

    #[test]
    fn self_cron_register_standard_denies() {
        let a = Action::SelfCronRegister {
            job_id: "morning-brief".into(),
        };
        assert!(evaluate(&a, AutonomyLevel::Standard).is_deny());
    }

    #[test]
    fn self_cron_register_elevated_confirms() {
        let a = Action::SelfCronRegister {
            job_id: "morning-brief".into(),
        };
        assert!(matches!(
            evaluate(&a, AutonomyLevel::Elevated),
            Decision::Confirm(_)
        ));
    }

    #[test]
    fn self_cron_register_full_confirms_never_auto_allows() {
        // Cron is NEVER auto-allowed even at Full sovereign — higher blast
        // radius than skill toggles (fires on schedule without further confirm).
        let a = Action::SelfCronRegister {
            job_id: "morning-brief".into(),
        };
        assert!(matches!(
            evaluate(&a, AutonomyLevel::Full),
            Decision::Confirm(_)
        ));
    }

    #[test]
    fn self_cron_register_is_not_lease_coverable() {
        let a = Action::SelfCronRegister {
            job_id: "morning-brief".into(),
        };
        assert_eq!(
            lease_scope_for(&a),
            None,
            "SelfCronRegister must never be pre-authorised by a lease"
        );
    }
}
