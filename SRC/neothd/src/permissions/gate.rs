//! Runtime permission gate — Phase 28b AU-4.
//!
//! Bridges [`evaluate`](super::evaluate) (pure decision matrix) with the
//! confirm/audit side effects: TTY confirmation, channel-driven approve/deny,
//! WAL audit events `0xA0 PERMISSION_GRANTED` / `0xA1 PERMISSION_DENIED`.
//!
//! Call sites stay thin:
//!
//! ```text
//! match Gate::for_policy(config.autonomy_policy())
//!     .check(&Action::ExecArbitrary, &writer).await {
//!     Ok(()) => run_the_thing(),
//!     Err(GateError::Denied(reason)) => return Err(...),
//!     Err(GateError::Aborted) => return Ok(()),  // operator said no
//! }
//! ```
//!
//! The placement of the gate is up to the orchestrator — usually right
//! before the side effect (provider call, channel send, shell exec). The
//! gate never owns the WAL writer; it borrows it.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use thiserror::Error;

use crate::wal::events::{EVENT_TYPE_PERMISSION_DENIED, EVENT_TYPE_PERMISSION_GRANTED};
use crate::wal::writer::WalWriterHandle;

use super::lease::{CapabilityLease, LeaseStore};
use super::{Action, AutonomyLevel, AutonomyPolicySnapshot, Decision, evaluate, lease_scope_for};

#[derive(Error, Debug)]
pub enum GateError {
    /// Static policy denied the action (no confirm round-trip happens).
    #[error("permission denied: {0}")]
    Denied(String),
    /// Operator was asked to confirm and declined.
    #[error("operator declined confirmation: {0}")]
    Aborted(String),
    /// The confirm path itself failed (no TTY available in `Tty` mode, etc).
    #[error("confirmation unavailable: {0}")]
    Unavailable(String),
}

/// How a `Confirm` decision is resolved into Allow/Abort.
#[derive(Clone, Copy, Debug)]
pub enum ConfirmStrategy {
    /// Interactive TTY prompt via dialoguer. Fails with `Unavailable` if no TTY.
    Tty,
    /// Channel-driven approve/deny — sends a message back through the channel
    /// adapter and waits for a yes/no reply with a timeout. Requires a
    /// [`ChannelAsker`]; a missing/unavailable asker fails closed.
    Channel,
    /// Daemon / cron / non-interactive: deny by default.
    FailClosed,
    /// Test-only: every `Confirm` becomes Allow. NEVER use outside tests.
    #[cfg(test)]
    #[doc(hidden)]
    AlwaysAllow,
}

/// Destination for a permission-decision audit frame.
///
/// One-shot CLIs use `DaemonRpc` while `neoth serve` owns the WAL and
/// `Writer` when they own a short-lived writer themselves. Keeping this in
/// the canonical gate prevents callers from reimplementing a weaker policy or
/// emitting a decision that does not match the one that actually authorised
/// the side effect.
#[derive(Clone, Copy)]
pub enum PermissionAuditSink<'a> {
    /// No audit destination. Valid only for best-effort callers.
    None,
    /// Append through a WAL writer owned by this process.
    Writer(&'a WalWriterHandle),
    /// Forward through the live daemon's kernel-authenticated same-user OS IPC.
    DaemonRpc(&'a Path),
    /// Deterministic audit failure used to prove required-audit fail-closed
    /// behaviour without starting a real writer.
    #[cfg(test)]
    #[doc(hidden)]
    Fail(&'static str),
}

/// R2-P1-2: trait the channel layer implements so the permission gate
/// can ask the operator a yes/no question through their active channel
/// (Telegram, Slack, future surfaces) and await a typed reply with a
/// bounded timeout. Returns `Some(true)` for approve / `Some(false)`
/// for deny / `None` if the channel adapter couldn't reach the
/// operator (offline, send failed). `None` is treated as deny by the
/// gate but distinguished in the audit log.
///
/// The trait is async because every real channel send is async; the
/// timeout is enforced INSIDE the gate via `tokio::time::timeout` so
/// implementations don't have to repeat the bounding logic.
#[async_trait::async_trait]
pub trait ChannelAsker: Send + Sync {
    /// Phrase a yes/no question on the operator's channel. `reason`
    /// is the operator-readable explanation of what the daemon is
    /// about to do (e.g. "send Telegram message to +49..." or
    /// "execute `rm -rf $TMP`"). Return `Some(approve)` once a reply
    /// arrives, `None` when the channel is unavailable.
    async fn ask(&self, reason: &str) -> Option<bool>;
}

/// SL-01a-b — an immutable, point-in-time snapshot of the operator's
/// active leases plus the **authenticated** subject the gate is deciding
/// for. Cloned at `Gate` construction (via [`Gate::with_lease_snapshot`])
/// so [`Gate::check`] never holds a live borrow of the daemon's
/// `LeaseStore` across its internal await points.
///
/// Two-clock model (deliberate): the candidate `leases` are filtered ONCE
/// at snapshot time so the daemon's store lock is never held across an
/// await — a lease granted AFTER the snapshot is not visible to this call
/// (fail-closed). But the authoritative expiry check runs at DECISION time
/// against a fresh wall-clock ([`Self::covering_lease_id`] takes `now_unix`
/// from [`Gate::check`], not a frozen field). Because decision-time is
/// always ≥ snapshot-time, the fresh check can only tighten the candidate
/// set — a lease that lapses between snapshot and decision is correctly
/// denied. The snapshot never *grants* a lease the live clock would refuse.
///
/// SECURITY CONTRACT: `subject` MUST be an identity the caller already
/// authenticated (an HMAC-verified peer pub-key-hex, a loaded plugin id, a
/// channel-platform-verified sender id, or an operator-typed value at a CLI
/// probe) — NEVER a string lifted from an untrusted inbound message body.
/// The gate compares it by equality against `lease.granted_to`; it cannot
/// itself verify authenticity. An empty subject is rejected at construction
/// ([`Gate::with_lease_snapshot`]) and again in [`CapabilityLease::covers`].
#[derive(Clone, Debug)]
pub struct LeaseContext {
    /// Leases that were active at snapshot time (already pruned of expired
    /// by [`LeaseStore::active`]). Expiry is RE-checked at decision time
    /// against a fresh clock — see the type-level two-clock note.
    leases: Vec<CapabilityLease>,
    /// The authenticated subject this gate decides for. Never empty
    /// (guarded at construction).
    subject: String,
}

impl LeaseContext {
    /// The first lease authorising `subject` for the scope `action` maps
    /// to, evaluated at `now_unix` (the caller's fresh decision-time
    /// clock), or `None`. Returns the lease id so the audit frame can
    /// record WHICH grant drove a `Confirm → Allow` upgrade. Actions that
    /// are unleasable ([`lease_scope_for`] → `None`) can never match here.
    fn covering_lease_id(&self, action: &Action, now_unix: i64) -> Option<String> {
        let scope = lease_scope_for(action)?;
        self.leases
            .iter()
            .find(|l| l.covers(&self.subject, &scope, now_unix))
            .map(|l| l.lease_id.clone())
    }
}

/// One per autonomy decision site. Cheap to construct.
pub struct Gate {
    policy: AutonomyPolicySnapshot,
    skill_invocation_policy: Option<crate::skills::resolver::SkillInvocationPolicy>,
    confirm: ConfirmStrategy,
    /// R2-P1-2: when `Some`, the `ConfirmStrategy::Channel` path
    /// routes through this asker instead of dead-failing. None
    /// preserves the pre-2026-05-22 deny-with-hint behaviour so
    /// existing call sites that haven't wired a channel layer keep
    /// their fail-closed semantics.
    channel_asker: Option<Arc<dyn ChannelAsker>>,
    /// R2-P1-2: bounded wait for the channel reply. Defaults to
    /// 90s (matches `confirm::DEFAULT_CHANNEL_TIMEOUT`). Operators
    /// running NEOTH in proactive-mode can lower it via builder.
    channel_timeout: Duration,
    /// SL-01a-b: when `Some`, a covering capability lease upgrades a
    /// `Confirm` decision to `Allow` (NEVER a `Deny` — see [`Gate::check`]).
    /// `None` preserves the pre-lease behaviour for call sites that don't
    /// pass a lease context.
    lease_ctx: Option<LeaseContext>,
    /// A previously authenticated, request-bound operator action may consume
    /// one non-interactive confirmation at a detached execution boundary.
    /// This marker upgrades only `Confirm`; the policy's `Deny` floor remains
    /// final. The source is persisted in the permission audit frame.
    preconfirmed_source: Option<&'static str>,
    audit_presentation: AuditPresentation,
}

#[derive(Clone, Copy, Default)]
enum AuditPresentation {
    #[default]
    Canonical,
    ReleasedResearch,
}

const RELEASED_RESEARCH_AUDIT_LABEL: &str = "released_research_search";
const RELEASED_RESEARCH_DENIAL_LABEL: &str = "released_research_request_denied";

struct AuditContext<'a> {
    subject: Option<&'a str>,
    lease_id: Option<&'a str>,
    confirmation_source: Option<&'a str>,
    request_binding_sha256: Option<&'a str>,
    presentation: AuditPresentation,
}

impl Gate {
    pub fn for_policy(policy: AutonomyPolicySnapshot) -> Self {
        Self {
            policy,
            skill_invocation_policy: None,
            confirm: ConfirmStrategy::FailClosed,
            channel_asker: None,
            channel_timeout: Duration::from_secs(90),
            lease_ctx: None,
            preconfirmed_source: None,
            audit_presentation: AuditPresentation::Canonical,
        }
    }

    /// Add a restrictive cap that was minted from a retained admitted skill
    /// route. This API intentionally accepts the capability itself rather than
    /// a skill id or a caller-computed decision, so neither manifest input nor
    /// a stale string can manufacture authority.
    pub(crate) fn with_skill_invocation_policy(
        mut self,
        policy: Option<crate::skills::resolver::SkillInvocationPolicy>,
    ) -> Self {
        self.skill_invocation_policy = policy;
        self
    }

    /// Built-in-level constructor retained only for the compact historical
    /// unit-test matrix. Production call sites must provide a real snapshot.
    #[cfg(test)]
    pub fn for_level(level: AutonomyLevel) -> Self {
        Self::for_policy(AutonomyPolicySnapshot::test_level(level))
    }

    /// Replace the confirm strategy. Defaults to `FailClosed`.
    pub fn with_confirm(mut self, strategy: ConfirmStrategy) -> Self {
        self.confirm = strategy;
        self
    }

    /// R2-P1-2: wire the channel-asker callback so
    /// `ConfirmStrategy::Channel` can actually ask the operator
    /// instead of dead-failing. Without this the strategy keeps
    /// returning Deny with a "channel-confirm not wired" hint so
    /// the operator sees WHY the action didn't run + how to fix it.
    pub fn with_channel_asker(mut self, asker: Arc<dyn ChannelAsker>) -> Self {
        self.channel_asker = Some(asker);
        self
    }

    /// R2-P1-2: override the channel-reply timeout. Default 90s.
    pub fn with_channel_timeout(mut self, timeout: Duration) -> Self {
        self.channel_timeout = timeout;
        self
    }

    /// Consume a confirmation that was authenticated by a narrower caller
    /// boundary (currently the private request-bound `/background` job
    /// capability). This never changes a static `Deny` into an allow.
    pub(crate) fn with_preconfirmed_confirmation(mut self, source: &'static str) -> Self {
        debug_assert!(!source.trim().is_empty());
        self.preconfirmed_source = (!source.trim().is_empty()).then_some(source);
        self
    }

    /// Keep the real request for policy and confirmation, but persist only
    /// provider-neutral labels for explicitly released external research.
    /// The caller must supply its random audit correlation, never the private
    /// topic-bearing permit binding. This changes no authorization decision.
    pub(crate) fn with_released_research_audit(mut self) -> Self {
        self.audit_presentation = AuditPresentation::ReleasedResearch;
        self
    }

    /// SL-01a-b: attach a capability-lease snapshot so the gate can upgrade
    /// a `Confirm` decision to `Allow` when the operator pre-authorised this
    /// `subject` for the action's scope. A read-only snapshot of the active
    /// leases is taken here (via [`LeaseStore::active`]) so [`Gate::check`]
    /// holds no live borrow across its await points.
    ///
    /// `subject` MUST be a pre-authenticated identity (verified peer
    /// pub-key-hex / loaded plugin id / channel-verified sender id /
    /// operator-typed probe value), never a value lifted from an untrusted
    /// message payload — see [`LeaseContext`]. `now_unix` is the snapshot
    /// clock used ONLY to pre-filter the candidate set; the authoritative
    /// expiry check happens at decision time in [`Gate::check`].
    ///
    /// An empty `subject` is rejected: the gate is returned unchanged (no
    /// lease context), so the decision falls through to the normal
    /// confirm/deny path. Defence-in-depth with [`CapabilityLease::covers`].
    pub fn with_lease_snapshot(
        mut self,
        store: &LeaseStore,
        subject: impl Into<String>,
        now_unix: i64,
    ) -> Self {
        let subject = subject.into();
        if subject.is_empty() {
            return self; // fail-closed: never build a context for an empty subject
        }
        self.lease_ctx = Some(LeaseContext {
            leases: store.active(now_unix).into_iter().cloned().collect(),
            subject,
        });
        self
    }

    /// Convenience: TTY confirm if stdin is a terminal, else fail closed.
    /// Used by interactive CLI commands. The channel pipeline uses
    /// `with_confirm(ConfirmStrategy::FailClosed)` until AU-4-part-2 lands.
    pub fn auto_confirm() -> ConfirmStrategy {
        use std::io::IsTerminal;
        if std::io::stdin().is_terminal() {
            ConfirmStrategy::Tty
        } else {
            ConfirmStrategy::FailClosed
        }
    }

    /// Decision-time wall-clock (unix seconds). Read fresh on every
    /// [`Self::check`] so lease expiry is enforced at the moment the action
    /// is decided, not at snapshot construction.
    fn now_unix() -> i64 {
        crate::time::now_unix_i64()
    }

    /// Resolve `action` under the configured level + confirm strategy.
    /// Emits legacy permission evidence plus one typed TrustDecision frame when
    /// `writer` is `Some`.
    ///
    /// Returns `Ok(())` on Allow, `Err(GateError::*)` otherwise.
    pub async fn check(
        &self,
        action: &Action,
        writer: Option<&WalWriterHandle>,
    ) -> Result<(), GateError> {
        let sink = writer
            .map(PermissionAuditSink::Writer)
            .unwrap_or(PermissionAuditSink::None);
        self.check_at_with_audit(action, sink, Self::now_unix(), false, None)
            .await
    }

    /// Resolve `action` and require the permission-decision frame to be
    /// durably appended before returning `Ok(())`. Paid provider dispatch uses
    /// this stronger boundary: an operator grant without its WAL proof must
    /// never open the network side effect.
    pub async fn check_required_audit(
        &self,
        action: &Action,
        writer: &WalWriterHandle,
    ) -> Result<(), GateError> {
        self.check_at_with_audit(
            action,
            PermissionAuditSink::Writer(writer),
            Self::now_unix(),
            true,
            None,
        )
        .await
    }

    /// Test-only variant of [`Self::check_required_audit`] with an explicit
    /// decision-time clock. Production callers must retain the fresh wall
    /// clock used by `check_required_audit`.
    #[cfg(test)]
    pub(crate) async fn check_required_audit_at(
        &self,
        action: &Action,
        writer: &WalWriterHandle,
        now_unix: i64,
        request_binding_sha256: Option<&str>,
    ) -> Result<(), GateError> {
        self.check_at_with_audit(
            action,
            PermissionAuditSink::Writer(writer),
            now_unix,
            true,
            request_binding_sha256,
        )
        .await
    }

    /// Resolve one action and route the exact permission decision through the
    /// caller's single-writer-compatible audit destination.
    ///
    /// `request_binding_sha256` lets a caller bind an otherwise payload-free
    /// action such as [`Action::ExecArbitrary`] to its concrete request. When
    /// `audit_required` is true, a missing or failing sink denies the action
    /// before the caller may perform its side effect.
    pub(crate) async fn check_with_audit_sink(
        &self,
        action: &Action,
        sink: PermissionAuditSink<'_>,
        audit_required: bool,
        request_binding_sha256: Option<&str>,
    ) -> Result<(), GateError> {
        self.check_at_with_audit(
            action,
            sink,
            Self::now_unix(),
            audit_required,
            request_binding_sha256,
        )
        .await
    }

    /// Resolve a descriptor for the writer-owned durable-admission
    /// transaction without appending generic permission evidence. The returned
    /// value is only an expected receipt; a caller must still obtain the
    /// authenticated typed receipt before crossing an effect boundary.
    ///
    /// The channel confirmation bus is deliberately excluded here: a live
    /// reply is not restart-safe authority. Static policy allows and active
    /// leases are represented; every other confirmation resolves to a durable
    /// denial until a separately verifiable durable capability exists.
    pub(crate) async fn resolve_trust_admission(
        &self,
        action: &Action,
        operation_id_sha256: &str,
        request_binding_sha256: &str,
    ) -> Result<super::trust_ledger::TrustAdmissionDescriptor, GateError> {
        let policy_snapshot = self.current_policy_snapshot();
        let (decision, lease_id, confirmation_source) = self
            .resolve_durable_decision_at(action, Self::now_unix(), &policy_snapshot)
            .await;
        let subject = self
            .lease_ctx
            .as_ref()
            .map(|context| context.subject.as_str());
        super::trust_ledger::TrustAdmissionDescriptor::from_gate_resolution(
            operation_id_sha256,
            action,
            policy_snapshot.level(),
            &decision,
            subject,
            lease_id.as_deref(),
            confirmation_source,
            request_binding_sha256,
            policy_snapshot.trust_fingerprint_sha256(),
        )
        .map_err(|error| {
            GateError::Unavailable(format!("invalid durable admission descriptor: {error}"))
        })
    }

    /// [`Self::check`] with an explicit decision-time clock. The lease
    /// expiry re-check uses `now_unix`; `check()` passes a fresh wall-clock,
    /// tests pass a deterministic value. Splitting it out keeps the lease
    /// liveness check testable without a real clock while production always
    /// re-enforces expiry at the live moment.
    ///
    /// `pub(crate)` ON PURPOSE: an explicit clock could be set to the past to
    /// make an expired lease appear live, so production code outside this
    /// crate must go through [`Self::check`] (which always reads a fresh
    /// wall-clock). Only the in-crate test module supplies a fixed clock.
    #[cfg(test)]
    pub(crate) async fn check_at(
        &self,
        action: &Action,
        writer: Option<&WalWriterHandle>,
        now_unix: i64,
    ) -> Result<(), GateError> {
        let sink = writer
            .map(PermissionAuditSink::Writer)
            .unwrap_or(PermissionAuditSink::None);
        self.check_at_with_audit(action, sink, now_unix, false, None)
            .await
    }

    async fn check_at_with_audit(
        &self,
        action: &Action,
        sink: PermissionAuditSink<'_>,
        now_unix: i64,
        audit_required: bool,
        request_binding_sha256: Option<&str>,
    ) -> Result<(), GateError> {
        let policy_snapshot = self.current_policy_snapshot();
        let (final_decision, lease_id, confirmation_source, audit_policy_snapshot) = self
            .resolve_decision_at(action, now_unix, &policy_snapshot)
            .await;

        if !matches!(sink, PermissionAuditSink::None) {
            let subject = self.lease_ctx.as_ref().map(|c| c.subject.as_str());
            let audit_result = audit(
                sink,
                action,
                audit_policy_snapshot.level(),
                &final_decision,
                AuditContext {
                    subject,
                    lease_id: lease_id.as_deref(),
                    confirmation_source,
                    request_binding_sha256,
                    presentation: self.audit_presentation,
                },
            )
            .await;
            if audit_required {
                audit_result.map_err(|error| {
                    GateError::Unavailable(format!(
                        "required permission audit WAL append failed: {error}"
                    ))
                })?;
            } else if let Err(error) = audit_result {
                tracing::warn!(
                    error = %error,
                    action = ?action,
                    decision = final_decision.tag(),
                    "best-effort permission audit WAL append failed"
                );
            }
        } else if audit_required {
            return Err(GateError::Unavailable(
                "required permission audit has no WAL writer or daemon audit-RPC sink".into(),
            ));
        }

        match final_decision {
            Decision::Allow => Ok(()),
            Decision::Deny(r) => Err(GateError::Denied(r)),
            // `Confirm` is never returned by resolve_confirm — it produces
            // Allow or Deny only. Treat as Aborted defensively.
            Decision::Confirm(r) => Err(GateError::Aborted(r)),
        }
    }

    async fn resolve_decision_at(
        &self,
        action: &Action,
        now_unix: i64,
        policy_snapshot: &AutonomyPolicySnapshot,
    ) -> (
        Decision,
        Option<String>,
        Option<&'static str>,
        AutonomyPolicySnapshot,
    ) {
        let decision = self.effective_decision_at(action, policy_snapshot);
        match decision {
            // A request-bound capability can accompany a policy Allow. Keep
            // the source in generic audit evidence even where no upgrade was
            // required.
            Decision::Allow => (
                Decision::Allow,
                None,
                self.preconfirmed_source,
                policy_snapshot.clone(),
            ),
            Decision::Deny(reason) => (Decision::Deny(reason), None, None, policy_snapshot.clone()),
            Decision::Confirm(reason) => match self
                .lease_ctx
                .as_ref()
                .and_then(|context| context.covering_lease_id(action, now_unix))
            {
                Some(id) => (
                    Decision::Allow,
                    Some(id),
                    Some("capability_lease"),
                    policy_snapshot.clone(),
                ),
                None => match self.preconfirmed_source {
                    Some(source) => (Decision::Allow, None, Some(source), policy_snapshot.clone()),
                    None => {
                        let resolved = self.resolve_confirm(action, &reason).await;
                        let source = if resolved.is_allow() {
                            match self.confirm {
                                ConfirmStrategy::Tty => Some("tty_operator_confirm"),
                                ConfirmStrategy::Channel => Some("channel_operator_confirm"),
                                ConfirmStrategy::FailClosed => None,
                                #[cfg(test)]
                                ConfirmStrategy::AlwaysAllow => Some("test_always_allow"),
                            }
                        } else {
                            None
                        };
                        let audit_policy_snapshot = if resolved.is_allow()
                            && self
                                .skill_invocation_policy
                                .as_ref()
                                .is_some_and(|policy| policy.has_skill_cap())
                        {
                            self.current_policy_snapshot()
                        } else {
                            policy_snapshot.clone()
                        };
                        let final_decision = if resolved.is_allow() {
                            // The answer already confirmed this exact action. A
                            // current Deny can revoke it; an unchanged Confirm
                            // must not discard the operator's positive answer.
                            match self.effective_decision_at(action, &audit_policy_snapshot) {
                                Decision::Deny(reason) => Decision::Deny(reason),
                                Decision::Allow | Decision::Confirm(_) => Decision::Allow,
                            }
                        } else {
                            resolved
                        };
                        let source = final_decision.is_allow().then_some(source).flatten();
                        (final_decision, None, source, audit_policy_snapshot)
                    }
                },
            },
        }
    }

    async fn resolve_durable_decision_at(
        &self,
        action: &Action,
        now_unix: i64,
        policy_snapshot: &AutonomyPolicySnapshot,
    ) -> (Decision, Option<String>, Option<&'static str>) {
        let decision = self.effective_decision_at(action, policy_snapshot);
        match decision {
            Decision::Allow => (Decision::Allow, None, None),
            Decision::Deny(reason) => (Decision::Deny(reason), None, None),
            Decision::Confirm(reason) => match self
                .lease_ctx
                .as_ref()
                .and_then(|context| context.covering_lease_id(action, now_unix))
            {
                Some(id) => (Decision::Allow, Some(id), Some("capability_lease")),
                None => {
                    let denied = match self.confirm {
                        ConfirmStrategy::FailClosed => {
                            format!("daemon-mode fail-closed; {reason}")
                        }
                        ConfirmStrategy::Channel => format!(
                            "durable admission refuses ephemeral channel confirmation; {reason}"
                        ),
                        ConfirmStrategy::Tty => format!(
                            "durable admission requires a request-bound confirmation receipt; {reason}"
                        ),
                        #[cfg(test)]
                        ConfirmStrategy::AlwaysAllow => format!(
                            "durable admission refuses test-only ephemeral confirmation; {reason}"
                        ),
                    };
                    (Decision::Deny(denied), None, None)
                }
            },
        }
    }

    async fn resolve_confirm(&self, action: &Action, reason: &str) -> Decision {
        match self.confirm {
            #[cfg(test)]
            ConfirmStrategy::AlwaysAllow => Decision::Allow,
            ConfirmStrategy::FailClosed => {
                Decision::Deny(format!("daemon-mode fail-closed; {reason}"))
            }
            ConfirmStrategy::Channel => {
                // R2-P1-2 (2026-05-22 Session 20): route through the
                // operator-supplied ChannelAsker when wired. Reply
                // semantics:
                //   - Some(true)  → Allow (operator approved)
                //   - Some(false) → Deny  ("operator denied: …")
                //   - None        → Deny  ("channel unavailable: …")
                //   - timeout     → Deny  ("channel-confirm timed out: …")
                // Without an asker we surface a clear "not wired" hint
                // so the operator sees WHY the action didn't run + how
                // to fix it (wire a channel adapter to the Gate).
                let _ = action;
                match &self.channel_asker {
                    Some(asker) => {
                        let timeout = self.channel_timeout;
                        match tokio::time::timeout(timeout, asker.ask(reason)).await {
                            Ok(Some(true)) => Decision::Allow,
                            Ok(Some(false)) => {
                                Decision::Deny(format!("operator denied via channel: {reason}"))
                            }
                            Ok(None) => {
                                Decision::Deny(format!("channel unavailable for confirm; {reason}"))
                            }
                            Err(_) => Decision::Deny(format!(
                                "channel-confirm timed out after {}s; {reason}",
                                timeout.as_secs()
                            )),
                        }
                    }
                    None => Decision::Deny(format!(
                        "channel-confirm not wired (wire a ChannelAsker via \
                         Gate::with_channel_asker); {reason}"
                    )),
                }
            }
            ConfirmStrategy::Tty => {
                #[cfg(feature = "wizard")]
                {
                    use std::io::IsTerminal;
                    if !std::io::stdin().is_terminal() {
                        return Decision::Deny(format!("no TTY for confirm; {reason}"));
                    }
                    let prompt = format!("[confirm] {reason} ({action:?})");
                    match dialoguer::Confirm::with_theme(
                        &dialoguer::theme::ColorfulTheme::default(),
                    )
                    .with_prompt(prompt)
                    .default(false)
                    .interact()
                    {
                        Ok(true) => Decision::Allow,
                        Ok(false) => Decision::Deny(format!("operator declined; {reason}")),
                        Err(e) => Decision::Deny(format!("confirm dialog error: {e}")),
                    }
                }
                #[cfg(not(feature = "wizard"))]
                {
                    let _ = (action, reason);
                    Decision::Deny(format!("wizard feature disabled; cannot prompt. {reason}"))
                }
            }
        }
    }

    fn current_policy_snapshot(&self) -> AutonomyPolicySnapshot {
        self.skill_invocation_policy.as_ref().map_or_else(
            || self.policy.clone(),
            |route_policy| route_policy.current_global_snapshot(&self.policy),
        )
    }

    fn effective_decision_at(
        &self,
        action: &Action,
        policy_snapshot: &AutonomyPolicySnapshot,
    ) -> Decision {
        self.skill_invocation_policy.as_ref().map_or_else(
            || evaluate(action, policy_snapshot),
            |route_policy| route_policy.evaluate_at_snapshot(action, policy_snapshot),
        )
    }
}

/// Append compatibility permission evidence and one typed TrustDecision frame.
///
/// `subject` and `lease_id` are SL-01a-b additions (both `None` for call
/// sites that pass no lease context). When a capability lease upgraded a
/// `Confirm` to `Allow`, `lease_id` names the grant that authorised it so
/// the operator can cross-reference `0xA5 LEASE_GRANTED` and prove the
/// chain: "subject S was allowed action A at T because of lease L". The
/// existing `0xA0 PERMISSION_GRANTED` / `0xA1 PERMISSION_DENIED` frame remains
/// byte-schema compatible; the paired typed record is metadata-only and uses
/// the extended `TrustDecision` subtype.
async fn audit(
    sink: PermissionAuditSink<'_>,
    action: &Action,
    level: AutonomyLevel,
    decision: &Decision,
    context: AuditContext<'_>,
) -> Result<()> {
    let AuditContext {
        subject,
        lease_id,
        confirmation_source,
        request_binding_sha256: explicit_request_binding_sha256,
        presentation,
    } = context;
    let projected_decision;
    let action_label;
    let decision = match presentation {
        AuditPresentation::Canonical => {
            action_label = format!("{action:?}");
            decision
        }
        AuditPresentation::ReleasedResearch => {
            anyhow::ensure!(
                matches!(action, Action::ExternalHttpRequest { .. }),
                "released-research audit presentation requires an external HTTP action"
            );
            action_label = RELEASED_RESEARCH_AUDIT_LABEL.to_owned();
            projected_decision = match decision {
                Decision::Allow => Decision::Allow,
                Decision::Deny(_) => Decision::Deny(RELEASED_RESEARCH_DENIAL_LABEL.into()),
                Decision::Confirm(_) => Decision::Confirm(RELEASED_RESEARCH_DENIAL_LABEL.into()),
            };
            &projected_decision
        }
    };
    let (event_type, reason): (u8, Option<&str>) = match decision {
        Decision::Allow => (EVENT_TYPE_PERMISSION_GRANTED, None),
        Decision::Deny(r) => (EVENT_TYPE_PERMISSION_DENIED, Some(r.as_str())),
        Decision::Confirm(r) => (EVENT_TYPE_PERMISSION_DENIED, Some(r.as_str())),
    };
    let (authorization_id, intrinsic_request_binding_sha256) = match action {
        Action::PaidProviderCall {
            authorization_id,
            request_binding_sha256,
            ..
        }
        | Action::UnboundedPaidProviderCall {
            authorization_id,
            request_binding_sha256,
            ..
        } => (
            Some(authorization_id.as_str()),
            Some(request_binding_sha256.as_str()),
        ),
        Action::ExternalTtsSynthesis {
            request_binding_sha256,
            ..
        }
        | Action::ExternalHttpRequest {
            request_binding_sha256,
            ..
        } => (None, Some(request_binding_sha256.as_str())),
        _ => (None, None),
    };
    if let (Some(explicit), Some(intrinsic)) = (
        explicit_request_binding_sha256,
        intrinsic_request_binding_sha256,
    ) {
        anyhow::ensure!(
            explicit == intrinsic,
            "explicit permission request binding does not match the action binding"
        );
    }
    let request_binding_sha256 =
        explicit_request_binding_sha256.or(intrinsic_request_binding_sha256);
    let trust_event = super::trust_ledger::TrustEvent::from_gate(
        action,
        level,
        decision,
        subject,
        lease_id,
        confirmation_source,
        request_binding_sha256,
        crate::time::now_unix_ns(),
    )?;
    let payload = serde_json::to_vec(&serde_json::json!({
        "level": level.as_str(),
        "action": action_label,
        "authorization_id": authorization_id,
        "request_binding_sha256": request_binding_sha256,
        "decision": decision.tag(),
        "reason": reason,
        "subject": subject,
        "lease_id": lease_id,
        "confirmation_source": confirmation_source,
        "ts_ns": crate::time::now_unix_ns(),
    }))?;
    match sink {
        PermissionAuditSink::None => Ok(()),
        PermissionAuditSink::Writer(writer) => {
            let header = crate::wal::HeaderBuilder::new(event_type, &payload)
                .flags(crate::wal::EventFlags::SYNTHETIC)
                .build();
            writer.append(header, payload).await?;
            super::trust_ledger::append_to_writer(writer, &trust_event).await?;
            Ok(())
        }
        PermissionAuditSink::DaemonRpc(home) => {
            crate::daemon::audit_rpc::try_post_audit_frame(home, event_type, &payload)
                .await
                .map_err(|error| anyhow::anyhow!(error))?;
            super::trust_ledger::append_to_daemon(home, &trust_event).await
        }
        #[cfg(test)]
        PermissionAuditSink::Fail(message) => anyhow::bail!("{message}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wal::events::{EVENT_TYPE_PERMISSION_DENIED, EVENT_TYPE_PERMISSION_GRANTED};
    use crate::wal::frame::decode_frame;
    use crate::wal::segment_header::SEGMENT_HEADER_LEN;
    use crate::wal::spawn as wal_spawn;
    use crate::wal::writer::spawn_for_home;
    use tempfile::tempdir;
    use tokio::fs::read;

    fn paid_action(eur_estimate: f32) -> Action {
        Action::PaidProviderCall {
            provider: "openai_api".into(),
            model: "gpt-5".into(),
            authorization_id: "a".repeat(64),
            request_binding_sha256: "b".repeat(64),
            eur_estimate,
        }
    }

    #[tokio::test]
    async fn allow_path_lets_action_through() {
        let gate = Gate::for_level(AutonomyLevel::Standard);
        let r = gate.check(&Action::Read, None).await;
        assert!(r.is_ok(), "Read on Standard must Allow, got {r:?}");
    }

    #[tokio::test]
    async fn custom_snapshot_drives_allow_confirm_and_deny_through_gate() {
        let mut custom = crate::permissions::CustomAutonomyConfig::default();
        custom.overrides.insert(
            crate::permissions::ActionKind::ExecArbitrary,
            crate::permissions::CustomDecision::Allow,
        );
        custom.overrides.insert(
            crate::permissions::ActionKind::Read,
            crate::permissions::CustomDecision::Confirm,
        );
        custom.overrides.insert(
            crate::permissions::ActionKind::ChannelSend,
            crate::permissions::CustomDecision::Deny,
        );
        let policy = AutonomyPolicySnapshot::new(AutonomyLevel::Custom, &custom);

        assert!(
            Gate::for_policy(policy.clone())
                .check(&Action::ExecArbitrary, None)
                .await
                .is_ok()
        );
        assert!(
            Gate::for_policy(policy.clone())
                .with_confirm(ConfirmStrategy::AlwaysAllow)
                .check(&Action::Read, None)
                .await
                .is_ok()
        );
        assert!(matches!(
            Gate::for_policy(policy)
                .check(&Action::ChannelSend, None)
                .await,
            Err(GateError::Denied(_))
        ));
    }

    #[tokio::test]
    async fn deny_path_returns_denied() {
        let gate = Gate::for_level(AutonomyLevel::Standard);
        let r = gate
            .check(&Action::DangerousTarget("home-server".into()), None)
            .await;
        assert!(matches!(r, Err(GateError::Denied(_))), "got {r:?}");
    }

    #[tokio::test]
    async fn confirm_under_failclosed_denies() {
        // Standard + WriteOutsideHome → Confirm; with FailClosed strategy
        // that becomes Deny (no operator to ask).
        let gate =
            Gate::for_level(AutonomyLevel::Standard).with_confirm(ConfirmStrategy::FailClosed);
        let r = gate.check(&Action::WriteOutsideHome, None).await;
        assert!(matches!(r, Err(GateError::Denied(_))), "got {r:?}");
    }

    #[tokio::test]
    async fn confirm_under_always_allow_passes() {
        // Test-only strategy: every Confirm collapses to Allow. Lets us
        // exercise the gate plumbing without a TTY.
        let gate =
            Gate::for_level(AutonomyLevel::Standard).with_confirm(ConfirmStrategy::AlwaysAllow);
        let r = gate.check(&Action::WriteOutsideHome, None).await;
        assert!(r.is_ok(), "AlwaysAllow must succeed, got {r:?}");
    }

    #[tokio::test]
    async fn channel_strategy_denies_until_wired() {
        // R2-P1-2: when no ChannelAsker is wired, the strategy
        // surfaces an actionable "wire a ChannelAsker via
        // Gate::with_channel_asker" hint instead of an opaque deny.
        let gate = Gate::for_level(AutonomyLevel::Standard).with_confirm(ConfirmStrategy::Channel);
        let r = gate.check(&Action::WriteOutsideHome, None).await;
        match r {
            Err(GateError::Denied(reason)) => {
                assert!(
                    reason.contains("not wired") && reason.contains("ChannelAsker"),
                    "deny reason must guide the operator: {reason}"
                );
            }
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    // ── R2-P1-2 channel-confirm wired-asker tests ────────────────────────

    struct ApproveAsker;
    #[async_trait::async_trait]
    impl ChannelAsker for ApproveAsker {
        async fn ask(&self, _reason: &str) -> Option<bool> {
            Some(true)
        }
    }

    struct DenyAsker;
    #[async_trait::async_trait]
    impl ChannelAsker for DenyAsker {
        async fn ask(&self, _reason: &str) -> Option<bool> {
            Some(false)
        }
    }

    struct UnavailableAsker;
    #[async_trait::async_trait]
    impl ChannelAsker for UnavailableAsker {
        async fn ask(&self, _reason: &str) -> Option<bool> {
            None
        }
    }

    struct SlowAsker;
    #[async_trait::async_trait]
    impl ChannelAsker for SlowAsker {
        async fn ask(&self, _reason: &str) -> Option<bool> {
            tokio::time::sleep(Duration::from_secs(5)).await;
            Some(true)
        }
    }

    #[tokio::test]
    async fn r2_p1_2_channel_asker_approve_results_in_allow() {
        let gate = Gate::for_level(AutonomyLevel::Standard)
            .with_confirm(ConfirmStrategy::Channel)
            .with_channel_asker(Arc::new(ApproveAsker));
        let r = gate.check(&Action::WriteOutsideHome, None).await;
        assert!(
            r.is_ok(),
            "channel approve must let action through, got {r:?}"
        );
    }

    #[tokio::test]
    async fn r2_p1_2_channel_asker_deny_results_in_denied_with_operator_reason() {
        let gate = Gate::for_level(AutonomyLevel::Standard)
            .with_confirm(ConfirmStrategy::Channel)
            .with_channel_asker(Arc::new(DenyAsker));
        let r = gate.check(&Action::WriteOutsideHome, None).await;
        match r {
            Err(GateError::Denied(reason)) => {
                assert!(
                    reason.contains("operator denied via channel"),
                    "deny reason must surface the operator's choice: {reason}"
                );
            }
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn r2_p1_2_channel_unavailable_yields_distinct_denied_reason() {
        let gate = Gate::for_level(AutonomyLevel::Standard)
            .with_confirm(ConfirmStrategy::Channel)
            .with_channel_asker(Arc::new(UnavailableAsker));
        let r = gate.check(&Action::WriteOutsideHome, None).await;
        match r {
            Err(GateError::Denied(reason)) => {
                assert!(
                    reason.contains("channel unavailable"),
                    "deny reason must distinguish unavailable channel from operator-denied: {reason}"
                );
            }
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn r2_p1_2_channel_confirm_respects_timeout() {
        // R2 done-criterion: "Channel-confirm mit Timeout". A slow
        // asker that takes 5s must hit the bounded wait + return
        // timeout-tagged deny so the WAL audit can distinguish a
        // hung channel from operator-denied.
        let gate = Gate::for_level(AutonomyLevel::Standard)
            .with_confirm(ConfirmStrategy::Channel)
            .with_channel_asker(Arc::new(SlowAsker))
            .with_channel_timeout(Duration::from_millis(80));
        let start = std::time::Instant::now();
        let r = gate.check(&Action::WriteOutsideHome, None).await;
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(1),
            "timeout must fire well before the asker's 5s sleep, took {elapsed:?}"
        );
        match r {
            Err(GateError::Denied(reason)) => {
                assert!(
                    reason.contains("timed out"),
                    "timeout deny must say so: {reason}"
                );
            }
            other => panic!("expected Denied on timeout, got {other:?}"),
        }
    }

    fn w138_retained_skill_policy(
        decision: Option<crate::permissions::CustomDecision>,
    ) -> crate::skills::resolver::SkillInvocationPolicy {
        let skill_id = crate::permissions::SkillId::parse("w138-retained-effect-skill")
            .expect("W138 fixture Skill id");
        let override_policy = decision.map(|decision| crate::permissions::SkillAutonomyOverride {
            level: AutonomyLevel::Custom,
            overrides: std::collections::BTreeMap::from([(
                crate::permissions::ActionKind::ExecArbitrary,
                decision,
            )]),
        });
        let config = crate::permissions::CustomAutonomyConfig {
            overrides: std::collections::BTreeMap::new(),
            skill_overrides: override_policy
                .map(|override_policy| {
                    std::collections::BTreeMap::from([(skill_id, override_policy)])
                })
                .unwrap_or_default(),
        };
        let admitted = AutonomyPolicySnapshot::new(AutonomyLevel::Full, &config);
        crate::skills::resolver::test_invocation_policy_for_skill_id(
            "w138-retained-effect-skill",
            &admitted,
        )
        .expect("mint real retained W138 route policy")
    }

    #[tokio::test]
    async fn w138_retained_skill_deny_blocks_effect_even_when_global_and_confirm_allow() {
        let result = Gate::for_level(AutonomyLevel::Full)
            .with_skill_invocation_policy(Some(w138_retained_skill_policy(Some(
                crate::permissions::CustomDecision::Deny,
            ))))
            .with_confirm(ConfirmStrategy::AlwaysAllow)
            .check(&Action::ExecArbitrary, None)
            .await;
        assert!(
            matches!(result, Err(GateError::Denied(_))),
            "a retained selected-skill Deny must stop the effect before confirmation can bypass it: {result:?}"
        );
    }

    #[tokio::test]
    async fn w138_retained_skill_confirm_uses_channel_operator_answer() {
        let policy = w138_retained_skill_policy(Some(crate::permissions::CustomDecision::Confirm));
        let approved = Gate::for_level(AutonomyLevel::Full)
            .with_skill_invocation_policy(Some(policy.clone()))
            .with_confirm(ConfirmStrategy::Channel)
            .with_channel_asker(Arc::new(ApproveAsker))
            .check(&Action::ExecArbitrary, None)
            .await;
        assert!(
            approved.is_ok(),
            "the actual channel approval must resolve retained Confirm"
        );

        let rejected = Gate::for_level(AutonomyLevel::Full)
            .with_skill_invocation_policy(Some(policy))
            .with_confirm(ConfirmStrategy::Channel)
            .with_channel_asker(Arc::new(DenyAsker))
            .check(&Action::ExecArbitrary, None)
            .await;
        assert!(
            matches!(&rejected, Err(GateError::Denied(reason)) if reason.contains("operator denied via channel")),
            "a retained Confirm must use the real channel rejection path, not inherit global Allow: {rejected:?}"
        );
    }

    #[tokio::test]
    async fn w138_effect_gate_applies_global_tightening_after_route_is_retained() {
        let retained = w138_retained_skill_policy(None);
        let result = Gate::for_level(AutonomyLevel::Strict)
            .with_skill_invocation_policy(Some(retained))
            .check(&Action::ExecArbitrary, None)
            .await;
        assert!(
            matches!(result, Err(GateError::Denied(_))),
            "the fresh Strict global policy must tighten a retained Full-route invocation"
        );
    }

    #[tokio::test]
    async fn w138_retained_route_without_skill_cap_preserves_global_effect_behavior() {
        let result = Gate::for_level(AutonomyLevel::Full)
            .with_skill_invocation_policy(Some(w138_retained_skill_policy(None)))
            .check(&Action::ExecArbitrary, None)
            .await;
        assert!(
            result.is_ok(),
            "a retained route without a cap must preserve Full global behavior: {result:?}"
        );
    }

    struct W138ReloadThenApproveAsker {
        reload: Arc<crate::config::reload::ReloadController>,
        config_path: std::path::PathBuf,
        changed: crate::config::FreedomConfig,
    }

    #[async_trait::async_trait]
    impl ChannelAsker for W138ReloadThenApproveAsker {
        async fn ask(&self, _reason: &str) -> Option<bool> {
            std::fs::write(
                &self.config_path,
                serde_yaml::to_string(&self.changed).unwrap(),
            )
            .expect("persist reloaded autonomy fixture");
            match self.reload.try_reload().expect("accepted autonomy reload") {
                crate::config::reload::ReloadResult::Reloaded { .. } => {}
                other => panic!("expected Reloaded before channel answer, got {other:?}"),
            }
            Some(true)
        }
    }

    #[tokio::test]
    async fn w138_channel_approval_rechecks_reloaded_cap_and_audits_current_deny() {
        let skill_id = crate::permissions::SkillId::parse("w138-channel-reload-cap").unwrap();
        let mut initial = crate::config::FreedomConfig {
            autonomy: AutonomyLevel::Standard,
            ..Default::default()
        };
        initial.custom_autonomy.overrides.insert(
            crate::permissions::ActionKind::ExecArbitrary,
            crate::permissions::CustomDecision::Confirm,
        );
        initial.custom_autonomy.skill_overrides.insert(
            skill_id,
            crate::permissions::SkillAutonomyOverride {
                level: AutonomyLevel::Custom,
                overrides: std::collections::BTreeMap::from([(
                    crate::permissions::ActionKind::ExecArbitrary,
                    crate::permissions::CustomDecision::Confirm,
                )]),
            },
        );
        let home = tempdir().unwrap();
        let config_path = home.path().join("freedom.yaml");
        std::fs::write(&config_path, serde_yaml::to_string(&initial).unwrap()).unwrap();
        let reload = Arc::new(crate::config::reload::ReloadController::new(
            initial.clone(),
            config_path.clone(),
        ));
        let admitted = reload.autonomy_policy();
        let admitted_fingerprint = admitted.trust_fingerprint_sha256();
        let retained = crate::skills::resolver::test_invocation_policy_for_skill_id_with_reload(
            "w138-channel-reload-cap",
            &admitted,
            Arc::clone(&reload),
        )
        .unwrap();
        let mut changed = initial;
        changed.autonomy = AutonomyLevel::Custom;
        changed.custom_autonomy.overrides.insert(
            crate::permissions::ActionKind::ExecArbitrary,
            crate::permissions::CustomDecision::Deny,
        );

        let wal_dir = home.path().join("wal");
        std::fs::create_dir_all(&wal_dir).unwrap();
        let segment = wal_dir.join("000001.wal");
        let (writer, join) = spawn_for_home(segment.clone(), home.path().to_path_buf()).unwrap();
        let result = Gate::for_policy(admitted)
            .with_skill_invocation_policy(Some(retained))
            .with_confirm(ConfirmStrategy::Channel)
            .with_channel_asker(Arc::new(W138ReloadThenApproveAsker {
                reload: Arc::clone(&reload),
                config_path,
                changed,
            }))
            .check_with_audit_sink(
                &Action::ExecArbitrary,
                PermissionAuditSink::Writer(&writer),
                true,
                None,
            )
            .await;
        assert!(
            matches!(result, Err(GateError::Denied(_))),
            "the reloaded Deny must win after a real channel approval: {result:?}"
        );
        let current = reload.autonomy_policy();
        let current_fingerprint = current.trust_fingerprint_sha256();
        assert_eq!(current.level(), AutonomyLevel::Custom);
        assert_ne!(current_fingerprint, admitted_fingerprint);

        drop(writer);
        join.await.unwrap();
        let bytes = read(&segment).await.unwrap();
        let legacy = decode_frame(&bytes[SEGMENT_HEADER_LEN..]).unwrap();
        assert_eq!(legacy.header.event_type, EVENT_TYPE_PERMISSION_DENIED);
        let legacy_payload: serde_json::Value = serde_json::from_slice(legacy.payload).unwrap();
        assert_eq!(legacy_payload["level"], "custom");
        assert_eq!(legacy_payload["decision"], "deny");
        let trust = decode_frame(&bytes[SEGMENT_HEADER_LEN + legacy.header.total_len as usize..])
            .expect("final typed TrustDecision follows denied permission audit");
        let trust = crate::permissions::trust_ledger::TrustEvent::decode(trust.payload).unwrap();
        assert_eq!(trust.outcome, crate::permissions::TrustOutcome::Denied);
        assert_eq!(trust.autonomy_level, current.level());
        assert_ne!(current_fingerprint, admitted_fingerprint);
    }
    #[tokio::test]
    async fn audit_emits_granted_frame_when_allow() {
        let home = tempdir().unwrap();
        let wal_dir = home.path().join("wal");
        std::fs::create_dir_all(&wal_dir).unwrap();
        let seg = wal_dir.join("000001.wal");
        let (writer, join) = spawn_for_home(seg.clone(), home.path().to_path_buf()).unwrap();

        let gate = Gate::for_level(AutonomyLevel::Standard);
        gate.check(&Action::Read, Some(&writer)).await.unwrap();

        drop(writer);
        join.await.unwrap();

        let bytes = read(&seg).await.unwrap();
        let f = decode_frame(&bytes[SEGMENT_HEADER_LEN..]).unwrap();
        assert_eq!(f.header.event_type, EVENT_TYPE_PERMISSION_GRANTED);
        let trust = decode_frame(&bytes[SEGMENT_HEADER_LEN + f.header.total_len as usize..])
            .expect("typed TrustDecision frame follows compatibility frame");
        assert_eq!(
            trust.header.event_type,
            crate::wal::events::EVENT_TYPE_EXTENDED
        );
        assert_eq!(
            trust.header.event_subtype,
            crate::wal::events::ExtendedSubtype::TrustDecision as u8
        );
        let trust_payload: serde_json::Value = serde_json::from_slice(trust.payload).unwrap();
        assert_eq!(trust_payload["action"], "read");
        assert_eq!(trust_payload["subject"], "local");
        assert!(trust_payload.get("reason_sha256").unwrap().is_null());
    }

    #[tokio::test]
    async fn required_gate_audit_replays_as_a_subject_scoped_trust_event() {
        let home = tempdir().unwrap();
        let wal_dir = home.path().join("wal");
        std::fs::create_dir_all(&wal_dir).unwrap();
        let (writer, join) =
            spawn_for_home(wal_dir.join("000001.wal"), home.path().to_path_buf()).unwrap();

        Gate::for_level(AutonomyLevel::Full)
            .check_required_audit(&Action::ExecArbitrary, &writer)
            .await
            .unwrap();

        let live_ledger = crate::permissions::TrustLedger::replay_subject_at_home(
            home.path(),
            crate::permissions::trust_ledger::LOCAL_SUBJECT,
        )
        .expect("the required Gate decision is marker-authenticated before allow returns");
        assert!(matches!(
            live_ledger.completeness,
            crate::permissions::TrustLedgerCompleteness::Complete
        ));
        assert_eq!(live_ledger.entries.len(), 1);
        drop(writer);
        join.await.unwrap();

        let ledger = crate::permissions::TrustLedger::replay_subject_at_home(home.path(), "local")
            .expect("canonical home WAL replays its typed Gate decision");
        assert_eq!(ledger.entries.len(), 1);
        assert_eq!(
            ledger.entries[0].event.action,
            crate::permissions::ActionKind::ExecArbitrary
        );
        assert_eq!(
            ledger.entries[0].event.outcome,
            crate::permissions::TrustOutcome::Allowed
        );
    }

    #[tokio::test]
    async fn required_gate_audit_fails_closed_when_typed_evidence_is_invalid() {
        let dir = tempdir().unwrap();
        let segment = dir.path().join("invalid-typed-evidence.wal");
        let (writer, join) = wal_spawn(segment.clone()).unwrap();
        let action = Action::PaidProviderCall {
            provider: "test-provider".into(),
            model: "test-model".into(),
            authorization_id: "a".repeat(64),
            request_binding_sha256: "not-a-canonical-sha256".into(),
            eur_estimate: 0.1,
        };

        let error = Gate::for_level(AutonomyLevel::Full)
            .check_required_audit(&action, &writer)
            .await
            .expect_err("an invalid typed receipt must block the external action");
        assert!(matches!(error, GateError::Unavailable(_)));
        drop(writer);
        join.await.unwrap();
        assert!(
            !segment.exists() || std::fs::read(segment).unwrap().len() <= SEGMENT_HEADER_LEN,
            "typed validation occurs before the legacy compatibility frame is appended"
        );
    }

    #[tokio::test]
    async fn bound_exec_audit_carries_the_exact_request_binding() {
        let home = tempdir().unwrap();
        let wal = home.path().join("wal");
        std::fs::create_dir_all(&wal).unwrap();
        let seg = wal.join("bound-exec-000001.wal");
        let (writer, join) = spawn_for_home(seg.clone(), home.path().to_path_buf()).unwrap();
        let binding = "ab".repeat(32);

        Gate::for_level(AutonomyLevel::Full)
            .with_preconfirmed_confirmation("gui_request_bound_token")
            .check_with_audit_sink(
                &Action::ExecArbitrary,
                PermissionAuditSink::Writer(&writer),
                true,
                Some(&binding),
            )
            .await
            .unwrap();

        drop(writer);
        join.await.unwrap();
        let bytes = read(&seg).await.unwrap();
        let frame = decode_frame(&bytes[SEGMENT_HEADER_LEN..]).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(frame.payload).unwrap();
        assert_eq!(frame.header.event_type, EVENT_TYPE_PERMISSION_GRANTED);
        assert_eq!(payload["action"], "ExecArbitrary");
        assert_eq!(payload["request_binding_sha256"], binding);
        assert_eq!(payload["confirmation_source"], "gui_request_bound_token");
    }

    #[tokio::test]
    async fn explicit_request_confirmation_is_audited_and_cannot_override_deny() {
        let home = tempdir().unwrap();
        let wal = home.path().join("wal");
        std::fs::create_dir_all(&wal).unwrap();
        let seg = wal.join("explicit-request-000001.wal");
        let (writer, join) = spawn_for_home(seg.clone(), home.path().to_path_buf()).unwrap();

        let gate = Gate::for_level(AutonomyLevel::Strict)
            .with_confirm(ConfirmStrategy::FailClosed)
            .with_preconfirmed_confirmation("explicit_request_capability");
        gate.check_required_audit(&paid_action(0.10), &writer)
            .await
            .unwrap();
        let denied = Gate::for_level(AutonomyLevel::Standard)
            .with_preconfirmed_confirmation("explicit_request_capability")
            .check(
                &Action::SelfSourceEdit {
                    target_paths: vec!["src/lib.rs".to_owned()],
                },
                None,
            )
            .await;
        assert!(matches!(denied, Err(GateError::Denied(_))));

        drop(writer);
        join.await.unwrap();
        let bytes = read(&seg).await.unwrap();
        let frame = decode_frame(&bytes[SEGMENT_HEADER_LEN..]).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(frame.payload).unwrap();
        assert_eq!(frame.header.event_type, EVENT_TYPE_PERMISSION_GRANTED);
        assert_eq!(
            payload["confirmation_source"],
            "explicit_request_capability"
        );
    }

    #[tokio::test]
    async fn required_audit_failure_blocks_an_otherwise_allowed_paid_call() {
        let dir = tempdir().unwrap();
        let seg = dir.path().join("required-audit.wal");
        let (writer, join) = wal_spawn(seg).unwrap();
        let writer = writer.with_quota_guard(Arc::new(crate::wal::writer::QuotaGuard::new(
            dir.path().to_path_buf(),
            0,
        )));
        let gate = Gate::for_level(AutonomyLevel::Full);
        let action = paid_action(0.10);

        assert!(
            gate.check(&action, Some(&writer)).await.is_ok(),
            "the legacy generic gate keeps its documented best-effort audit semantics"
        );
        let error = gate
            .check_required_audit(&action, &writer)
            .await
            .expect_err("paid-call grant without a durable audit must fail closed");
        assert!(
            matches!(&error, GateError::Unavailable(reason) if reason.contains("required permission audit WAL append failed")),
            "unexpected error: {error:?}"
        );

        drop(writer);
        join.await.unwrap();
    }

    #[tokio::test]
    async fn paid_call_permission_frame_carries_request_binding_fields() {
        let home = tempdir().unwrap();
        let wal = home.path().join("wal");
        std::fs::create_dir_all(&wal).unwrap();
        let seg = wal.join("bound-paid-call-000001.wal");
        let (writer, join) = spawn_for_home(seg.clone(), home.path().to_path_buf()).unwrap();
        let action = paid_action(0.10);

        Gate::for_level(AutonomyLevel::Full)
            .check_required_audit(&action, &writer)
            .await
            .unwrap();
        drop(writer);
        join.await.unwrap();

        let bytes = read(&seg).await.unwrap();
        let frame = decode_frame(&bytes[SEGMENT_HEADER_LEN..]).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(frame.payload).unwrap();
        assert_eq!(payload["authorization_id"], "a".repeat(64));
        assert_eq!(payload["request_binding_sha256"], "b".repeat(64));
        let action_debug = payload["action"].as_str().unwrap();
        assert!(action_debug.contains(&"a".repeat(64)));
        assert!(action_debug.contains(&"b".repeat(64)));
    }

    #[tokio::test]
    async fn audit_emits_denied_frame_when_deny() {
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (writer, join) = wal_spawn(seg.clone()).unwrap();

        let gate = Gate::for_level(AutonomyLevel::Standard);
        let _ = gate
            .check(
                &Action::DangerousTarget("home-server".into()),
                Some(&writer),
            )
            .await;

        drop(writer);
        join.await.unwrap();

        let bytes = read(&seg).await.unwrap();
        let f = decode_frame(&bytes[SEGMENT_HEADER_LEN..]).unwrap();
        assert_eq!(f.header.event_type, EVENT_TYPE_PERMISSION_DENIED);
    }

    // ── Pick #10 follow-up (Session 14 Pick #21) — autonomy-gate
    //    integration tests covering the three scenarios that were
    //    deferred when Pick #10 shipped the cost::predict + ChannelSend
    //    gate wires in serve.rs. End-to-end shape: build the Action
    //    exactly the way `serve.rs` does, run it through `Gate::check`
    //    with `FailClosed` (daemon mode), assert the WAL audit frame.

    #[tokio::test]
    async fn standard_expensive_paid_call_under_failclosed_denies() {
        // Pick #10 scenario 1: Standard autonomy + a paid provider call
        // that crosses the €0.50 ceiling MUST deny under daemon-mode
        // FailClosed (no TTY to confirm). This is the exact case the
        // pre-fix `eur_estimate: 0.0` hardcode silently bypassed —
        // without this test, a regression to the old behaviour would
        // ship undetected.
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (writer, join) = wal_spawn(seg.clone()).unwrap();

        let gate =
            Gate::for_level(AutonomyLevel::Standard).with_confirm(ConfirmStrategy::FailClosed);
        let action = paid_action(1.25); // > €0.50 ceiling → triggers Confirm
        let r = gate.check(&action, Some(&writer)).await;
        assert!(
            matches!(r, Err(GateError::Denied(_))),
            "expected Denied via FailClosed; got {r:?}"
        );

        drop(writer);
        join.await.unwrap();
        let bytes = read(&seg).await.unwrap();
        let f = decode_frame(&bytes[SEGMENT_HEADER_LEN..]).unwrap();
        assert_eq!(
            f.header.event_type, EVENT_TYPE_PERMISSION_DENIED,
            "audit frame must record the denial"
        );
    }

    #[tokio::test]
    async fn standard_cheap_paid_call_allows() {
        // Counterpart to the expensive case: a paid call BELOW the
        // €0.50 ceiling must Allow. Catches an over-correction where
        // a bad refactor accidentally denies every paid call.
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (writer, join) = wal_spawn(seg.clone()).unwrap();

        let gate =
            Gate::for_level(AutonomyLevel::Standard).with_confirm(ConfirmStrategy::FailClosed);
        let action = paid_action(0.10);
        let r = gate.check(&action, Some(&writer)).await;
        assert!(
            r.is_ok(),
            "cheap paid call at €0.10 must Allow under Standard; got {r:?}"
        );

        drop(writer);
        join.await.unwrap();
        let bytes = read(&seg).await.unwrap();
        let f = decode_frame(&bytes[SEGMENT_HEADER_LEN..]).unwrap();
        assert_eq!(f.header.event_type, EVENT_TYPE_PERMISSION_GRANTED);
    }

    #[tokio::test]
    async fn strict_channel_send_under_failclosed_denies() {
        // Pick #10 scenario 2: Strict autonomy treats every
        // `ChannelSend` as Confirm. Daemon-mode FailClosed turns that
        // into Deny. Without the Pick #10 gate-wiring at serve.rs
        // line 1745, channel messages would silently send under
        // Strict — the security-mode-of-record for paranoid operators.
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (writer, join) = wal_spawn(seg.clone()).unwrap();

        let gate = Gate::for_level(AutonomyLevel::Strict).with_confirm(ConfirmStrategy::FailClosed);
        let r = gate.check(&Action::ChannelSend, Some(&writer)).await;
        assert!(
            matches!(r, Err(GateError::Denied(_))),
            "ChannelSend on Strict must Deny under FailClosed; got {r:?}"
        );

        drop(writer);
        join.await.unwrap();
        let bytes = read(&seg).await.unwrap();
        let f = decode_frame(&bytes[SEGMENT_HEADER_LEN..]).unwrap();
        assert_eq!(f.header.event_type, EVENT_TYPE_PERMISSION_DENIED);
    }

    #[tokio::test]
    async fn standard_channel_send_allows_silently() {
        // Standard treats ChannelSend as Allow (operator opted into
        // channels by configuring them in freedom.yaml). This pins
        // the contrast with Strict — same Action, different verdict
        // by autonomy level.
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (writer, join) = wal_spawn(seg.clone()).unwrap();

        let gate =
            Gate::for_level(AutonomyLevel::Standard).with_confirm(ConfirmStrategy::FailClosed);
        let r = gate.check(&Action::ChannelSend, Some(&writer)).await;
        assert!(r.is_ok(), "ChannelSend on Standard must Allow; got {r:?}");

        drop(writer);
        join.await.unwrap();
        let bytes = read(&seg).await.unwrap();
        let f = decode_frame(&bytes[SEGMENT_HEADER_LEN..]).unwrap();
        assert_eq!(f.header.event_type, EVENT_TYPE_PERMISSION_GRANTED);
    }

    #[tokio::test]
    async fn full_level_allows_paid_call_channel_send_and_exec() {
        // Pick #10 scenario 3: Full autonomy allows every non-Dangerous
        // action without Confirm — even a 10-euro provider call. Pins
        // the upper bound of the lattice: Full must not accidentally
        // grow a hidden Confirm branch.
        let home = tempdir().unwrap();
        let wal_dir = home.path().join("wal");
        std::fs::create_dir_all(&wal_dir).unwrap();
        let seg = wal_dir.join("000001.wal");
        let (writer, join) = spawn_for_home(seg.clone(), home.path().to_path_buf()).unwrap();

        let gate = Gate::for_level(AutonomyLevel::Full).with_confirm(ConfirmStrategy::FailClosed);
        for action in [
            paid_action(10.0),
            Action::ChannelSend,
            Action::WriteOutsideHome,
            Action::ExecArbitrary,
            Action::McpToolInvocation {
                server_id: "filesystem".into(),
                tool: "read".into(),
            },
        ] {
            let r = gate.check(&action, Some(&writer)).await;
            assert!(r.is_ok(), "Full must Allow {action:?}; got {r:?}",);
        }

        drop(writer);
        join.await.unwrap();
        // Five Allow checks preserve five legacy frames and add five typed
        // TrustDecision frames. A compaction marker is bookkeeping only.
        let bytes = read(&seg).await.unwrap();
        let mut cursor = SEGMENT_HEADER_LEN;
        let mut granted_count = 0;
        let mut trust_count = 0;
        while cursor < bytes.len() {
            let f = decode_frame(&bytes[cursor..]).expect("frame parse");
            cursor += f.header.total_len as usize;
            // TESTDEBT-WAL-01: a home-bound writer appends its own `0x15`
            // compaction marker on drain. That is WAL bookkeeping, not a
            // permission decision — skip it rather than let it masquerade as
            // an unexpected verdict.
            if f.header.event_type == crate::wal::events::EVENT_TYPE_COMPACTION_MARKER {
                continue;
            }
            if f.header.event_type == EVENT_TYPE_PERMISSION_GRANTED {
                granted_count += 1;
            } else {
                assert_eq!(f.header.event_type, crate::wal::events::EVENT_TYPE_EXTENDED);
                assert_eq!(
                    f.header.event_subtype,
                    crate::wal::events::ExtendedSubtype::TrustDecision as u8
                );
                trust_count += 1;
            }
        }
        assert_eq!(
            granted_count, 5,
            "expected exactly 5 GRANTED frames; got {granted_count}"
        );
        assert_eq!(
            trust_count, 5,
            "expected exactly 5 typed TrustDecision frames; got {trust_count}"
        );
    }

    #[tokio::test]
    async fn full_level_still_confirms_dangerous_target() {
        // Pick #10 scenario 3 inverse: Full does NOT bypass
        // DangerousTarget. The dangerous_targets list is the absolute
        // floor — operator cannot opt out of the confirm prompt by
        // setting autonomy=full. Under FailClosed this still Denies.
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (writer, join) = wal_spawn(seg.clone()).unwrap();

        let gate = Gate::for_level(AutonomyLevel::Full).with_confirm(ConfirmStrategy::FailClosed);
        let r = gate
            .check(&Action::DangerousTarget("192.0.2.1".into()), Some(&writer))
            .await;
        assert!(
            matches!(r, Err(GateError::Denied(_))),
            "Full must still gate DangerousTarget; got {r:?}"
        );

        drop(writer);
        join.await.unwrap();
        let bytes = read(&seg).await.unwrap();
        let f = decode_frame(&bytes[SEGMENT_HEADER_LEN..]).unwrap();
        assert_eq!(f.header.event_type, EVENT_TYPE_PERMISSION_DENIED);
    }

    #[tokio::test]
    async fn cost_predict_feeds_eur_estimate_for_paid_call() {
        // Pick #10 cost-integration spine: the daemon path constructs
        // request-bound `Action::PaidProviderCall { .. }`
        // from `providers::cost::predict()`. This test verifies the
        // wire — a non-trivial prompt against a paid provider produces
        // a non-zero estimate, and that estimate flows through the gate
        // intact (Standard threshold at €0.50 is in scope).
        use crate::providers::cost::predict as predict_cost;
        use crate::providers::meter::Meter;

        let meter = Meter::with_default_window();
        // Use a realistic prompt size — small enough to land below
        // the €0.50 Standard threshold for a typical operator query.
        let prompt = "Summarise the operator's last 24h of activity in two sentences.";
        let cost = predict_cost("openai_api", "gpt-5.5", prompt, &meter);
        assert!(
            cost.total_eur >= 0.0,
            "cost predict must produce non-negative estimate; got {}",
            cost.total_eur
        );

        let action = paid_action(cost.total_eur);
        let gate =
            Gate::for_level(AutonomyLevel::Standard).with_confirm(ConfirmStrategy::FailClosed);
        let r = gate.check(&action, None).await;
        if cost.total_eur > 0.50 {
            assert!(
                matches!(r, Err(GateError::Denied(_))),
                "estimate {} > €0.50 must Deny under Standard FailClosed; got {:?}",
                cost.total_eur,
                r
            );
        } else {
            assert!(
                r.is_ok(),
                "estimate {} ≤ €0.50 must Allow under Standard; got {:?}",
                cost.total_eur,
                r
            );
        }
    }

    // ── SL-01a-b: capability-lease → gate integration ────────────────────
    //
    // The panel's core rule: a covering lease upgrades Confirm → Allow and
    // ONLY Confirm. Deny is the operator's hard floor and is never
    // overridable. Wrong-subject / expired / uncoverable all fail closed.

    use crate::permissions::lease::{CapabilityLease, LeaseScope, LeaseStore};

    const LT0: i64 = 1_700_000_000;

    fn store_with(subject: &str, scope: LeaseScope, ttl: i64, granted_at: i64) -> LeaseStore {
        let mut s = LeaseStore::default();
        s.grant(CapabilityLease::new(subject, scope, ttl, granted_at));
        s
    }

    #[tokio::test]
    async fn lease_upgrades_confirm_to_allow() {
        // Strict + WriteNeothHome = Confirm. Under FailClosed that is Deny…
        let base = Gate::for_level(AutonomyLevel::Strict).with_confirm(ConfirmStrategy::FailClosed);
        assert!(
            matches!(
                base.check(&Action::WriteNeothHome, None).await,
                Err(GateError::Denied(_))
            ),
            "no lease ⇒ FailClosed Deny"
        );
        // …but a covering lease for the subject upgrades it to Allow without
        // any confirm round-trip.
        let store = store_with("peerA", LeaseScope::WriteNeothHome, 3600, LT0);
        let leased = Gate::for_level(AutonomyLevel::Strict)
            .with_confirm(ConfirmStrategy::FailClosed)
            .with_lease_snapshot(&store, "peerA", LT0 + 10);
        assert!(
            leased
                .check_at(&Action::WriteNeothHome, None, LT0 + 10)
                .await
                .is_ok(),
            "covering lease must upgrade Confirm → Allow"
        );
    }

    #[tokio::test]
    async fn lease_never_overrides_deny() {
        // Strict + ProactiveChannelSend = Deny (the operator's hard floor).
        // Even with a ChannelSend lease present for the subject, Deny is
        // final — and ProactiveChannelSend maps to no scope anyway.
        let store = store_with("peerA", LeaseScope::ChannelSend, 3600, LT0);
        let gate = Gate::for_level(AutonomyLevel::Strict)
            .with_confirm(ConfirmStrategy::FailClosed)
            .with_lease_snapshot(&store, "peerA", LT0 + 10);
        let r = gate
            .check_at(
                &Action::ProactiveChannelSend {
                    channel: "telegram".into(),
                },
                None,
                LT0 + 10,
            )
            .await;
        assert!(
            matches!(r, Err(GateError::Denied(_))),
            "a lease must NEVER rescue a Deny; got {r:?}"
        );
    }

    #[tokio::test]
    async fn lease_wrong_subject_fails_closed() {
        // Lease granted to peerA; the gate is deciding for peerB.
        let store = store_with("peerA", LeaseScope::WriteNeothHome, 3600, LT0);
        let gate = Gate::for_level(AutonomyLevel::Strict)
            .with_confirm(ConfirmStrategy::FailClosed)
            .with_lease_snapshot(&store, "peerB", LT0 + 10);
        assert!(
            matches!(
                gate.check_at(&Action::WriteNeothHome, None, LT0 + 10).await,
                Err(GateError::Denied(_))
            ),
            "a lease for a different subject must not authorise peerB"
        );
    }

    #[tokio::test]
    async fn channel_account_lease_subject_isolated_across_accounts_and_legacy_sender() {
        use crate::channels::ChannelKind;
        use crate::channels::registry::{ChannelAccountId, ChannelRef};
        use crate::permissions::lease::channel_lease_subject;

        let account_a = ChannelRef::new(
            ChannelKind::Telegram,
            ChannelAccountId::new("account-a").unwrap(),
        );
        let account_b = ChannelRef::new(
            ChannelKind::Telegram,
            ChannelAccountId::new("account-b").unwrap(),
        );
        let alice_a = channel_lease_subject(&account_a, "alice");
        let alice_b = channel_lease_subject(&account_b, "alice");
        let channel_send = Action::ChannelSend;
        let mcp_tool = Action::McpToolInvocation {
            server_id: "server".into(),
            tool: "tool".into(),
        };

        let mut scoped_store = LeaseStore::default();
        scoped_store.grant(CapabilityLease::new(
            alice_a.clone(),
            LeaseScope::ChannelSend,
            3600,
            LT0,
        ));
        scoped_store.grant(CapabilityLease::new(
            alice_a.clone(),
            LeaseScope::McpTool("server:tool".into()),
            3600,
            LT0,
        ));
        let gate_for_a = Gate::for_level(AutonomyLevel::Strict)
            .with_confirm(ConfirmStrategy::FailClosed)
            .with_lease_snapshot(&scoped_store, alice_a, LT0 + 10);
        assert!(
            gate_for_a
                .check_at(&channel_send, None, LT0 + 10)
                .await
                .is_ok()
        );
        assert!(gate_for_a.check_at(&mcp_tool, None, LT0 + 10).await.is_ok());

        let gate_for_b = Gate::for_level(AutonomyLevel::Strict)
            .with_confirm(ConfirmStrategy::FailClosed)
            .with_lease_snapshot(&scoped_store, alice_b.clone(), LT0 + 10);
        assert!(matches!(
            gate_for_b.check_at(&channel_send, None, LT0 + 10).await,
            Err(GateError::Denied(_))
        ));
        assert!(matches!(
            gate_for_b.check_at(&mcp_tool, None, LT0 + 10).await,
            Err(GateError::Denied(_))
        ));

        let mut legacy_store = LeaseStore::default();
        legacy_store.grant(CapabilityLease::new(
            "alice",
            LeaseScope::ChannelSend,
            3600,
            LT0,
        ));
        legacy_store.grant(CapabilityLease::new(
            "alice",
            LeaseScope::McpTool("server:tool".into()),
            3600,
            LT0,
        ));
        for subject in [channel_lease_subject(&account_a, "alice"), alice_b] {
            let gate = Gate::for_level(AutonomyLevel::Strict)
                .with_confirm(ConfirmStrategy::FailClosed)
                .with_lease_snapshot(&legacy_store, subject, LT0 + 10);
            assert!(matches!(
                gate.check_at(&channel_send, None, LT0 + 10).await,
                Err(GateError::Denied(_))
            ));
            assert!(matches!(
                gate.check_at(&mcp_tool, None, LT0 + 10).await,
                Err(GateError::Denied(_))
            ));
        }
    }

    #[tokio::test]
    async fn expired_lease_fails_closed() {
        // Lease granted at LT0-7200 with 3600s TTL ⇒ expired at LT0-3600.
        // Snapshot taken at LT0 must exclude it (active() filters expired).
        let store = store_with("peerA", LeaseScope::WriteNeothHome, 3600, LT0 - 7200);
        let gate = Gate::for_level(AutonomyLevel::Strict)
            .with_confirm(ConfirmStrategy::FailClosed)
            .with_lease_snapshot(&store, "peerA", LT0);
        assert!(
            matches!(
                gate.check_at(&Action::WriteNeothHome, None, LT0).await,
                Err(GateError::Denied(_))
            ),
            "an expired lease must never upgrade a decision"
        );
    }

    #[tokio::test]
    async fn post_snapshot_expiry_denied_at_decision_time() {
        // The frozen-clock regression (review HIGH): a lease that is active
        // at SNAPSHOT time but expires before the DECISION must be denied —
        // the gate re-checks expiry against the fresh decision clock, not
        // the snapshot clock. Lease expires at LT0+100; snapshot at LT0+10
        // (in the candidate set); decision at LT0+200 (past expiry).
        let store = store_with("peerA", LeaseScope::WriteNeothHome, 100, LT0);
        let gate = Gate::for_level(AutonomyLevel::Strict)
            .with_confirm(ConfirmStrategy::FailClosed)
            .with_lease_snapshot(&store, "peerA", LT0 + 10);
        // Sanity: at a decision time still inside the TTL it WOULD upgrade.
        assert!(
            gate.check_at(&Action::WriteNeothHome, None, LT0 + 50)
                .await
                .is_ok(),
            "still-live lease upgrades"
        );
        // …but past expiry the same snapshot must fail closed.
        assert!(
            matches!(
                gate.check_at(&Action::WriteNeothHome, None, LT0 + 200)
                    .await,
                Err(GateError::Denied(_))
            ),
            "a lease that lapsed after the snapshot must be denied at decision time"
        );
    }

    #[tokio::test]
    async fn uncoverable_action_ignores_lease() {
        // WriteOutsideHome is Confirm at Standard but maps to no LeaseScope.
        // Even a (mismatched) lease present must not upgrade it.
        let store = store_with("peerA", LeaseScope::WriteNeothHome, 3600, LT0);
        let gate = Gate::for_level(AutonomyLevel::Standard)
            .with_confirm(ConfirmStrategy::FailClosed)
            .with_lease_snapshot(&store, "peerA", LT0 + 10);
        assert!(
            matches!(
                gate.check_at(&Action::WriteOutsideHome, None, LT0 + 10)
                    .await,
                Err(GateError::Denied(_))
            ),
            "unleasable action must fall through to the normal confirm path"
        );
    }

    #[tokio::test]
    async fn audit_frame_records_lease_id_and_subject_on_upgrade() {
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (writer, join) = wal_spawn(seg.clone()).unwrap();

        let store = store_with("peerA", LeaseScope::WriteNeothHome, 3600, LT0);
        let lease_id = store.leases[0].lease_id.clone();
        let gate = Gate::for_level(AutonomyLevel::Strict)
            .with_confirm(ConfirmStrategy::FailClosed)
            .with_lease_snapshot(&store, "peerA", LT0 + 10);
        gate.check_at(&Action::WriteNeothHome, Some(&writer), LT0 + 10)
            .await
            .unwrap();

        drop(writer);
        join.await.unwrap();

        let bytes = read(&seg).await.unwrap();
        let f = decode_frame(&bytes[SEGMENT_HEADER_LEN..]).unwrap();
        assert_eq!(
            f.header.event_type, EVENT_TYPE_PERMISSION_GRANTED,
            "lease upgrade is a GRANTED frame"
        );
        let v: serde_json::Value = serde_json::from_slice(f.payload).unwrap();
        assert_eq!(
            v["lease_id"], lease_id,
            "the WAL must record WHICH lease authorised the grant"
        );
        assert_eq!(v["subject"], "peerA");
    }

    #[tokio::test]
    async fn audit_frame_has_null_lease_id_without_lease() {
        // Regression: a plain Allow (no lease) carries lease_id: null —
        // operators filter `lease_id != null` to find lease-driven grants.
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (writer, join) = wal_spawn(seg.clone()).unwrap();

        let gate = Gate::for_level(AutonomyLevel::Standard);
        gate.check(&Action::Read, Some(&writer)).await.unwrap();

        drop(writer);
        join.await.unwrap();

        let bytes = read(&seg).await.unwrap();
        let f = decode_frame(&bytes[SEGMENT_HEADER_LEN..]).unwrap();
        let v: serde_json::Value = serde_json::from_slice(f.payload).unwrap();
        assert!(v["lease_id"].is_null(), "no lease ⇒ lease_id null");
    }

    fn durable_digest(byte: char) -> String {
        std::iter::repeat_n(byte, 64).collect()
    }

    #[tokio::test]
    async fn durable_resolution_returns_typed_allow_and_denied_descriptors_without_audit() {
        let allowed = Gate::for_level(AutonomyLevel::Full)
            .resolve_trust_admission(
                &Action::ChannelSend,
                &durable_digest('a'),
                &durable_digest('b'),
            )
            .await
            .unwrap();
        assert_eq!(allowed.outcome(), crate::permissions::TrustOutcome::Allowed);
        assert_eq!(allowed.operation_id_sha256(), durable_digest('a'));
        assert_eq!(allowed.request_binding_sha256(), durable_digest('b'));
        assert_eq!(
            allowed.subject(),
            crate::permissions::trust_ledger::LOCAL_SUBJECT
        );

        let denied = Gate::for_level(AutonomyLevel::Strict)
            .with_confirm(ConfirmStrategy::FailClosed)
            .resolve_trust_admission(
                &Action::ChannelSend,
                &durable_digest('c'),
                &durable_digest('d'),
            )
            .await
            .unwrap();
        assert_eq!(denied.outcome(), crate::permissions::TrustOutcome::Denied);
        assert_ne!(
            allowed.policy_snapshot_sha256(),
            denied.policy_snapshot_sha256(),
            "the durable receipt binds the exact snapshot that resolved it"
        );
    }

    #[tokio::test]
    async fn durable_resolution_refuses_ephemeral_channel_confirmation() {
        let descriptor = Gate::for_level(AutonomyLevel::Standard)
            .with_confirm(ConfirmStrategy::Channel)
            .resolve_trust_admission(
                &Action::ExecArbitrary,
                &durable_digest('e'),
                &durable_digest('f'),
            )
            .await
            .unwrap();
        assert_eq!(
            descriptor.outcome(),
            crate::permissions::TrustOutcome::Denied,
            "a live ConfirmBus answer is not durable authority"
        );
        assert!(descriptor.reason_sha256().is_some());

        let ordinary_preconfirmation = Gate::for_level(AutonomyLevel::Standard)
            .with_confirm(ConfirmStrategy::FailClosed)
            .with_preconfirmed_confirmation("ordinary_cli_yes")
            .resolve_trust_admission(
                &Action::ExecArbitrary,
                &durable_digest('0'),
                &durable_digest('1'),
            )
            .await
            .unwrap();
        assert_eq!(
            ordinary_preconfirmation.outcome(),
            crate::permissions::TrustOutcome::Denied,
            "a generic preconfirmation label is not a durable recovery capability"
        );
    }
}
