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
}

impl Gate {
    pub fn for_policy(policy: AutonomyPolicySnapshot) -> Self {
        Self {
            policy,
            confirm: ConfirmStrategy::FailClosed,
            channel_asker: None,
            channel_timeout: Duration::from_secs(90),
            lease_ctx: None,
        }
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
    /// Emits a single WAL audit frame (PERMISSION_GRANTED or PERMISSION_DENIED)
    /// when `writer` is `Some`.
    ///
    /// Returns `Ok(())` on Allow, `Err(GateError::*)` otherwise.
    pub async fn check(
        &self,
        action: &Action,
        writer: Option<&WalWriterHandle>,
    ) -> Result<(), GateError> {
        self.check_at_with_audit(action, writer, Self::now_unix(), false)
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
        self.check_at_with_audit(action, Some(writer), Self::now_unix(), true)
            .await
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
    pub(crate) async fn check_at(
        &self,
        action: &Action,
        writer: Option<&WalWriterHandle>,
        now_unix: i64,
    ) -> Result<(), GateError> {
        self.check_at_with_audit(action, writer, now_unix, false)
            .await
    }

    async fn check_at_with_audit(
        &self,
        action: &Action,
        writer: Option<&WalWriterHandle>,
        now_unix: i64,
        audit_required: bool,
    ) -> Result<(), GateError> {
        let decision = evaluate(action, &self.policy);
        // SL-01a-b: a covering capability lease upgrades `Confirm → Allow`,
        // and ONLY `Confirm`. `Deny` is the operator's hard floor at this
        // autonomy level — it is final and a lease can NEVER override it
        // (so `Strict` stays `Strict`). `Allow` already needs no lease. The
        // lease is therefore consulted on the `Confirm` branch alone,
        // BEFORE the (TTY / channel / fail-closed) confirm round-trip. When
        // a lease wins, its id is threaded into the audit frame so `neoth
        // wal show --type permission_granted` records WHY the action was
        // allowed — the verifiable-loyalty grant chain.
        let (final_decision, lease_id) = match decision {
            Decision::Allow => (Decision::Allow, None),
            Decision::Deny(reason) => (Decision::Deny(reason), None),
            Decision::Confirm(reason) => match self
                .lease_ctx
                .as_ref()
                .and_then(|ctx| ctx.covering_lease_id(action, now_unix))
            {
                Some(id) => (Decision::Allow, Some(id)),
                None => (self.resolve_confirm(action, &reason).await, None),
            },
        };

        if let Some(w) = writer {
            let subject = self.lease_ctx.as_ref().map(|c| c.subject.as_str());
            let audit_result = audit(
                w,
                action,
                self.policy.level(),
                &final_decision,
                subject,
                lease_id.as_deref(),
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
        }

        match final_decision {
            Decision::Allow => Ok(()),
            Decision::Deny(r) => Err(GateError::Denied(r)),
            // `Confirm` is never returned by resolve_confirm — it produces
            // Allow or Deny only. Treat as Aborted defensively.
            Decision::Confirm(r) => Err(GateError::Aborted(r)),
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
}

/// Append a single permission-decision frame to the WAL.
///
/// `subject` and `lease_id` are SL-01a-b additions (both `None` for call
/// sites that pass no lease context). When a capability lease upgraded a
/// `Confirm` to `Allow`, `lease_id` names the grant that authorised it so
/// the operator can cross-reference `0xA5 LEASE_GRANTED` and prove the
/// chain: "subject S was allowed action A at T because of lease L". No new
/// event code is allocated — the existing `0xA0 PERMISSION_GRANTED` /
/// `0xA1 PERMISSION_DENIED` payload is enriched (single frame per decision,
/// inherits immediate-sync, no SC-01a band churn).
async fn audit(
    writer: &WalWriterHandle,
    action: &Action,
    level: AutonomyLevel,
    decision: &Decision,
    subject: Option<&str>,
    lease_id: Option<&str>,
) -> Result<()> {
    let (event_type, reason): (u8, Option<&str>) = match decision {
        Decision::Allow => (EVENT_TYPE_PERMISSION_GRANTED, None),
        Decision::Deny(r) => (EVENT_TYPE_PERMISSION_DENIED, Some(r.as_str())),
        Decision::Confirm(r) => (EVENT_TYPE_PERMISSION_DENIED, Some(r.as_str())),
    };
    let (authorization_id, request_binding_sha256) = match action {
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
    let payload = serde_json::to_vec(&serde_json::json!({
        "level": level.as_str(),
        "action": format!("{action:?}"),
        "authorization_id": authorization_id,
        "request_binding_sha256": request_binding_sha256,
        "decision": decision.tag(),
        "reason": reason,
        "subject": subject,
        "lease_id": lease_id,
        "ts_ns": crate::time::now_unix_ns(),
    }))?;
    let header = crate::wal::HeaderBuilder::new(event_type, &payload)
        .flags(crate::wal::EventFlags::SYNTHETIC)
        .build();
    writer.append(header, payload).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wal::events::{EVENT_TYPE_PERMISSION_DENIED, EVENT_TYPE_PERMISSION_GRANTED};
    use crate::wal::frame::decode_frame;
    use crate::wal::segment_header::SEGMENT_HEADER_LEN;
    use crate::wal::spawn as wal_spawn;
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
        assert!(r.is_ok(), "Read on Standard must Allow, got {:?}", r);
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
        assert!(matches!(r, Err(GateError::Denied(_))), "got {:?}", r);
    }

    #[tokio::test]
    async fn confirm_under_failclosed_denies() {
        // Standard + WriteOutsideHome → Confirm; with FailClosed strategy
        // that becomes Deny (no operator to ask).
        let gate =
            Gate::for_level(AutonomyLevel::Standard).with_confirm(ConfirmStrategy::FailClosed);
        let r = gate.check(&Action::WriteOutsideHome, None).await;
        assert!(matches!(r, Err(GateError::Denied(_))), "got {:?}", r);
    }

    #[tokio::test]
    async fn confirm_under_always_allow_passes() {
        // Test-only strategy: every Confirm collapses to Allow. Lets us
        // exercise the gate plumbing without a TTY.
        let gate =
            Gate::for_level(AutonomyLevel::Standard).with_confirm(ConfirmStrategy::AlwaysAllow);
        let r = gate.check(&Action::WriteOutsideHome, None).await;
        assert!(r.is_ok(), "AlwaysAllow must succeed, got {:?}", r);
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

    #[tokio::test]
    async fn audit_emits_granted_frame_when_allow() {
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (writer, join) = wal_spawn(seg.clone()).unwrap();

        let gate = Gate::for_level(AutonomyLevel::Standard);
        gate.check(&Action::Read, Some(&writer)).await.unwrap();

        drop(writer);
        join.await.unwrap();

        let bytes = read(&seg).await.unwrap();
        let f = decode_frame(&bytes[SEGMENT_HEADER_LEN..]).unwrap();
        assert_eq!(f.header.event_type, EVENT_TYPE_PERMISSION_GRANTED);
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
        let dir = tempdir().unwrap();
        let seg = dir.path().join("bound-paid-call.wal");
        let (writer, join) = wal_spawn(seg.clone()).unwrap();
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
            "expected Denied via FailClosed; got {:?}",
            r
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
            "cheap paid call at €0.10 must Allow under Standard; got {:?}",
            r
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
            "ChannelSend on Strict must Deny under FailClosed; got {:?}",
            r
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
        assert!(r.is_ok(), "ChannelSend on Standard must Allow; got {:?}", r);

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
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (writer, join) = wal_spawn(seg.clone()).unwrap();

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
            assert!(r.is_ok(), "Full must Allow {:?}; got {:?}", action, r,);
        }

        drop(writer);
        join.await.unwrap();
        // Five Allow checks should produce five PERMISSION_GRANTED frames.
        let bytes = read(&seg).await.unwrap();
        let mut cursor = SEGMENT_HEADER_LEN;
        let mut granted_count = 0;
        while cursor < bytes.len() {
            let f = decode_frame(&bytes[cursor..]).expect("frame parse");
            assert_eq!(f.header.event_type, EVENT_TYPE_PERMISSION_GRANTED);
            cursor += f.header.total_len as usize;
            granted_count += 1;
        }
        assert_eq!(
            granted_count, 5,
            "expected exactly 5 GRANTED frames; got {granted_count}"
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
            "Full must still gate DangerousTarget; got {:?}",
            r
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
}
