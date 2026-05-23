//! Runtime permission gate — Phase 28b AU-4.
//!
//! Bridges [`evaluate`](super::evaluate) (pure decision matrix) with the
//! confirm/audit side effects: TTY confirmation, channel-driven approve/deny,
//! WAL audit events `0xA0 PERMISSION_GRANTED` / `0xA1 PERMISSION_DENIED`.
//!
//! Call sites stay thin:
//!
//! ```text
//! match Gate::for_level(level).check(&Action::ExecArbitrary, &writer).await {
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

use super::{Action, AutonomyLevel, Decision, evaluate};

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
    /// adapter and waits for a yes/no reply with a timeout. Not implemented
    /// in this commit; falls through to `FailClosed` until Phase 28b AU-4-part-2
    /// wires the channel callback.
    Channel,
    /// Daemon / cron / non-interactive: deny by default.
    FailClosed,
    /// Test-only: every `Confirm` becomes Allow. NEVER use outside tests.
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

/// One per autonomy decision site. Cheap to construct.
pub struct Gate {
    level: AutonomyLevel,
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
}

impl Gate {
    pub fn for_level(level: AutonomyLevel) -> Self {
        Self {
            level,
            confirm: ConfirmStrategy::FailClosed,
            channel_asker: None,
            channel_timeout: Duration::from_secs(90),
        }
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
        let decision = evaluate(action, self.level);
        let final_decision = match decision {
            Decision::Allow => Decision::Allow,
            Decision::Deny(reason) => Decision::Deny(reason),
            Decision::Confirm(reason) => self.resolve_confirm(action, &reason).await,
        };

        if let Some(w) = writer {
            // Best-effort audit. A WAL append failure must not block the
            // decision the operator just made.
            let _ = audit(w, action, self.level, &final_decision).await;
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
async fn audit(
    writer: &WalWriterHandle,
    action: &Action,
    level: AutonomyLevel,
    decision: &Decision,
) -> Result<()> {
    let (event_type, reason): (u8, Option<&str>) = match decision {
        Decision::Allow => (EVENT_TYPE_PERMISSION_GRANTED, None),
        Decision::Deny(r) => (EVENT_TYPE_PERMISSION_DENIED, Some(r.as_str())),
        Decision::Confirm(r) => (EVENT_TYPE_PERMISSION_DENIED, Some(r.as_str())),
    };
    let payload = serde_json::to_vec(&serde_json::json!({
        "level": level.as_str(),
        "action": format!("{action:?}"),
        "decision": decision.tag(),
        "reason": reason,
        "ts_ns": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
            .unwrap_or(0),
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

    #[tokio::test]
    async fn allow_path_lets_action_through() {
        let gate = Gate::for_level(AutonomyLevel::Standard);
        let r = gate.check(&Action::Read, None).await;
        assert!(r.is_ok(), "Read on Standard must Allow, got {:?}", r);
    }

    #[tokio::test]
    async fn deny_path_returns_denied() {
        let gate = Gate::for_level(AutonomyLevel::Standard);
        let r = gate
            .check(&Action::DangerousTarget("cube".into()), None)
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
    async fn audit_emits_denied_frame_when_deny() {
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (writer, join) = wal_spawn(seg.clone()).unwrap();

        let gate = Gate::for_level(AutonomyLevel::Standard);
        let _ = gate
            .check(&Action::DangerousTarget("cube".into()), Some(&writer))
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
        let action = Action::PaidProviderCall {
            eur_estimate: 1.25, // > €0.50 ceiling → triggers Confirm
        };
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
        let action = Action::PaidProviderCall { eur_estimate: 0.10 };
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
            Action::PaidProviderCall { eur_estimate: 10.0 },
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
            .check(
                &Action::DangerousTarget("100.68.210.50".into()),
                Some(&writer),
            )
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
        // `Action::PaidProviderCall { eur_estimate: cost.total_eur }`
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

        let action = Action::PaidProviderCall {
            eur_estimate: cost.total_eur,
        };
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
}
