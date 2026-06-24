//! GOLD-ADAPT-GOOSE-03 — UUID-keyed operator-approval suspend/resume bus.
//!
//! Bridges the daemon's autonomous permission gate ([`Gate`](super::gate::Gate)
//! with [`ConfirmStrategy::Channel`]) to any front-end that can deliver a
//! yes/no reply from the operator: Telegram chat reply, future Slint-GUI
//! button, future HTTP endpoint, CLI `neoth channel confirm <uuid>`.
//!
//! ## Flow
//!
//! ```text
//! Gate::check  ─►  ChannelAsker::ask (BusAsker)
//!                  ├─ assigns UUID
//!                  ├─ sends ConfirmRequest onto mpsc
//!                  └─ blocks on oneshot w/ timeout
//!                       │
//! drain task (Telegram)─┤  sends elicitation to operator
//!                       │
//! inbound UUID-reply ───┤  submit_response(uuid, true/false)
//!                       │
//!              oneshot fires ──► Gate returns Ok/Err
//! ```
//!
//! ## WAL audit
//!
//! No new WAL event byte is needed. The existing `0xA0 PERMISSION_GRANTED` /
//! `0xA1 PERMISSION_DENIED` frames fire inside `Gate::check_at` AFTER
//! `resolve_confirm` returns — they already capture the terminal decision.
//! The in-flight "waiting for operator reply" state is ephemeral; the
//! `ConfirmRequest` payload carries enough context for tracing spans.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::oneshot;
use uuid::Uuid;

/// A single pending approval request delivered to a front-end (Telegram drain
/// task, GUI panel, HTTP endpoint, CLI). The drain task serialises this into
/// a human-readable elicitation message and sends it to the operator.
pub struct ConfirmRequest {
    /// Stable identifier the operator echoes back in their reply.
    pub uuid: Uuid,
    /// Operator-readable description of what the daemon is about to do (e.g.
    /// `"channel send to +49…"` or `"paid provider call €1.20"`).
    pub description: String,
    /// Structured payload for GUI / web front-ends (always
    /// `{"type": "binary_confirm", "reason": "<description>"}`  for the MVP).
    pub action_json: serde_json::Value,
}

/// Singleton approval bus shared across all channel adapters in a single daemon
/// run. Cheaply clonable via `Arc<ConfirmBus>`; the inner state is
/// `Mutex`-protected for non-async critical sections (no `await` inside the
/// lock, so no deadlock).
///
/// Construct via [`ConfirmBus::new`] — the `Receiver` side is handed to the
/// drain task once; the `Arc<ConfirmBus>` is cloned into every call site.
pub struct ConfirmBus {
    /// Sender side of the elicitation queue. The drain task owns the `Receiver`.
    tx: tokio::sync::mpsc::Sender<ConfirmRequest>,
    /// Pending approvals keyed by UUID. The oneshot sender is stored here until
    /// [`Self::submit_response`] fires it (or the timeout drops it).
    pending: Arc<Mutex<HashMap<Uuid, oneshot::Sender<bool>>>>,
}

impl ConfirmBus {
    /// Construct a new bus. Returns the bus (`Arc`) and the `Receiver` side of
    /// the elicitation queue. The `Receiver` must be handed to the drain task
    /// that forwards requests to the operator's channel.
    pub fn new() -> (Arc<Self>, tokio::sync::mpsc::Receiver<ConfirmRequest>) {
        let (tx, rx) = tokio::sync::mpsc::channel(32);
        let bus = Arc::new(Self {
            tx,
            pending: Arc::new(Mutex::new(HashMap::new())),
        });
        (bus, rx)
    }

    /// Issue a UUID, register a pending oneshot, enqueue the [`ConfirmRequest`],
    /// and block (async) until the operator replies or `timeout` elapses.
    ///
    /// Returns:
    /// - `Some(true)`  — operator approved
    /// - `Some(false)` — operator denied
    /// - `None`        — timed out (caller treats as deny, per gate semantics)
    pub async fn request_and_wait(
        &self,
        description: impl Into<String>,
        action_json: serde_json::Value,
        timeout: Duration,
    ) -> Option<bool> {
        let uuid = Uuid::now_v7();
        let (resp_tx, resp_rx) = oneshot::channel();
        // Register the waiter BEFORE enqueueing so the drain task can never
        // beat us to submit_response.
        self.pending
            .lock()
            .expect("confirm_bus pending lock poisoned")
            .insert(uuid, resp_tx);

        let req = ConfirmRequest {
            uuid,
            description: description.into(),
            action_json,
        };
        // Best-effort send — if the drain task has exited, the request
        // disappears and the timeout path returns None (deny), preserving
        // fail-closed semantics.
        let _ = self.tx.send(req).await;

        match tokio::time::timeout(timeout, resp_rx).await {
            Ok(Ok(v)) => Some(v),
            _ => {
                // Timeout or oneshot sender dropped (drain died).
                // Clean up the orphaned waiter entry.
                self.pending
                    .lock()
                    .expect("confirm_bus pending lock poisoned")
                    .remove(&uuid);
                None
            }
        }
    }

    /// Fire an operator reply into the corresponding pending waiter.
    ///
    /// Called from:
    /// - The inbound pipeline UUID-reply fast-path (Telegram / Slack / Discord)
    /// - Future Slint-GUI thread
    /// - Future HTTP endpoint
    /// - `neoth channel confirm <uuid>` CLI subcommand
    ///
    /// Returns `true` if a waiter was found and notified, `false` if the UUID
    /// was unknown (already timed out, or a duplicate reply).
    pub fn submit_response(&self, uuid: Uuid, approved: bool) -> bool {
        if let Some(tx) = self
            .pending
            .lock()
            .expect("confirm_bus pending lock poisoned")
            .remove(&uuid)
        {
            // Ignore the send error — the waiter may have timed out and dropped
            // its receiver between the HashMap remove and this send.
            let _ = tx.send(approved);
            return true;
        }
        false
    }

    /// Number of approvals currently in-flight (for diagnostics / metrics).
    pub fn pending_count(&self) -> usize {
        self.pending
            .lock()
            .expect("confirm_bus pending lock poisoned")
            .len()
    }
}

// ── ChannelAsker adapter ───────────────────────────────────────────────────

/// [`ChannelAsker`](super::gate::ChannelAsker) implementation that delegates
/// `ask()` to a [`ConfirmBus`]. The `Gate` calls `ask(reason)` and the bus
/// assigns a UUID, serialises a request, and suspends until the operator
/// replies via any front-end that holds a clone of the `Arc<ConfirmBus>`.
pub struct BusAsker(pub Arc<ConfirmBus>);

#[async_trait::async_trait]
impl crate::permissions::gate::ChannelAsker for BusAsker {
    async fn ask(&self, reason: &str) -> Option<bool> {
        self.0
            .request_and_wait(
                reason,
                serde_json::json!({ "type": "binary_confirm", "reason": reason }),
                crate::permissions::confirm::DEFAULT_CHANNEL_TIMEOUT,
            )
            .await
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn gated_action_suspends_on_uuid_and_resumes_on_submit_response() {
        let (bus, mut rx) = ConfirmBus::new();
        let bus_arc = Arc::clone(&bus);

        // Simulate the Gate caller (runs in background — waits on bus).
        let wait_task = tokio::spawn(async move {
            bus_arc
                .request_and_wait(
                    "write outside ~/.neoth/",
                    serde_json::json!({"type": "binary_confirm"}),
                    Duration::from_secs(5),
                )
                .await
        });

        // Drain the request — simulates the Telegram drain task reading ConfirmRequests.
        let req = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("recv timed out")
            .expect("channel closed");
        assert!(!req.uuid.is_nil(), "UUID must be non-nil");
        assert!(
            req.description.contains("write outside"),
            "description must carry reason: {}",
            req.description
        );

        // Simulate operator reply — submit approval via UUID.
        let found = bus.submit_response(req.uuid, true);
        assert!(found, "submit_response must find the pending waiter");

        // The gate caller unblocks with Some(true).
        let result = wait_task.await.expect("task panicked");
        assert_eq!(result, Some(true), "approved response must unblock the waiter");
    }

    #[tokio::test]
    async fn confirm_bus_times_out_cleanly_when_no_response_arrives() {
        let (bus, _rx) = ConfirmBus::new();
        // Drop rx immediately — no one will drain or respond.
        let result = bus
            .request_and_wait(
                "test",
                serde_json::json!({}),
                Duration::from_millis(50),
            )
            .await;
        assert_eq!(result, None, "must return None on timeout");
    }

    #[tokio::test]
    async fn timeout_cleans_up_pending_entry() {
        let (bus, _rx) = ConfirmBus::new();
        let _ = bus
            .request_and_wait("x", serde_json::json!({}), Duration::from_millis(30))
            .await;
        // After timeout the pending HashMap must be empty — no leak.
        assert_eq!(
            bus.pending_count(),
            0,
            "pending entry must be removed after timeout"
        );
    }

    #[tokio::test]
    async fn submit_response_returns_false_for_unknown_uuid() {
        let (bus, _rx) = ConfirmBus::new();
        let unknown = Uuid::now_v7();
        let found = bus.submit_response(unknown, true);
        assert!(!found, "unknown UUID must return false");
    }

    #[tokio::test]
    async fn deny_reply_propagates_as_some_false() {
        let (bus, mut rx) = ConfirmBus::new();
        let bus_arc = Arc::clone(&bus);

        let wait_task = tokio::spawn(async move {
            bus_arc
                .request_and_wait("deny-test", serde_json::json!({}), Duration::from_secs(5))
                .await
        });

        let req = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("recv timed out")
            .unwrap();
        bus.submit_response(req.uuid, false);

        let result = wait_task.await.expect("task panicked");
        assert_eq!(result, Some(false), "deny reply must surface as Some(false)");
    }

    /// Integration test: BusAsker → Gate::check → ConfirmStrategy::Channel arm
    /// → ChannelAsker::ask → ConfirmBus. Proves the end-to-end seam works without
    /// a real Telegram connection.
    #[tokio::test]
    async fn bus_asker_integrates_with_gate_channel_strategy() {
        use crate::permissions::gate::{ConfirmStrategy, Gate};
        use crate::permissions::{Action, AutonomyLevel};

        let (bus, mut rx) = ConfirmBus::new();
        let asker: Arc<dyn crate::permissions::gate::ChannelAsker> =
            Arc::new(BusAsker(Arc::clone(&bus)));

        // Standard + WriteOutsideHome → Confirm; Channel strategy + wired asker → Ask.
        let gate = Gate::for_level(AutonomyLevel::Standard)
            .with_confirm(ConfirmStrategy::Channel)
            .with_channel_asker(asker)
            .with_channel_timeout(Duration::from_secs(5));

        // Run the gate concurrently with a simulated operator approval.
        let gate_task = tokio::spawn(async move {
            gate.check(&Action::WriteOutsideHome, None).await
        });

        // Drain + approve.
        let req = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("recv timed out")
            .expect("channel closed");
        bus.submit_response(req.uuid, true);

        let result = gate_task.await.expect("gate task panicked");
        assert!(
            result.is_ok(),
            "channel-approved action must pass the gate: {result:?}"
        );
    }
}
