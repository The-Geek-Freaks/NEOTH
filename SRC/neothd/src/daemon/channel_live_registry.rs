//! Generation-bound access to live-instance-owned proactive channel adapters.
//!
//! IRC, Twitch and Nostr own long-lived receive connections; Google Chat owns
//! a running Pub/Sub pull adapter with its parsed service-account authority and
//! token cache. This registry never builds a replacement transport: it
//! publishes only an already-ready adapter and returns a lease wrapper rather
//! than the raw adapter. The wrapper rechecks the same entry at the actual
//! proactive effect boundary.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::{Mutex as AsyncMutex, Notify};

use crate::channels::registry::ChannelRef;
use crate::channels::{Channel, ChannelError};

#[derive(Default)]
pub struct ChannelLiveRegistry {
    entries: Mutex<BTreeMap<ChannelRef, Arc<LiveEntry>>>,
    closed: Arc<std::sync::atomic::AtomicBool>,
    /// Serializes the final shutdown fence with the actual transport effect,
    /// not merely with adapter lookup.
    closing_gate: Arc<AsyncMutex<()>>,
}

struct LiveEntry {
    state: Arc<AsyncMutex<EntryState>>,
    active: AtomicUsize,
    drained: Notify,
}

struct EntryState {
    generation: u64,
    fingerprint: u64,
    accepting: bool,
    channel: Option<Arc<dyn Channel>>,
}

impl Default for LiveEntry {
    fn default() -> Self {
        Self {
            state: Arc::new(AsyncMutex::new(EntryState {
                generation: 0,
                fingerprint: 0,
                accepting: false,
                channel: None,
            })),
            active: AtomicUsize::new(0),
            drained: Notify::new(),
        }
    }
}

/// Opaque authority for one replacement lifecycle.  A readiness task may only
/// publish the adapter constructed for this exact generation and fingerprint.
pub struct LiveChannelPublicationLease {
    generation: u64,
    fingerprint: u64,
    entry: Option<Arc<LiveEntry>>,
}

impl ChannelLiveRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    fn entry_for(&self, channel_ref: &ChannelRef) -> Option<Arc<LiveEntry>> {
        let mut entries = self
            .entries
            .lock()
            .expect("live-channel registry mutex poisoned");
        (!self.closed.load(Ordering::Acquire)).then(|| {
            Arc::clone(
                entries
                    .entry(channel_ref.clone())
                    .or_insert_with(|| Arc::new(LiveEntry::default())),
            )
        })
    }

    fn existing_entry(&self, channel_ref: &ChannelRef) -> Option<Arc<LiveEntry>> {
        self.entries
            .lock()
            .expect("live-channel registry mutex poisoned")
            .get(channel_ref)
            .cloned()
    }

    async fn wait_for_drain(entry: &LiveEntry) {
        loop {
            if entry.active.load(Ordering::Acquire) == 0 {
                return;
            }
            let notified = entry.drained.notified();
            if entry.active.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }

    async fn revoke_entry_and_drain(entry: &Arc<LiveEntry>) {
        let retired_generation = {
            let mut state = entry.state.lock().await;
            state.accepting = false;
            state.generation
        };
        Self::wait_for_drain(entry).await;
        let mut state = entry.state.lock().await;
        if !state.accepting && state.generation == retired_generation {
            state.channel = None;
        }
    }

    /// Revoke the previous lifecycle, wait for its owned egress work, then
    /// create the sole authority capable of publishing its replacement.
    pub async fn begin_replacement(
        &self,
        channel_ref: ChannelRef,
        fingerprint: u64,
    ) -> LiveChannelPublicationLease {
        let Some(entry) = self.entry_for(&channel_ref) else {
            return LiveChannelPublicationLease {
                generation: 0,
                fingerprint,
                entry: None,
            };
        };
        Self::revoke_entry_and_drain(&entry).await;
        if self.closed.load(Ordering::Acquire) {
            return LiveChannelPublicationLease {
                generation: 0,
                fingerprint,
                entry: None,
            };
        }
        let (generation, fingerprint) = {
            let mut state = entry.state.lock().await;
            state.generation = state.generation.saturating_add(1);
            state.fingerprint = fingerprint;
            state.accepting = true;
            state.channel = None;
            (state.generation, state.fingerprint)
        };
        LiveChannelPublicationLease {
            generation,
            fingerprint,
            entry: Some(entry),
        }
    }

    /// Publish only a ready adapter built under `lease`.  A stale readiness
    /// task loses harmlessly after reload or shutdown.
    pub async fn publish(
        &self,
        lease: &LiveChannelPublicationLease,
        channel: Arc<dyn Channel>,
    ) -> bool {
        if self.closed.load(Ordering::Acquire) {
            return false;
        }
        let Some(entry) = lease.entry.as_ref() else {
            return false;
        };
        let mut state = entry.state.lock().await;
        if !state.accepting
            || self.closed.load(Ordering::Acquire)
            || state.generation != lease.generation
            || state.fingerprint != lease.fingerprint
            || state.channel.is_some()
        {
            return false;
        }
        state.channel = Some(channel);
        true
    }

    /// Acquire one opaque proactive permit. It owns active-work until it is
    /// consumed or dropped and rechecks current authority at the raw effect.
    pub(super) async fn acquire(
        &self,
        channel_ref: &ChannelRef,
        fingerprint: u64,
    ) -> Option<ConnectionBoundProactivePermit> {
        if self.closed.load(Ordering::Acquire) {
            return None;
        }
        let entry = self.existing_entry(channel_ref)?;
        let state = entry.state.lock().await;
        if self.closed.load(Ordering::Acquire)
            || !state.accepting
            || state.fingerprint != fingerprint
        {
            return None;
        }
        let channel = state.channel.clone()?;
        let generation = state.generation;
        entry.active.fetch_add(1, Ordering::AcqRel);
        drop(state);
        Some(ConnectionBoundProactivePermit {
            channel,
            entry,
            channel_ref: channel_ref.clone(),
            generation,
            fingerprint,
            closed: Arc::clone(&self.closed),
            closing_gate: Arc::clone(&self.closing_gate),
        })
    }

    /// Refuse future acquisitions for one reference, retain already-acquired
    /// egress through its terminal path, then release the old adapter.
    pub async fn revoke_and_drain(&self, channel_ref: &ChannelRef) {
        if let Some(entry) = self.existing_entry(channel_ref) {
            Self::revoke_entry_and_drain(&entry).await;
        }
    }

    /// Shutdown helper: retire all registry entries before transport tasks are
    /// aborted, so no lease is silently detached from a live send.
    pub async fn revoke_all_and_drain(&self) {
        // Once set, this fence is permanent for the daemon instance.  Hold it
        // only through the transition itself: an effect already inside the
        // gate completes, while every later effect sees the closed flag.
        {
            let _closing = self.closing_gate.lock().await;
            self.closed.store(true, Ordering::Release);
        }
        let entries = self
            .entries
            .lock()
            .expect("live-channel registry mutex poisoned")
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for entry in entries {
            Self::revoke_entry_and_drain(&entry).await;
        }
    }

    /// Test-only opaque forwarding preserves the production permit boundary
    /// while allowing sibling crate test modules to exercise lifecycle races.
    #[cfg(test)]
    pub(crate) async fn acquire_for_test(
        &self,
        channel_ref: &ChannelRef,
        fingerprint: u64,
    ) -> Option<ConnectionBoundProactiveTestPermit> {
        self.acquire(channel_ref, fingerprint)
            .await
            .map(ConnectionBoundProactiveTestPermit)
    }
}

/// Non-cloneable authority for one live-instance-owned proactive effect. It is
/// intentionally not a `Channel`: handing out an `Arc<dyn Channel>` would
/// let callers duplicate the capability and later send outside the durable
/// claim path.  The egress executor consumes this permit exactly once after
/// its Prepared, Intent and Armed records have all been acknowledged.
pub(super) struct ConnectionBoundProactivePermit {
    channel: Arc<dyn Channel>,
    entry: Arc<LiveEntry>,
    channel_ref: ChannelRef,
    generation: u64,
    fingerprint: u64,
    closed: Arc<std::sync::atomic::AtomicBool>,
    closing_gate: Arc<AsyncMutex<()>>,
}

#[cfg(test)]
pub(crate) struct ConnectionBoundProactiveTestPermit(ConnectionBoundProactivePermit);

#[cfg(test)]
impl ConnectionBoundProactiveTestPermit {
    pub(crate) async fn send_once(
        self,
        chat_id: String,
        text: String,
    ) -> std::result::Result<crate::channels::MessageId, ChannelError> {
        self.0.send_once(chat_id, text).await
    }
}

impl ConnectionBoundProactivePermit {
    pub(super) fn channel_ref(&self) -> &ChannelRef {
        &self.channel_ref
    }

    pub(super) fn generation(&self) -> u64 {
        self.generation
    }

    pub(super) fn fingerprint(&self) -> u64 {
        self.fingerprint
    }

    /// Consume this sole permit at the actual provider boundary.  No caller
    /// can retain a raw channel or retry a second send after this future.
    pub(super) async fn send_once(
        self,
        chat_id: String,
        text: String,
    ) -> std::result::Result<crate::channels::MessageId, ChannelError> {
        let _closing = Arc::clone(&self.closing_gate).lock_owned().await;
        {
            let state = Arc::clone(&self.entry.state).lock_owned().await;
            if self.closed.load(Ordering::Acquire)
                || !state.accepting
                || state.generation != self.generation
                || state.fingerprint != self.fingerprint
                || !state
                    .channel
                    .as_ref()
                    .is_some_and(|current| Arc::ptr_eq(current, &self.channel))
            {
                return Err(ChannelError::Transport(
                    "connection-owned proactive channel was revoked".to_string(),
                ));
            }
        }
        self.channel.send_proactive(&chat_id, &text).await
    }
}

impl Drop for ConnectionBoundProactivePermit {
    fn drop(&mut self) {
        if self.entry.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.entry.drained.notify_waiters();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channels::{ChannelKind, MessageId, PipelineHandler};
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingChannel(AtomicUsize);

    struct BlockingChannel {
        entered: Notify,
        release: AsyncMutex<Option<tokio::sync::oneshot::Receiver<()>>>,
        sends: AtomicUsize,
    }

    #[async_trait]
    impl Channel for CountingChannel {
        fn name(&self) -> &'static str {
            "irc"
        }

        async fn run(&self, _handler: PipelineHandler) -> anyhow::Result<()> {
            Ok(())
        }

        async fn send_proactive(
            &self,
            _chat_id: &str,
            _text: &str,
        ) -> std::result::Result<MessageId, ChannelError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(MessageId("sent".to_string()))
        }
    }

    #[async_trait]
    impl Channel for BlockingChannel {
        fn name(&self) -> &'static str {
            "irc"
        }

        async fn run(&self, _handler: PipelineHandler) -> anyhow::Result<()> {
            Ok(())
        }

        async fn send_proactive(
            &self,
            _chat_id: &str,
            _text: &str,
        ) -> std::result::Result<MessageId, ChannelError> {
            self.entered.notify_one();
            let release = self
                .release
                .lock()
                .await
                .take()
                .expect("blocking channel may receive exactly one send");
            release.await.expect("test release sender dropped");
            self.sends.fetch_add(1, Ordering::SeqCst);
            Ok(MessageId("sent".to_string()))
        }
    }

    fn irc_ref() -> ChannelRef {
        ChannelRef::default_account(ChannelKind::Irc)
    }

    #[tokio::test]
    async fn acquire_returns_only_matching_published_generation() {
        let registry = ChannelLiveRegistry::new();
        let lease = registry.begin_replacement(irc_ref(), 41).await;
        let channel = Arc::new(CountingChannel(AtomicUsize::new(0)));
        assert!(registry.publish(&lease, channel.clone()).await);
        assert!(registry.acquire(&irc_ref(), 40).await.is_none());
        let acquired = registry.acquire(&irc_ref(), 41).await.unwrap();
        acquired
            .send_once("#ops".to_string(), "hello".to_string())
            .await
            .unwrap();
        assert_eq!(channel.0.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn stale_publication_cannot_reanimate_replaced_adapter() {
        let registry = ChannelLiveRegistry::new();
        let old = registry.begin_replacement(irc_ref(), 41).await;
        let new = registry.begin_replacement(irc_ref(), 42).await;
        let channel = Arc::new(CountingChannel(AtomicUsize::new(0)));
        assert!(!registry.publish(&old, channel.clone()).await);
        assert!(registry.publish(&new, channel).await);
        assert!(registry.acquire(&irc_ref(), 41).await.is_none());
        assert!(registry.acquire(&irc_ref(), 42).await.is_some());
    }

    #[tokio::test]
    async fn shutdown_rejects_even_a_previously_uncreated_channel_reference() {
        let registry = ChannelLiveRegistry::new();
        registry.revoke_all_and_drain().await;
        let lease = registry
            .begin_replacement(ChannelRef::default_account(ChannelKind::Nostr), 88)
            .await;
        assert!(
            !registry
                .publish(&lease, Arc::new(CountingChannel(AtomicUsize::new(0))))
                .await
        );
        assert!(
            registry
                .acquire(&ChannelRef::default_account(ChannelKind::Nostr), 88)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn revocation_waits_for_an_acquired_lease_then_refuses_new_egress() {
        let registry = Arc::new(ChannelLiveRegistry::new());
        let lease = registry.begin_replacement(irc_ref(), 41).await;
        let channel = Arc::new(CountingChannel(AtomicUsize::new(0)));
        assert!(registry.publish(&lease, channel.clone()).await);
        let acquired = registry.acquire(&irc_ref(), 41).await.unwrap();
        let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
        let revoking = Arc::clone(&registry);
        let revoking_ref = irc_ref();
        let revocation = tokio::spawn(async move {
            revoking.revoke_and_drain(&revoking_ref).await;
            let _ = finished_tx.send(());
        });
        let mut finished_rx = finished_rx;
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if registry.acquire(&irc_ref(), 41).await.is_none() {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("revocation did not refuse new proactive acquisitions");
        assert!(
            matches!(
                finished_rx.try_recv(),
                Err(tokio::sync::oneshot::error::TryRecvError::Empty)
            ),
            "revocation must retain acquired egress until its lease drops"
        );
        assert!(
            acquired
                .send_once("#ops".to_string(), "must not send".to_string())
                .await
                .is_err(),
            "the acquired wrapper must recheck revocation at the effect boundary"
        );
        assert_eq!(
            channel.0.load(Ordering::SeqCst),
            0,
            "a revoked lease must never reach the raw adapter"
        );
        finished_rx.await.unwrap();
        revocation.await.unwrap();
        assert!(registry.acquire(&irc_ref(), 41).await.is_none());
    }

    #[tokio::test]
    async fn shutdown_waits_for_an_effect_already_inside_the_real_send_boundary() {
        let registry = Arc::new(ChannelLiveRegistry::new());
        let lease = registry.begin_replacement(irc_ref(), 41).await;
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let channel = Arc::new(BlockingChannel {
            entered: Notify::new(),
            release: AsyncMutex::new(Some(release_rx)),
            sends: AtomicUsize::new(0),
        });
        assert!(registry.publish(&lease, channel.clone()).await);
        let acquired = registry.acquire(&irc_ref(), 41).await.unwrap();
        let entered = channel.entered.notified();
        let sending = tokio::spawn(async move {
            acquired
                .send_once("#ops".to_string(), "in flight".to_string())
                .await
        });
        entered.await;

        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (finished_tx, mut finished_rx) = tokio::sync::oneshot::channel();
        let closing = Arc::clone(&registry);
        let shutdown = tokio::spawn(async move {
            let _ = started_tx.send(());
            closing.revoke_all_and_drain().await;
            let _ = finished_tx.send(());
        });
        started_rx.await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(25), &mut finished_rx)
                .await
                .is_err(),
            "shutdown must wait for a send already inside the effect boundary"
        );
        release_tx.send(()).unwrap();
        sending.await.unwrap().unwrap();
        finished_rx.await.unwrap();
        shutdown.await.unwrap();
        assert_eq!(channel.sends.load(Ordering::SeqCst), 1);
        assert!(registry.acquire(&irc_ref(), 41).await.is_none());
    }
}
