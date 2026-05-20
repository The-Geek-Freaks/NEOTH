//! Per-adapter request deduplication (B-9).
//!
//! When two concurrent operator messages produce the same `(prompt,
//! system, model)` tuple — e.g. a channel adapter retransmits before
//! NEOTH acks, or the operator hits "send" twice — naively each call
//! would fire a paid provider request. `Singleflight::do_call` collapses
//! identical in-flight requests: the first arrival does the work, the
//! second arrival waits on a `Notify` and reads the result the first
//! arrival published.
//!
//! Scope: only the success path is deduplicated. On error the slot is
//! removed and any subsequent caller retries on its own — this loses a
//! tiny bit of efficiency but keeps the error path simple and avoids
//! cloning [`anyhow::Error`] (which is not [`Clone`]).
//!
//! Generic over `T: Clone + Send + Sync + 'static` so adapters can reuse
//! it for [`Completion`](super::Completion), JSON envelopes, or any
//! future request-scoped value.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use tokio::sync::Notify;

/// In-flight request map. One instance per adapter; shared across
/// `complete` / `stream` calls on that adapter via `Arc`.
pub struct Singleflight<T> {
    slots: Mutex<HashMap<u64, Arc<Slot<T>>>>,
}

/// One pending slot. `notify` wakes every waiter when the first arrival
/// publishes the result into `value`. `value` holds an `Arc<T>` so the
/// first arrival can construct once and every waiter gets a cheap
/// reference-count clone.
struct Slot<T> {
    notify: Notify,
    value: Mutex<Option<Arc<T>>>,
}

impl<T: Send + Sync + 'static> Default for Singleflight<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Send + Sync + 'static> Singleflight<T> {
    pub fn new() -> Self {
        Self {
            slots: Mutex::new(HashMap::new()),
        }
    }

    /// Run `op` exactly once across all concurrent callers sharing
    /// `key`. The first caller executes the future; every other caller
    /// for the same key during the in-flight window awaits the same
    /// result. On error the slot is dropped — subsequent callers run
    /// `op` themselves.
    pub async fn do_call<F, Fut>(&self, key: u64, op: F) -> Result<Arc<T>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        // Phase 1 — acquire or insert the slot. The map lock is held
        // only for the lookup/insert; the future runs without it so
        // other keys don't queue.
        let (slot, is_owner) = {
            let mut guard = self
                .slots
                .lock()
                .expect("singleflight slots mutex poisoned");
            match guard.get(&key) {
                Some(existing) => (existing.clone(), false),
                None => {
                    let new_slot = Arc::new(Slot {
                        notify: Notify::new(),
                        value: Mutex::new(None),
                    });
                    guard.insert(key, new_slot.clone());
                    (new_slot, true)
                }
            }
        };

        if is_owner {
            // Phase 2a — owner runs the future, publishes result.
            let result = op().await;
            match result {
                Ok(value) => {
                    let arc_value = Arc::new(value);
                    {
                        let mut v = slot
                            .value
                            .lock()
                            .expect("singleflight value mutex poisoned");
                        *v = Some(arc_value.clone());
                    }
                    // Wake every subscriber BEFORE removing the slot;
                    // subscribers re-check value under their own lock,
                    // so the order of these two operations is correct.
                    slot.notify.notify_waiters();
                    self.remove_slot(key);
                    Ok(arc_value)
                }
                Err(e) => {
                    // Error path: drop the slot so subsequent callers
                    // (or any current waiters) fall through and try
                    // themselves. Wake waiters so they don't deadlock.
                    self.remove_slot(key);
                    slot.notify.notify_waiters();
                    Err(e)
                }
            }
        } else {
            // Phase 2b — subscriber. Create the Notified future BEFORE
            // checking value to close the wake/check race: if owner
            // publishes between our value-check and our await, the
            // pre-registered Notified still fires.
            let notified = slot.notify.notified();
            {
                let guard = slot
                    .value
                    .lock()
                    .expect("singleflight value mutex poisoned");
                if let Some(v) = guard.as_ref() {
                    return Ok(v.clone());
                }
            }
            notified.await;
            // After wake, re-check. If empty, the owner errored; the
            // subscriber must surface a retry-at-caller error since
            // `op` was already consumed (FnOnce).
            let guard = slot
                .value
                .lock()
                .expect("singleflight value mutex poisoned");
            if let Some(v) = guard.as_ref() {
                Ok(v.clone())
            } else {
                Err(anyhow::anyhow!(
                    "singleflight: in-flight request failed, retry at caller"
                ))
            }
        }
    }

    fn remove_slot(&self, key: u64) {
        let mut guard = self
            .slots
            .lock()
            .expect("singleflight slots mutex poisoned");
        guard.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[tokio::test]
    async fn single_caller_runs_once_and_returns_value() {
        let sf = Singleflight::<u64>::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let c = counter.clone();
        let v = sf
            .do_call(42, || async move {
                c.fetch_add(1, Ordering::SeqCst);
                Ok(100u64)
            })
            .await
            .unwrap();
        assert_eq!(*v, 100);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn concurrent_callers_share_one_execution() {
        // Two tasks with the same key — `op` must run exactly once.
        let sf = Arc::new(Singleflight::<u64>::new());
        let counter = Arc::new(AtomicUsize::new(0));

        let sf1 = sf.clone();
        let c1 = counter.clone();
        let task1 = tokio::spawn(async move {
            sf1.do_call(42, || async move {
                tokio::time::sleep(Duration::from_millis(40)).await;
                c1.fetch_add(1, Ordering::SeqCst);
                Ok(7u64)
            })
            .await
        });

        // Give task1 a head start so it owns the slot.
        tokio::time::sleep(Duration::from_millis(5)).await;

        let sf2 = sf.clone();
        let c2 = counter.clone();
        let task2 = tokio::spawn(async move {
            sf2.do_call(42, || async move {
                // This should never run — task1 owns the slot.
                c2.fetch_add(100, Ordering::SeqCst);
                Ok(999u64)
            })
            .await
        });

        let r1 = task1.await.unwrap().unwrap();
        let r2 = task2.await.unwrap().unwrap();
        assert_eq!(*r1, 7);
        assert_eq!(*r2, 7, "subscriber must read the owner's value");
        // 1, not 101: subscriber's op never ran.
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn different_keys_run_independently() {
        let sf = Singleflight::<u64>::new();
        let counter = Arc::new(AtomicUsize::new(0));

        let c1 = counter.clone();
        let v1 = sf
            .do_call(1, || async move {
                c1.fetch_add(1, Ordering::SeqCst);
                Ok(11)
            })
            .await
            .unwrap();

        let c2 = counter.clone();
        let v2 = sf
            .do_call(2, || async move {
                c2.fetch_add(1, Ordering::SeqCst);
                Ok(22)
            })
            .await
            .unwrap();

        assert_eq!(*v1, 11);
        assert_eq!(*v2, 22);
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn slot_is_released_after_success_so_next_call_runs_op_again() {
        let sf = Singleflight::<u64>::new();
        let counter = Arc::new(AtomicUsize::new(0));

        let c1 = counter.clone();
        let v1 = sf
            .do_call(7, || async move {
                c1.fetch_add(1, Ordering::SeqCst);
                Ok(1)
            })
            .await
            .unwrap();
        // First call published + removed slot. A later call must run
        // `op` again (dedup is a concurrent-window optimisation, not a
        // permanent cache).
        let c2 = counter.clone();
        let v2 = sf
            .do_call(7, || async move {
                c2.fetch_add(1, Ordering::SeqCst);
                Ok(2)
            })
            .await
            .unwrap();
        assert_eq!(*v1, 1);
        assert_eq!(*v2, 2);
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn owner_error_propagates_and_subscriber_falls_through() {
        let sf = Arc::new(Singleflight::<u64>::new());

        let sf1 = sf.clone();
        let task1 = tokio::spawn(async move {
            sf1.do_call(99, || async move {
                tokio::time::sleep(Duration::from_millis(30)).await;
                Err::<u64, _>(anyhow::anyhow!("upstream blew up"))
            })
            .await
        });
        tokio::time::sleep(Duration::from_millis(5)).await;

        let sf2 = sf.clone();
        let task2 = tokio::spawn(async move { sf2.do_call(99, || async move { Ok(42) }).await });

        let r1 = task1.await.unwrap();
        let r2 = task2.await.unwrap();
        assert!(r1.is_err(), "owner surfaces its own error");
        assert!(r1.as_ref().unwrap_err().to_string().contains("upstream"));
        assert!(
            r2.is_err(),
            "subscriber surfaces a retry-at-caller error when owner fails",
        );
        assert!(r2.unwrap_err().to_string().contains("retry at caller"));
    }
}
