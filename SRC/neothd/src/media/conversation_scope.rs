//! Generation-based cancellation for one realtime conversation.
//!
//! A producer takes a [`GenerationToken`] before starting work and polls
//! [`CancelScope::is_stale`] while producing audio or text. Invalidating the
//! scope makes every token from its preceding generation stale at once.
//!
//! `u32::MAX` is deliberately reserved as a terminal, invalidated sentinel.
//! It is never issued in a token. When the final usable generation is
//! invalidated, the scope enters that sentinel and reports
//! [`GenerationExhausted`] instead of wrapping to zero, so an ancient token
//! can never become current again.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

/// Cloneable cancellation domain for all work belonging to one conversation.
///
/// Clones share one atomic generation counter, allowing the capture, LLM, TTS,
/// and playback tasks to observe the same cancellation boundary without a lock.
#[derive(Clone, Debug)]
pub struct CancelScope {
    generation: Arc<AtomicU32>,
}

/// Opaque snapshot of a [`CancelScope`] generation.
///
/// The generation is private so callers cannot forge a token for a newer
/// conversation state. Obtain one only through [`CancelScope::snapshot`].
#[derive(Clone, Debug)]
#[must_use = "a generation token must be polled with CancelScope::is_stale"]
pub struct GenerationToken {
    scope: Arc<AtomicU32>,
    generation: u32,
}

/// Returned when a scope can no longer issue or advance a generation safely.
///
/// This is terminal for the scope: it remains invalidated and every previously
/// issued token stays stale.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("conversation cancellation generation exhausted")]
pub struct GenerationExhausted;

impl Default for CancelScope {
    fn default() -> Self {
        Self::new()
    }
}

impl CancelScope {
    /// Create a fresh cancellation domain at its first usable generation.
    pub fn new() -> Self {
        Self {
            generation: Arc::new(AtomicU32::new(0)),
        }
    }

    /// Snapshot the current generation for a newly started unit of work.
    ///
    /// Returns [`GenerationExhausted`] once this scope has reached its terminal
    /// sentinel, rather than issuing a token that could later be revalidated.
    pub fn snapshot(&self) -> Result<GenerationToken, GenerationExhausted> {
        let generation = self.generation.load(Ordering::SeqCst);
        if generation == u32::MAX {
            return Err(GenerationExhausted);
        }
        Ok(GenerationToken {
            scope: Arc::clone(&self.generation),
            generation,
        })
    }

    /// Invalidate all tokens issued before this call.
    ///
    /// The last usable generation transitions to the terminal sentinel and
    /// returns [`GenerationExhausted`]. That call has still invalidated the old
    /// token; callers must treat the error as a terminal fail-closed state.
    pub fn invalidate(&self) -> Result<(), GenerationExhausted> {
        let result = self.generation.fetch_update(
            Ordering::SeqCst,
            Ordering::SeqCst,
            |generation| match generation {
                u32::MAX => None,
                generation => Some(generation + 1),
            },
        );

        match result {
            Ok(generation) if generation == u32::MAX - 1 => Err(GenerationExhausted),
            Err(u32::MAX) => Err(GenerationExhausted),
            Ok(_) => Ok(()),
            Err(_) => unreachable!("the cancellation generation only rejects its terminal sentinel"),
        }
    }

    /// True when `token` no longer belongs to this scope's current generation.
    ///
    /// A token from another scope is also stale: token snapshots carry their
    /// originating allocation, and this check rejects a different one before
    /// comparing generations.
    pub fn is_stale(&self, token: &GenerationToken) -> bool {
        !Arc::ptr_eq(&self.generation, &token.scope)
            || self.generation.load(Ordering::SeqCst) != token.generation
    }

    #[cfg(test)]
    fn from_generation(generation: u32) -> Self {
        Self {
            generation: Arc::new(AtomicU32::new(generation)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::thread;

    use super::CancelScope;

    #[test]
    fn fresh_token_is_current() {
        let scope = CancelScope::new();
        let token = scope.snapshot().expect("fresh scope must issue a token");

        assert!(!scope.is_stale(&token));
    }

    #[test]
    fn invalidation_stales_prior_token_and_new_token_is_current() {
        let scope = CancelScope::new();
        let prior = scope.snapshot().expect("fresh scope must issue a token");

        scope.invalidate().expect("first invalidation must advance");
        let current = scope
            .snapshot()
            .expect("advanced scope must issue a new token");

        assert!(scope.is_stale(&prior));
        assert!(!scope.is_stale(&current));
    }

    #[test]
    fn clones_share_the_same_cancellation_boundary() {
        let scope = CancelScope::new();
        let clone = scope.clone();
        let token = clone.snapshot().expect("fresh clone must issue a token");

        scope.invalidate().expect("first invalidation must advance");

        assert!(clone.is_stale(&token));
    }

    #[test]
    fn token_from_another_scope_is_always_stale() {
        let first = CancelScope::new();
        let second = CancelScope::new();
        let token = second
            .snapshot()
            .expect("fresh independent scope must issue a token");

        assert!(first.is_stale(&token));
    }

    #[test]
    fn concurrent_invalidations_advance_one_shared_generation_per_call() {
        const INVALIDATORS: usize = 8;

        let scope = Arc::new(CancelScope::new());
        let original = scope.snapshot().expect("fresh scope must issue a token");
        let handles: Vec<_> = (0..INVALIDATORS)
            .map(|_| {
                let scope = Arc::clone(&scope);
                thread::spawn(move || scope.invalidate())
            })
            .collect();

        for handle in handles {
            handle
                .join()
                .expect("invalidation worker must not panic")
                .expect("small concurrent batch must not exhaust generation");
        }

        let current = scope
            .snapshot()
            .expect("small concurrent batch must leave a usable generation");
        assert_eq!(current.generation, INVALIDATORS as u32);
        assert!(scope.is_stale(&original));
        assert!(!scope.is_stale(&current));
    }

    #[test]
    fn exhaustion_invalidates_without_wrapping_or_revalidating_old_tokens() {
        let scope = CancelScope::from_generation(u32::MAX - 1);
        let final_usable = scope
            .snapshot()
            .expect("the final usable generation must still be snapshotable");

        assert_eq!(scope.invalidate(), Err(super::GenerationExhausted));
        assert!(scope.is_stale(&final_usable));
        assert!(matches!(
            scope.snapshot(),
            Err(super::GenerationExhausted)
        ));
        assert_eq!(scope.invalidate(), Err(super::GenerationExhausted));
        assert!(scope.is_stale(&final_usable));
    }
}
