//! GR-04 deferred: RAII stream wrapper for circuit-breaker coverage of
//! `Provider::stream`.
//!
//! # Design — Option B: `run_stream_with_breaker`
//!
//! `run_with_breaker` works for `complete` because the future resolves to a
//! single `Result<T>`.  For streams the permit must span the entire lazy
//! iteration, not just the construction of the `ChunkStream` box.
//!
//! **Option B** — a thin helper that:
//!   1. Acquires the `OwnedPermit` synchronously before the stream is built
//!      (fast-fails when the breaker is Open).
//!   2. Wraps the inner `ChunkStream` in a `StreamGuard` that holds the
//!      permit and finalises it on completion or drop.
//!   3. Returns the wrapped `ChunkStream` so every call site is a one-liner.
//!
//! Option A (implementing `futures::Stream` directly on a struct) requires
//! `pin-project` and forces each provider to carry the guard generically.
//! Option B keeps the inner stream as an opaque `ChunkStream` and composes
//! via a single wrapper type — cleaner at three call sites, zero generics
//! leaked into providers.

use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::Result;
use futures_util::Stream;

use super::circuit_breaker::acquire_for;
use super::{ChunkStream, CompletionChunk};

// ── StreamGuard ──────────────────────────────────────────────────────────────

/// Wraps an inner `ChunkStream` and holds an `OwnedPermit` for the lifetime of
/// the stream.  Settles the breaker on the first terminal event:
///
/// - `Poll::Ready(Some(Ok(chunk)))` where `chunk.done == true` → success
/// - `Poll::Ready(Some(Err(_)))` → failure (first error chunk only)
/// - `Poll::Ready(None)` (stream exhausted without a done chunk) → failure
/// - `Drop` before any of the above fires → failure (via `OwnedPermit`'s own
///   `Drop` impl, which calls `record_failure_inner` when `settled == false`)
///
/// The `OwnedPermit` already has a `Drop` impl that records failure when
/// `settled == false`, so premature consumer drops are covered for free.
#[pin_project::pin_project(PinnedDrop)]
pub struct StreamGuard {
    #[pin]
    inner: ChunkStream,
    /// `None` once the permit has been settled (success or failure).
    permit: Option<super::circuit_breaker::OwnedPermit>,
}

impl Stream for StreamGuard {
    type Item = Result<CompletionChunk>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();

        match this.inner.poll_next(cx) {
            Poll::Pending => Poll::Pending,

            // ── done chunk: success ──────────────────────────────────────────
            Poll::Ready(Some(Ok(chunk))) if chunk.done => {
                if let Some(permit) = this.permit.take() {
                    permit.record_success();
                }
                Poll::Ready(Some(Ok(chunk)))
            }

            // ── non-done chunk: pass through, no settle yet ──────────────────
            Poll::Ready(Some(Ok(chunk))) => Poll::Ready(Some(Ok(chunk))),

            // ── error chunk: failure, first occurrence only ──────────────────
            Poll::Ready(Some(Err(e))) => {
                if let Some(permit) = this.permit.take() {
                    permit.record_failure();
                }
                Poll::Ready(Some(Err(e)))
            }

            // ── stream exhausted without done chunk: failure ─────────────────
            Poll::Ready(None) => {
                if let Some(permit) = this.permit.take() {
                    permit.record_failure();
                }
                Poll::Ready(None)
            }
        }
    }
}

#[pin_project::pinned_drop]
impl PinnedDrop for StreamGuard {
    fn drop(self: Pin<&mut Self>) {
        // `OwnedPermit::drop` already records failure when !settled.
        // We just need to drop `permit` here; the field drop handles it.
        // Explicit take() silences the `must_use` lint.
        let this = self.project();
        drop(this.permit.take());
    }
}

// ── Public helper — the one-liner used at every stream call site ─────────────

/// Acquire the circuit-breaker permit for `provider_id`, then wrap the
/// `ChunkStream` produced by `stream_fut` so the permit is settled when the
/// stream terminates.
///
/// Fast-fails (before building the stream) when the breaker is Open.
///
/// # Usage at a stream call site
/// ```ignore
/// async fn stream(&self, req: Request) -> Result<ChunkStream> {
///     run_stream_with_breaker("claude_cli", async move {
///         // existing body that returns Result<ChunkStream>
///         let inner: ChunkStream = ...;
///         Ok(inner)
///     }).await
/// }
/// ```
pub async fn run_stream_with_breaker<F>(provider_id: &str, stream_fut: F) -> Result<ChunkStream>
where
    F: std::future::Future<Output = Result<ChunkStream>>,
{
    // 1. Acquire permit before touching the provider (fast-fail if Open).
    let permit = acquire_for(provider_id)
        .map_err(|e| anyhow::anyhow!("circuit breaker open for {provider_id}: {e}"))?;

    // 2. Build the inner stream; if construction fails, drop the permit
    //    (OwnedPermit::drop records failure).
    let inner = stream_fut.await?;

    // 3. Wrap with the guard that carries the permit across lazy iteration.
    let guard = StreamGuard {
        inner,
        permit: Some(permit),
    };

    Ok(Box::pin(guard))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::CompletionChunk;
    use crate::providers::circuit_breaker::GLOBAL;
    use futures_util::StreamExt;
    use futures_util::stream as fstream;

    fn unique_provider_id(suffix: &str) -> String {
        format!("gr04stream-{}-{}", suffix, crate::time::now_unix_ns_u128())
    }

    fn consecutive_failures(id: &str) -> u32 {
        GLOBAL
            .snapshot_all()
            .into_iter()
            .find(|(k, _)| k == id)
            .map(|(_, s)| s.consecutive_failures)
            .unwrap_or(0)
    }

    fn chunk(delta: &str, done: bool) -> CompletionChunk {
        CompletionChunk {
            delta: delta.into(),
            done,
            input_tokens: None,
            output_tokens: None,
        }
    }

    #[tokio::test]
    async fn stream_guard_records_success_on_done_chunk() {
        let id = unique_provider_id("ok");
        let inner: ChunkStream = Box::pin(fstream::iter(vec![
            Ok(chunk("hi", false)),
            Ok(chunk("", true)),
        ]));
        let mut s = run_stream_with_breaker(&id, async { Ok::<_, anyhow::Error>(inner) })
            .await
            .expect("admitted");
        // Drain the stream — done-chunk arrives, permit settles success.
        while s.next().await.is_some() {}
        assert_eq!(
            consecutive_failures(&id),
            0,
            "done-chunk path must NOT record a failure"
        );
    }

    #[tokio::test]
    async fn stream_guard_records_failure_on_err_chunk() {
        let id = unique_provider_id("err");
        let inner: ChunkStream = Box::pin(fstream::iter(vec![
            Ok(chunk("partial", false)),
            Err(anyhow::anyhow!("upstream blew up")),
        ]));
        let mut s = run_stream_with_breaker(&id, async { Ok::<_, anyhow::Error>(inner) })
            .await
            .expect("admitted");
        while s.next().await.is_some() {}
        assert!(
            consecutive_failures(&id) >= 1,
            "err-chunk path must record a failure"
        );
    }

    #[tokio::test]
    async fn stream_guard_records_failure_on_premature_drop() {
        let id = unique_provider_id("drop");
        let inner: ChunkStream = Box::pin(fstream::iter(vec![Ok(chunk("first", false))]));
        let mut s = run_stream_with_breaker(&id, async { Ok::<_, anyhow::Error>(inner) })
            .await
            .expect("admitted");
        // Consume just one chunk, then drop the stream — never reaches
        // a done-chunk; permit's Drop records failure.
        let _ = s.next().await;
        drop(s);
        assert!(
            consecutive_failures(&id) >= 1,
            "premature-drop path must record a failure via OwnedPermit::drop"
        );
    }

    #[tokio::test]
    async fn stream_guard_records_failure_on_exhausted_without_done() {
        let id = unique_provider_id("exhaust");
        let inner: ChunkStream = Box::pin(fstream::iter(vec![
            Ok(chunk("only", false)), // no done chunk follows
        ]));
        let mut s = run_stream_with_breaker(&id, async { Ok::<_, anyhow::Error>(inner) })
            .await
            .expect("admitted");
        while s.next().await.is_some() {}
        // Stream returned Poll::Ready(None) without a done — failure.
        assert!(
            consecutive_failures(&id) >= 1,
            "exhausted-without-done must record a failure"
        );
    }

    #[tokio::test]
    async fn run_stream_with_breaker_fast_fails_when_open() {
        let id = unique_provider_id("trip");
        // Trip the breaker via the synchronous path. Default
        // BreakerConfig threshold is 5 failures.
        for _ in 0..6 {
            let _ = crate::providers::circuit_breaker::run_with_breaker(&id, async {
                Err::<(), _>(anyhow::anyhow!("fail"))
            })
            .await;
        }
        // The stream-future MUST NOT be polled when the breaker is Open.
        // `ChunkStream` is a trait object so it doesn't impl Debug; use
        // pattern matching instead of `expect_err`.
        let r = run_stream_with_breaker(&id, async {
            panic!("stream_fut polled despite Open circuit");
            #[allow(unreachable_code)]
            Ok::<_, anyhow::Error>(
                Box::pin(fstream::iter(Vec::<Result<CompletionChunk>>::new())) as ChunkStream,
            )
        })
        .await;
        let err = match r {
            Ok(_) => panic!("Open circuit must reject"),
            Err(e) => e,
        };
        assert!(format!("{err}").contains("circuit breaker open"));
        assert!(format!("{err}").contains(&id));
    }

    #[tokio::test]
    async fn run_stream_with_breaker_construction_failure_records_failure() {
        let id = unique_provider_id("ctor");
        let r = run_stream_with_breaker(&id, async {
            Err::<ChunkStream, _>(anyhow::anyhow!("could not build stream"))
        })
        .await;
        assert!(r.is_err());
        assert!(
            consecutive_failures(&id) >= 1,
            "construction-failure must record via OwnedPermit::drop"
        );
    }
}
