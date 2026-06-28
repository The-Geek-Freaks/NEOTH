//! SPEC-03b — per-provider HTTP-429 fallback chain (decorator).
//!
//! A `FallbackProvider` wraps an ordered `Vec<Box<dyn Provider>>` —
//! `[0]` is the primary, `[1..]` the operator-configured fallbacks — and
//! implements `Provider` itself. When the primary's `complete()` returns
//! `QuotaError` (HTTP 429), it transparently tries each fallback in order.
//!
//! ## Why a decorator (4-lens gremium design, 2026-05-30)
//!
//! The retry lives entirely inside `complete()`, so the three QuotaError
//! handling sites in `cli/chat.rs` are UNCHANGED — the chat dispatch still
//! sees one `&dyn Provider`. The chain is built once at construction
//! (`providers::fallback_chain_from_config`), not threaded through the hot
//! path. Empty chain ⇒ the caller hands back the bare primary, so there is
//! zero overhead + zero behaviour change for operators with no `fallback:`
//! config.
//!
//! ## Hard rules the gremium flagged
//!
//! - **429-only.** Fallback fires ONLY on `QuotaError`. A non-quota error
//!   propagates immediately — masking a real outage as failover would
//!   hide the problem AND contaminate the circuit breaker's signal.
//! - **Consent is enforced upstream**, in `fallback_chain_from_config`:
//!   a cloud fallback the operator never consented to is never even built
//!   into the chain. By the time a `Box<dyn Provider>` reaches this
//!   decorator it has already passed the consent gate.
//! - **Bounded.** `max_hops` caps the fallback attempts (cycle + retry-
//!   storm guard); candidates already in `QuotaTracker` backoff are
//!   skipped via a cheap in-memory pre-flight.
//! - **Streams don't fall over.** A partially-consumed stream cannot be
//!   rewound onto a second provider, so `stream()` delegates to the
//!   primary only (documented follow-on).

use anyhow::Result;
use async_trait::async_trait;

use super::quota::{QuotaError, QuotaTracker};
use super::{ChunkStream, Completion, Provider, Request};

/// Ordered primary + fallbacks. See module docs.
pub struct FallbackProvider {
    /// `[0]` = primary; `[1..]` = ordered fallbacks. Non-empty.
    chain: Vec<Box<dyn Provider>>,
    /// Hard cap on fallback hops (does not count the primary attempt).
    max_hops: u8,
    /// SPEC-03b — optional WAL writer for the `0x25
    /// PROVIDER_FALLBACK_ATTEMPTED` audit frame, emitted at each hop so a
    /// 429-driven provider switch is durably auditable (the trust claim).
    /// `None` on the CLI one-shot path (the operator is present + sees the
    /// `tracing::warn!`; the writer is created below this provider in the
    /// chat call stack). The daemon (`cli::serve`) threads its live writer
    /// in, so the unattended channel/cron path — where prompts actually
    /// "wander" between providers — is the one that gets the durable frame.
    wal_writer: Option<crate::wal::writer::WalWriterHandle>,
}

/// What to do with one fallback candidate. Extracted as a pure decision so
/// the hop-accounting contract is unit-testable without disk/async/env —
/// the `Skip` arm must NOT consume a hop slot (see [`FallbackProvider::decide_hop`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HopAction {
    /// Candidate is in a 429 backoff window — skip it WITHOUT spending a hop.
    Skip,
    /// Attempt this candidate; the caller advances the hop counter.
    Attempt,
    /// Hop cap reached — stop walking the chain, surface the last 429.
    Stop,
}

impl FallbackProvider {
    pub fn new(
        chain: Vec<Box<dyn Provider>>,
        max_hops: u8,
        wal_writer: Option<crate::wal::writer::WalWriterHandle>,
    ) -> Self {
        // `assert!` (not `debug_assert!`) so the invariant holds in release
        // too — `stream()` does `.first().expect(..)` and would otherwise
        // hard-panic on an empty chain in a release binary.
        assert!(
            !chain.is_empty(),
            "FallbackProvider chain must be non-empty (primary at [0])"
        );
        Self {
            chain,
            max_hops,
            wal_writer,
        }
    }

    /// Per-candidate hop decision for a fallback slot (`i > 0`). A candidate
    /// already in a 429 backoff window is skipped *without* consuming a hop
    /// (`hops_used` unchanged) — otherwise two backed-off slots would burn
    /// the whole `max_hops` budget and starve a healthy slot behind them.
    /// Only an actual attempt advances `hops_used`; `hops_used + 1 > max_hops`
    /// stops the walk.
    fn decide_hop(in_backoff: bool, hops_used: u8, max_hops: u8) -> HopAction {
        if in_backoff {
            return HopAction::Skip;
        }
        if hops_used.saturating_add(1) > max_hops {
            return HopAction::Stop;
        }
        HopAction::Attempt
    }

    fn is_quota_error(e: &anyhow::Error) -> bool {
        e.downcast_ref::<QuotaError>().is_some()
    }

    fn now_unix() -> u64 {
        crate::time::now_unix_secs()
    }
}

#[async_trait]
impl Provider for FallbackProvider {
    fn name(&self) -> &'static str {
        self.chain.first().map(|p| p.name()).unwrap_or("fallback")
    }

    async fn complete(&self, req: Request) -> Result<Completion> {
        let quota_path = crate::config::FreedomConfig::default_neoth_home().join("quota.json");
        let now = Self::now_unix();
        // Lazy: the QuotaTracker is only read when we actually reach a
        // fallback candidate, so the common primary-success path pays ZERO
        // disk I/O. `load_from` degrades OPEN on an unreadable/corrupt file
        // (empty tracker + its own `warn!`) — the storm guard becomes a
        // no-op but a legitimate 429 failover still proceeds; we never
        // block failover because the quota file could not be read.
        let mut tracker: Option<QuotaTracker> = None;
        let mut last_err: Option<anyhow::Error> = None;
        let mut hops = 0u8;

        for (i, candidate) in self.chain.iter().enumerate() {
            if i > 0 {
                // Fallback hop. Load the tracker on first use (see above).
                let tracker = tracker.get_or_insert_with(|| QuotaTracker::load_from(&quota_path));
                let in_backoff = tracker
                    .backoff_remaining_for(candidate.name(), now)
                    .is_some();
                match Self::decide_hop(in_backoff, hops, self.max_hops) {
                    HopAction::Skip => {
                        // In a 429 backoff window — skip WITHOUT spending a
                        // hop, so a healthy slot behind it stays reachable.
                        tracing::warn!(
                            provider = candidate.name(),
                            "fallback skipped: provider in quota backoff"
                        );
                        continue;
                    }
                    HopAction::Stop => {
                        tracing::warn!(
                            max_hops = self.max_hops,
                            "fallback chain hop cap reached — surfacing the last 429"
                        );
                        break;
                    }
                    HopAction::Attempt => {
                        // Only an actual attempt consumes a hop slot.
                        hops += 1;
                        tracing::warn!(
                            from = self.chain[0].name(),
                            to = candidate.name(),
                            hop = hops,
                            "provider failover on 429"
                        );
                        // SPEC-03b — durable audit of the hop (0x25). Emitted
                        // only when a writer is wired (daemon path); the CLI
                        // one-shot path passes None. Best-effort: an audit
                        // append failure must NEVER block the failover.
                        if let Some(w) = &self.wal_writer {
                            let payload = serde_json::json!({
                                "from_provider": self.chain[0].name(),
                                "to_provider": candidate.name(),
                                "reason": "quota_429",
                                "hop": hops,
                                // Same field + encoding (u64) as the
                                // PROVIDER_REQUEST (0x20) frame, so an operator
                                // can correlate the hop with the turn.
                                "prompt_hash_xxh3": xxhash_rust::xxh3::xxh3_64(req.prompt.as_bytes()),
                                "ts_unix": now,
                            });
                            match serde_json::to_vec(&payload) {
                                Ok(bytes) => {
                                    let header = crate::wal::make_header(
                                        crate::wal::events::EVENT_TYPE_PROVIDER_FALLBACK_ATTEMPTED,
                                        &bytes,
                                    );
                                    if let Err(e) = w.append(header, bytes).await {
                                        tracing::warn!(
                                            error = %e,
                                            "fallback audit frame (0x25) append failed; \
                                             failover proceeds"
                                        );
                                    }
                                }
                                Err(e) => tracing::warn!(
                                    error = %e,
                                    "fallback audit frame (0x25) serialize failed; \
                                     failover proceeds"
                                ),
                            }
                        }
                    }
                }
            }
            match candidate.complete(req.clone()).await {
                Ok(c) => return Ok(c),
                // 429 → try the next candidate.
                Err(e) if Self::is_quota_error(&e) => {
                    last_err = Some(e);
                    continue;
                }
                // Non-quota error → propagate immediately (do not mask a
                // real failure as failover; only 429 chains).
                Err(e) => return Err(e),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            anyhow::anyhow!(
                "fallback chain exhausted: every provider returned 429 or was in backoff"
            )
        }))
    }

    async fn stream(&self, req: Request) -> Result<ChunkStream> {
        // No fallback on streams — a partially-consumed stream cannot be
        // rewound + re-issued against a second provider. The primary's 429
        // surfaces unchanged; the operator switches to non-stream or waits
        // out the backoff. Stream fallback is a documented follow-on.
        self.chain
            .first()
            .expect("FallbackProvider chain is non-empty")
            .stream(req)
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[derive(Clone, Copy)]
    enum Behavior {
        Ok,
        Quota,
        Other,
    }

    struct MockProvider {
        name: &'static str,
        behavior: Behavior,
    }

    #[async_trait]
    impl Provider for MockProvider {
        fn name(&self) -> &'static str {
            self.name
        }
        async fn complete(&self, _req: Request) -> Result<Completion> {
            match self.behavior {
                Behavior::Ok => Ok(Completion {
                    text: format!("ok:{}", self.name),
                    model: "mock".into(),
                    latency: Duration::from_millis(1),
                    input_tokens: None,
                    output_tokens: None,
                    cache_creation_tokens: None,
                    cache_read_tokens: None,
                }),
                Behavior::Quota => Err(anyhow::Error::new(QuotaError {
                    provider: self.name,
                    retry_after: None,
                    body: String::new(),
                })),
                Behavior::Other => Err(anyhow::anyhow!("non-quota failure from {}", self.name)),
            }
        }
    }

    fn mock(name: &'static str, behavior: Behavior) -> Box<dyn Provider> {
        Box::new(MockProvider { name, behavior })
    }

    #[tokio::test]
    async fn primary_ok_returns_primary_no_fallback() {
        let fp = FallbackProvider::new(
            vec![mock("primary", Behavior::Ok), mock("fb", Behavior::Ok)],
            2,
            None,
        );
        let c = fp.complete(Request::default()).await.unwrap();
        assert_eq!(c.text, "ok:primary");
        assert_eq!(fp.name(), "primary");
    }

    #[tokio::test]
    async fn primary_429_falls_over_to_fallback() {
        let fp = FallbackProvider::new(
            vec![mock("primary", Behavior::Quota), mock("fb", Behavior::Ok)],
            2,
            None,
        );
        let c = fp.complete(Request::default()).await.unwrap();
        assert_eq!(c.text, "ok:fb", "fallback must answer when primary 429s");
    }

    /// Decode the first `0x25 PROVIDER_FALLBACK_ATTEMPTED` payload from an
    /// uncompressed WAL segment (test writer uses the plain `spawn`).
    fn first_fallback_payload(seg: &std::path::Path) -> Option<serde_json::Value> {
        let bytes = std::fs::read(seg).ok()?;
        let hdr = crate::wal::segment_header::parse_segment_header(&bytes).ok()?;
        let mut cursor = hdr.header_len();
        while cursor < bytes.len() {
            let dec = crate::wal::frame::decode_frame(&bytes[cursor..]).ok()?;
            if dec.header.event_type == crate::wal::events::EVENT_TYPE_PROVIDER_FALLBACK_ATTEMPTED {
                return serde_json::from_slice(dec.payload).ok();
            }
            let total = dec.header.total_len as usize;
            if total == 0 {
                break;
            }
            cursor = cursor.saturating_add(total);
        }
        None
    }

    #[tokio::test]
    async fn fallback_hop_emits_audit_frame_when_writer_wired() {
        // SPEC-03b trust claim: a 429 hop with a writer present emits a
        // durable 0x25 frame recording from/to/reason/hop + a prompt hash
        // that correlates with the PROVIDER_REQUEST (0x20) frame.
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("fb.wal");
        let (writer, join) = crate::wal::writer::spawn(seg.clone()).unwrap();
        let fp = FallbackProvider::new(
            vec![mock("primary", Behavior::Quota), mock("fb", Behavior::Ok)],
            2,
            Some(writer.clone()),
        );
        let req = Request {
            prompt: "hello".into(),
            ..Default::default()
        };
        let c = fp.complete(req).await.unwrap();
        assert_eq!(c.text, "ok:fb");
        // Flush: drop both writer handles so the writer task drains + exits.
        drop(fp);
        drop(writer);
        let _ = join.await;

        let payload = first_fallback_payload(&seg).expect("0x25 frame must be emitted on a hop");
        assert_eq!(payload["from_provider"], "primary");
        assert_eq!(payload["to_provider"], "fb");
        assert_eq!(payload["reason"], "quota_429");
        assert_eq!(payload["hop"], 1);
        assert_eq!(
            payload["prompt_hash_xxh3"].as_u64().unwrap(),
            xxhash_rust::xxh3::xxh3_64(b"hello"),
            "prompt hash must correlate with the PROVIDER_REQUEST frame"
        );
    }

    #[tokio::test]
    async fn primary_ok_emits_no_audit_frame() {
        // No hop taken → no 0x25 frame even with a writer wired.
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("fb.wal");
        let (writer, join) = crate::wal::writer::spawn(seg.clone()).unwrap();
        let fp = FallbackProvider::new(
            vec![mock("primary", Behavior::Ok), mock("fb", Behavior::Ok)],
            2,
            Some(writer.clone()),
        );
        let c = fp.complete(Request::default()).await.unwrap();
        assert_eq!(c.text, "ok:primary");
        drop(fp);
        drop(writer);
        let _ = join.await;
        assert!(
            first_fallback_payload(&seg).is_none(),
            "no hop → no 0x25 frame"
        );
    }

    #[tokio::test]
    async fn non_quota_error_propagates_without_fallback() {
        // primary fails with a NON-429 error → must NOT fall over; the
        // fallback (which would succeed) is never tried.
        let fp = FallbackProvider::new(
            vec![mock("primary", Behavior::Other), mock("fb", Behavior::Ok)],
            2,
            None,
        );
        let err = fp.complete(Request::default()).await.unwrap_err();
        assert!(err.to_string().contains("non-quota failure from primary"));
    }

    #[tokio::test]
    async fn all_429_returns_exhausted_error() {
        let fp = FallbackProvider::new(
            vec![
                mock("primary", Behavior::Quota),
                mock("fb1", Behavior::Quota),
            ],
            2,
            None,
        );
        let err = fp.complete(Request::default()).await.unwrap_err();
        // The last error surfaced is a QuotaError (fb1's), downcastable.
        assert!(err.downcast_ref::<QuotaError>().is_some());
    }

    #[tokio::test]
    async fn max_hops_caps_fallback_attempts() {
        // primary 429, fb1 429, fb2 Ok — but max_hops = 1 means only fb1
        // is tried (hop 1); fb2 (hop 2) is past the cap, so the Ok at
        // position 2 is NEVER reached → exhausted error.
        let fp = FallbackProvider::new(
            vec![
                mock("primary", Behavior::Quota),
                mock("fb1", Behavior::Quota),
                mock("fb2", Behavior::Ok),
            ],
            1,
            None,
        );
        assert!(
            fp.complete(Request::default()).await.is_err(),
            "max_hops=1 must not reach the Ok provider at hop 2"
        );

        // Same chain, max_hops = 2 → fb2 IS reached + answers.
        let fp2 = FallbackProvider::new(
            vec![
                mock("primary", Behavior::Quota),
                mock("fb1", Behavior::Quota),
                mock("fb2", Behavior::Ok),
            ],
            2,
            None,
        );
        assert_eq!(
            fp2.complete(Request::default()).await.unwrap().text,
            "ok:fb2"
        );
    }

    #[test]
    fn decide_hop_skips_backoff_without_consuming_a_hop() {
        // The regression guard for the increment-before-skip bug: a slot in
        // backoff is skipped REGARDLESS of the hop budget, and (crucially)
        // the caller leaves `hops_used` untouched on Skip — so the very next
        // healthy slot still gets an Attempt even at max_hops=1.
        assert_eq!(
            FallbackProvider::decide_hop(true, 0, 1),
            HopAction::Skip,
            "in-backoff slot must skip"
        );
        assert_eq!(
            FallbackProvider::decide_hop(true, 5, 1),
            HopAction::Skip,
            "backoff skip ignores the hop budget entirely"
        );
        // After a backoff skip kept hops_used at 0, the next healthy slot is
        // still attemptable under max_hops=1 — the bug made this a Stop.
        assert_eq!(
            FallbackProvider::decide_hop(false, 0, 1),
            HopAction::Attempt
        );
    }

    #[test]
    fn decide_hop_caps_actual_attempts_at_max_hops() {
        assert_eq!(
            FallbackProvider::decide_hop(false, 0, 2),
            HopAction::Attempt
        );
        assert_eq!(
            FallbackProvider::decide_hop(false, 1, 2),
            HopAction::Attempt
        );
        // hops_used == max_hops → the next attempt would be hop 3 > 2.
        assert_eq!(FallbackProvider::decide_hop(false, 2, 2), HopAction::Stop);
        // max_hops = 0 → no fallback attempt is ever allowed.
        assert_eq!(FallbackProvider::decide_hop(false, 0, 0), HopAction::Stop);
    }
}
