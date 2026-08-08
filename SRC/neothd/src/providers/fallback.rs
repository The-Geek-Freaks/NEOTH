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

use anyhow::{Context, Result};
use async_trait::async_trait;
use futures_util::StreamExt;
use std::path::PathBuf;

use super::quota::{QuotaError, QuotaTracker};
use super::{
    ChunkStream, Completion, Provider, ProviderDispatchPermit, ProviderRequestControls, Request,
};

/// Ordered primary + fallbacks. See module docs.
pub struct FallbackProvider {
    /// `[0]` = primary; `[1..]` = ordered fallbacks. Non-empty.
    chain: Vec<Box<dyn Provider>>,
    /// Configured model for each candidate. `Request.model`, when present,
    /// belongs to the primary only; every fallback resolves its own configured
    /// or adapter-default model before its separate leaf authorization.
    configured_models: Vec<Option<String>>,
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
    /// Operator-scoped quota state. Bound at construction so a custom config
    /// home cannot accidentally read the default operator's backoff state.
    quota_path: PathBuf,
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
    fn stamp_stream_route(stream: ChunkStream, slot: usize) -> ChunkStream {
        Box::pin(stream.map(move |item| {
            item.and_then(|mut chunk| {
                chunk.identity.prepend_dispatch_slot(slot)?;
                Ok(chunk)
            })
        }))
    }

    pub fn new(
        chain: Vec<Box<dyn Provider>>,
        max_hops: u8,
        wal_writer: Option<crate::wal::writer::WalWriterHandle>,
    ) -> Self {
        let configured_models = vec![None; chain.len()];
        Self::new_with_models(chain, configured_models, max_hops, wal_writer)
    }

    pub fn new_with_models(
        chain: Vec<Box<dyn Provider>>,
        configured_models: Vec<Option<String>>,
        max_hops: u8,
        wal_writer: Option<crate::wal::writer::WalWriterHandle>,
    ) -> Self {
        let quota_path = crate::config::FreedomConfig::default_neoth_home().join("quota.json");
        Self::new_with_models_at(chain, configured_models, max_hops, wal_writer, quota_path)
    }

    pub fn new_with_models_at(
        chain: Vec<Box<dyn Provider>>,
        configured_models: Vec<Option<String>>,
        max_hops: u8,
        wal_writer: Option<crate::wal::writer::WalWriterHandle>,
        quota_path: PathBuf,
    ) -> Self {
        // `assert!` (not `debug_assert!`) so the invariant holds in release
        // too — `stream()` does `.first().expect(..)` and would otherwise
        // hard-panic on an empty chain in a release binary.
        assert!(
            !chain.is_empty(),
            "FallbackProvider chain must be non-empty (primary at [0])"
        );
        assert_eq!(
            chain.len(),
            configured_models.len(),
            "FallbackProvider model metadata must match the provider chain"
        );
        Self {
            chain,
            configured_models,
            max_hops,
            wal_writer,
            quota_path,
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

    async fn append_audit_event(
        &self,
        authorizer: Option<&crate::providers::cost_authorization::ProviderCallAuthorizer>,
        event_type: u8,
        value: serde_json::Value,
        context: &'static str,
    ) -> Result<()> {
        // Authorized dispatches must use the authorizer's lifecycle writer.
        // The decorator-local writer is only the best-effort sink for raw
        // dispatch, and the two are deliberately never written together.
        if authorizer.is_none() && self.wal_writer.is_none() {
            return Ok(());
        }
        let payload = match serde_json::to_vec(&value) {
            Ok(payload) => payload,
            Err(error) if authorizer.is_some() => {
                return Err(error).with_context(|| context);
            }
            Err(error) => {
                tracing::warn!(error = %error, context, "fallback audit serialization failed");
                return Ok(());
            }
        };
        if let Some(authorizer) = authorizer {
            return authorizer
                .append_required_auxiliary_event(event_type, payload, context)
                .await;
        }
        if let Some(writer) = &self.wal_writer {
            let header = crate::wal::HeaderBuilder::new(event_type, &payload).build();
            if let Err(error) = writer.append(header, payload).await {
                tracing::warn!(
                    error = %error,
                    context,
                    "fallback audit append failed; raw dispatch proceeds"
                );
            }
        }
        Ok(())
    }

    async fn persist_quota_error(
        &self,
        provider_name: &'static str,
        retry_after: Option<std::time::Duration>,
        now: u64,
        audit_authorizer: Option<&crate::providers::cost_authorization::ProviderCallAuthorizer>,
    ) -> Result<QuotaTracker> {
        let (snapshot, effective, state) = QuotaTracker::update_at(&self.quota_path, |tracker| {
            let effective = tracker.record_429(provider_name, retry_after, now);
            let state = tracker.get(provider_name).cloned();
            Ok((tracker.clone(), effective, state))
        })
        .with_context(|| {
            format!(
                "persist fallback quota state for `{provider_name}` at {}",
                self.quota_path.display()
            )
        })?;

        self.append_audit_event(
            audit_authorizer,
            crate::wal::events::EVENT_TYPE_PROVIDER_QUOTA_EXCEEDED,
            serde_json::json!({
                "provider": provider_name,
                "retry_after_secs": effective.as_secs(),
                "requests_today": state.as_ref().map(|value| value.requests_today),
                "daily_cap": state.as_ref().and_then(|value| value.estimated_daily_cap),
                "backoff_until_unix": state.as_ref().and_then(|value| value.backoff_until_unix),
                "source": "fallback_candidate",
                "ts_unix": now,
            }),
            "fallback quota state persisted but required WAL audit failed",
        )
        .await?;
        tracing::warn!(
            provider = provider_name,
            retry_after_secs = effective.as_secs(),
            "fallback candidate returned HTTP 429; durable backoff recorded"
        );
        Ok(snapshot)
    }

    fn request_for_candidate(
        &self,
        index: usize,
        candidate: &dyn Provider,
        base: &Request,
    ) -> Result<Request> {
        let mut req = base.clone();
        // An explicit caller model belongs to the primary request only. Every
        // fallback slot has its own configured/default model and must never
        // inherit a model id from a different provider.
        req.model = if index == 0 {
            base.model
                .clone()
                .or_else(|| self.configured_models[index].clone())
                .or_else(|| candidate.default_model().map(str::to_owned))
        } else {
            self.configured_models[index]
                .clone()
                .or_else(|| candidate.default_model().map(str::to_owned))
        };
        if req.model.is_none() {
            anyhow::bail!(
                "fallback candidate `{}` has no configured or declared default model",
                candidate.name()
            );
        }
        Ok(req)
    }

    async fn complete_with_authorization(
        &self,
        req: Request,
        authorization: Option<(
            &crate::providers::cost_authorization::ProviderCallAuthorizer,
            &'static str,
        )>,
        raw_permit: Option<&ProviderDispatchPermit>,
    ) -> Result<Completion> {
        let mut tracker = QuotaTracker::load_from(&self.quota_path)
            .with_context(|| format!("load fallback quota state {}", self.quota_path.display()))?;
        let mut last_err: Option<anyhow::Error> = None;
        let mut hops = 0u8;
        let mut shortest_active_backoff: Option<u64> = None;

        for (i, candidate) in self.chain.iter().enumerate() {
            let preflight_now = Self::now_unix();
            let backoff_remaining = if candidate.handles_nonstream_quota_backoff() {
                None
            } else {
                tracker.backoff_remaining_for(candidate.name(), preflight_now)
            };
            if let Some(remaining) = backoff_remaining {
                shortest_active_backoff =
                    Some(shortest_active_backoff.map_or(remaining, |known| known.min(remaining)));
            }
            let in_backoff = backoff_remaining.is_some();
            if i == 0 && in_backoff {
                tracing::warn!(
                    provider = candidate.name(),
                    "primary provider skipped: durable quota backoff active"
                );
                continue;
            }
            if i > 0 {
                match Self::decide_hop(in_backoff, hops, self.max_hops) {
                    HopAction::Skip => {
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
                        hops += 1;
                        tracing::warn!(
                            from = self.chain[0].name(),
                            to = candidate.name(),
                            hop = hops,
                            "provider failover on 429"
                        );
                        self.append_audit_event(
                            authorization.map(|(authorizer, _)| authorizer),
                            crate::wal::events::EVENT_TYPE_PROVIDER_FALLBACK_ATTEMPTED,
                            serde_json::json!({
                                "from_provider": self.chain[0].name(),
                                "to_provider": candidate.name(),
                                "reason": "quota_429",
                                "hop": hops,
                                "prompt_hash_xxh3": xxhash_rust::xxh3::xxh3_64(req.prompt.as_bytes()),
                                "ts_unix": preflight_now,
                            }),
                            "fallback audit frame (0x25) failed; candidate call blocked",
                        )
                        .await?;
                    }
                }
            }

            let candidate_req = self.request_for_candidate(i, candidate.as_ref(), &req)?;
            let result = match authorization {
                Some((authorizer, call_scope)) => {
                    candidate
                        .complete_authorized(candidate_req, authorizer, call_scope)
                        .await
                }
                None => {
                    candidate
                        .complete_raw(
                            candidate_req,
                            raw_permit.expect("raw fallback dispatch requires a permit"),
                        )
                        .await
                }
            };
            match result {
                Ok(mut completion) => {
                    completion.identity.prepend_dispatch_slot(i)?;
                    return Ok(completion);
                }
                Err(error) if Self::is_quota_error(&error) => {
                    if candidate.handles_nonstream_quota_backoff() {
                        // A nested routing decorator already persisted and
                        // audited its concrete leaf. The outer chain may move
                        // on, but must not relabel or double-record that 429.
                        last_err = Some(error);
                        continue;
                    }
                    let quota = error
                        .downcast_ref::<QuotaError>()
                        .expect("quota-error branch must contain QuotaError");
                    if quota.provider != candidate.name() {
                        anyhow::bail!(
                            "fallback candidate `{}` returned quota state for mismatched provider `{}`",
                            candidate.name(),
                            quota.provider
                        );
                    }
                    let observed_at = Self::now_unix();
                    tracker = self
                        .persist_quota_error(
                            quota.provider,
                            quota.retry_after,
                            observed_at,
                            authorization.map(|(authorizer, _)| authorizer),
                        )
                        .await?;
                    last_err = Some(error);
                }
                Err(error) => return Err(error),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            if let Some(remaining) = shortest_active_backoff {
                anyhow::Error::new(QuotaError {
                    provider: self.name(),
                    retry_after: Some(std::time::Duration::from_secs(remaining)),
                    body: "fallback chain exhausted: every provider is in durable backoff"
                        .to_owned(),
                })
            } else {
                anyhow::anyhow!(
                    "fallback chain exhausted: every provider returned 429 or was in backoff"
                )
            }
        }))
    }
}

#[async_trait]
impl Provider for FallbackProvider {
    fn name(&self) -> &'static str {
        self.chain.first().map(|p| p.name()).unwrap_or("fallback")
    }

    fn request_controls(&self) -> ProviderRequestControls {
        let Some(first) = self.chain.first() else {
            return ProviderRequestControls::NONE;
        };
        self.chain
            .iter()
            .skip(1)
            .fold(first.request_controls(), |controls, provider| {
                controls.intersection(provider.request_controls())
            })
    }

    fn handles_nonstream_quota_backoff(&self) -> bool {
        true
    }

    fn preserves_inner_response_identity(&self) -> bool {
        true
    }

    fn validate_request_controls(&self, req: &Request) -> Result<()> {
        self.request_controls().validate(self.name(), req)?;
        for (index, candidate) in self.chain.iter().enumerate() {
            let candidate_req = self.request_for_candidate(index, candidate.as_ref(), req)?;
            candidate.validate_request_controls(&candidate_req)?;
        }
        Ok(())
    }

    fn default_model(&self) -> Option<&str> {
        self.configured_models
            .first()
            .and_then(Option::as_deref)
            .or_else(|| self.chain.first().and_then(|p| p.default_model()))
    }

    fn resolve_model_for_wire(&self, requested_model: &str) -> String {
        self.chain.first().map_or_else(
            || requested_model.to_owned(),
            |provider| provider.resolve_model_for_wire(requested_model),
        )
    }

    fn output_token_ceiling(&self, req: &Request) -> Option<u32> {
        self.chain
            .first()
            .and_then(|provider| provider.output_token_ceiling(req))
    }

    fn streams_on_wire(&self) -> bool {
        self.chain
            .first()
            .is_some_and(|provider| provider.streams_on_wire())
    }

    async fn complete_raw(
        &self,
        req: Request,
        permit: &ProviderDispatchPermit,
    ) -> Result<Completion> {
        self.complete_with_authorization(req, None, Some(permit))
            .await
    }

    async fn complete_authorized(
        &self,
        req: Request,
        authorizer: &crate::providers::cost_authorization::ProviderCallAuthorizer,
        call_scope: &'static str,
    ) -> Result<Completion> {
        self.complete_with_authorization(req, Some((authorizer, call_scope)), None)
            .await
    }

    async fn complete_authorized_pinned(
        &self,
        req: Request,
        expected: &super::CompletionIdentity,
        authorizer: &crate::providers::cost_authorization::ProviderCallAuthorizer,
        call_scope: &'static str,
    ) -> Result<Completion> {
        let Some(&slot) = expected.dispatch_route.first() else {
            anyhow::bail!(
                "fallback provider cannot replay `{}`/`{}` without a pinned chain slot",
                expected.provider,
                expected.wire_model
            );
        };
        let index = usize::from(slot);
        let candidate = self.chain.get(index).ok_or_else(|| {
            anyhow::anyhow!(
                "pinned fallback slot {index} is outside chain length {}",
                self.chain.len()
            )
        })?;
        let tracker = QuotaTracker::load_from(&self.quota_path)
            .with_context(|| format!("load fallback quota state {}", self.quota_path.display()))?;
        let now = Self::now_unix();
        if !candidate.handles_nonstream_quota_backoff()
            && let Some(remaining) = tracker.backoff_remaining_for(candidate.name(), now)
        {
            return Err(anyhow::Error::new(QuotaError {
                provider: candidate.name(),
                retry_after: Some(std::time::Duration::from_secs(remaining)),
                body: "durable pinned-leaf backoff active".to_owned(),
            }));
        }
        let child_expected = expected.child_identity_for_slot(index)?;
        let mut candidate_req = self.request_for_candidate(index, candidate.as_ref(), &req)?;
        candidate_req.model = Some(expected.wire_model.clone());
        let result = candidate
            .complete_authorized_pinned(candidate_req, &child_expected, authorizer, call_scope)
            .await;
        let mut completion = match result {
            Ok(completion) => completion,
            Err(error)
                if Self::is_quota_error(&error) && candidate.handles_nonstream_quota_backoff() =>
            {
                // Nested router owns the exact child-leaf quota state and has
                // already persisted it. Pinned recovery never hops.
                return Err(error);
            }
            Err(error) if Self::is_quota_error(&error) => {
                let quota = error
                    .downcast_ref::<QuotaError>()
                    .expect("quota-error branch must contain QuotaError");
                if quota.provider != candidate.name() {
                    anyhow::bail!(
                        "pinned fallback candidate `{}` returned quota state for mismatched provider `{}`",
                        candidate.name(),
                        quota.provider
                    );
                }
                let _persisted = self
                    .persist_quota_error(
                        quota.provider,
                        quota.retry_after,
                        Self::now_unix(),
                        Some(authorizer),
                    )
                    .await?;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        completion.identity.prepend_dispatch_slot(index)?;
        if completion.identity != *expected {
            anyhow::bail!(
                "pinned fallback recovery identity drifted from `{:?}` to `{:?}`",
                expected,
                completion.identity
            );
        }
        Ok(completion)
    }

    async fn stream_raw(
        &self,
        req: Request,
        permit: &ProviderDispatchPermit,
    ) -> Result<ChunkStream> {
        // No fallback on streams — a partially-consumed stream cannot be
        // rewound + re-issued against a second provider. The primary's 429
        // surfaces unchanged; the operator switches to non-stream or waits
        // out the backoff. Stream fallback is a documented follow-on.
        let primary = self
            .chain
            .first()
            .expect("FallbackProvider chain is non-empty");
        let req = self.request_for_candidate(0, primary.as_ref(), &req)?;
        let stream = primary.stream_raw(req, permit).await?;
        Ok(Self::stamp_stream_route(stream, 0))
    }

    async fn stream_authorized(
        &self,
        req: Request,
        authorizer: &crate::providers::cost_authorization::ProviderCallAuthorizer,
        call_scope: &'static str,
    ) -> Result<ChunkStream> {
        let primary = self
            .chain
            .first()
            .expect("FallbackProvider chain is non-empty");
        let req = self.request_for_candidate(0, primary.as_ref(), &req)?;
        let stream = primary
            .stream_authorized(req, authorizer, call_scope)
            .await?;
        Ok(Self::stamp_stream_route(stream, 0))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::providers::CompletionIdentity;

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
        fn default_model(&self) -> Option<&str> {
            Some(self.name)
        }
        async fn complete(&self, _req: Request) -> Result<Completion> {
            match self.behavior {
                Behavior::Ok => Ok(Completion {
                    termination: Default::default(),
                    text: format!("ok:{}", self.name),
                    identity: Default::default(),
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

    fn fallback_at(
        home: &std::path::Path,
        chain: Vec<Box<dyn Provider>>,
        max_hops: u8,
        wal_writer: Option<crate::wal::writer::WalWriterHandle>,
    ) -> FallbackProvider {
        let configured_models = vec![None; chain.len()];
        FallbackProvider::new_with_models_at(
            chain,
            configured_models,
            max_hops,
            wal_writer,
            home.join("quota.json"),
        )
    }

    #[tokio::test]
    async fn primary_ok_returns_primary_no_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let fp = fallback_at(
            dir.path(),
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
        let dir = tempfile::tempdir().unwrap();
        let fp = fallback_at(
            dir.path(),
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

    fn event_payloads(seg: &std::path::Path, event_type: u8) -> Vec<serde_json::Value> {
        let bytes = std::fs::read(seg).unwrap();
        let hdr = crate::wal::segment_header::parse_segment_header(&bytes).unwrap();
        let mut cursor = hdr.header_len();
        let mut payloads = Vec::new();
        while cursor < bytes.len() {
            let dec = crate::wal::frame::decode_frame(&bytes[cursor..]).unwrap();
            if dec.header.event_type == event_type {
                payloads.push(serde_json::from_slice(dec.payload).unwrap());
            }
            let total = dec.header.total_len as usize;
            if total == 0 {
                break;
            }
            cursor = cursor.saturating_add(total);
        }
        payloads
    }

    fn cost_payloads(seg: &std::path::Path) -> Vec<serde_json::Value> {
        event_payloads(seg, crate::wal::events::EVENT_TYPE_COST_ESTIMATE_SHOWN)
    }

    fn lifecycle_frames(seg: &std::path::Path) -> Vec<(u8, serde_json::Value)> {
        let bytes = std::fs::read(seg).unwrap();
        let hdr = crate::wal::segment_header::parse_segment_header(&bytes).unwrap();
        let mut cursor = hdr.header_len();
        let mut frames = Vec::new();
        while cursor < bytes.len() {
            let dec = crate::wal::frame::decode_frame(&bytes[cursor..]).unwrap();
            if matches!(
                dec.header.event_type,
                crate::wal::events::EVENT_TYPE_PROVIDER_REQUEST
                    | crate::wal::events::EVENT_TYPE_PROVIDER_RESPONSE
                    | crate::wal::events::EVENT_TYPE_PROVIDER_ERROR
            ) {
                frames.push((
                    dec.header.event_type,
                    serde_json::from_slice(dec.payload).unwrap(),
                ));
            }
            let total = dec.header.total_len as usize;
            if total == 0 {
                break;
            }
            cursor = cursor.saturating_add(total);
        }
        frames
    }

    struct RecordingProvider {
        name: &'static str,
        default_model: &'static str,
        output_token_ceiling: u32,
        behavior: Behavior,
        requests: std::sync::Arc<std::sync::Mutex<Vec<Request>>>,
    }

    #[async_trait]
    impl Provider for RecordingProvider {
        fn name(&self) -> &'static str {
            self.name
        }

        fn default_model(&self) -> Option<&str> {
            Some(self.default_model)
        }

        fn request_controls(&self) -> ProviderRequestControls {
            ProviderRequestControls::OUTPUT_TOKEN_LIMIT
        }

        fn output_token_ceiling(&self, req: &Request) -> Option<u32> {
            Some(
                req.max_output_tokens
                    .map_or(self.output_token_ceiling, |requested| {
                        self.output_token_ceiling.min(requested)
                    }),
            )
        }

        async fn complete(&self, req: Request) -> Result<Completion> {
            self.requests.lock().unwrap().push(req.clone());
            match self.behavior {
                Behavior::Ok => Ok(Completion {
                    termination: Default::default(),
                    text: format!("ok:{}", self.name),
                    model: req.model.unwrap(),
                    latency: Duration::ZERO,
                    ..Completion::default()
                }),
                Behavior::Quota => Err(anyhow::Error::new(QuotaError {
                    provider: self.name,
                    retry_after: None,
                    body: String::new(),
                })),
                Behavior::Other => anyhow::bail!("non-quota failure from {}", self.name),
            }
        }
    }

    #[tokio::test]
    async fn quota_backoff_is_durable_and_next_request_skips_primary() {
        let dir = tempfile::tempdir().unwrap();
        let quota_path = dir.path().join("quota.json");
        let primary_requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let fallback_requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

        let first = FallbackProvider::new_with_models_at(
            vec![
                Box::new(RecordingProvider {
                    name: "persist_primary",
                    default_model: "primary-model",
                    output_token_ceiling: 1024,
                    behavior: Behavior::Quota,
                    requests: primary_requests.clone(),
                }),
                Box::new(RecordingProvider {
                    name: "persist_fallback",
                    default_model: "fallback-model",
                    output_token_ceiling: 1024,
                    behavior: Behavior::Ok,
                    requests: fallback_requests.clone(),
                }),
            ],
            vec![None, None],
            1,
            None,
            quota_path.clone(),
        );
        assert_eq!(
            first.complete(Request::default()).await.unwrap().text,
            "ok:persist_fallback"
        );

        let persisted = QuotaTracker::load_from(&quota_path).unwrap();
        assert!(
            persisted
                .backoff_remaining_for("persist_primary", FallbackProvider::now_unix())
                .is_some(),
            "the primary 429 must be durable before the fallback succeeds"
        );

        let second = FallbackProvider::new_with_models_at(
            vec![
                Box::new(RecordingProvider {
                    name: "persist_primary",
                    default_model: "primary-model",
                    output_token_ceiling: 1024,
                    behavior: Behavior::Ok,
                    requests: primary_requests.clone(),
                }),
                Box::new(RecordingProvider {
                    name: "persist_fallback",
                    default_model: "fallback-model",
                    output_token_ceiling: 1024,
                    behavior: Behavior::Ok,
                    requests: fallback_requests.clone(),
                }),
            ],
            vec![None, None],
            1,
            None,
            quota_path,
        );
        assert!(second.handles_nonstream_quota_backoff());
        assert_eq!(
            second.complete(Request::default()).await.unwrap().text,
            "ok:persist_fallback"
        );
        assert_eq!(
            primary_requests.lock().unwrap().len(),
            1,
            "the second request must not hit a primary in durable backoff"
        );
        assert_eq!(fallback_requests.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn every_quota_candidate_is_persisted_before_the_next_hop() {
        let dir = tempfile::tempdir().unwrap();
        let quota_path = dir.path().join("quota.json");
        let fallback = fallback_at(
            dir.path(),
            vec![
                mock("quota-primary", Behavior::Quota),
                mock("quota-fallback", Behavior::Quota),
                mock("healthy-fallback", Behavior::Ok),
            ],
            2,
            None,
        );

        assert_eq!(
            fallback.complete(Request::default()).await.unwrap().text,
            "ok:healthy-fallback"
        );
        let persisted = QuotaTracker::load_from(&quota_path).unwrap();
        let now = FallbackProvider::now_unix();
        assert!(
            persisted
                .backoff_remaining_for("quota-primary", now)
                .is_some()
        );
        assert!(
            persisted
                .backoff_remaining_for("quota-fallback", now)
                .is_some()
        );
    }

    #[tokio::test]
    async fn pinned_retry_replays_the_original_fallback_leaf_without_hopping() {
        let dir = tempfile::tempdir().unwrap();
        let (writer, join) =
            crate::wal::writer::spawn(dir.path().join("pinned-retry.wal")).unwrap();
        let primary_requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let fallback_requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let provider = FallbackProvider::new_with_models_at(
            vec![
                Box::new(RecordingProvider {
                    name: "pinned_primary",
                    default_model: "primary-default",
                    output_token_ceiling: 4096,
                    behavior: Behavior::Quota,
                    requests: primary_requests.clone(),
                }),
                Box::new(RecordingProvider {
                    name: "pinned_secondary",
                    default_model: "secondary-default",
                    output_token_ceiling: 4096,
                    behavior: Behavior::Ok,
                    requests: fallback_requests.clone(),
                }),
            ],
            vec![Some("primary-wire".into()), Some("secondary-wire".into())],
            1,
            None,
            dir.path().join("quota.json"),
        );
        let authorizer = crate::providers::cost_authorization::ProviderCallAuthorizer::fail_closed(
            crate::permissions::AutonomyLevel::Full,
            Some(writer.clone()),
            crate::config::TokensConfig::default_max_per_request(),
        )
        .with_usage_home(dir.path());

        let first = provider
            .complete_authorized(
                Request {
                    prompt: "first".into(),
                    model: Some("primary-wire".into()),
                    ..Request::default()
                },
                &authorizer,
                "test.pinned.initial",
            )
            .await
            .expect("fallback completion");
        assert_eq!(first.identity.provider, "pinned_secondary");
        assert_eq!(first.identity.wire_model, "secondary-wire");
        assert_eq!(first.identity.dispatch_route, vec![1]);

        let retry = provider
            .complete_authorized_pinned(
                Request {
                    prompt: "retry".into(),
                    model: Some("primary-wire".into()),
                    ..Request::default()
                },
                &first.identity,
                &authorizer,
                "test.pinned.retry",
            )
            .await
            .expect("exact secondary retry");
        assert_eq!(retry.identity, first.identity);
        assert_eq!(primary_requests.lock().unwrap().len(), 1);
        {
            let fallback_requests = fallback_requests.lock().unwrap();
            assert_eq!(fallback_requests.len(), 2);
            assert_eq!(
                fallback_requests[1].model.as_deref(),
                Some("secondary-wire")
            );
        }
        drop(authorizer);
        drop(writer);
        join.await.unwrap();
    }

    #[tokio::test]
    async fn pinned_route_selects_between_leafs_with_identical_identity() {
        let dir = tempfile::tempdir().unwrap();
        let first_requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let second_requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let provider = FallbackProvider::new_with_models_at(
            vec![
                Box::new(RecordingProvider {
                    name: "same-provider",
                    default_model: "same-model",
                    output_token_ceiling: 4096,
                    behavior: Behavior::Ok,
                    requests: first_requests.clone(),
                }),
                Box::new(RecordingProvider {
                    name: "same-provider",
                    default_model: "same-model",
                    output_token_ceiling: 4096,
                    behavior: Behavior::Ok,
                    requests: second_requests.clone(),
                }),
            ],
            vec![Some("same-model".into()), Some("same-model".into())],
            1,
            None,
            dir.path().join("quota.json"),
        );
        let authorizer = crate::providers::cost_authorization::ProviderCallAuthorizer::test_only(
            crate::permissions::AutonomyLevel::Full,
        );
        let expected = CompletionIdentity {
            provider: "same-provider".into(),
            wire_model: "same-model".into(),
            dispatch_route: vec![1],
        };

        let completion = provider
            .complete_authorized_pinned(
                Request {
                    prompt: "retry".into(),
                    ..Request::default()
                },
                &expected,
                &authorizer,
                "test.pinned.identical_identity",
            )
            .await
            .unwrap();

        assert_eq!(completion.identity, expected);
        assert!(first_requests.lock().unwrap().is_empty());
        assert_eq!(second_requests.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn pinned_route_rejects_missing_or_invalid_slot_before_dispatch() {
        let dir = tempfile::tempdir().unwrap();
        let primary_requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let secondary_requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let provider = FallbackProvider::new_with_models_at(
            vec![
                Box::new(RecordingProvider {
                    name: "route-primary",
                    default_model: "route-primary-model",
                    output_token_ceiling: 4096,
                    behavior: Behavior::Ok,
                    requests: primary_requests.clone(),
                }),
                Box::new(RecordingProvider {
                    name: "route-secondary",
                    default_model: "route-secondary-model",
                    output_token_ceiling: 4096,
                    behavior: Behavior::Ok,
                    requests: secondary_requests.clone(),
                }),
            ],
            vec![None, None],
            1,
            None,
            dir.path().join("quota.json"),
        );
        let authorizer = crate::providers::cost_authorization::ProviderCallAuthorizer::test_only(
            crate::permissions::AutonomyLevel::Full,
        );
        for route in [Vec::new(), vec![9]] {
            let expected = CompletionIdentity {
                provider: "route-secondary".into(),
                wire_model: "route-secondary-model".into(),
                dispatch_route: route,
            };
            assert!(
                provider
                    .complete_authorized_pinned(
                        Request::default(),
                        &expected,
                        &authorizer,
                        "test.pinned.invalid_route",
                    )
                    .await
                    .is_err()
            );
        }
        assert!(primary_requests.lock().unwrap().is_empty());
        assert!(secondary_requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn pinned_leaf_in_durable_backoff_is_not_called_and_never_hops() {
        let dir = tempfile::tempdir().unwrap();
        let quota_path = dir.path().join("quota.json");
        QuotaTracker::update_at(&quota_path, |tracker| {
            tracker.record_429(
                "backoff-secondary",
                Some(std::time::Duration::from_secs(600)),
                FallbackProvider::now_unix(),
            );
            Ok(())
        })
        .unwrap();
        let primary_requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let secondary_requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let provider = FallbackProvider::new_with_models_at(
            vec![
                Box::new(RecordingProvider {
                    name: "backoff-primary",
                    default_model: "primary-model",
                    output_token_ceiling: 4096,
                    behavior: Behavior::Ok,
                    requests: primary_requests.clone(),
                }),
                Box::new(RecordingProvider {
                    name: "backoff-secondary",
                    default_model: "secondary-model",
                    output_token_ceiling: 4096,
                    behavior: Behavior::Ok,
                    requests: secondary_requests.clone(),
                }),
            ],
            vec![None, None],
            1,
            None,
            quota_path,
        );
        let authorizer = crate::providers::cost_authorization::ProviderCallAuthorizer::test_only(
            crate::permissions::AutonomyLevel::Full,
        );
        let error = provider
            .complete_authorized_pinned(
                Request::default(),
                &CompletionIdentity {
                    provider: "backoff-secondary".into(),
                    wire_model: "secondary-model".into(),
                    dispatch_route: vec![1],
                },
                &authorizer,
                "test.pinned.backoff",
            )
            .await
            .unwrap_err();

        assert!(error.downcast_ref::<QuotaError>().is_some());
        assert!(primary_requests.lock().unwrap().is_empty());
        assert!(secondary_requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn pinned_leaf_new_quota_error_is_persisted_without_hop() {
        let dir = tempfile::tempdir().unwrap();
        let (writer, join) =
            crate::wal::writer::spawn(dir.path().join("pinned-new-quota.wal")).unwrap();
        let quota_path = dir.path().join("quota.json");
        let primary_requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let secondary_requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let provider = FallbackProvider::new_with_models_at(
            vec![
                Box::new(RecordingProvider {
                    name: "quota-retry-primary",
                    default_model: "primary-model",
                    output_token_ceiling: 4096,
                    behavior: Behavior::Ok,
                    requests: primary_requests.clone(),
                }),
                Box::new(RecordingProvider {
                    name: "quota-retry-secondary",
                    default_model: "secondary-model",
                    output_token_ceiling: 4096,
                    behavior: Behavior::Quota,
                    requests: secondary_requests.clone(),
                }),
            ],
            vec![None, None],
            1,
            None,
            quota_path.clone(),
        );
        let authorizer = crate::providers::cost_authorization::ProviderCallAuthorizer::fail_closed(
            crate::permissions::AutonomyLevel::Full,
            Some(writer.clone()),
            crate::config::TokensConfig::default_max_per_request(),
        )
        .with_usage_home(dir.path());
        let error = provider
            .complete_authorized_pinned(
                Request::default(),
                &CompletionIdentity {
                    provider: "quota-retry-secondary".into(),
                    wire_model: "secondary-model".into(),
                    dispatch_route: vec![1],
                },
                &authorizer,
                "test.pinned.new_quota",
            )
            .await
            .unwrap_err();

        assert!(error.downcast_ref::<QuotaError>().is_some());
        assert!(primary_requests.lock().unwrap().is_empty());
        assert_eq!(secondary_requests.lock().unwrap().len(), 1);
        assert!(
            QuotaTracker::load_from(&quota_path)
                .unwrap()
                .backoff_remaining_for("quota-retry-secondary", FallbackProvider::now_unix())
                .is_some()
        );
        drop(authorizer);
        drop(writer);
        join.await.unwrap();
    }

    struct IdentityDriftProvider {
        requests: std::sync::Arc<std::sync::Mutex<Vec<Request>>>,
    }

    #[async_trait]
    impl Provider for IdentityDriftProvider {
        fn name(&self) -> &'static str {
            "identity-drift"
        }

        fn default_model(&self) -> Option<&str> {
            Some("expected-model")
        }

        fn output_token_ceiling(&self, _req: &Request) -> Option<u32> {
            Some(4096)
        }

        fn preserves_inner_response_identity(&self) -> bool {
            true
        }

        async fn complete(&self, req: Request) -> Result<Completion> {
            self.requests.lock().unwrap().push(req);
            Ok(Completion {
                text: "wrong leaf".into(),
                model: "other-model".into(),
                identity: CompletionIdentity {
                    provider: "other-provider".into(),
                    wire_model: "other-model".into(),
                    dispatch_route: Vec::new(),
                },
                ..Completion::default()
            })
        }
    }

    #[tokio::test]
    async fn pinned_leaf_identity_drift_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let provider = fallback_at(
            dir.path(),
            vec![Box::new(IdentityDriftProvider {
                requests: requests.clone(),
            })],
            0,
            None,
        );
        let authorizer = crate::providers::cost_authorization::ProviderCallAuthorizer::test_only(
            crate::permissions::AutonomyLevel::Full,
        );

        let error = provider
            .complete_authorized_pinned(
                Request::default(),
                &CompletionIdentity {
                    provider: "identity-drift".into(),
                    wire_model: "expected-model".into(),
                    dispatch_route: vec![0],
                },
                &authorizer,
                "test.pinned.identity_drift",
            )
            .await
            .unwrap_err();

        assert!(error.to_string().contains("identity drifted"));
        assert_eq!(requests.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn nested_pinned_route_reaches_only_inner_secondary() {
        let dir = tempfile::tempdir().unwrap();
        let outer_primary_requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let inner_primary_requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let inner_secondary_requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let inner = FallbackProvider::new_with_models_at(
            vec![
                Box::new(RecordingProvider {
                    name: "inner-primary",
                    default_model: "inner-primary-model",
                    output_token_ceiling: 4096,
                    behavior: Behavior::Ok,
                    requests: inner_primary_requests.clone(),
                }),
                Box::new(RecordingProvider {
                    name: "inner-secondary",
                    default_model: "inner-secondary-model",
                    output_token_ceiling: 4096,
                    behavior: Behavior::Ok,
                    requests: inner_secondary_requests.clone(),
                }),
            ],
            vec![None, None],
            1,
            None,
            dir.path().join("inner-quota.json"),
        );
        let outer = FallbackProvider::new_with_models_at(
            vec![
                Box::new(RecordingProvider {
                    name: "outer-primary",
                    default_model: "outer-primary-model",
                    output_token_ceiling: 4096,
                    behavior: Behavior::Ok,
                    requests: outer_primary_requests.clone(),
                }),
                Box::new(inner),
            ],
            vec![None, Some("inner-primary-model".into())],
            1,
            None,
            dir.path().join("outer-quota.json"),
        );
        let authorizer = crate::providers::cost_authorization::ProviderCallAuthorizer::test_only(
            crate::permissions::AutonomyLevel::Full,
        );
        let expected = CompletionIdentity {
            provider: "inner-secondary".into(),
            wire_model: "inner-secondary-model".into(),
            dispatch_route: vec![1, 1],
        };

        let completion = outer
            .complete_authorized_pinned(
                Request::default(),
                &expected,
                &authorizer,
                "test.pinned.nested",
            )
            .await
            .unwrap();

        assert_eq!(completion.identity, expected);
        assert!(outer_primary_requests.lock().unwrap().is_empty());
        assert!(inner_primary_requests.lock().unwrap().is_empty());
        assert_eq!(inner_secondary_requests.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn nested_pinned_quota_is_owned_once_by_inner_router() {
        let dir = tempfile::tempdir().unwrap();
        let (writer, join) =
            crate::wal::writer::spawn(dir.path().join("nested-pinned-quota.wal")).unwrap();
        let inner_quota_path = dir.path().join("inner-quota.json");
        let outer_quota_path = dir.path().join("outer-quota.json");
        let outer_primary_requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let inner_primary_requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let inner_secondary_requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let inner = FallbackProvider::new_with_models_at(
            vec![
                Box::new(RecordingProvider {
                    name: "nested-quota-primary",
                    default_model: "nested-primary-model",
                    output_token_ceiling: 4096,
                    behavior: Behavior::Ok,
                    requests: inner_primary_requests.clone(),
                }),
                Box::new(RecordingProvider {
                    name: "nested-quota-secondary",
                    default_model: "nested-secondary-model",
                    output_token_ceiling: 4096,
                    behavior: Behavior::Quota,
                    requests: inner_secondary_requests.clone(),
                }),
            ],
            vec![None, None],
            1,
            None,
            inner_quota_path.clone(),
        );
        let outer = FallbackProvider::new_with_models_at(
            vec![
                Box::new(RecordingProvider {
                    name: "nested-outer-primary",
                    default_model: "outer-primary-model",
                    output_token_ceiling: 4096,
                    behavior: Behavior::Ok,
                    requests: outer_primary_requests.clone(),
                }),
                Box::new(inner),
            ],
            vec![None, Some("nested-primary-model".into())],
            1,
            None,
            outer_quota_path.clone(),
        );
        let authorizer = crate::providers::cost_authorization::ProviderCallAuthorizer::fail_closed(
            crate::permissions::AutonomyLevel::Full,
            Some(writer.clone()),
            crate::config::TokensConfig::default_max_per_request(),
        )
        .with_usage_home(dir.path());

        let error = outer
            .complete_authorized_pinned(
                Request::default(),
                &CompletionIdentity {
                    provider: "nested-quota-secondary".into(),
                    wire_model: "nested-secondary-model".into(),
                    dispatch_route: vec![1, 1],
                },
                &authorizer,
                "test.pinned.nested_quota",
            )
            .await
            .unwrap_err();

        assert!(error.downcast_ref::<QuotaError>().is_some());
        assert!(outer_primary_requests.lock().unwrap().is_empty());
        assert!(inner_primary_requests.lock().unwrap().is_empty());
        assert_eq!(inner_secondary_requests.lock().unwrap().len(), 1);
        assert!(
            QuotaTracker::load_from(&inner_quota_path)
                .unwrap()
                .backoff_remaining_for("nested-quota-secondary", FallbackProvider::now_unix())
                .is_some()
        );
        assert!(
            QuotaTracker::load_from(&outer_quota_path)
                .unwrap()
                .backoff_remaining_for("nested-quota-primary", FallbackProvider::now_unix())
                .is_none()
        );
        drop(authorizer);
        drop(writer);
        join.await.unwrap();
    }

    #[tokio::test]
    async fn authorized_fallback_persists_one_usage_event_per_leaf_attempt() {
        let dir = tempfile::tempdir().unwrap();
        let wal_dir = dir.path().join("wal");
        std::fs::create_dir_all(&wal_dir).unwrap();
        let seg = wal_dir.join("authorized-fallback-000001.wal");
        let (writer, join) =
            crate::wal::writer::spawn_for_home(seg.clone(), dir.path().to_path_buf()).unwrap();
        let primary_requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let fallback_requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let fallback = FallbackProvider::new_with_models_at(
            vec![
                Box::new(RecordingProvider {
                    name: "primary_cloud",
                    default_model: "primary-default",
                    output_token_ceiling: 4096,
                    behavior: Behavior::Quota,
                    requests: primary_requests.clone(),
                }),
                Box::new(RecordingProvider {
                    name: "fallback_cloud",
                    default_model: "fallback-default",
                    output_token_ceiling: 10_000,
                    behavior: Behavior::Ok,
                    requests: fallback_requests.clone(),
                }),
            ],
            vec![
                Some("primary-config".into()),
                Some("fallback-config".into()),
            ],
            1,
            None,
            dir.path().join("quota.json"),
        );
        let provider = crate::providers::cost_authorization::AuthorizedProvider::from_box(
            Box::new(fallback),
            crate::providers::cost_authorization::ProviderCallAuthorizer::fail_closed(
                crate::permissions::AutonomyLevel::Full,
                Some(writer.clone()),
                crate::config::TokensConfig::default_max_per_request(),
            )
            .with_usage_home(dir.path()),
            None,
            "fallback.test",
        );

        let completion = provider
            .complete(Request {
                prompt: "same prompt".into(),
                system: Some("same system".into()),
                model: Some("caller-primary-model".into()),
                max_output_tokens: Some(2048),
                ..Request::default()
            })
            .await
            .unwrap();
        assert_eq!(completion.model, "fallback-config");
        assert_eq!(completion.identity.provider, "fallback_cloud");
        assert_eq!(completion.identity.wire_model, "fallback-config");
        assert_eq!(
            primary_requests.lock().unwrap()[0].model.as_deref(),
            Some("caller-primary-model")
        );
        assert_eq!(
            fallback_requests.lock().unwrap()[0].model.as_deref(),
            Some("fallback-config"),
            "a fallback must never inherit another provider's model"
        );
        assert_eq!(
            primary_requests.lock().unwrap()[0].max_output_tokens,
            Some(2048),
            "the primary must receive the caller's strict output cap"
        );
        assert_eq!(
            fallback_requests.lock().unwrap()[0].max_output_tokens,
            Some(2048),
            "fallback must preserve the caller's strict output cap"
        );

        drop(provider);
        drop(writer);
        join.await.unwrap();
        let payloads = cost_payloads(&seg);
        assert_eq!(payloads.len(), 2);
        assert_eq!(payloads[0]["provider"], "primary_cloud");
        assert_eq!(payloads[0]["model"], "caller-primary-model");
        assert_eq!(payloads[0]["output_tokens_est"], 2048);
        assert_eq!(payloads[0]["requested_max_output_tokens"], 2048);
        assert_eq!(payloads[1]["provider"], "fallback_cloud");
        assert_eq!(payloads[1]["model"], "fallback-config");
        assert_eq!(payloads[1]["output_tokens_est"], 2048);
        assert_eq!(payloads[1]["requested_max_output_tokens"], 2048);

        let quota_payloads =
            event_payloads(&seg, crate::wal::events::EVENT_TYPE_PROVIDER_QUOTA_EXCEEDED);
        assert_eq!(
            quota_payloads.len(),
            1,
            "the authorizer writer must receive one quota frame even when the fallback has no writer"
        );
        assert_eq!(quota_payloads[0]["provider"], "primary_cloud");
        let hop_payloads = event_payloads(
            &seg,
            crate::wal::events::EVENT_TYPE_PROVIDER_FALLBACK_ATTEMPTED,
        );
        assert_eq!(hop_payloads.len(), 1);
        assert_eq!(hop_payloads[0]["from_provider"], "primary_cloud");
        assert_eq!(hop_payloads[0]["to_provider"], "fallback_cloud");

        let lifecycle = lifecycle_frames(&seg);
        assert_eq!(
            lifecycle.iter().map(|frame| frame.0).collect::<Vec<_>>(),
            [
                crate::wal::events::EVENT_TYPE_PROVIDER_REQUEST,
                crate::wal::events::EVENT_TYPE_PROVIDER_ERROR,
                crate::wal::events::EVENT_TYPE_PROVIDER_REQUEST,
                crate::wal::events::EVENT_TYPE_PROVIDER_RESPONSE,
            ],
            "each concrete fallback child hop needs its own paired lifecycle"
        );
        assert_eq!(lifecycle[0].1["provider"], "primary_cloud");
        assert_eq!(lifecycle[0].1["wire_model"], "caller-primary-model");
        assert_eq!(
            lifecycle[1].1["invocation_id"],
            lifecycle[0].1["invocation_id"]
        );
        assert_eq!(lifecycle[2].1["provider"], "fallback_cloud");
        assert_eq!(lifecycle[2].1["wire_model"], "fallback-config");
        assert_eq!(
            lifecycle[3].1["invocation_id"],
            lifecycle[2].1["invocation_id"]
        );
        assert_ne!(
            lifecycle[0].1["invocation_id"],
            lifecycle[2].1["invocation_id"]
        );

        let mut usage_paths = std::fs::read_dir(crate::daemon::usage_log::usage_dir(dir.path()))
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("jsonl"))
            .collect::<Vec<_>>();
        usage_paths.sort();
        let usage = usage_paths
            .into_iter()
            .flat_map(|path| {
                std::fs::read_to_string(path)
                    .unwrap()
                    .lines()
                    .map(|line| {
                        serde_json::from_str::<crate::daemon::usage_log::UsageEvent>(line).unwrap()
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            usage.len(),
            2,
            "primary 429 and fallback success are distinct leaf attempts"
        );
        assert_eq!(usage[0].provider, "primary_cloud");
        assert_eq!(usage[0].model, "caller-primary-model");
        assert!(!usage[0].ok);
        assert_eq!(usage[0].input_tokens, None);
        assert_eq!(usage[1].provider, "fallback_cloud");
        assert_eq!(usage[1].model, "fallback-config");
        assert!(usage[1].ok);
        assert_ne!(usage[0].invocation_id, usage[1].invocation_id);
    }

    #[tokio::test]
    async fn active_council_cap_reserves_and_settles_each_fallback_leaf() {
        let dir = tempfile::tempdir().unwrap();
        let wal_dir = dir.path().join("wal");
        std::fs::create_dir_all(&wal_dir).unwrap();
        let segment = wal_dir.join("council-fallback-budget.wal");
        let (writer, join) = crate::wal::writer::spawn(segment.clone()).unwrap();
        let fallback = FallbackProvider::new_with_models_at(
            vec![
                Box::new(RecordingProvider {
                    name: "openai_api",
                    default_model: "gpt-4o",
                    output_token_ceiling: 4096,
                    behavior: Behavior::Quota,
                    requests: Default::default(),
                }),
                Box::new(RecordingProvider {
                    name: "anthropic_api",
                    default_model: "claude-sonnet-4-6",
                    output_token_ceiling: 4096,
                    behavior: Behavior::Ok,
                    requests: Default::default(),
                }),
            ],
            vec![Some("gpt-4o".into()), Some("claude-sonnet-4-6".into())],
            1,
            None,
            dir.path().join("quota.json"),
        );
        let authorizer = crate::providers::cost_authorization::ProviderCallAuthorizer::fail_closed(
            crate::permissions::AutonomyLevel::Full,
            Some(writer.clone()),
            crate::config::TokensConfig::default_max_per_request(),
        )
        .with_council_daily_cap(dir.path(), Some(1.0))
        .unwrap();

        let attempt_budget = crate::council::BudgetToken::new(2);
        attempt_budget
            .charge()
            .expect("Council caller pre-charges the primary leaf");
        let completion = crate::providers::cost_authorization::precharged_council_attempt_scope(
            attempt_budget.clone(),
            fallback.complete_authorized(Request::default(), &authorizer, "council_leaf"),
        )
        .await
        .unwrap();
        assert_eq!(completion.identity.provider, "anthropic_api");
        assert_eq!(
            attempt_budget.used(),
            2,
            "primary and fallback must each consume exactly one Council call"
        );

        drop(authorizer);
        drop(fallback);
        drop(writer);
        join.await.unwrap();
        let lifecycle = lifecycle_frames(&segment);
        assert_eq!(
            lifecycle.iter().map(|frame| frame.0).collect::<Vec<_>>(),
            [
                crate::wal::events::EVENT_TYPE_PROVIDER_REQUEST,
                crate::wal::events::EVENT_TYPE_PROVIDER_ERROR,
                crate::wal::events::EVENT_TYPE_PROVIDER_REQUEST,
                crate::wal::events::EVENT_TYPE_PROVIDER_RESPONSE,
            ]
        );
        let ledger: serde_json::Value = serde_json::from_slice(
            &std::fs::read(dir.path().join("budget").join("daily.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(ledger["pending"].as_object().unwrap().len(), 0);
        assert!(ledger["settled_usd_nanos"].as_u64().unwrap() > 0);
    }

    #[tokio::test]
    async fn fallback_hop_emits_audit_frame_when_writer_wired() {
        // SPEC-03b trust claim: a 429 hop with a writer present emits a
        // durable 0x25 frame recording from/to/reason/hop + a prompt hash
        // that correlates with the PROVIDER_REQUEST (0x20) frame.
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("fb.wal");
        let (writer, join) = crate::wal::writer::spawn(seg.clone()).unwrap();
        let fp = fallback_at(
            dir.path(),
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
        let fp = fallback_at(
            dir.path(),
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
        let dir = tempfile::tempdir().unwrap();
        let fp = fallback_at(
            dir.path(),
            vec![mock("primary", Behavior::Other), mock("fb", Behavior::Ok)],
            2,
            None,
        );
        let err = fp.complete(Request::default()).await.unwrap_err();
        assert!(err.to_string().contains("non-quota failure from primary"));
    }

    #[tokio::test]
    async fn all_429_returns_exhausted_error() {
        let dir = tempfile::tempdir().unwrap();
        let fp = fallback_at(
            dir.path(),
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
        let dir = tempfile::tempdir().unwrap();
        let fp = fallback_at(
            dir.path(),
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
        let dir2 = tempfile::tempdir().unwrap();
        let fp2 = fallback_at(
            dir2.path(),
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
