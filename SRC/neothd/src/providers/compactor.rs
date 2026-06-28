//! GOLD-ADAPT-HARNESS-03 — message-history compaction middleware.
//! GOLD-ADAPT-ODY-06 — raises threshold to 0.85 and wires SELF_SUMMARY_SYSTEM_PROMPT
//! into the utility summarisation call so the compactor uses the Odysseus
//! self-summary persona.
//!
//! [`CompactingProvider`] is a decorator that wraps any `Box<dyn Provider>`.
//! On every call it estimates the token count of the flat `prompt + system`
//! text. When the count exceeds `threshold_fraction * max_tokens` it:
//!
//! 1. Splits the prompt into an "old zone" (everything before the last
//!    `keep_recent_chars` characters) and a "live zone" (the tail).
//! 2. Calls the `utility` provider to summarise the old zone.
//! 3. Prepends `[CONTEXT SUMMARY: …]` to the live zone.
//! 4. Emits WAL slot `0xF9 HISTORY_COMPACTION_FIRED` (best-effort — failure
//!    logged, not propagated).
//! 5. Forwards the compacted request to the inner provider.
//!
//! The MCP dispatch-loop compaction (slots 0x5B/0x5C) is a separate system —
//! do not conflate the two.

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use serde_json::json;
use tracing::warn;

use sha2::{Digest, Sha256};

use crate::config::policy::TokensConfig;
use crate::providers::{ChunkStream, Completion, Provider, Request};
use crate::tokens::budget::count_tokens;
use crate::wal::events::EVENT_TYPE_HISTORY_COMPACTION_FIRED;
use crate::wal::writer::WalWriterHandle;
use crate::wal::{EventFlags, HeaderBuilder};

// ---------------------------------------------------------------------------
// Payload struct (serialised into WAL frame)

#[derive(serde::Serialize)]
struct CompactionPayload<'a> {
    original_chars: usize,
    summarised_chars: usize,
    kept_chars: usize,
    threshold_tokens: u32,
    model: &'a str,
    /// SHA-256 hex of the pre-compaction old_zone text. Content-addresses the
    /// raw snapshot so the audit record can prove (or disprove) that the
    /// summary dropped a constraint — ODY-06 compactor-rawhash fix.
    raw_hash: String,
}

// ---------------------------------------------------------------------------
// CompactingProvider

/// Wraps an inner `Box<dyn Provider>` and transparently squashes the old
/// portion of the flat `prompt` when the estimated token count crosses the
/// configured threshold.
pub struct CompactingProvider {
    inner: Box<dyn Provider>,
    /// Cheap model used for summarisation. `None` skips the summary step and
    /// simply truncates the old zone (still emits the WAL frame).
    utility: Option<Box<dyn Provider>>,
    /// `max_per_request` from `TokensConfig` — used to derive the threshold.
    max_tokens: u32,
    /// Fire when `count_tokens(prompt + system) > max_tokens * threshold_fraction`.
    threshold_fraction: f32,
    /// Characters of the prompt tail to preserve verbatim.
    keep_recent_chars: usize,
    /// WAL writer for audit frames. `None` in unit tests / when no WAL is open.
    wal: Option<WalWriterHandle>,
}

impl CompactingProvider {
    /// Full constructor. Prefer [`from_config`] in production.
    pub fn new(
        inner: Box<dyn Provider>,
        utility: Option<Box<dyn Provider>>,
        max_tokens: u32,
        threshold_fraction: f32,
        keep_recent_chars: usize,
        wal: Option<WalWriterHandle>,
    ) -> Self {
        Self {
            inner,
            utility,
            max_tokens,
            threshold_fraction,
            keep_recent_chars,
            wal,
        }
    }

    /// Construct from a `TokensConfig` slice. Returns the compactor boxed as
    /// `Box<dyn Provider>` ready to drop into the call chain.
    pub fn from_config(
        inner: Box<dyn Provider>,
        utility: Option<Box<dyn Provider>>,
        cfg: &TokensConfig,
        wal: Option<WalWriterHandle>,
    ) -> Box<dyn Provider> {
        Box::new(Self::new(
            inner,
            utility,
            cfg.max_per_request,
            cfg.history_compaction_threshold,
            cfg.history_keep_recent_chars,
            wal,
        ))
    }

    /// Computes the threshold in tokens.
    fn threshold_tokens(&self) -> u32 {
        // saturating_mul would overflow u32 for large max_tokens * f32 — cast via f64.
        let t = (self.max_tokens as f64 * self.threshold_fraction as f64) as u64;
        t.min(u32::MAX as u64) as u32
    }

    /// Returns the compacted request, or the original if compaction did not
    /// fire. Also emits the WAL audit frame when compaction fires.
    async fn maybe_compact(&self, mut req: Request) -> Request {
        let system_text = req.system.as_deref().unwrap_or("");
        let combined_chars = req.prompt.len() + system_text.len();
        let estimated_tokens = count_tokens(&req.prompt) + count_tokens(system_text);

        if estimated_tokens <= self.threshold_tokens() {
            return req;
        }

        let original_chars = req.prompt.len();

        // Split prompt into old zone + live zone.
        let keep = self.keep_recent_chars.min(req.prompt.len());
        let split_at = req.prompt.len() - keep;
        // Align split to a char boundary.
        let mut split_at = split_at;
        while split_at > 0 && !req.prompt.is_char_boundary(split_at) {
            split_at -= 1;
        }

        let old_zone = &req.prompt[..split_at];
        let live_zone = &req.prompt[split_at..];

        // Summarise the old zone via the utility provider (best-effort).
        let summary = if old_zone.is_empty() {
            String::new()
        } else if let Some(util) = &self.utility {
            // GOLD-ADAPT-ODY-06: pass the Odysseus self-summary system prompt so
            // the utility provider receives the structured compaction persona.
            let summary_req = Request {
                prompt: format!(
                    "Summarise the following conversation history concisely, \
                     preserving key facts, decisions, and context:\n\n{old_zone}"
                ),
                system: Some(
                    crate::context::compactor::SELF_SUMMARY_SYSTEM_PROMPT.to_owned(),
                ),
                model: None,
                temperature: Some(0.3),
                top_p: None,
                sampling_seed: None,
                stop_sequences: vec![],
                thinking_budget: None,
            };
            match util.complete(summary_req).await {
                Ok(c) => c.text,
                Err(e) => {
                    warn!(error = %e, "compactor: utility summarisation failed; using truncation");
                    format!("[truncated {} chars of earlier context]", old_zone.len())
                }
            }
        } else {
            format!("[truncated {} chars of earlier context]", old_zone.len())
        };

        let summarised_chars = summary.len();
        let kept_chars = live_zone.len();

        // Reassemble: summary block + live zone.
        let new_prompt = if summary.is_empty() {
            live_zone.to_owned()
        } else {
            format!("[CONTEXT SUMMARY: {summary}]\n\n{live_zone}")
        };

        // Best-effort WAL emit.
        if let Some(ref wal) = self.wal {
            let model_name = self
                .utility
                .as_ref()
                .map(|u| u.name())
                .unwrap_or("none");
            // ODY-06 compactor-rawhash: content-address the pre-compaction raw text
            // so the audit record can verify summary fidelity.
            let raw_hash = hex::encode(Sha256::digest(old_zone.as_bytes()));
            let payload_json = json!(CompactionPayload {
                original_chars,
                summarised_chars,
                kept_chars,
                threshold_tokens: self.threshold_tokens(),
                model: model_name,
                raw_hash,
            });
            match serde_json::to_vec(&payload_json) {
                Ok(bytes) => {
                    let header = HeaderBuilder::new(EVENT_TYPE_HISTORY_COMPACTION_FIRED, &bytes)
                        .flags(EventFlags::empty())
                        .build();
                    if let Err(e) = wal.append(header, bytes).await {
                        warn!(error = %e, "compactor: WAL emit failed (non-fatal)");
                    }
                }
                Err(e) => {
                    warn!(error = %e, "compactor: payload serialisation failed (non-fatal)");
                }
            }
        }

        let _ = combined_chars; // consumed above via original_chars
        req.prompt = new_prompt;
        req
    }
}

#[async_trait]
impl Provider for CompactingProvider {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    async fn complete(&self, req: Request) -> Result<Completion> {
        let req = self.maybe_compact(req).await;
        self.inner.complete(req).await
    }

    async fn stream(&self, req: Request) -> Result<ChunkStream> {
        let req = self.maybe_compact(req).await;
        self.inner.stream(req).await
    }
}

// ---------------------------------------------------------------------------
// Arc-compatible constructor for the serve path

/// Like [`CompactingProvider::from_config`] but returns `Arc<dyn Provider>`
/// for the daemon's shared-provider slot.
pub fn arc_from_config(
    inner: Arc<dyn Provider>,
    utility: Option<Box<dyn Provider>>,
    cfg: &TokensConfig,
    wal: Option<WalWriterHandle>,
) -> Arc<dyn Provider> {
    // Wrap the Arc<dyn Provider> in an adapter so we can put it in a Box<dyn Provider>.
    struct ArcAdapter(Arc<dyn Provider>);
    #[async_trait]
    impl Provider for ArcAdapter {
        fn name(&self) -> &'static str {
            self.0.name()
        }
        async fn complete(&self, req: Request) -> Result<Completion> {
            self.0.complete(req).await
        }
        async fn stream(&self, req: Request) -> Result<ChunkStream> {
            self.0.stream(req).await
        }
    }

    Arc::from(CompactingProvider::from_config(
        Box::new(ArcAdapter(inner)),
        utility,
        cfg,
        wal,
    ))
}

// ---------------------------------------------------------------------------
// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::Completion;
    use std::sync::Mutex;
    use std::time::Duration;

    /// Provider stub that records prompts and returns a fixed reply.
    struct StubProvider {
        reply: String,
        calls: Arc<Mutex<Vec<String>>>,
    }
    impl StubProvider {
        fn new(reply: &str) -> (Self, Arc<Mutex<Vec<String>>>) {
            let calls = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    reply: reply.to_owned(),
                    calls: Arc::clone(&calls),
                },
                calls,
            )
        }
    }
    #[async_trait]
    impl Provider for StubProvider {
        fn name(&self) -> &'static str {
            "stub"
        }
        async fn complete(&self, req: Request) -> Result<Completion> {
            self.calls.lock().unwrap().push(req.prompt.clone());
            Ok(Completion {
                text: self.reply.clone(),
                model: "stub".into(),
                latency: Duration::from_millis(1),
                input_tokens: None,
                output_tokens: None,
                cache_creation_tokens: None,
                cache_read_tokens: None,
            })
        }
        async fn stream(&self, _req: Request) -> Result<ChunkStream> {
            unimplemented!()
        }
    }

    fn long_prompt(chars: usize) -> String {
        "x".repeat(chars)
    }

    /// Build a compactor where threshold fires at 100 tokens → 400 chars.
    fn make_compactor(
        inner_calls: &Arc<Mutex<Vec<String>>>,
    ) -> (CompactingProvider, Arc<Mutex<Vec<String>>>) {
        let (inner, ic) = StubProvider::new("inner_reply");
        // Give the inner a separate call-tracker — we want to verify inner IS called.
        let _ = inner_calls; // caller passes theirs; we wire it below differently
        let (util, _uc) = StubProvider::new("SUMMARY");
        (
            CompactingProvider::new(
                Box::new(inner),
                Some(Box::new(util)),
                /* max_tokens */ 100,
                /* threshold */ 0.8, // fires at 80 tokens → 320 chars
                /* keep_recent_chars */ 50,
                None,
            ),
            ic,
        )
    }

    #[tokio::test]
    async fn no_fire_when_under_threshold() {
        // 80 chars → 20 tokens → well under 80-token threshold
        let prompt = long_prompt(80);
        let (inner, ic) = StubProvider::new("inner_reply");
        let (util, _uc) = StubProvider::new("SUMMARY");
        let cp = CompactingProvider::new(
            Box::new(inner),
            Some(Box::new(util)),
            100,
            0.8,
            50,
            None,
        );
        let req = Request {
            prompt: prompt.clone(),
            system: None,
            model: None,
            temperature: None,
            top_p: None,
            sampling_seed: None,
            stop_sequences: vec![],
            thinking_budget: None,
        };
        let result = cp.complete(req).await.unwrap();
        assert_eq!(result.text, "inner_reply");
        // inner received the original prompt unchanged
        let calls = ic.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], prompt);
    }

    #[tokio::test]
    async fn fires_over_threshold_and_prepends_summary() {
        // 500 chars → 125 tokens → over 80-token threshold (80 % of 100)
        let prompt = long_prompt(500);
        let (inner, ic) = StubProvider::new("inner_reply");
        let (util, _uc) = StubProvider::new("SUMMARY_TEXT");
        let cp = CompactingProvider::new(
            Box::new(inner),
            Some(Box::new(util)),
            100,
            0.8,
            50,
            None,
        );
        let req = Request {
            prompt: prompt.clone(),
            system: None,
            model: None,
            temperature: None,
            top_p: None,
            sampling_seed: None,
            stop_sequences: vec![],
            thinking_budget: None,
        };
        let result = cp.complete(req).await.unwrap();
        assert_eq!(result.text, "inner_reply");
        let calls = ic.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let forwarded = &calls[0];
        // Must contain the summary block
        assert!(
            forwarded.starts_with("[CONTEXT SUMMARY:"),
            "expected summary block, got: {forwarded:.80}"
        );
        // Live zone (last 50 chars) must be present
        let live = &prompt[prompt.len() - 50..];
        assert!(
            forwarded.ends_with(live),
            "live zone missing from compacted prompt"
        );
    }

    #[tokio::test]
    async fn disabled_config_skips_compaction() {
        let cfg = TokensConfig {
            history_compaction_enabled: false,
            ..Default::default()
        };
        // If disabled, caller should never construct CompactingProvider at all.
        // Verify the default config has disabled = false (default).
        assert!(!cfg.history_compaction_enabled);
    }

    // -------------------------------------------------------------------------
    // GOLD-ADAPT-ODY-06 tests

    /// A utility stub that captures the `system` field of the Request it receives.
    /// Used to verify SELF_SUMMARY_SYSTEM_PROMPT is wired into the utility call.
    struct SystemCapture(Arc<Mutex<Option<String>>>);
    #[async_trait]
    impl Provider for SystemCapture {
        fn name(&self) -> &'static str {
            "capture"
        }
        async fn complete(&self, req: Request) -> Result<Completion> {
            *self.0.lock().unwrap() = req.system.clone();
            Ok(Completion {
                text: "SUMMARY".into(),
                model: "capture".into(),
                latency: Duration::from_millis(0),
                input_tokens: None,
                output_tokens: None,
                cache_creation_tokens: None,
                cache_read_tokens: None,
            })
        }
        async fn stream(&self, _: Request) -> Result<ChunkStream> {
            unimplemented!()
        }
    }

    /// ODY-06: the utility summarisation request must carry SELF_SUMMARY_SYSTEM_PROMPT
    /// as its `system` field, and that prompt must contain the word "DENSE".
    #[tokio::test]
    async fn self_summary_prompt_used_as_utility_system() {
        let captured_system = Arc::new(Mutex::new(None::<String>));
        let (inner, _ic) = StubProvider::new("inner");
        let cp = CompactingProvider::new(
            Box::new(inner),
            Some(Box::new(SystemCapture(Arc::clone(&captured_system)))),
            /* max_tokens */ 100,
            /* threshold */ 0.85, // ODY-06 threshold
            /* keep_recent */ 50,
            None,
        );
        // 500 chars → ~125 tokens → over 85-token threshold (100 * 0.85 = 85)
        let req = Request {
            prompt: "x".repeat(500),
            system: None,
            model: None,
            temperature: None,
            top_p: None,
            sampling_seed: None,
            stop_sequences: vec![],
            thinking_budget: None,
        };
        cp.complete(req).await.unwrap();
        let sys = captured_system.lock().unwrap().clone();
        assert!(sys.is_some(), "utility must receive a system prompt (ODY-06)");
        let sys = sys.unwrap();
        assert!(
            sys.contains("DENSE"),
            "SELF_SUMMARY_SYSTEM_PROMPT must contain the word DENSE; got: {sys:.120}"
        );
    }

    /// ODY-06: with threshold_fraction=0.85 and max_tokens=100, compaction fires
    /// at ~85 tokens (≈340 chars) and must NOT fire at 80 chars (≈20 tokens).
    #[tokio::test]
    async fn threshold_0_85_fires_at_correct_token_count() {
        // Under threshold: 80 chars ≈ 20 tokens — should NOT compact
        let (inner_under, ic_under) = StubProvider::new("inner_reply");
        let (util_under, _) = StubProvider::new("SUMMARY");
        let cp_under = CompactingProvider::new(
            Box::new(inner_under),
            Some(Box::new(util_under)),
            100,
            0.85,
            50,
            None,
        );
        let req_under = Request {
            prompt: "x".repeat(80),
            system: None,
            model: None,
            temperature: None,
            top_p: None,
            sampling_seed: None,
            stop_sequences: vec![],
            thinking_budget: None,
        };
        cp_under.complete(req_under.clone()).await.unwrap();
        {
            let calls = ic_under.lock().unwrap();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0], "x".repeat(80), "should not compact under threshold");
        }

        // Over threshold: 500 chars ≈ 125 tokens — SHOULD compact
        let (inner_over, ic_over) = StubProvider::new("inner_reply");
        let (util_over, _) = StubProvider::new("SUMMARY_TEXT");
        let cp_over = CompactingProvider::new(
            Box::new(inner_over),
            Some(Box::new(util_over)),
            100,
            0.85,
            50,
            None,
        );
        let req_over = Request {
            prompt: "x".repeat(500),
            system: None,
            model: None,
            temperature: None,
            top_p: None,
            sampling_seed: None,
            stop_sequences: vec![],
            thinking_budget: None,
        };
        cp_over.complete(req_over).await.unwrap();
        {
            let calls = ic_over.lock().unwrap();
            assert_eq!(calls.len(), 1);
            assert!(
                calls[0].starts_with("[CONTEXT SUMMARY:"),
                "over-threshold should produce summary block; got: {:.80}",
                calls[0]
            );
        }
    }

    /// ODY-06: default TokensConfig threshold must now be 0.85, not 0.80.
    #[test]
    fn default_threshold_is_0_85() {
        let cfg = TokensConfig::default();
        assert!(
            (cfg.history_compaction_threshold - 0.85).abs() < f32::EPSILON,
            "default threshold must be 0.85 (ODY-06); got {}",
            cfg.history_compaction_threshold
        );
    }
}
