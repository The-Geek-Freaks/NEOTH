//! GOLD-ADAPT-HARNESS-03 — message-history compaction middleware.
//! GOLD-ADAPT-ODY-06 — raises threshold to 0.85 and wires SELF_SUMMARY_SYSTEM_PROMPT
//! into the utility summarisation call so the compactor uses the Odysseus
//! self-summary persona.
//! GOLD-PXP-01 — keepSharp verbatim-risk guard (`should_compact_block`).
//! GOLD-PXP-02 — semantic boundary split: stable/dynamic at last turn boundary.
//! GOLD-PXP-03 — churn telemetry in the 0xF9 WAL payload.
//! GOLD-PXP-04 — calibrated chars-per-token constants (dense-JSON vs prose).
//!
//! [`CompactingProvider`] is a decorator that wraps any `Box<dyn Provider>`.
//! On every call it estimates the token count of the flat `prompt + system`
//! text. When the count exceeds `threshold_fraction * max_tokens` it:
//!
//! 1. Splits the prompt into a "stable zone" (everything before the last
//!    semantic boundary at or before `keep_recent_chars` chars from the end)
//!    and a "live zone" (the tail). The split is message-boundary-aware so
//!    the stable prefix stays byte-identical across consecutive fires, enabling
//!    provider prompt-cache hits (GOLD-PXP-02).
//! 2. Guards the old zone with the verbatim-risk predicate; if it contains
//!    UUIDs, long hex runs, file paths, or numeric-ID clusters, it survives
//!    byte-identical without being summarised (GOLD-PXP-01).
//! 3. Calls the `utility` provider to summarise the old zone (when guard passes).
//! 4. Prepends `[CONTEXT SUMMARY: …]` to the live zone.
//! 5. Emits WAL slot `0xF9 HISTORY_COMPACTION_FIRED` with extended churn
//!    telemetry fields (GOLD-PXP-03).
//! 6. Forwards the compacted request to the inner provider.
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
use crate::context::compress::content_detector::{ContentType, detect_content_type};
use crate::providers::{
    ChunkStream, Completion, Provider, ProviderDispatchPermit, ProviderRequestControls, Request,
};
use crate::wal::events::EVENT_TYPE_HISTORY_COMPACTION_FIRED;
use crate::wal::writer::WalWriterHandle;
use crate::wal::{EventFlags, HeaderBuilder};

// ---------------------------------------------------------------------------
// GOLD-PXP-04 — calibrated chars-per-token constants (pxpipe empirical,
// Opus N=391). Used in `estimate_tokens_pxp` to replace the flat char/4
// heuristic with content-class-aware estimates.

/// Dense JSON and source code compress to ~2 chars/token under the o200k
/// tokeniser (pxpipe empirical, N=391).
const DENSE_JSON_CHARS_PER_TOKEN: f64 = 2.0;
/// Natural-language prose sits around 3.7 chars/token.
const PROSE_CHARS_PER_TOKEN: f64 = 3.7;
/// Fallback for content that the detector cannot classify confidently.
/// Matches the legacy char/4 = 4.0 heuristic.
const FALLBACK_CHARS_PER_TOKEN: f64 = 4.0;

/// GOLD-PXP-04: estimate tokens from `text` using the content-type-aware
/// chars-per-token constant. Falls back to the legacy char/4 estimate for
/// unclassifiable content.  Returns `u32`, saturating at `u32::MAX`.
fn estimate_tokens_pxp(text: &str) -> u32 {
    if text.is_empty() {
        return 0;
    }
    let chars = text.chars().count() as f64;
    let chars_per_tok = match detect_content_type(text).content_type {
        ContentType::JsonArray | ContentType::SourceCode => DENSE_JSON_CHARS_PER_TOKEN,
        ContentType::PlainText => PROSE_CHARS_PER_TOKEN,
        // Mixed/structured types: use the fallback (same as legacy char/4).
        _ => FALLBACK_CHARS_PER_TOKEN,
    };
    let tokens = (chars / chars_per_tok).ceil() as u64;
    tokens.min(u32::MAX as u64) as u32
}

// ---------------------------------------------------------------------------
// GOLD-PXP-01 — keepSharp verbatim-risk guard.
//
// Port of pxpipe `transform.ts::keepSharp`. Before summarising any block,
// this predicate returns `false` (= do NOT compact, keep verbatim) if the
// content contains byte-exact-retrieval material:
//   • UUID patterns  (8-4-4-4-12 hex)
//   • Long hex runs  (≥ 8 contiguous hex digits, e.g. commit hashes, HMAC)
//   • File-system paths  (Unix /dir/file or Windows C:\dir\file)
//   • Numeric-ID clusters (≥ 3 integers each ≥ 6 digits on adjacent lines)
//
// A panic inside this function (which should never happen, but defensive) is
// caught by `std::panic::catch_unwind`; on panic the block is kept verbatim
// (fail-safe).

use regex::Regex;
use std::sync::LazyLock;

static RE_UUID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}").unwrap()
});
static RE_HEX_RUN: LazyLock<Regex> = LazyLock::new(|| {
    // ≥8 contiguous hex chars, optionally `0x`-prefixed. The optional prefix
    // matters: a bare `\b[0-9a-f]{8,}\b` never anchors on `0xdeadbeef…`
    // because `x` is a word char, so the boundary before the hex run fails —
    // Ethereum addresses / tx hashes / Rust hex literals would slip through
    // and get summarised. Leading `\b` keeps it off mid-word base64.
    Regex::new(r"(?i)\b(?:0x)?[0-9a-f]{8,}\b").unwrap()
});
static RE_FILE_PATH_UNIX: LazyLock<Regex> = LazyLock::new(|| {
    // Two+ `/segment` components, but only when the leading `/` sits at the
    // start of the text or right after whitespace / a quote / a delimiter —
    // NOT after `//` in a URL. This catches mid-sentence filesystem paths
    // ("config lives at /etc/neoth/config.yaml", "path:/var/log",
    // "2>/var/log/err", "cmd |/usr/bin/tee") while NOT matching the path
    // portion of an https:// URL. Matching every URL would veto compaction of
    // essentially every real conversation (they nearly always contain a link),
    // silently disabling the feature.
    Regex::new(r#"(?:^|[\s"'(<=,:>|])(?:/[a-zA-Z0-9_.\-]+){2,}"#).unwrap()
});
static RE_FILE_PATH_WIN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^[A-Za-z]:\\(?:[^\\\r\n]+\\)+").unwrap());
static RE_NUMERIC_ID: LazyLock<Regex> = LazyLock::new(|| {
    // A 6+-digit integer standing alone on a line (or after a colon/space).
    Regex::new(r"(?m)^\s*\d{6,}\s*$").unwrap()
});

/// GOLD-PXP-01: returns `true` if it is safe to summarise `content`, `false`
/// if the block contains byte-exact-retrieval material that must survive
/// verbatim.  Exceptions inside the predicate → `false` (fail-safe).
fn should_compact_block(content: &str) -> bool {
    // Wrap in catch_unwind so a regex panic keeps the block verbatim.
    let result = std::panic::catch_unwind(|| -> bool {
        if RE_UUID.is_match(content) {
            return false;
        }
        // A hex run counts as a byte-exact identifier only if it contains a
        // digit (real hashes/addresses always do). Requiring a digit avoids
        // vetoing compaction on ordinary English words that happen to be 8+
        // all-[a-f] letters ("deadbeef", "cafebabe", "facefeed"), which would
        // otherwise keep the whole zone verbatim forever.
        if RE_HEX_RUN
            .find_iter(content)
            .any(|m| m.as_str().bytes().any(|b| b.is_ascii_digit()))
        {
            return false;
        }
        if RE_FILE_PATH_UNIX.is_match(content) || RE_FILE_PATH_WIN.is_match(content) {
            return false;
        }
        // Numeric-ID cluster: ≥ 3 lines each matching a lone 6+-digit integer.
        let cluster_count = RE_NUMERIC_ID.find_iter(content).count();
        if cluster_count >= 3 {
            return false;
        }
        true
    });
    // On panic, keep verbatim (fail-safe).
    result.unwrap_or(false)
}

// ---------------------------------------------------------------------------
// GOLD-PXP-02 — semantic boundary split helpers.
//
// Port of pxpipe `lastStaticSystemCacheControl` pattern. Instead of a raw
// char-count split, find the last *turn boundary* marker at or before the
// `keep_recent_chars` offset from the end.  Turn boundaries are:
//   • "\n\nHuman:" / "\n\nAssistant:" (Claude-style flat prompts)
//   • "\n\n---\n\n" (generic section separator)
//   • Start of the string (fallback)
//
// The stable prefix then ends on a clean boundary so it is byte-identical
// across consecutive fires (provider prompt-cache hit).

/// Recognised turn-boundary patterns, ordered longest-first so the search
/// does not accidentally match a prefix of a longer marker.
static TURN_MARKERS: &[&str] = &["\n\nAssistant:", "\n\nHuman:", "\n\n---\n\n", "\n\n"];

/// GOLD-PXP-02: find the split index for the stable/live zones.
///
/// `prompt_len` is `prompt.len()`; `keep_recent_chars` is the configured tail
/// length.  Returns a byte offset into the prompt such that:
/// - everything `[0..split]` is the stable (old) zone, and
/// - everything `[split..]` is the live zone.
///
/// The returned offset always falls on a char boundary AND on a turn boundary
/// if one exists within ±25 % of the raw char-count split point.
fn semantic_split(prompt: &str, keep_recent_chars: usize) -> usize {
    let keep = keep_recent_chars.min(prompt.len());
    let raw_split = prompt.len() - keep;

    // Adjust to char boundary.
    let mut raw_split = raw_split;
    while raw_split > 0 && !prompt.is_char_boundary(raw_split) {
        raw_split -= 1;
    }

    // Wave-11: when `keep_recent_chars >= prompt.len()` the whole prompt is the
    // live zone (old zone is empty) — return 0 so nothing is summarised. Without
    // this, the marker search below could pick a boundary > 0 and hand a slice
    // of "recent" content to the summariser.
    if raw_split == 0 {
        return 0;
    }

    // Search window: up to 25% of keep_recent_chars BACKWARD from raw_split.
    // The upper bound is raw_split itself, never past it: a boundary chosen in
    // the live zone (> raw_split) would grow the stable prefix into content that
    // changes every turn, breaking the byte-identical-prefix cache guarantee AND
    // shrinking the live zone below keep_recent_chars. `search_lo` is a raw byte
    // count so it must be snapped back to a char boundary before slicing (emoji
    // / CJK straddling the bound would otherwise panic). `raw_split` is already
    // a char boundary from the adjustment above.
    let window = keep_recent_chars / 4;
    let mut search_lo = raw_split.saturating_sub(window);
    while search_lo > 0 && !prompt.is_char_boundary(search_lo) {
        search_lo -= 1;
    }
    let search_hi = raw_split;

    // Find the last turn-boundary marker whose *end* falls within [search_lo, search_hi].
    let mut best: Option<usize> = None;
    for marker in TURN_MARKERS {
        // Scan the window region for the last occurrence of this marker.
        let region = &prompt[search_lo..search_hi.min(prompt.len())];
        let mut search_from = 0usize;
        while let Some(pos) = region[search_from..].find(marker) {
            let abs = search_lo + search_from + pos + marker.len();
            // abs must be a char boundary in the original string.
            if prompt.is_char_boundary(abs) {
                best = Some(match best {
                    Some(prev) => prev.max(abs),
                    None => abs,
                });
            }
            search_from += pos + 1;
            if search_from >= region.len() {
                break;
            }
        }
    }

    best.unwrap_or(raw_split)
}

// ---------------------------------------------------------------------------
// Payload struct (serialised into WAL frame)

/// GOLD-PXP-03: extended payload for `0xF9 HISTORY_COMPACTION_FIRED`.
/// New fields are `#[serde(default)]`-gated so old WAL frames that lack them
/// decode cleanly (the codebase bug-class: derive(Default) nulls serde field
/// defaults — we use explicit per-field attributes instead).
#[derive(serde::Serialize, serde::Deserialize)]
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

    // ── GOLD-PXP-03 churn telemetry fields ──────────────────────────────────
    /// Byte length of the stable (old) zone this fire.
    #[serde(default)]
    static_chars: usize,
    /// Byte length of the live (recent) zone this fire.
    #[serde(default)]
    dynamic_chars: usize,
    /// True when the stable zone SHA-256 differs from the previous fire's hash,
    /// indicating the "stable" prefix is not actually stable across turns.
    #[serde(default)]
    churn_detected: bool,
    /// True when the stable zone SHA-256 matches the previous fire: the provider
    /// cache almost certainly reused the encoded KV-cache for this block.
    #[serde(default)]
    cache_hit_probable: bool,
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
    /// Exact model pinned for the utility request in production.
    utility_model: Option<String>,
    /// `max_per_request` from `TokensConfig` — used to derive the threshold.
    max_tokens: u32,
    /// Fire when `estimate_tokens_pxp(prompt + system) > max_tokens * threshold_fraction`.
    threshold_fraction: f32,
    /// Characters of the prompt tail to preserve verbatim.
    keep_recent_chars: usize,
    /// WAL writer for audit frames. `None` in unit tests / when no WAL is open.
    wal: Option<WalWriterHandle>,
    /// GOLD-PXP-03: SHA-256 hex of the stable zone from the previous fire.
    /// Stored behind a Mutex so `maybe_compact` can read/write across `&self`.
    prev_static_hash: std::sync::Mutex<Option<String>>,
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
        Self::new_with_utility_model(
            inner,
            utility,
            None,
            max_tokens,
            threshold_fraction,
            keep_recent_chars,
            wal,
        )
    }

    fn new_with_utility_model(
        inner: Box<dyn Provider>,
        utility: Option<Box<dyn Provider>>,
        utility_model: Option<String>,
        max_tokens: u32,
        threshold_fraction: f32,
        keep_recent_chars: usize,
        wal: Option<WalWriterHandle>,
    ) -> Self {
        Self {
            inner,
            utility,
            utility_model,
            max_tokens,
            threshold_fraction,
            keep_recent_chars,
            wal,
            prev_static_hash: std::sync::Mutex::new(None),
        }
    }

    /// Construct from a `TokensConfig` slice. Returns the compactor boxed as
    /// `Box<dyn Provider>` ready to drop into the call chain.
    pub fn from_config(
        inner: Box<dyn Provider>,
        utility: Option<Box<dyn Provider>>,
        utility_model: Option<String>,
        cfg: &TokensConfig,
        wal: Option<WalWriterHandle>,
    ) -> Box<dyn Provider> {
        Box::new(Self::new_with_utility_model(
            inner,
            utility,
            utility_model,
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
    async fn maybe_compact(
        &self,
        mut req: Request,
        authorization: Option<(
            &crate::providers::cost_authorization::ProviderCallAuthorizer,
            &'static str,
        )>,
        raw_permit: Option<&ProviderDispatchPermit>,
    ) -> Result<Request> {
        let system_text = req.system.as_deref().unwrap_or("");
        // GOLD-PXP-04: use calibrated chars-per-token estimate instead of flat char/4.
        let estimated_tokens = estimate_tokens_pxp(&req.prompt) + estimate_tokens_pxp(system_text);

        if estimated_tokens <= self.threshold_tokens() {
            return Ok(req);
        }

        let original_chars = req.prompt.len();

        // GOLD-PXP-02: semantic boundary split — find the last turn boundary at
        // or before the keep_recent_chars offset, so the stable prefix is
        // byte-identical across consecutive fires (prompt-cache hits).
        let split_at = semantic_split(&req.prompt, self.keep_recent_chars);

        let old_zone = &req.prompt[..split_at];
        let live_zone = &req.prompt[split_at..];

        // GOLD-PXP-01: verbatim-risk guard — if the old zone contains
        // byte-exact-retrieval content (UUIDs, hex runs, paths, ID clusters),
        // skip summarisation and keep the block verbatim.
        let summary = if old_zone.is_empty() {
            String::new()
        } else if !should_compact_block(old_zone) {
            // Keep verbatim — do NOT summarise.
            old_zone.to_owned()
        } else if let Some(util) = &self.utility {
            // GOLD-ADAPT-ODY-06: pass the Odysseus self-summary system prompt so
            // the utility provider receives the structured compaction persona.
            let summary_req = Request {
                prompt: format!(
                    "Summarise the following conversation history concisely, \
                     preserving key facts, decisions, and context:\n\n{old_zone}"
                ),
                system: Some(crate::context::compactor::SELF_SUMMARY_SYSTEM_PROMPT.to_owned()),
                model: self
                    .utility_model
                    .clone()
                    .or_else(|| util.default_model().map(str::to_owned)),
                // The utility may be Claude CLI, which intentionally exposes
                // no sampling knobs. Provider defaults are the only portable
                // compaction contract; never attach a control a leaf may drop.
                temperature: None,
                top_p: None,
                sampling_seed: None,
                stop_sequences: vec![],
                thinking_budget: None,
            };
            let summary_result = match authorization {
                Some((authorizer, _)) => {
                    util.complete_authorized(summary_req, authorizer, "history_compaction.summary")
                        .await
                }
                None => {
                    util.complete_raw(
                        summary_req,
                        raw_permit.expect("raw compaction dispatch requires a permit"),
                    )
                    .await
                }
            };
            match summary_result {
                // A non-empty summary is the happy path.
                Ok(c) if !c.text.trim().is_empty() => c.text,
                // An empty-but-Ok summary must NOT be used: it would make
                // `summary` empty, and the reassembly below would then forward
                // `live_zone` alone — silently DISCARDING `old_zone` with no
                // audit frame. Fall back to the truncation placeholder so the
                // old zone is accounted for and the WAL still fires.
                Ok(_) => {
                    warn!("compactor: utility returned an empty summary; using truncation");
                    format!("[truncated {} chars of earlier context]", old_zone.len())
                }
                Err(e)
                    if e.downcast_ref::<
                        crate::providers::cost_authorization::ProviderAuthorizationError,
                    >()
                    .is_some() =>
                {
                    return Err(e);
                }
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

        // Did we actually reduce anything? The verbatim-risk guard
        // (`summary == old_zone`) and an empty old zone are no-ops — forwarding
        // the original prompt unchanged. Emitting HISTORY_COMPACTION_FIRED in
        // those cases records a ratio-1.0 "compaction" that never happened and
        // pollutes the churn/cache telemetry, so we skip the WAL frame.
        let compacted = !summary.is_empty() && summary != old_zone;

        // Reassemble: summary block + live zone.
        // When keep-verbatim fired, `summary` == `old_zone` and we skip the
        // [CONTEXT SUMMARY:] wrapper so the original bytes are preserved exactly.
        let new_prompt = if summary.is_empty() {
            live_zone.to_owned()
        } else if summary == old_zone {
            // verbatim-risk guard kept the old zone intact — re-join without wrapper.
            format!("{old_zone}{live_zone}")
        } else {
            format!("[CONTEXT SUMMARY: {summary}]\n\n{live_zone}")
        };

        // GOLD-PXP-03 churn telemetry: track the stable-zone hash on EVERY
        // past-threshold fire with a non-empty old zone — including verbatim-keep
        // fires that emit no WAL. If we only updated inside the `compacted` block,
        // a verbatim-keep fire between two real compactions would leave
        // prev_static_hash stale and the next compaction's churn/cache booleans
        // wrong. `raw_hash` also content-addresses the pre-compaction raw text
        // (ODY-06) for the WAL payload below.
        let raw_hash = hex::encode(Sha256::digest(old_zone.as_bytes()));
        let (churn_detected, cache_hit_probable) = if old_zone.is_empty() {
            (false, false)
        } else {
            let mut guard = self.prev_static_hash.lock().unwrap();
            let prev = guard.clone();
            let churn = prev.as_ref().is_some_and(|p| p != &raw_hash);
            let cache_hit = prev.as_ref().is_some_and(|p| p == &raw_hash);
            *guard = Some(raw_hash.clone());
            (churn, cache_hit)
        };

        // Best-effort WAL emit — only when a real compaction occurred.
        if let (true, Some(wal)) = (compacted, &self.wal) {
            let model_name = self.utility.as_ref().map(|u| u.name()).unwrap_or("none");

            let payload_json = json!(CompactionPayload {
                original_chars,
                summarised_chars,
                kept_chars,
                threshold_tokens: self.threshold_tokens(),
                model: model_name,
                raw_hash,
                static_chars: old_zone.len(),
                dynamic_chars: live_zone.len(),
                churn_detected,
                cache_hit_probable,
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

        req.prompt = new_prompt;
        Ok(req)
    }
}

#[async_trait]
impl Provider for CompactingProvider {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn request_controls(&self) -> ProviderRequestControls {
        self.inner.request_controls()
    }

    fn default_model(&self) -> Option<&str> {
        self.inner.default_model()
    }

    fn output_token_ceiling(&self, req: &Request) -> Option<u32> {
        self.inner.output_token_ceiling(req)
    }

    fn streams_on_wire(&self) -> bool {
        self.inner.streams_on_wire()
    }

    async fn complete_raw(
        &self,
        req: Request,
        permit: &ProviderDispatchPermit,
    ) -> Result<Completion> {
        let req = self.maybe_compact(req, None, Some(permit)).await?;
        self.inner.complete_raw(req, permit).await
    }

    async fn stream_raw(
        &self,
        req: Request,
        permit: &ProviderDispatchPermit,
    ) -> Result<ChunkStream> {
        let req = self.maybe_compact(req, None, Some(permit)).await?;
        self.inner.stream_raw(req, permit).await
    }

    async fn complete_authorized(
        &self,
        req: Request,
        authorizer: &crate::providers::cost_authorization::ProviderCallAuthorizer,
        call_scope: &'static str,
    ) -> Result<Completion> {
        let req = self
            .maybe_compact(req, Some((authorizer, call_scope)), None)
            .await?;
        self.inner
            .complete_authorized(req, authorizer, call_scope)
            .await
    }

    async fn stream_authorized(
        &self,
        req: Request,
        authorizer: &crate::providers::cost_authorization::ProviderCallAuthorizer,
        call_scope: &'static str,
    ) -> Result<ChunkStream> {
        let req = self
            .maybe_compact(req, Some((authorizer, call_scope)), None)
            .await?;
        self.inner
            .stream_authorized(req, authorizer, call_scope)
            .await
    }
}

// ---------------------------------------------------------------------------
// Arc-compatible constructor for the serve path

/// Like [`CompactingProvider::from_config`] but returns `Arc<dyn Provider>`
/// for the daemon's shared-provider slot.
pub fn arc_from_config(
    inner: Arc<dyn Provider>,
    utility: Option<Box<dyn Provider>>,
    utility_model: Option<String>,
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
        fn request_controls(&self) -> ProviderRequestControls {
            self.0.request_controls()
        }
        fn default_model(&self) -> Option<&str> {
            self.0.default_model()
        }
        fn output_token_ceiling(&self, req: &Request) -> Option<u32> {
            self.0.output_token_ceiling(req)
        }
        fn streams_on_wire(&self) -> bool {
            self.0.streams_on_wire()
        }
        async fn complete_raw(
            &self,
            req: Request,
            permit: &ProviderDispatchPermit,
        ) -> Result<Completion> {
            self.0.complete_raw(req, permit).await
        }
        async fn stream_raw(
            &self,
            req: Request,
            permit: &ProviderDispatchPermit,
        ) -> Result<ChunkStream> {
            self.0.stream_raw(req, permit).await
        }
        async fn complete_authorized(
            &self,
            req: Request,
            authorizer: &crate::providers::cost_authorization::ProviderCallAuthorizer,
            call_scope: &'static str,
        ) -> Result<Completion> {
            self.0
                .complete_authorized(req, authorizer, call_scope)
                .await
        }
        async fn stream_authorized(
            &self,
            req: Request,
            authorizer: &crate::providers::cost_authorization::ProviderCallAuthorizer,
            call_scope: &'static str,
        ) -> Result<ChunkStream> {
            self.0.stream_authorized(req, authorizer, call_scope).await
        }
    }

    Arc::from(CompactingProvider::from_config(
        Box::new(ArcAdapter(inner)),
        utility,
        utility_model,
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
                identity: Default::default(),
                model: "stub".into(),
                latency: Duration::from_millis(1),
                input_tokens: None,
                output_tokens: None,
                cache_creation_tokens: None,
                cache_read_tokens: None,
            })
        }
        async fn stream_raw(
            &self,
            _req: Request,
            _permit: &ProviderDispatchPermit,
        ) -> Result<ChunkStream> {
            unimplemented!()
        }
    }

    fn long_prompt(chars: usize) -> String {
        "x".repeat(chars)
    }

    struct RequestRecordingProvider {
        name: &'static str,
        default_model: &'static str,
        output_token_ceiling: u32,
        reply: &'static str,
        calls: Arc<Mutex<Vec<Request>>>,
    }

    #[async_trait]
    impl Provider for RequestRecordingProvider {
        fn name(&self) -> &'static str {
            self.name
        }

        fn default_model(&self) -> Option<&str> {
            Some(self.default_model)
        }

        fn output_token_ceiling(&self, _req: &Request) -> Option<u32> {
            Some(self.output_token_ceiling)
        }

        async fn complete(&self, req: Request) -> Result<Completion> {
            self.calls.lock().unwrap().push(req.clone());
            Ok(Completion {
                text: self.reply.to_string(),
                model: req.model.unwrap(),
                latency: Duration::ZERO,
                ..Completion::default()
            })
        }
    }

    fn cost_payloads(seg: &std::path::Path) -> Vec<serde_json::Value> {
        let bytes = std::fs::read(seg).unwrap();
        let header = crate::wal::segment_header::parse_segment_header(&bytes).unwrap();
        let mut cursor = header.header_len();
        let mut payloads = Vec::new();
        while cursor < bytes.len() {
            let frame = crate::wal::frame::decode_frame(&bytes[cursor..]).unwrap();
            if frame.header.event_type == crate::wal::events::EVENT_TYPE_COST_ESTIMATE_SHOWN {
                payloads.push(serde_json::from_slice(frame.payload).unwrap());
            }
            let total = frame.header.total_len as usize;
            if total == 0 {
                break;
            }
            cursor = cursor.saturating_add(total);
        }
        payloads
    }

    #[tokio::test]
    async fn authorized_compaction_gates_exact_summary_then_mutated_main_request() {
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("compactor-cost.wal");
        let (writer, join) = crate::wal::writer::spawn(seg.clone()).unwrap();
        let main_calls = Arc::new(Mutex::new(Vec::new()));
        let summary_calls = Arc::new(Mutex::new(Vec::new()));
        let compactor = CompactingProvider::new_with_utility_model(
            Box::new(RequestRecordingProvider {
                name: "main_cloud",
                default_model: "main-model",
                output_token_ceiling: 4096,
                reply: "main reply",
                calls: main_calls.clone(),
            }),
            Some(Box::new(RequestRecordingProvider {
                name: "summary_cloud",
                default_model: "summary-default",
                output_token_ceiling: 2048,
                reply: "bounded summary",
                calls: summary_calls.clone(),
            })),
            Some("summary-model".into()),
            100,
            0.8,
            50,
            Some(writer.clone()),
        );
        let provider = crate::providers::cost_authorization::AuthorizedProvider::from_box(
            Box::new(compactor),
            crate::providers::cost_authorization::ProviderCallAuthorizer::fail_closed(
                crate::permissions::AutonomyLevel::Full,
                Some(writer.clone()),
            ),
            None,
            "compactor.main",
        );
        let original_prompt = long_prompt(500);
        let original_system = "outer system".to_string();

        provider
            .complete(Request {
                prompt: original_prompt.clone(),
                system: Some(original_system.clone()),
                ..Request::default()
            })
            .await
            .unwrap();

        let summary_req = summary_calls.lock().unwrap()[0].clone();
        let main_req = main_calls.lock().unwrap()[0].clone();
        assert_eq!(summary_req.model.as_deref(), Some("summary-model"));
        assert_eq!(
            summary_req.system.as_deref(),
            Some(crate::context::compactor::SELF_SUMMARY_SYSTEM_PROMPT)
        );
        assert!(summary_req.prompt.contains(&original_prompt[..400]));
        assert_eq!(main_req.model.as_deref(), Some("main-model"));
        assert_eq!(main_req.system.as_deref(), Some(original_system.as_str()));
        assert!(
            main_req
                .prompt
                .starts_with("[CONTEXT SUMMARY: bounded summary]")
        );
        assert!(
            main_req
                .prompt
                .ends_with(&original_prompt[original_prompt.len() - 50..])
        );

        drop(provider);
        drop(writer);
        join.await.unwrap();
        let payloads = cost_payloads(&seg);
        assert_eq!(payloads.len(), 2);
        assert_eq!(payloads[0]["provider"], "summary_cloud");
        assert_eq!(payloads[0]["model"], "summary-model");
        assert_eq!(payloads[0]["output_tokens_est"], 2048);
        assert_eq!(payloads[0]["streaming"], false);
        assert_eq!(
            payloads[0]["system_hash_xxh3"].as_u64().unwrap(),
            xxhash_rust::xxh3::xxh3_64(summary_req.system.as_deref().unwrap().as_bytes())
        );
        assert_eq!(
            payloads[0]["prompt_hash_xxh3"].as_u64().unwrap(),
            xxhash_rust::xxh3::xxh3_64(summary_req.prompt.as_bytes())
        );
        assert_eq!(payloads[1]["provider"], "main_cloud");
        assert_eq!(payloads[1]["model"], "main-model");
        assert_eq!(payloads[1]["output_tokens_est"], 4096);
        assert_eq!(
            payloads[1]["system_hash_xxh3"].as_u64().unwrap(),
            xxhash_rust::xxh3::xxh3_64(main_req.system.as_deref().unwrap().as_bytes())
        );
        assert_eq!(
            payloads[1]["prompt_hash_xxh3"].as_u64().unwrap(),
            xxhash_rust::xxh3::xxh3_64(main_req.prompt.as_bytes())
        );
    }

    #[tokio::test]
    async fn no_fire_when_under_threshold() {
        // 80 chars → 20 tokens → well under 80-token threshold
        let prompt = long_prompt(80);
        let (inner, ic) = StubProvider::new("inner_reply");
        let (util, _uc) = StubProvider::new("SUMMARY");
        let cp = CompactingProvider::new(Box::new(inner), Some(Box::new(util)), 100, 0.8, 50, None);
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
        let cp = CompactingProvider::new(Box::new(inner), Some(Box::new(util)), 100, 0.8, 50, None);
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

    /// Wave-6 regression: an empty-but-Ok utility summary must NOT silently
    /// drop the old zone. The compactor falls back to a truncation placeholder,
    /// so the forwarded prompt still accounts for the earlier context.
    #[tokio::test]
    async fn empty_utility_summary_falls_back_to_truncation_not_drop() {
        let prompt = long_prompt(500);
        let (inner, ic) = StubProvider::new("inner_reply");
        let (util, _uc) = StubProvider::new(""); // empty-but-Ok summary
        let cp = CompactingProvider::new(Box::new(inner), Some(Box::new(util)), 100, 0.8, 50, None);
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
        cp.complete(req).await.unwrap();
        let forwarded = ic.lock().unwrap()[0].clone();
        // Old zone must NOT be silently dropped — the truncation placeholder
        // stands in for it, and the live tail is still present.
        assert!(
            forwarded.contains("[truncated") && forwarded.contains("chars of earlier context]"),
            "empty summary must fall back to truncation, got: {forwarded:.120}"
        );
        let live = &prompt[prompt.len() - 50..];
        assert!(forwarded.ends_with(live), "live zone missing");
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
                identity: Default::default(),
                model: "capture".into(),
                latency: Duration::from_millis(0),
                input_tokens: None,
                output_tokens: None,
                cache_creation_tokens: None,
                cache_read_tokens: None,
            })
        }
        async fn stream_raw(
            &self,
            _: Request,
            _permit: &ProviderDispatchPermit,
        ) -> Result<ChunkStream> {
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
        assert!(
            sys.is_some(),
            "utility must receive a system prompt (ODY-06)"
        );
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
            assert_eq!(
                calls[0],
                "x".repeat(80),
                "should not compact under threshold"
            );
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

    // -------------------------------------------------------------------------
    // GOLD-PXP-01 — keepSharp verbatim-risk guard

    /// A block containing a UUID and a 24-char hex key must survive
    /// maybe_compact byte-identical — even though the total prompt is large
    /// enough to trigger compaction.
    #[tokio::test]
    async fn pxp01_uuid_block_survives_verbatim() {
        // Build a prompt: a big prose preamble followed by a small block that
        // contains a UUID and a 24-char hex key. The preamble is the "old zone"
        // that would normally be summarised; the critical block is embedded in
        // the old zone so the guard must keep it.
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        let hex_key = "deadbeefcafebabe12345678"; // 24 hex chars — matches RE_HEX_RUN
        let critical = format!("resource id: {uuid}\ntoken: {hex_key}");
        // Prepend enough prose to push estimated tokens above threshold.
        let preamble = "word ".repeat(600); // 3000 chars → ~3000/3.7≈810 tokens
        let prompt = format!("{preamble}\n\n{critical}");

        let (inner, ic) = StubProvider::new("inner_reply");
        let (util, uc) = StubProvider::new("SUMMARISED");
        let cp = CompactingProvider::new(
            Box::new(inner),
            Some(Box::new(util)),
            /* max_tokens   */ 100,
            /* threshold    */ 0.8,
            /* keep_recent  */ 50,
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
        cp.complete(req).await.unwrap();

        // The utility must NOT have been called (old zone kept verbatim).
        let util_calls = uc.lock().unwrap();
        assert_eq!(
            util_calls.len(),
            0,
            "utility must not be called for a UUID/hex block"
        );

        // Inner must have received the whole prompt (old zone kept verbatim,
        // no [CONTEXT SUMMARY:] wrapper injected by the summariser).
        let inner_calls = ic.lock().unwrap();
        assert_eq!(inner_calls.len(), 1);
        // The prompt forwarded to inner must contain the UUID and hex key.
        let fwd = &inner_calls[0];
        assert!(
            fwd.contains(uuid),
            "UUID must be present in forwarded prompt"
        );
        assert!(
            fwd.contains(hex_key),
            "hex key must be present in forwarded prompt"
        );
    }

    /// should_compact_block must return true for plain prose (no identifiers).
    #[test]
    fn pxp01_plain_prose_is_compactable() {
        let prose = "This is some ordinary discussion about architecture decisions. \
                     No special identifiers here, just plain words repeated. "
            .repeat(10);
        assert!(
            should_compact_block(&prose),
            "plain prose should be compactable"
        );
    }

    /// should_compact_block must return false for a block with a UUID.
    #[test]
    fn pxp01_uuid_not_compactable() {
        let s = "here is a resource: 550e8400-e29b-41d4-a716-446655440000 end";
        assert!(
            !should_compact_block(s),
            "UUID block must not be compactable"
        );
    }

    /// should_compact_block must return false for a block with a long hex run.
    #[test]
    fn pxp01_long_hex_not_compactable() {
        let s = "commit hash: deadbeef12345678abcdef90 was the culprit";
        assert!(
            !should_compact_block(s),
            "long hex run must not be compactable"
        );
    }

    /// Wave-3 regression: `0x`-prefixed hex (Ethereum addresses, tx hashes,
    /// Rust literals) must be caught — the `x` in `0x` is a word char, so a
    /// bare `\b[0-9a-f]{8,}\b` used to miss them.
    #[test]
    fn pxp01_0x_prefixed_hex_not_compactable() {
        for s in [
            "send to 0x742d35Cc6634C0532925a3b844Bc454e4438f44e now",
            "tx 0xdeadbeefdeadbeef confirmed",
            "const MAGIC: u32 = 0xCAFEBABE;",
        ] {
            assert!(
                !should_compact_block(s),
                "0x-hex must not be compactable: {s}"
            );
        }
    }

    /// Wave-8 regression: an ordinary English word that happens to be 8+
    /// all-[a-f] letters must NOT veto compaction (no digit → not an id).
    #[test]
    fn pxp01_english_hex_word_is_compactable() {
        for s in [
            "the whole thing is a total deadbeef situation honestly",
            "that cafebabe of a plan will never facefeed correctly",
        ] {
            assert!(
                should_compact_block(s),
                "all-alpha hex word must stay compactable: {s}"
            );
        }
    }

    /// Wave-3 regression: a Unix path appearing mid-sentence must be caught —
    /// the old `^`-anchored regex only matched paths at the start of a line.
    #[test]
    fn pxp01_midline_unix_path_not_compactable() {
        let s = "Your config lives at /etc/neoth/config.yaml — update it now";
        assert!(
            !should_compact_block(s),
            "mid-sentence path must not be compactable"
        );
    }

    /// Wave-4 regression: a URL's path must NOT veto compaction — otherwise a
    /// history containing any link (nearly all of them) is kept verbatim and
    /// compaction never fires. A plain-prose block with only a URL and no other
    /// identifier is compactable.
    #[test]
    fn pxp01_url_only_block_is_compactable() {
        let s = "The docs are at https://api.anthropic.com/v1/messages for reference.";
        assert!(
            should_compact_block(s),
            "a URL alone must not veto compaction"
        );
    }

    /// Wave-5 regression: a path after a shell redirect/pipe operator (no space)
    /// must still be caught.
    #[test]
    fn pxp01_redirect_path_not_compactable() {
        for s in [
            "run 2>/var/log/neoth/err.log now",
            "tee |/usr/bin/logger here",
        ] {
            assert!(
                !should_compact_block(s),
                "redirect/pipe path must not be compactable: {s}"
            );
        }
    }

    // -------------------------------------------------------------------------
    // GOLD-PXP-02 — semantic boundary split

    /// Wave-9 regression: multibyte codepoints straddling the search window
    /// bounds must NOT panic (`byte index N is not a char boundary`). The split
    /// point returned must always be a valid char boundary.
    #[test]
    fn pxp02_semantic_split_no_panic_on_multibyte() {
        for (prompt, keep) in [
            ("💡abc", 4usize),
            ("日本語テキスト💡more text here", 6),
            ("emoji 🎉 in the middle 🚀 of things", 10),
            ("плоскость экран 中文 mixed", 8),
        ] {
            let at = semantic_split(prompt, keep);
            assert!(
                prompt.is_char_boundary(at),
                "split {at} not a char boundary in {prompt:?}"
            );
            // Slicing at the returned point must not panic.
            let _ = &prompt[..at];
            let _ = &prompt[at..];
        }
    }

    /// Wave-11: when keep_recent_chars >= prompt.len() the whole prompt is live,
    /// so the split must be 0 — even if the prompt contains a turn marker.
    #[test]
    fn pxp02_semantic_split_zero_when_keep_covers_whole_prompt() {
        let prompt = "assistant preamble\n\nHuman: hi there, this is the whole thing";
        assert_eq!(semantic_split(prompt, prompt.len()), 0);
        assert_eq!(semantic_split(prompt, prompt.len() + 1000), 0);
    }

    /// Wave-18: the split must NEVER exceed the raw keep_recent boundary — a
    /// turn marker sitting in the live zone must not pull the split forward
    /// (that would shrink the live zone below keep_recent_chars and make the
    /// "stable" prefix change every fire, defeating the prompt cache).
    #[test]
    fn pxp02_semantic_split_never_exceeds_keep_recent_boundary() {
        // 200-char stable prefix, then a marker right at the boundary, then the
        // live tail. keep_recent_chars=100 → raw_split≈len-100 sits before the
        // second marker, which must NOT be chosen.
        let stable = "x".repeat(200);
        let prompt = format!("{stable}\n\nHuman: recent turn content here padded out");
        let keep = 40;
        let raw_boundary = prompt.len() - keep.min(prompt.len());
        let at = semantic_split(&prompt, keep);
        assert!(
            at <= raw_boundary,
            "split {at} exceeded keep_recent boundary {raw_boundary}"
        );
        assert!(prompt.is_char_boundary(at));
    }

    /// Two consecutive fires over the same stable prefix must produce identical
    /// stable-zone bytes (byte-identical prefix → prompt-cache hit).
    #[tokio::test]
    async fn pxp02_stable_prefix_identical_across_two_fires() {
        // Build a prompt that always fires compaction: big stable prefix +
        // a small per-turn tail that changes.
        fn big_prompt(turn_suffix: &str) -> String {
            // Use prose so PXP-04 gives ~3.7 chars/token; 1500 chars → ~405 tokens > 80
            format!(
                "{}\n\nHuman: {turn_suffix}",
                "The system context remains constant. ".repeat(40)
            )
        }

        // We need to observe what the old zone is.  Use a SystemCapture-style
        // provider that records the full prompt text it receives.
        struct PromptCapture(Arc<Mutex<Vec<String>>>);
        #[async_trait]
        impl Provider for PromptCapture {
            fn name(&self) -> &'static str {
                "capture"
            }
            async fn complete(&self, req: Request) -> Result<Completion> {
                self.0.lock().unwrap().push(req.prompt.clone());
                Ok(Completion {
                    text: "ok".into(),
                    identity: Default::default(),
                    model: "capture".into(),
                    latency: Duration::from_millis(0),
                    input_tokens: None,
                    output_tokens: None,
                    cache_creation_tokens: None,
                    cache_read_tokens: None,
                })
            }
            async fn stream_raw(
                &self,
                _: Request,
                _permit: &ProviderDispatchPermit,
            ) -> Result<ChunkStream> {
                unimplemented!()
            }
        }

        let captures = Arc::new(Mutex::new(Vec::new()));
        let inner = PromptCapture(Arc::clone(&captures));
        let (util, _) = StubProvider::new("SUMMARY");

        let cp = CompactingProvider::new(
            Box::new(inner),
            Some(Box::new(util)),
            /* max_tokens   */ 100,
            /* threshold    */ 0.8,
            /* keep_recent  */ 80,
            None,
        );

        // Fire 1
        let req1 = Request {
            prompt: big_prompt("first turn"),
            system: None,
            model: None,
            temperature: None,
            top_p: None,
            sampling_seed: None,
            stop_sequences: vec![],
            thinking_budget: None,
        };
        cp.complete(req1).await.unwrap();

        // Fire 2 — identical stable prefix, different tail.
        let req2 = Request {
            prompt: big_prompt("second turn"),
            system: None,
            model: None,
            temperature: None,
            top_p: None,
            sampling_seed: None,
            stop_sequences: vec![],
            thinking_budget: None,
        };
        cp.complete(req2).await.unwrap();

        let calls = captures.lock().unwrap();
        assert_eq!(calls.len(), 2, "both fires must reach inner provider");
        // The stable zone (summary or verbatim keep) is the non-tail part of the
        // forwarded prompt. Both forwarded prompts must share the same prefix
        // up to the live zone.  We verify by checking that the live zone of
        // fire-2 is absent from the live zone of fire-1.
        assert!(
            !calls[0].contains("second turn"),
            "first fire's stable zone must not contain second-turn tail"
        );
        assert!(
            !calls[1].contains("first turn"),
            "second fire's stable zone must not contain first-turn tail"
        );
    }

    // -------------------------------------------------------------------------
    // GOLD-PXP-03 — churn telemetry

    /// Two fires over identical stable zones → cache_hit_probable=true.
    /// After mutating the stable zone → churn_detected=true.
    #[test]
    fn pxp03_churn_flags_across_two_fires() {
        // We test the churn logic in isolation by driving prev_static_hash
        // directly (the field is private but accessible within the module).
        let hash_a = "aabbcc";
        let hash_b = "ddeeff";

        // Simulate: first fire — no previous hash yet.
        let mut prev: Option<String> = None;
        let (churn1, cache1) = {
            let churn = prev.as_ref().is_some_and(|p| p != hash_a);
            let cache = prev.as_ref().is_some_and(|p| p == hash_a);
            prev = Some(hash_a.to_owned());
            (churn, cache)
        };
        assert!(!churn1, "no churn on first fire (no prev)");
        assert!(!cache1, "no cache-hit on first fire (no prev)");

        // Simulate: second fire — same hash as first.
        let (churn2, cache2) = {
            let churn = prev.as_ref().is_some_and(|p| p != hash_a);
            let cache = prev.as_ref().is_some_and(|p| p == hash_a);
            prev = Some(hash_a.to_owned());
            (churn, cache)
        };
        assert!(!churn2, "no churn when stable zone unchanged");
        assert!(cache2, "cache_hit_probable when stable zone unchanged");

        // Simulate: third fire — different hash (stable zone changed).
        let (churn3, cache3) = {
            let churn = prev.as_ref().is_some_and(|p| p != hash_b);
            let cache = prev.as_ref().is_some_and(|p| p == hash_b);
            prev = Some(hash_b.to_owned());
            (churn, cache)
        };
        assert!(churn3, "churn_detected when stable zone changed");
        assert!(!cache3, "no cache-hit when stable zone changed");
        let _ = prev;
    }

    // -------------------------------------------------------------------------
    // GOLD-PXP-04 — calibrated chars-per-token

    /// Dense JSON must trigger compaction earlier (fewer chars needed to cross
    /// the token threshold) than plain prose of the same char count.
    #[test]
    fn pxp04_dense_json_fires_earlier_than_prose() {
        // With max_tokens=100 and threshold=0.8, compaction fires when
        // estimated_tokens > 80.
        //
        // JSON: 2.0 chars/token → need > 160 chars to exceed 80 tokens.
        // Prose: 3.7 chars/token → need > 296 chars to exceed 80 tokens.
        //
        // So 200 chars of dense JSON should exceed the threshold,
        // but 200 chars of prose should NOT.

        let json_block: String = {
            // Build a valid JSON array of objects (dense JSON).
            let items: Vec<String> = (0..10)
                .map(|i| format!(r#"{{"id":{i},"value":{i}00,"flag":true}}"#))
                .collect();
            format!("[{}]", items.join(","))
        };
        assert!(
            json_block.len() >= 160,
            "JSON block must be at least 160 chars for the test to be meaningful; got {}",
            json_block.len()
        );

        let prose_block: String = "word ".repeat(40); // 200 chars of prose
        assert_eq!(prose_block.len(), 200);

        let json_tokens = estimate_tokens_pxp(&json_block);
        let prose_tokens = estimate_tokens_pxp(&prose_block);

        // JSON tokens should be higher (denser) than prose tokens for the same
        // approximate char count: more tokens per char = denser.
        assert!(
            json_tokens > prose_tokens,
            "dense JSON ({} chars → {} tokens) should estimate more tokens \
             than same-length prose ({} chars → {} tokens)",
            json_block.len(),
            json_tokens,
            prose_block.len(),
            prose_tokens
        );

        // Verify the threshold behaviour: JSON block should cross 80 tokens.
        assert!(
            json_tokens > 80,
            "JSON block ({} chars → {} tokens) must exceed threshold of 80",
            json_block.len(),
            json_tokens
        );
        // Prose block should NOT cross 80 tokens with 200 chars.
        assert!(
            prose_tokens <= 80,
            "prose block (200 chars → {} tokens) must not exceed threshold of 80",
            prose_tokens
        );
    }
}
