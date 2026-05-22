# SPEC — R-02 Phase 3 (LLM clustering for dreaming pipeline)

**Status**: blocked on Day-14b local inference. Single-session
ship structurally impossible until in-process Qwen3-Q8 inference
lands.

**Parent**: R-02 dreaming pipeline. Phase 1 + 2 already in tree
(`daemon::dreaming` module: storage + composer + JSONL persist +
`seed_with_dreams` recall hook).

## What Phase 3 does

The Phase 2 composer surfaces the day's events as a flat
deterministic snapshot — "Theme `morning`: 47 events between
ts=1000 and ts=86399. Anchors: first | second | … last". That
gets the operator a structural answer but no SEMANTIC compression.
Phase 3 replaces the deterministic composer with an LLM-driven
one:

1. **Theme clustering**: take the day's events, run them through
   an embedding model (Qwen3-Q8 mean-pool over the 768-dim
   embed), build a cosine-similarity matrix, run agglomerative
   clustering with a 0.65 threshold to identify ~3-7 themes.
2. **Theme summarisation**: for each cluster, feed the events
   into a local LLM prompt ("Summarise these {n} events as a
   2-3 sentence motif. Surface the key actors, the topic, and
   the outcome.") + capture the response.
3. **Cross-theme dependencies**: if two themes share >40%
   actor overlap OR their events are temporally adjacent,
   merge into one with a compound label.

## Why it's blocked

Day-14b (in-process local Qwen3 inference via candle) is the
blocker. The current state of Day-14b in PROGRESS.md:

- Phase 1 candle 0.8 builds clean, accelerator-detect works,
  InferenceTopology + 3-hemisphere wiring done
- Forward-pass + sampling-loop NOT yet shipped (memory note
  `neoth_d14b_phase1`)

Without forward-pass, there's no way to compute embeddings or
run summarisation locally. Cloud fallback is theoretically
available (the operator's OpenAI / Anthropic provider would
work), but:

- The dreaming pipeline runs nightly + processes 100s of
  events per day → cloud cost balloons.
- Memory tier privacy: every event flowing through the
  dreaming pipeline is then sent to a cloud provider —
  conflicts with the operator's autonomy gates + the
  `consent_required_for_cloud` policy.

## Phase 3 wire-in shape (when Day-14b ships)

The composer signature is already stable:

```rust
pub fn compose_dream(day: &str, theme_label: &str, events: &[EventRef]) -> Dream
```

Phase 3 replaces the body — same return type, same call sites.
Add a Phase 3 entry point:

```rust
pub async fn compose_themed_dreams_for_day(
    home: &Path,
    day: &str,
    embedder: &dyn LocalEmbedder,
    summariser: &dyn LocalSummariser,
) -> Vec<Dream>
```

The `LocalEmbedder` + `LocalSummariser` trait objects are
filled by Day-14b's Qwen3 forward-pass. Until then, the
function returns an empty Vec (no dreams composed via LLM).

## Open decisions

1. **Embedding model choice**: stay on Qwen3-Q8 (matches the
   skill router's two-stage embedding plan) OR switch to a
   smaller dedicated embedder like BGE-small-en (faster, but
   adds a second model to the in-binary footprint)?
2. **Daily run cadence**: cron at 03:00 local (when the
   operator's laptop is likely idle) vs on-demand via
   `neoth dream now` CLI?
3. **Privacy boundary**: should events from the operator's
   Telegram / Slack / WhatsApp chats be included in the
   clustering by default? Memory tier already has them, but
   the dream summaries are surfaced in recall — operator may
   not want "your conversation with Alice" surfaced as a
   theme.

## Estimate

Once Day-14b forward-pass ships: ~2 weeks of focused work.

- Clustering primitives: 3-4 days
- Summarisation prompts + golden-set test: 2-3 days
- Cron wire-up + WAL `0xF1 DREAM_COMPOSED` audit frame: 2 days
- Privacy gate + per-event opt-out tag: 2-3 days
- Operator-facing surface (`neoth dream` CLI + GUI panel):
  2-3 days
