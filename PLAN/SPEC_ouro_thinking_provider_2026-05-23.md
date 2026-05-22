# SPEC — Ouro Thinking Models as Qwen-Alternative Provider

**Status**: BUILD-READY — multi-day work blocked on operator pick of phase order.
**Created**: 2026-05-23 Session 21.
**Triggered by**: operator brief — "als Qwen alternative soll man in cli oder gui auch Ouro auswählen können die thinking-modelle".
**Research**: agent run a010e018... (Session 21, 2026-05-23).

---

## What Ouro is

ByteDance Seed's `Ouro` family — **looped decoder-only transformers**
(LoopLM) where 24 layers are applied 4 times recurrently before any
output token. Reasoning happens in *latent* recurrent state, not in
`<think>` text tags.

**Public checkpoints** (all Apache-2.0, HuggingFace, `ByteDance/` org):

| ID | Params | Variant |
|---|---|---|
| `ByteDance/Ouro-1.4B` | 1.4B | Base LoopLM |
| `ByteDance/Ouro-2.6B` | 2.6B | Base LoopLM (upcycled from 1.4B) |
| `ByteDance/Ouro-1.4B-Thinking` | 1.4B | SFT reasoning variant |
| `ByteDance/Ouro-2.6B-Thinking` | 2.6B | SFT reasoning variant |

Paper: [arXiv 2510.25741](https://arxiv.org/abs/2510.25741).
Project: [ouro-llm.github.io](https://ouro-llm.github.io).

## Why not Qwen-as-Ouro

Architecture is **genuinely novel** — `candle_transformers::models::*`
does **NOT** support it. Key non-Qwen-isms:

- 24 layers applied 4× recurrently (`total_ut_steps: 4`) — same weight
  tensor referenced N times, not separate per-loop weights
- MHA, not GQA (Qwen2 uses GQA)
- Sandwich RMSNorm (Qwen2 uses standard RMSNorm)
- Custom `model_type` requires `trust_remote_code=True` + transformers
  `<4.56.0`
- No GGUF / Q8 quantization in the wild — only SafeTensors BF16/FP16
- No `<think>` tag stripping needed; reasoning is inline prose in the
  -Thinking variants

## Why NEOTH wants it

- **Reasoning model** alongside Qwen3-Q8 default → operator gets
  thinking-style replies on demand without an external API
- **Tiny memory footprint**: Ouro-1.4B-Thinking BF16 ≈ 3-4.5 GB VRAM,
  Q8 (manual) ≈ 2-2.5 GB VRAM → operator-safe on any laptop with
  ≥4 GB VRAM or CPU-only
- **Apache-2.0** — clean for the OSS release path

## Scope (single workstream, ~5-10 dev-days)

This SPEC pins the build order so future sessions pick up cleanly.

### Phase O-1 — Custom candle model module (~3 days)

New file: `SRC/neothd/src/providers/ouro/model.rs`

Implements the LoopLM forward pass from scratch. NEOTH-internal
module — not upstream candle. Uses primitives from
`candle_nn` (`linear`, `embedding`, `RmsNorm` already in
`candle_transformers::models::with_tracing`) so weight loading
hits the standard `VarBuilder` path.

Components:

```
pub struct OuroConfig {
    pub vocab_size: usize,         // 49152
    pub hidden_size: usize,        // 2048
    pub intermediate_size: usize,
    pub num_layers: usize,         // 24
    pub num_attention_heads: usize, // MHA (no num_kv_heads)
    pub max_position_embeddings: usize, // 32K
    pub rope_theta: f64,
    pub rms_norm_eps: f64,
    pub total_ut_steps: usize,     // 4 — loop count
    pub early_exit_threshold: Option<f32>,
}

struct OuroAttention { /* MHA, RoPE-rotated Q/K */ }
struct OuroMLP       { /* SwiGLU */ }
struct OuroLayer {
    norm_pre: RmsNorm,
    attn: OuroAttention,
    norm_mid: RmsNorm,    // Sandwich norm
    mlp: OuroMLP,
    norm_post: RmsNorm,
}

pub struct Ouro {
    embed_tokens: Embedding,
    layers: Vec<OuroLayer>, // 24 layers shared
    norm: RmsNorm,
    lm_head: Linear,
    total_ut_steps: usize,
}

impl Ouro {
    pub fn new(cfg: &OuroConfig, vb: VarBuilder) -> Result<Self>;
    pub fn forward(&mut self, ids: &Tensor, kv_offset: usize) -> Result<Tensor>;
    // Inside forward: for _ in 0..total_ut_steps { xs = layers.iter().fold(xs, |h, l| l.forward(h)) }
}
```

Tests: shape-only smoke tests against a synthetic config that
constructs the model on CPU + runs forward on `[1, 4]` input
ids. Real weights gated by `NEOTH_OURO_TEST_REPO_PATH`.

### Phase O-2 — Provider impl (~1 day)

New file: `SRC/neothd/src/providers/ouro/mod.rs`

```
pub struct OuroAdapter {
    repo: String,
    cache_dir: PathBuf,
    weights_path: PathBuf,
    config_path: PathBuf,
    tokenizer_path: PathBuf,
    accelerator: Option<Accelerator>,
    sampling: SamplingConfig,
    loaded: Arc<Mutex<Option<LoadedOuro>>>,
}

#[async_trait]
impl Provider for OuroAdapter {
    fn name(&self) -> &'static str { "ouro" }
    async fn complete(&self, req: Request) -> Result<Completion>;
    async fn stream(&self, req: Request) -> Result<ChunkStream>;
}

#[async_trait]
impl EmbedProvider for OuroAdapter { /* mirror local_qwen pattern */ }
```

Mirrors `local_qwen.rs` structure (ensure_loaded + run_forward +
sample_token reuse).

### Phase O-3 — Config + wizard + CLI surface (~1 day)

`config/inference.rs`:
- Extend `ProviderKind` enum with `Ouro` variant
- New `OuroConfig` block on `FreedomConfig`:
  ```
  ouro:
    checkpoint: ouro-1.4b-thinking | ouro-2.6b-thinking | ouro-1.4b | ouro-2.6b
    max_loop_steps: u32        # operator override for total_ut_steps (default 4)
    early_exit_threshold: f32  # optional — when hidden-state entropy
                               # falls below this on loop N<4, stop early
  ```
- Provider selector wires `OuroAdapter` for `provider_kind: ouro`

`cli/init.rs` (wizard):
- New "ouro" option in provider selector step 5
- Operator-readable copy: "Ouro — looped reasoning model from
  ByteDance. Thinks in latent state, replies with explicit reasoning
  prose. Smaller than Qwen3 (1.4B vs 3B) but slower per-token because
  of 4 internal passes. Apache-2.0."
- Checkpoint sub-step: 4 options (1.4b base/thinking, 2.6b base/thinking)

`cli/providers.rs` (or wherever provider introspection lives):
- `neoth providers --output table` lists ouro with checkpoint + loop count

### Phase O-4 — GUI surface (~0.5 day)

`SRC/neothd-gui/ui/main.slint` + `settings.slint`:
- Wizard provider-choice dropdown gains "ouro" option
- Settings → Config → provider combo gains "ouro" option
- New Ouro-specific sub-panel under Settings → Hemispheres: checkpoint
  selector + loop-steps slider (operator can experiment with N=1..6)

### Phase O-5 — Q8 quantization path (~2 days, optional)

Currently no GGUF / Q8 for Ouro on HuggingFace. Options:

1. **In-process Q8 at load time** — candle's `quantized::QTensor` can
   quantize BF16 weights on the fly during `VarBuilder` construction.
   Cost: ~30-60s extra cold-start, ~50% memory reduction.
2. **Upstream llama.cpp PR** — community-dependent, weeks. Skip for v1.

Recommended: Phase O-5 ships as in-process Q8 (option 1) gated behind
`freedom.yaml::inference.ouro.quantize: q8`. Default `none` (BF16) for
v1; operator opts in when low-VRAM matters.

### Phase O-6 — Integration tests (~1 day)

`tests/ouro_integration.rs` (gated `#[ignore]`, needs
`NEOTH_OURO_TEST_REPO_PATH`):
- forward pass: prompt → completion contains reasoning prose
- embed pass: L2-normalised vector, cos<0.99 between distinct prompts
- stream pass: SSE-style chunks arrive progressively
- loop-step override: max_loop_steps=2 produces different output than
  max_loop_steps=4 (proves the loop count is honoured)

## Effort estimate

| Phase | Days | Blocking |
|---|---|---|
| O-1 candle model module | 3 | None |
| O-2 Provider impl | 1 | O-1 |
| O-3 Config + wizard + CLI | 1 | O-2 |
| O-4 GUI surface | 0.5 | O-3 |
| O-5 Q8 quantization | 2 | O-2 (optional for v1) |
| O-6 Integration tests | 1 | O-3 |
| **Total v1 (skip O-5)** | **6.5 days** | |
| **Total with Q8** | **8.5 days** | |

## Decisions deferred to the build session

1. **Default checkpoint** — recommend `Ouro-1.4B-Thinking` (smaller +
   reasoning-friendly). Operator opts up to 2.6B for harder tasks.
2. **Streaming format** — Ouro doesn't natively stream within a loop
   (one forward pass = N×24 layer applications, then one token). Stream
   chunk granularity = per-token, same as Qwen path.
3. **Loop-step override safety** — clamp at `[1, 8]`; values outside
   bail with operator-readable error. 4 is the trained default; >8
   is wasted compute, <1 breaks the architecture.

## Hard-rule compliance

- ✅ **AIO**: weights auto-download via `hf-hub` (same pattern as
  Qwen)
- ✅ **Self-contained**: candle in-process inference, no external
  worker
- ✅ **Default-ON + runtime toggle**: operator picks ouro vs qwen via
  `provider_kind`; both work; neither blocks the other
- ✅ **Noob wizard explains**: copy already drafted in O-3 above
- ✅ **GUI + CLI parity**: O-3 + O-4 ship both surfaces

## Not in this SPEC

- Multi-loop branching / beam search at the loop level (research only,
  not in any shipped Ouro checkpoint)
- Custom early-exit threshold tuning — exposed but defaults to the
  paper's value; no operator-facing tuning UI
- Ouro-as-hemisphere (Left/Right/Cerebellum slot) — falls out of O-3
  for free since hemispheres consume ProviderKind, no extra work

## Status

Ratified by architect-agent verdict in Session 21 (2026-05-23) per
`memory/neoth_open_decisions_verdicts.md`. Build sessions consume
phases O-1..O-6 in order. Operator can run `neoth init --force` after
O-3 lands to flip to Ouro without waiting for O-4 GUI.
