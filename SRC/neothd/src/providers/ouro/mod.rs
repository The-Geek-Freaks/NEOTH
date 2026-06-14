//! Ouro thinking-models provider — ByteDance Seed's LoopLM family
//! as a Qwen-alternative on-device inference path.
//!
//! Architecture: looped decoder-only transformer (LoopLM). 24 layers
//! applied 4× recurrently before producing each output token. Reasoning
//! happens in *latent* recurrent state — `Ouro-*` base variants output
//! plain tokens, `Ouro-*-Thinking` SFT variants prepend inline reasoning
//! prose. **No `<think>` tag stripping needed.**
//!
//! Public checkpoints (Apache-2.0, HuggingFace `ByteDance/` org):
//!   - `ByteDance/Ouro-1.4B` / `Ouro-2.6B` — base LoopLM
//!   - `ByteDance/Ouro-1.4B-Thinking` / `Ouro-2.6B-Thinking` — SFT
//!     reasoning variants (default for NEOTH wizard's "reasoning"
//!     checkpoint pick)
//!
//! Paper: [arXiv 2510.25741](https://arxiv.org/abs/2510.25741).
//!
//! ## Why a custom module
//!
//! Ouro's architecture is structurally incompatible with
//! `candle_transformers::models::qwen2` / `llama` / others:
//!   - 24 layers applied 4× recurrently (`total_ut_steps`) — same
//!     weight tensor referenced N times, not separate per-loop weights
//!   - MHA, not GQA (Qwen2 uses GQA)
//!   - Sandwich RMSNorm (norm_pre + norm_mid + norm_post per layer)
//!   - Custom `model_type` requires `trust_remote_code=True` in HF
//!     transformers; no upstream candle module exists
//!
//! v0.1 scope = O-1 (config + model scaffolding). O-2 (Provider impl),
//! O-3 (config/wizard/CLI), O-4 (GUI), O-5 (Q8 quantisation), O-6
//! (integration tests) follow in subsequent sessions per
//! `PLAN/SPEC_ouro_thinking_provider_2026-05-23.md`.

pub mod adapter;
pub mod forward;
pub mod layers;
pub mod model;
pub mod model_trait;
/// GOLD-ADAPT-KV-01 — cross-request prefix-KV reuse cache (LMCache idea, adapted
/// to Ouro's recurrent per-loop KV). Gated OFF by default.
pub mod prefix_kv_cache;
pub mod quantize;
pub mod quantized_forward;
pub mod quantized_layers;
pub mod rope;
