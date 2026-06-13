//! GOLD-ADAPT-ODY-13 — hardware-fit model scorer.
//!
//! Memory-bandwidth-bound decode-throughput estimate + VRAM fit + ranking,
//! surfaced via `neoth models fit`. Complements `models recommend` (which
//! model) with "how fast will it run on this GPU".

pub mod fit;

pub use fit::{
    default_candidates, estimate_tok_s, lookup_gpu, rank_models, GpuSpec, ModelFit,
    DECODE_EFFICIENCY, FIT_HEADROOM, KNOWN_GPUS,
};
