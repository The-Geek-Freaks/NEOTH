//! GOLD-ADOPT-10/11 — local-model selection (whichllm-port, stage 1).
//!
//! Pick the largest local model that ACTUALLY fits the operator's VRAM in
//! NEOTH's `local_qwen` candle path. That path loads **F16 safetensors** (not
//! quantized GGUF), so the fit math is honest about F16 weight bytes — unlike
//! the old `GpuReport::recommended_model_tier()` thresholds, which assumed
//! quantized inference and would recommend a 72B model (~144 GB F16) for a
//! 24 GiB GPU that can only hold a 7B (~14 GB F16).
//!
//! **Operator mandate (2026-06-09): local models run QUANTIZED — Q8 or Q4 —
//! preferring abliterated / unsloth GGUFs, always offering the newest/best.**
//! Quantizing is the whole point: a 24 GiB GPU stuck at a 7B in F16 runs a **32B
//! at Q4** (~21 GB) or a near-lossless **14B at Q8** instead. So the quant-aware
//! [`quantized_shortlist`] / [`recommend_quantized`] are the primary surface
//! (`Quant::{Q4,Q8}`); they need a GGUF runtime (Ollama via OpenAiCompat, or a
//! candle GGUF loader — GOLD-ADOPT-13) to actually load those models. The
//! [`fit_local_qwen`] F16 path remains the stopgap for NEOTH's current
//! in-process candle `local_qwen` loader (safetensors only) until ADOPT-13.
//!
//! Stage 2 (GOLD-ADOPT-11) resolves each (size, quant) pick to a concrete,
//! NEWEST abliterated/unsloth GGUF repo via a live HuggingFace lookup, and
//! layers a benchmark-quality score table on top.

/// Quantization of a local GGUF model. Bytes-per-weight drives the VRAM fit:
/// Q4 ≈ 0.5 B/param, Q8 ≈ 1.0 B/param, F16 ≈ 2.0 B/param. Quantizing is how a
/// 24 GiB GPU runs a 32B (Q4 ≈ 21 GB) instead of being stuck at a 7B in F16 —
/// and abliterated / unsloth releases ship as Q4_K_M / Q8_0 GGUFs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quant {
    /// ~4-bit (`Q4_K_M`) — fits the biggest model; the operator-default for VRAM-bound rigs.
    Q4,
    /// ~8-bit (`Q8_0`) — near-lossless; preferred when it fits.
    Q8,
    /// Full F16 safetensors — what NEOTH's in-process candle path loads today.
    F16,
}

impl Quant {
    /// Bytes per weight parameter for VRAM sizing.
    pub fn bytes_per_param(self) -> f32 {
        match self {
            Quant::Q4 => 0.5,
            Quant::Q8 => 1.0,
            Quant::F16 => 2.0,
        }
    }
    /// GGUF quant tag (the file suffix on HF) — e.g. `Q4_K_M`.
    pub fn gguf_tag(self) -> &'static str {
        match self {
            Quant::Q4 => "Q4_K_M",
            Quant::Q8 => "Q8_0",
            Quant::F16 => "F16",
        }
    }
}

/// Live VRAM need (GB) for a model at a quant: weights × bytes/param × 1.3
/// (KV-cache + activation + framework headroom).
pub fn est_vram_gb_quant(param_b: f32, quant: Quant) -> f32 {
    param_b * quant.bytes_per_param() * 1.3
}

/// One offered local-model choice (GOLD-ADOPT-11): a model SIZE at a QUANT that
/// fits the operator's VRAM. The actual abliterated/unsloth repo + the
/// "newest/best" resolution is a live HuggingFace lookup layered on top; this is
/// the pure fit/ranking core.
#[derive(Debug, Clone, PartialEq)]
pub struct QuantOption {
    pub param_b: f32,
    pub quant: Quant,
    pub est_vram_gb: f32,
    /// Quality heuristic for ordering (higher = better): rewards bigger models
    /// and less-aggressive quant. A 32B-Q4 outranks a 7B-Q8; a 14B-Q8 outranks
    /// a 14B-Q4.
    pub quality: f32,
}

/// The candidate model sizes (billions of params), largest → smallest. The
/// abliterated / unsloth families ship GGUFs at all of these.
const SIZE_LADDER_B: &[f32] = &[72.0, 32.0, 14.0, 7.0, 3.0, 1.5, 0.5];

/// GOLD-ADOPT-11 core: the ranked SHORTLIST of (size, quant) the operator should
/// choose from for their VRAM — Q8 and Q4 both offered, biggest-best first, so
/// they trade quality (Q8) vs size (Q4). Quant is the user-mandated default for
/// local models (never F16 GGUF — too big for no quality gain over Q8). The
/// wizard renders the top few; the abliterated/unsloth repo for each is resolved
/// live from HuggingFace (newest release wins).
pub fn quantized_shortlist(vram_mib: Option<u32>) -> Vec<QuantOption> {
    // No GPU → CPU runs small Q4 models from system RAM; offer a modest set.
    let vram_gb = match vram_mib {
        Some(mib) => mib as f32 / 1024.0,
        None => 8.0, // assume a CPU operator has ≥8 GB RAM to spare
    };
    let mut opts: Vec<QuantOption> = Vec::new();
    for &param_b in SIZE_LADDER_B {
        for quant in [Quant::Q8, Quant::Q4] {
            let need = est_vram_gb_quant(param_b, quant);
            if need <= vram_gb {
                // Quality: bigger model dominates; Q8 edges Q4 at equal size.
                let quality = param_b + if quant == Quant::Q8 { 0.3 } else { 0.0 };
                opts.push(QuantOption { param_b, quant, est_vram_gb: need, quality });
            }
        }
    }
    opts.sort_by(|a, b| b.quality.partial_cmp(&a.quality).unwrap_or(std::cmp::Ordering::Equal));
    opts.truncate(4); // a focused shortlist, not the whole ladder
    opts
}

/// The single recommended quantized pick (the top of [`quantized_shortlist`]) —
/// the biggest model that fits at the best quant.
pub fn recommend_quantized(vram_mib: Option<u32>) -> Option<QuantOption> {
    quantized_shortlist(vram_mib).into_iter().next()
}

/// GOLD-ADOPT-12 — plan `n_local` LOCAL hemispheres into the available VRAM.
/// The operator wants to run 1, 2, or 3 local models across the left / right /
/// cerebellum slots (the rest go cloud). Distinct models do NOT share VRAM, so
/// the budget is split evenly across the local slots and each gets the biggest
/// (size, quant) that fits its share. Returns one [`QuantOption`] per slot, or
/// **empty** when `n_local` models can't all fit (caller steps `n_local` down).
///
/// The slots come back identical (same VRAM share → same best pick); the wizard
/// lets the operator swap an individual slot to a different size or to cloud.
pub fn plan_local_hemispheres(vram_mib: Option<u32>, n_local: u8) -> Vec<QuantOption> {
    if n_local == 0 {
        return Vec::new();
    }
    let total_gb = match vram_mib {
        Some(m) => m as f32 / 1024.0,
        None => 8.0, // a CPU operator's spare RAM
    };
    let per_slot_mib = ((total_gb / n_local as f32) * 1024.0) as u32;
    let mut slots = Vec::with_capacity(n_local as usize);
    for _ in 0..n_local {
        match recommend_quantized(Some(per_slot_mib)) {
            Some(pick) => slots.push(pick),
            None => return Vec::new(), // a slot's share can't hold any model
        }
    }
    slots
}

/// How many local hemispheres the hardware comfortably supports — the most
/// slots (3 → 2 → 1) where EVERY slot still gets a usable (≥3B) model. `0` when
/// not even one ≥3B local fits (operator should go cloud).
pub fn recommended_local_count(vram_mib: Option<u32>) -> u8 {
    for n in [3u8, 2, 1] {
        let plan = plan_local_hemispheres(vram_mib, n);
        if plan.len() == n as usize && plan.iter().all(|o| o.param_b >= 3.0) {
            return n;
        }
    }
    0
}

/// A chosen local model: the HF repo to download, an operator-facing tier
/// label, and the sizing that drove the pick.
#[derive(Debug, Clone, PartialEq)]
pub struct ModelFit {
    /// HuggingFace repo id (safetensors, loadable by the candle path).
    pub repo: &'static str,
    /// Operator-facing tier label (e.g. `qwen2.5-7b`).
    pub label: &'static str,
    /// Model size in billions of parameters.
    pub param_b: f32,
    /// Estimated F16 VRAM need in GB (weights + ~30% KV-cache/activation
    /// headroom) — what gated the pick.
    pub est_vram_gb: f32,
}

impl ModelFit {
    /// Rough HF download size in GB — F16 safetensors are ~2 bytes/param, so
    /// `param_b × 2`. Drives the wizard's "~N GB download" copy.
    pub fn download_gb(&self) -> u32 {
        (self.param_b * 2.0).round() as u32
    }
}

/// The Qwen2.5-Instruct F16 ladder, largest → smallest. Stage 2 widens this to
/// other families + abliterated/unsloth variants.
const QWEN2_5_LADDER: &[(f32, &str, &str)] = &[
    (72.0, "Qwen/Qwen2.5-72B-Instruct", "qwen2.5-72b"),
    (32.0, "Qwen/Qwen2.5-32B-Instruct", "qwen2.5-32b"),
    (14.0, "Qwen/Qwen2.5-14B-Instruct", "qwen2.5-14b"),
    (7.0, "Qwen/Qwen2.5-7B-Instruct", "qwen2.5-7b"),
    (3.0, "Qwen/Qwen2.5-3B-Instruct", "qwen2.5-3b"),
    (1.5, "Qwen/Qwen2.5-1.5B-Instruct", "qwen2.5-1.5b"),
    (0.5, "Qwen/Qwen2.5-0.5B-Instruct", "qwen2.5-0.5b"),
];

/// CPU / unknown-VRAM floor: the model a no-GPU operator gets. Matches NEOTH's
/// historical hardcoded default (3B) so CPU operators see no regression — a 3B
/// F16 is ~6 GB, comfortable in system RAM.
const CPU_FLOOR: (f32, &str, &str) = (3.0, "Qwen/Qwen2.5-3B-Instruct", "qwen2.5-3b");

/// F16 weight + headroom estimate in GB: 2 bytes/param (F16) × 1.3 for the
/// KV-cache + activation + framework overhead. Calibrated against the
/// `ouro`/`local_qwen` candle memory profile (a 7B F16 lands ~18 GB live).
fn est_f16_vram_gb(param_b: f32) -> f32 {
    param_b * 2.0 * 1.3
}

/// Pick the largest Qwen2.5 variant that fits `vram_mib` of VRAM in F16.
/// `None` (no GPU detected / unknown VRAM) returns the CPU floor.
pub fn fit_local_qwen(vram_mib: Option<u32>) -> ModelFit {
    let Some(mib) = vram_mib else {
        let (param_b, repo, label) = CPU_FLOOR;
        return ModelFit { repo, label, param_b, est_vram_gb: est_f16_vram_gb(param_b) };
    };
    // MiB → GB (1 GiB ≈ 1.074 GB; using /1024 keeps a small safety margin).
    let vram_gb = mib as f32 / 1024.0;
    for &(param_b, repo, label) in QWEN2_5_LADDER {
        let need = est_f16_vram_gb(param_b);
        if need <= vram_gb {
            return ModelFit { repo, label, param_b, est_vram_gb: need };
        }
    }
    // VRAM smaller than the smallest GPU model → the CPU floor (runs on CPU+RAM).
    let (param_b, repo, label) = CPU_FLOOR;
    ModelFit { repo, label, param_b, est_vram_gb: est_f16_vram_gb(param_b) }
}

/// Operator-facing RECOMMENDATION tier for a VRAM size — the single source of
/// truth that `GpuReport::recommended_model_tier()` routes through. Unlike
/// [`fit_local_qwen`] (which always returns a runnable local model), this keeps
/// a `"cloud"` floor: VRAM that only fits a sub-3B model recommends cloud,
/// because a 1.5B/0.5B local is too weak to be the operator's primary
/// assistant. No GPU at all → `"cloud"`.
pub fn recommended_tier_label(vram_mib: Option<u32>) -> &'static str {
    match vram_mib {
        None => "cloud",
        Some(mib) => {
            let fit = fit_local_qwen(Some(mib));
            if fit.param_b >= 3.0 { fit.label } else { "cloud" }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fit_is_f16_honest_not_quantized_aspirational() {
        // A 24 GiB GPU (3090/4090) holds a 7B in F16 (~18 GB), NOT a 72B
        // (~187 GB) — the bug in the old recommended_model_tier thresholds.
        assert_eq!(fit_local_qwen(Some(24 * 1024)).repo, "Qwen/Qwen2.5-7B-Instruct");
        // 48 GiB (A6000) fits the 14B (~36 GB); 32B (~83 GB) still doesn't.
        assert_eq!(fit_local_qwen(Some(48 * 1024)).label, "qwen2.5-14b");
        // 80 GiB (A100) F16 still can't hold the 32B (~83 GB) → 14B.
        assert_eq!(fit_local_qwen(Some(80 * 1024)).label, "qwen2.5-14b");
        // 96 GiB+ finally fits the 32B; the 72B (~187 GB) needs more still.
        assert_eq!(fit_local_qwen(Some(96 * 1024)).label, "qwen2.5-32b");
    }

    #[test]
    fn fit_steps_down_with_vram() {
        assert_eq!(fit_local_qwen(Some(16 * 1024)).label, "qwen2.5-3b"); // 7B needs ~18 GB
        assert_eq!(fit_local_qwen(Some(8 * 1024)).label, "qwen2.5-3b"); // 3B needs ~7.8 GB
        assert_eq!(fit_local_qwen(Some(6 * 1024)).label, "qwen2.5-1.5b");
        assert_eq!(fit_local_qwen(Some(4 * 1024)).label, "qwen2.5-1.5b"); // 1.5B needs ~3.9 GB
        assert_eq!(fit_local_qwen(Some(2 * 1024)).label, "qwen2.5-0.5b");
    }

    #[test]
    fn no_gpu_returns_cpu_floor_3b_no_regression() {
        let fit = fit_local_qwen(None);
        assert_eq!(fit.repo, "Qwen/Qwen2.5-3B-Instruct");
        assert_eq!(fit.label, "qwen2.5-3b");
    }

    #[test]
    fn tiny_vram_falls_to_cpu_floor() {
        // 1 GiB can't even hold the 0.5B in F16 (~1.3 GB) → CPU floor.
        assert_eq!(fit_local_qwen(Some(1024)).repo, "Qwen/Qwen2.5-3B-Instruct");
    }

    #[test]
    fn quant_bytes_and_tags_pinned() {
        assert_eq!(Quant::Q4.bytes_per_param(), 0.5);
        assert_eq!(Quant::Q8.bytes_per_param(), 1.0);
        assert_eq!(Quant::F16.bytes_per_param(), 2.0);
        assert_eq!(Quant::Q4.gguf_tag(), "Q4_K_M");
        assert_eq!(Quant::Q8.gguf_tag(), "Q8_0");
    }

    #[test]
    fn quantized_pick_uses_q4_q8_to_fit_far_bigger_models() {
        // The operator mandate: Q8/Q4, biggest/best for the hardware. A 24 GiB
        // GPU runs a 32B at Q4 (~21 GB) — vs the 7B ceiling in F16.
        let top = recommend_quantized(Some(24 * 1024)).unwrap();
        assert_eq!(top.param_b, 32.0);
        assert_eq!(top.quant, Quant::Q4);
        // ...and the shortlist also offers a near-lossless quality pick (14B-Q8)
        // for the same VRAM, so the operator chooses size vs fidelity.
        let list = quantized_shortlist(Some(24 * 1024));
        assert!(list.iter().any(|o| o.param_b == 14.0 && o.quant == Quant::Q8));
        assert!(list.len() <= 4 && !list.is_empty());
    }

    #[test]
    fn quantized_pick_scales_with_vram() {
        // 8 GiB → a 7B at Q4 (~4.6 GB), not stuck at the F16-path 3B.
        let mid = recommend_quantized(Some(8 * 1024)).unwrap();
        assert_eq!(mid.param_b, 7.0);
        assert_eq!(mid.quant, Quant::Q4);
        // 4 GiB → a small model still fits (3B at Q8 ~3.9 GB).
        let small = recommend_quantized(Some(4 * 1024)).unwrap();
        assert!(small.param_b <= 7.0 && small.est_vram_gb <= 4.0);
    }

    #[test]
    fn plan_local_hemispheres_splits_vram_across_slots() {
        // 24 GiB GPU. 1 local slot → the full 32B-Q4. 3 local slots → 8 GiB
        // each → still a usable 7B-Q4 per hemisphere (the operator's "3 lokale
        // Modelle für die 3 Hemisphären").
        let one = plan_local_hemispheres(Some(24 * 1024), 1);
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].param_b, 32.0);
        let three = plan_local_hemispheres(Some(24 * 1024), 3);
        assert_eq!(three.len(), 3);
        assert!(three.iter().all(|o| o.param_b >= 7.0), "{three:?}");
        // Smaller per-slot share → smaller-or-equal model than the single slot.
        assert!(three[0].param_b <= one[0].param_b);
    }

    #[test]
    fn plan_returns_empty_when_n_local_cannot_all_fit() {
        // n_local = 0 is always empty.
        assert!(plan_local_hemispheres(Some(24 * 1024), 0).is_empty());
        // A 512 MiB GPU split 3 ways → ~170 MiB/slot, below even a 0.5B-Q4
        // (~0.33 GB) → no slot fits → empty (caller steps n_local down).
        assert!(plan_local_hemispheres(Some(512), 3).is_empty());
    }

    #[test]
    fn recommended_local_count_scales_with_vram() {
        // Big GPU comfortably runs 3 local ≥3B hemispheres.
        assert_eq!(recommended_local_count(Some(48 * 1024)), 3);
        // 24 GiB also supports 3 (8 GiB/slot → 7B each).
        assert_eq!(recommended_local_count(Some(24 * 1024)), 3);
        // 8 GiB → 3 too: 2.67 GiB/slot still holds a 3B-Q4 (~2 GB) each.
        assert_eq!(recommended_local_count(Some(8 * 1024)), 3);
        // 5 GiB: 3-way → 1.67 GiB → only sub-3B; 2-way → 2.5 GiB → 3B → 2 slots.
        assert_eq!(recommended_local_count(Some(5 * 1024)), 2);
        // 3.5 GiB: only a single 3B-Q4 slot clears the ≥3B bar.
        assert_eq!(recommended_local_count(Some(3584)), 1);
        // Tiny GPU → 0 (go cloud).
        assert_eq!(recommended_local_count(Some(512)), 0);
    }

    #[test]
    fn recommended_tier_keeps_a_cloud_floor() {
        // Big enough for a real local model → the fit label.
        assert_eq!(recommended_tier_label(Some(24 * 1024)), "qwen2.5-7b");
        assert_eq!(recommended_tier_label(Some(8 * 1024)), "qwen2.5-3b");
        // Only fits sub-3B → recommend cloud (the local fit is still 1.5B/0.5B).
        assert_eq!(recommended_tier_label(Some(6 * 1024)), "cloud");
        assert_eq!(fit_local_qwen(Some(6 * 1024)).label, "qwen2.5-1.5b");
        // No GPU → cloud recommendation, but fit still offers the 3B floor.
        assert_eq!(recommended_tier_label(None), "cloud");
        assert_eq!(fit_local_qwen(None).label, "qwen2.5-3b");
    }
}
