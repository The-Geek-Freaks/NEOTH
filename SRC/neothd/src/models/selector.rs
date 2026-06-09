//! GOLD-ADOPT-10/11 — local-model selection (whichllm-port, stage 1).
//!
//! Pick the largest local model that ACTUALLY fits the operator's VRAM in
//! NEOTH's `local_qwen` candle path. That path loads **F16 safetensors** (not
//! quantized GGUF), so the fit math is honest about F16 weight bytes — unlike
//! the old `GpuReport::recommended_model_tier()` thresholds, which assumed
//! quantized inference and would recommend a 72B model (~144 GB F16) for a
//! 24 GiB GPU that can only hold a 7B (~14 GB F16).
//!
//! Stage 2 (GOLD-ADOPT-11) layers a benchmark-quality score table + an
//! abliterated/unsloth repo bias on top of this fit gate, and ranks across
//! multiple model families. Stage 1 here is the correct F16-fit floor that the
//! wizard + `recommended_model_tier()` route through.

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
