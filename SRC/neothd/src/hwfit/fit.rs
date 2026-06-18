//! GOLD-ADAPT-ODY-13 — hardware-fit model scorer.
//!
//! Estimates local-inference decode throughput from the one fact that
//! dominates it: autoregressive decode is **memory-bandwidth bound** — every
//! generated token streams the entire weight set through the memory bus once,
//! so `tok/s ≈ efficiency × bandwidth_GB_s / model_bytes_GB`. Pairs the
//! estimate with a VRAM-fit check (weights + KV/activation headroom) and ranks
//! a candidate set. Complements `models recommend` (which picks *which* model);
//! this answers *how fast* it will run.
//!
//! Pure (no I/O, no probing — the GPU spec + candidate sizes are passed in), so
//! the formula + ranking are unit-tested deterministically. The CLI resolves
//! the GPU from `--gpu`/`--vram`/`--bandwidth` or hardware detection.

/// A GPU's memory characteristics. Bandwidth is the headline number for the
/// decode-throughput estimate; VRAM gates the fit.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct GpuSpec {
    pub name: &'static str,
    pub vram_gb: f64,
    pub bandwidth_gb_s: f64,
}

/// Curated table of common inference GPUs (memory bandwidth from vendor
/// specs, GB/s). Not exhaustive — `--bandwidth` overrides for anything absent.
pub const KNOWN_GPUS: &[GpuSpec] = &[
    GpuSpec {
        name: "H100",
        vram_gb: 80.0,
        bandwidth_gb_s: 3350.0,
    },
    GpuSpec {
        name: "A100",
        vram_gb: 80.0,
        bandwidth_gb_s: 2039.0,
    },
    GpuSpec {
        name: "RTX 4090",
        vram_gb: 24.0,
        bandwidth_gb_s: 1008.0,
    },
    GpuSpec {
        name: "RTX 3090",
        vram_gb: 24.0,
        bandwidth_gb_s: 936.0,
    },
    GpuSpec {
        name: "RTX 4080",
        vram_gb: 16.0,
        bandwidth_gb_s: 717.0,
    },
    GpuSpec {
        name: "RTX 3080",
        vram_gb: 10.0,
        bandwidth_gb_s: 760.0,
    },
    GpuSpec {
        name: "RTX 4070",
        vram_gb: 12.0,
        bandwidth_gb_s: 504.0,
    },
    GpuSpec {
        name: "RTX 3060",
        vram_gb: 12.0,
        bandwidth_gb_s: 360.0,
    },
    GpuSpec {
        name: "RTX 4060",
        vram_gb: 8.0,
        bandwidth_gb_s: 272.0,
    },
];

/// Fraction of the theoretical bandwidth/size ceiling a real decode loop hits
/// (kernel launch + attention + sampling overhead). ~0.5-0.6 is typical for
/// llama.cpp/vLLM single-stream decode; we use a conservative mid-point.
pub const DECODE_EFFICIENCY: f64 = 0.55;

/// KV-cache + activation headroom multiplier applied to the weight bytes when
/// deciding whether a model fits in VRAM.
pub const FIT_HEADROOM: f64 = 1.2;

/// Estimated decode tokens/sec for a memory-bound model of `model_size_gb`
/// in-memory bytes on a bus of `bandwidth_gb_s`. Returns 0 for a non-positive
/// size (avoids a div-by-zero / infinity).
pub fn estimate_tok_s(bandwidth_gb_s: f64, model_size_gb: f64) -> f64 {
    if model_size_gb <= 0.0 || bandwidth_gb_s <= 0.0 {
        return 0.0;
    }
    DECODE_EFFICIENCY * bandwidth_gb_s / model_size_gb
}

/// Look up a known GPU by case-insensitive name overlap (either direction, so
/// `"4090"`, `"rtx 4090"`, and `"NVIDIA GeForce RTX 4090"` all match).
pub fn lookup_gpu(name: &str) -> Option<&'static GpuSpec> {
    let q = name.trim().to_ascii_lowercase();
    if q.is_empty() {
        return None;
    }
    KNOWN_GPUS.iter().find(|g| {
        let n = g.name.to_ascii_lowercase();
        q.contains(&n) || n.contains(&q)
    })
}

/// One candidate model scored against a GPU.
#[derive(Clone, Debug, PartialEq)]
pub struct ModelFit {
    pub label: String,
    /// In-memory weight size, GB.
    pub size_gb: f64,
    /// Weights + headroom fit inside VRAM.
    pub fits: bool,
    /// Estimated decode throughput, tokens/sec.
    pub tok_s: f64,
}

/// Score + rank candidate `(label, size_gb)` models for a GPU: fitting models
/// first, then by estimated tok/s descending. `vram_gb <= 0` treats every
/// model as "fits unknown" → ranks purely by throughput.
pub fn rank_models(
    vram_gb: f64,
    bandwidth_gb_s: f64,
    candidates: &[(String, f64)],
) -> Vec<ModelFit> {
    let mut out: Vec<ModelFit> = candidates
        .iter()
        .map(|(label, size)| ModelFit {
            label: label.clone(),
            size_gb: *size,
            fits: vram_gb > 0.0 && size * FIT_HEADROOM <= vram_gb,
            tok_s: estimate_tok_s(bandwidth_gb_s, *size),
        })
        .collect();
    out.sort_by(|a, b| {
        b.fits.cmp(&a.fits).then(
            b.tok_s
                .partial_cmp(&a.tok_s)
                .unwrap_or(std::cmp::Ordering::Equal),
        )
    });
    out
}

/// A representative ladder of quantized local models (label → in-memory GB at
/// Q4_K_M ≈ 0.5 B/param) for the default `models fit` ranking.
pub fn default_candidates() -> Vec<(String, f64)> {
    vec![
        ("1.5B Q4".to_string(), 1.0),
        ("3B Q4".to_string(), 2.0),
        ("7B Q4".to_string(), 4.5),
        ("8B Q8".to_string(), 8.5),
        ("14B Q4".to_string(), 9.0),
        ("32B Q4".to_string(), 20.0),
        ("70B Q4".to_string(), 40.0),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tok_s_is_bandwidth_over_size_with_efficiency() {
        // 1000 GB/s, 4 GB model → 0.55 * 1000 / 4 = 137.5
        let t = estimate_tok_s(1000.0, 4.0);
        assert!((t - 137.5).abs() < 1e-6);
        // Bigger model → slower.
        assert!(estimate_tok_s(1000.0, 8.0) < t);
    }

    #[test]
    fn tok_s_guards_non_positive_inputs() {
        assert_eq!(estimate_tok_s(1000.0, 0.0), 0.0);
        assert_eq!(estimate_tok_s(0.0, 4.0), 0.0);
        assert_eq!(estimate_tok_s(1000.0, -1.0), 0.0);
    }

    #[test]
    fn lookup_matches_substring_either_direction() {
        assert_eq!(lookup_gpu("4090").map(|g| g.name), Some("RTX 4090"));
        assert_eq!(
            lookup_gpu("NVIDIA GeForce RTX 4090").map(|g| g.name),
            Some("RTX 4090")
        );
        assert_eq!(lookup_gpu("a100").map(|g| g.name), Some("A100"));
        assert!(lookup_gpu("intel arc").is_none());
        assert!(lookup_gpu("").is_none());
    }

    #[test]
    fn rank_puts_fitting_models_first_then_fastest() {
        // 24 GB GPU, 1000 GB/s. 70B (40GB) doesn't fit; 32B (20GB*1.2=24 ok);
        // smaller ones fit + are faster.
        let cands = default_candidates();
        let ranked = rank_models(24.0, 1000.0, &cands);
        // Every fitting model comes before every non-fitting one.
        let first_nonfit = ranked.iter().position(|m| !m.fits);
        if let Some(idx) = first_nonfit {
            assert!(ranked[..idx].iter().all(|m| m.fits));
            assert!(ranked[idx..].iter().all(|m| !m.fits));
        }
        // 70B must NOT fit on 24 GB.
        let f70 = ranked.iter().find(|m| m.label == "70B Q4").unwrap();
        assert!(!f70.fits);
        // Among fitting models, the smallest (fastest) ranks first.
        assert_eq!(ranked[0].label, "1.5B Q4");
        assert!(ranked[0].tok_s > ranked[1].tok_s);
    }

    #[test]
    fn zero_vram_ranks_purely_by_throughput_and_marks_unfit() {
        let ranked = rank_models(0.0, 500.0, &default_candidates());
        assert!(ranked.iter().all(|m| !m.fits), "no VRAM info → fits=false");
        // Still ordered fastest-first.
        assert!(ranked[0].tok_s >= ranked[1].tok_s);
    }
}
