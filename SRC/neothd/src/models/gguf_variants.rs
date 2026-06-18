//! GOLD-ADOPT-11 stage 2 — resolve a `(size, quant)` pick from
//! [`crate::models::selector`] to a CONCRETE GGUF repo on HuggingFace, honoring
//! the operator mandate (2026-06-09): *local models run quantized (Q4/Q8),
//! preferring abliterated / unsloth GGUFs, always offering the newest/best.*
//!
//! Two layers:
//!   1. **Live HF lookup** ([`resolve_live`]) — queries the HuggingFace model API
//!      filtered to GGUF repos, then ranks by FAMILY capability score
//!      ([`crate::models::benchmark_scores`], GOLD-ADOPT-11(b)) first, downloads
//!      (proven/"best") second, recency ("newest") last — so a fresh,
//!      stronger-family abliterated release wins automatically without code
//!      changes, and popularity never buries a better model. This is the
//!      primary path.
//!   2. **Verified curated fallback** ([`curated_fallback`]) — used offline / on
//!      API failure. Every repo here was checked live (HF API `200`) on
//!      2026-06-09: abliterated GGUFs ship from `mradermacher/*-abliterated-GGUF`
//!      (the abliterated→GGUF converter), standard from `bartowski/*-GGUF`.
//!
//! The resolved [`GgufVariant`] turns into a runnable Ollama model via
//! [`GgufVariant::pull_ref`] → [`crate::installers::ollama::hf_gguf_ref`] →
//! `ollama pull hf.co/<repo>:<Q4_K_M|Q8_0>` (GOLD-ADOPT-13).

use std::time::Duration;

use serde::Deserialize;

use crate::models::selector::Quant;

/// HuggingFace model-list API base.
const HF_API: &str = "https://huggingface.co/api/models";

/// Which release lineage a GGUF repo belongs to. The operator prefers
/// `Abliterated` (refusal-ablated / uncensored) for an unconstrained local
/// assistant; `Standard` is the neutral fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VariantClass {
    /// Refusal-ablated ("abliterated") / uncensored fine-tune.
    Abliterated,
    /// Unsloth dynamic-quant release.
    Unsloth,
    /// Vanilla instruct GGUF (e.g. bartowski conversions).
    Standard,
}

impl VariantClass {
    pub fn label(self) -> &'static str {
        match self {
            Self::Abliterated => "abliterated",
            Self::Unsloth => "unsloth",
            Self::Standard => "standard",
        }
    }

    /// The keyword folded into the HF search query to bias results toward this
    /// lineage. `Standard` searches the plain instruct name.
    fn search_keyword(self) -> &'static str {
        match self {
            Self::Abliterated => "abliterated",
            Self::Unsloth => "unsloth",
            Self::Standard => "Instruct",
        }
    }

    /// Classify a repo id by its owner/name tokens.
    pub fn from_repo_id(id: &str) -> Self {
        let lo = id.to_ascii_lowercase();
        if lo.contains("abliterat") || lo.contains("uncensored") {
            Self::Abliterated
        } else if lo.contains("unsloth") {
            Self::Unsloth
        } else {
            Self::Standard
        }
    }
}

/// A concrete, resolved GGUF repo for a chosen model size + lineage.
#[derive(Debug, Clone, PartialEq)]
pub struct GgufVariant {
    /// HuggingFace repo id, e.g. `mradermacher/Qwen2.5-7B-Instruct-abliterated-GGUF`.
    pub repo: String,
    /// The lineage this repo was matched as.
    pub class: VariantClass,
    /// Download count (popularity / "best" proxy); `0` for curated fallback.
    pub downloads: u64,
    /// ISO-8601 creation timestamp ("newest" tiebreak); empty for curated.
    pub created_at: String,
}

impl GgufVariant {
    /// The `ollama pull` ref for this repo at `quant` — the bridge to
    /// GOLD-ADOPT-13: `hf.co/<repo>:<Q4_K_M|Q8_0>`.
    pub fn pull_ref(&self, quant: Quant) -> String {
        crate::installers::ollama::hf_gguf_ref(&self.repo, quant.gguf_tag())
    }
}

/// Format a size in billions for repo-id tokens: `7.0 → "7"`, `1.5 → "1.5"`.
fn fmt_size(size_b: f32) -> String {
    if size_b.fract().abs() < 0.01 {
        format!("{}", size_b as u32)
    } else {
        format!("{size_b}")
    }
}

/// Percent-encode a search query (HF API `?search=`). Only `[A-Za-z0-9._-]` pass
/// through unescaped; everything else (spaces, etc.) is `%XX`.
fn encode_query(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Build the HF model-search URL for a size + lineage, GGUF-filtered, ordered by
/// downloads (so the most-adopted release leads).
pub fn hf_search_url(size_b: f32, class: VariantClass) -> String {
    let q = encode_query(&format!(
        "Qwen2.5-{}B-Instruct {} GGUF",
        fmt_size(size_b),
        class.search_keyword()
    ));
    format!("{HF_API}?search={q}&filter=gguf&sort=downloads&direction=-1&limit=20")
}

/// One row of the HF model-list API response (only the fields we rank on).
#[derive(Debug, Clone, Deserialize)]
pub struct HfModelHit {
    pub id: String,
    #[serde(default)]
    pub downloads: u64,
    #[serde(default, rename = "createdAt")]
    pub created_at: String,
}

/// Parse the HF API JSON array; malformed → empty (fall back to curated).
pub fn parse_hf_models(json: &str) -> Vec<HfModelHit> {
    serde_json::from_str(json).unwrap_or_default()
}

/// True if `id_lower` has the exact hyphen/dot-delimited size token (so `"7b"`
/// matches `qwen2.5-7b-instruct` but NOT `17b` or the `2.5` in `qwen2.5`).
fn contains_size_token(id_lower: &str, token: &str) -> bool {
    id_lower
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '.')
        .any(|seg| seg == token)
}

/// Filter HF hits to GGUF repos of the wanted size + lineage, then rank.
///
/// GOLD-ADOPT-11(b): the PRIMARY key is the family CAPABILITY score
/// ([`crate::models::benchmark_scores`]) — at the SAME size + lineage a
/// genuinely-stronger family (e.g. Qwen3) outranks a more-downloaded weaker one
/// (e.g. a legacy Qwen2), so popularity no longer buries quality. Downloads
/// (proven adoption) is the within-family tiebreak, newest `createdAt` last.
pub fn rank_variants(hits: Vec<HfModelHit>, size_b: f32, class: VariantClass) -> Vec<GgufVariant> {
    use crate::models::benchmark_scores::family_score_for;
    let token = format!("{}b", fmt_size(size_b)).to_ascii_lowercase();
    let mut out: Vec<GgufVariant> = hits
        .into_iter()
        .filter(|h| {
            let lo = h.id.to_ascii_lowercase();
            lo.contains("gguf")
                && contains_size_token(&lo, &token)
                && VariantClass::from_repo_id(&h.id) == class
        })
        .map(|h| GgufVariant {
            repo: h.id,
            class,
            downloads: h.downloads,
            created_at: h.created_at,
        })
        .collect();
    out.sort_by(|a, b| {
        family_score_for(&b.repo)
            .cmp(&family_score_for(&a.repo))
            .then_with(|| b.downloads.cmp(&a.downloads))
            .then_with(|| b.created_at.cmp(&a.created_at))
    });
    out
}

/// Verified curated repos (HF API `200` on 2026-06-09): `(size_b,
/// abliterated_gguf, standard_gguf)`. The 0.5B has no abliterated GGUF (and
/// ablating a 0.5B is pointless), so it carries `None`.
const CURATED: &[(f32, Option<&str>, &str)] = &[
    (
        32.0,
        Some("mradermacher/Qwen2.5-32B-Instruct-abliterated-GGUF"),
        "bartowski/Qwen2.5-32B-Instruct-GGUF",
    ),
    (
        14.0,
        Some("mradermacher/Qwen2.5-14B-Instruct-abliterated-GGUF"),
        "bartowski/Qwen2.5-14B-Instruct-GGUF",
    ),
    (
        7.0,
        Some("mradermacher/Qwen2.5-7B-Instruct-abliterated-GGUF"),
        "bartowski/Qwen2.5-7B-Instruct-GGUF",
    ),
    (
        3.0,
        Some("mradermacher/Qwen2.5-3B-Instruct-abliterated-GGUF"),
        "bartowski/Qwen2.5-3B-Instruct-GGUF",
    ),
    (
        1.5,
        Some("mradermacher/Qwen2.5-1.5B-Instruct-abliterated-GGUF"),
        "bartowski/Qwen2.5-1.5B-Instruct-GGUF",
    ),
    (0.5, None, "bartowski/Qwen2.5-0.5B-Instruct-GGUF"),
];

/// Offline / API-failure fallback: the verified repo for an EXACT curated size
/// + lineage (`±0.01`). Returns `None` for a size with no curated row — callers
/// that must always resolve use [`curated_or_nearest`].
pub fn curated_fallback(size_b: f32, class: VariantClass) -> Option<GgufVariant> {
    CURATED
        .iter()
        .find(|(s, _, _)| (*s - size_b).abs() < 0.01)
        .map(|(_, abl, std)| curated_variant(*abl, std, class))
}

/// Map a CURATED row (`abl`/`std` repos) + requested lineage to a concrete
/// [`GgufVariant`]. `Abliterated` with no abliterated GGUF (0.5B) degrades to
/// the standard repo. GR-135 — `Unsloth` is a CLASSIFICATION-only lineage
/// (detected from a live HF repo id by [`VariantClass::from_repo_id`]); no
/// recommendation path REQUESTS it and there are no curated unsloth GGUFs for
/// Qwen2.5, so it deliberately folds into the standard repo here — an explicit
/// design choice, not an accidental silent drop.
fn curated_variant(abl: Option<&str>, std: &str, class: VariantClass) -> GgufVariant {
    let (repo, cls) = match class {
        VariantClass::Abliterated => match abl {
            Some(r) => (r, VariantClass::Abliterated),
            None => (std, VariantClass::Standard),
        },
        VariantClass::Unsloth | VariantClass::Standard => (std, VariantClass::Standard),
    };
    GgufVariant {
        repo: repo.to_string(),
        class: cls,
        downloads: 0,
        created_at: String::new(),
    }
}

/// GR-040 — the curated entry whose size is NEAREST to `size_b` (no exact-match
/// requirement). An exotic request such as 72B has no curated row, so it must
/// degrade to the closest real model (32B), NOT silently collapse to the
/// hardcoded 7B backstop the call sites previously used. CURATED is non-empty
/// → always `Some`.
fn nearest_curated(size_b: f32, class: VariantClass) -> Option<GgufVariant> {
    CURATED
        .iter()
        .min_by(|(a, _, _), (b, _, _)| (*a - size_b).abs().total_cmp(&(*b - size_b).abs()))
        .map(|(_, abl, std)| curated_variant(*abl, std, class))
}

/// The exact curated repo for `size_b`, else the NEAREST curated size (GR-040).
/// Always resolves (CURATED is non-empty) — the canonical offline fallback for
/// every call site, replacing the old `curated_fallback(size).or_else(7B)` chain
/// that downgraded a 72B request to 7B instead of the nearest 32B.
pub fn curated_or_nearest(size_b: f32, class: VariantClass) -> GgufVariant {
    curated_fallback(size_b, class)
        .or_else(|| nearest_curated(size_b, class))
        .expect("CURATED is non-empty so nearest always resolves")
}

/// Best-effort live HF resolution for a size + lineage. `None` on any network /
/// parse failure so the caller falls back to [`curated_fallback`].
async fn resolve_live(size_b: f32, class: VariantClass) -> Option<GgufVariant> {
    let url = hf_search_url(size_b, class);
    // GR-023/034 — route through the audited client builder so the operator's
    // NEOTH_HTTP_PROXY (+ egress allowlist) applies; a direct reqwest::Client
    // bypassed the configured egress proxy entirely. Keep the resolver's tight 8s
    // budget as a per-request timeout (overrides build_client's 120s default).
    let client = crate::providers::http_client::build_client().ok()?;
    let resp = client
        .get(&url)
        .timeout(Duration::from_secs(8))
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body = resp.text().await.ok()?;
    rank_variants(parse_hf_models(&body), size_b, class)
        .into_iter()
        .next()
}

/// Resolve a chosen model size + lineage to a concrete GGUF repo — live HF
/// lookup ("newest best") first, verified curated repo as fallback. The nearest
/// curated size backstops an exotic request so this never returns nothing.
pub async fn resolve_gguf_repo(size_b: f32, class: VariantClass) -> GgufVariant {
    if let Some(v) = resolve_live(size_b, class).await {
        return v;
    }
    // GR-040 — exact curated row, else the NEAREST curated size (so 72B → 32B,
    // not the old silent collapse to 7B).
    curated_or_nearest(size_b, class)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_from_repo_id_classifies() {
        assert_eq!(
            VariantClass::from_repo_id("mradermacher/Qwen2.5-7B-Instruct-abliterated-GGUF"),
            VariantClass::Abliterated
        );
        assert_eq!(
            VariantClass::from_repo_id("huihui-ai/Llama-3-8B-uncensored"),
            VariantClass::Abliterated
        );
        assert_eq!(
            VariantClass::from_repo_id("unsloth/Qwen3-8B-GGUF"),
            VariantClass::Unsloth
        );
        assert_eq!(
            VariantClass::from_repo_id("bartowski/Qwen2.5-7B-Instruct-GGUF"),
            VariantClass::Standard
        );
    }

    #[test]
    fn search_url_has_size_keyword_and_gguf_filter() {
        let url = hf_search_url(7.0, VariantClass::Abliterated);
        assert!(url.contains("Qwen2.5-7B-Instruct"), "{url}");
        assert!(url.contains("abliterated"), "{url}");
        assert!(url.contains("filter=gguf"), "{url}");
        assert!(url.contains("sort=downloads"), "{url}");
        // Spaces are percent-encoded, not raw.
        assert!(!url.contains(' '), "{url}");
        // 1.5B keeps the fractional token.
        assert!(hf_search_url(1.5, VariantClass::Standard).contains("Qwen2.5-1.5B-Instruct"));
    }

    #[test]
    fn size_token_is_boundary_exact() {
        assert!(contains_size_token("qwen2.5-7b-instruct-gguf", "7b"));
        assert!(contains_size_token("qwen2.5-1.5b-instruct-gguf", "1.5b"));
        // Must NOT match 7b inside 17b, nor the "2.5" of the family name.
        assert!(!contains_size_token("qwen2.5-17b-instruct-gguf", "7b"));
        assert!(!contains_size_token("qwen2.5-72b-instruct-gguf", "2b"));
    }

    #[test]
    fn rank_filters_by_size_class_and_orders_by_downloads() {
        let json = r#"[
            {"id":"mradermacher/Qwen2.5-7B-Instruct-abliterated-GGUF","downloads":5000,"createdAt":"2025-01-10T00:00:00.000Z"},
            {"id":"someone/Qwen2.5-7B-Instruct-abliterated-GGUF","downloads":9000,"createdAt":"2024-12-01T00:00:00.000Z"},
            {"id":"bartowski/Qwen2.5-7B-Instruct-GGUF","downloads":99999,"createdAt":"2025-02-01T00:00:00.000Z"},
            {"id":"mradermacher/Qwen2.5-14B-Instruct-abliterated-GGUF","downloads":7000,"createdAt":"2025-03-01T00:00:00.000Z"}
        ]"#;
        let ranked = rank_variants(parse_hf_models(json), 7.0, VariantClass::Abliterated);
        // 14B (wrong size) and bartowski standard (wrong class) excluded.
        assert_eq!(ranked.len(), 2);
        // Most-downloaded abliterated 7B wins.
        assert_eq!(
            ranked[0].repo,
            "someone/Qwen2.5-7B-Instruct-abliterated-GGUF"
        );
        assert_eq!(ranked[0].downloads, 9000);
        assert!(ranked.iter().all(|v| v.class == VariantClass::Abliterated));
    }

    #[test]
    fn rank_prefers_stronger_family_over_more_downloads() {
        // GOLD-ADOPT-11(b): a 7B abliterated search can return mixed bases. A
        // newer-generation Qwen3 with FEWER downloads must outrank a legacy
        // Qwen2 with MORE downloads — popularity no longer buries capability.
        let json = r#"[
            {"id":"legacy/Qwen2-7B-Instruct-abliterated-GGUF","downloads":50000,"createdAt":"2024-06-01T00:00:00.000Z"},
            {"id":"fresh/Qwen3-7B-abliterated-GGUF","downloads":1200,"createdAt":"2025-09-01T00:00:00.000Z"}
        ]"#;
        let ranked = rank_variants(parse_hf_models(json), 7.0, VariantClass::Abliterated);
        assert_eq!(ranked.len(), 2);
        assert_eq!(ranked[0].repo, "fresh/Qwen3-7B-abliterated-GGUF");
        // Within ONE family, downloads still decide (no regression).
    }

    #[test]
    fn rank_newest_breaks_download_ties() {
        let json = r#"[
            {"id":"a/Qwen2.5-7B-Instruct-abliterated-GGUF","downloads":100,"createdAt":"2025-01-01T00:00:00.000Z"},
            {"id":"b/Qwen2.5-7B-Instruct-abliterated-GGUF","downloads":100,"createdAt":"2025-06-01T00:00:00.000Z"}
        ]"#;
        let ranked = rank_variants(parse_hf_models(json), 7.0, VariantClass::Abliterated);
        assert_eq!(ranked[0].repo, "b/Qwen2.5-7B-Instruct-abliterated-GGUF");
    }

    #[test]
    fn curated_fallback_returns_verified_repos() {
        let abl = curated_fallback(7.0, VariantClass::Abliterated).unwrap();
        assert_eq!(
            abl.repo,
            "mradermacher/Qwen2.5-7B-Instruct-abliterated-GGUF"
        );
        assert_eq!(abl.class, VariantClass::Abliterated);
        let std = curated_fallback(32.0, VariantClass::Standard).unwrap();
        assert_eq!(std.repo, "bartowski/Qwen2.5-32B-Instruct-GGUF");
        // 0.5B has no abliterated GGUF → degrades to standard.
        let tiny = curated_fallback(0.5, VariantClass::Abliterated).unwrap();
        assert_eq!(tiny.repo, "bartowski/Qwen2.5-0.5B-Instruct-GGUF");
        assert_eq!(tiny.class, VariantClass::Standard);
        // Unmodeled size → None.
        assert!(curated_fallback(99.0, VariantClass::Standard).is_none());
    }

    #[test]
    fn curated_or_nearest_exotic_size_degrades_to_nearest_not_7b() {
        // GR-040 — a 72B request has no curated row; the nearest is 32B, NOT
        // the old hardcoded-7B backstop.
        let v = curated_or_nearest(72.0, VariantClass::Standard);
        assert_eq!(v.repo, "bartowski/Qwen2.5-32B-Instruct-GGUF");
        // 80B → still 32B (the largest curated). Proves it tracks the nearest,
        // not a fixed cap.
        assert_eq!(
            curated_or_nearest(80.0, VariantClass::Standard).repo,
            "bartowski/Qwen2.5-32B-Instruct-GGUF"
        );
        // An exact curated size still resolves to itself.
        assert_eq!(
            curated_or_nearest(14.0, VariantClass::Standard).repo,
            "bartowski/Qwen2.5-14B-Instruct-GGUF"
        );
        // Between 7 and 14, 10 is closer to 7 (3 vs 4).
        assert_eq!(
            curated_or_nearest(10.0, VariantClass::Standard).repo,
            "bartowski/Qwen2.5-7B-Instruct-GGUF"
        );
        // Nearest also honours the abliterated lineage.
        assert_eq!(
            curated_or_nearest(72.0, VariantClass::Abliterated).repo,
            "mradermacher/Qwen2.5-32B-Instruct-abliterated-GGUF"
        );
    }

    #[test]
    fn pull_ref_bridges_to_ollama_quant_tag() {
        let v = curated_fallback(7.0, VariantClass::Abliterated).unwrap();
        assert_eq!(
            v.pull_ref(Quant::Q4),
            "hf.co/mradermacher/Qwen2.5-7B-Instruct-abliterated-GGUF:Q4_K_M"
        );
        assert_eq!(
            v.pull_ref(Quant::Q8),
            "hf.co/mradermacher/Qwen2.5-7B-Instruct-abliterated-GGUF:Q8_0"
        );
    }

    #[test]
    fn fmt_size_drops_trailing_zero_keeps_fraction() {
        assert_eq!(fmt_size(7.0), "7");
        assert_eq!(fmt_size(32.0), "32");
        assert_eq!(fmt_size(1.5), "1.5");
        assert_eq!(fmt_size(0.5), "0.5");
    }
}
