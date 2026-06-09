//! GOLD-ADOPT-11(b) — coarse benchmark-quality scores for ranking model
//! FAMILIES at equal hardware fit.
//!
//! [`crate::models::gguf_variants`] ranks HuggingFace candidates by DOWNLOAD
//! count — a POPULARITY proxy. A heavily-downloaded older family can outrank a
//! newer, genuinely-stronger one at the same parameter count. This table adds a
//! CAPABILITY signal: a coarse `0..=100` quality tier per model family, used as
//! the PRIMARY ranking key so that at equal VRAM fit the stronger family wins,
//! with downloads (then recency) as the within-family tiebreak.
//!
//! ⚠ **The numbers are COARSE ORDERING HINTS, NOT exact published benchmark
//! figures.** They are distilled from public general-capability standings
//! (LiveBench / Open-LLM-Leaderboard, early 2026) and encode only "family A is
//! meaningfully stronger than family B *at the same parameter count*" — nothing
//! finer. An unrecognised family gets a neutral mid score
//! ([`UNKNOWN_FAMILY_SCORE`]) that sits ABOVE the legacy families but below the
//! current strong ones, so a brand-new release is never silently buried beneath
//! a known-weaker family, yet also doesn't auto-win against a proven leader.
//!
//! The score is FAMILY-only (generation strength), deliberately independent of
//! size — size is already the dominant term in [`crate::models::selector`]'s
//! fit math. This table breaks the "which family at this size" question.

/// Quality score for a family NEOTH cannot classify from the repo id. Neutral
/// mid: above the legacy families (Qwen2 / Llama-3) but below the current
/// strong ones (Mistral and up) — a new release ranks fairly without
/// leapfrogging a proven leader on an unverified guess.
pub const UNKNOWN_FAMILY_SCORE: u8 = 72;

/// A recognised local-model family lineage. Used purely to attach a coarse
/// capability score; the concrete repo + quant are resolved elsewhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelFamily {
    /// Qwen3.x (2025 generation — the operator-favoured abliterated base).
    Qwen3,
    /// Qwen2.5 (NEOTH's verified curated family).
    Qwen25,
    /// Qwen2 (legacy).
    Qwen2,
    /// Llama 3.3.
    Llama33,
    /// Llama 3.1.
    Llama31,
    /// Llama 3 / 3.0 (legacy).
    Llama3,
    /// Mistral / Mixtral.
    Mistral,
    /// Gemma 2.
    Gemma2,
    /// Microsoft Phi (3 / 3.5).
    Phi,
    /// DeepSeek (V3 / R1-distill family).
    DeepSeek,
    /// Unclassified — gets [`UNKNOWN_FAMILY_SCORE`].
    Unknown,
}

impl ModelFamily {
    /// Coarse capability tier `0..=100` (higher = stronger at equal size).
    pub fn score(self) -> u8 {
        match self {
            ModelFamily::Qwen3 => 92,
            ModelFamily::Qwen25 => 85,
            ModelFamily::DeepSeek => 84,
            ModelFamily::Llama33 => 82,
            ModelFamily::Gemma2 => 78,
            ModelFamily::Mistral => 74,
            ModelFamily::Llama31 => 73,
            ModelFamily::Phi => 70,
            ModelFamily::Llama3 => 66,
            ModelFamily::Qwen2 => 60,
            ModelFamily::Unknown => UNKNOWN_FAMILY_SCORE,
        }
    }

    /// Short operator-facing label.
    pub fn label(self) -> &'static str {
        match self {
            ModelFamily::Qwen3 => "qwen3",
            ModelFamily::Qwen25 => "qwen2.5",
            ModelFamily::Qwen2 => "qwen2",
            ModelFamily::Llama33 => "llama-3.3",
            ModelFamily::Llama31 => "llama-3.1",
            ModelFamily::Llama3 => "llama-3",
            ModelFamily::Mistral => "mistral",
            ModelFamily::Gemma2 => "gemma-2",
            ModelFamily::Phi => "phi",
            ModelFamily::DeepSeek => "deepseek",
            ModelFamily::Unknown => "unknown",
        }
    }
}

/// Classify a model family from a repo id / model label. Order-sensitive:
/// more-specific generation tokens (`qwen3`, `qwen2.5`, `llama-3.3`) are tested
/// before their broader prefixes so `qwen2.5` never falls through to `qwen2`.
/// Hyphens, dots and underscores are normalised so `Llama-3.1` / `llama3.1` /
/// `Llama_3_1` all classify the same.
pub fn classify(id: &str) -> ModelFamily {
    // Normalise separators to nothing so "llama-3.1", "llama3.1" and
    // "llama_3_1" all collapse to "llama31" for token matching.
    let lo = id.to_ascii_lowercase();
    let compact: String = lo
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();

    // DeepSeek FIRST — its releases are commonly distilled onto a Qwen/Llama
    // base whose name also appears in the id (e.g. "DeepSeek-R1-Distill-Qwen2.5").
    // The "deepseek" token is the authoritative lineage signal, so test it
    // before the base-family checks below.
    if compact.contains("deepseek") {
        return ModelFamily::DeepSeek;
    }
    // Qwen — most specific generation first.
    if compact.contains("qwen3") {
        return ModelFamily::Qwen3;
    }
    if compact.contains("qwen25") {
        return ModelFamily::Qwen25;
    }
    if compact.contains("qwen2") {
        return ModelFamily::Qwen2;
    }
    // Llama — 3.3 / 3.1 before the bare 3.0.
    if compact.contains("llama33") {
        return ModelFamily::Llama33;
    }
    if compact.contains("llama31") {
        return ModelFamily::Llama31;
    }
    if compact.contains("llama3") {
        return ModelFamily::Llama3;
    }
    if compact.contains("gemma2") {
        return ModelFamily::Gemma2;
    }
    // Mistral / Mixtral share the lineage + score.
    if compact.contains("mistral") || compact.contains("mixtral") {
        return ModelFamily::Mistral;
    }
    if compact.contains("phi") {
        return ModelFamily::Phi;
    }
    ModelFamily::Unknown
}

/// The capability score for a repo id / label — classify then look up. This is
/// the value [`crate::models::gguf_variants::rank_variants`] sorts on first.
pub fn family_score_for(id: &str) -> u8 {
    classify(id).score()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_qwen_generations_without_falling_through() {
        // qwen2.5 must NOT classify as the weaker qwen2.
        assert_eq!(
            classify("mradermacher/Qwen2.5-7B-Instruct-abliterated-GGUF"),
            ModelFamily::Qwen25
        );
        assert_eq!(classify("unsloth/Qwen3-8B-GGUF"), ModelFamily::Qwen3);
        assert_eq!(classify("some/Qwen2-7B-Instruct-GGUF"), ModelFamily::Qwen2);
    }

    #[test]
    fn classifies_llama_generations() {
        assert_eq!(classify("bartowski/Llama-3.3-70B-Instruct-GGUF"), ModelFamily::Llama33);
        assert_eq!(classify("x/Meta-Llama-3.1-8B-Instruct-GGUF"), ModelFamily::Llama31);
        assert_eq!(classify("x/Llama-3-8B-Instruct-GGUF"), ModelFamily::Llama3);
        // Separator-insensitive.
        assert_eq!(classify("x/llama3.1-8b"), ModelFamily::Llama31);
        assert_eq!(classify("x/Llama_3_1_8B"), ModelFamily::Llama31);
    }

    #[test]
    fn classifies_other_families_and_unknown() {
        assert_eq!(classify("TheBloke/Mistral-7B-Instruct-GGUF"), ModelFamily::Mistral);
        assert_eq!(classify("x/Mixtral-8x7B"), ModelFamily::Mistral);
        assert_eq!(classify("bartowski/gemma-2-9b-it-GGUF"), ModelFamily::Gemma2);
        assert_eq!(classify("microsoft/Phi-3.5-mini-instruct"), ModelFamily::Phi);
        assert_eq!(classify("x/DeepSeek-R1-Distill-Qwen-7B-GGUF"), ModelFamily::DeepSeek);
        assert_eq!(classify("totally/Unheard-Of-7B"), ModelFamily::Unknown);
    }

    #[test]
    fn deepseek_distill_classifies_as_deepseek_not_its_base() {
        // The "deepseek" token is tested before the qwen/llama base checks, so
        // a distill carrying its base family in the id still classifies as the
        // authoritative DeepSeek lineage.
        assert_eq!(classify("deepseek/DeepSeek-V3-GGUF"), ModelFamily::DeepSeek);
        assert_eq!(
            classify("bartowski/DeepSeek-R1-Distill-Qwen2.5-7B-GGUF"),
            ModelFamily::DeepSeek
        );
    }

    #[test]
    fn stronger_family_outscores_weaker_at_equal_size() {
        assert!(ModelFamily::Qwen3.score() > ModelFamily::Qwen25.score());
        assert!(ModelFamily::Qwen25.score() > ModelFamily::Qwen2.score());
        assert!(ModelFamily::Llama33.score() > ModelFamily::Llama3.score());
        // Unknown sits above the legacy families, below the strong ones.
        assert!(ModelFamily::Unknown.score() > ModelFamily::Qwen2.score());
        assert!(ModelFamily::Unknown.score() > ModelFamily::Llama3.score());
        assert!(ModelFamily::Unknown.score() < ModelFamily::Qwen25.score());
        assert!(ModelFamily::Unknown.score() < ModelFamily::Mistral.score());
    }

    #[test]
    fn family_score_for_classifies_and_scores() {
        assert_eq!(
            family_score_for("unsloth/Qwen3-8B-GGUF"),
            ModelFamily::Qwen3.score()
        );
        assert_eq!(family_score_for("totally/Mystery-7B"), UNKNOWN_FAMILY_SCORE);
    }
}
