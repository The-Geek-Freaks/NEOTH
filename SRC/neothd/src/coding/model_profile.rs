//! Per-model capability profiles — port of smallcode's
//! `src/model/profiles.js`.
//!
//! Per `PLAN/SMALLCODE_AUDIT_2026-05-21.md` port #2. NEOTH today
//! ships the same prompt template regardless of whether the bound
//! provider is a Qwen3 (hermes tool format), a Gemma (native tool
//! format), or a CodeLlama (no tool calling at all). Wrong tool
//! format = silent JSON parse failure inside the coding worker
//! loop. This module is the source of truth for that per-model
//! awareness.
//!
//! ## Surface
//!
//!   - [`ToolFormat`]: enum of the five tool-calling wire forms
//!     small LLMs actually emit (`native` / `hermes` / `json` /
//!     `xml` / `text`).
//!   - [`ModelProfile`]: capability bag — context window, max
//!     output, whether tool calling is supported at all, the
//!     `ToolFormat` the provider expects, plus operator-readable
//!     strength + weakness labels the dispatcher's heuristic
//!     classifier can read (`reasoning` / `code_completion` /
//!     `tool_use` / `long_context` / `complex_reasoning` / ...).
//!   - [`KNOWN_PROFILES`]: const table keyed by canonical model
//!     stem (`qwen3`, `gemma-4`, `deepseek-coder`, ...). The
//!     keys match smallcode's `KNOWN_PROFILES` entries 1:1 so
//!     operator-facing wire forms stay portable.
//!   - [`match_profile`]: fuzzy substring match against
//!     `KNOWN_PROFILES`. Longest key wins so
//!     `huihui-gemma-4-e4b-it-abliterated` resolves to
//!     `gemma-4-e4b`, not `gemma-4`.
//!   - [`get_profile`]: returns a [`ModelProfile`] with sensible
//!     defaults when no key matches. `detected_context_window`
//!     (e.g. from `endpoint::auto_detect_context`) overrides the
//!     table's context_length when non-zero so endpoint-side
//!     reality beats the static catalogue.
//!
//! ## Why no IO + no async
//!
//! Pure-function module — caller passes the model name string in and gets a
//! struct back. `provider_worker::ProviderWorker::execute()` consumes the
//! profile on every coding task to select direct vs two-stage tool routing and
//! to frame a model-appropriate tool-use hint. Tests pin the table contents,
//! longest-key-wins matching, and the worker integration.
//!
//! ## What this module is NOT
//!
//! Not the dispatcher: it does not pick hemispheres, it does
//! not route tasks, it does not score "this model is better for
//! this task". The `strengths` field is data the caller can
//! consult; the policy (which strength wins for which task) lives
//! in `classifier.rs` + `dispatcher.rs`. Keep policy separate
//! from the data table so adding a new model is a one-line entry,
//! not a routing-logic edit.

use std::collections::HashMap;
use std::sync::LazyLock;

/// Tool-calling wire formats the small-LLM ecosystem uses.
///
/// `Native` — OpenAI-style function calling embedded in the
/// response payload (Gemma, llama-3, mistral-nemo).
/// `Hermes` — Hermes-Pro-style XML tags (`<tool_call>` /
/// `<tool_response>`) the Qwen family emits.
/// `Json` — bare JSON object on its own line (DeepSeek-coder).
/// `Xml` — Anthropic-style `<function_calls>` tags (held in
/// reserve — most NEOTH-targeted local models use one of the
/// four above, but keeping this variant means an Anthropic
/// adapter wired through ProviderWorker doesn't need a parallel
/// enum).
/// `Text` — provider does not support tool calling at all
/// (CodeLlama, StarCoder); caller must fall back to free-form
/// completions + post-hoc parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ToolFormat {
    Native,
    Hermes,
    Json,
    Xml,
    Text,
}

impl ToolFormat {
    /// Stable lowercase wire form for logs + WAL. Matches
    /// smallcode's exact string keys so audit consumers can
    /// grep across both projects without translation.
    pub fn as_str(self) -> &'static str {
        match self {
            ToolFormat::Native => "native",
            ToolFormat::Hermes => "hermes",
            ToolFormat::Json => "json",
            ToolFormat::Xml => "xml",
            ToolFormat::Text => "text",
        }
    }
}

/// One model's capability bag. Cheap to clone — strengths +
/// weaknesses are `&'static str` so callers don't pay an alloc.
#[derive(Debug, Clone)]
pub struct ModelProfile {
    pub context_length: u32,
    pub max_output: u32,
    pub supports_tool_calling: bool,
    pub tool_format: ToolFormat,
    pub strengths: &'static [&'static str],
    pub weaknesses: &'static [&'static str],
    /// Which `KNOWN_PROFILES` key produced this profile. `None`
    /// when [`get_profile`] returned the default fallback so the
    /// caller can tell "we know this model" from "we are
    /// guessing".
    pub matched_key: Option<&'static str>,
}

impl ModelProfile {
    /// Default profile for unknown models. Mirrors smallcode's
    /// `getProfile` fallback: 32k context, 4k output, tool
    /// calling assumed-yes (most modern endpoints support it),
    /// native tool format, no strength/weakness annotations.
    pub fn unknown_default() -> Self {
        Self {
            context_length: 32_768,
            max_output: 4_096,
            supports_tool_calling: true,
            tool_format: ToolFormat::Native,
            strengths: &[],
            weaknesses: &[],
            matched_key: None,
        }
    }

    /// True when the model is small enough that the 2-stage
    /// tool router (port #3) should kick in. The 16k threshold
    /// matches smallcode's `two_stage_router.js` heuristic —
    /// below it, the full tool schema set eats too much of the
    /// budget before the task description.
    pub fn needs_two_stage_router(&self) -> bool {
        self.context_length <= 16_384
    }

    /// Operator-readable summary line for `neoth code` debug
    /// output. Short, no allocations beyond the format string.
    pub fn summary_line(&self) -> String {
        format!(
            "{} ctx={} out={} tools={} fmt={}",
            self.matched_key.unwrap_or("unknown"),
            self.context_length,
            self.max_output,
            if self.supports_tool_calling {
                "yes"
            } else {
                "no"
            },
            self.tool_format.as_str()
        )
    }
}

/// One row in the static profile table. Separate from
/// `ModelProfile` because `matched_key` is filled in by the
/// matcher; the const table only carries the data.
struct ProfileEntry {
    key: &'static str,
    context_length: u32,
    max_output: u32,
    supports_tool_calling: bool,
    tool_format: ToolFormat,
    strengths: &'static [&'static str],
    weaknesses: &'static [&'static str],
}

/// Smallcode's `KNOWN_PROFILES` table, 1:1. Keys are the
/// canonical model stems used for fuzzy substring matching;
/// they MUST stay lowercase + hyphen-separated so the matcher
/// can compare lower-case operator-supplied model names
/// without re-normalising.
const KNOWN_PROFILES: &[ProfileEntry] = &[
    // Gemma family — Google's open small models, native tool calling.
    ProfileEntry {
        key: "gemma-4-e4b",
        context_length: 32_768,
        max_output: 8_192,
        supports_tool_calling: true,
        tool_format: ToolFormat::Native,
        strengths: &["speed", "code_completion", "tool_use"],
        weaknesses: &["complex_reasoning", "multi_file"],
    },
    ProfileEntry {
        key: "gemma-4",
        context_length: 32_768,
        max_output: 8_192,
        supports_tool_calling: true,
        tool_format: ToolFormat::Native,
        strengths: &["code_completion", "instruction_following", "tool_use"],
        weaknesses: &["very_long_planning"],
    },
    // Qwen family — Alibaba's coder-leaning small models, hermes tool calling.
    ProfileEntry {
        key: "qwen2.5-coder",
        context_length: 32_768,
        max_output: 8_192,
        supports_tool_calling: true,
        tool_format: ToolFormat::Hermes,
        strengths: &["code_completion", "refactoring"],
        weaknesses: &["long_planning", "multi_file"],
    },
    ProfileEntry {
        key: "qwen3",
        context_length: 32_768,
        max_output: 8_192,
        supports_tool_calling: true,
        tool_format: ToolFormat::Hermes,
        strengths: &["reasoning", "code_generation", "planning"],
        weaknesses: &["verbosity"],
    },
    // DeepSeek — bare-JSON tool calling, smaller context.
    ProfileEntry {
        key: "deepseek-coder",
        context_length: 16_384,
        max_output: 4_096,
        supports_tool_calling: true,
        tool_format: ToolFormat::Json,
        strengths: &["code_completion", "debugging"],
        weaknesses: &["instruction_following", "tool_use_reliability"],
    },
    // CodeLlama — no tool calling at all.
    ProfileEntry {
        key: "codellama",
        context_length: 16_384,
        max_output: 4_096,
        supports_tool_calling: false,
        tool_format: ToolFormat::Text,
        strengths: &["code_completion"],
        weaknesses: &["tool_use", "instruction_following", "planning"],
    },
    // Llama-3 — native tool calling, general-purpose.
    ProfileEntry {
        key: "llama-3",
        context_length: 8_192,
        max_output: 4_096,
        supports_tool_calling: true,
        tool_format: ToolFormat::Native,
        strengths: &["general_reasoning"],
        weaknesses: &["code_specific"],
    },
    // Mistral-Nemo — long-context champion of the small-model class.
    ProfileEntry {
        key: "mistral-nemo",
        context_length: 128_000,
        max_output: 4_096,
        supports_tool_calling: true,
        tool_format: ToolFormat::Native,
        strengths: &["long_context", "instruction_following"],
        weaknesses: &["code_specific"],
    },
    // StarCoder — no tool calling.
    ProfileEntry {
        key: "starcoder",
        context_length: 8_192,
        max_output: 4_096,
        supports_tool_calling: false,
        tool_format: ToolFormat::Text,
        strengths: &["code_completion", "infilling"],
        weaknesses: &["instruction_following", "tool_use", "planning"],
    },
];

/// Sorted index into [`KNOWN_PROFILES`] by descending key
/// length. The matcher walks this so the LONGEST substring
/// match wins — `huihui-gemma-4-e4b-it-abliterated` matches
/// `gemma-4-e4b`, not `gemma-4`.
static LONGEST_KEYS_FIRST: LazyLock<Vec<usize>> = LazyLock::new(|| {
    let mut idx: Vec<usize> = (0..KNOWN_PROFILES.len()).collect();
    idx.sort_by(|&a, &b| {
        KNOWN_PROFILES[b]
            .key
            .len()
            .cmp(&KNOWN_PROFILES[a].key.len())
    });
    idx
});

/// Fast hash lookup for the exact-key path. Built lazily; used
/// only when [`match_profile`] sees a name that IS a key (no
/// substring matching needed).
static EXACT_LOOKUP: LazyLock<HashMap<&'static str, usize>> = LazyLock::new(|| {
    let mut m = HashMap::with_capacity(KNOWN_PROFILES.len());
    for (i, p) in KNOWN_PROFILES.iter().enumerate() {
        m.insert(p.key, i);
    }
    m
});

fn entry_to_profile(e: &ProfileEntry) -> ModelProfile {
    ModelProfile {
        context_length: e.context_length,
        max_output: e.max_output,
        supports_tool_calling: e.supports_tool_calling,
        tool_format: e.tool_format,
        strengths: e.strengths,
        weaknesses: e.weaknesses,
        matched_key: Some(e.key),
    }
}

/// Fuzzy-match a model name against the static profile table.
/// `None` when no key is a substring of the (lowercased) input.
///
/// Match algorithm:
///   1. Lowercase the input once.
///   2. Try the exact-key hash first (fast path).
///   3. Walk keys longest-first; first substring match wins.
///
/// Why longest-first: model names in the wild are heavily
/// suffixed/prefixed (`huihui-gemma-4-e4b-it-abliterated`).
/// Without the length sort, the matcher would pick `gemma-4`
/// for that name and miss the more-specific `gemma-4-e4b`
/// profile (which has different strengths + weaknesses).
pub fn match_profile(model_name: &str) -> Option<ModelProfile> {
    let lower = model_name.to_ascii_lowercase();
    if let Some(&i) = EXACT_LOOKUP.get(lower.as_str()) {
        return Some(entry_to_profile(&KNOWN_PROFILES[i]));
    }
    for &i in LONGEST_KEYS_FIRST.iter() {
        let entry = &KNOWN_PROFILES[i];
        if lower.contains(entry.key) {
            return Some(entry_to_profile(entry));
        }
    }
    None
}

/// Get the effective profile for a model. Falls back to a
/// safe default when no key matches, with the optional
/// `detected_context_window` (e.g. from `endpoint::auto_detect`)
/// overriding the static table's `context_length` when
/// non-zero. The endpoint-detected value is the ground truth;
/// the table is only a hint when detection didn't run.
pub fn get_profile(model_name: &str, detected_context_window: u32) -> ModelProfile {
    let mut p = match_profile(model_name).unwrap_or_else(ModelProfile::unknown_default);
    if detected_context_window > 0 {
        p.context_length = detected_context_window;
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_profiles_table_is_non_empty_and_each_key_unique() {
        assert!(KNOWN_PROFILES.iter().any(|entry| entry.key == "gemma-4"));
        let mut seen: HashMap<&'static str, usize> = HashMap::new();
        for (i, e) in KNOWN_PROFILES.iter().enumerate() {
            assert!(
                seen.insert(e.key, i).is_none(),
                "duplicate key in KNOWN_PROFILES: {}",
                e.key
            );
        }
    }

    #[test]
    fn known_profiles_keys_are_lowercase_and_hyphen_safe() {
        // Pin the matcher's input-normalisation contract: keys
        // must be lowercase so `to_ascii_lowercase` on operator
        // input + `lower.contains(key)` is correct. Hyphens
        // allowed; underscores are not (matcher would fail
        // against `gemma_4` vs `gemma-4`).
        for e in KNOWN_PROFILES.iter() {
            assert_eq!(
                e.key,
                e.key.to_ascii_lowercase(),
                "key not lowercase: {}",
                e.key
            );
            assert!(
                !e.key.contains('_'),
                "key must not contain '_' (matcher uses hyphens): {}",
                e.key
            );
        }
    }

    #[test]
    fn match_profile_exact_key_hits() {
        let p = match_profile("qwen3").expect("qwen3 must match");
        assert_eq!(p.matched_key, Some("qwen3"));
        assert_eq!(p.tool_format, ToolFormat::Hermes);
    }

    #[test]
    fn match_profile_is_case_insensitive() {
        let p = match_profile("QWEN3").expect("uppercase must match");
        assert_eq!(p.matched_key, Some("qwen3"));
    }

    #[test]
    fn match_profile_longest_key_wins_for_suffixed_name() {
        // huihui-gemma-4-e4b-it-abliterated must resolve to
        // `gemma-4-e4b`, not the shorter `gemma-4`.
        let p =
            match_profile("huihui-gemma-4-e4b-it-abliterated").expect("must match a gemma profile");
        assert_eq!(p.matched_key, Some("gemma-4-e4b"));
        assert_eq!(p.strengths, &["speed", "code_completion", "tool_use"]);
    }

    #[test]
    fn match_profile_substring_match_for_qwen_coder_variant() {
        // `qwen2.5-coder-7b-instruct` -> qwen2.5-coder (longer
        // than `qwen3`); validates that the longest-first sort
        // catches the more-specific qwen entry.
        let p = match_profile("qwen2.5-coder-7b-instruct").expect("must match");
        assert_eq!(p.matched_key, Some("qwen2.5-coder"));
    }

    #[test]
    fn match_profile_returns_none_for_truly_unknown_name() {
        assert!(match_profile("totally-unknown-fictional-model-9000").is_none());
    }

    #[test]
    fn get_profile_falls_back_to_unknown_default_when_no_match() {
        let p = get_profile("totally-unknown-fictional-model-9000", 0);
        assert_eq!(p.matched_key, None);
        assert_eq!(p.context_length, 32_768);
        assert!(p.supports_tool_calling);
        assert_eq!(p.tool_format, ToolFormat::Native);
    }

    #[test]
    fn get_profile_detected_window_overrides_table_value() {
        // Mistral-Nemo's table value is 128k; operator's
        // endpoint detected 24k. Detected wins.
        let p = get_profile("mistral-nemo-instruct-2407", 24_000);
        assert_eq!(p.matched_key, Some("mistral-nemo"));
        assert_eq!(p.context_length, 24_000);
    }

    #[test]
    fn get_profile_detected_zero_keeps_table_value() {
        // Common case: detection didn't run -> use the table.
        let p = get_profile("mistral-nemo", 0);
        assert_eq!(p.context_length, 128_000);
    }

    #[test]
    fn needs_two_stage_router_threshold_is_16k() {
        let p_deepseek = match_profile("deepseek-coder-v2").expect("must match");
        assert!(p_deepseek.needs_two_stage_router(), "16k must trigger");

        let p_qwen3 = match_profile("qwen3").expect("must match");
        assert!(!p_qwen3.needs_two_stage_router(), "32k must NOT trigger");
    }

    #[test]
    fn tool_format_str_is_stable_wire_form() {
        // Smallcode operator audit + NEOTH operator audit need
        // identical strings so cross-project grep works.
        assert_eq!(ToolFormat::Native.as_str(), "native");
        assert_eq!(ToolFormat::Hermes.as_str(), "hermes");
        assert_eq!(ToolFormat::Json.as_str(), "json");
        assert_eq!(ToolFormat::Xml.as_str(), "xml");
        assert_eq!(ToolFormat::Text.as_str(), "text");
    }

    #[test]
    fn codellama_signals_no_tool_calling() {
        // Caller of `match_profile` must be able to bail out of
        // tool-calling paths cleanly for models that don't
        // support them.
        let p = match_profile("codellama-13b-instruct").expect("must match");
        assert!(!p.supports_tool_calling);
        assert_eq!(p.tool_format, ToolFormat::Text);
    }

    #[test]
    fn summary_line_includes_key_and_capabilities() {
        let p = match_profile("qwen3").expect("must match");
        let s = p.summary_line();
        assert!(s.contains("qwen3"));
        assert!(s.contains("ctx=32768"));
        assert!(s.contains("fmt=hermes"));
        assert!(s.contains("tools=yes"));
    }

    #[test]
    fn summary_line_for_unknown_default_says_unknown() {
        let p = ModelProfile::unknown_default();
        let s = p.summary_line();
        assert!(s.contains("unknown"));
    }
}
