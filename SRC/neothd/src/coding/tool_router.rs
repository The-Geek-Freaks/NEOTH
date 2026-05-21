//! 2-stage tool router — port of smallcode's
//! `src/tools/two_stage_router.js`.
//!
//! Per `PLAN/SMALLCODE_AUDIT_2026-05-21.md` port #5. Small
//! local LLMs (Qwen 7B-20B, Gemma 4B-12B, deepseek-coder) ship
//! with 8k-16k effective context. NEOTH's coding session sends
//! the entire tool schema set per turn; when the schemas alone
//! eat 30-40% of the budget, the task description gets squeezed
//! out and the model produces under-specified patches.
//!
//! Smallcode solves this with a two-stage handshake:
//!
//!   Stage 1: model picks ONE category from a ~200-token
//!            menu (`read` / `write` / `search` / `run` /
//!            `plan` / `code_intel`).
//!   Stage 2: system injects only that category's full
//!            schemas — typically 3-5 tools instead of
//!            20+ — and the model makes the real tool call.
//!
//! ## NEOTH wiring status
//!
//! NEOTH today does not have a unified "tool registry" — the
//! tool-call surface lives in hooks, skills, slash commands,
//! and the upcoming MCP server bridge. This module ships the
//! pure-decision half of the router so the data + routing
//! gate is ready when the tool registry lands:
//!
//!   - [`RoutingMode`] enum + [`routing_mode`] decision fn
//!     keyed off [`model_profile::ModelProfile::context_length`]
//!     + an optional env override (`NEOTH_TOOL_ROUTING`)
//!   - [`ToolCategory`] enum with stable lowercase wire forms
//!     identical to smallcode's keys, so a future operator
//!     reading both projects' logs sees the same labels
//!   - [`category_description`] human-readable hint shown in
//!     the Stage 1 selector prompt
//!   - [`category_member_hint`] indicative tool-name list
//!     (smallcode-aligned strings the model can match against
//!     even before NEOTH's tool registry exists)
//!
//! What this module is NOT:
//!
//!   - Not a tool registry. It does not know which tools NEOTH
//!     supports today; the `category_member_hint` strings are
//!     hints, not authoritative.
//!   - Not a dispatcher. The actual Stage-1 -> Stage-2 prompt
//!     handshake belongs in `ProviderWorker::execute()` once
//!     ProviderWorker switches from free-form to tool-call.
//!   - No IO. Pure functions + const data.

use crate::coding::model_profile::ModelProfile;

/// Smallcode's six tool categories, 1:1. Stable lowercase
/// wire form so audit consumers see identical strings across
/// projects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ToolCategory {
    Read,
    Write,
    Search,
    Run,
    Plan,
    CodeIntel,
}

impl ToolCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            ToolCategory::Read => "read",
            ToolCategory::Write => "write",
            ToolCategory::Search => "search",
            ToolCategory::Run => "run",
            ToolCategory::Plan => "plan",
            ToolCategory::CodeIntel => "code_intel",
        }
    }

    /// Parse a category from its lowercase wire form. `None`
    /// when the input is not a known category — the caller
    /// usually falls back to "inject all schemas" in that
    /// case, which is the safe default.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "read" => Some(ToolCategory::Read),
            "write" => Some(ToolCategory::Write),
            "search" => Some(ToolCategory::Search),
            "run" => Some(ToolCategory::Run),
            "plan" => Some(ToolCategory::Plan),
            "code_intel" | "codeintel" => Some(ToolCategory::CodeIntel),
            _ => None,
        }
    }

    /// Every category in iteration order. Stable — drives the
    /// Stage-1 prompt template; if this order changes, the
    /// selector menu changes, and the model's response token
    /// distribution shifts. Pin via test.
    pub const ALL: &'static [ToolCategory] = &[
        ToolCategory::Read,
        ToolCategory::Write,
        ToolCategory::Search,
        ToolCategory::Run,
        ToolCategory::Plan,
        ToolCategory::CodeIntel,
    ];
}

/// Which router mode the dispatcher should use for one
/// ProviderWorker turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingMode {
    /// Inject every available tool schema in one shot. Default
    /// for models with >16k context.
    Direct,
    /// Inject the Stage-1 category selector first, then on
    /// reply inject only that category's schemas. Default for
    /// ≤16k context.
    TwoStage,
}

impl RoutingMode {
    pub fn as_str(self) -> &'static str {
        match self {
            RoutingMode::Direct => "direct",
            RoutingMode::TwoStage => "two_stage",
        }
    }
}

/// 16k threshold below which two-stage routing is the default.
/// Mirrors smallcode's `two_stage_router.js` heuristic; also
/// reachable via [`ModelProfile::needs_two_stage_router`] so
/// callers can ask the profile directly without naming the
/// constant.
pub const TWO_STAGE_THRESHOLD: u32 = 16_384;

/// Pick the routing mode for one turn. `env_override` honours
/// the same `NEOTH_TOOL_ROUTING=direct|two_stage` operator
/// switch smallcode exposes via `SMALLCODE_TOOL_ROUTING`. Any
/// other value (or `None`) falls back to the auto-decision
/// based on `context_length`.
pub fn routing_mode(context_length: u32, env_override: Option<&str>) -> RoutingMode {
    match env_override {
        Some("direct") => RoutingMode::Direct,
        Some("two_stage") => RoutingMode::TwoStage,
        _ => {
            if context_length <= TWO_STAGE_THRESHOLD {
                RoutingMode::TwoStage
            } else {
                RoutingMode::Direct
            }
        }
    }
}

/// Convenience: decide the routing mode straight from a
/// `ModelProfile`. Reads the operator env override on the
/// caller's behalf via `std::env::var("NEOTH_TOOL_ROUTING")`.
pub fn routing_mode_for_profile(profile: &ModelProfile) -> RoutingMode {
    let env = std::env::var("NEOTH_TOOL_ROUTING").ok();
    routing_mode(profile.context_length, env.as_deref())
}

/// Human-readable category description shown in the Stage-1
/// selector prompt. Strings mirror smallcode's exact text so
/// model outputs trained on one corpus match the other.
pub fn category_description(cat: ToolCategory) -> &'static str {
    match cat {
        ToolCategory::Read => "Read file contents, find files by pattern",
        ToolCategory::Write => "Create files, edit files with patch, rewrite files",
        ToolCategory::Search => "Search code by regex, search code graph, explain symbols",
        ToolCategory::Run => "Run shell commands, execute scripts",
        ToolCategory::Plan => "Load/save project memory, BoneScript compile/check",
        ToolCategory::CodeIntel => "AST navigation, symbol resolution, type queries",
    }
}

/// Indicative member tools per category. Names match
/// smallcode's tool catalogue so a small LLM that's been
/// fine-tuned on smallcode traces does not have to re-learn
/// the vocabulary when run against NEOTH. NEOTH's real tool
/// registry (lands with the MCP bridge) will override these
/// hints with the actual canonical names.
pub fn category_member_hint(cat: ToolCategory) -> &'static [&'static str] {
    match cat {
        ToolCategory::Read => &["read_file", "find_files", "find_and_read"],
        ToolCategory::Write => &["write_file", "patch", "read_and_patch", "create_and_run"],
        ToolCategory::Search => &[
            "search",
            "search_and_read",
            "graph_search",
            "explain_symbol",
            "list_projects",
        ],
        ToolCategory::Run => &["bash", "run"],
        ToolCategory::Plan => &[
            "memory_load",
            "memory_remember",
            "bone_compile",
            "bone_check",
        ],
        ToolCategory::CodeIntel => &["explain_symbol", "graph_search"],
    }
}

/// Build the Stage-1 selector prompt body. Pure — no IO; the
/// caller wraps this in the provider Request alongside the
/// task description. Format follows smallcode's exact
/// shape so a model trained on either set of traces sees the
/// same prompt skeleton.
pub fn build_selector_prompt() -> String {
    let mut out = String::with_capacity(512);
    out.push_str(
        "You have access to several tool categories. Pick exactly ONE \
         category that fits your next action. Reply with the category \
         name only — no JSON, no prose.\n\n\
         Categories:\n",
    );
    for cat in ToolCategory::ALL {
        out.push_str("  - ");
        out.push_str(cat.as_str());
        out.push_str(": ");
        out.push_str(category_description(*cat));
        out.push('\n');
    }
    out.push_str("\nReply with the category name.\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn category_wire_forms_are_stable_lowercase() {
        // Audit-grep contract: these strings appear in WAL
        // events + cross-project logs. Pin them.
        assert_eq!(ToolCategory::Read.as_str(), "read");
        assert_eq!(ToolCategory::Write.as_str(), "write");
        assert_eq!(ToolCategory::Search.as_str(), "search");
        assert_eq!(ToolCategory::Run.as_str(), "run");
        assert_eq!(ToolCategory::Plan.as_str(), "plan");
        assert_eq!(ToolCategory::CodeIntel.as_str(), "code_intel");
    }

    #[test]
    fn category_from_str_roundtrips_every_variant() {
        for cat in ToolCategory::ALL {
            let parsed = ToolCategory::from_str(cat.as_str())
                .unwrap_or_else(|| panic!("must parse: {}", cat.as_str()));
            assert_eq!(parsed, *cat);
        }
    }

    #[test]
    fn category_from_str_accepts_codeintel_no_underscore_alias() {
        // Operator typo tolerance — model replies vary
        // between `code_intel` and `codeintel`. Accept both.
        assert_eq!(
            ToolCategory::from_str("codeintel"),
            Some(ToolCategory::CodeIntel)
        );
        assert_eq!(
            ToolCategory::from_str("code_intel"),
            Some(ToolCategory::CodeIntel)
        );
    }

    #[test]
    fn category_from_str_unknown_returns_none() {
        assert_eq!(ToolCategory::from_str("nope"), None);
        assert_eq!(ToolCategory::from_str(""), None);
        // Case-sensitive: from_str is the wire-form parser,
        // not a human-input parser. CLI/UI code lowercases
        // before calling.
        assert_eq!(ToolCategory::from_str("READ"), None);
    }

    #[test]
    fn all_iteration_order_is_pinned() {
        // The selector prompt template + WAL audit order
        // both depend on this. Don't reorder lightly.
        let expected = [
            ToolCategory::Read,
            ToolCategory::Write,
            ToolCategory::Search,
            ToolCategory::Run,
            ToolCategory::Plan,
            ToolCategory::CodeIntel,
        ];
        assert_eq!(ToolCategory::ALL, &expected);
    }

    #[test]
    fn routing_mode_is_two_stage_for_small_context() {
        // 16k is INCLUSIVE in the two-stage band — the
        // threshold matches smallcode's `<= 16384`.
        assert_eq!(routing_mode(16_384, None), RoutingMode::TwoStage);
        assert_eq!(routing_mode(8_000, None), RoutingMode::TwoStage);
        assert_eq!(routing_mode(1_024, None), RoutingMode::TwoStage);
    }

    #[test]
    fn routing_mode_is_direct_for_large_context() {
        assert_eq!(routing_mode(16_385, None), RoutingMode::Direct);
        assert_eq!(routing_mode(32_768, None), RoutingMode::Direct);
        assert_eq!(routing_mode(128_000, None), RoutingMode::Direct);
    }

    #[test]
    fn env_override_direct_forces_direct() {
        assert_eq!(routing_mode(1_024, Some("direct")), RoutingMode::Direct);
    }

    #[test]
    fn env_override_two_stage_forces_two_stage() {
        assert_eq!(
            routing_mode(128_000, Some("two_stage")),
            RoutingMode::TwoStage
        );
    }

    #[test]
    fn env_override_unknown_value_falls_back_to_auto() {
        // Operator typo / future value must NOT break the
        // pipeline — silently fall back to the size heuristic.
        assert_eq!(
            routing_mode(1_024, Some("yolo")),
            RoutingMode::TwoStage,
            "unknown override falls back to context-size auto"
        );
        assert_eq!(
            routing_mode(128_000, Some("yolo")),
            RoutingMode::Direct,
            "unknown override falls back to context-size auto"
        );
    }

    #[test]
    fn routing_mode_for_profile_uses_profile_context_length() {
        // Pin the profile -> mode bridge. We don't set the
        // env var in this test so the env-override branch
        // is empty.
        let qwen3 = crate::coding::model_profile::match_profile("qwen3").unwrap();
        assert_eq!(qwen3.context_length, 32_768);
        // SAFETY: tests are single-threaded enough that
        // remove_var is fine, but we don't want to depend on
        // process state. Just assert against the function's
        // pure path via `routing_mode` instead.
        let mode = routing_mode(qwen3.context_length, None);
        assert_eq!(mode, RoutingMode::Direct);

        let deepseek = crate::coding::model_profile::match_profile("deepseek-coder").unwrap();
        assert_eq!(deepseek.context_length, 16_384);
        let mode = routing_mode(deepseek.context_length, None);
        assert_eq!(mode, RoutingMode::TwoStage);
    }

    #[test]
    fn routing_mode_as_str_is_stable_wire_form() {
        assert_eq!(RoutingMode::Direct.as_str(), "direct");
        assert_eq!(RoutingMode::TwoStage.as_str(), "two_stage");
    }

    #[test]
    fn category_description_is_non_empty_for_every_variant() {
        for cat in ToolCategory::ALL {
            let d = category_description(*cat);
            assert!(!d.is_empty(), "description must be non-empty for {cat:?}");
        }
    }

    #[test]
    fn category_member_hint_is_non_empty_for_every_variant() {
        for cat in ToolCategory::ALL {
            let m = category_member_hint(*cat);
            assert!(!m.is_empty(), "member list must be non-empty for {cat:?}");
        }
    }

    #[test]
    fn build_selector_prompt_lists_every_category_in_order() {
        let prompt = build_selector_prompt();
        let mut last_pos = 0usize;
        for cat in ToolCategory::ALL {
            let p = prompt
                .find(cat.as_str())
                .unwrap_or_else(|| panic!("missing category {} in prompt", cat.as_str()));
            assert!(
                p >= last_pos,
                "category {} appeared out of order in selector prompt",
                cat.as_str()
            );
            last_pos = p;
        }
    }

    #[test]
    fn build_selector_prompt_includes_descriptions() {
        let prompt = build_selector_prompt();
        for cat in ToolCategory::ALL {
            assert!(
                prompt.contains(category_description(*cat)),
                "missing description for {cat:?}"
            );
        }
    }

    #[test]
    fn two_stage_threshold_constant_pinned() {
        // The 16k value flows into both `routing_mode` and
        // `ModelProfile::needs_two_stage_router`. Pin the
        // constant so changing it requires touching the test.
        assert_eq!(TWO_STAGE_THRESHOLD, 16_384);
    }
}
