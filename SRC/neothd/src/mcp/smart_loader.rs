//! N-04 (Session 24) — Smart MCP loader.
//!
//! Pre-fix: every chat turn rendered the FULL MCP tool catalogue
//! into the system prompt regardless of whether the operator's
//! prompt referenced any tool. With 4-5 MCP servers loaded, each
//! one shipping 10+ tools, that's ~3-8 KiB of tokens burned on
//! every turn — most of which the model ignores.
//!
//! Smart loader: load a server's tools into the prompt context
//! only when the operator's prompt is plausibly about to use
//! them. Two trigger signals:
//!
//! 1. **Explicit reference**: operator typed a slash command
//!    starting with `/<server-name>` or mentioned `<server-name>`
//!    as a word in the prompt.
//! 2. **Tool-name match**: operator's prompt contains a
//!    substring that matches a known tool name for that server.
//!
//! Servers that match either signal are **active**; the rest are
//! **deferred**. The deferred set still ships a one-line
//! "available on demand" hint so the model knows it CAN ask for
//! them via a follow-up slash command. Operators with strict
//! token-budget needs can disable the hint via the config flag.
//!
//! ## Why pure-keyword + not LLM-driven
//!
//! Same rationale as M-09 region routing: zero-cost zero-network
//! classifier covers the 80% case where the operator's intent is
//! lexically obvious. Mis-route surfaces as "tool not loaded" →
//! operator re-asks with `/server-name tool-args`. A future v0.9
//! enhancement can swap the keyword scan for a tiny local
//! relevance model without changing the [`LoadPlan`] interface.

use std::collections::HashSet;

use serde::Serialize;

/// One known MCP server + its tool names. Operator-supplied
/// (today via the existing `mcp::config` surface; this module
/// only consumes the resolved view).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerProfile {
    pub name: String,
    /// Lowercased tool names exposed by this server. Matching is
    /// case-insensitive against the prompt.
    pub tool_names: Vec<String>,
}

impl ServerProfile {
    /// Builder helper for tests + future external consumers.
    pub fn new(name: impl Into<String>, tool_names: impl IntoIterator<Item = String>) -> Self {
        Self {
            name: name.into(),
            tool_names: tool_names
                .into_iter()
                .map(|t| t.to_lowercase())
                .collect(),
        }
    }
}

/// Per-server load decision. Carries a reason string so operators
/// inspecting `neoth mcp explain --prompt "..."` see WHICH signal
/// activated which server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LoadDecision {
    pub server_name: String,
    pub active: bool,
    pub reason: LoadReason,
}

/// Why a server is active or deferred. Snake_case wire form for
/// stable CLI / GUI / JSON consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadReason {
    /// Prompt contains the server name as a word OR as a
    /// `/<name>` slash command.
    ExplicitReference,
    /// Prompt contains a substring matching one of the server's
    /// tool names.
    ToolNameMatch,
    /// No trigger fired — server stays deferred + appears in the
    /// "available on demand" hint instead of the full catalogue.
    NoTrigger,
}

impl LoadReason {
    /// Stable wire form. Drift-guard pinned.
    pub fn as_str(self) -> &'static str {
        match self {
            LoadReason::ExplicitReference => "explicit_reference",
            LoadReason::ToolNameMatch => "tool_name_match",
            LoadReason::NoTrigger => "no_trigger",
        }
    }
}

/// What [`plan_loader`] returns. `decisions` carries one entry
/// per known server; helpers split them into active vs deferred
/// for the caller's render path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LoadPlan {
    pub decisions: Vec<LoadDecision>,
}

impl LoadPlan {
    pub fn active_servers(&self) -> Vec<&str> {
        self.decisions
            .iter()
            .filter(|d| d.active)
            .map(|d| d.server_name.as_str())
            .collect()
    }

    pub fn deferred_servers(&self) -> Vec<&str> {
        self.decisions
            .iter()
            .filter(|d| !d.active)
            .map(|d| d.server_name.as_str())
            .collect()
    }

    /// Total token-saving signal — how many of the known servers
    /// the loader successfully deferred. Tests + the future
    /// `neoth mcp explain` CLI consume this for the operator
    /// summary line ("12 of 15 servers deferred this turn").
    pub fn deferred_count(&self) -> usize {
        self.decisions.iter().filter(|d| !d.active).count()
    }
}

/// Build the load plan for one prompt against the known server
/// set. Pure-fn: no IO, no clock, no network. Deterministic on
/// (prompt, servers).
pub fn plan_loader(prompt: &str, servers: &[ServerProfile]) -> LoadPlan {
    let lowered = prompt.to_lowercase();
    // Tokenize once for word-boundary checks (explicit-reference
    // signal). The slash-prefix scan does substring match because
    // `/foo` is a structurally distinct prefix.
    let tokens: HashSet<&str> = lowered
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-')
        .filter(|t| !t.is_empty())
        .collect();

    let mut decisions = Vec::with_capacity(servers.len());
    for server in servers {
        let lower_name = server.name.to_lowercase();
        let slash_prefix = format!("/{lower_name}");

        // Explicit reference: slash command OR word-boundary mention.
        if lowered.contains(&slash_prefix) || tokens.contains(lower_name.as_str()) {
            decisions.push(LoadDecision {
                server_name: server.name.clone(),
                active: true,
                reason: LoadReason::ExplicitReference,
            });
            continue;
        }

        // Tool-name match: any tool name appears as a substring.
        // Substring (not word-boundary) because operator queries
        // like "search for the search_files thing" mention the
        // tool name embedded in description text.
        let tool_hit = server
            .tool_names
            .iter()
            .any(|tool| !tool.is_empty() && lowered.contains(tool.as_str()));
        if tool_hit {
            decisions.push(LoadDecision {
                server_name: server.name.clone(),
                active: true,
                reason: LoadReason::ToolNameMatch,
            });
            continue;
        }

        // No trigger — defer.
        decisions.push(LoadDecision {
            server_name: server.name.clone(),
            active: false,
            reason: LoadReason::NoTrigger,
        });
    }

    LoadPlan { decisions }
}

/// Render the "available on demand" hint that lists deferred
/// servers + their tool counts. Returned as a single line ready
/// to drop into the system prompt's tail. Returns `None` when
/// every server is active (no deferred to advertise).
///
/// Format (intentionally terse to minimise token spend):
/// `"MCP servers available on demand: foo (3 tools), bar (12 tools).
///   Type /<server-name> to load."`
pub fn render_deferred_hint(plan: &LoadPlan, servers: &[ServerProfile]) -> Option<String> {
    let deferred: Vec<&ServerProfile> = servers
        .iter()
        .filter(|s| {
            plan.decisions
                .iter()
                .any(|d| d.server_name == s.name && !d.active)
        })
        .collect();
    if deferred.is_empty() {
        return None;
    }
    let parts: Vec<String> = deferred
        .iter()
        .map(|s| {
            let n = s.tool_names.len();
            let plural = if n == 1 { "tool" } else { "tools" };
            format!("{} ({} {})", s.name, n, plural)
        })
        .collect();
    Some(format!(
        "MCP servers available on demand: {}. Type /<server-name> to load.",
        parts.join(", "),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(name: &str, tools: &[&str]) -> ServerProfile {
        ServerProfile::new(name, tools.iter().map(|s| s.to_string()))
    }

    // ── reason wire-form drift guard ──────────────────────────────────

    #[test]
    fn reason_as_str_pinned_for_audit() {
        assert_eq!(LoadReason::ExplicitReference.as_str(), "explicit_reference");
        assert_eq!(LoadReason::ToolNameMatch.as_str(), "tool_name_match");
        assert_eq!(LoadReason::NoTrigger.as_str(), "no_trigger");
    }

    // ── plan_loader: trigger signals ──────────────────────────────────

    #[test]
    fn slash_prefix_activates_server() {
        let s = server("filesystem", &["read_file", "list_dir"]);
        let plan = plan_loader("/filesystem read_file foo.txt", &[s]);
        assert_eq!(plan.decisions[0].active, true);
        assert_eq!(plan.decisions[0].reason, LoadReason::ExplicitReference);
    }

    #[test]
    fn word_boundary_mention_activates_server() {
        let s = server("github", &["create_issue"]);
        let plan = plan_loader("can you use github for this", &[s]);
        assert_eq!(plan.decisions[0].active, true);
        assert_eq!(plan.decisions[0].reason, LoadReason::ExplicitReference);
    }

    #[test]
    fn server_name_inside_larger_word_does_not_trigger_explicit() {
        // "githubusercontent" does NOT mention `github` as a word.
        // Pin so a future substring-match drift doesn't false-fire.
        let s = server("github", &["create_issue"]);
        let plan = plan_loader(
            "fetch raw.githubusercontent.com/foo/bar/main.txt",
            &[s.clone()],
        );
        // No tool match either → deferred.
        assert!(!plan.decisions[0].active);
        assert_eq!(plan.decisions[0].reason, LoadReason::NoTrigger);
    }

    #[test]
    fn tool_name_substring_activates_server() {
        let s = server("fs_server", &["read_file", "list_dir"]);
        let plan = plan_loader("I need to read_file from the project", &[s]);
        assert_eq!(plan.decisions[0].active, true);
        assert_eq!(plan.decisions[0].reason, LoadReason::ToolNameMatch);
    }

    #[test]
    fn tool_name_match_is_case_insensitive() {
        let s = server("fs_server", &["read_file"]);
        let plan = plan_loader("READ_FILE the manifest", &[s]);
        assert_eq!(plan.decisions[0].active, true);
        assert_eq!(plan.decisions[0].reason, LoadReason::ToolNameMatch);
    }

    #[test]
    fn no_trigger_defers_server() {
        let s = server("github", &["create_issue", "list_prs"]);
        let plan = plan_loader("just a normal chat about the weather", &[s]);
        assert!(!plan.decisions[0].active);
        assert_eq!(plan.decisions[0].reason, LoadReason::NoTrigger);
    }

    #[test]
    fn empty_tool_name_does_not_match_everything() {
        // Drift guard: a server with an empty-string tool_name
        // entry must NOT match every prompt via `"".contains("")`.
        let s = ServerProfile {
            name: "broken".into(),
            tool_names: vec!["".into()],
        };
        let plan = plan_loader("any prompt at all", &[s]);
        assert!(!plan.decisions[0].active);
    }

    #[test]
    fn explicit_reference_wins_over_tool_match_when_both_present() {
        // Pin: classifier returns at the FIRST signal it finds.
        // Explicit reference is checked first, so a prompt that
        // matches both surfaces ExplicitReference (operator-visible
        // "why was this loaded?" answer is the strongest signal).
        let s = server("fs_server", &["read_file"]);
        let plan = plan_loader("/fs_server read_file foo", &[s]);
        assert_eq!(plan.decisions[0].reason, LoadReason::ExplicitReference);
    }

    #[test]
    fn multi_server_plan_partitions_active_and_deferred() {
        let plan = plan_loader(
            "lets check /github for prs",
            &[
                server("github", &["list_prs"]),
                server("filesystem", &["read_file"]),
                server("kanban", &["move_task"]),
            ],
        );
        let active = plan.active_servers();
        let deferred = plan.deferred_servers();
        assert_eq!(active, vec!["github"]);
        assert!(deferred.contains(&"filesystem"));
        assert!(deferred.contains(&"kanban"));
        assert_eq!(plan.deferred_count(), 2);
    }

    #[test]
    fn empty_server_list_returns_empty_plan() {
        let plan = plan_loader("any prompt", &[]);
        assert!(plan.decisions.is_empty());
        assert_eq!(plan.deferred_count(), 0);
    }

    // ── render_deferred_hint ──────────────────────────────────────────

    #[test]
    fn deferred_hint_lists_servers_with_tool_counts() {
        let servers = vec![
            server("github", &["list_prs", "create_issue", "merge"]),
            server("filesystem", &["read_file"]),
        ];
        let plan = plan_loader("unrelated weather chat", &servers);
        let hint = render_deferred_hint(&plan, &servers).unwrap();
        assert!(hint.contains("github (3 tools)"));
        assert!(hint.contains("filesystem (1 tool)"));
        assert!(hint.contains("/<server-name>"));
    }

    #[test]
    fn deferred_hint_pluralises_correctly() {
        // 1 tool → "tool" singular; 0 + >=2 → "tools".
        let single = vec![server("solo", &["only_one"])];
        let plan = plan_loader("nothing matches", &single);
        let hint = render_deferred_hint(&plan, &single).unwrap();
        assert!(hint.contains("(1 tool)"));
        assert!(!hint.contains("(1 tools)"));

        // Use long unique tool names so the substring matcher
        // can't false-fire against incidental prompt characters.
        let multi = vec![
            server("zero", &[]),
            server("many", &["xyzzy_alpha", "xyzzy_beta"]),
        ];
        let plan_m = plan_loader("qqqqq prompt", &multi);
        let hint_m = render_deferred_hint(&plan_m, &multi).unwrap();
        assert!(hint_m.contains("(0 tools)"), "got: {hint_m}");
        assert!(hint_m.contains("(2 tools)"), "got: {hint_m}");
    }

    #[test]
    fn deferred_hint_returns_none_when_every_server_active() {
        let s = server("github", &["list_prs"]);
        let plan = plan_loader("/github list_prs", &[s.clone()]);
        let hint = render_deferred_hint(&plan, &[s]);
        assert!(hint.is_none());
    }

    #[test]
    fn deferred_hint_returns_none_for_empty_server_list() {
        let plan = plan_loader("any", &[]);
        assert!(render_deferred_hint(&plan, &[]).is_none());
    }
}
