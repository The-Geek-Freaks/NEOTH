//! GOLD-ADAPT-SPEAKR-01 — 5-layer prompt composition for summarization.
//!
//! Concept re-implemented from speakr (AGPL-3.0) — no text was copied.
//!
//! ## Layer order (highest→lowest priority)
//!
//! ```text
//! 1. admin     — operator-level hardcoded baseline (never user-overridable)
//! 2. user      — user-supplied override
//! 3. folder    — folder/context-scoped prompt
//! 4. tag       — tag-scoped prompt
//! 5. append    — base append-mode layer (lowest priority, merged when append_mode=true)
//! ```
//!
//! `compose()` short-circuits at the FIRST `Some` layer (highest to lowest)
//! **unless** `append_mode` is set — in that case, ALL non-`None` layers are
//! concatenated in priority order (admin first, append last).
//!
//! After composition, `{{var}}` placeholders are substituted from a caller-
//! supplied map. Substitution runs last (after compose) so layer authors do not
//! need to duplicate variable bindings.
//!
//! ## Prompt-role split
//!
//! `compose_with_roles()` splits the composed text into two roles that map to
//! provider `Request`:
//!   - The **context** layer (admin + folder) → `system` prompt.
//!   - The **instructions** layer (user + tag + append) → `user` prompt.
//!
//! Both sides pass through `{{var}}` substitution independently.
//!
//! ## Integration note
//!
//! The `SummarizePromptLayers` struct is standalone and has no I/O dependency.
//! Integration with `freedom.yaml::skills.meeting_summary.prompt_layers` and
//! the memory ingress summarisation path is a follow-up wire — this module is
//! fully tested headless.

use std::collections::HashMap;

/// Priority slots for a 5-layer compose stack.
///
/// `None` = absent/unset (slot skipped).  `append_mode = true` merges all
/// non-`None` slots rather than short-circuiting at the first hit.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SummarizePromptLayers {
    /// Layer 1 — hardcoded admin baseline (highest priority).
    pub admin: Option<String>,
    /// Layer 2 — user-supplied override.
    pub user: Option<String>,
    /// Layer 3 — folder/context-scoped prompt.
    pub folder: Option<String>,
    /// Layer 4 — tag-scoped prompt.
    pub tag: Option<String>,
    /// Layer 5 — base append-mode text (lowest priority).
    pub append: Option<String>,
    /// When `true`, all non-`None` layers are concatenated (highest→lowest)
    /// rather than short-circuiting at the first hit.
    pub append_mode: bool,
}

/// Layers iterated in priority order (highest first).
const PRIORITY_ORDER: usize = 5;

impl SummarizePromptLayers {
    /// Return references to all 5 slots in priority order (admin first,
    /// append last).  Used by compose() so the ordering is defined once.
    fn slots(&self) -> [Option<&str>; PRIORITY_ORDER] {
        [
            self.admin.as_deref(),
            self.user.as_deref(),
            self.folder.as_deref(),
            self.tag.as_deref(),
            self.append.as_deref(),
        ]
    }

    /// Compose all layers into a single prompt string.
    ///
    /// - In **override** mode (`append_mode = false`): returns the first
    ///   `Some` slot's text, ignoring all lower-priority slots.
    /// - In **append** mode (`append_mode = true`): concatenates every
    ///   non-`None` slot's text, highest-priority first, separated by `\n`.
    ///   Empty-after-trim strings are skipped even when the slot is `Some`.
    ///
    /// Returns an empty string when every slot is `None`.
    pub fn compose(&self) -> String {
        if self.append_mode {
            self.slots()
                .iter()
                .filter_map(|s| {
                    s.and_then(|t| {
                        let t = t.trim();
                        if t.is_empty() {
                            None
                        } else {
                            Some(t.to_owned())
                        }
                    })
                })
                .collect::<Vec<_>>()
                .join("\n")
        } else {
            // Short-circuit at first non-empty Some.
            for t in self.slots().iter().flatten() {
                let t = t.trim();
                if !t.is_empty() {
                    return t.to_owned();
                }
            }
            String::new()
        }
    }

    /// Compose and then substitute every `{{key}}` placeholder in the result
    /// with the matching value from `vars`.  Unknown keys are left verbatim.
    pub fn compose_with_vars(&self, vars: &HashMap<&str, &str>) -> String {
        substitute(self.compose(), vars)
    }

    /// Split into `(system_prompt, user_prompt)` for provider `Request`:
    ///
    /// - **system** = admin + folder layers (context-level framing).
    /// - **user**   = user + tag + append layers (task instructions).
    ///
    /// Each side is composed **independently** (respecting `append_mode`
    /// within its own set of slots) and then `{{var}}` substituted.
    pub fn compose_with_roles(&self, vars: &HashMap<&str, &str>) -> (String, String) {
        // Context (system) side: admin + folder.
        let context_layers = SummarizePromptLayers {
            admin: self.admin.clone(),
            folder: self.folder.clone(),
            append_mode: self.append_mode,
            ..Default::default()
        };
        // Instructions (user) side: user + tag + append.
        let instructions_layers = SummarizePromptLayers {
            user: self.user.clone(),
            tag: self.tag.clone(),
            append: self.append.clone(),
            append_mode: self.append_mode,
            ..Default::default()
        };
        (
            substitute(context_layers.compose(), vars),
            substitute(instructions_layers.compose(), vars),
        )
    }
}

/// Substitute `{{key}}` placeholders in `text` using `vars`.
/// Unknown keys are left as-is.  The function is allocation-efficient:
/// it scans once, replacing in a single pass via a growable `String`.
pub fn substitute(text: String, vars: &HashMap<&str, &str>) -> String {
    if !text.contains("{{") {
        return text; // fast path — nothing to substitute
    }
    let mut out = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Look for `{{`.
        if i + 1 < bytes.len() && bytes[i] == b'{' && bytes[i + 1] == b'{' {
            // Find the closing `}}`.
            if let Some(end) = text[i + 2..].find("}}") {
                let key = &text[i + 2..i + 2 + end];
                if let Some(&val) = vars.get(key) {
                    out.push_str(val);
                } else {
                    // Unknown key — leave verbatim.
                    out.push_str(&text[i..i + 2 + end + 2]);
                }
                i += 2 + end + 2; // skip past `}}`
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars<'a>(pairs: &[(&'a str, &'a str)]) -> HashMap<&'a str, &'a str> {
        pairs.iter().copied().collect()
    }

    // --- compose() override mode ---

    #[test]
    fn compose_returns_admin_when_set() {
        let layers = SummarizePromptLayers {
            admin: Some("admin baseline".to_owned()),
            user: Some("user override".to_owned()),
            folder: Some("folder ctx".to_owned()),
            tag: Some("tag ctx".to_owned()),
            append: Some("append base".to_owned()),
            append_mode: false,
        };
        assert_eq!(layers.compose(), "admin baseline");
    }

    #[test]
    fn compose_falls_through_to_user_when_admin_absent() {
        let layers = SummarizePromptLayers {
            admin: None,
            user: Some("user override".to_owned()),
            folder: Some("folder ctx".to_owned()),
            ..Default::default()
        };
        assert_eq!(layers.compose(), "user override");
    }

    #[test]
    fn compose_skips_empty_some_and_continues() {
        // A Some("") in a high-priority slot must be treated as absent.
        let layers = SummarizePromptLayers {
            admin: Some("   ".to_owned()), // whitespace-only → skip
            user: Some("user prompt".to_owned()),
            ..Default::default()
        };
        assert_eq!(layers.compose(), "user prompt");
    }

    #[test]
    fn compose_returns_empty_when_all_slots_are_none() {
        let layers = SummarizePromptLayers::default();
        assert_eq!(layers.compose(), "");
    }

    #[test]
    fn compose_returns_last_slot_when_all_others_absent() {
        let layers = SummarizePromptLayers {
            append: Some("base fallback".to_owned()),
            ..Default::default()
        };
        assert_eq!(layers.compose(), "base fallback");
    }

    // --- compose() append mode ---

    #[test]
    fn compose_append_mode_concatenates_all_non_none_slots() {
        let layers = SummarizePromptLayers {
            admin: Some("admin".to_owned()),
            user: Some("user".to_owned()),
            folder: None,
            tag: Some("tag".to_owned()),
            append: Some("base".to_owned()),
            append_mode: true,
        };
        let result = layers.compose();
        // All four present slots must appear, in priority order.
        assert!(result.contains("admin"), "admin missing");
        assert!(result.contains("user"), "user missing");
        assert!(result.contains("tag"), "tag missing");
        assert!(result.contains("base"), "base missing");
        // Priority ordering: admin before user before tag before base.
        let ai = result.find("admin").unwrap();
        let ui = result.find("user").unwrap();
        let ti = result.find("tag").unwrap();
        let bi = result.find("base").unwrap();
        assert!(ai < ui, "admin must precede user");
        assert!(ui < ti, "user must precede tag");
        assert!(ti < bi, "tag must precede base");
    }

    #[test]
    fn compose_append_mode_skips_empty_slots() {
        let layers = SummarizePromptLayers {
            admin: Some("   ".to_owned()),
            user: Some("instructions".to_owned()),
            append_mode: true,
            ..Default::default()
        };
        let result = layers.compose();
        assert_eq!(
            result, "instructions",
            "whitespace-only slot must be skipped"
        );
    }

    #[test]
    fn compose_append_mode_with_single_slot_is_just_that_slot() {
        let layers = SummarizePromptLayers {
            user: Some("only me".to_owned()),
            append_mode: true,
            ..Default::default()
        };
        assert_eq!(layers.compose(), "only me");
    }

    // --- {{var}} substitution ---

    #[test]
    fn substitute_expands_known_vars() {
        let vars = vars(&[("name", "Alex"), ("date", "2026-06-21")]);
        let text = "Summary for {{name}} on {{date}}.".to_owned();
        assert_eq!(substitute(text, &vars), "Summary for Alex on 2026-06-21.");
    }

    #[test]
    fn substitute_leaves_unknown_vars_verbatim() {
        let text = "Hello {{unknown}}.".to_owned();
        let result = substitute(text, &HashMap::new());
        assert_eq!(result, "Hello {{unknown}}.");
    }

    #[test]
    fn substitute_fast_path_when_no_braces() {
        let text = "no substitution needed".to_owned();
        let result = substitute(text.clone(), &HashMap::new());
        assert_eq!(result, text);
    }

    #[test]
    fn substitute_multiple_occurrences_of_same_key() {
        let vars = vars(&[("x", "42")]);
        let text = "{{x}} + {{x}} = 84".to_owned();
        assert_eq!(substitute(text, &vars), "42 + 42 = 84");
    }

    // --- compose_with_vars ---

    #[test]
    fn compose_with_vars_expands_after_compose() {
        let layers = SummarizePromptLayers {
            user: Some("Meeting on {{date}}".to_owned()),
            ..Default::default()
        };
        let v = vars(&[("date", "2026-06-21")]);
        assert_eq!(layers.compose_with_vars(&v), "Meeting on 2026-06-21");
    }

    #[test]
    fn compose_with_vars_append_mode_expands_all_layers() {
        let layers = SummarizePromptLayers {
            admin: Some("Admin for {{topic}}".to_owned()),
            user: Some("User prompt".to_owned()),
            append_mode: true,
            ..Default::default()
        };
        let v = vars(&[("topic", "Q2")]);
        let result = layers.compose_with_vars(&v);
        assert!(result.contains("Admin for Q2"));
        assert!(result.contains("User prompt"));
    }

    // --- compose_with_roles ---

    #[test]
    fn roles_split_system_and_user_prompts() {
        let layers = SummarizePromptLayers {
            admin: Some("system framing".to_owned()),
            folder: Some("folder context".to_owned()),
            user: Some("task instructions".to_owned()),
            tag: Some("tag hint".to_owned()),
            append: None,
            append_mode: false,
        };
        let (system, user) = layers.compose_with_roles(&HashMap::new());
        // admin → system (short-circuits at first hit)
        assert_eq!(system, "system framing");
        // user  → user (short-circuits at first hit)
        assert_eq!(user, "task instructions");
    }

    #[test]
    fn roles_system_falls_through_to_folder_when_admin_absent() {
        let layers = SummarizePromptLayers {
            admin: None,
            folder: Some("folder context".to_owned()),
            user: Some("instructions".to_owned()),
            ..Default::default()
        };
        let (system, user) = layers.compose_with_roles(&HashMap::new());
        assert_eq!(system, "folder context");
        assert_eq!(user, "instructions");
    }

    #[test]
    fn roles_system_empty_when_no_context_layers_set() {
        let layers = SummarizePromptLayers {
            user: Some("only user".to_owned()),
            ..Default::default()
        };
        let (system, user) = layers.compose_with_roles(&HashMap::new());
        assert_eq!(system, "", "no admin/folder → empty system");
        assert_eq!(user, "only user");
    }

    #[test]
    fn roles_substitute_vars_in_both_sides() {
        let layers = SummarizePromptLayers {
            admin: Some("Context: {{ctx}}".to_owned()),
            user: Some("Summarize {{topic}}".to_owned()),
            ..Default::default()
        };
        let v = vars(&[("ctx", "meeting"), ("topic", "Q3 planning")]);
        let (system, user) = layers.compose_with_roles(&v);
        assert_eq!(system, "Context: meeting");
        assert_eq!(user, "Summarize Q3 planning");
    }

    #[test]
    fn roles_append_mode_merges_each_side_independently() {
        let layers = SummarizePromptLayers {
            admin: Some("admin base".to_owned()),
            folder: Some("folder ctx".to_owned()),
            user: Some("user inst".to_owned()),
            tag: Some("tag inst".to_owned()),
            append: Some("append base".to_owned()),
            append_mode: true,
        };
        let (system, user) = layers.compose_with_roles(&HashMap::new());
        // system = admin + folder merged
        assert!(system.contains("admin base") && system.contains("folder ctx"));
        // user = user + tag + append merged
        assert!(
            user.contains("user inst") && user.contains("tag inst") && user.contains("append base")
        );
        // No cross-contamination
        assert!(
            !system.contains("user inst"),
            "user text must not bleed into system"
        );
        assert!(
            !user.contains("admin base"),
            "admin text must not bleed into user"
        );
    }
}
