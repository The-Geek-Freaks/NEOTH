//! TOML schema for declarative hooks — Phase 29 R-15 H-2.
//!
//! A hook is a named filter that fires at a specific pipeline stage and
//! either lets the message through, replaces its body, or blocks it.
//! Hooks are operator-defined, declarative TOML; no Rust trait impls
//! required for v0.1.
//!
//! ```toml
//! # ~/.neoth/hooks/redact-tokens.toml
//! name    = "redact-tokens"
//! stage   = "pre_provider_call"
//! enabled = true
//!
//! [matcher]
//! # Regex applied to the message body. Optional — when absent, the hook
//! # fires on every message at this stage.
//! pattern = "(?i)\\b(api[_-]?key|secret|token)\\s*[:=]\\s*\\S+"
//!
//! [action]
//! kind     = "replace"
//! template = "[REDACTED]"
//! ```
//!
//! Compiled (Rust) hooks via the `neoth-plugin-sdk::Hook<L>` trait remain
//! available for advanced use, but the v0.1 operator surface is TOML.

use serde::{Deserialize, Serialize};

use super::stages::HookStage;

/// One operator-defined hook.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct HookDef {
    /// Stable identifier. Surfaces in `/hooks list` and WAL audit events.
    pub name: String,
    /// Pipeline stage this hook attaches to.
    pub stage: HookStage,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub matcher: Option<HookMatcher>,
    pub action: HookAction,
}

impl HookDef {
    pub fn is_enabled(&self) -> bool {
        self.enabled.unwrap_or(true)
    }
}

/// Optional content filter. Anchored at the start of the body. If absent,
/// the hook fires unconditionally at its stage.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct HookMatcher {
    /// Regex applied to the inbound text. Compiled lazily so an invalid
    /// pattern fails at first-use, not at load (one bad operator hook
    /// shouldn't tank the daemon).
    pub pattern: String,
}

/// What the hook does when its matcher fires.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HookAction {
    /// Allow the pipeline to continue unmodified. Useful for hooks that
    /// only emit audit events.
    Allow,
    /// Replace the matched portion of the body with `template`.
    /// `template` supports `{0}` substitution for the matched group.
    Replace { template: String },
    /// Stop the pipeline. The operator-visible reason is logged.
    Block { reason: String },
    /// Pick #34 follow-up (2026-05-20): invoke a discovered WASM
    /// plugin by id. The hook dispatcher delegates to the operator-
    /// provided `PluginInvoker`; no wasmtime dep leaks into the
    /// hook module itself.
    ///
    /// ## `required` flag (R2-P0-3 / 2026-05-22)
    ///
    /// Closes the silent-fail-open hole flagged by the R2 reviewer
    /// (`PLAN/REEVALUATION_GESAMT_2026-05-21_R2.md` §4 P0-3).
    /// Pre-fix: missing invoker / compile failure / discovery skip
    /// silently degraded Plugin actions to Allow + warn log. Fine for
    /// optional telemetry hooks; catastrophic for safety hooks that
    /// the operator wrote precisely BECAUSE they wanted a block.
    /// Post-fix:
    ///
    /// - `required: false` (default) — invoker-missing degrades to
    ///   Allow + warn (legacy semantics, telemetry-style usage).
    /// - `required: true` — invoker-missing OR invoker-error escalates
    ///   to `Block { reason: "required plugin <id> unavailable" }`
    ///   so the operator's safety contract holds.
    ///
    /// Doctor surfaces required-plugin-with-no-invoker as a red
    /// policy gap; the `bootstrap_plugin_invoker` slim-build path
    /// must refuse to boot if any required hook is unresolvable.
    Plugin {
        plugin_id: String,
        /// Operator-set safety guarantee. `false` (default) preserves
        /// the pre-2026-05-22 telemetry-style fail-open behaviour;
        /// `true` flips to fail-closed for safety hooks.
        #[serde(default)]
        required: bool,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_allow_hook() {
        let toml_src = r#"
            name = "audit"
            stage = "pre_provider_call"
            [action]
            kind = "allow"
        "#;
        let h: HookDef = toml::from_str(toml_src).unwrap();
        assert_eq!(h.name, "audit");
        assert_eq!(h.stage, HookStage::PreProviderCall);
        assert!(h.is_enabled(), "enabled defaults to true");
        assert!(h.matcher.is_none());
        assert!(matches!(h.action, HookAction::Allow));
    }

    #[test]
    fn parses_replace_hook_with_matcher() {
        let toml_src = r#"
            name = "redact"
            stage = "pre_provider_call"
            enabled = true

            [matcher]
            pattern = "secret=\\S+"

            [action]
            kind = "replace"
            template = "[REDACTED]"
        "#;
        let h: HookDef = toml::from_str(toml_src).unwrap();
        assert_eq!(h.matcher.unwrap().pattern, "secret=\\S+");
        match h.action {
            HookAction::Replace { template } => assert_eq!(template, "[REDACTED]"),
            other => panic!("expected Replace, got {other:?}"),
        }
    }

    #[test]
    fn parses_block_hook() {
        let toml_src = r#"
            name = "no-shell"
            stage = "pre_provider_call"

            [action]
            kind = "block"
            reason = "shell-out attempt detected"
        "#;
        let h: HookDef = toml::from_str(toml_src).unwrap();
        match h.action {
            HookAction::Block { reason } => {
                assert_eq!(reason, "shell-out attempt detected");
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn r2_p0_3_plugin_hook_required_field_defaults_false() {
        // Legacy TOML without explicit `required = true` must still
        // parse — operators with existing plugin hooks keep their
        // telemetry-style fail-open semantics unless they opt in.
        let toml_src = r#"
            name = "audit-plugin"
            stage = "pre_provider_call"
            [action]
            kind = "plugin"
            plugin_id = "audit-logger"
        "#;
        let h: HookDef = toml::from_str(toml_src).unwrap();
        match h.action {
            HookAction::Plugin {
                plugin_id,
                required,
            } => {
                assert_eq!(plugin_id, "audit-logger");
                assert!(!required, "required defaults to false (telemetry-style)");
            }
            other => panic!("expected Plugin, got {other:?}"),
        }
    }

    #[test]
    fn r2_p0_3_plugin_hook_can_be_marked_required() {
        // Safety-hook operators opt in with required = true. Missing
        // invoker must escalate to Block, not silent Allow.
        let toml_src = r#"
            name = "safety-gate"
            stage = "pre_provider_call"
            [action]
            kind = "plugin"
            plugin_id = "policy-checker"
            required = true
        "#;
        let h: HookDef = toml::from_str(toml_src).unwrap();
        match h.action {
            HookAction::Plugin {
                plugin_id,
                required,
            } => {
                assert_eq!(plugin_id, "policy-checker");
                assert!(required, "required: true must be picked up");
            }
            other => panic!("expected Plugin, got {other:?}"),
        }
    }

    #[test]
    fn disabled_hook_round_trips() {
        let toml_src = r#"
            name = "off"
            stage = "post_provider_call"
            enabled = false
            [action]
            kind = "allow"
        "#;
        let h: HookDef = toml::from_str(toml_src).unwrap();
        assert!(!h.is_enabled());
    }
}
