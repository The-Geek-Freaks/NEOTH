//! Daemon-side hook stages — Phase 29 R-15.
//!
//! Superset of `neoth-plugin-sdk::PipelineStage`. The SDK ships the names
//! the compiled (Rust) `Hook<L>` trait knows; this enum adds NEOTH-specific
//! stages that don't make sense in the plugin SDK (cron firing, channel
//! ingress before any provider exists, daemon shutdown).
//!
//! ## omc cross-pollination (Q-6 / 2026-05-22)
//!
//! NEOTH stays on TOML (operators already write freedom.yaml + tweaks.toml
//! + hooks/*.toml — same surface). The omc `hooks.json` structural concept
//! that DID land: per-event hook lists fire in declaration order, the first
//! Block wins, Replace-actions update the body for the next hook. The
//! event-name → NEOTH-stage mapping:
//!
//! | omc JSON event       | NEOTH `HookStage`        |
//! |----------------------|---------------------------|
//! | `UserPromptSubmit`   | `PreChannelIngress`       |
//! | `PreToolUse`         | `PreProviderCall`         |
//! | `PostToolUse`        | `PostProviderCall`        |
//! | `SessionStart`       | `OnSessionStart`          |
//! | `Stop`               | `OnShutdown`              |
//!
//! What did NOT port: omc's `command` action (shell-out with timeout).
//! NEOTH routes that workload through `HookAction::Plugin { plugin_id }`
//! which dispatches to a sandboxed wasm plugin via the daemon's registered
//! `PluginInvoker`. The wasm path has stronger isolation than a forked
//! shell + the operator picks plugins via `neoth plugins list` rather
//! than splicing arbitrary commands into a YAML file an attacker who
//! tampered with `~/.neoth/hooks/` could exploit.

use serde::{Deserialize, Serialize};

/// All hook attachment points the daemon dispatches on.
///
/// Names match the spec verbatim — operators write `stage = "pre_provider_call"`
/// in TOML and the serde derives convert.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookStage {
    /// Before channel-sanitizer + WAL ingress frame. Runs FIRST in the
    /// pipeline — the only stage that sees the raw operator text.
    PreChannelIngress,
    /// After ingress/sanitize, before the provider HTTP request is built.
    /// Equivalent to the SDK's `PrePipeline`.
    PrePipeline,
    /// Right before `provider.complete()`. Last chance to mutate the
    /// outbound payload.
    ///
    /// Maps to Claude Code's `PreToolUse` event (omc cross-pollination Q-6).
    /// A `Block` outcome here (**exit-2 equivalent**) aborts the tool call
    /// before it reaches the provider — `enforce_preflight` in `cli/chat.rs`
    /// bails the turn when `run_hook_stage` returns `HookOutcome::Blocked`.
    PreProviderCall,
    /// Immediately after `provider.complete()` returns. Sees the reply
    /// text; can replace, block, or pass through.
    PostProviderCall,
    /// Final filter before the channel adapter sends the reply outbound.
    /// Used for per-messenger formatting rules (Phase 18 R-10).
    PreEgress,
    /// Cron scheduler dispatched a job. Hook runs before `runner::run_job`
    /// fires the prompt.
    JobFired,
    /// Cron job completed (success or failure). Hook sees the outcome.
    JobDone,
    /// Daemon boot — fires after WAL writer + indexer are up and the
    /// daemon is ready to accept channel traffic. Maps to omc's
    /// `SessionStart`. Operators wire here for "load X cache",
    /// "send a daemon-up notification to Slack", "warm the local Qwen
    /// model with a no-op forward pass".
    OnSessionStart,
    /// Daemon received a shutdown signal and is draining. Last chance to
    /// flush operator-side state.
    OnShutdown,
}

impl HookStage {
    pub fn as_str(self) -> &'static str {
        match self {
            HookStage::PreChannelIngress => "pre_channel_ingress",
            HookStage::PrePipeline => "pre_pipeline",
            HookStage::PreProviderCall => "pre_provider_call",
            HookStage::PostProviderCall => "post_provider_call",
            HookStage::PreEgress => "pre_egress",
            HookStage::JobFired => "job_fired",
            HookStage::JobDone => "job_done",
            HookStage::OnSessionStart => "on_session_start",
            HookStage::OnShutdown => "on_shutdown",
        }
    }

    /// Q-6: omc JSON event name this stage maps to, or `None` when the
    /// stage is NEOTH-specific (no omc equivalent). Used by future
    /// import tooling that ports an operator's `hooks.json` from a
    /// Claude-Code-style install over to `~/.neoth/hooks/*.toml`.
    pub fn omc_event(self) -> Option<&'static str> {
        match self {
            HookStage::PreChannelIngress => Some("UserPromptSubmit"),
            HookStage::PreProviderCall => Some("PreToolUse"),
            HookStage::PostProviderCall => Some("PostToolUse"),
            HookStage::OnSessionStart => Some("SessionStart"),
            HookStage::OnShutdown => Some("Stop"),
            // NEOTH-specific stages with no omc analogue.
            HookStage::PrePipeline
            | HookStage::PreEgress
            | HookStage::JobFired
            | HookStage::JobDone => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snake_case_roundtrip() {
        for stage in [
            HookStage::PreChannelIngress,
            HookStage::PrePipeline,
            HookStage::PreProviderCall,
            HookStage::PostProviderCall,
            HookStage::PreEgress,
            HookStage::JobFired,
            HookStage::JobDone,
            HookStage::OnSessionStart,
            HookStage::OnShutdown,
        ] {
            let s = serde_json::to_value(stage).unwrap();
            let back: HookStage = serde_json::from_value(s).unwrap();
            assert_eq!(stage, back, "roundtrip failed for {stage:?}");
            // as_str matches the serde wire form.
            assert_eq!(
                stage.as_str(),
                serde_json::to_string(&stage).unwrap().trim_matches('"')
            );
        }
    }

    #[test]
    fn q6_omc_event_mapping_pins_the_documented_table() {
        // Pin the omc → NEOTH mapping so a future refactor that
        // renames a stage surfaces immediately as a test failure,
        // not as a silent ports-tool regression.
        assert_eq!(
            HookStage::PreChannelIngress.omc_event(),
            Some("UserPromptSubmit")
        );
        assert_eq!(HookStage::PreProviderCall.omc_event(), Some("PreToolUse"));
        assert_eq!(HookStage::PostProviderCall.omc_event(), Some("PostToolUse"));
        assert_eq!(HookStage::OnSessionStart.omc_event(), Some("SessionStart"));
        assert_eq!(HookStage::OnShutdown.omc_event(), Some("Stop"));
    }

    #[test]
    fn q6_neoth_specific_stages_have_no_omc_event() {
        // PrePipeline / PreEgress / JobFired / JobDone exist for
        // NEOTH-specific surfaces (intermediate dispatch / per-
        // messenger formatting / cron) that omc doesn't have.
        // Return None so ports tooling skips them rather than
        // mapping to a wrong event name.
        assert_eq!(HookStage::PrePipeline.omc_event(), None);
        assert_eq!(HookStage::PreEgress.omc_event(), None);
        assert_eq!(HookStage::JobFired.omc_event(), None);
        assert_eq!(HookStage::JobDone.omc_event(), None);
    }

    #[test]
    fn on_session_start_parses_from_toml() {
        // The new stage must be reachable from operator-written TOML
        // exactly like the others — pin the round-trip path.
        let v: serde_json::Value = serde_json::from_str("\"on_session_start\"").unwrap();
        let stage: HookStage = serde_json::from_value(v).unwrap();
        assert_eq!(stage, HookStage::OnSessionStart);
    }
}
