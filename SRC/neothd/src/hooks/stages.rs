//! Daemon-side hook stages — Phase 29 R-15.
//!
//! Superset of `neoth-plugin-sdk::PipelineStage`. The SDK ships the names
//! the compiled (Rust) `Hook<L>` trait knows; this enum adds NEOTH-specific
//! stages that don't make sense in the plugin SDK (cron firing, channel
//! ingress before any provider exists, daemon shutdown).
//!
//! Mapping to the omc JSON hook events for cross-pollination:
//!
//! | omc JSON event       | NEOTH `HookStage`            |
//! |----------------------|-------------------------------|
//! | `UserPromptSubmit`   | `PreChannelIngress`           |
//! | `PreToolUse`         | `PreProviderCall`             |
//! | `PostToolUse`        | `PostProviderCall`            |
//! | `SessionStart`       | `OnSessionStart` (Phase 30+)  |
//! | `Stop`               | `OnShutdown`                  |

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
            HookStage::OnShutdown => "on_shutdown",
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
}
