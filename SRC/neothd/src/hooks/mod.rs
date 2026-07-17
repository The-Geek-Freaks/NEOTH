//! Hook engine bridge — re-exports the `neoth-plugin-sdk::hook` types and
//! provides the daemon-side registry that Phase 29 (`R-15 Hooks engine`)
//! will fill out.
//!
//! Phase 33b SP-4 — re-exports only. The runtime dispatcher
//! (`PreChannelIngress`, `PreProviderCall`, `PostProviderCall`, `PreEgress`,
//! `JobFired`, `JobDone`, `Shutdown`) lands with Phase 29's TOML loader.
//!
//! Why this exists today: without the bridge, Phase 28b (autonomy) and
//! Phase 29 (hooks) cannot compile against `crate::hooks::*` symbols. The
//! re-export plumbing is the smallest sliver that unblocks both downstream
//! phases.

pub mod block_filter;
pub mod dispatcher;
pub mod loader;
pub mod schema;
pub mod stages;

pub use block_filter::restore_blocks;
pub use dispatcher::{
    SessionOnceGuard, StageOnceResult, StageOutcome, run_stage, run_stage_with_once_guard,
};
pub use loader::{load_all, load_all_strict};
pub use stages::HookStage;

// Compiled-plugin trait surface — still available for advanced (Rust)
// plugins. The v0.1 operator surface is the TOML hooks above.
// allow(unused_imports): consumed only by in-crate tests today; the runtime
// dispatcher reaches them via fully-qualified SDK paths.
#[allow(unused_imports)]
pub use neoth_plugin_sdk::hook::{
    Hook, HookContext, HookError, HookOutput, HookResult, PipelineStage,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::permissions::{PermissionToken, ReadOnly};

    /// Sanity check: a trivial no-op hook compiles against the re-exported
    /// trait. If the SDK changes its trait surface, this fails to compile
    /// before the daemon-side loader touches anything.
    struct SmokeHook;

    impl Hook<ReadOnly> for SmokeHook {
        fn id(&self) -> &'static str {
            "smoke"
        }
        fn stage(&self) -> PipelineStage {
            PipelineStage::PrePipeline
        }
        fn run(&self, _ctx: HookContext<'_, ReadOnly>) -> HookResult {
            Ok(HookOutput::Continue)
        }
    }

    #[test]
    fn hook_trait_is_object_safe_via_re_export() {
        let _: &dyn Hook<ReadOnly> = &SmokeHook;
    }

    #[test]
    fn hook_metadata_is_accessible_via_re_export() {
        // `HookContext` carries `#[non_exhaustive]` so it cannot be built
        // outside the SDK crate. Validate the slice of the surface we
        // actually need from the daemon: id, stage, and trait-object
        // dispatch. Token minting works because `_host` is enabled.
        let hook = SmokeHook;
        assert_eq!(hook.id(), "smoke");
        assert_eq!(hook.stage(), PipelineStage::PrePipeline);
        let _token: PermissionToken<ReadOnly> = PermissionToken::mint();
        // Compile-time exercise of the error path enum (no construction here).
        let _err_variants = (
            std::any::type_name::<HookError>(),
            std::any::type_name::<HookResult>(),
            std::any::type_name::<HookOutput>(),
        );
    }
}
