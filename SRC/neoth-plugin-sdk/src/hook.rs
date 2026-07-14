//! Hook trait and supporting types — what a plugin author actually implements.

use serde::{Deserialize, Serialize};

use crate::permission::PermissionToken;

/// Pipeline stages a hook may attach to. Each stage corresponds to a point
/// in the daemon's request lifecycle where plugin code is invoked. The
/// concrete WAL event-type assignments for hook entry/exit will be allocated
/// in SPEC_wal_lifecycle.md alongside the lifecycle event range (currently
/// provisional, see `cli/serve.rs::EVENT_TYPE_BOOT`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelineStage {
    /// Before the daemon dispatches a user-originated message to providers.
    PrePipeline,
    /// Before a single provider HTTP request leaves the daemon.
    PreProviderCall,
    /// After a provider response arrives, before the user sees it.
    PostProviderCall,
    /// Final filter on the outbound channel adapter (Telegram/Slack/etc).
    PreEgress,
    /// Nightly batch consolidation (Pineal scheduler).
    DefaultMode,
}

/// Read-only context provided to a hook by native Rust integration code.
///
/// The integration populates every field before calling `Hook::run`. Plugins
/// read the fields directly; mutation is not possible (the type is
/// `Copy`-friendly in practice — `session_id` and `node_id` are fixed-size
/// arrays).
///
/// **Field encoding**
/// - `session_id`, `node_id`: raw 16-byte UUID v7 in big-endian byte order
///   (matches the wire encoding used by the WAL `EventHeaderV2`).
/// - `message`: bytes of the inbound payload. For text-channel events this is
///   UTF-8; for binary channels (future) it may be opaque. Plugins should
///   validate before interpreting.
/// - `permission`: SDK-side marker at the exact level `L` the hook declared.
///   Rust integration code can require a fresh `FreedomGrant` for typed
///   upgrades. Neither zero-sized type crosses the WASM ABI: the production
///   host stores a separate `HostcallPermission` in `PluginStoreState` and
///   checks it independently on every hostcall.
#[derive(Debug)]
#[non_exhaustive]
pub struct HookContext<'a, L: crate::permission::PermissionLevel> {
    /// UUID v7 of the active session (16 bytes, raw).
    pub session_id: [u8; 16],
    /// UUID v7 of this node (16 bytes, raw). Multi-node deployments use this
    /// to attribute events to their originating daemon.
    pub node_id: [u8; 16],
    /// Pipeline stage this hook was invoked for.
    pub stage: PipelineStage,
    /// Inbound message payload as borrowed bytes.
    pub message: &'a [u8],
    /// Zero-sized API marker at exactly the level `L` the hook declared.
    pub permission: PermissionToken<L>,
}

/// What a hook returns after it runs.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HookOutput {
    /// No modification; allow the pipeline to continue.
    Continue,
    /// Pipeline continues with a replaced message body.
    Replace {
        /// Replacement payload bytes (UTF-8 expected for text channels).
        bytes: Vec<u8>,
    },
    /// Stop the pipeline. Used by refusal hooks. `reason` is operator-visible.
    Stop {
        /// Operator-visible reason text.
        reason: String,
    },
    /// Stop the pipeline silently. No user-visible response. Audit only.
    Drop,
}

/// Convenience alias.
pub type HookResult = Result<HookOutput, HookError>;

/// Errors a hook can return.
#[derive(thiserror::Error, Debug)]
pub enum HookError {
    /// Hook needs a higher permission level than its token carries.
    #[error("permission denied: {0}")]
    PermissionDenied(#[from] crate::permission::UnauthorizedLevel),
    /// Hook implementation bug or unexpected state.
    #[error("hook internal error: {0}")]
    Internal(String),
}

/// The trait every plugin author implements.
///
/// Implementations should be cheap to clone (no heap state) since an
/// integration may instantiate one per request.
pub trait Hook<L: crate::permission::PermissionLevel>: Send + Sync {
    /// Stable identifier for this hook. Used in WAL audit events.
    fn id(&self) -> &'static str;

    /// Pipeline stage this hook handles.
    fn stage(&self) -> PipelineStage;

    /// Run the hook. Borrows context; returns an output or error.
    fn run(&self, ctx: HookContext<'_, L>) -> HookResult;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::permission::ReadOnly;

    struct NoopHook;

    impl Hook<ReadOnly> for NoopHook {
        fn id(&self) -> &'static str {
            "noop"
        }
        fn stage(&self) -> PipelineStage {
            PipelineStage::PrePipeline
        }
        fn run(&self, _ctx: HookContext<'_, ReadOnly>) -> HookResult {
            Ok(HookOutput::Continue)
        }
    }

    #[test]
    fn noop_hook_compiles_and_runs() {
        // With default features, plugin tests can construct a Hook but the
        // host-integration token constructor is absent. This verifies the
        // public trait shape, not a runtime authorization boundary.
        let h = NoopHook;
        assert_eq!(h.id(), "noop");
        assert_eq!(h.stage(), PipelineStage::PrePipeline);
    }

    #[test]
    fn hook_output_serde_roundtrip() {
        let cases = vec![
            HookOutput::Continue,
            HookOutput::Replace {
                bytes: b"replacement".to_vec(),
            },
            HookOutput::Stop {
                reason: "policy".into(),
            },
            HookOutput::Drop,
        ];
        for case in cases {
            let json = serde_json::to_string(&case).unwrap();
            let back: HookOutput = serde_json::from_str(&json).unwrap();
            assert_eq!(format!("{case:?}"), format!("{back:?}"));
        }
    }
}
