//! Typed, bounded metadata for one authorized MCP tool use.
//!
//! The boundary deliberately carries a JSON summary instead of the raw
//! argument tree, so a future CRG consumer cannot receive an unbounded model
//! body by accident.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde_json::Value;

pub const MAX_PRE_TOOL_USE_ARGUMENT_SUMMARY_BYTES: usize = 4 * 1024;
pub const MAX_PRE_TOOL_USE_ENRICHMENT_BYTES: usize = 2 * 1024;
pub const MAX_PRE_TOOL_USE_IDENTIFIER_BYTES: usize = 256;

static NEXT_PRE_TOOL_USE_CALL_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PreToolUseCallId(u64);

impl PreToolUseCallId {
    fn allocate() -> Self {
        Self(NEXT_PRE_TOOL_USE_CALL_ID.fetch_add(1, Ordering::Relaxed))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreToolUseOrigin {
    ProviderEmittedMcp,
    DirectCliMcp,
    /// An operator-selected `neoth fs read` admission.  This is deliberately
    /// separate from both MCP variants: it neither came from a provider nor
    /// carries an MCP server/tool descriptor.
    DirectCliOsFileRead,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreToolUseArguments {
    summary: String,
    truncated: bool,
}

impl PreToolUseArguments {
    pub fn from_json(arguments: &Value) -> Result<Self, PreToolUseContextError> {
        let rendered = serde_json::to_string(arguments)
            .map_err(|error| PreToolUseContextError::ArgumentEncoding(error.to_string()))?;
        if rendered.len() <= MAX_PRE_TOOL_USE_ARGUMENT_SUMMARY_BYTES {
            return Ok(Self {
                summary: rendered,
                truncated: false,
            });
        }
        let mut end = MAX_PRE_TOOL_USE_ARGUMENT_SUMMARY_BYTES;
        while !rendered.is_char_boundary(end) {
            end -= 1;
        }
        Ok(Self {
            summary: format!("{}…", &rendered[..end]),
            truncated: true,
        })
    }

    pub fn summary(&self) -> &str {
        &self.summary
    }
    pub fn was_truncated(&self) -> bool {
        self.truncated
    }
}

/// Bounded data-only enrichment returned through the ordinary MCP tool-result
/// path after the actual tool response. It has no authority to alter arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreToolUseEnrichment(String);

impl PreToolUseEnrichment {
    pub fn new(value: String) -> Result<Self, PreToolUseContextError> {
        if value.len() > MAX_PRE_TOOL_USE_ENRICHMENT_BYTES {
            return Err(PreToolUseContextError::EnrichmentTooLarge(value.len()));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreToolUseReplay {
    pub attempt: u32,
    pub replayed: bool,
}

impl PreToolUseReplay {
    pub const fn direct_request() -> Self {
        Self {
            attempt: 1,
            replayed: false,
        }
    }
}

/// Live cancellation state supplied by the turn owner.  Direct MCP commands
/// have no enclosing cancellable turn and therefore use `Unbound` truthfully.
#[derive(Clone, Debug)]
pub enum PreToolUseCancellation {
    Unbound,
    ChatTurn(Arc<AtomicBool>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreToolUseCancellationState {
    Unbound,
    Open,
    Cancelled,
}

impl PreToolUseCancellation {
    pub(crate) fn from_chat_turn(cancelled: Arc<AtomicBool>) -> Self {
        Self::ChatTurn(cancelled)
    }

    pub(crate) const fn unbound() -> Self {
        Self::Unbound
    }

    pub fn state(&self) -> PreToolUseCancellationState {
        match self {
            Self::Unbound => PreToolUseCancellationState::Unbound,
            Self::ChatTurn(cancelled) if cancelled.load(Ordering::Acquire) => {
                PreToolUseCancellationState::Cancelled
            }
            Self::ChatTurn(_) => PreToolUseCancellationState::Open,
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.state() == PreToolUseCancellationState::Cancelled
    }
}

/// Root and cwd are canonical before a hook sees them. `deadline` is bounded
/// by the same default used for a normal MCP request; a W41 effect lease may
/// only shorten the concrete call later.
#[derive(Clone, Debug)]
pub struct PreToolUseContext {
    call_id: PreToolUseCallId,
    origin: PreToolUseOrigin,
    server: String,
    tool: String,
    arguments: PreToolUseArguments,
    canonical_root: PathBuf,
    canonical_cwd: PathBuf,
    deadline: Instant,
    cancellation: PreToolUseCancellation,
    replay: PreToolUseReplay,
}

impl PreToolUseContext {
    #[allow(clippy::too_many_arguments)]
    pub fn admitted(
        origin: PreToolUseOrigin,
        server: &str,
        tool: &str,
        arguments: &Value,
        root: &Path,
        cwd: &Path,
        timeout: Duration,
        cancellation: PreToolUseCancellation,
        replay: PreToolUseReplay,
    ) -> Result<Self, PreToolUseContextError> {
        if cancellation.is_cancelled() {
            return Err(PreToolUseContextError::Cancelled);
        }
        let deadline = Instant::now() + timeout;
        if Instant::now() >= deadline {
            return Err(PreToolUseContextError::DeadlineElapsed);
        }
        Ok(Self {
            call_id: PreToolUseCallId::allocate(),
            origin,
            server: bounded_identifier("server", server)?,
            tool: bounded_identifier("tool", tool)?,
            arguments: PreToolUseArguments::from_json(arguments)?,
            canonical_root: canonicalize(root, "root")?,
            canonical_cwd: canonicalize(cwd, "cwd")?,
            deadline,
            cancellation,
            replay,
        })
    }

    pub fn call_id(&self) -> PreToolUseCallId {
        self.call_id
    }
    pub fn origin(&self) -> PreToolUseOrigin {
        self.origin
    }
    pub fn server(&self) -> &str {
        &self.server
    }
    pub fn tool(&self) -> &str {
        &self.tool
    }
    pub fn arguments(&self) -> &PreToolUseArguments {
        &self.arguments
    }
    pub fn canonical_root(&self) -> &Path {
        &self.canonical_root
    }
    pub fn canonical_cwd(&self) -> &Path {
        &self.canonical_cwd
    }
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
    pub fn cancellation_state(&self) -> PreToolUseCancellationState {
        self.cancellation.state()
    }
    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }
    pub fn deadline_elapsed(&self) -> bool {
        Instant::now() >= self.deadline
    }
    pub fn replay(&self) -> PreToolUseReplay {
        self.replay
    }
}

fn canonicalize(path: &Path, label: &'static str) -> Result<PathBuf, PreToolUseContextError> {
    path.canonicalize()
        .map_err(|error| PreToolUseContextError::CanonicalPath {
            label,
            reason: error.to_string(),
        })
}

fn bounded_identifier(label: &'static str, value: &str) -> Result<String, PreToolUseContextError> {
    if value.is_empty() || value.len() > MAX_PRE_TOOL_USE_IDENTIFIER_BYTES {
        return Err(PreToolUseContextError::IdentifierOutOfBounds {
            label,
            bytes: value.len(),
        });
    }
    Ok(value.to_owned())
}

#[derive(Debug, thiserror::Error)]
pub enum PreToolUseContextError {
    #[error("PreToolUse {label} path cannot be canonicalized: {reason}")]
    CanonicalPath { label: &'static str, reason: String },
    #[error("PreToolUse arguments cannot be encoded: {0}")]
    ArgumentEncoding(String),
    #[error(
        "PreToolUse {label} identifier is outside 1..={MAX_PRE_TOOL_USE_IDENTIFIER_BYTES} bytes: {bytes}"
    )]
    IdentifierOutOfBounds { label: &'static str, bytes: usize },
    #[error(
        "PreToolUse enrichment exceeds the {MAX_PRE_TOOL_USE_ENRICHMENT_BYTES}-byte bound: {0}"
    )]
    EnrichmentTooLarge(usize),
    #[error("PreToolUse deadline elapsed before the hook completed")]
    DeadlineElapsed,
    #[error("PreToolUse was cancelled before the external call")]
    Cancelled,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_arguments_are_summarized_before_typed_hook_delivery() {
        let arguments =
            serde_json::json!({"body": "x".repeat(MAX_PRE_TOOL_USE_ARGUMENT_SUMMARY_BYTES * 2)});
        let summary = PreToolUseArguments::from_json(&arguments).expect("serializable JSON");
        assert!(summary.was_truncated());
        assert!(summary.summary().len() <= MAX_PRE_TOOL_USE_ARGUMENT_SUMMARY_BYTES + 3);
    }

    #[test]
    fn cancelled_turn_is_rejected_before_context_delivery() {
        let cancelled = Arc::new(AtomicBool::new(true));
        let root = tempfile::tempdir().expect("canonical root");
        let error = PreToolUseContext::admitted(
            PreToolUseOrigin::ProviderEmittedMcp,
            "server",
            "tool",
            &serde_json::json!({}),
            root.path(),
            root.path(),
            Duration::from_secs(1),
            PreToolUseCancellation::from_chat_turn(cancelled),
            PreToolUseReplay::direct_request(),
        )
        .expect_err("closed turn cannot reach an external tool");
        assert!(matches!(error, PreToolUseContextError::Cancelled));
    }

    #[test]
    fn zero_deadline_is_rejected_before_context_delivery() {
        let root = tempfile::tempdir().expect("canonical root");
        let error = PreToolUseContext::admitted(
            PreToolUseOrigin::DirectCliMcp,
            "server",
            "tool",
            &serde_json::json!({}),
            root.path(),
            root.path(),
            Duration::ZERO,
            PreToolUseCancellation::unbound(),
            PreToolUseReplay::direct_request(),
        )
        .expect_err("zero deadline cannot reach an external tool");
        assert!(matches!(error, PreToolUseContextError::DeadlineElapsed));
    }
}
