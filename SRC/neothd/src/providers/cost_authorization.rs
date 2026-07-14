//! B22 — bind `PaidProviderCall` to the request that actually reaches a provider.
//!
//! A chat preflight cannot know how many paid rounds `/research`, an MCP loop,
//! council recursion, or a fallback decorator will execute. This module puts
//! the cost gate at each actual provider leaf instead. Every real `complete` /
//! `stream` invocation is authorized from the exact final system, prompt,
//! provider, model and streaming mode immediately before the inner call runs.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use anyhow::Result;
use async_trait::async_trait;
use futures_util::StreamExt;
use sha2::{Digest, Sha256};

use super::{
    ChunkStream, Completion, Provider, ProviderDispatchPermit, ProviderRequestControls, Request,
};
#[cfg(test)]
use crate::permissions::AutonomyLevel;
use crate::permissions::gate::ChannelAsker;
use crate::permissions::{Action, AutonomyPolicySnapshot, ConfirmStrategy, Gate};
use crate::wal::writer::WalWriterHandle;

static AUTHORIZATION_ID_NONCE: AtomicU64 = AtomicU64::new(0);

fn hash_binding_field(hasher: &mut Sha256, name: &str, value: &[u8]) {
    hasher.update((name.len() as u64).to_be_bytes());
    hasher.update(name.as_bytes());
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn finish_sha256(hasher: Sha256) -> String {
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Cryptographically bind every request/control field that can alter the
/// concrete provider invocation or its reviewed cost ceiling. Length-prefixing
/// each field prevents concatenation ambiguity and keeps the digest stable.
fn request_binding_sha256(
    provider: &str,
    model: &str,
    req: &Request,
    call_scope: &str,
    streaming: bool,
    output_token_ceiling: Option<u32>,
) -> String {
    let mut hasher = Sha256::new();
    hash_binding_field(&mut hasher, "schema", b"neoth.provider-call-binding.v1");
    hash_binding_field(&mut hasher, "call_scope", call_scope.as_bytes());
    hash_binding_field(&mut hasher, "provider", provider.as_bytes());
    hash_binding_field(&mut hasher, "model", model.as_bytes());
    hash_binding_field(&mut hasher, "streaming", &[u8::from(streaming)]);
    hash_binding_field(
        &mut hasher,
        "system_present",
        &[u8::from(req.system.is_some())],
    );
    hash_binding_field(
        &mut hasher,
        "system",
        req.system.as_deref().unwrap_or_default().as_bytes(),
    );
    hash_binding_field(&mut hasher, "prompt", req.prompt.as_bytes());
    hash_binding_field(
        &mut hasher,
        "temperature",
        &req.temperature
            .map(f32::to_bits)
            .unwrap_or_default()
            .to_be_bytes(),
    );
    hash_binding_field(
        &mut hasher,
        "temperature_present",
        &[u8::from(req.temperature.is_some())],
    );
    hash_binding_field(
        &mut hasher,
        "top_p",
        &req.top_p
            .map(f32::to_bits)
            .unwrap_or_default()
            .to_be_bytes(),
    );
    hash_binding_field(
        &mut hasher,
        "top_p_present",
        &[u8::from(req.top_p.is_some())],
    );
    hash_binding_field(
        &mut hasher,
        "sampling_seed",
        &req.sampling_seed.unwrap_or_default().to_be_bytes(),
    );
    hash_binding_field(
        &mut hasher,
        "sampling_seed_present",
        &[u8::from(req.sampling_seed.is_some())],
    );
    hash_binding_field(
        &mut hasher,
        "stop_sequences_len",
        &(req.stop_sequences.len() as u64).to_be_bytes(),
    );
    for stop_sequence in &req.stop_sequences {
        hash_binding_field(&mut hasher, "stop_sequence", stop_sequence.as_bytes());
    }
    hash_binding_field(
        &mut hasher,
        "thinking_budget",
        &req.thinking_budget.unwrap_or_default().to_be_bytes(),
    );
    hash_binding_field(
        &mut hasher,
        "thinking_budget_present",
        &[u8::from(req.thinking_budget.is_some())],
    );
    hash_binding_field(
        &mut hasher,
        "output_token_ceiling",
        &output_token_ceiling.unwrap_or_default().to_be_bytes(),
    );
    hash_binding_field(
        &mut hasher,
        "output_token_ceiling_present",
        &[u8::from(output_token_ceiling.is_some())],
    );
    finish_sha256(hasher)
}

fn new_authorization_id(request_binding_sha256: &str) -> String {
    let mut hasher = Sha256::new();
    hash_binding_field(
        &mut hasher,
        "schema",
        b"neoth.provider-call-authorization-id.v1",
    );
    hash_binding_field(
        &mut hasher,
        "request_binding_sha256",
        request_binding_sha256.as_bytes(),
    );
    hash_binding_field(
        &mut hasher,
        "ts_ns",
        &crate::time::now_unix_ns().to_be_bytes(),
    );
    hash_binding_field(&mut hasher, "process_id", &std::process::id().to_be_bytes());
    hash_binding_field(
        &mut hasher,
        "nonce",
        &AUTHORIZATION_ID_NONCE
            .fetch_add(1, Ordering::Relaxed)
            .to_be_bytes(),
    );
    finish_sha256(hasher)
}

/// Confirmation surface for the caller that owns this provider round.
#[derive(Clone)]
pub enum CostConfirm {
    /// Interactive CLI: TTY when available, otherwise fail closed.
    Interactive,
    /// Daemon/cron path without an operator callback.
    FailClosed,
    /// Channel path with the live approve/deny callback.
    Channel(Arc<dyn ChannelAsker>),
}

#[derive(Clone)]
enum AutonomySource {
    Fixed(AutonomyPolicySnapshot),
    Reload(Arc<crate::config::reload::ReloadController>),
}

impl AutonomySource {
    fn current(&self) -> AutonomyPolicySnapshot {
        match self {
            Self::Fixed(policy) => policy.clone(),
            Self::Reload(controller) => controller.autonomy_policy(),
        }
    }
}

/// Type-sealed production input for fixed provider-call policy. Production
/// code can pass only an immutable snapshot; the level-only compatibility impl
/// exists under cfg(test), where no Custom policy can be lost accidentally.
pub trait ProviderPolicyInput {
    fn into_provider_policy(self) -> AutonomyPolicySnapshot;
}

impl ProviderPolicyInput for AutonomyPolicySnapshot {
    fn into_provider_policy(self) -> AutonomyPolicySnapshot {
        self
    }
}

#[cfg(test)]
impl ProviderPolicyInput for AutonomyLevel {
    fn into_provider_policy(self) -> AutonomyPolicySnapshot {
        AutonomyPolicySnapshot::test_level(self)
    }
}

/// Typed marker for failures that happen before the network boundary. Provider
/// decorators use it to distinguish an authorization failure (which must stay
/// fail-closed) from an ordinary child-provider failure they may recover from.
#[derive(Debug, thiserror::Error)]
#[error("provider call authorization failed: {0}")]
pub struct ProviderAuthorizationError(String);

/// Content-free domain metadata carried into the provider lifecycle frames.
/// The fixed field set is intentional: callers cannot smuggle prompts,
/// responses, arbitrary JSON or credentials into the audit trail. Dynamic
/// request/task identifiers are hashed before serialization.
#[derive(Clone, Debug, Default)]
pub struct ProviderCallAuditContext {
    pub source: Option<&'static str>,
    pub call_type: Option<&'static str>,
    pub request_id: Option<String>,
    pub task_id: Option<String>,
    pub operator_id: Option<String>,
    pub session_id: Option<String>,
    pub target: Option<String>,
    pub configured_provider_kind: Option<String>,
    pub model_source: Option<&'static str>,
    pub cost_estimate_model: Option<String>,
    pub prompt_bundle_hash: Option<String>,
    pub prompt_token_estimate: Option<u32>,
    pub cluster_delegated: bool,
    pub incognito: bool,
}

fn identifier_sha256(value: &str) -> String {
    finish_sha256(Sha256::new_with_prefix(value.as_bytes()))
}

fn add_audit_context(
    payload: &mut serde_json::Map<String, serde_json::Value>,
    context: &ProviderCallAuditContext,
) {
    if let Some(source) = context.source {
        payload.insert("source".into(), source.into());
    }
    if let Some(call_type) = context.call_type {
        payload.insert("call_type".into(), call_type.into());
    }
    if let Some(request_id) = context.request_id.as_deref() {
        payload.insert(
            "request_id_sha256".into(),
            identifier_sha256(request_id).into(),
        );
    }
    if let Some(task_id) = context.task_id.as_deref() {
        payload.insert("task_id_sha256".into(), identifier_sha256(task_id).into());
    }
    if let Some(operator_id) = context.operator_id.as_deref() {
        payload.insert("operator_id".into(), operator_id.into());
    }
    if let Some(session_id) = context.session_id.as_deref() {
        payload.insert("session_id".into(), session_id.into());
    }
    if let Some(target) = context.target.as_deref() {
        payload.insert("target".into(), target.into());
    }
    if let Some(provider_kind) = context.configured_provider_kind.as_deref() {
        payload.insert("provider_kind".into(), provider_kind.into());
    }
    if let Some(model_source) = context.model_source {
        payload.insert("model_source".into(), model_source.into());
    }
    if let Some(cost_estimate_model) = context.cost_estimate_model.as_deref() {
        payload.insert("cost_estimate_model".into(), cost_estimate_model.into());
    }
    if let Some(prompt_bundle_hash) = context.prompt_bundle_hash.as_deref() {
        payload.insert("prompt_bundle_hash".into(), prompt_bundle_hash.into());
    }
    if let Some(prompt_token_estimate) = context.prompt_token_estimate {
        payload.insert("prompt_token_estimate".into(), prompt_token_estimate.into());
    }
    if context.cluster_delegated {
        payload.insert("cluster_delegated".into(), true.into());
    }
    if context.incognito {
        payload.insert("incognito".into(), true.into());
    }
}

enum ProviderCallAuditSink {
    Wal(WalWriterHandle),
    /// Writerless provider orchestration is available only to unit tests that
    /// deliberately bypass the lifecycle-WAL boundary.
    #[cfg(test)]
    Disabled,
}

struct ProviderCallAuditTicket {
    audit_sink: ProviderCallAuditSink,
    invocation_id: String,
    request_binding_sha256: String,
    provider: &'static str,
    wire_model: String,
    call_scope: &'static str,
    streaming: bool,
    local: bool,
    system_hash_xxh3: u64,
    prompt_hash_xxh3: u64,
    system_bytes: usize,
    prompt_bytes: usize,
    context: ProviderCallAuditContext,
    started: Instant,
}

impl ProviderCallAuditTicket {
    fn base_payload(&self) -> serde_json::Map<String, serde_json::Value> {
        let mut payload = serde_json::Map::from_iter([
            ("schema".into(), "neoth.provider-lifecycle.v1".into()),
            ("invocation_id".into(), self.invocation_id.clone().into()),
            (
                "request_binding_sha256".into(),
                self.request_binding_sha256.clone().into(),
            ),
            ("call_scope".into(), self.call_scope.into()),
            ("provider".into(), self.provider.into()),
            ("wire_model".into(), self.wire_model.clone().into()),
            // Compatibility for WAL consumers predating typed wire identity.
            ("model".into(), self.wire_model.clone().into()),
            ("streaming".into(), self.streaming.into()),
            ("streamed".into(), self.streaming.into()),
            ("local".into(), self.local.into()),
            ("system_hash_xxh3".into(), self.system_hash_xxh3.into()),
            ("prompt_hash_xxh3".into(), self.prompt_hash_xxh3.into()),
            ("system_bytes".into(), self.system_bytes.into()),
            ("prompt_bytes".into(), self.prompt_bytes.into()),
            ("ts_unix".into(), crate::time::now_unix_secs().into()),
        ]);
        add_audit_context(&mut payload, &self.context);
        payload
    }

    async fn append_terminal(self, terminal: ProviderCallTerminal) -> Result<()> {
        #[cfg(not(test))]
        let ProviderCallAuditSink::Wal(writer) = &self.audit_sink;
        #[cfg(test)]
        let writer = match &self.audit_sink {
            ProviderCallAuditSink::Wal(writer) => writer,
            ProviderCallAuditSink::Disabled => return Ok(()),
        };
        let mut payload = self.base_payload();
        let event_type = match terminal {
            ProviderCallTerminal::Success {
                response_hash_sha256,
                response_hash_xxh3,
                response_bytes,
                latency_ns,
                provider_latency_ns,
                input_tokens,
                output_tokens,
                cache_creation_tokens,
                cache_read_tokens,
                terminal_kind,
            } => {
                payload.insert("ok".into(), true.into());
                payload.insert("terminal_kind".into(), terminal_kind.into());
                payload.insert("response_hash_sha256".into(), response_hash_sha256.into());
                payload.insert("response_hash_xxh3".into(), response_hash_xxh3.into());
                payload.insert("response_bytes".into(), response_bytes.into());
                payload.insert("completion_bytes".into(), response_bytes.into());
                payload.insert("latency_ns".into(), latency_ns.into());
                payload.insert("latency_ms".into(), (latency_ns / 1_000_000).into());
                payload.insert("provider_latency_ns".into(), provider_latency_ns.into());
                payload.insert("input_tokens".into(), input_tokens.into());
                payload.insert("prompt_token_actual".into(), input_tokens.into());
                payload.insert("output_tokens".into(), output_tokens.into());
                payload.insert("cache_creation_tokens".into(), cache_creation_tokens.into());
                payload.insert("cache_read_tokens".into(), cache_read_tokens.into());
                crate::wal::events::EVENT_TYPE_PROVIDER_RESPONSE
            }
            ProviderCallTerminal::Failure {
                error_kind,
                latency_ns,
            } => {
                payload.insert("ok".into(), false.into());
                payload.insert("error_kind".into(), error_kind.into());
                // Stable compatibility code for existing WAL consumers. Never
                // the raw provider/transport error string.
                payload.insert("error".into(), error_kind.into());
                payload.insert("latency_ns".into(), latency_ns.into());
                crate::wal::events::EVENT_TYPE_PROVIDER_ERROR
            }
        };
        let payload = serde_json::to_vec(&payload).map_err(|error| {
            anyhow::anyhow!(ProviderAuthorizationError(format!(
                "provider terminal WAL serialization failed for `{}`: {error}",
                self.call_scope
            )))
        })?;
        let header = crate::wal::HeaderBuilder::new(event_type, &payload).build();
        writer
            .append(header, payload)
            .await
            .map(|_| ())
            .map_err(|error| {
                anyhow::anyhow!(ProviderAuthorizationError(format!(
                    "provider terminal WAL append failed for `{}`: {error}",
                    self.call_scope
                )))
            })
    }
}

enum ProviderCallTerminal {
    Success {
        response_hash_sha256: String,
        response_hash_xxh3: u64,
        response_bytes: usize,
        latency_ns: u64,
        provider_latency_ns: u64,
        input_tokens: Option<u32>,
        output_tokens: Option<u32>,
        cache_creation_tokens: Option<u32>,
        cache_read_tokens: Option<u32>,
        terminal_kind: &'static str,
    },
    Failure {
        error_kind: &'static str,
        latency_ns: u64,
    },
}

/// Cost/permission-approved leaf call. The only way to mint the raw dispatch
/// permit is to durably convert this into a lifecycle guard (0x20 first).
pub(crate) struct AuthorizedLeafCall {
    ticket: ProviderCallAuditTicket,
}

impl AuthorizedLeafCall {
    pub(crate) async fn begin_dispatch(mut self) -> Result<ProviderCallAuditGuard> {
        match &self.ticket.audit_sink {
            ProviderCallAuditSink::Wal(writer) => {
                let payload = serde_json::to_vec(&self.ticket.base_payload()).map_err(|error| {
                    anyhow::anyhow!(ProviderAuthorizationError(format!(
                        "provider intent WAL serialization failed for `{}`: {error}",
                        self.ticket.call_scope
                    )))
                })?;
                let header = crate::wal::HeaderBuilder::new(
                    crate::wal::events::EVENT_TYPE_PROVIDER_REQUEST,
                    &payload,
                )
                .build();
                writer.append(header, payload).await.map_err(|error| {
                    anyhow::anyhow!(ProviderAuthorizationError(format!(
                        "provider intent WAL append failed for `{}`; dispatch blocked: {error}",
                        self.ticket.call_scope
                    )))
                })?;
            }
            #[cfg(test)]
            ProviderCallAuditSink::Disabled => {}
        }
        self.ticket.started = Instant::now();
        Ok(ProviderCallAuditGuard {
            ticket: Some(self.ticket),
        })
    }
}

/// Owns the mandatory terminal edge. Cancellation/drop after 0x20 spawns a
/// detached, fsync-acknowledged 0x22 append so timeouts cannot orphan intent.
pub(crate) struct ProviderCallAuditGuard {
    ticket: Option<ProviderCallAuditTicket>,
}

impl ProviderCallAuditGuard {
    fn elapsed_ns(ticket: &ProviderCallAuditTicket) -> u64 {
        u64::try_from(ticket.started.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }

    async fn finish(&mut self, terminal: ProviderCallTerminal) -> Result<()> {
        let Some(ticket) = self.ticket.take() else {
            return Ok(());
        };
        // A detached task keeps the terminal append alive if the caller drops
        // the completion/stream future while the WAL fsync is in progress.
        tokio::spawn(ticket.append_terminal(terminal))
            .await
            .map_err(|error| {
                anyhow::anyhow!(ProviderAuthorizationError(format!(
                    "provider terminal WAL task failed: {error}"
                )))
            })?
    }

    pub(crate) async fn complete_success(&mut self, completion: &Completion) -> Result<()> {
        let Some(ticket) = self.ticket.as_ref() else {
            return Ok(());
        };
        let collect_babel_sample = !ticket.context.incognito;
        let terminal = ProviderCallTerminal::Success {
            response_hash_sha256: identifier_sha256(&completion.text),
            response_hash_xxh3: xxhash_rust::xxh3::xxh3_64(completion.text.as_bytes()),
            response_bytes: completion.text.len(),
            latency_ns: Self::elapsed_ns(ticket),
            provider_latency_ns: u64::try_from(completion.latency.as_nanos()).unwrap_or(u64::MAX),
            input_tokens: completion.input_tokens,
            output_tokens: completion.output_tokens,
            cache_creation_tokens: completion.cache_creation_tokens,
            cache_read_tokens: completion.cache_read_tokens,
            terminal_kind: "complete",
        };
        self.finish(terminal).await?;
        if collect_babel_sample {
            crate::analytics::babel::khist::submit_response_text(
                crate::time::now_unix_i64(),
                &completion.text,
            );
        }
        Ok(())
    }

    pub(crate) async fn failure(&mut self, error_kind: &'static str) -> Result<()> {
        let Some(ticket) = self.ticket.as_ref() else {
            return Ok(());
        };
        let terminal = ProviderCallTerminal::Failure {
            error_kind,
            latency_ns: Self::elapsed_ns(ticket),
        };
        self.finish(terminal).await
    }

    pub(crate) fn wrap_stream(self, mut inner: ChunkStream) -> ChunkStream {
        Box::pin(async_stream::try_stream! {
            let mut audit = self;
            let collect_babel_sample = audit
                .ticket
                .as_ref()
                .is_some_and(|ticket| !ticket.context.incognito);
            let mut babel_response = String::new();
            let mut response_hasher = Sha256::new();
            let mut response_bytes = 0usize;
            let mut response_xxh3 = xxhash_rust::xxh3::Xxh3::new();
            let mut input_tokens = None;
            let mut output_tokens = None;
            let mut cache_creation_tokens = None;
            let mut cache_read_tokens = None;

            while let Some(item) = inner.next().await {
                match item {
                    Ok(chunk) => {
                        if collect_babel_sample {
                            babel_response.push_str(&chunk.delta);
                        }
                        response_hasher.update(chunk.delta.as_bytes());
                        response_xxh3.update(chunk.delta.as_bytes());
                        response_bytes = response_bytes.saturating_add(chunk.delta.len());
                        input_tokens = chunk.input_tokens.or(input_tokens);
                        output_tokens = chunk.output_tokens.or(output_tokens);
                        cache_creation_tokens = chunk.cache_creation_tokens.or(cache_creation_tokens);
                        cache_read_tokens = chunk.cache_read_tokens.or(cache_read_tokens);
                        if chunk.done {
                            let ticket = audit.ticket.as_ref().expect("unsettled provider stream audit");
                            let terminal = ProviderCallTerminal::Success {
                                response_hash_sha256: finish_sha256(response_hasher),
                                response_hash_xxh3: response_xxh3.digest(),
                                response_bytes,
                                latency_ns: Self::elapsed_ns(ticket),
                                provider_latency_ns: 0,
                                input_tokens,
                                output_tokens,
                                cache_creation_tokens,
                                cache_read_tokens,
                                terminal_kind: "stream_done",
                            };
                            audit.finish(terminal).await?;
                            if collect_babel_sample {
                                crate::analytics::babel::khist::submit_response_text(
                                    crate::time::now_unix_i64(),
                                    &babel_response,
                                );
                            }
                            yield chunk;
                            return;
                        }
                        yield chunk;
                    }
                    Err(error) => {
                        if let Err(audit_error) = audit.failure("stream_error").await {
                            Err(anyhow::anyhow!(
                                "provider stream failed and terminal audit failed: {audit_error}; provider error: {error}"
                            ))?;
                        }
                        Err(error)?;
                    }
                }
            }

            let ticket = audit.ticket.as_ref().expect("unsettled provider stream audit");
            let terminal = ProviderCallTerminal::Success {
                response_hash_sha256: finish_sha256(response_hasher),
                response_hash_xxh3: response_xxh3.digest(),
                response_bytes,
                latency_ns: Self::elapsed_ns(ticket),
                provider_latency_ns: 0,
                input_tokens,
                output_tokens,
                cache_creation_tokens,
                cache_read_tokens,
                terminal_kind: "stream_eof",
            };
            audit.finish(terminal).await?;
            if collect_babel_sample {
                crate::analytics::babel::khist::submit_response_text(
                    crate::time::now_unix_i64(),
                    &babel_response,
                );
            }
        })
    }
}

impl Drop for ProviderCallAuditGuard {
    fn drop(&mut self) {
        let Some(ticket) = self.ticket.take() else {
            return;
        };
        #[cfg(test)]
        if matches!(&ticket.audit_sink, ProviderCallAuditSink::Disabled) {
            return;
        }
        let terminal = ProviderCallTerminal::Failure {
            error_kind: if ticket.streaming {
                "stream_dropped"
            } else {
                "provider_call_cancelled"
            },
            latency_ns: Self::elapsed_ns(&ticket),
        };
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                runtime.spawn(async move {
                    if let Err(error) = ticket.append_terminal(terminal).await {
                        tracing::error!(error = %error, "provider cancellation terminal audit failed");
                    }
                });
            }
            Err(error) => {
                tracing::error!(error = %error, "provider audit guard dropped outside a Tokio runtime");
            }
        }
    }
}

/// Reusable authorization context. Cloning preserves the WAL writer and the
/// channel callback, so council recursion can carry the exact same policy to
/// every leaf call.
#[derive(Clone)]
pub struct ProviderCallAuthorizer {
    autonomy: AutonomySource,
    writer: Option<WalWriterHandle>,
    confirm: CostConfirm,
    audit_context: ProviderCallAuditContext,
    #[cfg(test)]
    allow_missing_writer: bool,
    #[cfg(test)]
    allow_unproven_ceiling: bool,
}

impl ProviderCallAuthorizer {
    /// Build an interactive authorizer with its own collision-resistant WAL
    /// segment. Standalone CLI commands cannot borrow the daemon writer, but
    /// they still must durably audit the estimate and permission decision.
    pub fn interactive_one_shot(policy: impl ProviderPolicyInput) -> Result<Self> {
        let wal_dir = crate::config::FreedomConfig::default_wal_dir();
        Self::interactive_one_shot_at(policy, &wal_dir)
    }

    /// Explicit-home variant for commands such as `neoth doctor --home`.
    /// Audit state must live beside the configuration/data being diagnosed;
    /// silently writing the process-default WAL would split operator truth.
    pub fn interactive_one_shot_at(
        policy: impl ProviderPolicyInput,
        wal_dir: &Path,
    ) -> Result<Self> {
        std::fs::create_dir_all(wal_dir).map_err(|error| {
            anyhow::anyhow!(ProviderAuthorizationError(format!(
                "create provider-call WAL directory {}: {error}",
                wal_dir.display()
            )))
        })?;
        let segment = crate::wal::writer::unique_standalone_segment_path(wal_dir, "provider-call");
        let (writer, join) = crate::wal::writer::spawn(segment).map_err(|error| {
            anyhow::anyhow!(ProviderAuthorizationError(format!(
                "spawn provider-call WAL writer: {error}"
            )))
        })?;
        // Each append awaits the writer's fsync acknowledgement. Detaching the
        // task is safe: the authorizer owns the sending handle for its lifetime.
        drop(join);
        Ok(Self::interactive(
            policy.into_provider_policy(),
            Some(writer),
        ))
    }

    pub fn interactive(policy: impl ProviderPolicyInput, writer: Option<WalWriterHandle>) -> Self {
        Self {
            autonomy: AutonomySource::Fixed(policy.into_provider_policy()),
            writer,
            confirm: CostConfirm::Interactive,
            audit_context: ProviderCallAuditContext::default(),
            #[cfg(test)]
            allow_missing_writer: false,
            #[cfg(test)]
            allow_unproven_ceiling: false,
        }
    }

    pub fn fail_closed(policy: impl ProviderPolicyInput, writer: Option<WalWriterHandle>) -> Self {
        Self {
            autonomy: AutonomySource::Fixed(policy.into_provider_policy()),
            writer,
            confirm: CostConfirm::FailClosed,
            audit_context: ProviderCallAuditContext::default(),
            #[cfg(test)]
            allow_missing_writer: false,
            #[cfg(test)]
            allow_unproven_ceiling: false,
        }
    }

    pub fn channel(
        policy: impl ProviderPolicyInput,
        writer: Option<WalWriterHandle>,
        asker: Arc<dyn ChannelAsker>,
    ) -> Self {
        Self {
            autonomy: AutonomySource::Fixed(policy.into_provider_policy()),
            writer,
            confirm: CostConfirm::Channel(asker),
            audit_context: ProviderCallAuditContext::default(),
            #[cfg(test)]
            allow_missing_writer: false,
            #[cfg(test)]
            allow_unproven_ceiling: false,
        }
    }

    /// Daemon/cron authorizer whose autonomy is resolved at the instant of
    /// every leaf call. A successful `neoth reload` therefore tightens or
    /// relaxes the next call without rebuilding long-lived provider handles.
    pub fn fail_closed_reload(
        reload: Arc<crate::config::reload::ReloadController>,
        writer: Option<WalWriterHandle>,
    ) -> Self {
        Self {
            autonomy: AutonomySource::Reload(reload),
            writer,
            confirm: CostConfirm::FailClosed,
            audit_context: ProviderCallAuditContext::default(),
            #[cfg(test)]
            allow_missing_writer: false,
            #[cfg(test)]
            allow_unproven_ceiling: false,
        }
    }

    /// Channel authorizer with the same per-leaf reload semantics as daemon
    /// cron work, while retaining the live channel approval callback.
    pub fn channel_reload(
        reload: Arc<crate::config::reload::ReloadController>,
        writer: Option<WalWriterHandle>,
        asker: Arc<dyn ChannelAsker>,
    ) -> Self {
        Self {
            autonomy: AutonomySource::Reload(reload),
            writer,
            confirm: CostConfirm::Channel(asker),
            audit_context: ProviderCallAuditContext::default(),
            #[cfg(test)]
            allow_missing_writer: false,
            #[cfg(test)]
            allow_unproven_ceiling: false,
        }
    }

    /// Unit-test constructor for provider orchestration tests that do not need
    /// to exercise the WAL/ceiling boundary itself. It supplies the historical
    /// 4096 synthetic ceiling to legacy test doubles. Production constructors
    /// never invent that cap: `None` uses the distinct unbounded paid-call gate.
    #[cfg(test)]
    pub(crate) fn test_only(autonomy: AutonomyLevel) -> Self {
        Self {
            autonomy: AutonomySource::Fixed(AutonomyPolicySnapshot::test_level(autonomy)),
            writer: None,
            confirm: CostConfirm::FailClosed,
            audit_context: ProviderCallAuditContext::default(),
            allow_missing_writer: true,
            allow_unproven_ceiling: true,
        }
    }

    #[cfg(test)]
    pub(crate) fn test_only_reload(reload: Arc<crate::config::reload::ReloadController>) -> Self {
        Self {
            autonomy: AutonomySource::Reload(reload),
            writer: None,
            confirm: CostConfirm::FailClosed,
            audit_context: ProviderCallAuditContext::default(),
            allow_missing_writer: true,
            allow_unproven_ceiling: true,
        }
    }

    fn gate(&self) -> Gate {
        let policy = self.autonomy.current();
        match &self.confirm {
            CostConfirm::Interactive => Gate::for_policy(policy).with_confirm(Gate::auto_confirm()),
            CostConfirm::FailClosed => {
                Gate::for_policy(policy).with_confirm(ConfirmStrategy::FailClosed)
            }
            CostConfirm::Channel(asker) => Gate::for_policy(policy)
                .with_confirm(ConfirmStrategy::Channel)
                .with_channel_asker(Arc::clone(asker)),
        }
    }

    /// Attach request/task/domain metadata to every concrete leaf reached by
    /// this authorizer. Only the typed content-free fields above are accepted.
    pub fn with_audit_context(mut self, context: ProviderCallAuditContext) -> Self {
        self.audit_context = context;
        self
    }

    /// Authorize one actual provider leaf immediately before it runs. The
    /// caller has already resolved `req.model`; the payload and any finite
    /// estimate are derived from the exact system/prompt/model/streaming tuple
    /// that will be sent. Canonically local providers bypass paid-call authorization; an
    /// unknown zero-priced provider does not. A missing whole-invocation output
    /// ceiling or an unknown price row is audited truthfully and uses
    /// `UnboundedPaidProviderCall` instead of being converted into a fabricated
    /// finite EUR estimate.
    pub(crate) async fn authorize_leaf(
        &self,
        provider: &'static str,
        req: &Request,
        call_scope: &'static str,
        streaming: bool,
        output_token_ceiling: Option<u32>,
    ) -> Result<AuthorizedLeafCall> {
        let model = req
            .model
            .as_deref()
            .filter(|model| !model.trim().is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!(ProviderAuthorizationError(format!(
                    "provider `{provider}` left its final model implicit"
                )))
            })?;
        // Every production leaf, including offline inference, requires the
        // lifecycle writer. Local calls skip the paid gate, never the 0x20/21/22
        // audit contract. The only writerless path is the cfg(test) constructor.
        let audit_sink = match self.writer.clone() {
            Some(writer) => ProviderCallAuditSink::Wal(writer),
            None => {
                #[cfg(test)]
                {
                    if self.allow_missing_writer {
                        ProviderCallAuditSink::Disabled
                    } else {
                        return Err(anyhow::anyhow!(ProviderAuthorizationError(format!(
                            "{call_scope} ({provider}/{model}): no WAL writer is attached; provider dispatch is blocked"
                        ))));
                    }
                }
                #[cfg(not(test))]
                {
                    return Err(anyhow::anyhow!(ProviderAuthorizationError(format!(
                        "{call_scope} ({provider}/{model}): no WAL writer is attached; provider dispatch is blocked"
                    ))));
                }
            }
        };

        let output_token_ceiling = output_token_ceiling.filter(|ceiling| *ceiling > 0);
        #[cfg(test)]
        let output_token_ceiling = output_token_ceiling.or_else(|| {
            self.allow_unproven_ceiling
                .then_some(super::DEFAULT_CLOUD_OUTPUT_TOKEN_CEILING)
        });

        let request_binding_sha256 = request_binding_sha256(
            provider,
            model,
            req,
            call_scope,
            streaming,
            output_token_ceiling,
        );
        let invocation_id = new_authorization_id(&request_binding_sha256);

        let system_hash =
            xxhash_rust::xxh3::xxh3_64(req.system.as_deref().unwrap_or("").as_bytes());
        let prompt_hash = xxhash_rust::xxh3::xxh3_64(req.prompt.as_bytes());
        if super::is_local_provider(provider) {
            return Ok(AuthorizedLeafCall {
                ticket: ProviderCallAuditTicket {
                    audit_sink,
                    invocation_id,
                    request_binding_sha256,
                    provider,
                    wire_model: model.to_owned(),
                    call_scope,
                    streaming,
                    local: true,
                    system_hash_xxh3: system_hash,
                    prompt_hash_xxh3: prompt_hash,
                    system_bytes: req.system.as_deref().map_or(0, str::len),
                    prompt_bytes: req.prompt.len(),
                    context: self.audit_context.clone(),
                    started: Instant::now(),
                },
            });
        }
        let (payload_value, action) = match (
            output_token_ceiling,
            crate::providers::cost::lookup_price(provider, model),
        ) {
            (Some(output_token_ceiling), Some(_price)) => {
                let estimate = crate::providers::cost::predict_authorization_bound(
                    provider,
                    model,
                    req,
                    output_token_ceiling,
                );
                (
                    serde_json::json!({
                        "call_scope": call_scope,
                        "authorization_binding": "actual_leaf_request",
                        "authorization_id": &invocation_id,
                        "invocation_id": &invocation_id,
                        "request_binding_sha256": &request_binding_sha256,
                        "provider": provider,
                        "model": model,
                        "streaming": streaming,
                        "system_hash_xxh3": system_hash,
                        "prompt_hash_xxh3": prompt_hash,
                        "cost_bound_kind": "wire_token_bounded_reviewed_price_estimate",
                        "input_bound_kind": "utf8_bytes_plus_request_message_overhead",
                        "input_tokens": estimate.input_tokens,
                        "input_token_upper_bound": estimate.input_tokens,
                        "output_tokens_est": estimate.output_tokens_est,
                        "output_token_ceiling": output_token_ceiling,
                        "total_eur": estimate.total_eur,
                        "total_eur_estimate": estimate.total_eur,
                        "total_eur_upper_bound": Option::<f32>::None,
                        "ts_unix": crate::time::now_unix_secs(),
                    }),
                    Action::PaidProviderCall {
                        provider: provider.to_owned(),
                        model: model.to_owned(),
                        authorization_id: invocation_id.clone(),
                        request_binding_sha256: request_binding_sha256.clone(),
                        eur_estimate: estimate.total_eur,
                    },
                )
            }
            (Some(output_token_ceiling), None) => {
                let input_token_upper_bound =
                    crate::providers::cost::authorization_input_token_upper_bound(req, model);
                (
                    serde_json::json!({
                        "call_scope": call_scope,
                        "authorization_binding": "actual_leaf_request",
                        "authorization_id": &invocation_id,
                        "invocation_id": &invocation_id,
                        "request_binding_sha256": &request_binding_sha256,
                        "provider": provider,
                        "model": model,
                        "streaming": streaming,
                        "system_hash_xxh3": system_hash,
                        "prompt_hash_xxh3": prompt_hash,
                        "cost_bound_kind": "token_bounded_unknown_pricing",
                        "input_bound_kind": "utf8_bytes_plus_request_message_overhead",
                        "input_tokens": input_token_upper_bound,
                        "input_token_upper_bound": input_token_upper_bound,
                        "output_tokens_est": output_token_ceiling,
                        "output_token_ceiling": output_token_ceiling,
                        "total_eur_upper_bound": Option::<f32>::None,
                        "ts_unix": crate::time::now_unix_secs(),
                    }),
                    Action::UnboundedPaidProviderCall {
                        provider: provider.to_owned(),
                        model: model.to_owned(),
                        authorization_id: invocation_id.clone(),
                        request_binding_sha256: request_binding_sha256.clone(),
                    },
                )
            }
            (None, _) => {
                let input_token_upper_bound =
                    crate::providers::cost::authorization_input_token_upper_bound(req, model);
                (
                    serde_json::json!({
                        "call_scope": call_scope,
                        "authorization_binding": "actual_leaf_request",
                        "authorization_id": &invocation_id,
                        "invocation_id": &invocation_id,
                        "request_binding_sha256": &request_binding_sha256,
                        "provider": provider,
                        "model": model,
                        "streaming": streaming,
                        "system_hash_xxh3": system_hash,
                        "prompt_hash_xxh3": prompt_hash,
                        "cost_bound_kind": "unbounded_provider_invocation",
                        "input_bound_kind": "utf8_bytes_plus_request_message_overhead",
                        "input_tokens": input_token_upper_bound,
                        "input_token_upper_bound": input_token_upper_bound,
                        "output_tokens_est": Option::<u32>::None,
                        "output_token_ceiling": Option::<u32>::None,
                        "total_eur_upper_bound": Option::<f32>::None,
                        "ts_unix": crate::time::now_unix_secs(),
                    }),
                    Action::UnboundedPaidProviderCall {
                        provider: provider.to_owned(),
                        model: model.to_owned(),
                        authorization_id: invocation_id.clone(),
                        request_binding_sha256: request_binding_sha256.clone(),
                    },
                )
            }
        };
        let payload = serde_json::to_vec(&payload_value).map_err(|error| {
            anyhow::anyhow!(ProviderAuthorizationError(format!(
                "cost-estimate WAL payload serialization failed for `{call_scope}`: {error}"
            )))
        })?;
        if let Some(writer) = &self.writer {
            let header = crate::wal::HeaderBuilder::new(
                crate::wal::events::EVENT_TYPE_COST_ESTIMATE_SHOWN,
                &payload,
            )
            .build();
            writer.append(header, payload).await.map_err(|error| {
                anyhow::anyhow!(ProviderAuthorizationError(format!(
                    "cost-estimate WAL append failed for `{call_scope}`: {error}"
                )))
            })?;
        }

        let gate_result = match self.writer.as_ref() {
            Some(writer) => self.gate().check_required_audit(&action, writer).await,
            #[cfg(test)]
            None => self.gate().check(&action, None).await,
            #[cfg(not(test))]
            None => {
                return Err(anyhow::anyhow!(ProviderAuthorizationError(format!(
                    "{call_scope} ({provider}/{model}): lifecycle WAL writer disappeared before the permission gate"
                ))));
            }
        };
        gate_result.map_err(|error| {
            anyhow::anyhow!(ProviderAuthorizationError(format!(
                "{call_scope} ({provider}/{model}): {error}"
            )))
        })?;
        Ok(AuthorizedLeafCall {
            ticket: ProviderCallAuditTicket {
                audit_sink,
                invocation_id,
                request_binding_sha256,
                provider,
                wire_model: model.to_owned(),
                call_scope,
                streaming,
                local: false,
                system_hash_xxh3: system_hash,
                prompt_hash_xxh3: prompt_hash,
                system_bytes: req.system.as_deref().map_or(0, str::len),
                prompt_bytes: req.prompt.len(),
                context: self.audit_context.clone(),
                started: Instant::now(),
            },
        })
    }
}

/// Borrowing provider decorator used at the final dispatch boundary. It also
/// fills a resolved default model into helper requests (`/research`, web goal
/// extraction, etc.) so the model authorized is byte-for-byte the model sent.
pub struct CostAuthorizingProvider<'a> {
    inner: &'a dyn Provider,
    authorizer: ProviderCallAuthorizer,
    default_model: Option<String>,
    call_scope: &'static str,
}

impl<'a> CostAuthorizingProvider<'a> {
    pub fn new(
        inner: &'a dyn Provider,
        authorizer: ProviderCallAuthorizer,
        default_model: Option<String>,
        call_scope: &'static str,
    ) -> Self {
        Self {
            inner,
            authorizer,
            default_model,
            call_scope,
        }
    }

    fn bind_model(&self, req: &mut Request) {
        if req.model.is_none() {
            req.model = self
                .default_model
                .clone()
                .or_else(|| self.inner.default_model().map(str::to_owned));
        }
    }
}

#[async_trait]
impl Provider for CostAuthorizingProvider<'_> {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn request_controls(&self) -> ProviderRequestControls {
        self.inner.request_controls()
    }

    fn validate_request_controls(&self, req: &Request) -> Result<()> {
        let mut req = req.clone();
        self.bind_model(&mut req);
        self.inner.validate_request_controls(&req)
    }

    fn default_model(&self) -> Option<&str> {
        self.default_model
            .as_deref()
            .or_else(|| self.inner.default_model())
    }

    fn output_token_ceiling(&self, req: &Request) -> Option<u32> {
        self.inner.output_token_ceiling(req)
    }

    fn streams_on_wire(&self) -> bool {
        self.inner.streams_on_wire()
    }

    fn preserves_inner_response_identity(&self) -> bool {
        true
    }

    async fn complete(&self, mut req: Request) -> Result<Completion> {
        self.bind_model(&mut req);
        if req.model.is_none() {
            anyhow::bail!(
                "provider `{}` has no explicit request model or declared default",
                self.inner.name()
            );
        }
        self.inner
            .complete_authorized(req, &self.authorizer, self.call_scope)
            .await
    }

    async fn complete_authorized(
        &self,
        req: Request,
        _outer_authorizer: &ProviderCallAuthorizer,
        _outer_call_scope: &'static str,
    ) -> Result<Completion> {
        let _ = req;
        anyhow::bail!(
            "nested provider authorization boundaries are forbidden; dispatch through the canonical inner boundary"
        )
    }

    async fn complete_raw(
        &self,
        req: Request,
        _permit: &ProviderDispatchPermit,
    ) -> Result<Completion> {
        // A permit here proves the caller's outer policy already passed. The
        // stored inner policy still runs through the safe entry below.
        self.complete(req).await
    }

    async fn stream(&self, mut req: Request) -> Result<ChunkStream> {
        self.bind_model(&mut req);
        if req.model.is_none() {
            anyhow::bail!(
                "provider `{}` has no explicit request model or declared default",
                self.inner.name()
            );
        }
        self.inner
            .stream_authorized(req, &self.authorizer, self.call_scope)
            .await
    }

    async fn stream_authorized(
        &self,
        req: Request,
        _outer_authorizer: &ProviderCallAuthorizer,
        _outer_call_scope: &'static str,
    ) -> Result<ChunkStream> {
        let _ = req;
        anyhow::bail!(
            "nested provider authorization boundaries are forbidden; dispatch through the canonical inner boundary"
        )
    }

    async fn stream_raw(
        &self,
        req: Request,
        _permit: &ProviderDispatchPermit,
    ) -> Result<ChunkStream> {
        self.stream(req).await
    }
}

/// Owned, cloneable dispatch boundary for daemon tasks and helpers that cannot
/// borrow a provider for the duration of their work. All network dispatch goes
/// through [`Provider::complete_authorized`] / [`Provider::stream_authorized`],
/// so decorators can authorize their actual child hops just in time.
#[derive(Clone)]
pub struct AuthorizedProvider {
    inner: Arc<dyn Provider>,
    authorizer: ProviderCallAuthorizer,
    default_model: Option<String>,
    call_scope: &'static str,
}

impl AuthorizedProvider {
    pub fn from_arc(
        inner: Arc<dyn Provider>,
        authorizer: ProviderCallAuthorizer,
        default_model: Option<String>,
        call_scope: &'static str,
    ) -> Self {
        Self {
            inner,
            authorizer,
            default_model,
            call_scope,
        }
    }

    pub fn from_box(
        inner: Box<dyn Provider>,
        authorizer: ProviderCallAuthorizer,
        default_model: Option<String>,
        call_scope: &'static str,
    ) -> Self {
        Self::from_arc(Arc::from(inner), authorizer, default_model, call_scope)
    }

    pub fn into_arc(self) -> Arc<dyn Provider> {
        Arc::new(self)
    }

    /// Clone this long-lived provider boundary with per-request domain audit
    /// metadata. The provider and policy are shared; only the typed context is
    /// replaced for this invocation.
    pub fn with_audit_context(&self, context: ProviderCallAuditContext) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            authorizer: self.authorizer.clone().with_audit_context(context),
            default_model: self.default_model.clone(),
            call_scope: self.call_scope,
        }
    }

    fn bind_model(&self, req: &mut Request) {
        if req.model.is_none() {
            req.model = self
                .default_model
                .clone()
                .or_else(|| self.inner.default_model().map(str::to_owned));
        }
    }
}

#[async_trait]
impl Provider for AuthorizedProvider {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn request_controls(&self) -> ProviderRequestControls {
        self.inner.request_controls()
    }

    fn validate_request_controls(&self, req: &Request) -> Result<()> {
        let mut req = req.clone();
        self.bind_model(&mut req);
        self.inner.validate_request_controls(&req)
    }

    fn default_model(&self) -> Option<&str> {
        self.default_model
            .as_deref()
            .or_else(|| self.inner.default_model())
    }

    fn output_token_ceiling(&self, req: &Request) -> Option<u32> {
        self.inner.output_token_ceiling(req)
    }

    fn streams_on_wire(&self) -> bool {
        self.inner.streams_on_wire()
    }

    fn preserves_inner_response_identity(&self) -> bool {
        true
    }

    async fn complete(&self, mut req: Request) -> Result<Completion> {
        self.bind_model(&mut req);
        self.inner
            .complete_authorized(req, &self.authorizer, self.call_scope)
            .await
    }

    async fn complete_authorized(
        &self,
        req: Request,
        _outer_authorizer: &ProviderCallAuthorizer,
        _outer_call_scope: &'static str,
    ) -> Result<Completion> {
        let _ = req;
        anyhow::bail!(
            "nested provider authorization boundaries are forbidden; dispatch through the canonical inner boundary"
        )
    }

    async fn complete_raw(
        &self,
        req: Request,
        _permit: &ProviderDispatchPermit,
    ) -> Result<Completion> {
        self.complete(req).await
    }

    async fn stream(&self, mut req: Request) -> Result<ChunkStream> {
        self.bind_model(&mut req);
        self.inner
            .stream_authorized(req, &self.authorizer, self.call_scope)
            .await
    }

    async fn stream_authorized(
        &self,
        req: Request,
        _outer_authorizer: &ProviderCallAuthorizer,
        _outer_call_scope: &'static str,
    ) -> Result<ChunkStream> {
        let _ = req;
        anyhow::bail!(
            "nested provider authorization boundaries are forbidden; dispatch through the canonical inner boundary"
        )
    }

    async fn stream_raw(
        &self,
        req: Request,
        _permit: &ProviderDispatchPermit,
    ) -> Result<ChunkStream> {
        self.stream(req).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use futures_util::StreamExt;

    use super::*;
    use crate::providers::CompletionIdentity;

    #[tokio::test]
    async fn explicit_one_shot_wal_dir_keeps_audit_beside_the_selected_home() {
        let home = tempfile::tempdir().unwrap();
        let wal_dir = home.path().join("wal");
        let authorizer =
            ProviderCallAuthorizer::interactive_one_shot_at(AutonomyLevel::Full, &wal_dir).unwrap();

        authorizer
            .authorize_leaf(
                "openai_api",
                &Request {
                    model: Some("gpt-5".into()),
                    prompt: "diagnose this explicit home".into(),
                    ..Request::default()
                },
                "test.explicit_home",
                false,
                Some(16),
            )
            .await
            .unwrap();

        let segments = std::fs::read_dir(&wal_dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "wal"))
            .count();
        assert_eq!(segments, 1);
    }

    struct CountingProvider {
        name: &'static str,
        calls: AtomicUsize,
        default_model: Option<String>,
    }

    #[async_trait]
    impl Provider for CountingProvider {
        fn name(&self) -> &'static str {
            self.name
        }

        fn default_model(&self) -> Option<&str> {
            self.default_model.as_deref()
        }

        fn request_controls(&self) -> ProviderRequestControls {
            ProviderRequestControls::THINKING_BUDGET
        }

        fn output_token_ceiling(&self, req: &Request) -> Option<u32> {
            Some(
                crate::providers::DEFAULT_CLOUD_OUTPUT_TOKEN_CEILING
                    .saturating_add(req.thinking_budget.unwrap_or(0)),
            )
        }

        async fn complete(&self, req: Request) -> Result<Completion> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Completion {
                text: req.model.unwrap_or_default(),
                model: "wire-model".into(),
                latency: Duration::ZERO,
                ..Completion::default()
            })
        }
    }

    struct ModelRestrictedProvider;

    #[async_trait]
    impl Provider for ModelRestrictedProvider {
        fn name(&self) -> &'static str {
            "model_restricted"
        }

        fn request_controls(&self) -> ProviderRequestControls {
            ProviderRequestControls::SAMPLING_WITHOUT_SEED
        }

        fn validate_request_controls(&self, req: &Request) -> Result<()> {
            self.request_controls().validate(self.name(), req)?;
            let model = req.model.as_deref().unwrap_or("inner-default");
            if req
                .temperature
                .is_some_and(|temperature| temperature != 1.0)
            {
                anyhow::bail!("model `{model}` accepts only temperature 1.0");
            }
            Ok(())
        }
    }

    #[test]
    fn authorization_wrappers_preserve_inner_request_control_capabilities() {
        let borrowed_inner = CountingProvider {
            name: "claude_cli",
            calls: AtomicUsize::new(0),
            default_model: Some("claude-sonnet-4-6".into()),
        };
        let borrowed = CostAuthorizingProvider::new(
            &borrowed_inner,
            ProviderCallAuthorizer::test_only(AutonomyLevel::Full),
            None,
            "test.controls.borrowed",
        );
        assert_eq!(
            borrowed.request_controls(),
            ProviderRequestControls::THINKING_BUDGET
        );

        let owned_inner: Arc<dyn Provider> = Arc::new(CountingProvider {
            name: "claude_cli",
            calls: AtomicUsize::new(0),
            default_model: Some("claude-sonnet-4-6".into()),
        });
        let owned = AuthorizedProvider::from_arc(
            owned_inner,
            ProviderCallAuthorizer::test_only(AutonomyLevel::Full),
            None,
            "test.controls.owned",
        );
        assert_eq!(
            owned.request_controls(),
            ProviderRequestControls::THINKING_BUDGET
        );

        let restricted = ModelRestrictedProvider;
        let borrowed = CostAuthorizingProvider::new(
            &restricted,
            ProviderCallAuthorizer::test_only(AutonomyLevel::Full),
            Some("borrowed-wire-model".into()),
            "test.controls.borrowed_model",
        );
        let error = borrowed
            .validate_request_controls(&Request {
                temperature: Some(0.1),
                ..Request::default()
            })
            .expect_err("borrowed wrapper must delegate model-aware validation");
        assert!(error.to_string().contains("borrowed-wire-model"));

        let owned = AuthorizedProvider::from_arc(
            Arc::new(ModelRestrictedProvider),
            ProviderCallAuthorizer::test_only(AutonomyLevel::Full),
            Some("owned-wire-model".into()),
            "test.controls.owned_model",
        );
        let error = owned
            .validate_request_controls(&Request {
                temperature: Some(0.1),
                ..Request::default()
            })
            .expect_err("owned wrapper must delegate model-aware validation");
        assert!(error.to_string().contains("owned-wire-model"));
    }

    #[tokio::test]
    async fn custom_paid_call_override_reaches_the_leaf_gate() {
        let dir = tempfile::tempdir().unwrap();
        let segment = dir.path().join("custom-paid-call-denied.wal");
        let (writer, join) = crate::wal::writer::spawn(segment.clone()).unwrap();
        let mut custom = crate::permissions::CustomAutonomyConfig::default();
        custom.overrides.insert(
            crate::permissions::ActionKind::PaidProviderCall,
            crate::permissions::CustomDecision::Deny,
        );
        let policy = AutonomyPolicySnapshot::new(AutonomyLevel::Custom, &custom);
        let inner = CountingProvider {
            name: "openai_api",
            calls: AtomicUsize::new(0),
            default_model: Some("gpt-4o".into()),
        };
        let provider = CostAuthorizingProvider::new(
            &inner,
            ProviderCallAuthorizer::fail_closed(policy, Some(writer.clone())),
            None,
            "test.custom_policy",
        );

        let error = provider.complete(Request::default()).await.unwrap_err();
        assert!(error.to_string().contains("custom override"));
        assert_eq!(inner.calls.load(Ordering::SeqCst), 0);
        drop(provider);
        drop(writer);
        join.await.unwrap();

        let frames = wal_frames(&segment);
        assert_eq!(frames.len(), 2);
        assert_eq!(
            frames[0].0,
            crate::wal::events::EVENT_TYPE_COST_ESTIMATE_SHOWN
        );
        assert_eq!(
            frames[1].0,
            crate::wal::events::EVENT_TYPE_PERMISSION_DENIED
        );
        assert_eq!(frames[1].1["level"], "custom");
        assert_eq!(frames[1].1["decision"], "deny");
    }

    struct NativeStreamingProvider {
        calls: AtomicUsize,
    }

    struct FailingProvider {
        name: &'static str,
        calls: AtomicUsize,
    }

    struct SensitiveSuccessProvider {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl Provider for SensitiveSuccessProvider {
        fn name(&self) -> &'static str {
            "local_ouro"
        }

        fn default_model(&self) -> Option<&str> {
            Some("ouro-test")
        }

        async fn complete(&self, _req: Request) -> Result<Completion> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Completion {
                text: "raw completion body with secret-token".into(),
                latency: Duration::from_millis(2),
                input_tokens: Some(11),
                output_tokens: Some(5),
                ..Completion::default()
            })
        }
    }

    #[async_trait]
    impl Provider for FailingProvider {
        fn name(&self) -> &'static str {
            self.name
        }

        fn default_model(&self) -> Option<&str> {
            Some("qwen-test")
        }

        async fn complete(&self, _req: Request) -> Result<Completion> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            anyhow::bail!("raw provider failure containing secret-token")
        }
    }

    #[derive(Clone, Copy)]
    enum StreamBehavior {
        Done,
        Eof,
        Error,
        PendingAfterFirst,
    }

    struct ScriptedStreamProvider {
        behavior: StreamBehavior,
    }

    fn stream_chunk(delta: &str, done: bool) -> crate::providers::CompletionChunk {
        crate::providers::CompletionChunk {
            delta: delta.to_owned(),
            done,
            input_tokens: done.then_some(7),
            output_tokens: done.then_some(3),
            ..Default::default()
        }
    }

    #[async_trait]
    impl Provider for ScriptedStreamProvider {
        fn name(&self) -> &'static str {
            "local_qwen"
        }

        fn default_model(&self) -> Option<&str> {
            Some("qwen-test")
        }

        fn streams_on_wire(&self) -> bool {
            true
        }

        async fn stream_raw(
            &self,
            _req: Request,
            _permit: &ProviderDispatchPermit,
        ) -> Result<ChunkStream> {
            let stream: ChunkStream = match self.behavior {
                StreamBehavior::Done => Box::pin(futures_util::stream::iter([
                    Ok(stream_chunk("secret-stream-body", false)),
                    Ok(stream_chunk("-done", true)),
                ])),
                StreamBehavior::Eof => Box::pin(futures_util::stream::iter([Ok(stream_chunk(
                    "eof-body", false,
                ))])),
                StreamBehavior::Error => Box::pin(futures_util::stream::iter([
                    Ok(stream_chunk("partial", false)),
                    Err(anyhow::anyhow!("raw stream error with secret-token")),
                ])),
                StreamBehavior::PendingAfterFirst => Box::pin(
                    futures_util::stream::iter([Ok(stream_chunk("drop-body", false))])
                        .chain(futures_util::stream::pending()),
                ),
            };
            Ok(stream)
        }
    }

    #[async_trait]
    impl Provider for NativeStreamingProvider {
        fn name(&self) -> &'static str {
            "openai_api"
        }

        fn default_model(&self) -> Option<&str> {
            Some("gpt-5")
        }

        fn output_token_ceiling(&self, _req: &Request) -> Option<u32> {
            Some(crate::providers::DEFAULT_CLOUD_OUTPUT_TOKEN_CEILING)
        }

        fn streams_on_wire(&self) -> bool {
            true
        }

        async fn complete(&self, _req: Request) -> Result<Completion> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Completion::default())
        }

        async fn stream_raw(
            &self,
            _req: Request,
            _permit: &ProviderDispatchPermit,
        ) -> Result<ChunkStream> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Box::pin(futures_util::stream::iter([Ok(
                crate::providers::CompletionChunk {
                    done: true,
                    identity: CompletionIdentity {
                        provider: "forged-provider".into(),
                        wire_model: "forged-model".into(),
                    },
                    ..Default::default()
                },
            )])))
        }
    }

    struct CanonicalizingProvider {
        wire_models: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl Provider for CanonicalizingProvider {
        fn name(&self) -> &'static str {
            "openai_api"
        }

        fn resolve_model_for_wire(&self, requested_model: &str) -> String {
            match requested_model {
                "opusplan" | "opus-plan" => "claude-opus-4-7[1m]".into(),
                other => other.into(),
            }
        }

        fn output_token_ceiling(&self, _req: &Request) -> Option<u32> {
            Some(crate::providers::DEFAULT_CLOUD_OUTPUT_TOKEN_CEILING)
        }

        async fn complete(&self, req: Request) -> Result<Completion> {
            let model = req.model.unwrap_or_default();
            self.wire_models.lock().unwrap().push(model.clone());
            Ok(Completion {
                text: model.clone(),
                identity: CompletionIdentity {
                    provider: "forged-provider".into(),
                    wire_model: "forged-model".into(),
                },
                model,
                latency: Duration::ZERO,
                ..Completion::default()
            })
        }
    }

    struct UnboundedCloudProvider {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl Provider for UnboundedCloudProvider {
        fn name(&self) -> &'static str {
            "unbounded_cloud"
        }

        fn default_model(&self) -> Option<&str> {
            Some("future-model")
        }

        async fn complete(&self, _req: Request) -> Result<Completion> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Completion::default())
        }
    }

    struct ApprovingAsker;

    #[async_trait]
    impl crate::permissions::gate::ChannelAsker for ApprovingAsker {
        async fn ask(&self, _reason: &str) -> Option<bool> {
            Some(true)
        }
    }

    struct AbortWriterAndApprove {
        abort: tokio::task::AbortHandle,
    }

    #[async_trait]
    impl crate::permissions::gate::ChannelAsker for AbortWriterAndApprove {
        async fn ask(&self, _reason: &str) -> Option<bool> {
            self.abort.abort();
            tokio::task::yield_now().await;
            Some(true)
        }
    }

    #[tokio::test]
    async fn complete_and_stream_authorize_the_canonical_wire_model() {
        let inner = CanonicalizingProvider {
            wire_models: Mutex::new(Vec::new()),
        };
        let provider = CostAuthorizingProvider::new(
            &inner,
            ProviderCallAuthorizer::test_only(AutonomyLevel::Full),
            None,
            "test.canonical_model",
        );

        let completion = provider
            .complete(Request {
                model: Some("opusplan".into()),
                ..Request::default()
            })
            .await
            .unwrap();
        assert_eq!(completion.identity.provider, "openai_api");
        assert_eq!(completion.identity.wire_model, "claude-opus-4-7[1m]");
        assert_eq!(completion.model, "claude-opus-4-7[1m]");
        let mut stream = provider
            .stream(Request {
                model: Some("opus-plan".into()),
                ..Request::default()
            })
            .await
            .unwrap();
        let mut final_chunk = None;
        while let Some(chunk) = stream.next().await {
            final_chunk = Some(chunk.unwrap());
        }
        let final_chunk = final_chunk.expect("default stream emits its final envelope");
        assert!(final_chunk.done);
        assert_eq!(final_chunk.identity.provider, "openai_api");
        assert_eq!(final_chunk.identity.wire_model, "claude-opus-4-7[1m]");

        assert_eq!(
            *inner.wire_models.lock().unwrap(),
            vec![
                "claude-opus-4-7[1m]".to_string(),
                "claude-opus-4-7[1m]".to_string(),
            ]
        );
    }

    #[tokio::test]
    async fn unknown_bound_standard_fail_closed_audits_then_blocks_before_dispatch() {
        let dir = tempfile::tempdir().unwrap();
        let segment = dir.path().join("unbounded-standard-denied.wal");
        let (writer, join) = crate::wal::writer::spawn(segment.clone()).unwrap();
        let inner = UnboundedCloudProvider {
            calls: AtomicUsize::new(0),
        };
        let provider = CostAuthorizingProvider::new(
            &inner,
            ProviderCallAuthorizer::fail_closed(AutonomyLevel::Standard, Some(writer.clone())),
            None,
            "test.unbounded",
        );

        let error = provider.complete(Request::default()).await.unwrap_err();
        assert!(error.to_string().contains("fail-closed"));
        assert_eq!(inner.calls.load(Ordering::SeqCst), 0);
        drop(provider);
        drop(writer);
        join.await.unwrap();

        let frames = wal_frames(&segment);
        assert_eq!(frames.len(), 2);
        assert_eq!(
            frames[0].0,
            crate::wal::events::EVENT_TYPE_COST_ESTIMATE_SHOWN
        );
        assert_eq!(
            frames[1].0,
            crate::wal::events::EVENT_TYPE_PERMISSION_DENIED
        );
        assert_unknown_bound_payload(&frames[0].1, "unbounded_cloud", "future-model");
        let audited_action = frames[1].1["action"].as_str().unwrap();
        assert!(audited_action.contains("UnboundedPaidProviderCall"));
        assert!(audited_action.contains("unbounded_cloud"));
        assert!(audited_action.contains("future-model"));
        assert_eq!(frames[1].1["level"], "standard");
        assert_eq!(frames[1].1["decision"], "deny");
    }

    #[tokio::test]
    async fn finite_token_cap_with_unknown_price_never_claims_a_eur_upper_bound() {
        let dir = tempfile::tempdir().unwrap();
        let segment = dir.path().join("unknown-price-denied.wal");
        let (writer, join) = crate::wal::writer::spawn(segment.clone()).unwrap();
        let inner = CountingProvider {
            name: "future_cloud",
            calls: AtomicUsize::new(0),
            default_model: Some("future-model".into()),
        };
        let provider = CostAuthorizingProvider::new(
            &inner,
            ProviderCallAuthorizer::fail_closed(AutonomyLevel::Standard, Some(writer.clone())),
            None,
            "test.unknown_price",
        );

        let error = provider.complete(Request::default()).await.unwrap_err();
        assert!(error.to_string().contains("fail-closed"));
        assert_eq!(inner.calls.load(Ordering::SeqCst), 0);
        drop(provider);
        drop(writer);
        join.await.unwrap();

        let frames = wal_frames(&segment);
        assert_eq!(frames.len(), 2);
        let estimate = &frames[0].1;
        assert_eq!(estimate["cost_bound_kind"], "token_bounded_unknown_pricing");
        assert_eq!(estimate["output_token_ceiling"], 4096);
        assert!(estimate["total_eur_upper_bound"].is_null());
        assert!(estimate.get("total_eur").is_none());
        assert_eq!(
            frames[1].0,
            crate::wal::events::EVENT_TYPE_PERMISSION_DENIED
        );
        assert!(
            frames[1].1["action"]
                .as_str()
                .unwrap()
                .contains("UnboundedPaidProviderCall")
        );
    }

    #[tokio::test]
    async fn copilot_without_live_billing_context_uses_unbounded_paid_action() {
        let dir = tempfile::tempdir().unwrap();
        let segment = dir.path().join("copilot-unknown-billing.wal");
        let (writer, join) = crate::wal::writer::spawn(segment.clone()).unwrap();
        let authorizer =
            ProviderCallAuthorizer::fail_closed(AutonomyLevel::Full, Some(writer.clone()));
        authorizer
            .authorize_leaf(
                "copilot_api",
                &Request {
                    model: Some("gpt-4o".into()),
                    prompt: "billing state is not available at the leaf".into(),
                    ..Request::default()
                },
                "test.copilot.billing",
                false,
                Some(4096),
            )
            .await
            .unwrap();
        drop(authorizer);
        drop(writer);
        join.await.unwrap();

        let frames = wal_frames(&segment);
        assert_eq!(frames.len(), 2);
        assert_eq!(
            frames[0].1["cost_bound_kind"],
            "token_bounded_unknown_pricing"
        );
        assert!(frames[0].1.get("total_eur").is_none());
        assert!(
            frames[1].1["action"]
                .as_str()
                .unwrap()
                .contains("UnboundedPaidProviderCall")
        );
    }

    #[tokio::test]
    async fn unknown_bound_standard_channel_approval_proceeds_and_is_audited() {
        let dir = tempfile::tempdir().unwrap();
        let segment = dir.path().join("unbounded-standard-approved.wal");
        let (writer, join) = crate::wal::writer::spawn(segment.clone()).unwrap();
        let inner = UnboundedCloudProvider {
            calls: AtomicUsize::new(0),
        };
        let provider = CostAuthorizingProvider::new(
            &inner,
            ProviderCallAuthorizer::channel(
                AutonomyLevel::Standard,
                Some(writer.clone()),
                Arc::new(ApprovingAsker),
            ),
            None,
            "test.unbounded.channel",
        );

        provider.complete(Request::default()).await.unwrap();
        assert_eq!(inner.calls.load(Ordering::SeqCst), 1);
        drop(provider);
        drop(writer);
        join.await.unwrap();

        let frames = wal_frames(&segment);
        assert_eq!(frames.len(), 4);
        assert_eq!(
            frames[0].0,
            crate::wal::events::EVENT_TYPE_COST_ESTIMATE_SHOWN
        );
        assert_eq!(
            frames[1].0,
            crate::wal::events::EVENT_TYPE_PERMISSION_GRANTED
        );
        assert_unknown_bound_payload(&frames[0].1, "unbounded_cloud", "future-model");
        assert_eq!(frames[1].1["decision"], "allow");
        assert_eq!(frames[2].0, crate::wal::events::EVENT_TYPE_PROVIDER_REQUEST);
        assert_eq!(
            frames[3].0,
            crate::wal::events::EVENT_TYPE_PROVIDER_RESPONSE
        );
    }

    #[tokio::test]
    async fn unknown_bound_full_fail_closed_proceeds_and_is_audited() {
        let dir = tempfile::tempdir().unwrap();
        let segment = dir.path().join("unbounded-full-granted.wal");
        let (writer, join) = crate::wal::writer::spawn(segment.clone()).unwrap();
        let inner = UnboundedCloudProvider {
            calls: AtomicUsize::new(0),
        };
        let provider = CostAuthorizingProvider::new(
            &inner,
            ProviderCallAuthorizer::fail_closed(AutonomyLevel::Full, Some(writer.clone())),
            None,
            "test.unbounded.full",
        );

        provider.complete(Request::default()).await.unwrap();
        assert_eq!(inner.calls.load(Ordering::SeqCst), 1);
        drop(provider);
        drop(writer);
        join.await.unwrap();

        let frames = wal_frames(&segment);
        assert_eq!(frames.len(), 4);
        assert_eq!(
            frames[0].0,
            crate::wal::events::EVENT_TYPE_COST_ESTIMATE_SHOWN
        );
        assert_eq!(
            frames[1].0,
            crate::wal::events::EVENT_TYPE_PERMISSION_GRANTED
        );
        assert_unknown_bound_payload(&frames[0].1, "unbounded_cloud", "future-model");
        assert_eq!(frames[1].1["decision"], "allow");
        assert_eq!(frames[2].0, crate::wal::events::EVENT_TYPE_PROVIDER_REQUEST);
        assert_eq!(
            frames[3].0,
            crate::wal::events::EVENT_TYPE_PROVIDER_RESPONSE
        );
    }

    #[tokio::test]
    async fn default_claude_full_is_not_structurally_disabled_or_given_a_fake_cap() {
        let dir = tempfile::tempdir().unwrap();
        let segment = dir.path().join("claude-unbounded-full.wal");
        let (writer, join) = crate::wal::writer::spawn(segment.clone()).unwrap();
        let adapter = crate::providers::claude_cli::ClaudeCliAdapter::new_with_backend(
            "claude".into(),
            "claude-opus-4-7".into(),
            crate::providers::claude_cli::ClaudeBackend::Subprocess,
            10,
        );
        let req = Request {
            model: adapter.default_model().map(str::to_owned),
            prompt: "bounded input, unknown whole-invocation output".into(),
            ..Request::default()
        };
        let authorizer =
            ProviderCallAuthorizer::fail_closed(AutonomyLevel::Full, Some(writer.clone()));

        authorizer
            .authorize_leaf(
                adapter.name(),
                &req,
                "test.claude.default",
                false,
                adapter.output_token_ceiling(&req),
            )
            .await
            .unwrap();

        drop(authorizer);
        drop(writer);
        join.await.unwrap();
        let frames = wal_frames(&segment);
        assert_eq!(frames.len(), 2);
        assert_eq!(
            frames[1].0,
            crate::wal::events::EVENT_TYPE_PERMISSION_GRANTED
        );
        assert_unknown_bound_payload(&frames[0].1, "claude_cli", "claude-opus-4-7");
    }

    #[tokio::test]
    async fn strict_blocks_each_real_round_before_inner_dispatch() {
        let inner = CountingProvider {
            name: "openai_api",
            calls: AtomicUsize::new(0),
            default_model: None,
        };
        let provider = CostAuthorizingProvider::new(
            &inner,
            ProviderCallAuthorizer::test_only(AutonomyLevel::Strict),
            Some("gpt-5".into()),
            "test_round",
        );
        for _ in 0..2 {
            assert!(provider.complete(Request::default()).await.is_err());
        }
        assert_eq!(inner.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn wrapper_binds_default_model_to_authorization_and_wire_request() {
        let inner = CountingProvider {
            name: "openai_api",
            calls: AtomicUsize::new(0),
            default_model: None,
        };
        let provider = CostAuthorizingProvider::new(
            &inner,
            ProviderCallAuthorizer::test_only(AutonomyLevel::Full),
            Some("gpt-5".into()),
            "test_round",
        );
        let completion = provider.complete(Request::default()).await.unwrap();
        assert_eq!(completion.text, "gpt-5");
        assert_eq!(completion.identity.provider, "openai_api");
        assert_eq!(completion.identity.wire_model, "gpt-5");
        assert_eq!(completion.model, "gpt-5");
        assert_eq!(inner.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn wrapper_materializes_adapter_default_model_before_authorization() {
        let inner = CountingProvider {
            name: "openai_api",
            calls: AtomicUsize::new(0),
            default_model: Some("gpt-adapter-default".into()),
        };
        let provider = CostAuthorizingProvider::new(
            &inner,
            ProviderCallAuthorizer::test_only(AutonomyLevel::Full),
            None,
            "test_round",
        );
        let completion = provider.complete(Request::default()).await.unwrap();
        assert_eq!(completion.text, "gpt-adapter-default");
        assert_eq!(completion.identity.provider, "openai_api");
        assert_eq!(completion.identity.wire_model, "gpt-adapter-default");
        assert_eq!(completion.model, "gpt-adapter-default");
        assert_eq!(inner.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn implicit_model_fails_closed_before_dispatch() {
        let inner = CountingProvider {
            name: "openai_api",
            calls: AtomicUsize::new(0),
            default_model: None,
        };
        let provider = CostAuthorizingProvider::new(
            &inner,
            ProviderCallAuthorizer::test_only(AutonomyLevel::Full),
            None,
            "test_round",
        );
        let error = provider.complete(Request::default()).await.unwrap_err();
        assert!(error.to_string().contains("no explicit request model"));
        assert_eq!(inner.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn cost_wal_failure_blocks_dispatch() {
        let tmp = tempfile::tempdir().unwrap();
        let (writer, join) = crate::wal::spawn(tmp.path().join("cost.wal")).unwrap();
        let writer = writer.with_quota_guard(Arc::new(crate::wal::writer::QuotaGuard::new(
            tmp.path().to_path_buf(),
            0,
        )));
        let inner = CountingProvider {
            name: "openai_api",
            calls: AtomicUsize::new(0),
            default_model: None,
        };
        let provider = CostAuthorizingProvider::new(
            &inner,
            ProviderCallAuthorizer::fail_closed(AutonomyLevel::Full, Some(writer)),
            Some("gpt-5".into()),
            "test_round",
        );

        let error = provider.complete(Request::default()).await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("cost-estimate WAL append failed")
        );
        assert_eq!(inner.calls.load(Ordering::SeqCst), 0);

        drop(provider);
        join.await.unwrap();
    }

    #[tokio::test]
    async fn permission_grant_wal_failure_after_cost_frame_blocks_dispatch() {
        let dir = tempfile::tempdir().unwrap();
        let segment = dir.path().join("permission-grant-failure.wal");
        let (writer, join) = crate::wal::writer::spawn(segment).unwrap();
        let inner = CountingProvider {
            name: "openai_api",
            calls: AtomicUsize::new(0),
            default_model: Some("gpt-5".into()),
        };
        let provider = CostAuthorizingProvider::new(
            &inner,
            ProviderCallAuthorizer::channel(
                AutonomyLevel::Strict,
                Some(writer.clone()),
                Arc::new(AbortWriterAndApprove {
                    abort: join.abort_handle(),
                }),
            ),
            None,
            "test.permission_grant_failure",
        );

        let error = provider
            .complete(Request::default())
            .await
            .expect_err("an approved call without its grant frame must stay blocked");
        assert!(
            error
                .to_string()
                .contains("required permission audit WAL append failed"),
            "unexpected error: {error:#}"
        );
        assert_eq!(
            inner.calls.load(Ordering::SeqCst),
            0,
            "network leaf must not run after grant-audit failure"
        );

        drop(provider);
        drop(writer);
        assert!(join.await.unwrap_err().is_cancelled());
    }

    #[tokio::test]
    async fn missing_cost_wal_blocks_cloud_dispatch() {
        let inner = CountingProvider {
            name: "openai_api",
            calls: AtomicUsize::new(0),
            default_model: Some("gpt-5".into()),
        };
        let provider = CostAuthorizingProvider::new(
            &inner,
            ProviderCallAuthorizer::fail_closed(AutonomyLevel::Full, None),
            None,
            "test.missing_wal",
        );

        let error = provider.complete(Request::default()).await.unwrap_err();
        assert!(error.to_string().contains("no WAL writer is attached"));
        assert_eq!(inner.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn missing_cost_wal_also_blocks_unknown_bound_dispatch_at_full() {
        let inner = UnboundedCloudProvider {
            calls: AtomicUsize::new(0),
        };
        let provider = CostAuthorizingProvider::new(
            &inner,
            ProviderCallAuthorizer::fail_closed(AutonomyLevel::Full, None),
            None,
            "test.unbounded.missing_wal",
        );

        let error = provider.complete(Request::default()).await.unwrap_err();
        assert!(error.to_string().contains("no WAL writer is attached"));
        assert_eq!(inner.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn missing_lifecycle_wal_also_blocks_local_dispatch() {
        let inner = SensitiveSuccessProvider {
            calls: AtomicUsize::new(0),
        };
        let provider = CostAuthorizingProvider::new(
            &inner,
            ProviderCallAuthorizer::fail_closed(AutonomyLevel::Full, None),
            None,
            "test.local.missing_wal",
        );

        let error = provider.complete(Request::default()).await.unwrap_err();
        assert!(error.to_string().contains("no WAL writer is attached"));
        assert_eq!(inner.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn incognito_complete_lifecycle_pairs_both_terminals_without_raw_content() {
        let dir = tempfile::tempdir().unwrap();
        let segment = dir.path().join("complete-lifecycle.wal");
        let (writer, join) = crate::wal::writer::spawn(segment.clone()).unwrap();
        let context = ProviderCallAuditContext {
            source: Some("test_source"),
            request_id: Some("raw-request-id".into()),
            incognito: true,
            ..Default::default()
        };
        let authorizer =
            ProviderCallAuthorizer::fail_closed(AutonomyLevel::Strict, Some(writer.clone()))
                .with_audit_context(context);

        let success = SensitiveSuccessProvider {
            calls: AtomicUsize::new(0),
        };
        CostAuthorizingProvider::new(&success, authorizer.clone(), None, "test.complete.success")
            .complete(Request {
                prompt: "raw prompt with secret-token".into(),
                ..Default::default()
            })
            .await
            .unwrap();

        let failure = FailingProvider {
            name: "local_ollama",
            calls: AtomicUsize::new(0),
        };
        CostAuthorizingProvider::new(&failure, authorizer, None, "test.complete.failure")
            .complete(Request {
                prompt: "second raw prompt".into(),
                ..Default::default()
            })
            .await
            .unwrap_err();

        drop(writer);
        join.await.unwrap();
        let frames = wal_frames(&segment);
        assert_eq!(
            frames.iter().map(|frame| frame.0).collect::<Vec<_>>(),
            [
                crate::wal::events::EVENT_TYPE_PROVIDER_REQUEST,
                crate::wal::events::EVENT_TYPE_PROVIDER_RESPONSE,
                crate::wal::events::EVENT_TYPE_PROVIDER_REQUEST,
                crate::wal::events::EVENT_TYPE_PROVIDER_ERROR,
            ]
        );
        for pair in frames.chunks_exact(2) {
            assert_eq!(pair[0].1["invocation_id"], pair[1].1["invocation_id"]);
            assert_eq!(
                pair[0].1["request_binding_sha256"],
                pair[1].1["request_binding_sha256"]
            );
            assert_eq!(pair[0].1["source"], "test_source");
            assert_eq!(pair[0].1["incognito"], true);
            assert_eq!(pair[1].1["incognito"], true);
            assert!(pair[0].1.get("request_id").is_none());
            assert_eq!(pair[0].1["request_id_sha256"].as_str().unwrap().len(), 64);
        }
        assert_eq!(frames[0].1["provider"], "local_ouro");
        assert_eq!(frames[0].1["wire_model"], "ouro-test");
        assert_eq!(frames[1].1["input_tokens"], 11);
        assert_eq!(frames[1].1["output_tokens"], 5);
        assert_eq!(frames[2].1["provider"], "local_ollama");
        assert_eq!(frames[3].1["error_kind"], "provider_call_failed");
        let segment_bytes = std::fs::read(&segment).unwrap();
        let serialized = String::from_utf8_lossy(&segment_bytes);
        assert!(!serialized.contains("raw prompt"));
        assert!(!serialized.contains("raw completion body"));
        assert!(!serialized.contains("raw provider failure"));
        assert!(!serialized.contains("secret-token"));
        assert!(!serialized.contains("raw-request-id"));
    }

    #[tokio::test]
    async fn stream_lifecycle_settles_done_eof_error_and_drop_exactly_once() {
        let dir = tempfile::tempdir().unwrap();
        let segment = dir.path().join("stream-lifecycle.wal");
        let (writer, join) = crate::wal::writer::spawn(segment.clone()).unwrap();
        let authorizer =
            ProviderCallAuthorizer::fail_closed(AutonomyLevel::Strict, Some(writer.clone()));

        for behavior in [StreamBehavior::Done, StreamBehavior::Eof] {
            let inner = ScriptedStreamProvider { behavior };
            let provider = CostAuthorizingProvider::new(
                &inner,
                authorizer.clone(),
                None,
                "test.stream.success",
            );
            let mut stream = provider.stream(Request::default()).await.unwrap();
            while let Some(item) = stream.next().await {
                item.unwrap();
            }
        }

        let error_inner = ScriptedStreamProvider {
            behavior: StreamBehavior::Error,
        };
        let error_provider = CostAuthorizingProvider::new(
            &error_inner,
            authorizer.clone(),
            None,
            "test.stream.error",
        );
        let mut stream = error_provider.stream(Request::default()).await.unwrap();
        assert!(stream.next().await.unwrap().is_ok());
        assert!(stream.next().await.unwrap().is_err());
        assert!(stream.next().await.is_none());
        drop(error_provider);

        let drop_inner = ScriptedStreamProvider {
            behavior: StreamBehavior::PendingAfterFirst,
        };
        let drop_provider =
            CostAuthorizingProvider::new(&drop_inner, authorizer, None, "test.stream.drop");
        let mut stream = drop_provider.stream(Request::default()).await.unwrap();
        assert!(stream.next().await.unwrap().is_ok());
        drop(stream);
        drop(drop_provider);
        drop(writer);
        join.await.unwrap();

        let frames = wal_frames(&segment);
        assert_eq!(frames.len(), 8);
        assert_eq!(frames[1].1["terminal_kind"], "stream_done");
        assert_eq!(frames[3].1["terminal_kind"], "stream_eof");
        assert_eq!(frames[5].1["error_kind"], "stream_error");
        assert_eq!(frames[7].1["error_kind"], "stream_dropped");
        for pair in frames.chunks_exact(2) {
            assert_eq!(pair[0].0, crate::wal::events::EVENT_TYPE_PROVIDER_REQUEST);
            assert!(matches!(
                pair[1].0,
                crate::wal::events::EVENT_TYPE_PROVIDER_RESPONSE
                    | crate::wal::events::EVENT_TYPE_PROVIDER_ERROR
            ));
            assert_eq!(pair[0].1["invocation_id"], pair[1].1["invocation_id"]);
        }
        let segment_bytes = std::fs::read(&segment).unwrap();
        let serialized = String::from_utf8_lossy(&segment_bytes);
        assert!(!serialized.contains("secret-stream-body"));
        assert!(!serialized.contains("raw stream error"));
        assert!(!serialized.contains("secret-token"));
    }

    fn wal_frames(segment: &std::path::Path) -> Vec<(u8, serde_json::Value)> {
        let bytes = std::fs::read(segment).unwrap();
        let header = crate::wal::segment_header::parse_segment_header(&bytes).unwrap();
        let mut cursor = header.header_len();
        let mut frames = Vec::new();
        while cursor < bytes.len() {
            let frame = crate::wal::frame::decode_frame(&bytes[cursor..]).unwrap();
            frames.push((
                frame.header.event_type,
                serde_json::from_slice(frame.payload).unwrap(),
            ));
            let total = frame.header.total_len as usize;
            if total == 0 {
                break;
            }
            cursor = cursor.saturating_add(total);
        }
        frames
    }

    fn cost_payloads(segment: &std::path::Path) -> Vec<serde_json::Value> {
        wal_frames(segment)
            .into_iter()
            .filter_map(|(event_type, payload)| {
                (event_type == crate::wal::events::EVENT_TYPE_COST_ESTIMATE_SHOWN)
                    .then_some(payload)
            })
            .collect()
    }

    fn assert_unknown_bound_payload(payload: &serde_json::Value, provider: &str, model: &str) {
        assert_eq!(payload["authorization_binding"], "actual_leaf_request");
        assert_eq!(payload["provider"], provider);
        assert_eq!(payload["model"], model);
        assert_eq!(payload["cost_bound_kind"], "unbounded_provider_invocation");
        assert_eq!(
            payload["input_bound_kind"],
            "utf8_bytes_plus_request_message_overhead"
        );
        assert!(payload["input_token_upper_bound"].as_u64().unwrap() > 0);
        assert!(payload["output_tokens_est"].is_null());
        assert!(payload["output_token_ceiling"].is_null());
        assert!(payload["total_eur_upper_bound"].is_null());
        assert!(
            payload.get("total_eur").is_none(),
            "an unknown-bound call must not record an input-only lower bound as a total"
        );
    }

    #[test]
    fn request_binding_sha256_covers_wire_mode_and_request_controls() {
        let req = Request {
            model: Some("gpt-5".into()),
            prompt: "bound prompt".into(),
            system: Some("bound system".into()),
            temperature: Some(0.7),
            top_p: Some(0.9),
            sampling_seed: Some(42),
            stop_sequences: vec!["STOP".into()],
            thinking_budget: Some(256),
        };
        let base = request_binding_sha256(
            "openai_api",
            "gpt-5",
            &req,
            "test.binding",
            false,
            Some(4096),
        );
        assert_eq!(base.len(), 64);
        assert!(base.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(
            base,
            request_binding_sha256(
                "openai_api",
                "gpt-5",
                &req,
                "test.binding",
                true,
                Some(4096),
            )
        );
        let mut changed = req.clone();
        changed.stop_sequences.push("SECOND".into());
        assert_ne!(
            base,
            request_binding_sha256(
                "openai_api",
                "gpt-5",
                &changed,
                "test.binding",
                false,
                Some(4096),
            )
        );
    }

    #[tokio::test]
    async fn authorization_id_and_binding_match_cost_and_permission_frames() {
        let dir = tempfile::tempdir().unwrap();
        let segment = dir.path().join("bound-authorizations.wal");
        let (writer, join) = crate::wal::writer::spawn(segment.clone()).unwrap();
        let authorizer =
            ProviderCallAuthorizer::fail_closed(AutonomyLevel::Full, Some(writer.clone()));
        let req = Request {
            model: Some("gpt-5".into()),
            prompt: "same request twice".into(),
            ..Request::default()
        };

        for _ in 0..2 {
            authorizer
                .authorize_leaf("openai_api", &req, "test.bound_frames", false, Some(4096))
                .await
                .unwrap();
        }
        drop(authorizer);
        drop(writer);
        join.await.unwrap();

        let frames = wal_frames(&segment);
        assert_eq!(frames.len(), 4);
        for pair in frames.chunks_exact(2) {
            assert_eq!(
                pair[0].0,
                crate::wal::events::EVENT_TYPE_COST_ESTIMATE_SHOWN
            );
            assert_eq!(pair[1].0, crate::wal::events::EVENT_TYPE_PERMISSION_GRANTED);
            assert_eq!(pair[0].1["authorization_id"], pair[1].1["authorization_id"]);
            assert_eq!(
                pair[0].1["request_binding_sha256"],
                pair[1].1["request_binding_sha256"]
            );
            assert_eq!(pair[0].1["authorization_id"].as_str().unwrap().len(), 64);
            assert_eq!(
                pair[0].1["request_binding_sha256"].as_str().unwrap().len(),
                64
            );
        }
        assert_eq!(
            frames[0].1["request_binding_sha256"], frames[2].1["request_binding_sha256"],
            "identical leaf requests must have the same request binding"
        );
        assert_ne!(
            frames[0].1["authorization_id"], frames[2].1["authorization_id"],
            "each approval attempt needs a unique replay-resistant authorization id"
        );
    }

    #[tokio::test]
    async fn audited_streaming_flag_matches_the_actual_wire_mode() {
        let dir = tempfile::tempdir().unwrap();
        let segment = dir.path().join("wire-streaming-mode.wal");
        let (writer, join) = crate::wal::writer::spawn(segment.clone()).unwrap();
        let authorizer =
            ProviderCallAuthorizer::fail_closed(AutonomyLevel::Full, Some(writer.clone()));

        let buffered = CountingProvider {
            name: "openai_api",
            calls: AtomicUsize::new(0),
            default_model: Some("gpt-5".into()),
        };
        let buffered = CostAuthorizingProvider::new(
            &buffered,
            authorizer.clone(),
            None,
            "test.buffered_stream",
        );
        let mut stream = buffered.stream(Request::default()).await.unwrap();
        let buffered_final = stream.next().await.unwrap().unwrap();
        assert!(buffered_final.done);
        assert_eq!(buffered_final.identity.provider, "openai_api");
        assert_eq!(buffered_final.identity.wire_model, "gpt-5");
        assert!(stream.next().await.is_none());
        drop(stream);
        drop(buffered);

        let native = NativeStreamingProvider {
            calls: AtomicUsize::new(0),
        };
        let native =
            CostAuthorizingProvider::new(&native, authorizer.clone(), None, "test.native_stream");
        let mut stream = native.stream(Request::default()).await.unwrap();
        let native_final = stream.next().await.unwrap().unwrap();
        assert!(native_final.done);
        assert_eq!(native_final.identity.provider, "openai_api");
        assert_eq!(native_final.identity.wire_model, "gpt-5");
        assert!(stream.next().await.is_none());
        drop(stream);
        drop(native);

        drop(authorizer);
        drop(writer);
        join.await.unwrap();
        let payloads = cost_payloads(&segment);
        assert_eq!(payloads.len(), 2);
        assert_eq!(payloads[0]["call_scope"], "test.buffered_stream");
        assert_eq!(payloads[0]["streaming"], false);
        assert_eq!(payloads[1]["call_scope"], "test.native_stream");
        assert_eq!(payloads[1]["streaming"], true);
    }

    #[tokio::test]
    async fn wal_and_paid_gate_use_each_leaf_output_ceiling() {
        let dir = tempfile::tempdir().unwrap();
        let segment = dir.path().join("cost-ceilings.wal");
        let (writer, join) = crate::wal::writer::spawn(segment.clone()).unwrap();
        let inner = CountingProvider {
            name: "openai_api",
            calls: AtomicUsize::new(0),
            default_model: Some("gpt-5".into()),
        };
        let provider = CostAuthorizingProvider::new(
            &inner,
            ProviderCallAuthorizer::fail_closed(AutonomyLevel::Full, Some(writer.clone())),
            None,
            "test.ceilings",
        );

        provider.complete(Request::default()).await.unwrap();
        provider
            .complete(Request {
                thinking_budget: Some(10_000),
                ..Request::default()
            })
            .await
            .unwrap();
        provider
            .complete(Request {
                thinking_budget: Some(16_384),
                ..Request::default()
            })
            .await
            .unwrap();
        assert_eq!(inner.calls.load(Ordering::SeqCst), 3);

        drop(provider);
        drop(writer);
        join.await.unwrap();
        let payloads = cost_payloads(&segment);
        assert_eq!(payloads.len(), 3);
        assert_eq!(
            payloads[0]["cost_bound_kind"],
            "wire_token_bounded_reviewed_price_estimate"
        );
        assert_eq!(payloads[0]["output_token_ceiling"], 4096);
        assert_eq!(payloads[0]["output_tokens_est"], 4096);
        assert_eq!(payloads[0]["total_eur_estimate"], payloads[0]["total_eur"]);
        assert!(payloads[0]["total_eur_upper_bound"].is_null());
        assert_eq!(payloads[1]["output_token_ceiling"], 14_096);
        assert_eq!(payloads[1]["output_tokens_est"], 14_096);
        assert_eq!(payloads[2]["output_token_ceiling"], 20_480);
        assert_eq!(payloads[2]["output_tokens_est"], 20_480);
        assert!(
            payloads[1]["total_eur"].as_f64().unwrap() > payloads[0]["total_eur"].as_f64().unwrap()
        );
        assert!(
            payloads[2]["total_eur"].as_f64().unwrap() > payloads[1]["total_eur"].as_f64().unwrap()
        );
    }

    #[tokio::test]
    async fn nested_authorization_wrappers_fail_closed_without_pseudo_leaf_audits() {
        let dir = tempfile::tempdir().unwrap();
        let inner_segment = dir.path().join("inner-cost.wal");
        let outer_segment = dir.path().join("outer-cost.wal");
        let (inner_writer, inner_join) = crate::wal::writer::spawn(inner_segment.clone()).unwrap();
        let (outer_writer, outer_join) = crate::wal::writer::spawn(outer_segment.clone()).unwrap();
        let leaf = Arc::new(CountingProvider {
            name: "openai_api",
            calls: AtomicUsize::new(0),
            default_model: Some("gpt-5".into()),
        });
        let owned = AuthorizedProvider::from_arc(
            leaf.clone(),
            ProviderCallAuthorizer::fail_closed(AutonomyLevel::Strict, Some(inner_writer.clone())),
            None,
            "inner.policy",
        );
        let outer = CostAuthorizingProvider::new(
            &owned,
            ProviderCallAuthorizer::fail_closed(AutonomyLevel::Full, Some(outer_writer.clone())),
            None,
            "outer.policy",
        );

        let error = outer
            .complete(Request::default())
            .await
            .expect_err("nested policy boundaries must fail closed");
        assert!(error.to_string().contains("nested provider authorization"));
        assert_eq!(leaf.calls.load(Ordering::SeqCst), 0);

        drop(outer);
        drop(owned);
        drop(inner_writer);
        drop(outer_writer);
        inner_join.await.unwrap();
        outer_join.await.unwrap();

        let inner_frames = wal_frames(&inner_segment);
        assert!(inner_frames.is_empty());

        let outer_frames = wal_frames(&outer_segment);
        assert!(
            outer_frames.is_empty(),
            "an authorization decorator is not a leaf and must not emit a duplicate lifecycle"
        );
    }

    #[tokio::test]
    async fn standard_paid_gate_denies_large_ceiling_that_cold_meter_would_allow() {
        let dir = tempfile::tempdir().unwrap();
        let (writer, join) =
            crate::wal::writer::spawn(dir.path().join("ceiling-gate.wal")).unwrap();
        let inner = CountingProvider {
            name: "openai_api",
            calls: AtomicUsize::new(0),
            default_model: Some("gpt-5".into()),
        };
        let provider = CostAuthorizingProvider::new(
            &inner,
            ProviderCallAuthorizer::fail_closed(AutonomyLevel::Standard, Some(writer.clone())),
            None,
            "test.ceiling_gate",
        );

        provider.complete(Request::default()).await.unwrap();
        let error = provider
            .complete(Request {
                thinking_budget: Some(16_384),
                ..Request::default()
            })
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("provider call authorization failed")
        );
        assert_eq!(
            inner.calls.load(Ordering::SeqCst),
            1,
            "the 20,480-token bound must be denied before the second cloud dispatch"
        );

        drop(provider);
        drop(writer);
        join.await.unwrap();
    }

    #[tokio::test]
    async fn only_canonical_local_providers_bypass_paid_call_gate() {
        let local = CountingProvider {
            name: "local_ollama",
            calls: AtomicUsize::new(0),
            default_model: Some("qwen-local".into()),
        };
        let local = CostAuthorizingProvider::new(
            &local,
            ProviderCallAuthorizer::test_only(AutonomyLevel::Strict),
            None,
            "test.local",
        );
        assert!(local.complete(Request::default()).await.is_ok());

        let unknown = CountingProvider {
            name: "unknown_zero_price",
            calls: AtomicUsize::new(0),
            default_model: Some("free-model".into()),
        };
        let unknown = CostAuthorizingProvider::new(
            &unknown,
            ProviderCallAuthorizer::test_only(AutonomyLevel::Strict),
            None,
            "test.unknown",
        );
        assert!(
            unknown.complete(Request::default()).await.is_err(),
            "an unknown zero-priced provider is still an outbound paid-call action"
        );
    }

    #[tokio::test]
    async fn reload_aware_authorizer_reads_current_autonomy_for_each_leaf() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("freedom.yaml");
        let mut initial = crate::config::FreedomConfig::default();
        initial.autonomy = AutonomyLevel::Full;
        std::fs::write(&path, serde_yaml::to_string(&initial).unwrap()).unwrap();
        let controller = Arc::new(crate::config::reload::ReloadController::new(
            initial.clone(),
            path.clone(),
        ));
        let inner = Arc::new(CountingProvider {
            name: "unknown_zero_price",
            calls: AtomicUsize::new(0),
            default_model: Some("free-model".into()),
        });
        let provider = AuthorizedProvider::from_arc(
            inner.clone(),
            ProviderCallAuthorizer::test_only_reload(controller.clone()),
            None,
            "test.reload",
        );

        provider.complete(Request::default()).await.unwrap();
        assert_eq!(inner.calls.load(Ordering::SeqCst), 1);

        let mut reloaded = initial;
        reloaded.autonomy = AutonomyLevel::Strict;
        std::fs::write(&path, serde_yaml::to_string(&reloaded).unwrap()).unwrap();
        assert!(matches!(
            controller.try_reload().unwrap(),
            crate::config::reload::ReloadResult::Reloaded { .. }
        ));
        assert!(provider.complete(Request::default()).await.is_err());
        assert_eq!(
            inner.calls.load(Ordering::SeqCst),
            1,
            "the post-reload Strict call must be blocked before dispatch"
        );
    }

    #[test]
    fn production_transports_cannot_override_the_safe_dispatch_entry() {
        fn production_prefix(source: &str) -> &str {
            source
                .split_once("#[cfg(test)]\nmod tests")
                .or_else(|| source.split_once("#[cfg(test)]\r\nmod tests"))
                .map_or(source, |(production, _)| production)
        }

        fn collect_rs(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    collect_rs(&path, out);
                } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
                    out.push(path);
                }
            }
        }

        let providers_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("providers");
        let mut safe_overrides = Vec::new();
        let mut permit_constructors = Vec::new();
        let mut files = Vec::new();
        collect_rs(&providers_dir, &mut files);
        files.sort();
        for path in files {
            let relative = path
                .strip_prefix(&providers_dir)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let source = std::fs::read_to_string(&path).unwrap();
            for line in production_prefix(&source).lines() {
                let compact = line.split_whitespace().collect::<String>();
                if compact.starts_with("asyncfncomplete(") {
                    safe_overrides.push(format!("{relative}:complete"));
                } else if compact.starts_with("asyncfnstream(") {
                    safe_overrides.push(format!("{relative}:stream"));
                }
                if !line.trim_start().starts_with("//")
                    && line.contains("ProviderDispatchPermit { _private: () }")
                {
                    permit_constructors.push(relative.clone());
                }
            }
        }

        assert_eq!(
            safe_overrides,
            [
                "cost_authorization.rs:complete",
                "cost_authorization.rs:stream",
                "cost_authorization.rs:complete",
                "cost_authorization.rs:stream",
                "mod.rs:complete",
                "mod.rs:stream",
            ],
            "only the two authorization decorators and the trait's fail-closed defaults may expose Provider::complete/stream in production"
        );
        assert_eq!(
            permit_constructors,
            ["mod.rs", "mod.rs", "mod.rs", "mod.rs"],
            "raw transport permits must only be minted inside the mandatory authorization boundary (plus cfg(test) compatibility paths)"
        );
    }

    #[test]
    fn production_provider_lifecycle_emitters_are_centralized() {
        fn production_prefix(source: &str) -> &str {
            source
                .split_once("#[cfg(test)]\nmod tests")
                .or_else(|| source.split_once("#[cfg(test)]\r\nmod tests"))
                .map_or(source, |(production, _)| production)
        }

        fn collect_rs(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    collect_rs(&path, out);
                } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
                    out.push(path);
                }
            }
        }

        let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        collect_rs(&src_dir, &mut files);
        files.sort();
        let event_names = [
            "EVENT_TYPE_PROVIDER_REQUEST",
            "EVENT_TYPE_PROVIDER_RESPONSE",
            "EVENT_TYPE_PROVIDER_ERROR",
        ];
        let mut emitters = Vec::new();
        let mut babel_submitters = Vec::new();
        for path in files {
            let source = std::fs::read_to_string(&path).unwrap();
            let compact = production_prefix(&source)
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect::<String>();
            let relative = path
                .strip_prefix(&src_dir)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            for _ in 0..compact
                .matches("crate::analytics::babel::khist::submit_response_text(")
                .count()
            {
                babel_submitters.push(relative.clone());
            }
            for event_name in event_names {
                let header_builder = format!("HeaderBuilder::new({event_name}");
                let qualified_builder =
                    format!("HeaderBuilder::new(crate::wal::events::{event_name}");
                let make_header = format!("make_header({event_name}");
                let qualified_make = format!("make_header(crate::wal::events::{event_name}");
                let count = compact.matches(&header_builder).count()
                    + compact.matches(&qualified_builder).count()
                    + compact.matches(&make_header).count()
                    + compact.matches(&qualified_make).count();
                for _ in 0..count {
                    emitters.push((relative.clone(), event_name));
                }
            }
        }

        assert_eq!(
            emitters,
            [(
                "providers/cost_authorization.rs".to_owned(),
                "EVENT_TYPE_PROVIDER_REQUEST"
            )],
            "literal 0x20/21/22 emitters outside the mandatory provider-leaf lifecycle are forbidden"
        );
        let central =
            std::fs::read_to_string(src_dir.join("providers/cost_authorization.rs")).unwrap();
        assert!(central.contains("EVENT_TYPE_PROVIDER_RESPONSE"));
        assert!(central.contains("EVENT_TYPE_PROVIDER_ERROR"));
        assert!(central.contains("HeaderBuilder::new(event_type"));
        assert_eq!(
            babel_submitters,
            [
                "providers/cost_authorization.rs",
                "providers/cost_authorization.rs",
                "providers/cost_authorization.rs",
            ],
            "Babel K_d samples must come from the canonical successful provider lifecycle, not selected callers"
        );
        assert!(
            central.contains("let collect_babel_sample = !ticket.context.incognito;"),
            "incognito provider calls must not emit content-derived Babel samples"
        );
    }

    fn raw_callsite_multiset_digest(source: &str) -> (usize, String) {
        use sha2::{Digest, Sha256};

        let lines = source.lines().collect::<Vec<_>>();
        let production_end = lines
            .iter()
            .enumerate()
            .find_map(|(index, line)| {
                let trimmed = line.trim();
                if trimmed != "mod tests {" && trimmed != "mod tests{" {
                    return None;
                }
                let guarded = lines[..index]
                    .iter()
                    .rev()
                    .find(|line| !line.trim().is_empty())
                    .is_some_and(|line| line.trim() == "#[cfg(test)]");
                guarded.then_some(index.saturating_sub(1))
            })
            .unwrap_or(lines.len());

        let mut contexts = Vec::new();
        for (index, line) in lines[..production_end].iter().enumerate() {
            if line.trim_start().starts_with("//") {
                continue;
            }
            let compact = line
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect::<String>();
            let hits = compact.matches(".complete(").count() + compact.matches(".stream(").count();
            if hits == 0 {
                continue;
            }

            let mut context = String::new();
            let start = index.saturating_sub(2);
            let end = (index + 3).min(production_end);
            for context_line in &lines[start..end] {
                let trimmed = context_line.trim_start();
                if trimmed.is_empty() || trimmed.starts_with("//") {
                    continue;
                }
                context.extend(
                    context_line
                        .chars()
                        .filter(|character| !character.is_whitespace()),
                );
            }
            for _ in 0..hits {
                contexts.push(context.clone());
            }
        }
        let digest = Sha256::digest(contexts.join("\0").as_bytes());
        let digest = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        (contexts.len(), digest)
    }

    #[test]
    fn raw_callsite_digest_detects_same_count_substitution() {
        let authorized = "fn run() {\n    authorized_provider.complete(req).await;\n}\n";
        let raw_cloud = "fn run() {\n    raw_cloud_provider.complete(req).await;\n}\n";
        let authorized_fingerprint = raw_callsite_multiset_digest(authorized);
        let raw_fingerprint = raw_callsite_multiset_digest(raw_cloud);
        assert_eq!(authorized_fingerprint.0, raw_fingerprint.0);
        assert_ne!(
            authorized_fingerprint.1, raw_fingerprint.1,
            "same-count receiver substitution must invalidate the reviewed surface"
        );
    }

    #[test]
    fn production_raw_complete_stream_surface_is_reviewed() {
        fn collect_rs(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    collect_rs(&path, out);
                } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
                    out.push(path);
                }
            }
        }

        // Exact reviewed surface. Entries are either:
        // - the Provider leaf/decorator implementation itself;
        // - a consumer reached only through CostAuthorizingProvider or the
        //   concrete AuthorizedProvider handle;
        // - an explicitly local provider path; or
        // - a same-named non-provider method (IRC/coding/OMI helpers).
        // Any new raw-looking call must be classified and centrally wired
        // before this inventory is deliberately updated.
        let expected = [
            (
                "channels/irc.rs",
                1usize,
                "08370bc276c05eedcae42dfeba84ee0fad41e42acd7ce09310dd327edc57f3a7",
            ),
            (
                "cli/arxiv_ingest_task.rs",
                1,
                "e97285d8304ac8cbaf03268075ab281c3bf4634c0d72e9047ab52a2b898371cb",
            ),
            (
                "cli/bg_session.rs",
                1,
                "6fe2c5967b5ae77624c95882bc7bc18927b9c952becfa7f779983e032d44e4fe",
            ),
            (
                "cli/chat.rs",
                4,
                "18572e38504f96127275153ff8ddc45c04594a7e4cc836a8ce07cbf9b317fedf",
            ),
            (
                "cli/clarify_chat.rs",
                1,
                "31dd1ec85b17c74ab6bd15e925fcbc3ef4877b907e2a1efa3d5c379b0df0b668",
            ),
            (
                "cli/doctor.rs",
                1,
                "512312f73fa25f3c6b3d6e5aaeca21beba630303a7eae8f19aae872d4900f3a7",
            ),
            (
                "cli/hemispheres.rs",
                1,
                "7cb1cb5e89d8b99f7045e45e55fdbfeec5bd1e89863b6373fa51fb04709bb8a4",
            ),
            (
                "cli/omi.rs",
                3,
                "4e4e83c7c286da5c06ce3fc9a822c01d067f86aaf5190d91aff8fe477277eec6",
            ),
            (
                "cli/serve_pipeline.rs",
                4,
                "28ff0d668aa42a58de0f4b864301cdc8f17de4208f7e00ef4e1f7bad8889fea4",
            ),
            (
                "cli/serve_tasks.rs",
                1,
                "2dfb67bb47bb79084d95f5d88a045907cb6c4d6f0382f4005e9d34f633ed26b3",
            ),
            (
                "cluster/executor.rs",
                1,
                "6a2e81422487632ea092f8d14a93bcde16c6601ee05ac4a02c04e7e0991cafd0",
            ),
            (
                "coding/cerebellum_provider.rs",
                1,
                "5b8551367198b92b88248c2b7d86e7b133a0390b281050bc53817242a9f02ff8",
            ),
            (
                "coding/decomposer.rs",
                2,
                "62f0bcda7525fd4d4f50d2f2e1f647a85ecab14149660c8928b80951d930963c",
            ),
            (
                "coding/plan_review.rs",
                1,
                "037bda696a769ca38c24cc1cc18b73eee31614702991caf8302d3754ed2a454f",
            ),
            (
                "coding/provider_worker.rs",
                2,
                "a6e2b42fe92282611899e6463990058fe92f3f969f6062a2b4be1b1bc294f861",
            ),
            (
                "coding/second_opinion.rs",
                1,
                "53f319339e894898d205f44a3f7b68b9e0e30d5a980701d4bff4b49711e88ae9",
            ),
            (
                "cron/runner.rs",
                1,
                "d2e0210d08842997e1c3fd53c1c0cfc8148587bb6b8104dc20c0248d4cd031f9",
            ),
            (
                "daemon/arxiv_skill_scan_cron.rs",
                1,
                "e97285d8304ac8cbaf03268075ab281c3bf4634c0d72e9047ab52a2b898371cb",
            ),
            (
                "daemon/checkin_cron.rs",
                1,
                "3088cac0ba4108e5ecad9e44506d70660a5a526677a9f3a4ef4dff80b032ce2a",
            ),
            (
                "daemon/dreaming.rs",
                1,
                "138900356591bc8ce26e9f81dd38cea9dc2887bb11d895b73e7b00319733fc17",
            ),
            (
                "daemon/regression_cron.rs",
                1,
                "81b2e25e7b3dec18c191fa96339afca31f0b671bacdbd075e7bc0fb95a0ed09d",
            ),
            (
                "daemon/session_sort_cron.rs",
                1,
                "72d16b8281f75de32793b2d825195e4209613dad9607073d75aa4f1e6e05e7e8",
            ),
            (
                "email/threat_tiebreak.rs",
                1,
                "b9ae3baedab03664ec7fe49af17f5e17d3d5f2e64786b26068bf668701653c6b",
            ),
            (
                "mcp/dispatch_loop.rs",
                3,
                "c2d8915ebf96745dc223a0cf07fc542e66a6e85b524df99a94a88c04ba520529",
            ),
            (
                "mcp/goal_judge.rs",
                1,
                "2b1d0df4343c2314a50b0dd7e789c7a75093404f9eb70ed39bc4d4cf9ff5fcbc",
            ),
            (
                "memory/entities.rs",
                1,
                "8be04efd23974c8a780d16ff3c5596242dd1d962a1bf469b86d741b180e005fe",
            ),
            (
                "memory/warm_summarize.rs",
                1,
                "79f6ebf38717c8e8b27ffe2c78f753f744fec605bf6041b5d23b8061bf779a7b",
            ),
            (
                "n8n_api/handlers.rs",
                1,
                "b2e9872e4362336a8160589c76e8c9ba9abbcf5074598898fde9c98484414144",
            ),
            (
                "profile/extract.rs",
                1,
                "f35c79af7b89e6cac25c7f5a12327cba6d10427086a23a763c1f15b9d299aa37",
            ),
            (
                "providers/cost_authorization.rs",
                4,
                "3849ff167c46a40b9e50492510a3360d160f93faba1ad3a0bc8a6b5adb451199",
            ),
            (
                "providers/mod.rs",
                1,
                "149b4a18f01caafe3cb16ec4bb9e96b3b7db90b30c90efee257d96f515a0dc24",
            ),
            (
                "security/jailbreak_retry.rs",
                1,
                "2a946cc418f69d12f5971c1fc5e3ca1cd5bbceda4d730e07a767e67ecd55a0a6",
            ),
            (
                "security/refusal_abliterated.rs",
                2,
                "df6b6d753e9016a94e2182a2039a91316d2168ccfd44baccf45b155eeb000c7b",
            ),
            (
                "security/refusal_recovery.rs",
                2,
                "d87ae6306552981bed3b385cb011d19c12e45a993e98116f466d6da46eaef49f",
            ),
            (
                "skills/auto_extract.rs",
                1,
                "3088cac0ba4108e5ecad9e44506d70660a5a526677a9f3a4ef4dff80b032ce2a",
            ),
            (
                "skills/test_harness.rs",
                2,
                "0c2d8e9e116a587bfacdd6d702eb773e272f049b690041c051ef18e801b6c603",
            ),
            (
                "sub_agents/review.rs",
                1,
                "7fc2062a37c4b30a2c596b80599986da8dc18ddbe06736569a907d7fafabce2b",
            ),
            (
                "tools/deep_research.rs",
                3,
                "bcb3b7889da6382bf1efe06bd2e77c889e1db6cdb37b1c0eb822eb1414f1d390",
            ),
            (
                "tools/web_fetch.rs",
                1,
                "a1638d8aae9ef8ff48eee6ff763f03c615f62f3e0c0e7dd28c5b704ee6d1cab3",
            ),
        ]
        .into_iter()
        .map(|(path, count, digest)| (path.to_string(), (count, digest.to_string())))
        .collect::<std::collections::BTreeMap<_, _>>();

        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        collect_rs(&root, &mut files);
        let mut actual = std::collections::BTreeMap::new();
        for path in files {
            let source = std::fs::read_to_string(&path).unwrap();
            let fingerprint = raw_callsite_multiset_digest(&source);
            let count = fingerprint.0;
            if count > 0 {
                let relative = path
                    .strip_prefix(&root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                actual.insert(relative, fingerprint);
            }
        }
        assert_eq!(
            actual, expected,
            "raw complete/stream callsite digest changed: classify and centrally wire the concrete receiver/arguments before deliberately updating this reviewed signature"
        );
    }
}
