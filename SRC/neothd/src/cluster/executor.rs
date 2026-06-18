//! SL-01 — cluster task executor.
//!
//! The "slave" side: a master delegates a task (via a `TaskDelegate` frame),
//! the per-peer session loop runs the 3-checkpoint accept gate, and on ACCEPT
//! hands the task to THIS executor over a bounded channel. The executor runs
//! the prompt through the node's local `Arc<dyn Provider>` and replies a
//! `TaskResult` frame via the [`PeerStreamRegistry`] outbound path.
//!
//! Why a dedicated task (not inline in the session loop): the per-peer loop is
//! read-to-completion (peeroxide reads are not cancel-safe). Running a
//! seconds-long `complete()` inline would block that connection inbound reads
//! and the master would mark this node UNHEALTHY (15s) mid-inference. So the
//! gate dispatches off-loop to here, and the loop returns to reading at once.
//!
//! Concurrency: the executor runs ONE inference at a time (sequential). The
//! dispatch channel is BOUNDED at capacity 1, so when an inference is in flight
//! the session loop's `try_send` fails and it replies `Rejected{reason:"busy"}`
//! — bounded back-pressure, no unbounded queue (multi-task scheduling is v1.0).

use std::sync::Arc;

use crate::providers::{Provider, Request, is_local_provider};
use crate::wal::writer::WalWriterHandle;

use super::heartbeat::{FrameBody, FrameKind, TaskResultBody, TaskResultStatus, WireFrame};
use super::peer_streams::PeerStreamRegistry;

/// Maximum bytes of completion text returned in a `TaskResult`. Keeps the
/// encoded reply frame comfortably under `heartbeat::MAX_FRAME_BYTES` (64 KiB)
/// and bounds how much a delegated task can make the slave ship back.
pub const MAX_TASK_RESULT_BYTES: usize = 32 * 1024;

/// Bounded dispatch channel depth. Capacity 1 = one inference in flight;
/// a second concurrent delegation gets a `busy` rejection at the gate.
pub const DISPATCH_QUEUE_DEPTH: usize = 1;

/// Wall-clock ceiling on a single delegated inference. Caps how long a
/// (possibly malicious) master can occupy the single executor / the GPU with
/// one task. On timeout the master gets a `Failed{error:"timeout"}`.
pub const TASK_INFERENCE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// An accepted delegated task handed from the session-loop gate to the
/// executor. The requester is the AUTHENTICATED Noise pubkey hex
/// (`reply_peer_pk`) — never a payload field.
#[derive(Debug, Clone)]
pub struct ClusterTaskJob {
    pub task_id: String,
    pub prompt: String,
    /// Authenticated peer Noise pubkey hex to reply to.
    pub reply_peer_pk: String,
    /// WAL writer so the executor can audit the inner provider call path.
    pub wal_writer: Option<Arc<WalWriterHandle>>,
}

/// Spawn the single cluster-task executor. Returns the bounded `Sender` the
/// session loop uses to dispatch accepted tasks. Holds a clone of the provider
/// + peer-stream registry for the daemon's lifetime.
pub fn spawn_cluster_executor(
    provider: Option<Arc<dyn Provider>>,
    peer_streams: Arc<PeerStreamRegistry>,
) -> tokio::sync::mpsc::Sender<ClusterTaskJob> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<ClusterTaskJob>(DISPATCH_QUEUE_DEPTH);
    // A stable peer_id for this executor's reply frames (master correlates by
    // task_id; this is observability only).
    let executor_peer_id = uuid::Uuid::now_v7().to_string();
    tokio::spawn(async move {
        let mut seq: u64 = 0;
        while let Some(job) = rx.recv().await {
            seq = seq.wrapping_add(1);
            // Panic-isolation: run the inference in a sub-task so a panicking
            // provider can't kill the executor loop (which would silently drop
            // ALL future tasks). On panic, synthesize a Failed result so every
            // accepted task (0xEB) has a terminating reply. Sequential is
            // preserved — we await the sub-task before recv()ing the next job.
            // Capture the reply target + id BEFORE the sub-task consumes `job`.
            let task_id = job.task_id.clone();
            let reply_peer_pk = job.reply_peer_pk.clone();
            let provider_clone = provider.clone();
            let result_body = match tokio::spawn(run_one_task(provider_clone, job)).await {
                Ok(body) => body,
                Err(join_err) => {
                    tracing::error!(
                        task_id = %task_id,
                        panic = %join_err,
                        "cluster executor: inference task panicked — replying Failed"
                    );
                    TaskResultBody {
                        task_id: task_id.clone(),
                        status: TaskResultStatus::Failed {
                            error: "executor_panic".to_string(),
                        },
                        result: None,
                        provider_name: None,
                    }
                }
            };
            let frame = WireFrame {
                kind: FrameKind::TaskResult,
                sequence: seq,
                sent_unix_ms: now_unix_ms(),
                peer_id: executor_peer_id.clone(),
                body: FrameBody::TaskResult(result_body),
            };
            match peer_streams.send_to(&reply_peer_pk, frame) {
                Ok(()) => {
                    tracing::debug!(
                        task_id = %task_id,
                        peer = %&reply_peer_pk[..16.min(reply_peer_pk.len())],
                        "cluster executor: TaskResult queued for delivery"
                    );
                }
                Err(e) => {
                    // The peer disconnected before we could reply — the master
                    // will time out + re-delegate. Nothing to retry to.
                    tracing::warn!(
                        task_id = %task_id,
                        error = %e,
                        "cluster executor: could not deliver TaskResult (peer gone)"
                    );
                }
            }
        }
        tracing::info!("cluster executor: dispatch channel closed, executor exiting");
    });
    tx
}

/// Run a single delegated task and build its `TaskResultBody`. Takes OWNED args
/// so it can run in an isolated sub-task (panic isolation). Transport-free —
/// returns the body to ship back.
async fn run_one_task(provider: Option<Arc<dyn Provider>>, job: ClusterTaskJob) -> TaskResultBody {
    let Some(provider) = provider else {
        // Honest failure (not theater): the master learns this node has no
        // provider + re-routes, instead of getting a fake OK.
        return TaskResultBody {
            task_id: job.task_id.clone(),
            status: TaskResultStatus::Failed {
                error: "no_provider_on_this_node".to_string(),
            },
            result: None,
            provider_name: None,
        };
    };
    let provider_name = provider.name().to_string();

    // The delegated prompt is the USER turn. The slave runs its OWN configured
    // provider (model_hint is advisory + ignored in this lane — no confused
    // deputy). The slave's own system/persona context is NOT bypassed.
    let req = Request {
        prompt: job.prompt.clone(),
        ..Default::default()
    };

    // Audit: a delegated call is a provider call on the operator's resources.
    // Local providers are cost-free ([[is_local_provider]]); a metered provider
    // running a peer's prompt is flagged so the audit chain distinguishes it.
    if !is_local_provider(&provider_name) {
        if let Some(w) = &job.wal_writer {
            emit_delegated_metered_call(w, &job.task_id, &provider_name);
        }
    }

    // Bound the inference wall-clock so a malicious master can't pin the single
    // executor / GPU indefinitely with a slow prompt.
    match tokio::time::timeout(TASK_INFERENCE_TIMEOUT, provider.complete(req)).await {
        Ok(Ok(completion)) => {
            let result = truncate_to_bytes(&completion.text, MAX_TASK_RESULT_BYTES);
            TaskResultBody {
                task_id: job.task_id.clone(),
                status: TaskResultStatus::Completed,
                result: Some(result),
                provider_name: Some(provider_name),
            }
        }
        Ok(Err(e)) => TaskResultBody {
            task_id: job.task_id.clone(),
            status: TaskResultStatus::Failed {
                // Redact — a provider error can echo prompt fragments / secrets.
                error: crate::security::redact::redact_text(&e.to_string()),
            },
            result: None,
            provider_name: Some(provider_name),
        },
        Err(_elapsed) => TaskResultBody {
            task_id: job.task_id.clone(),
            status: TaskResultStatus::Failed {
                error: "timeout".to_string(),
            },
            result: None,
            provider_name: Some(provider_name),
        },
    }
}

/// Truncate `s` to at most `max` bytes WITHOUT splitting a UTF-8 char. Appends
/// a visible marker when truncation happened so the master sees it was cut.
fn truncate_to_bytes(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    const MARKER: &str = "\n…[truncated by cluster slave]";
    // Edge: if `max` is too small to fit the marker, drop the marker and just
    // cut to a char boundary <= max (the byte cap is the hard contract).
    if max < MARKER.len() {
        let mut end = max.min(s.len());
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        return s[..end].to_string();
    }
    let budget = max - MARKER.len();
    // Find the largest char boundary <= budget.
    let mut end = budget.min(s.len());
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = s[..end].to_string();
    out.push_str(MARKER);
    out
}

/// Durable audit anchor: a delegated task ran on a METERED provider (cost on
/// the operator's account). Reuses the provider-request event band so it joins
/// the normal cost trail; the `cluster_delegated` marker + task_id distinguish
/// it from operator-initiated calls. Uses `try_append_sync` (not spawn+append)
/// so the frame is enqueued in the writer channel BEFORE we return — no
/// crash-window where the cost frame is lost (review finding).
fn emit_delegated_metered_call(writer: &WalWriterHandle, task_id: &str, provider_name: &str) {
    let payload = serde_json::json!({
        "cluster_delegated": true,
        "task_id": task_id,
        "provider": provider_name,
        "ts_unix": now_unix_secs(),
    })
    .to_string()
    .into_bytes();
    let header =
        crate::wal::HeaderBuilder::new(crate::wal::events::EVENT_TYPE_PROVIDER_REQUEST, &payload)
            .build();
    if let Err(e) = writer.try_append_sync(header, payload) {
        tracing::warn!(error = %e, "cluster executor: delegated-call audit append failed");
    }
}

fn now_unix_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn now_unix_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(prompt: &str) -> ClusterTaskJob {
        ClusterTaskJob {
            task_id: "t-1".into(),
            prompt: prompt.into(),
            reply_peer_pk: "aa".into(),
            wal_writer: None,
        }
    }

    #[tokio::test]
    async fn no_provider_yields_honest_failure_not_fake_ok() {
        let body = run_one_task(None, job("hi")).await;
        assert_eq!(body.task_id, "t-1");
        match body.status {
            TaskResultStatus::Failed { error } => assert_eq!(error, "no_provider_on_this_node"),
            other => panic!("expected Failed, got {other:?}"),
        }
        assert!(body.result.is_none(), "no fake result text");
    }

    #[test]
    fn truncate_respects_byte_cap_and_char_boundaries() {
        let s = "a".repeat(100_000);
        let out = truncate_to_bytes(&s, MAX_TASK_RESULT_BYTES);
        assert!(
            out.len() <= MAX_TASK_RESULT_BYTES,
            "stays under cap: {}",
            out.len()
        );
        assert!(out.ends_with("[truncated by cluster slave]"));

        // Multi-byte chars are not split.
        let multi = "€".repeat(20_000); // 3 bytes each = 60 KiB
        let cut = truncate_to_bytes(&multi, 1000);
        assert!(cut.len() <= 1000);
        assert!(cut.starts_with('€'), "valid UTF-8 preserved");
    }

    #[test]
    fn short_text_is_returned_verbatim() {
        let out = truncate_to_bytes("hello", MAX_TASK_RESULT_BYTES);
        assert_eq!(out, "hello");
    }

    #[tokio::test]
    async fn provider_error_is_redacted_failure() {
        use crate::providers::Completion;
        use async_trait::async_trait;
        struct ErrProvider;
        #[async_trait]
        impl Provider for ErrProvider {
            fn name(&self) -> &'static str {
                "local_qwen"
            }
            async fn complete(&self, _req: Request) -> anyhow::Result<Completion> {
                // A provider error that echoes a secret (the real leak risk).
                anyhow::bail!("upstream rejected key sk-ant-api03-AAAABBBBCCCCDDDDEEEE1234")
            }
        }
        let p: Option<Arc<dyn Provider>> = Some(Arc::new(ErrProvider));
        let body = run_one_task(p, job("hi")).await;
        match body.status {
            TaskResultStatus::Failed { error } => {
                // The secret must be scrubbed before it crosses the wire to the master.
                assert!(
                    !error.contains("sk-ant-api03-AAAABBBBCCCCDDDDEEEE1234"),
                    "secret must be redacted in the delegated-task error: {error}"
                );
                assert!(
                    error.contains("[REDACTED"),
                    "redaction marker present: {error}"
                );
            }
            other => panic!("expected Failed, got {other:?}"),
        }
        assert_eq!(body.provider_name.as_deref(), Some("local_qwen"));
    }

    #[tokio::test]
    async fn completion_is_returned_as_completed() {
        use crate::providers::Completion;
        use async_trait::async_trait;
        use std::time::Duration;
        struct OkProvider;
        #[async_trait]
        impl Provider for OkProvider {
            fn name(&self) -> &'static str {
                "local_qwen"
            }
            async fn complete(&self, req: Request) -> anyhow::Result<Completion> {
                Ok(Completion {
                    text: format!("echo: {}", req.prompt),
                    model: "qwen3".into(),
                    latency: Duration::from_millis(1),
                    input_tokens: Some(2),
                    output_tokens: Some(3),
                })
            }
        }
        let p: Option<Arc<dyn Provider>> = Some(Arc::new(OkProvider));
        let body = run_one_task(p, job("ping")).await;
        assert!(matches!(body.status, TaskResultStatus::Completed));
        assert_eq!(body.result.as_deref(), Some("echo: ping"));
        assert_eq!(body.provider_name.as_deref(), Some("local_qwen"));
    }
}
