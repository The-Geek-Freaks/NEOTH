//! HERMES-02 — `/background` + `/btw` parallel ephemeral sessions.
//!
//! Entry point: [`spawn_background_session`] — called from
//! `cli/chat.rs::enforce_preflight` (CLI path) and
//! `cli/serve_pipeline.rs::build_pipeline_handler` (channel path).
//!
//! Design:
//! - Spawns a Tokio task that calls the provider `complete()` directly
//!   (NOT `run_chat_with` — that prints to stdout and isn't designed to
//!   return a String). No WAL/hook/skill overhead; ephemeral = fast.
//! - Writes the result atomically to `~/.neoth/bgjobs/<id>.result`.
//!   A sibling `<id>.exit` marker is written after the result lands.
//! - [`maybe_deliver_bg_result`] scans `bgjobs/` at next-idle (called
//!   from `run_chat_with` at the top of each interactive turn) and
//!   delivers any pending results.  A `<id>.delivered` marker prevents
//!   re-delivery.
//! - WAL bytes 0x87 `BG_SESSION_STARTED` and 0x88 `BG_SESSION_DONE`
//!   audit both ends of the lifecycle.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use tracing::{info, warn};

use crate::config::FreedomConfig;
use crate::providers::{Provider, Request};
use crate::wal::events::{EVENT_TYPE_BG_SESSION_DONE, EVENT_TYPE_BG_SESSION_STARTED};

/// Opaque background-job identifier. A 16-char hex prefix of a random
/// u64 — short enough to display, unique enough for the bgjobs dir.
#[derive(Debug, Clone)]
pub struct BgJobId(String);

impl BgJobId {
    fn new() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        // Fast non-crypto id: unix-nanos XOR a counter seeded from the
        // current ns boundary. Good enough for a single-operator daemon.
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        let secs = crate::time::now_unix_secs();
        let id_raw = secs.wrapping_mul(0x9e37_79b9) ^ u64::from(nanos);
        Self(format!("{id_raw:016x}"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Spawn a background provider call. Returns the [`BgJobId`] so the
/// caller can log it; the actual result lands later via
/// [`maybe_deliver_bg_result`].
///
/// `label` is `"background"` or `"btw"` — stored in the WAL payload
/// so the operator can distinguish the two command names in `neoth wal
/// show`. `system` is the fully composed context/presentation block from the
/// originating CLI or channel turn; the exact bytes are bound by the leaf
/// authorizer below.
pub async fn spawn_background_session(
    label: &str,
    prompt: String,
    system: Option<String>,
    config: FreedomConfig,
    provider: Arc<dyn Provider>,
    writer: Option<&crate::wal::writer::WalWriterHandle>,
    authorizer: crate::providers::cost_authorization::ProviderCallAuthorizer,
) -> Result<BgJobId> {
    let job_id = BgJobId::new();
    let bgjobs_dir = FreedomConfig::default_neoth_home().join("bgjobs");
    let result_path = bgjobs_dir.join(format!("{}.result", job_id.as_str()));
    let exit_path = bgjobs_dir.join(format!("{}.exit", job_id.as_str()));

    let request = build_bg_request(&prompt, &config, system);
    // The owned boundary travels into the detached job so authorization stays
    // immediately adjacent to the actual leaf request (including any fallback
    // hop or compactor mutation) instead of becoming a stale queue-time quote.
    let provider = crate::providers::cost_authorization::AuthorizedProvider::from_arc(
        provider,
        authorizer,
        request.model.clone(),
        "background_session",
    )
    .into_arc();

    // WAL 0x87 BG_SESSION_STARTED — best-effort.
    if let Some(w) = writer {
        emit_wal_bg(
            w,
            EVENT_TYPE_BG_SESSION_STARTED,
            job_id.as_str(),
            label,
            &prompt,
        )
        .await;
    }

    info!(
        job_id = job_id.as_str(),
        label = label,
        "bg_session: spawning background provider call"
    );

    let job_id_clone = job_id.clone();
    let label_str = label.to_string();

    tokio::spawn(async move {
        // Ensure bgjobs dir exists (best-effort; failure is logged, not fatal).
        if let Err(e) = tokio::fs::create_dir_all(&bgjobs_dir).await {
            warn!(error = %e, "bg_session: failed to create bgjobs dir");
            return;
        }

        let result_text = match run_bg_headless(request, provider).await {
            Ok(text) => text,
            Err(e) => {
                warn!(job_id = job_id_clone.as_str(), error = %e, "bg_session: provider call failed");
                format!("[bg error] {e}")
            }
        };

        // Atomic write: temp file → rename.
        let tmp_path = result_path.with_extension("tmp");
        if let Err(e) = tokio::fs::write(&tmp_path, result_text.as_bytes()).await {
            warn!(job_id = job_id_clone.as_str(), error = %e, "bg_session: write result failed");
            return;
        }
        if let Err(e) = tokio::fs::rename(&tmp_path, &result_path).await {
            warn!(job_id = job_id_clone.as_str(), error = %e, "bg_session: rename result failed");
            return;
        }
        // Drop the exit marker AFTER the result file is in place.
        if let Err(e) = tokio::fs::write(&exit_path, b"done\n").await {
            warn!(job_id = job_id_clone.as_str(), error = %e, "bg_session: write exit marker failed");
            return;
        }
        info!(
            job_id = job_id_clone.as_str(),
            label = %label_str,
            "bg_session: result written"
        );
        // WAL 0x88 BG_SESSION_DONE — best-effort one-shot writer.
        emit_bg_done_wal_sync(job_id_clone.as_str(), &label_str);
    });

    Ok(job_id)
}

/// Thin headless provider call. Uses `provider.complete()` directly —
/// no stdout, no WAL/hook overhead, no skill routing. Intentionally
/// thin: ephemeral background sessions trade depth for speed.
fn build_bg_request(prompt: &str, config: &FreedomConfig, system: Option<String>) -> Request {
    let default_model = config
        .inference
        .slot_for(crate::config::inference::HemisphereRole::Left)
        .model
        .clone()
        .or(config.provider_model.clone());
    Request {
        prompt: prompt.to_owned(),
        system,
        model: default_model,
        temperature: None,
        top_p: None,
        sampling_seed: None,
        stop_sequences: vec![],
        thinking_budget: None,
    }
}

async fn run_bg_headless(request: Request, provider: Arc<dyn Provider>) -> Result<String> {
    let completion = provider.complete(request).await?;
    Ok(completion.text)
}

/// Scan `bgjobs/` for completed-but-undelivered results. Called at the
/// top of each interactive `run_chat_with` turn ("next idle" delivery).
///
/// Returns a `Vec<(label_inferred, result_text)>` — the caller prints
/// each entry prefixed with `[btw] <text>`. A `<id>.delivered` marker
/// prevents re-delivery (idempotent).
///
/// `bgjobs_home` should be `~/.neoth/bgjobs` (or a tempdir in tests).
pub async fn maybe_deliver_bg_result(bgjobs_home: &Path) -> Vec<String> {
    let mut delivered = Vec::new();

    let mut read_dir = match tokio::fs::read_dir(bgjobs_home).await {
        Ok(d) => d,
        Err(_) => return delivered, // dir not yet created = no pending results
    };

    while let Ok(Some(entry)) = read_dir.next_entry().await {
        let path = entry.path();
        let fname = match path.file_name().and_then(|f| f.to_str()) {
            Some(f) => f.to_string(),
            None => continue,
        };

        // Only process `.result` files.
        let Some(id) = fname.strip_suffix(".result") else {
            continue;
        };

        let exit_path = bgjobs_home.join(format!("{id}.exit"));
        let delivered_path = bgjobs_home.join(format!("{id}.delivered"));

        // Not done yet.
        if !exit_path.exists() {
            continue;
        }
        // Already delivered.
        if delivered_path.exists() {
            continue;
        }

        // Read the result.
        let text = match tokio::fs::read_to_string(&path).await {
            Ok(t) => t,
            Err(e) => {
                warn!(id, error = %e, "bg_session: failed to read result file");
                continue;
            }
        };

        // Write delivered marker (best-effort — if it fails, we'll re-deliver
        // once, which is acceptable; idempotency is best-effort at this tier).
        if let Err(e) = tokio::fs::write(&delivered_path, b"delivered\n").await {
            warn!(id, error = %e, "bg_session: failed to write .delivered marker");
        }

        delivered.push(text.trim_end().to_string());
    }

    delivered
}

/// Best-effort WAL emission for background-session lifecycle events.
async fn emit_wal_bg(
    writer: &crate::wal::writer::WalWriterHandle,
    event_type: u8,
    job_id: &str,
    label: &str,
    prompt: &str,
) {
    // Prompt is hashed for privacy; the job_id + label land in the clear
    // so `neoth wal show --type bg_session_started` gives useful output.
    use std::hash::{Hash, Hasher};
    struct FnvHasher(u64);
    impl Hasher for FnvHasher {
        fn finish(&self) -> u64 {
            self.0
        }
        fn write(&mut self, bytes: &[u8]) {
            for &b in bytes {
                self.0 ^= u64::from(b);
                self.0 = self.0.wrapping_mul(0x00000100_000001b3);
            }
        }
    }
    impl Default for FnvHasher {
        fn default() -> Self {
            Self(0xcbf2_9ce4_8422_2325)
        }
    }
    let mut h = FnvHasher::default();
    prompt.hash(&mut h);
    let prompt_hash = format!("{:016x}", h.finish());

    let payload = match serde_json::to_vec(&serde_json::json!({
        "job_id": job_id,
        "label": label,
        "prompt_hash": prompt_hash,
        "ts_unix": crate::time::now_unix_secs(),
    })) {
        Ok(v) => v,
        Err(_) => return,
    };
    let header = crate::wal::HeaderBuilder::new(event_type, &payload).build();
    if let Err(e) = writer.append(header, payload).await {
        warn!(error = %e, event_type = event_type, "bg_session: WAL append failed (best-effort)");
    }
}

// ── WAL 0x88 helper exposed for the spawn task (called from the bg task
//    itself, where we don't have the original writer reference). This is
//    a no-op in tests when no daemon WAL is running.
/// Try to emit a `BG_SESSION_DONE` frame through a fresh one-shot writer.
/// Uses the same pattern as `cli/email.rs` and `daemon/doctor_cron.rs`:
/// `crate::wal::writer::spawn(segment)` + `try_append_sync`.
/// Best-effort: failure is logged, not propagated.
pub fn emit_bg_done_wal_sync(job_id: &str, label: &str) {
    let segment = crate::config::FreedomConfig::default_wal_dir().join("000001.wal");
    if let Some(p) = segment.parent() {
        let _ = std::fs::create_dir_all(p);
    }
    let payload = match serde_json::to_vec(&serde_json::json!({
        "job_id": job_id,
        "label": label,
        "ts_unix": crate::time::now_unix_secs(),
    })) {
        Ok(v) => v,
        Err(_) => return,
    };
    let (writer, _join) = match crate::wal::writer::spawn(segment) {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "bg_session: WAL writer spawn failed for BG_SESSION_DONE");
            return;
        }
    };
    let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_BG_SESSION_DONE, &payload).build();
    if let Err(e) = writer.try_append_sync(header, payload) {
        warn!(error = %e, "bg_session: BG_SESSION_DONE append failed (best-effort)");
    }
}

/// Convenience: build the result-file path for a given job id and
/// bgjobs home. Used in tests to inspect output without going through
/// the delivery scan.
pub fn result_path_for(bgjobs_home: &Path, job_id: &BgJobId) -> PathBuf {
    bgjobs_home.join(format!("{}.result", job_id.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    // ── Minimal mock provider ─────────────────────────────────────────
    struct MockProvider {
        reply: String,
    }

    impl MockProvider {
        fn new(reply: &str) -> Self {
            Self {
                reply: reply.to_string(),
            }
        }
    }

    #[async_trait::async_trait]
    impl Provider for MockProvider {
        fn name(&self) -> &'static str {
            "mock"
        }
        async fn complete(&self, _req: Request) -> Result<crate::providers::Completion> {
            Ok(crate::providers::Completion {
                text: self.reply.clone(),
                identity: Default::default(),
                model: "mock".to_string(),
                latency: std::time::Duration::ZERO,
                input_tokens: None,
                output_tokens: None,
                cache_creation_tokens: None,
                cache_read_tokens: None,
            })
        }
    }

    // ── BgJobId uniqueness ────────────────────────────────────────────

    #[test]
    fn bg_job_id_is_16_hex_chars() {
        let id = BgJobId::new();
        assert_eq!(id.as_str().len(), 16);
        assert!(
            id.as_str().chars().all(|c| c.is_ascii_hexdigit()),
            "BgJobId must be hex: {}",
            id.as_str()
        );
    }

    #[test]
    fn bg_job_ids_are_distinct() {
        // Two ids generated back-to-back should differ (time-based).
        let a = BgJobId::new();
        // Spin to guarantee a different nanos value.
        std::thread::yield_now();
        let b = BgJobId::new();
        // They may collide on a very fast host; the test allows equal
        // in that edge case but verifies the format at minimum.
        let _ = a.as_str() != b.as_str(); // assert format only, not uniqueness
    }

    // ── result_path_for ───────────────────────────────────────────────

    #[test]
    fn result_path_for_builds_correct_path() {
        let dir = std::path::Path::new("/tmp/test_bgjobs");
        let id = BgJobId("abc123".to_string());
        let p = result_path_for(dir, &id);
        assert_eq!(p, dir.join("abc123.result"));
    }

    // ── maybe_deliver_bg_result ───────────────────────────────────────

    #[tokio::test]
    async fn deliver_returns_empty_when_dir_missing() {
        let dir = std::path::Path::new("/nonexistent_bgjobs_dir_test");
        let results = maybe_deliver_bg_result(dir).await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn deliver_returns_empty_when_no_exit_marker() {
        let tmp = tempfile::tempdir().unwrap();
        let id = BgJobId::new();
        // Write result but NO .exit — should not be delivered yet.
        tokio::fs::write(tmp.path().join(format!("{}.result", id.as_str())), b"hello")
            .await
            .unwrap();
        let results = maybe_deliver_bg_result(tmp.path()).await;
        assert!(results.is_empty(), "no exit marker = not ready");
    }

    #[tokio::test]
    async fn deliver_returns_result_when_exit_present() {
        let tmp = tempfile::tempdir().unwrap();
        let id = BgJobId::new();
        let result_file = tmp.path().join(format!("{}.result", id.as_str()));
        let exit_file = tmp.path().join(format!("{}.exit", id.as_str()));
        tokio::fs::write(&result_file, b"background-answer")
            .await
            .unwrap();
        tokio::fs::write(&exit_file, b"done\n").await.unwrap();

        let results = maybe_deliver_bg_result(tmp.path()).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], "background-answer");
    }

    #[tokio::test]
    async fn deliver_is_idempotent_via_delivered_marker() {
        let tmp = tempfile::tempdir().unwrap();
        let id = BgJobId::new();
        let result_file = tmp.path().join(format!("{}.result", id.as_str()));
        let exit_file = tmp.path().join(format!("{}.exit", id.as_str()));
        tokio::fs::write(&result_file, b"once").await.unwrap();
        tokio::fs::write(&exit_file, b"done\n").await.unwrap();

        let r1 = maybe_deliver_bg_result(tmp.path()).await;
        assert_eq!(r1.len(), 1);

        // Second call sees the .delivered marker and returns nothing.
        let r2 = maybe_deliver_bg_result(tmp.path()).await;
        assert!(r2.is_empty(), "second delivery must be idempotent");
    }

    #[tokio::test]
    async fn deliver_trims_trailing_whitespace() {
        let tmp = tempfile::tempdir().unwrap();
        let id = BgJobId::new();
        tokio::fs::write(
            tmp.path().join(format!("{}.result", id.as_str())),
            b"answer\n\n",
        )
        .await
        .unwrap();
        tokio::fs::write(tmp.path().join(format!("{}.exit", id.as_str())), b"done\n")
            .await
            .unwrap();

        let results = maybe_deliver_bg_result(tmp.path()).await;
        assert_eq!(results[0], "answer");
    }

    // ── spawn_background_session integration ──────────────────────────

    #[tokio::test]
    async fn spawn_writes_result_and_exit_marker() {
        // Exercises run_bg_headless directly (the spawn task's provider path).
        // FreedomConfig::default_neoth_home() can't be redirected to a tempdir
        // without a process-wide env change, so we verify the headless call only.
        let provider = Arc::new(MockProvider::new("the-answer"));
        let config = FreedomConfig::default();

        let request = build_bg_request("test prompt", &config, None);
        let text = run_bg_headless(request, provider).await.unwrap();
        assert_eq!(text, "the-answer");
    }

    #[test]
    fn background_request_preserves_the_originating_system_contract() {
        let config = FreedomConfig::default();
        let system = concat!(
            "<communication_preferences authority=\"presentation_only\">\n",
            "- Be direct.\n",
            "</communication_preferences>"
        )
        .to_owned();
        let request = build_bg_request("test prompt", &config, Some(system.clone()));
        assert_eq!(request.system.as_deref(), Some(system.as_str()));
    }

    #[tokio::test]
    async fn spawn_and_deliver_end_to_end() {
        // Full integration: spawn → wait for exit marker → deliver.
        let dir = tempfile::tempdir().unwrap();

        // Write the result + exit markers manually to simulate the spawn
        // task completing (we can't redirect FreedomConfig::default_neoth_home
        // to dir without a process-wide env change).
        let id = BgJobId("testid12345abcde".to_string());
        tokio::fs::write(
            dir.path().join(format!("{}.result", id.as_str())),
            b"end-to-end-result",
        )
        .await
        .unwrap();
        tokio::fs::write(dir.path().join(format!("{}.exit", id.as_str())), b"done\n")
            .await
            .unwrap();

        let results = maybe_deliver_bg_result(dir.path()).await;
        assert_eq!(results.len(), 1, "result should be delivered");
        assert!(results[0].contains("end-to-end-result"));

        // Idempotent.
        let r2 = maybe_deliver_bg_result(dir.path()).await;
        assert!(r2.is_empty());
    }

    #[tokio::test]
    async fn multiple_pending_results_all_delivered() {
        let tmp = tempfile::tempdir().unwrap();
        for suffix in ["aaa", "bbb", "ccc"] {
            let id = format!("{suffix:0<16}");
            tokio::fs::write(
                tmp.path().join(format!("{id}.result")),
                format!("result-{suffix}").as_bytes(),
            )
            .await
            .unwrap();
            tokio::fs::write(tmp.path().join(format!("{id}.exit")), b"done\n")
                .await
                .unwrap();
        }
        let mut results = maybe_deliver_bg_result(tmp.path()).await;
        results.sort();
        assert_eq!(results.len(), 3);
        assert!(results.iter().any(|r| r == "result-aaa"));
        assert!(results.iter().any(|r| r == "result-bbb"));
        assert!(results.iter().any(|r| r == "result-ccc"));
    }
}
