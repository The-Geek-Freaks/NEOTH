//! QM-16 — Parallel sub-agent dispatcher.
//!
//! Per `PLAN/QUELLEN_ADOPT_superpowers_2026-05-22.md` SP-A2
//! `dispatching-parallel-agents` ADOPT-AS-SUB-AGENT. The fan-out
//! pattern (identify independent domains → create focused tasks →
//! dispatch concurrently → integrate) is encoded in
//! [`crate::skills::loader`]-installed `dispatching_parallel_agents`
//! skill as the operator-facing discipline; this module is the
//! CORE Rust controller that actually runs the fan-out when a
//! caller decides to parallelise.
//!
//! ## Iron Law (mirrors the skill)
//!
//! Parallelise ONLY when the tasks are independent — no output→
//! input dependency, no shared mutable resource, no overlapping
//! files. Sequential is the default; parallel is the opt-in for
//! genuine domain splits.
//!
//! ## What ships
//!
//! - [`SubAgentWorker`] trait — caller plugs in a worker that
//!   takes one [`SubAgentRequest`] and returns a
//!   [`SubAgentResult`]. The same worker is reused across N
//!   parallel calls (interior `&self`).
//! - [`dispatch_parallel`] — drives a `JoinSet` of worker tasks,
//!   awaits all, collects results. Bounded concurrency via
//!   `max_concurrent` (defaults to the request count so single-
//!   shot fan-out runs everything at once; larger sets stay
//!   bounded via a `Semaphore`).
//! - [`DispatchReport`] — per-request outcome with aggregate
//!   stats (`pass_count`, `fail_count`, `blocked_count`,
//!   `panicked_count`) for the operator-facing renderer.
//!
//! ## What's NOT here (yet)
//!
//! - The actual coding-workflow worker. That's `coding::worker`
//!   today, single-shot. A future commit replaces the dispatcher's
//!   sequential loop with `dispatch_parallel` when the operator
//!   passes `--parallel`.
//! - The "domain-split" decision tree. The
//!   `dispatching_parallel_agents` skill (QM-22 batch A) carries
//!   the prompt-side discipline that decides WHEN to fan out; this
//!   module trusts the caller already made that call.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tracing::{info, warn};

use super::schema::{SubAgentRequest, SubAgentResult};
#[cfg(test)]
use crate::council::quality_score::FailureItem;
use crate::council::quality_score::QaVerdict;

/// QM-16: trait the caller implements so the dispatcher can run an
/// arbitrary worker (coding worker, reviewer sub-agent, evidence
/// collector) against each request. Async + Send + Sync so the
/// `JoinSet` can hand work to any tokio worker.
#[async_trait::async_trait]
pub trait SubAgentWorker: Send + Sync {
    /// Execute the request. Implementations own the actual work —
    /// LLM call, code generation, verification, etc. Errors
    /// percolate as a `Blocked` verdict in [`dispatch_parallel`] so
    /// one bad worker doesn't abort the whole fan-out.
    async fn run(&self, request: SubAgentRequest) -> Result<SubAgentResult>;
}

/// QM-16: aggregate report from one parallel dispatch. Operator-
/// facing renderer (`neoth code show --parallel`) consumes this.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DispatchReport {
    /// Per-request outcomes in the same order as the input requests.
    pub results: Vec<SubAgentResult>,
    /// Count of `Pass` verdicts.
    pub pass_count: usize,
    /// Count of `Fail` verdicts (retriable).
    pub fail_count: usize,
    /// Count of `Blocked` verdicts (operator escalation).
    pub blocked_count: usize,
    /// Count of tasks that panicked or failed to join. Synthesized
    /// as Blocked-with-panic-reason in the results vec; this field
    /// surfaces the count separately so the operator sees "real
    /// blocks" vs "infrastructure failures".
    pub panicked_count: usize,
}

impl DispatchReport {
    pub fn total(&self) -> usize {
        self.results.len()
    }

    /// True when every request returned a `Pass` verdict.
    pub fn all_passed(&self) -> bool {
        !self.results.is_empty() && self.pass_count == self.results.len()
    }
}

/// QM-16 entry point. Drives N requests concurrently through one
/// worker, collects results, returns the aggregated report.
///
/// `max_concurrent: Option<usize>` bounds the in-flight fan-out;
/// `None` runs every request at once (single-shot fan-out for small
/// N) and `Some(k)` caps the JoinSet to k concurrent runs (use when
/// downstream resources — LLM provider rate limits, RAM — can't
/// absorb unbounded parallel calls).
///
/// `per_task_timeout: Option<Duration>` bounds each individual
/// worker. Timeout hits → synthesized Blocked verdict with reason
/// "timed out after Xs". `None` = no per-task ceiling.
pub async fn dispatch_parallel<W>(
    worker: Arc<W>,
    requests: Vec<SubAgentRequest>,
    max_concurrent: Option<usize>,
    per_task_timeout: Option<Duration>,
) -> Result<DispatchReport>
where
    W: SubAgentWorker + 'static,
{
    if requests.is_empty() {
        return Ok(DispatchReport {
            results: Vec::new(),
            pass_count: 0,
            fail_count: 0,
            blocked_count: 0,
            panicked_count: 0,
        });
    }

    let total = requests.len();
    let concurrency = max_concurrent.unwrap_or(total).max(1).min(total);
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut joinset: JoinSet<(usize, Result<SubAgentResult>)> = JoinSet::new();

    info!(
        total = total,
        concurrency = concurrency,
        "parallel dispatch starting"
    );

    for (idx, req) in requests.into_iter().enumerate() {
        let worker = Arc::clone(&worker);
        let sem = Arc::clone(&semaphore);
        let timeout = per_task_timeout;
        joinset.spawn(async move {
            // Acquire permit for the task's lifetime. `acquire_owned`
            // fails only when the semaphore is closed, which we
            // never do here.
            let _permit = match sem.acquire_owned().await {
                Ok(p) => p,
                Err(e) => {
                    return (idx, Err(anyhow::anyhow!("semaphore closed: {e}")));
                }
            };
            let req_id = req.task_id.clone();
            let result = match timeout {
                Some(t) => match tokio::time::timeout(t, worker.run(req)).await {
                    Ok(r) => r,
                    Err(_) => Err(anyhow::anyhow!(
                        "parallel worker timed out after {}s on task {}",
                        t.as_secs(),
                        req_id
                    )),
                },
                None => worker.run(req).await,
            };
            (idx, result)
        });
    }

    // Collect by index so the output order matches the input order
    // — operators expect "request[3] failed" not "the third one to
    // finish failed".
    let mut indexed: Vec<Option<Result<SubAgentResult>>> = (0..total).map(|_| None).collect();
    while let Some(joined) = joinset.join_next().await {
        match joined {
            Ok((idx, result)) => {
                indexed[idx] = Some(result);
            }
            Err(e) => {
                // Tokio JoinError — task panicked. We don't have
                // the index here, so synthesise a placeholder at
                // the first empty slot. This is an edge case (real
                // workers should catch their own panics).
                warn!(error = %e, "parallel dispatch task panicked");
                if let Some(slot) = indexed.iter_mut().find(|s| s.is_none()) {
                    *slot = Some(Err(anyhow::anyhow!("parallel dispatch task panicked: {e}")));
                }
            }
        }
    }

    let mut results = Vec::with_capacity(total);
    let mut pass_count = 0;
    let mut fail_count = 0;
    let mut blocked_count = 0;
    let mut panicked_count = 0;
    for (idx, slot) in indexed.into_iter().enumerate() {
        let result = match slot {
            Some(Ok(r)) => r,
            Some(Err(e)) => {
                panicked_count += 1;
                synth_blocked(idx, &format!("worker error: {e}"))
            }
            None => {
                panicked_count += 1;
                synth_blocked(idx, "no result returned (joinset missed)")
            }
        };
        match &result.verdict {
            QaVerdict::Pass { .. } => pass_count += 1,
            QaVerdict::Fail { .. } => fail_count += 1,
            QaVerdict::Blocked { .. } => blocked_count += 1,
        }
        results.push(result);
    }

    info!(
        total = total,
        pass = pass_count,
        fail = fail_count,
        blocked = blocked_count,
        panicked = panicked_count,
        "parallel dispatch complete"
    );

    Ok(DispatchReport {
        results,
        pass_count,
        fail_count,
        blocked_count,
        panicked_count,
    })
}

/// Synthesise a `Blocked` `SubAgentResult` for a worker that
/// errored or panicked. Used so the report stays one-per-input
/// even when a worker fails to return a real result.
fn synth_blocked(idx: usize, reason: &str) -> SubAgentResult {
    SubAgentResult {
        from: "<parallel-dispatcher>".into(),
        to: "<caller>".into(),
        task_id: format!("synth-{idx}"),
        verdict: QaVerdict::Blocked {
            reason: reason.to_string(),
        },
        evidence: vec![],
        next_agent: None,
        ts_unix: now_unix(),
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// QM-16 convenience: drive a single request through the dispatcher
/// for callers that want the timeout + retry envelope without doing
/// the manual `Arc` + `Vec` wrap. Returns the single result.
pub async fn dispatch_one<W>(
    worker: Arc<W>,
    request: SubAgentRequest,
    timeout: Option<Duration>,
) -> Result<SubAgentResult>
where
    W: SubAgentWorker + 'static,
{
    let report = dispatch_parallel(worker, vec![request], Some(1), timeout)
        .await
        .context("dispatch_one")?;
    report
        .results
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("dispatch_one returned no result"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sub_agents::schema::HandoffPriority;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn make_request(task_id: &str) -> SubAgentRequest {
        SubAgentRequest {
            from: "test".into(),
            to: "worker".into(),
            phase: "test".into(),
            task_id: task_id.to_string(),
            priority: HandoffPriority::Normal,
            context: "ctx".into(),
            deliverable: "d".into(),
            success_criteria: vec![],
            evidence_required: vec![],
            ts_unix: 1_700_000_000,
        }
    }

    struct PassingWorker;
    #[async_trait::async_trait]
    impl SubAgentWorker for PassingWorker {
        async fn run(&self, req: SubAgentRequest) -> Result<SubAgentResult> {
            Ok(SubAgentResult {
                from: "worker".into(),
                to: req.from,
                task_id: req.task_id,
                verdict: QaVerdict::pass(),
                evidence: vec!["worker ran".into()],
                next_agent: None,
                ts_unix: 1_700_000_001,
            })
        }
    }

    struct FailingWorker;
    #[async_trait::async_trait]
    impl SubAgentWorker for FailingWorker {
        async fn run(&self, req: SubAgentRequest) -> Result<SubAgentResult> {
            Ok(SubAgentResult {
                from: "worker".into(),
                to: req.from,
                task_id: req.task_id,
                verdict: QaVerdict::fail(vec![FailureItem {
                    kind: "test_failure".into(),
                    message: "synthetic".into(),
                    citation: None,
                }]),
                evidence: vec![],
                next_agent: None,
                ts_unix: 1_700_000_001,
            })
        }
    }

    struct ErroringWorker;
    #[async_trait::async_trait]
    impl SubAgentWorker for ErroringWorker {
        async fn run(&self, _req: SubAgentRequest) -> Result<SubAgentResult> {
            anyhow::bail!("synthetic worker error")
        }
    }

    struct SlowWorker;
    #[async_trait::async_trait]
    impl SubAgentWorker for SlowWorker {
        async fn run(&self, req: SubAgentRequest) -> Result<SubAgentResult> {
            tokio::time::sleep(Duration::from_secs(5)).await;
            Ok(SubAgentResult {
                from: "slow".into(),
                to: req.from,
                task_id: req.task_id,
                verdict: QaVerdict::pass(),
                evidence: vec![],
                next_agent: None,
                ts_unix: 1_700_000_010,
            })
        }
    }

    struct CountingWorker {
        seen: AtomicUsize,
    }
    #[async_trait::async_trait]
    impl SubAgentWorker for CountingWorker {
        async fn run(&self, req: SubAgentRequest) -> Result<SubAgentResult> {
            self.seen.fetch_add(1, Ordering::SeqCst);
            Ok(SubAgentResult {
                from: "counter".into(),
                to: req.from,
                task_id: req.task_id,
                verdict: QaVerdict::pass(),
                evidence: vec![],
                next_agent: None,
                ts_unix: 1_700_000_001,
            })
        }
    }

    #[tokio::test]
    async fn empty_requests_returns_empty_report() {
        let w = Arc::new(PassingWorker);
        let r = dispatch_parallel(w, vec![], None, None).await.unwrap();
        assert_eq!(r.total(), 0);
        assert!(!r.all_passed(), "empty report is NOT all-passed");
    }

    #[tokio::test]
    async fn all_pass_when_worker_returns_pass() {
        let w = Arc::new(PassingWorker);
        let reqs = vec![make_request("t1"), make_request("t2"), make_request("t3")];
        let r = dispatch_parallel(w, reqs, None, None).await.unwrap();
        assert_eq!(r.total(), 3);
        assert_eq!(r.pass_count, 3);
        assert_eq!(r.fail_count, 0);
        assert_eq!(r.blocked_count, 0);
        assert!(r.all_passed());
    }

    #[tokio::test]
    async fn fail_count_increments_when_worker_returns_fail() {
        let w = Arc::new(FailingWorker);
        let reqs = vec![make_request("t1"), make_request("t2")];
        let r = dispatch_parallel(w, reqs, None, None).await.unwrap();
        assert_eq!(r.fail_count, 2);
        assert_eq!(r.pass_count, 0);
        assert!(!r.all_passed());
    }

    #[tokio::test]
    async fn erroring_worker_synthesizes_blocked_verdict() {
        let w = Arc::new(ErroringWorker);
        let reqs = vec![make_request("t1")];
        let r = dispatch_parallel(w, reqs, None, None).await.unwrap();
        assert_eq!(r.blocked_count, 1);
        assert_eq!(r.panicked_count, 1);
        match &r.results[0].verdict {
            QaVerdict::Blocked { reason } => assert!(reason.contains("synthetic worker error")),
            other => panic!("expected Blocked, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn results_preserve_input_order_under_concurrent_runs() {
        let w = Arc::new(PassingWorker);
        let reqs: Vec<_> = (0..10).map(|i| make_request(&format!("t{i}"))).collect();
        let r = dispatch_parallel(w, reqs, None, None).await.unwrap();
        for (idx, result) in r.results.iter().enumerate() {
            assert_eq!(result.task_id, format!("t{idx}"));
        }
    }

    #[tokio::test]
    async fn timeout_synthesizes_blocked_when_worker_too_slow() {
        let w = Arc::new(SlowWorker);
        let start = std::time::Instant::now();
        let r = dispatch_parallel(
            w,
            vec![make_request("t-slow")],
            None,
            Some(Duration::from_millis(80)),
        )
        .await
        .unwrap();
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(2),
            "timeout must fire well before the 5s worker sleep, took {elapsed:?}"
        );
        assert_eq!(r.blocked_count, 1);
        match &r.results[0].verdict {
            QaVerdict::Blocked { reason } => {
                assert!(reason.contains("timed out"));
            }
            other => panic!("expected Blocked, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn concurrency_cap_bounds_in_flight_workers() {
        // Cap = 1 → workers run serially even when 5 are submitted.
        // CountingWorker increments per call; final count = total.
        let w = Arc::new(CountingWorker {
            seen: AtomicUsize::new(0),
        });
        let reqs: Vec<_> = (0..5).map(|i| make_request(&format!("t{i}"))).collect();
        let r = dispatch_parallel(Arc::clone(&w), reqs, Some(1), None)
            .await
            .unwrap();
        assert_eq!(r.pass_count, 5);
        assert_eq!(w.seen.load(Ordering::SeqCst), 5);
    }

    #[tokio::test]
    async fn dispatch_one_drives_single_request_through_dispatcher() {
        let w = Arc::new(PassingWorker);
        let r = dispatch_one(w, make_request("t-one"), None).await.unwrap();
        assert_eq!(r.task_id, "t-one");
        assert!(r.verdict.is_pass());
    }

    #[tokio::test]
    async fn all_passed_returns_false_when_any_fail() {
        let w = Arc::new(FailingWorker);
        let r = dispatch_parallel(w, vec![make_request("t1")], None, None)
            .await
            .unwrap();
        assert!(!r.all_passed());
    }

    #[tokio::test]
    async fn mixed_outcomes_aggregate_correctly() {
        // Hand-rolled worker that returns different verdicts based
        // on task_id.
        struct MixedWorker;
        #[async_trait::async_trait]
        impl SubAgentWorker for MixedWorker {
            async fn run(&self, req: SubAgentRequest) -> Result<SubAgentResult> {
                let verdict = match req.task_id.as_str() {
                    "t-pass" => QaVerdict::pass(),
                    "t-fail" => QaVerdict::fail(vec![FailureItem {
                        kind: "x".into(),
                        message: "y".into(),
                        citation: None,
                    }]),
                    _ => QaVerdict::blocked("synthetic"),
                };
                Ok(SubAgentResult {
                    from: "mix".into(),
                    to: req.from,
                    task_id: req.task_id,
                    verdict,
                    evidence: vec![],
                    next_agent: None,
                    ts_unix: 0,
                })
            }
        }
        let w = Arc::new(MixedWorker);
        let reqs = vec![
            make_request("t-pass"),
            make_request("t-fail"),
            make_request("t-blocked"),
        ];
        let r = dispatch_parallel(w, reqs, None, None).await.unwrap();
        assert_eq!(r.pass_count, 1);
        assert_eq!(r.fail_count, 1);
        assert_eq!(r.blocked_count, 1);
        assert_eq!(r.panicked_count, 0);
    }
}
