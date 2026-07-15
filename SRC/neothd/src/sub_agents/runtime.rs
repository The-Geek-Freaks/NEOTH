//! Production provider-backed sub-agent fan-out and structured QA.
//!
//! Every provider call enters through an [`crate::providers::cost_authorization::AuthorizedProvider`]
//! supplied by the caller. This module trusts only the B22-stamped
//! [`crate::providers::CompletionIdentity`], emits content-free QA metadata to
//! WAL, and hard-caps correction to one operator-enabled retry.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::SubAgent;
use super::parallel::SubAgentWorker;
use super::schema::{SubAgentProviderCall, SubAgentRequest, SubAgentResult};
use crate::council::qa_verdict::QaVerdict;
use crate::providers::{Completion, Provider, Request};
use crate::wal::writer::WalWriterHandle;

pub const MAX_FAN_OUT: usize = 8;
pub const MAX_CONCURRENT: usize = 4;
pub const MAX_PROMPT_BYTES: usize = 64 * 1024;
const MAX_SYSTEM_BYTES: usize = 64 * 1024;
const MAX_QA_CANDIDATE_BYTES: usize = 128 * 1024;
const MAX_QA_RETRIES: u8 = 1;

#[derive(Debug)]
pub struct QaCallOutcome {
    pub verdict: std::result::Result<QaVerdict, String>,
    pub call: SubAgentProviderCall,
    pub response_hash_xxh3: u64,
}

/// Run named provider-only agents through the real parallel controller.
/// Host tools are deliberately absent on this bounded CLI path; the system
/// prompt says so explicitly instead of letting a model fabricate tool use.
pub struct ProviderSubAgentWorker {
    provider: Arc<dyn Provider>,
    agents: HashMap<String, SubAgent>,
    retry_failed: bool,
    writer: WalWriterHandle,
}

impl ProviderSubAgentWorker {
    pub fn new(
        provider: Arc<dyn Provider>,
        agents: impl IntoIterator<Item = SubAgent>,
        retry_failed: bool,
        writer: WalWriterHandle,
    ) -> Self {
        Self {
            provider,
            agents: agents
                .into_iter()
                .map(|agent| (agent.name.clone(), agent))
                .collect(),
            retry_failed,
            writer,
        }
    }
}

#[async_trait::async_trait]
impl SubAgentWorker for ProviderSubAgentWorker {
    async fn run(&self, request: SubAgentRequest) -> Result<SubAgentResult> {
        let agent = self
            .agents
            .get(&request.to)
            .with_context(|| format!("sub-agent `{}` disappeared before dispatch", request.to))?;
        validate_request(agent, &request)?;

        let mut prompt = request.context.clone();
        let mut provider_calls = Vec::with_capacity(4);
        let mut output = String::new();
        let max_attempts = 1 + u8::from(self.retry_failed) * MAX_QA_RETRIES;

        for attempt in 1..=max_attempts {
            let completion = self
                .provider
                .complete(Request {
                    prompt: prompt.clone(),
                    system: Some(agent_system(agent)),
                    model: agent.model.clone(),
                    ..Request::default()
                })
                .await
                .with_context(|| format!("sub-agent `{}` primary attempt {attempt}", agent.name))?;
            let primary_call = provider_call("primary", attempt, &completion)?;
            output = completion.text;
            provider_calls.push(primary_call);

            if output.len() > MAX_QA_CANDIDATE_BYTES {
                let verdict = QaVerdict::blocked(format!(
                    "candidate is {} bytes; bounded QA limit is {MAX_QA_CANDIDATE_BYTES}",
                    output.len()
                ));
                emit_qa_verdict(
                    &self.writer,
                    &request.task_id,
                    &agent.name,
                    attempt,
                    &verdict,
                    &output,
                    provider_calls.last(),
                )
                .await?;
                return Ok(result(
                    agent,
                    request,
                    verdict,
                    output,
                    provider_calls,
                    attempt,
                ));
            }

            let qa = match request_qa_verdict(
                self.provider.as_ref(),
                &request,
                &output,
                agent.model.clone(),
                attempt,
            )
            .await
            {
                Ok(qa) => qa,
                Err(error) => {
                    let verdict = QaVerdict::blocked(format!("QA provider call failed: {error:#}"));
                    emit_qa_verdict(
                        &self.writer,
                        &request.task_id,
                        &agent.name,
                        attempt,
                        &verdict,
                        &output,
                        provider_calls.last(),
                    )
                    .await?;
                    return Ok(result(
                        agent,
                        request,
                        verdict,
                        output,
                        provider_calls,
                        attempt,
                    ));
                }
            };
            provider_calls.push(qa.call);

            let verdict = match qa.verdict {
                Ok(verdict) => verdict,
                Err(error) => QaVerdict::blocked(format!("malformed QA verdict: {error}")),
            };
            emit_qa_verdict(
                &self.writer,
                &request.task_id,
                &agent.name,
                attempt,
                &verdict,
                &output,
                provider_calls.last(),
            )
            .await?;

            if verdict.is_retriable() && attempt < max_attempts {
                prompt = retry_prompt(&request.context, &output, &verdict)?;
                continue;
            }
            return Ok(result(
                agent,
                request,
                verdict,
                output,
                provider_calls,
                attempt,
            ));
        }

        unreachable!("max_attempts is always at least one")
    }
}

fn validate_request(agent: &SubAgent, request: &SubAgentRequest) -> Result<()> {
    if request.context.trim().is_empty() {
        anyhow::bail!("sub-agent task prompt is empty");
    }
    if request.context.len() > MAX_PROMPT_BYTES {
        anyhow::bail!(
            "sub-agent task prompt is {} bytes; limit is {MAX_PROMPT_BYTES}",
            request.context.len()
        );
    }
    if agent.system.trim().is_empty() || agent.system.len() > MAX_SYSTEM_BYTES {
        anyhow::bail!(
            "sub-agent `{}` system prompt is empty or exceeds {MAX_SYSTEM_BYTES} bytes",
            agent.name
        );
    }
    Ok(())
}

fn agent_system(agent: &SubAgent) -> String {
    format!(
        "{}\n\nRuntime boundary: this bounded fan-out call exposes no host tools. \
         Use only the operator-supplied task. Do not claim to have read files, \
         run commands, called tools, or verified external state unless that \
         evidence is present in the task itself.",
        agent.system
    )
}

fn provider_call(
    stage: &str,
    attempt: u8,
    completion: &Completion,
) -> Result<SubAgentProviderCall> {
    if !completion.identity.is_bound() {
        anyhow::bail!("provider returned a completion without a B22-bound leaf identity");
    }
    Ok(SubAgentProviderCall {
        stage: stage.to_string(),
        attempt,
        provider: completion.identity.provider.clone(),
        wire_model: completion.identity.wire_model.clone(),
        input_tokens: completion.input_tokens,
        output_tokens: completion.output_tokens,
    })
}

fn result(
    agent: &SubAgent,
    request: SubAgentRequest,
    verdict: QaVerdict,
    output: String,
    provider_calls: Vec<SubAgentProviderCall>,
    attempts: u8,
) -> SubAgentResult {
    let evidence = provider_calls
        .iter()
        .map(|call| {
            format!(
                "{}#{}={}/{}",
                call.stage, call.attempt, call.provider, call.wire_model
            )
        })
        .collect();
    SubAgentResult {
        from: agent.name.clone(),
        to: request.from,
        task_id: request.task_id,
        verdict,
        evidence,
        output,
        provider_calls,
        attempts,
        next_agent: None,
        ts_unix: crate::time::now_unix_i64(),
    }
}

fn qa_system_prompt() -> &'static str {
    r#"You are a strict QA verifier. Judge only the supplied task, acceptance criteria, requested evidence, and candidate output. Never infer hidden tool use or external verification.

Return exactly one JSON object and no markdown:
{"kind":"pass","evidence":["specific evidence"]}
or
{"kind":"fail","failures":[{"kind":"lowercase_ascii_slug","message":"specific defect","citation":null}]}
or
{"kind":"blocked","reason":"specific missing prerequisite"}

Pass only when every acceptance criterion is met. Fail means the candidate itself can be corrected. Blocked means external evidence or access is missing and retrying the same task cannot fix it."#
}

fn qa_prompt(request: &SubAgentRequest, candidate: &str) -> Result<String> {
    let contract = serde_json::to_string(&serde_json::json!({
        "task_id": request.task_id,
        "agent": request.to,
        "deliverable": request.deliverable,
        "success_criteria": request.success_criteria,
        "evidence_required": request.evidence_required,
    }))?;
    Ok(format!(
        "<qa_contract>{contract}</qa_contract>\n<operator_task>{}</operator_task>\n<candidate>{candidate}</candidate>",
        request.context
    ))
}

pub async fn request_qa_verdict(
    provider: &dyn Provider,
    request: &SubAgentRequest,
    candidate: &str,
    model: Option<String>,
    attempt: u8,
) -> Result<QaCallOutcome> {
    if candidate.len() > MAX_QA_CANDIDATE_BYTES {
        anyhow::bail!("candidate exceeds bounded QA limit");
    }
    let temperature = crate::providers::internal_temperature(provider, 0.0, "sub_agents.qa");
    let completion = provider
        .complete(Request {
            prompt: qa_prompt(request, candidate)?,
            system: Some(qa_system_prompt().to_string()),
            model,
            temperature,
            ..Request::default()
        })
        .await
        .context("structured QA provider call")?;
    let call = provider_call("qa", attempt, &completion)?;
    let response_hash_xxh3 = xxhash_rust::xxh3::xxh3_64(completion.text.as_bytes());
    let verdict = parse_qa_verdict(&completion.text);
    Ok(QaCallOutcome {
        verdict,
        call,
        response_hash_xxh3,
    })
}

pub fn parse_qa_verdict(text: &str) -> std::result::Result<QaVerdict, String> {
    let verdict: QaVerdict = serde_json::from_str(text.trim())
        .map_err(|error| format!("expected one strict JSON object: {error}"))?;
    verdict.validate()?;
    Ok(verdict)
}

fn retry_prompt(original: &str, candidate: &str, verdict: &QaVerdict) -> Result<String> {
    debug_assert!(verdict.is_retriable());
    let failures = serde_json::to_string(verdict)?;
    Ok(format!(
        "Correct the previous answer once. Return a complete replacement, not a patch to the prose.\n\n\
         <operator_task>{original}</operator_task>\n\
         <previous_candidate>{candidate}</previous_candidate>\n\
         <qa_failures>{failures}</qa_failures>"
    ))
}

/// Content-free WAL event. `0x84` remains backward-compatible with the older
/// two-stage review event; `schema` distinguishes the structured aggregate.
pub async fn emit_qa_verdict(
    writer: &WalWriterHandle,
    task_id: &str,
    agent_name: &str,
    attempt: u8,
    verdict: &QaVerdict,
    candidate: &str,
    qa_call: Option<&SubAgentProviderCall>,
) -> Result<()> {
    let verdict_bytes = serde_json::to_vec(verdict)?;
    let (kind, failure_count, evidence_count) = match verdict {
        QaVerdict::Pass { evidence } => ("pass", 0, evidence.len()),
        QaVerdict::Fail { failures } => ("fail", failures.len(), 0),
        QaVerdict::Blocked { .. } => ("blocked", 0, 0),
    };
    let payload = serde_json::to_vec(&serde_json::json!({
        "schema": "neoth.qa-verdict.v1",
        "task_id": task_id,
        "agent_name": agent_name,
        "attempt": attempt,
        "kind": kind,
        "failure_count": failure_count,
        "evidence_count": evidence_count,
        "verdict_hash_xxh3": xxhash_rust::xxh3::xxh3_64(&verdict_bytes),
        "candidate_hash_xxh3": xxhash_rust::xxh3::xxh3_64(candidate.as_bytes()),
        "provider": qa_call.map(|call| call.provider.as_str()),
        "model": qa_call.map(|call| call.wire_model.as_str()),
        "ts_unix": crate::time::now_unix_secs(),
    }))?;
    let header = crate::wal::HeaderBuilder::new(
        crate::wal::events::EVENT_TYPE_SUBAGENT_REVIEW_STAGE,
        &payload,
    )
    .build();
    writer
        .append(header, payload)
        .await
        .context("persist structured QA verdict WAL frame")?;
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubAgentRunRecord {
    pub schema_version: u8,
    pub run_id: String,
    pub ts_unix: i64,
    pub prompt_hash_xxh3: u64,
    pub results: Vec<SubAgentResult>,
}

pub fn persist_run(
    home: &std::path::Path,
    record: &SubAgentRunRecord,
) -> Result<std::path::PathBuf> {
    let path = run_dir(home).join(format!("{}.json", record.run_id));
    let bytes = serde_json::to_vec_pretty(record)?;
    crate::util::atomic_write::atomic_write_private(&path, &bytes)
        .with_context(|| format!("persist private sub-agent run {}", path.display()))?;
    Ok(path)
}

pub fn load_run(home: &std::path::Path, run_id: &str) -> Result<SubAgentRunRecord> {
    validate_run_id(run_id)?;
    let path = run_dir(home).join(format!("{run_id}.json"));
    let metadata = std::fs::symlink_metadata(&path)
        .with_context(|| format!("read sub-agent run metadata {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        anyhow::bail!("sub-agent run path is not a regular file");
    }
    let body = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&body).with_context(|| format!("parse {}", path.display()))
}

pub fn list_runs(home: &std::path::Path, limit: usize) -> Result<Vec<SubAgentRunRecord>> {
    let dir = run_dir(home);
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut paths: Vec<_> = std::fs::read_dir(&dir)?
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    paths.sort_by(|a, b| b.file_name().cmp(&a.file_name()));
    paths
        .into_iter()
        .take(limit.min(100))
        .map(|path| {
            let id = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .context("sub-agent run filename is not UTF-8")?;
            load_run(home, id)
        })
        .collect()
}

fn run_dir(home: &std::path::Path) -> std::path::PathBuf {
    home.join("sub-agent-runs")
}

fn validate_run_id(run_id: &str) -> Result<()> {
    if run_id.is_empty()
        || run_id.len() > 80
        || !run_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        anyhow::bail!("invalid sub-agent run id");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::providers::cost_authorization::{AuthorizedProvider, ProviderCallAuthorizer};
    use crate::providers::{
        CompletionIdentity, ProviderDispatchPermit, ProviderRequestControls,
    };
    use crate::sub_agents::parallel::dispatch_parallel;
    use crate::sub_agents::schema::HandoffPriority;

    struct QaScriptProvider {
        calls: AtomicUsize,
        malformed: bool,
        always_fail: bool,
        fail_primary_system: Option<String>,
    }

    #[async_trait::async_trait]
    impl Provider for QaScriptProvider {
        fn name(&self) -> &'static str {
            "openai_api"
        }

        fn default_model(&self) -> Option<&str> {
            Some("wire-model-v1")
        }

        fn request_controls(&self) -> ProviderRequestControls {
            ProviderRequestControls::SAMPLING
        }

        fn output_token_ceiling(&self, _req: &Request) -> Option<u32> {
            Some(128)
        }

        async fn complete_raw(
            &self,
            req: Request,
            _permit: &ProviderDispatchPermit,
        ) -> Result<Completion> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let is_qa = req
                .system
                .as_deref()
                .is_some_and(|system| system.contains("strict QA verifier"));
            if !is_qa
                && self
                    .fail_primary_system
                    .as_deref()
                    .is_some_and(|needle| req.system.as_deref().is_some_and(|s| s.contains(needle)))
            {
                anyhow::bail!("synthetic primary failure");
            }
            let text = if is_qa && self.malformed {
                "VERDICT: PASS".to_string()
            } else if is_qa && self.always_fail {
                r#"{"kind":"fail","failures":[{"kind":"missing_requirement","message":"still incomplete","citation":null}]}"#.to_string()
            } else if is_qa {
                r#"{"kind":"pass","evidence":["candidate addresses task"]}"#.to_string()
            } else {
                "candidate output".to_string()
            };
            Ok(Completion {
                text,
                // The boundary must replace this spoof with its exact leaf.
                identity: CompletionIdentity {
                    provider: "spoof".into(),
                    wire_model: "spoof".into(),
                },
                model: "spoof".into(),
                input_tokens: Some(10),
                output_tokens: Some(5),
                ..Completion::default()
            })
        }
    }

    fn agent(name: &str, system: &str) -> SubAgent {
        SubAgent {
            name: name.into(),
            description: "test".into(),
            model: Some("wire-model-v1".into()),
            system: system.into(),
            tools: vec![],
            disallowed_tools: vec![],
            enabled: true,
            omit_operator_context: true,
            omit_mcp_catalogue: true,
            omit_moral_core: false,
            omit_preset: true,
            omit_recall: true,
            omit_repo_context: true,
        }
    }

    fn request(name: &str, id: &str) -> SubAgentRequest {
        SubAgentRequest {
            from: "cli".into(),
            to: name.into(),
            phase: "fan_out".into(),
            task_id: id.into(),
            priority: HandoffPriority::Normal,
            context: "review this bounded task".into(),
            deliverable: "complete answer".into(),
            success_criteria: vec!["addresses task".into()],
            evidence_required: vec![],
            ts_unix: 1,
        }
    }

    fn audit_writer(dir: &tempfile::TempDir) -> WalWriterHandle {
        let (writer, join) = crate::wal::writer::spawn(dir.path().join("qa.wal")).unwrap();
        drop(join);
        writer
    }

    fn authorized(raw: Arc<QaScriptProvider>) -> Arc<dyn Provider> {
        Arc::new(AuthorizedProvider::from_arc(
            raw,
            ProviderCallAuthorizer::test_only(crate::permissions::AutonomyLevel::Full),
            Some("wire-model-v1".into()),
            "sub_agents.test",
        ))
    }

    #[tokio::test]
    async fn production_worker_fans_out_and_records_actual_leaf_identity() {
        let dir = tempfile::tempdir().unwrap();
        let raw = Arc::new(QaScriptProvider {
            calls: AtomicUsize::new(0),
            malformed: false,
            always_fail: false,
            fail_primary_system: None,
        });
        let worker = Arc::new(ProviderSubAgentWorker::new(
            authorized(Arc::clone(&raw)),
            [agent("a", "agent a"), agent("b", "agent b")],
            false,
            audit_writer(&dir),
        ));
        let report = dispatch_parallel(
            worker,
            vec![request("a", "t-a"), request("b", "t-b")],
            Some(2),
            None,
        )
        .await
        .unwrap();
        assert_eq!(report.pass_count, 2);
        assert_eq!(raw.calls.load(Ordering::SeqCst), 4);
        assert!(report.results.iter().all(|result| {
            result.provider_calls.len() == 2
                && result
                    .provider_calls
                    .iter()
                    .all(|call| call.provider == "openai_api" && call.wire_model == "wire-model-v1")
        }));
    }

    #[tokio::test]
    async fn partial_primary_failure_does_not_abort_other_agent() {
        let dir = tempfile::tempdir().unwrap();
        let raw = Arc::new(QaScriptProvider {
            calls: AtomicUsize::new(0),
            malformed: false,
            always_fail: false,
            fail_primary_system: Some("FAIL_ME".into()),
        });
        let worker = Arc::new(ProviderSubAgentWorker::new(
            authorized(raw),
            [agent("ok", "safe"), agent("bad", "FAIL_ME")],
            false,
            audit_writer(&dir),
        ));
        let report = dispatch_parallel(
            worker,
            vec![request("ok", "t-ok"), request("bad", "t-bad")],
            Some(2),
            None,
        )
        .await
        .unwrap();
        assert_eq!(report.pass_count, 1);
        assert_eq!(report.blocked_count, 1);
        assert_eq!(report.results[1].task_id, "t-bad");
    }

    #[tokio::test]
    async fn malformed_qa_is_blocked_without_retry() {
        let dir = tempfile::tempdir().unwrap();
        let raw = Arc::new(QaScriptProvider {
            calls: AtomicUsize::new(0),
            malformed: true,
            always_fail: false,
            fail_primary_system: None,
        });
        let worker = Arc::new(ProviderSubAgentWorker::new(
            authorized(Arc::clone(&raw)),
            [agent("a", "agent")],
            true,
            audit_writer(&dir),
        ));
        let report = dispatch_parallel(worker, vec![request("a", "t")], Some(1), None)
            .await
            .unwrap();
        assert_eq!(report.blocked_count, 1);
        assert_eq!(report.results[0].attempts, 1);
        assert_eq!(raw.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn retry_is_hard_capped_at_one_correction() {
        let dir = tempfile::tempdir().unwrap();
        let raw = Arc::new(QaScriptProvider {
            calls: AtomicUsize::new(0),
            malformed: false,
            always_fail: true,
            fail_primary_system: None,
        });
        let worker = Arc::new(ProviderSubAgentWorker::new(
            authorized(Arc::clone(&raw)),
            [agent("a", "agent")],
            true,
            audit_writer(&dir),
        ));
        let report = dispatch_parallel(worker, vec![request("a", "t")], Some(1), None)
            .await
            .unwrap();
        assert_eq!(report.fail_count, 1);
        assert_eq!(report.results[0].attempts, 2);
        assert_eq!(raw.calls.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn run_persistence_is_private_and_rejects_traversal_ids() {
        let dir = tempfile::tempdir().unwrap();
        let record = SubAgentRunRecord {
            schema_version: 1,
            run_id: "run-123".into(),
            ts_unix: 1,
            prompt_hash_xxh3: 2,
            results: vec![],
        };
        persist_run(dir.path(), &record).unwrap();
        assert_eq!(load_run(dir.path(), "run-123").unwrap().run_id, "run-123");
        assert!(load_run(dir.path(), "../secret").is_err());
    }
}
