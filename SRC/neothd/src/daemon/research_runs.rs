//! P2-09 operator-owned deep-research run ledger.
//!
//! This is deliberately a small private file store, not a task queue.  The
//! record is the authority for a single explicitly approved research effect;
//! process-local cancellation is not treated as cross-process control.

use std::ffi::OsStr;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

const STORE_DIR: &str = "research-runs";
const MAX_TOPIC_BYTES: usize = 4_096;
const MAX_SCOPE_BYTES: usize = 4_096;
const MAX_RUNS_LISTED: usize = 200;
const MAX_STORE_BYTES: usize = 512 * 1024;
const MAX_AUDIT_ROWS: usize = 128;
const SCHEMA_VERSION: u8 = 1;
const LOCK_FILE: &str = "research-runs.lock";

static RESEARCH_RUNS_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum ResearchRunState {
    Draft,
    Approved,
    Running,
    Paused,
    Cancelled,
    Completed,
    Failed,
    Interrupted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchRunBudget {
    pub max_rounds: u8,
    pub results_per_query: usize,
    pub pages_per_round: usize,
    pub max_provider_tokens: u32,
    pub max_wall_secs: u64,
    pub max_provider_calls: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchRun {
    pub schema_version: u8,
    pub id: String,
    pub revision: u64,
    pub state: ResearchRunState,
    pub topic: String,
    pub scope: String,
    pub budget: ResearchRunBudget,
    pub completed_rounds: u8,
    #[serde(default)]
    pub checkpoint: crate::tools::deep_research::ResearchCheckpoint,
    pub control_request: Option<String>,
    pub effect_started: bool,
    pub attempt_token: Option<String>,
    pub created_unix: i64,
    pub updated_unix: i64,
    pub result_sha256: Option<String>,
    pub report: Option<String>,
    pub citations: Vec<crate::tools::deep_research::CitedSource>,
    pub evidence_sha256: Vec<String>,
    pub audit: Vec<ResearchRunAudit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchRunAudit {
    pub at_unix: i64,
    pub event: String,
    pub detail_sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResearchControl {
    Continue,
    PauseRequested,
    Cancelled,
}

impl ResearchRunBudget {
    pub fn from_config(cfg: &crate::config::DeepResearchConfig) -> Self {
        let max_rounds = cfg.max_rounds.unwrap_or(5).clamp(1, 5);
        let results_per_query = cfg.results_per_query.unwrap_or(5).clamp(1, 20);
        let pages_per_round = cfg.pages_per_round.unwrap_or(3).clamp(1, 5);
        Self {
            max_rounds,
            results_per_query,
            pages_per_round,
            max_provider_tokens: 0,
            max_wall_secs: 300,
            max_provider_calls: u32::from(max_rounds)
                .saturating_mul((pages_per_round as u32).saturating_add(1))
                .saturating_add(1),
        }
    }
}

pub fn create(
    home: &Path,
    topic: String,
    scope: String,
    budget: ResearchRunBudget,
) -> Result<ResearchRun> {
    validate_text("topic", &topic, MAX_TOPIC_BYTES)?;
    validate_text("scope", &scope, MAX_SCOPE_BYTES)?;
    let id = format!(
        "rr-{:016x}",
        xxhash_rust::xxh3::xxh3_64(
            format!("{}:{}", crate::time::now_unix_ns_i64(), topic).as_bytes()
        )
    );
    let now = crate::time::now_unix_i64();
    let run = ResearchRun {
        schema_version: SCHEMA_VERSION,
        id: id.clone(),
        revision: 1,
        state: ResearchRunState::Draft,
        topic,
        scope,
        budget,
        completed_rounds: 0,
        checkpoint: crate::tools::deep_research::ResearchCheckpoint::default(),
        control_request: None,
        effect_started: false,
        attempt_token: None,
        created_unix: now,
        updated_unix: now,
        result_sha256: None,
        report: None,
        citations: Vec::new(),
        evidence_sha256: Vec::new(),
        audit: vec![audit("created", None)],
    };
    with_lock(home, |dir, _| {
        write(dir, &run)?;
        Ok(run.clone())
    })
}

pub fn load(home: &Path, id: &str) -> Result<ResearchRun> {
    validate_id(id)?;
    with_existing_store(home, |directory, display| {
        read(directory, id, &display.join(run_file_name(id)))
    })
}

pub fn list(home: &Path) -> Result<Vec<ResearchRun>> {
    with_existing_store(home, |directory, display| {
        let mut out = Vec::new();
        for entry in directory
            .entries()
            .context("enumerate bounded research run store")?
        {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_str().context("research run entry is not UTF-8")?;
            let Some(id) = name.strip_suffix(".json") else {
                continue;
            };
            validate_id(id)?;
            out.push(read(directory, id, &display.join(name))?);
            anyhow::ensure!(
                out.len() <= MAX_RUNS_LISTED,
                "research run store exceeds bounded list limit"
            );
        }
        out.sort_by(|a, b| b.created_unix.cmp(&a.created_unix));
        Ok(out)
    })
}

pub fn approve(home: &Path, id: &str, expected: u64) -> Result<ResearchRun> {
    mutate(home, id, expected, |r| {
        require(&r.state, ResearchRunState::Draft)?;
        r.state = ResearchRunState::Approved;
        r.audit.push(audit("approved", None));
        Ok(())
    })
}
pub fn request_control(home: &Path, id: &str, expected: u64, request: &str) -> Result<ResearchRun> {
    if request != "pause" && request != "cancel" {
        anyhow::bail!("invalid research control request")
    };
    mutate(home, id, expected, |r| {
        if matches!(
            r.state,
            ResearchRunState::Completed
                | ResearchRunState::Cancelled
                | ResearchRunState::Failed
                | ResearchRunState::Interrupted
        ) {
            anyhow::bail!("research run is terminal")
        };
        if request == "pause" && r.state != ResearchRunState::Running {
            anyhow::bail!("only a running research run can be paused")
        };
        if request == "cancel"
            && matches!(
                r.state,
                ResearchRunState::Draft | ResearchRunState::Approved | ResearchRunState::Paused
            )
        {
            r.state = ResearchRunState::Cancelled;
            r.control_request = None;
            r.audit.push(audit("cancelled_before_effect", None));
            return Ok(());
        };
        r.control_request = Some(request.to_owned());
        r.audit.push(audit(request, None));
        Ok(())
    })
}

/// Executor-side durable polling. A different CLI process writes the request;
/// the network-owning process observes and commits the terminal/paused state.
pub fn observe_control(home: &Path, id: &str, attempt: &str) -> Result<ResearchControl> {
    validate_attempt(attempt)?;
    with_lock(home, |dir, display| {
        let mut run = read(dir, id, &display.join(run_file_name(id)))?;
        require_attempt(&run, attempt)?;
        match run.control_request.as_deref() {
            None => Ok(ResearchControl::Continue),
            Some("pause") => Ok(ResearchControl::PauseRequested),
            Some("cancel") => {
                run.control_request = None;
                run.state = ResearchRunState::Cancelled;
                run.attempt_token = None;
                run.effect_started = false;
                run.revision = run
                    .revision
                    .checked_add(1)
                    .context("research run revision overflow")?;
                run.updated_unix = crate::time::now_unix_i64();
                run.audit.push(audit("cancelled", None));
                write(dir, &run)?;
                Ok(ResearchControl::Cancelled)
            }
            Some(_) => anyhow::bail!("invalid stored research control request"),
        }
    })
}

pub fn pause_at_boundary(home: &Path, id: &str, attempt: &str) -> Result<ResearchRun> {
    validate_attempt(attempt)?;
    mutate_unchecked(home, id, |run| {
        require_attempt(run, attempt)?;
        anyhow::ensure!(
            run.control_request.as_deref() == Some("pause"),
            "research pause is not pending"
        );
        anyhow::ensure!(
            !run.effect_started,
            "research pause requires a durable post-effect checkpoint"
        );
        run.control_request = None;
        run.state = ResearchRunState::Paused;
        run.attempt_token = None;
        run.effect_started = false;
        run.audit.push(audit("paused_at_checkpoint", None));
        Ok(())
    })
}

pub fn checkpoint(
    home: &Path,
    id: &str,
    attempt: &str,
    checkpoint: crate::tools::deep_research::ResearchCheckpoint,
) -> Result<()> {
    validate_attempt(attempt)?;
    if checkpoint.queries.len() > 5
        || checkpoint.evidence.len() > 100
        || checkpoint
            .evidence
            .iter()
            .any(|e| e.content.len() > MAX_SCOPE_BYTES * 2)
    {
        anyhow::bail!("research checkpoint exceeds bounded private-store limits")
    };
    mutate_unchecked(home, id, |r| {
        require_attempt(r, attempt)?;
        if checkpoint.completed_rounds < r.completed_rounds {
            anyhow::bail!("research checkpoint would rewind completed rounds")
        };
        r.completed_rounds = checkpoint.completed_rounds;
        r.checkpoint = checkpoint;
        r.evidence_sha256 = r
            .checkpoint
            .evidence
            .iter()
            .map(|e| sha(&e.content))
            .collect();
        r.effect_started = false;
        r.audit.push(audit("round_checkpoint", None));
        Ok(())
    })
    .map(|_| ())
}
pub fn begin_effect(home: &Path, id: &str, attempt: &str) -> Result<()> {
    validate_attempt(attempt)?;
    with_lock(home, |dir, display| {
        let mut r = read(dir, id, &display.join(run_file_name(id)))?;
        require_attempt(&r, attempt)?;
        if r.control_request.as_deref() == Some("cancel") {
            r.control_request = None;
            r.state = ResearchRunState::Cancelled;
            r.attempt_token = None;
            r.effect_started = false;
            r.revision = r
                .revision
                .checked_add(1)
                .context("research run revision overflow")?;
            r.updated_unix = crate::time::now_unix_i64();
            r.audit.push(audit("cancelled_before_effect", None));
            write(dir, &r)?;
            anyhow::bail!("research cancel observed before external effect")
        };
        r.effect_started = true;
        r.revision = r
            .revision
            .checked_add(1)
            .context("research run revision overflow")?;
        r.updated_unix = crate::time::now_unix_i64();
        r.audit.push(audit("effect_started", None));
        write(dir, &r)?;
        Ok(())
    })
}
pub fn fail_pre_effect(home: &Path, id: &str, attempt: &str) -> Result<()> {
    validate_attempt(attempt)?;
    mutate_unchecked(home, id, |r| {
        require_attempt(r, attempt)?;
        if r.effect_started {
            anyhow::bail!("cannot mark an effect-started run as pre-effect failure")
        };
        r.state = ResearchRunState::Failed;
        r.attempt_token = None;
        r.audit.push(audit("setup_failed_before_effect", None));
        Ok(())
    })
    .map(|_| ())
}

/// Claim the single network-capable execution. An effect-started interrupted
/// run is intentionally unrecoverable by `run`; a human must inspect it.
pub fn claim_run(home: &Path, id: &str, expected: u64) -> Result<ResearchRun> {
    mutate(home, id, expected, |r| {
        match r.state {
            ResearchRunState::Approved | ResearchRunState::Paused => {}
            ResearchRunState::Interrupted if r.effect_started => {
                anyhow::bail!("research run has an unknown prior external effect; refusing reissue")
            }
            _ => anyhow::bail!("research run is not approved or paused"),
        };
        if r.control_request.as_deref() == Some("cancel") {
            r.state = ResearchRunState::Cancelled;
            r.audit.push(audit("cancelled_before_effect", None));
            return Ok(());
        };
        r.control_request = None;
        r.state = ResearchRunState::Running;
        r.effect_started = false;
        let nonce = sha(&format!(
            "{}:{}:{}",
            r.id,
            r.revision,
            crate::time::now_unix_ns_i64()
        ));
        r.attempt_token = Some(nonce[..32].to_owned());
        r.audit.push(audit("execution_claimed", None));
        Ok(())
    })
}
pub fn complete(
    home: &Path,
    id: &str,
    attempt: &str,
    result: &str,
    citations: &[crate::tools::deep_research::CitedSource],
) -> Result<ResearchRun> {
    let result_hash = sha(result);
    mutate_unchecked(home, id, |r| {
        require_attempt(r, attempt)?;
        if r.control_request.take().is_some() {
            r.audit
                .push(audit("control_observed_after_final_effect", None));
        }
        r.result_sha256 = Some(result_hash.clone());
        r.report = Some(result.to_owned());
        r.citations = citations.to_vec();
        r.state = ResearchRunState::Completed;
        r.attempt_token = None;
        r.effect_started = false;
        r.audit.push(audit("completed", Some(result_hash.clone())));
        Ok(())
    })
}
pub fn fail_interrupted(home: &Path, id: &str, attempt: &str) -> Result<ResearchRun> {
    mutate_unchecked(home, id, |r| {
        require_attempt(r, attempt)?;
        r.state = ResearchRunState::Interrupted;
        r.attempt_token = None;
        r.audit.push(audit("interrupted_unknown_effect", None));
        Ok(())
    })
}

fn mutate(
    home: &Path,
    id: &str,
    expected: u64,
    f: impl FnOnce(&mut ResearchRun) -> Result<()>,
) -> Result<ResearchRun> {
    validate_id(id)?;
    with_lock(home, |dir, display| {
        let mut r = read(dir, id, &display.join(run_file_name(id)))?;
        if r.revision != expected {
            anyhow::bail!(
                "stale research run revision: expected {expected}, current {}",
                r.revision
            )
        };
        f(&mut r)?;
        r.revision = r
            .revision
            .checked_add(1)
            .context("research run revision overflow")?;
        r.updated_unix = crate::time::now_unix_i64();
        write(dir, &r)?;
        Ok(r)
    })
}
fn mutate_unchecked(
    home: &Path,
    id: &str,
    f: impl FnOnce(&mut ResearchRun) -> Result<()>,
) -> Result<ResearchRun> {
    validate_id(id)?;
    with_lock(home, |dir, display| {
        let mut r = read(dir, id, &display.join(run_file_name(id)))?;
        f(&mut r)?;
        r.revision = r
            .revision
            .checked_add(1)
            .context("research run revision overflow")?;
        r.updated_unix = crate::time::now_unix_i64();
        write(dir, &r)?;
        Ok(r)
    })
}
fn with_lock<T>(home: &Path, f: impl FnOnce(&cap_std::fs::Dir, &Path) -> Result<T>) -> Result<T> {
    let _guard = RESEARCH_RUNS_MUTEX
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| anyhow::anyhow!("research run mutex is poisoned"))?;
    let home_directory =
        crate::skills::store::open_bound_directory(home, false, "research run home")?
            .context("research run home does not exist")?;
    let display = home_directory.physical_display_path.join(STORE_DIR);
    let directory = crate::skills::store::open_or_create_private_child_dir(
        &home_directory.dir,
        OsStr::new(STORE_DIR),
        &display,
    )?;
    let (directory, binding) = crate::skills::store::bind_retained_real_child_dir(
        &home_directory.dir,
        OsStr::new(STORE_DIR),
        &display,
        directory,
    )?;
    crate::skills::store::ensure_cap_directory_is_owner_private(
        &directory,
        "research run store",
        &display,
    )?;
    let lock_path = display.join(LOCK_FILE);
    let (lock, lock_binding) = crate::skills::store::open_or_create_bound_lockfile(
        &directory,
        OsStr::new(LOCK_FILE),
        &lock_path,
    )?;
    match lock.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => {
            anyhow::bail!("research run store is already active")
        }
        Err(std::fs::TryLockError::Error(error)) => return Err(error.into()),
    }
    let result = f(&directory, &display)?;
    anyhow::ensure!(
        lock_binding.matches_regular_file_child_readonly(
            &directory,
            OsStr::new(LOCK_FILE),
            &lock_path
        )?,
        "research run lock changed during operation"
    );
    anyhow::ensure!(
        binding.matches_directory_child(&home_directory.dir, OsStr::new(STORE_DIR), &display)?,
        "research run store changed during operation"
    );
    Ok(result)
}

fn with_existing_store<T>(
    home: &Path,
    f: impl FnOnce(&cap_std::fs::Dir, &Path) -> Result<T>,
) -> Result<T> {
    let Some(home_directory) =
        crate::skills::store::open_bound_directory(home, false, "research run read home")?
    else {
        anyhow::bail!("research run home does not exist");
    };
    let display = home_directory.physical_display_path.join(STORE_DIR);
    let Some(directory) = crate::skills::store::open_real_child_dir_if_present(
        &home_directory.dir,
        OsStr::new(STORE_DIR),
        &display,
    )?
    else {
        anyhow::bail!("research run store does not exist")
    };
    let (directory, binding) = crate::skills::store::bind_retained_real_child_dir(
        &home_directory.dir,
        OsStr::new(STORE_DIR),
        &display,
        directory,
    )?;
    crate::skills::store::ensure_cap_directory_is_owner_private(
        &directory,
        "research run read store",
        &display,
    )?;
    let result = f(&directory, &display)?;
    anyhow::ensure!(
        binding.matches_directory_child(&home_directory.dir, OsStr::new(STORE_DIR), &display)?,
        "research run store changed before read return"
    );
    Ok(result)
}

fn run_file_name(id: &str) -> String {
    format!("{id}.json")
}

fn write(dir: &cap_std::fs::Dir, r: &ResearchRun) -> Result<()> {
    validate_run(r)?;
    let body = serde_json::to_vec(r).context("encode research run")?;
    anyhow::ensure!(
        body.len() <= MAX_STORE_BYTES,
        "research run exceeds bounded storage"
    );
    let name = run_file_name(&r.id);
    crate::skills::store::atomic_write_private_child(
        dir,
        OsStr::new(&name),
        Path::new(&name),
        &body,
    )
    .context("atomically persist private research run")
}

fn read(dir: &cap_std::fs::Dir, id: &str, path: &Path) -> Result<ResearchRun> {
    let name = run_file_name(id);
    let bytes = crate::skills::store::read_regular_file_bounded(
        dir,
        OsStr::new(&name),
        path,
        MAX_STORE_BYTES,
    )?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).context("parse research run JSON")?;
    validate_json_shape(&value)?;
    let run: ResearchRun = serde_json::from_value(value).context("decode research run")?;
    anyhow::ensure!(run.id == id, "research run filename/id mismatch");
    validate_run(&run)?;
    Ok(run)
}
fn validate_run(run: &ResearchRun) -> Result<()> {
    anyhow::ensure!(
        run.schema_version == SCHEMA_VERSION,
        "unsupported research run schema"
    );
    validate_id(&run.id)?;
    anyhow::ensure!(
        run.revision > 0 && run.created_unix >= 0 && run.updated_unix >= run.created_unix,
        "invalid research run revision or clock"
    );
    validate_text("topic", &run.topic, MAX_TOPIC_BYTES)?;
    validate_text("scope", &run.scope, MAX_SCOPE_BYTES)?;
    anyhow::ensure!(
        run.control_request
            .as_deref()
            .is_none_or(|request| request == "pause" || request == "cancel"),
        "invalid research control request"
    );
    anyhow::ensure!(
        (1..=5).contains(&run.budget.max_rounds)
            && (1..=20).contains(&run.budget.results_per_query)
            && (1..=5).contains(&run.budget.pages_per_round)
            && (1..=3600).contains(&run.budget.max_wall_secs)
            && run.budget.max_provider_tokens <= 1_000_000
            && (1..=64).contains(&run.budget.max_provider_calls),
        "invalid immutable research budget"
    );
    anyhow::ensure!(
        run.completed_rounds <= run.budget.max_rounds
            && run.checkpoint.completed_rounds == run.completed_rounds,
        "invalid research checkpoint rounds"
    );
    anyhow::ensure!(
        run.checkpoint.queries.len() <= run.budget.max_rounds as usize
            && run.checkpoint.evidence.len() <= 100
            && run.citations.len() <= 100
            && run.evidence_sha256.len() <= 100
            && run.audit.len() <= MAX_AUDIT_ROWS,
        "research run exceeds bounded collections"
    );
    for query in &run.checkpoint.queries {
        validate_text("checkpoint query", query, MAX_TOPIC_BYTES)?;
    }
    for evidence in &run.checkpoint.evidence {
        validate_text("evidence id", &evidence.source_id, 256)?;
        validate_text("evidence content", &evidence.content, MAX_SCOPE_BYTES * 2)?;
        validate_text("citation title", &evidence.citation.title, 1024)?;
        validate_text("citation url", &evidence.citation.url, 4096)?;
    }
    for citation in &run.citations {
        validate_text("citation title", &citation.title, 1024)?;
        validate_text("citation url", &citation.url, 4096)?;
    }
    for hash in run.evidence_sha256.iter().chain(run.result_sha256.iter()) {
        validate_hash(hash)?;
    }
    for audit in &run.audit {
        validate_text("audit event", &audit.event, 128)?;
        if let Some(hash) = &audit.detail_sha256 {
            validate_hash(hash)?;
        }
    }
    if let Some(token) = &run.attempt_token {
        validate_attempt(token)?;
        anyhow::ensure!(
            run.state == ResearchRunState::Running,
            "attempt token outside running state"
        );
    }
    if run.effect_started {
        anyhow::ensure!(
            run.state == ResearchRunState::Running || run.state == ResearchRunState::Interrupted,
            "effect marker outside active or interrupted state"
        );
    }
    Ok(())
}
fn validate_json_shape(value: &serde_json::Value) -> Result<()> {
    let object = value
        .as_object()
        .context("research run must be a JSON object")?;
    const FIELDS: &[&str] = &[
        "schema_version",
        "id",
        "revision",
        "state",
        "topic",
        "scope",
        "budget",
        "completed_rounds",
        "checkpoint",
        "control_request",
        "effect_started",
        "attempt_token",
        "created_unix",
        "updated_unix",
        "result_sha256",
        "report",
        "citations",
        "evidence_sha256",
        "audit",
    ];
    anyhow::ensure!(
        object.keys().all(|key| FIELDS.contains(&key.as_str())),
        "unknown research run field"
    );
    Ok(())
}
fn validate_hash(value: &str) -> Result<()> {
    anyhow::ensure!(
        value.len() == 64
            && value.bytes().all(|byte| byte.is_ascii_digit()
                || (byte.is_ascii_lowercase() && byte.is_ascii_hexdigit())),
        "invalid research run SHA-256"
    );
    Ok(())
}
fn validate_attempt(value: &str) -> Result<()> {
    anyhow::ensure!(
        value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid research attempt token"
    );
    Ok(())
}
fn validate_id(id: &str) -> Result<()> {
    if id.len() != 19 || !id.starts_with("rr-") || !id[3..].bytes().all(|b| b.is_ascii_hexdigit()) {
        anyhow::bail!("invalid opaque research run id")
    };
    Ok(())
}
fn require_attempt(run: &ResearchRun, attempt: &str) -> Result<()> {
    require(&run.state, ResearchRunState::Running)?;
    anyhow::ensure!(
        run.attempt_token.as_deref() == Some(attempt),
        "stale research run attempt"
    );
    Ok(())
}
fn validate_text(name: &str, v: &str, max: usize) -> Result<()> {
    if v.trim().is_empty() || v.len() > max {
        anyhow::bail!("research {name} must be nonempty and at most {max} bytes")
    };
    Ok(())
}
fn require(actual: &ResearchRunState, want: ResearchRunState) -> Result<()> {
    if actual != &want {
        anyhow::bail!("invalid research run transition from {actual:?}")
    };
    Ok(())
}
fn sha(v: &str) -> String {
    use sha2::Digest as _;
    format!("{:x}", sha2::Sha256::digest(v.as_bytes()))
}
fn audit(event: &str, detail: Option<String>) -> ResearchRunAudit {
    ResearchRunAudit {
        at_unix: crate::time::now_unix_i64(),
        event: event.to_owned(),
        detail_sha256: detail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn budget() -> ResearchRunBudget {
        ResearchRunBudget {
            max_rounds: 3,
            results_per_query: 2,
            pages_per_round: 2,
            max_provider_tokens: 16,
            max_wall_secs: 60,
            max_provider_calls: 8,
        }
    }
    #[test]
    fn approval_is_revision_bound_and_budget_is_immutable() {
        let home = tempfile::tempdir().unwrap();
        let budget = ResearchRunBudget {
            max_rounds: 2,
            results_per_query: 4,
            pages_per_round: 2,
            max_provider_tokens: 16,
            max_wall_secs: 60,
            max_provider_calls: 8,
        };
        let created = create(home.path(), "topic".into(), "scope".into(), budget.clone()).unwrap();
        assert!(approve(home.path(), &created.id, created.revision + 1).is_err());
        let approved = approve(home.path(), &created.id, created.revision).unwrap();
        assert_eq!(approved.budget.max_rounds, budget.max_rounds);
    }
    #[test]
    fn cancel_before_effect_is_terminal() {
        let home = tempfile::tempdir().unwrap();
        let created = create(
            home.path(),
            "topic".into(),
            "scope".into(),
            ResearchRunBudget {
                max_rounds: 1,
                results_per_query: 1,
                pages_per_round: 1,
                max_provider_tokens: 16,
                max_wall_secs: 60,
                max_provider_calls: 8,
            },
        )
        .unwrap();
        let approved = approve(home.path(), &created.id, created.revision).unwrap();
        let cancelled =
            request_control(home.path(), &approved.id, approved.revision, "cancel").unwrap();
        assert_eq!(cancelled.state, ResearchRunState::Cancelled);
    }
    #[test]
    fn checkpoint_survives_pause_and_claimed_resume_without_round_rewind() {
        let home = tempfile::tempdir().unwrap();
        let created = create(
            home.path(),
            "topic".into(),
            "scope".into(),
            ResearchRunBudget {
                max_rounds: 3,
                results_per_query: 1,
                pages_per_round: 1,
                max_provider_tokens: 16,
                max_wall_secs: 60,
                max_provider_calls: 8,
            },
        )
        .unwrap();
        let approved = approve(home.path(), &created.id, created.revision).unwrap();
        let running = claim_run(home.path(), &approved.id, approved.revision).unwrap();
        checkpoint(
            home.path(),
            &running.id,
            running.attempt_token.as_deref().unwrap(),
            crate::tools::deep_research::ResearchCheckpoint {
                queries: vec!["one".into(), "two".into(), "three".into()],
                completed_rounds: 1,
                evidence: Vec::new(),
            },
        )
        .unwrap();
        let current = load(home.path(), &running.id).unwrap();
        let requested =
            request_control(home.path(), &current.id, current.revision, "pause").unwrap();
        assert_eq!(
            observe_control(
                home.path(),
                &requested.id,
                running.attempt_token.as_deref().unwrap()
            )
            .unwrap(),
            ResearchControl::PauseRequested
        );
        let paused = pause_at_boundary(
            home.path(),
            &requested.id,
            running.attempt_token.as_deref().unwrap(),
        )
        .unwrap();
        assert_eq!(paused.checkpoint.completed_rounds, 1);
        let resumed = claim_run(home.path(), &paused.id, paused.revision).unwrap();
        assert_eq!(
            resumed.checkpoint.queries[resumed.checkpoint.completed_rounds as usize],
            "two"
        );
    }

    #[test]
    fn malformed_unknown_future_or_filename_mismatched_store_refuses_without_overwrite() {
        let home = tempfile::tempdir().unwrap();
        let run = create(home.path(), "topic".into(), "scope".into(), budget()).unwrap();
        let path = home.path().join(STORE_DIR).join(run_file_name(&run.id));
        let mut future = serde_json::to_value(&run).unwrap();
        future["schema_version"] = serde_json::json!(2);
        let mut unknown = serde_json::to_value(&run).unwrap();
        unknown["unknown"] = serde_json::json!(true);
        for bytes in [
            b"{broken".to_vec(),
            serde_json::to_vec(&future).unwrap(),
            serde_json::to_vec(&unknown).unwrap(),
        ] {
            std::fs::write(&path, bytes).unwrap();
            let before = std::fs::read(&path).unwrap();
            assert!(load(home.path(), &run.id).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), before);
        }
        let other = "rr-0000000000000000";
        std::fs::write(
            &path,
            serde_json::to_vec(&ResearchRun {
                id: other.into(),
                ..run.clone()
            })
            .unwrap(),
        )
        .unwrap();
        let before = std::fs::read(&path).unwrap();
        assert!(load(home.path(), &run.id).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let mut invalid_budget = run.clone();
        invalid_budget.budget.max_wall_secs = 0;
        std::fs::write(&path, serde_json::to_vec(&invalid_budget).unwrap()).unwrap();
        let before = std::fs::read(&path).unwrap();
        assert!(load(home.path(), &run.id).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let mut invalid_checkpoint = run.clone();
        invalid_checkpoint.checkpoint.completed_rounds = 1;
        std::fs::write(&path, serde_json::to_vec(&invalid_checkpoint).unwrap()).unwrap();
        let before = std::fs::read(&path).unwrap();
        assert!(load(home.path(), &run.id).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn missing_home_reads_create_nothing_and_held_lock_refuses_rewrite() {
        let parent = tempfile::tempdir().unwrap();
        let missing = parent.path().join("missing-home");
        assert!(load(&missing, "rr-0000000000000000").is_err());
        assert!(list(&missing).is_err());
        assert!(!missing.exists());
        let home = tempfile::tempdir().unwrap();
        let run = create(home.path(), "topic".into(), "scope".into(), budget()).unwrap();
        let state = home.path().join(STORE_DIR).join(run_file_name(&run.id));
        let before = std::fs::read(&state).unwrap();
        let held = crate::util::locked_file::try_lock_file_once(
            &home.path().join(STORE_DIR).join(LOCK_FILE),
            "research test",
        )
        .unwrap()
        .unwrap();
        assert!(approve(home.path(), &run.id, run.revision).is_err());
        assert_eq!(std::fs::read(&state).unwrap(), before);
        drop(held);
    }

    #[test]
    fn stale_attempt_cannot_mutate_resumed_run_and_late_control_still_completes() {
        let home = tempfile::tempdir().unwrap();
        let created = create(home.path(), "topic".into(), "scope".into(), budget()).unwrap();
        let approved = approve(home.path(), &created.id, created.revision).unwrap();
        let first = claim_run(home.path(), &approved.id, approved.revision).unwrap();
        let first_token = first.attempt_token.clone().unwrap();
        begin_effect(home.path(), &first.id, &first_token).unwrap();
        checkpoint(
            home.path(),
            &first.id,
            &first_token,
            crate::tools::deep_research::ResearchCheckpoint::default(),
        )
        .unwrap();
        let paused = request_control(
            home.path(),
            &first.id,
            load(home.path(), &first.id).unwrap().revision,
            "pause",
        )
        .unwrap();
        pause_at_boundary(home.path(), &paused.id, &first_token).unwrap();
        let resumed = claim_run(
            home.path(),
            &first.id,
            load(home.path(), &first.id).unwrap().revision,
        )
        .unwrap();
        let second_token = resumed.attempt_token.clone().unwrap();
        assert_ne!(first_token, second_token);
        let persisted_checkpoint = crate::tools::deep_research::ResearchCheckpoint::default();
        assert!(checkpoint(home.path(), &resumed.id, &first_token, persisted_checkpoint).is_err());
        assert!(begin_effect(home.path(), &resumed.id, &first_token).is_err());
        assert!(complete(home.path(), &resumed.id, &first_token, "old", &[]).is_err());
        assert!(fail_interrupted(home.path(), &resumed.id, &first_token).is_err());
        begin_effect(home.path(), &resumed.id, &second_token).unwrap();
        let requested = request_control(
            home.path(),
            &resumed.id,
            load(home.path(), &resumed.id).unwrap().revision,
            "cancel",
        )
        .unwrap();
        let completed = complete(
            home.path(),
            &requested.id,
            &second_token,
            "final report",
            &[],
        )
        .unwrap();
        assert_eq!(completed.state, ResearchRunState::Completed);
        assert_eq!(completed.report.as_deref(), Some("final report"));
        assert!(
            completed
                .audit
                .iter()
                .any(|row| row.event == "control_observed_after_final_effect")
        );
        let created = create(home.path(), "topic two".into(), "scope".into(), budget()).unwrap();
        let approved = approve(home.path(), &created.id, created.revision).unwrap();
        let running = claim_run(home.path(), &approved.id, approved.revision).unwrap();
        let token = running.attempt_token.clone().unwrap();
        begin_effect(home.path(), &running.id, &token).unwrap();
        let requested = request_control(
            home.path(),
            &running.id,
            load(home.path(), &running.id).unwrap().revision,
            "pause",
        )
        .unwrap();
        let completed = complete(
            home.path(),
            &requested.id,
            &token,
            "final pause report",
            &[],
        )
        .unwrap();
        assert_eq!(completed.state, ResearchRunState::Completed);
        assert_eq!(completed.report.as_deref(), Some("final pause report"));
        assert!(
            completed
                .audit
                .iter()
                .any(|row| row.event == "control_observed_after_final_effect")
        );
        let created = create(home.path(), "topic three".into(), "scope".into(), budget()).unwrap();
        let approved = approve(home.path(), &created.id, created.revision).unwrap();
        let running = claim_run(home.path(), &approved.id, approved.revision).unwrap();
        let token = running.attempt_token.clone().unwrap();
        begin_effect(home.path(), &running.id, &token).unwrap();
        let requested = request_control(
            home.path(),
            &running.id,
            load(home.path(), &running.id).unwrap().revision,
            "cancel",
        )
        .unwrap();
        assert_eq!(
            observe_control(home.path(), &requested.id, &token).unwrap(),
            ResearchControl::Cancelled
        );
        assert_eq!(
            load(home.path(), &requested.id).unwrap().state,
            ResearchRunState::Cancelled
        );
    }
}
