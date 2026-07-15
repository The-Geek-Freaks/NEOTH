//! Job schema + validated YAML snapshots. The scheduler reloads the file on
//! every tick and only swaps in a fully validated generation.
//!
//! CRON-A batch additions (HERMES-01 / JV-PRO-01 / JV-PRO-04 / JV-PRO-05 / JV-PRO-09):
//! - `Job::validate()` — edit-guard (JV-PRO-01)
//! - `preflight(job)` — advisory schedule/prompt warnings (JV-PRO-04)
//! - `CronRole` + `classify_role(job)` — keyword/schedule heuristic (JV-PRO-05)
//! - `schedule_collides(new, existing, horizon_hours)` — collision detection (JV-PRO-09)
//! - `JobsFile::save_to_path()` — atomic YAML write (HERMES-01)
//!
//! JV-PRO-03 additions (wave/dependency scheduler):
//! - `Job::depends_on` — ordered dependency list (back-compat: absent → empty)
//! - `WaveError` — cycle / unknown-dep errors from the DAG validator
//! - `topo_order(jobs)` — Kahn topological sort; returns ids in dependency order
//! - `ready_jobs(jobs, completed, now, last_run, freshness)` — 4h-default freshness gate
//! - `JobsFile::validate_waves()` — DAG validation seam called by add/edit CLI guards

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::str::FromStr;
use std::sync::Mutex;

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use chrono_tz::Tz;
use serde::{Deserialize, Serialize};

/// Serialises in-process jobs.yaml read-modify-write cycles. The sibling OS
/// lock in [`JobsFile::modify_at_path`] covers separate `neoth` processes.
static JOBS_RMW_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobsFile {
    /// Schema version. Currently always `1`. Bumped only when the YAML shape
    /// changes incompatibly; minor field additions stay at version 1.
    pub version: u32,
    #[serde(default)]
    pub jobs: Vec<Job>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Job {
    pub id: String,
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub schedule: Schedule,
    pub prompt: String,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u32,
    #[serde(default)]
    pub delivery: Option<Delivery>,
    /// Ids of jobs that must have completed (within the freshness window) before
    /// this job is considered READY. Absent in YAML → empty → independent job.
    /// JV-PRO-03
    #[serde(default)]
    pub depends_on: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Schedule {
    /// 5-field cron expression in standard syntax: `min hour dom mon dow`.
    pub cron: String,
    /// IANA timezone name, e.g. "Europe/Berlin". Defaults to UTC when omitted.
    #[serde(default)]
    pub tz: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delivery {
    /// Channel name as recognized by `channels::Channel::name()`, for example
    /// "telegram". The actual destination is always resolved from the
    /// operator-owned channel routing configuration.
    pub channel: String,
    /// Backward-deserialization seam for pre-v1 jobs that embedded a recipient.
    /// Item-controlled recipients violate proactive delivery's anti-spoof
    /// invariant, so [`Job::validate`] rejects this field when present.
    #[serde(default, rename = "recipient", skip_serializing_if = "Option::is_none")]
    legacy_recipient: Option<String>,
}

impl Delivery {
    /// Create a delivery request for an operator-configured channel route.
    pub fn new(channel: impl Into<String>) -> Self {
        Self {
            channel: channel.into(),
            legacy_recipient: None,
        }
    }
}

fn default_true() -> bool {
    true
}
fn default_timeout() -> u32 {
    600
}

/// Role classifier for cron jobs. Derived from prompt/name keywords and
/// schedule frequency. Used by `neoth cron list` to aid operator orientation.
/// JV-PRO-05
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CronRole {
    Briefing,
    Monitor,
    Maintenance,
    Research,
    Proactive,
    Automation,
    Other,
}

impl std::fmt::Display for CronRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            CronRole::Briefing => "briefing",
            CronRole::Monitor => "monitor",
            CronRole::Maintenance => "maintenance",
            CronRole::Research => "research",
            CronRole::Proactive => "proactive",
            CronRole::Automation => "automation",
            CronRole::Other => "other",
        };
        f.write_str(s)
    }
}

/// Classify a job's role from its name + prompt text + schedule.
/// Keyword matching is case-insensitive; first match wins in priority order.
/// JV-PRO-05
pub fn classify_role(job: &Job) -> CronRole {
    let haystack = format!("{} {}", job.name, job.prompt).to_lowercase();

    if haystack.contains("brief")
        || haystack.contains("morning")
        || haystack.contains("daily digest")
        || haystack.contains("summary")
        || haystack.contains("roundup")
    {
        return CronRole::Briefing;
    }
    if haystack.contains("monitor")
        || haystack.contains("check")
        || haystack.contains("alert")
        || haystack.contains("watch")
        || haystack.contains("health")
    {
        return CronRole::Monitor;
    }
    if haystack.contains("maintenance")
        || haystack.contains("cleanup")
        || haystack.contains("clean up")
        || haystack.contains("vacuum")
        || haystack.contains("prune")
        || haystack.contains("backup")
    {
        return CronRole::Maintenance;
    }
    if haystack.contains("research")
        || haystack.contains("scan")
        || haystack.contains("arxiv")
        || haystack.contains("trend")
        || haystack.contains("discover")
    {
        return CronRole::Research;
    }
    if haystack.contains("proactive") || haystack.contains("suggest") || haystack.contains("remind")
    {
        return CronRole::Proactive;
    }
    if haystack.contains("automat")
        || haystack.contains("sync")
        || haystack.contains("export")
        || haystack.contains("import")
        || haystack.contains("deploy")
    {
        return CronRole::Automation;
    }
    CronRole::Other
}

/// Run pre-flight schedule checks on a job. Returns a (possibly
/// empty) list of human-readable warning strings. Warnings do not block save —
/// they are surfaced by `neoth cron add` for operator awareness.
/// JV-PRO-04
pub fn preflight(job: &Job) -> Vec<String> {
    let mut warnings: Vec<String> = Vec::new();

    // (1) timeout 0 or absurdly large (> 24 h)
    if job.timeout_seconds == 0 {
        warnings.push("timeout_seconds is 0 — job will be cancelled immediately".to_string());
    } else if job.timeout_seconds > 86_400 {
        warnings.push(format!(
            "timeout_seconds ({}) is over 24 h — this may block the scheduler for a very long time",
            job.timeout_seconds
        ));
    }

    // (2) prompt suspiciously short (< 10 non-whitespace chars)
    if job.prompt.split_whitespace().count() < 3 {
        warnings.push(format!(
            "prompt is very short ({} words) — make sure this is intentional",
            job.prompt.split_whitespace().count()
        ));
    }

    // (3) schedule fires more often than every minute (< 1-min granularity)
    // Standard 5-field cron minimum is 1 minute; we check by computing two
    // consecutive fire times and measuring the gap.
    if let Some(t0) = job.schedule.next_after(crate::time::utc_now()) {
        if let Some(t1) = job.schedule.next_after(t0) {
            let gap_secs = (t1 - t0).num_seconds();
            if gap_secs > 0 && gap_secs < 60 {
                warnings.push(format!(
                    "schedule fires every ~{gap_secs}s (sub-minute) — \
                     the scheduler tick is 30 s so this is fine but unusual"
                ));
            }
        }
    }

    warnings
}

/// Check whether `new_schedule` fires at the same minute as any existing job
/// within `horizon_hours` from now. Returns a list of collision descriptions.
/// JV-PRO-09
pub fn schedule_collides(
    new_schedule: &Schedule,
    existing: &[Job],
    horizon_hours: i64,
) -> Vec<String> {
    let horizon = chrono::Duration::hours(horizon_hours);
    let now = crate::time::utc_now();
    let end = now + horizon;

    // Collect fire-minute buckets for the new schedule.
    let new_fires: std::collections::HashSet<String> = {
        let mut set = std::collections::HashSet::new();
        let mut cursor = now;
        loop {
            match new_schedule.next_after(cursor) {
                Some(t) if t <= end => {
                    // Bucket = "YYYY-MM-DDTHH:MM" — minute precision
                    set.insert(t.format("%Y-%m-%dT%H:%M").to_string());
                    cursor = t;
                }
                _ => break,
            }
        }
        set
    };

    let mut collisions: Vec<String> = Vec::new();
    for job in existing {
        let mut cursor = now;
        loop {
            match job.schedule.next_after(cursor) {
                Some(t) if t <= end => {
                    let bucket = t.format("%Y-%m-%dT%H:%M").to_string();
                    if new_fires.contains(&bucket) {
                        collisions.push(format!(
                            "fires at the same minute as job `{}` ({}): {} — consider staggering by 1–5 min",
                            job.id, job.name, bucket
                        ));
                        break; // one collision warning per existing job is enough
                    }
                    cursor = t;
                }
                _ => break,
            }
        }
    }
    collisions
}

// ── JV-PRO-03: wave / dependency scheduler ───────────────────────────────────

/// Default freshness window: a dependency completion older than this makes the
/// downstream job NOT ready (the whole chain must re-run). Tunable per call.
pub const DEFAULT_FRESHNESS: Duration = Duration::hours(4);

/// Errors produced by the DAG validator / topo-sorter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WaveError {
    /// The depends_on graph contains a cycle. The vec holds the cycle members
    /// in the order they were detected by Kahn's algorithm.
    Cycle(Vec<String>),
    /// A job references a dependency id that does not exist in the job set.
    UnknownDep {
        /// The job that declared the bad dependency.
        job: String,
        /// The dependency id that was not found.
        dep: String,
    },
}

impl std::fmt::Display for WaveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WaveError::Cycle(members) => {
                write!(
                    f,
                    "dependency cycle detected among jobs: {}",
                    members.join(" → ")
                )
            }
            WaveError::UnknownDep { job, dep } => {
                write!(f, "job `{job}` depends on `{dep}` which is not defined")
            }
        }
    }
}

/// Kahn topological sort over the `depends_on` DAG.
///
/// Returns job ids in dependency order (roots first, leaves last) so a wave
/// scheduler can fire batches in sequence. Pure — does not read from disk.
///
/// # Errors
/// - `WaveError::UnknownDep` if any `depends_on` entry names a job id not
///   present in `jobs`.
/// - `WaveError::Cycle` if the graph contains a cycle; the returned vec lists
///   the jobs that were never scheduled (all cycle members plus anything that
///   depended on them).
pub fn topo_order(jobs: &[Job]) -> Result<Vec<String>, WaveError> {
    // Build id → index map for O(1) lookup.
    let id_set: HashSet<&str> = jobs.iter().map(|j| j.id.as_str()).collect();

    // Validate all dependency references before building adjacency.
    for job in jobs {
        for dep in &job.depends_on {
            if !id_set.contains(dep.as_str()) {
                return Err(WaveError::UnknownDep {
                    job: job.id.clone(),
                    dep: dep.clone(),
                });
            }
        }
    }

    // Compute in-degree and successor lists.
    // `successors[id]` = list of jobs that list `id` as a dependency (edges
    // flow from dependency → dependent, which is the Kahn direction).
    let mut in_degree: HashMap<&str, usize> = jobs.iter().map(|j| (j.id.as_str(), 0)).collect();
    let mut successors: HashMap<&str, Vec<&str>> =
        jobs.iter().map(|j| (j.id.as_str(), vec![])).collect();

    for job in jobs {
        for dep in &job.depends_on {
            *in_degree.entry(job.id.as_str()).or_insert(0) += 1;
            successors
                .entry(dep.as_str())
                .or_default()
                .push(job.id.as_str());
        }
    }

    // Seed the queue with every job that has no dependencies (in-degree 0).
    let mut queue: VecDeque<&str> = in_degree
        .iter()
        .filter_map(|(&id, &deg)| if deg == 0 { Some(id) } else { None })
        .collect();
    // Sort for deterministic output order.
    let mut queue_vec: Vec<&str> = queue.drain(..).collect();
    queue_vec.sort_unstable();
    queue.extend(queue_vec);

    let mut order: Vec<String> = Vec::with_capacity(jobs.len());

    while let Some(id) = queue.pop_front() {
        order.push(id.to_string());
        if let Some(succs) = successors.get(id) {
            let mut next_batch: Vec<&str> = succs
                .iter()
                .filter_map(|&succ| {
                    let deg = in_degree.get_mut(succ)?;
                    *deg -= 1;
                    if *deg == 0 { Some(succ) } else { None }
                })
                .collect();
            next_batch.sort_unstable();
            queue.extend(next_batch);
        }
    }

    if order.len() != jobs.len() {
        // Some nodes were never dequeued — they are part of a cycle.
        let remaining: Vec<String> = jobs
            .iter()
            .map(|j| j.id.as_str())
            .filter(|id| !order.contains(&id.to_string()))
            .map(str::to_string)
            .collect();
        return Err(WaveError::Cycle(remaining));
    }

    Ok(order)
}

/// Return the subset of `jobs` that are READY to fire right now.
///
/// A job is READY when **all** of the following hold:
/// 1. `job.enabled` is `true`.
/// 2. Every id in `job.depends_on` is present in `completed`.
/// 3. Every dependency completed **within** `freshness` before `now`
///    (stale dependency → not ready; the whole chain must re-run).
///
/// Independent jobs (empty `depends_on`) satisfy conditions 2 and 3
/// trivially and are ready as long as they are enabled.
///
/// Returns job ids in the same order as `topo_order` would produce so
/// callers can fire waves in sequence. Pure — does not read from disk.
///
/// # Wire point ✅ WIRED (2026-06-20, JV-PRO-03 tick-integration)
/// `cron::scheduler::run_scheduler` maintains a `completed` map (populated by
/// each spawned `run_job` on success) + `last_fired`, calls `ready_jobs` every
/// tick, and only fires the returned ids — so a job with `depends_on` is held
/// until its deps have COMPLETED within `DEFAULT_FRESHNESS`.
pub fn ready_jobs(
    jobs: &[Job],
    completed: &HashSet<String>,
    now: DateTime<Utc>,
    last_run: &HashMap<String, DateTime<Utc>>,
    freshness: Duration,
) -> Vec<String> {
    jobs.iter()
        .filter(|job| {
            if !job.enabled {
                return false;
            }
            for dep in &job.depends_on {
                // Condition 2: dependency must have completed.
                if !completed.contains(dep) {
                    return false;
                }
                // Condition 3: dependency completion must be within the freshness window.
                match last_run.get(dep) {
                    Some(&completed_at) => {
                        if now - completed_at > freshness {
                            return false;
                        }
                    }
                    // Completed but no timestamp recorded — treat as stale.
                    None => return false,
                }
            }
            true
        })
        .map(|job| job.id.clone())
        .collect()
}

impl JobsFile {
    /// Validate the `depends_on` DAG across all jobs.
    ///
    /// Called by `neoth cron add` and `cron edit` after `Job::validate()` so
    /// a cyclic or broken `depends_on` is rejected before saving. JV-PRO-03
    pub fn validate_waves(&self) -> Result<()> {
        topo_order(&self.jobs).map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(())
    }
}

impl JobsFile {
    /// Empty, valid v1 snapshot used while watching for the first jobs file.
    pub fn empty() -> Self {
        Self {
            version: 1,
            jobs: Vec::new(),
        }
    }

    /// Validate a complete snapshot, including invariants manual edits can
    /// bypass and the cross-job dependency graph.
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            anyhow::bail!("jobs.yaml version {} not supported (only v1)", self.version);
        }
        let mut ids = HashSet::with_capacity(self.jobs.len());
        for job in &self.jobs {
            job.validate()
                .with_context(|| format!("invalid job '{}' ({})", job.name, job.id))?;
            if !ids.insert(job.id.as_str()) {
                anyhow::bail!("duplicate job id `{}`", job.id);
            }
        }
        self.validate_waves()?;
        Ok(())
    }

    pub async fn load_from_path(path: &Path) -> Result<Self> {
        let body = tokio::fs::read_to_string(path)
            .await
            .with_context(|| format!("read jobs file {}", path.display()))?;
        let parsed: JobsFile = serde_yaml::from_str(&body)
            .with_context(|| format!("parse YAML at {}", path.display()))?;
        parsed.validate()?;
        Ok(parsed)
    }

    /// In-memory constructor for tests.
    pub fn from_yaml_str(s: &str) -> Result<Self> {
        let parsed: JobsFile = serde_yaml::from_str(s).context("parse jobs YAML")?;
        parsed.validate()?;
        Ok(parsed)
    }

    /// Mutate a complete jobs.yaml snapshot under process-local and OS-level
    /// locks, validate the resulting generation, then commit it atomically.
    ///
    /// Atomic rename alone prevents torn reads but not lost updates when two
    /// CLI processes both load the same generation. Every production jobs.yaml
    /// mutation must use this helper so the scheduler's live reload observes a
    /// complete, serialised generation. If `mutate` or validation fails, the
    /// original file remains byte-for-byte untouched.
    pub fn modify_at_path<T>(
        path: &Path,
        mutate: impl FnOnce(&mut JobsFile) -> Result<T>,
    ) -> Result<T> {
        let _process_guard = JOBS_RMW_LOCK
            .lock()
            .map_err(|_| anyhow::anyhow!("jobs.yaml in-process lock poisoned"))?;
        let lock_path = path.with_extension("yaml.lock");
        let _file_guard = crate::util::locked_file::lock_file_blocking(&lock_path, "cron jobs")
            .with_context(|| format!("lock jobs file {}", path.display()))?;

        let mut jobs = if path.exists() {
            let body = std::fs::read_to_string(path)
                .with_context(|| format!("read jobs file {}", path.display()))?;
            Self::from_yaml_str(&body)
                .with_context(|| format!("load jobs file {}", path.display()))?
        } else {
            Self::empty()
        };
        let result = mutate(&mut jobs)?;
        jobs.save_to_path(path)?;
        Ok(result)
    }

    /// Atomic YAML save via the shared fsync + rename primitive. On Unix the
    /// final file is chmoded 0600. HERMES-01
    pub fn save_to_path(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let yaml = serde_yaml::to_string(self).context("serialize jobs.yaml")?;
        crate::util::atomic_write::atomic_write(path, yaml.as_bytes())
            .with_context(|| format!("atomic write {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(path) {
                let mut perms = meta.permissions();
                perms.set_mode(0o600);
                let _ = std::fs::set_permissions(path, perms);
            }
        }
        Ok(())
    }
}

impl Job {
    /// Validate a job before Add/Edit persists it. Called by the CLI CRUD
    /// path; returns an error string describing the first violation found.
    /// JV-PRO-01
    pub fn validate(&self) -> Result<()> {
        if self.id.trim().is_empty() {
            anyhow::bail!("job id must not be empty");
        }
        if self.name.trim().is_empty() {
            anyhow::bail!("job name must not be empty");
        }
        if self.prompt.trim().is_empty() {
            anyhow::bail!("job prompt must not be empty");
        }
        // Validates cron expression + tz
        self.schedule
            .validate()
            .with_context(|| format!("invalid schedule on job `{}`", self.id))?;
        if let Some(delivery) = &self.delivery {
            if delivery.channel.trim().is_empty() {
                anyhow::bail!("delivery.channel must not be empty");
            }
            if delivery.legacy_recipient.is_some() {
                anyhow::bail!(
                    "delivery.recipient is no longer supported; configure the operator-owned \
                     destination in channel_routing.yaml and keep only delivery.channel"
                );
            }
        }
        Ok(())
    }
}

impl Schedule {
    /// Parse the cron expression once. Returns a `cron::Schedule` ready to
    /// produce next-fire timestamps.
    pub fn parse(&self) -> Result<cron::Schedule> {
        // The `cron` crate expects a 6-or-7-field expression (with optional
        // seconds + year). Standard 5-field cron "0 7 * * *" needs a leading
        // "0 " for seconds so the crate accepts it.
        let normalized = if self.cron.split_whitespace().count() == 5 {
            format!("0 {}", self.cron)
        } else {
            self.cron.clone()
        };
        cron::Schedule::from_str(&normalized)
            .with_context(|| format!("parse cron expression `{}`", self.cron))
    }

    pub fn validate(&self) -> Result<()> {
        let _ = self.parse()?;
        if let Some(tz) = &self.tz {
            tz.parse::<Tz>()
                .map_err(|e| anyhow::anyhow!("invalid tz `{tz}`: {e}"))?;
        }
        Ok(())
    }

    /// Timezone resolution: explicit `tz` or UTC.
    pub fn timezone(&self) -> Tz {
        self.tz
            .as_deref()
            .and_then(|s| s.parse::<Tz>().ok())
            .unwrap_or(Tz::UTC)
    }

    /// Next firing time after `now`. None if the cron expression has no
    /// future match (e.g. "0 0 30 2 *" — Feb 30, never).
    pub fn next_after(&self, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
        let sched = self.parse().ok()?;
        let tz = self.timezone();
        let now_local = now.with_timezone(&tz);
        sched
            .after(&now_local)
            .next()
            .map(|t| t.with_timezone(&Utc))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_yaml() {
        let yaml = r#"
version: 1
jobs:
  - id: morning-news
    name: Morning News
    enabled: true
    schedule:
      cron: "0 7 * * *"
      tz: Europe/Berlin
    prompt: |
      Hi
    delivery:
      channel: telegram
"#;
        let f = JobsFile::from_yaml_str(yaml).unwrap();
        assert_eq!(f.version, 1);
        assert_eq!(f.jobs.len(), 1);
        let j = &f.jobs[0];
        assert_eq!(j.id, "morning-news");
        assert!(j.enabled);
        assert_eq!(j.schedule.cron, "0 7 * * *");
        assert_eq!(j.schedule.tz.as_deref(), Some("Europe/Berlin"));
    }

    #[test]
    fn enabled_defaults_true_when_omitted() {
        let yaml = r#"
version: 1
jobs:
  - id: x
    name: X
    schedule:
      cron: "0 7 * * *"
    prompt: hi
"#;
        let f = JobsFile::from_yaml_str(yaml).unwrap();
        assert!(f.jobs[0].enabled);
    }

    #[test]
    fn timeout_defaults_to_600_seconds() {
        let yaml = r#"
version: 1
jobs:
  - id: x
    name: X
    schedule:
      cron: "0 7 * * *"
    prompt: hi
"#;
        let f = JobsFile::from_yaml_str(yaml).unwrap();
        assert_eq!(f.jobs[0].timeout_seconds, 600);
    }

    #[test]
    fn invalid_cron_expr_fails_load() {
        let yaml = r#"
version: 1
jobs:
  - id: x
    name: X
    schedule:
      cron: "not a cron expression"
    prompt: hi
"#;
        let err = JobsFile::from_yaml_str(yaml).unwrap_err();
        let message = format!("{err:#}");
        assert!(
            message.contains("parse cron expression `not a cron expression`"),
            "unexpected validation error chain: {message}"
        );
    }

    #[test]
    fn invalid_tz_fails_load() {
        let yaml = r#"
version: 1
jobs:
  - id: x
    name: X
    schedule:
      cron: "0 7 * * *"
      tz: Fake/Timezone
    prompt: hi
"#;
        let err = JobsFile::from_yaml_str(yaml).unwrap_err();
        let message = format!("{err:#}");
        assert!(
            message.contains("invalid tz `Fake/Timezone`"),
            "unexpected validation error chain: {message}"
        );
    }

    #[test]
    fn unsupported_version_rejected_by_snapshot_validation() {
        let yaml = "version: 99\njobs: []\n";
        let err = JobsFile::from_yaml_str(yaml).unwrap_err();
        assert!(err.to_string().contains("version 99"), "{err}");
    }

    #[test]
    fn next_after_returns_some_for_daily_cron() {
        let s = Schedule {
            cron: "0 7 * * *".to_string(),
            tz: Some("UTC".to_string()),
        };
        let now = Utc::now();
        let next = s.next_after(now).unwrap();
        assert!(next > now);
    }

    // ── CRON-A: JV-PRO-01 validate() ─────────────────────────────────────────

    fn daily_job(id: &str, name: &str, cron: &str, prompt: &str) -> Job {
        Job {
            id: id.to_string(),
            name: name.to_string(),
            enabled: true,
            schedule: Schedule {
                cron: cron.to_string(),
                tz: None,
            },
            prompt: prompt.to_string(),
            timeout_seconds: 600,
            delivery: None,
            depends_on: vec![],
        }
    }

    /// Build a daily_job with explicit depends_on list. JV-PRO-03 helper.
    fn dep_job(id: &str, deps: &[&str]) -> Job {
        Job {
            id: id.to_string(),
            name: id.to_string(),
            enabled: true,
            schedule: Schedule {
                cron: "0 7 * * *".to_string(),
                tz: None,
            },
            prompt: "do something meaningful please".to_string(),
            timeout_seconds: 600,
            delivery: None,
            depends_on: deps.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn validate_rejects_bad_cron() {
        let mut j = daily_job("x", "X", "not-a-cron", "do stuff");
        j.schedule.cron = "not a cron".to_string();
        let err = j.validate().unwrap_err();
        assert!(
            err.to_string().contains("parse cron") || err.to_string().contains("invalid"),
            "expected cron-parse error, got: {err}"
        );
    }

    #[test]
    fn validate_rejects_empty_id() {
        let mut j = daily_job("x", "X", "0 7 * * *", "do stuff");
        j.id = "  ".to_string();
        let err = j.validate().unwrap_err();
        assert!(err.to_string().contains("id must not be empty"), "{err}");
    }

    #[test]
    fn validate_rejects_empty_prompt() {
        let j = daily_job("x", "X", "0 7 * * *", "");
        let err = j.validate().unwrap_err();
        assert!(
            err.to_string().contains("prompt must not be empty"),
            "{err}"
        );
    }

    #[test]
    fn validate_accepts_valid_job() {
        let j = daily_job("good-job", "Good Job", "0 8 * * *", "Summarise news.");
        j.validate().expect("valid job should not error");
    }

    #[test]
    fn snapshot_rejects_duplicate_job_ids() {
        let jobs = JobsFile {
            version: 1,
            jobs: vec![
                daily_job("same", "First", "0 7 * * *", "first prompt"),
                daily_job("same", "Second", "5 7 * * *", "second prompt"),
            ],
        };
        let err = jobs.validate().unwrap_err();
        assert!(err.to_string().contains("duplicate job id `same`"), "{err}");
    }

    #[test]
    fn atomic_save_rejects_invalid_snapshot_without_replacing_valid_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("jobs.yaml");
        let valid = JobsFile {
            version: 1,
            jobs: vec![daily_job("valid", "Valid", "0 7 * * *", "valid prompt")],
        };
        valid.save_to_path(&path).unwrap();
        let before = std::fs::read(&path).unwrap();
        let invalid = JobsFile {
            version: 1,
            jobs: vec![daily_job("invalid", "Invalid", "not cron", "prompt")],
        };
        assert!(invalid.save_to_path(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn locked_modify_serialises_concurrent_job_additions() {
        let dir = tempfile::tempdir().unwrap();
        let path = std::sync::Arc::new(dir.path().join("jobs.yaml"));
        let mut threads = Vec::new();
        for id in ["first", "second"] {
            let path = std::sync::Arc::clone(&path);
            threads.push(std::thread::spawn(move || {
                JobsFile::modify_at_path(&path, |jobs| {
                    jobs.jobs.push(daily_job(
                        id,
                        id,
                        "0 7 * * *",
                        "run the complete scheduled task",
                    ));
                    Ok(())
                })
                .unwrap();
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }

        let body = std::fs::read_to_string(path.as_ref()).unwrap();
        let jobs = JobsFile::from_yaml_str(&body).unwrap();
        assert_eq!(jobs.jobs.len(), 2, "neither concurrent update may be lost");
        assert!(jobs.jobs.iter().any(|job| job.id == "first"));
        assert!(jobs.jobs.iter().any(|job| job.id == "second"));
    }

    #[test]
    fn locked_modify_error_preserves_original_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("jobs.yaml");
        let jobs = JobsFile {
            version: 1,
            jobs: vec![daily_job("valid", "Valid", "0 7 * * *", "valid prompt")],
        };
        jobs.save_to_path(&path).unwrap();
        let before = std::fs::read(&path).unwrap();

        let error = JobsFile::modify_at_path(&path, |_jobs| -> Result<()> {
            anyhow::bail!("refuse mutation")
        })
        .unwrap_err();
        assert!(error.to_string().contains("refuse mutation"));
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    // ── CRON-A: JV-PRO-04 preflight() ────────────────────────────────────────

    #[test]
    fn validation_rejects_empty_delivery_channel() {
        let mut j = daily_job("x", "X", "0 7 * * *", "do stuff do stuff");
        j.delivery = Some(Delivery {
            channel: "".to_string(),
            legacy_recipient: None,
        });
        let err = j.validate().unwrap_err();
        assert!(err.to_string().contains("delivery.channel"));
    }

    #[test]
    fn validation_rejects_legacy_item_controlled_recipient() {
        let mut j = daily_job("x", "X", "0 7 * * *", "send news send news");
        j.delivery = Some(Delivery {
            channel: "telegram".to_string(),
            legacy_recipient: Some("123".to_string()),
        });
        let err = j.validate().unwrap_err();
        assert!(err.to_string().contains("delivery.recipient"));
        assert!(err.to_string().contains("channel_routing.yaml"));
    }

    #[test]
    fn channel_only_delivery_is_valid_and_has_no_delivery_warning() {
        let mut j = daily_job(
            "x",
            "X",
            "0 7 * * *",
            "Summarise overnight tech news for the team.",
        );
        j.delivery = Some(Delivery::new("telegram"));
        j.validate().unwrap();
        let warns = preflight(&j);
        let delivery_warns: Vec<_> = warns
            .iter()
            .filter(|w| w.contains("recipient") || w.contains("channel"))
            .collect();
        assert!(
            delivery_warns.is_empty(),
            "unexpected delivery warnings: {delivery_warns:?}"
        );
    }

    // ── CRON-A: JV-PRO-05 classify_role() ────────────────────────────────────

    #[test]
    fn classify_role_morning_briefing() {
        let j = daily_job(
            "mb",
            "Morning Briefing",
            "0 7 * * *",
            "Summarise overnight events.",
        );
        assert_eq!(classify_role(&j), CronRole::Briefing);
    }

    #[test]
    fn classify_role_monitor_disk() {
        let j = daily_job(
            "md",
            "Monitor disk usage",
            "*/5 * * * *",
            "Check disk usage and alert if above 80%.",
        );
        assert_eq!(classify_role(&j), CronRole::Monitor);
    }

    #[test]
    fn classify_role_research() {
        let j = daily_job(
            "ar",
            "Arxiv Scanner",
            "0 9 * * *",
            "Research new papers on arxiv LLM.",
        );
        assert_eq!(classify_role(&j), CronRole::Research);
    }

    #[test]
    fn classify_role_other_fallback() {
        let j = daily_job(
            "zz",
            "Zap Widget",
            "0 1 * * *",
            "Do some totally unique thing.",
        );
        assert_eq!(classify_role(&j), CronRole::Other);
    }

    // ── CRON-A: JV-PRO-09 schedule_collides() ────────────────────────────────

    #[test]
    fn schedule_collides_detects_same_minute() {
        let existing = daily_job("existing", "Existing", "0 7 * * *", "hi there hello world");
        let new_sched = Schedule {
            cron: "0 7 * * *".to_string(),
            tz: None,
        };
        let collisions = schedule_collides(&new_sched, &[existing], 48);
        assert!(
            !collisions.is_empty(),
            "expected collision for identical schedule"
        );
    }

    #[test]
    fn schedule_collides_no_collision_for_staggered() {
        let existing = daily_job("existing", "Existing", "0 7 * * *", "hi there hello world");
        // 5 minutes offset
        let new_sched = Schedule {
            cron: "5 7 * * *".to_string(),
            tz: None,
        };
        let collisions = schedule_collides(&new_sched, &[existing], 48);
        assert!(
            collisions.is_empty(),
            "expected no collision for staggered schedules, got: {collisions:?}"
        );
    }

    // ── JV-PRO-03: topo_order + ready_jobs ───────────────────────────────────

    #[test]
    fn topo_order_linear_chain_a_b_c() {
        // a → b → c  (a must run first, then b, then c)
        let jobs = vec![
            dep_job("c", &["b"]),
            dep_job("b", &["a"]),
            dep_job("a", &[]),
        ];
        let order = topo_order(&jobs).expect("linear chain is acyclic");
        // a before b, b before c
        let pos: HashMap<&str, usize> = order
            .iter()
            .enumerate()
            .map(|(i, id)| (id.as_str(), i))
            .collect();
        assert!(pos["a"] < pos["b"], "a must come before b");
        assert!(pos["b"] < pos["c"], "b must come before c");
    }

    #[test]
    fn topo_order_diamond_resolves() {
        // Diamond: a → {b, c} → d
        let jobs = vec![
            dep_job("a", &[]),
            dep_job("b", &["a"]),
            dep_job("c", &["a"]),
            dep_job("d", &["b", "c"]),
        ];
        let order = topo_order(&jobs).expect("diamond is acyclic");
        let pos: HashMap<&str, usize> = order
            .iter()
            .enumerate()
            .map(|(i, id)| (id.as_str(), i))
            .collect();
        assert!(pos["a"] < pos["b"]);
        assert!(pos["a"] < pos["c"]);
        assert!(pos["b"] < pos["d"]);
        assert!(pos["c"] < pos["d"]);
        assert_eq!(order.len(), 4);
    }

    #[test]
    fn topo_order_cycle_a_b_a_returns_wave_error() {
        // a depends on b, b depends on a → cycle
        let jobs = vec![dep_job("a", &["b"]), dep_job("b", &["a"])];
        let err = topo_order(&jobs).unwrap_err();
        assert!(
            matches!(err, WaveError::Cycle(_)),
            "expected Cycle, got: {err}"
        );
        // Display must mention cycle
        assert!(err.to_string().contains("cycle"), "{err}");
    }

    #[test]
    fn topo_order_unknown_dep_returns_error() {
        let jobs = vec![dep_job("a", &["nonexistent"])];
        let err = topo_order(&jobs).unwrap_err();
        assert!(
            matches!(&err, WaveError::UnknownDep { job, dep } if job == "a" && dep == "nonexistent"),
            "expected UnknownDep{{job=a, dep=nonexistent}}, got: {err}"
        );
        assert!(err.to_string().contains("nonexistent"), "{err}");
    }

    #[test]
    fn ready_jobs_independent_job_is_ready() {
        let jobs = vec![dep_job("solo", &[])];
        let completed: HashSet<String> = HashSet::new();
        let last_run: HashMap<String, DateTime<Utc>> = HashMap::new();
        let now = Utc::now();
        let ready = ready_jobs(&jobs, &completed, now, &last_run, Duration::hours(4));
        assert_eq!(ready, vec!["solo".to_string()]);
    }

    #[test]
    fn ready_jobs_dep_completed_fresh_is_ready() {
        let jobs = vec![dep_job("b", &["a"]), dep_job("a", &[])];
        let mut completed: HashSet<String> = HashSet::new();
        completed.insert("a".to_string());
        let now = Utc::now();
        // a completed 1 hour ago — well within 4h freshness
        let mut last_run: HashMap<String, DateTime<Utc>> = HashMap::new();
        last_run.insert("a".to_string(), now - Duration::hours(1));
        let ready = ready_jobs(&jobs, &completed, now, &last_run, Duration::hours(4));
        assert!(
            ready.contains(&"b".to_string()),
            "b should be ready; got {ready:?}"
        );
    }

    #[test]
    fn ready_jobs_dep_stale_is_not_ready() {
        let jobs = vec![dep_job("b", &["a"])];
        let mut completed: HashSet<String> = HashSet::new();
        completed.insert("a".to_string());
        let now = Utc::now();
        // a completed 5 hours ago — outside 4h freshness window
        let mut last_run: HashMap<String, DateTime<Utc>> = HashMap::new();
        last_run.insert("a".to_string(), now - Duration::hours(5));
        let ready = ready_jobs(&jobs, &completed, now, &last_run, Duration::hours(4));
        assert!(
            !ready.contains(&"b".to_string()),
            "b must not be ready with stale dep; got {ready:?}"
        );
    }

    #[test]
    fn ready_jobs_incomplete_dep_is_not_ready() {
        let jobs = vec![dep_job("b", &["a"])];
        // a has NOT run — completed set is empty
        let completed: HashSet<String> = HashSet::new();
        let last_run: HashMap<String, DateTime<Utc>> = HashMap::new();
        let now = Utc::now();
        let ready = ready_jobs(&jobs, &completed, now, &last_run, Duration::hours(4));
        assert!(
            !ready.contains(&"b".to_string()),
            "b must not be ready when a is incomplete"
        );
    }
}
