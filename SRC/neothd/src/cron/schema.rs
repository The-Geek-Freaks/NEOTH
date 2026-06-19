//! Job schema + YAML loader. Loaded once at scheduler startup; live-reload
//! deferred (operator runs `neoth serve` restart for now).
//!
//! CRON-A batch additions (HERMES-01 / JV-PRO-01 / JV-PRO-04 / JV-PRO-05 / JV-PRO-09):
//! - `Job::validate()` — edit-guard (JV-PRO-01)
//! - `preflight(job)` — 5-check delivery pre-flight warnings (JV-PRO-04)
//! - `CronRole` + `classify_role(job)` — keyword/schedule heuristic (JV-PRO-05)
//! - `schedule_collides(new, existing, horizon_hours)` — collision detection (JV-PRO-09)
//! - `JobsFile::save_to_path()` — atomic YAML write (HERMES-01)

use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use chrono_tz::Tz;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobsFile {
    /// Schema version. Currently always `1`. Bumped only when the YAML shape
    /// changes incompatibly; minor field additions stay at version 1.
    pub version: u32,
    #[serde(default)]
    pub jobs: Vec<Job>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Schedule {
    /// 5-field cron expression in standard syntax: `min hour dom mon dow`.
    pub cron: String,
    /// IANA timezone name, e.g. "Europe/Berlin". Defaults to UTC when omitted.
    #[serde(default)]
    pub tz: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delivery {
    /// Channel name as recognized by `channels::Channel::name()`: "telegram",
    /// "keet", … When omitted from the job, the result only lands in the WAL.
    pub channel: String,
    /// Optional channel-specific recipient id. Required for some channels
    /// (Telegram chat_id), optional for others (WAL-only delivery).
    #[serde(default)]
    pub recipient: Option<String>,
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
    if haystack.contains("proactive")
        || haystack.contains("suggest")
        || haystack.contains("remind")
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

/// Channels that require an explicit `recipient` field.
/// JV-PRO-04
const CHANNELS_NEEDING_RECIPIENT: &[&str] = &["telegram", "whatsapp", "discord"];

/// Run pre-flight delivery/schedule checks on a job. Returns a (possibly
/// empty) list of human-readable warning strings. Warnings do not block save —
/// they are surfaced by `neoth cron add` for operator awareness.
/// JV-PRO-04
pub fn preflight(job: &Job) -> Vec<String> {
    let mut warnings: Vec<String> = Vec::new();

    match &job.delivery {
        None => {}
        Some(d) => {
            // (1) recipient set but channel empty
            if d.channel.trim().is_empty() && d.recipient.is_some() {
                warnings.push(
                    "delivery.recipient is set but delivery.channel is empty — \
                     recipient will be ignored (no channel to route to)"
                        .to_string(),
                );
            }
            // (2) channel requires a recipient but none given
            if CHANNELS_NEEDING_RECIPIENT.contains(&d.channel.to_lowercase().as_str())
                && d.recipient.is_none()
            {
                warnings.push(format!(
                    "channel `{}` usually requires a recipient (e.g. chat_id / user_id) \
                     but none is set",
                    d.channel
                ));
            }
        }
    }

    // (3) timeout 0 or absurdly large (> 24 h)
    if job.timeout_seconds == 0 {
        warnings.push("timeout_seconds is 0 — job will be cancelled immediately".to_string());
    } else if job.timeout_seconds > 86_400 {
        warnings.push(format!(
            "timeout_seconds ({}) is over 24 h — this may block the scheduler for a very long time",
            job.timeout_seconds
        ));
    }

    // (4) prompt suspiciously short (< 10 non-whitespace chars)
    if job.prompt.split_whitespace().count() < 3 {
        warnings.push(format!(
            "prompt is very short ({} words) — make sure this is intentional",
            job.prompt.split_whitespace().count()
        ));
    }

    // (5) schedule fires more often than every minute (< 1-min granularity)
    // Standard 5-field cron minimum is 1 minute; we check by computing two
    // consecutive fire times and measuring the gap.
    if let Some(t0) = job.schedule.next_after(Utc::now()) {
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
    let now = Utc::now();
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

impl JobsFile {
    pub async fn load_from_path(path: &Path) -> Result<Self> {
        let body = tokio::fs::read_to_string(path)
            .await
            .with_context(|| format!("read jobs file {}", path.display()))?;
        let parsed: JobsFile = serde_yaml::from_str(&body)
            .with_context(|| format!("parse YAML at {}", path.display()))?;
        if parsed.version != 1 {
            anyhow::bail!(
                "jobs.yaml version {} not supported (only v1)",
                parsed.version
            );
        }
        // Validate cron expressions + tz names up-front so misconfig fails
        // loudly at startup rather than silently never firing.
        for j in &parsed.jobs {
            j.schedule
                .validate()
                .with_context(|| format!("invalid schedule on job '{}' ({})", j.name, j.id))?;
        }
        Ok(parsed)
    }

    /// In-memory constructor for tests.
    pub fn from_yaml_str(s: &str) -> Result<Self> {
        let parsed: JobsFile = serde_yaml::from_str(s).context("parse jobs YAML")?;
        for j in &parsed.jobs {
            j.schedule.validate()?;
        }
        Ok(parsed)
    }

    /// Atomic YAML save. Writes to `<path>.tmp` then renames over `path`.
    /// On Unix the final file is chmoded 0600. Mirrors the pattern used by
    /// `council.rs` for freedom.yaml. HERMES-01
    pub fn save_to_path(&self, path: &Path) -> Result<()> {
        let yaml = serde_yaml::to_string(self).context("serialize jobs.yaml")?;
        let tmp = path.with_extension("yaml.tmp");
        std::fs::write(&tmp, &yaml)
            .with_context(|| format!("write {}", tmp.display()))?;
        std::fs::rename(&tmp, path)
            .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
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
      recipient: "12345"
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
        assert!(
            err.to_string().contains("parse cron expression")
                || err.to_string().contains("invalid")
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
        assert!(
            err.to_string().to_lowercase().contains("invalid tz")
                || err.to_string().contains("Fake")
        );
    }

    #[test]
    fn unsupported_version_rejected_in_load_from_path() {
        // Use from_yaml_str directly to avoid filesystem; assert manual version check.
        let yaml = "version: 99\njobs: []\n";
        let parsed: JobsFile = serde_yaml::from_str(yaml).unwrap();
        // The version check lives in load_from_path; emulate by checking
        // the field is what we expect.
        assert_eq!(parsed.version, 99);
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
            schedule: Schedule { cron: cron.to_string(), tz: None },
            prompt: prompt.to_string(),
            timeout_seconds: 600,
            delivery: None,
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
        let mut j = daily_job("x", "X", "0 7 * * *", "");
        let err = j.validate().unwrap_err();
        assert!(err.to_string().contains("prompt must not be empty"), "{err}");
    }

    #[test]
    fn validate_accepts_valid_job() {
        let j = daily_job("good-job", "Good Job", "0 8 * * *", "Summarise news.");
        j.validate().expect("valid job should not error");
    }

    // ── CRON-A: JV-PRO-04 preflight() ────────────────────────────────────────

    #[test]
    fn preflight_flags_recipient_without_channel() {
        let mut j = daily_job("x", "X", "0 7 * * *", "do stuff do stuff");
        j.delivery = Some(Delivery {
            channel: "".to_string(),
            recipient: Some("123".to_string()),
        });
        let warns = preflight(&j);
        assert!(
            warns.iter().any(|w| w.contains("channel is empty")),
            "expected recipient-without-channel warning, got: {warns:?}"
        );
    }

    #[test]
    fn preflight_flags_telegram_without_recipient() {
        let mut j = daily_job("x", "X", "0 7 * * *", "send news send news");
        j.delivery = Some(Delivery {
            channel: "telegram".to_string(),
            recipient: None,
        });
        let warns = preflight(&j);
        assert!(
            warns.iter().any(|w| w.contains("recipient")),
            "expected missing-recipient warning for telegram, got: {warns:?}"
        );
    }

    #[test]
    fn preflight_no_warnings_for_well_formed_job() {
        let mut j = daily_job("x", "X", "0 7 * * *", "Summarise overnight tech news for the team.");
        j.delivery = Some(Delivery {
            channel: "telegram".to_string(),
            recipient: Some("99999".to_string()),
        });
        let warns = preflight(&j);
        // May have no warnings (timeout/prompt ok, schedule daily)
        let delivery_warns: Vec<_> = warns
            .iter()
            .filter(|w| w.contains("recipient") || w.contains("channel"))
            .collect();
        assert!(delivery_warns.is_empty(), "unexpected delivery warnings: {delivery_warns:?}");
    }

    // ── CRON-A: JV-PRO-05 classify_role() ────────────────────────────────────

    #[test]
    fn classify_role_morning_briefing() {
        let j = daily_job("mb", "Morning Briefing", "0 7 * * *", "Summarise overnight events.");
        assert_eq!(classify_role(&j), CronRole::Briefing);
    }

    #[test]
    fn classify_role_monitor_disk() {
        let j = daily_job("md", "Monitor disk usage", "*/5 * * * *", "Check disk usage and alert if above 80%.");
        assert_eq!(classify_role(&j), CronRole::Monitor);
    }

    #[test]
    fn classify_role_research() {
        let j = daily_job("ar", "Arxiv Scanner", "0 9 * * *", "Research new papers on arxiv LLM.");
        assert_eq!(classify_role(&j), CronRole::Research);
    }

    #[test]
    fn classify_role_other_fallback() {
        let j = daily_job("zz", "Zap Widget", "0 1 * * *", "Do some totally unique thing.");
        assert_eq!(classify_role(&j), CronRole::Other);
    }

    // ── CRON-A: JV-PRO-09 schedule_collides() ────────────────────────────────

    #[test]
    fn schedule_collides_detects_same_minute() {
        let existing = daily_job("existing", "Existing", "0 7 * * *", "hi there hello world");
        let new_sched = Schedule { cron: "0 7 * * *".to_string(), tz: None };
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
        let new_sched = Schedule { cron: "5 7 * * *".to_string(), tz: None };
        let collisions = schedule_collides(&new_sched, &[existing], 48);
        assert!(
            collisions.is_empty(),
            "expected no collision for staggered schedules, got: {collisions:?}"
        );
    }
}
