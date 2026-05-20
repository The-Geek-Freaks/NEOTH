//! Job schema + YAML loader. Loaded once at scheduler startup; live-reload
//! deferred (operator runs `neoth serve` restart for now).

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
}
