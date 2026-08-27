//! `neoth reflect` — self-reflection surfaces. `tech-news` pulls trending
//! Hacker News topics and flags the ones the operator's installed skills +
//! recent memory don't cover yet (a "tech-currency" gap). The operator tunes
//! the noisy HN signal with per-operator ignore/pin lists (`reflect ignore` /
//! `reflect pin`). The feed adapter lives in `crate::sources::hackernews`.

use std::ffi::OsStr;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::memory::store;
use crate::reflection::hygiene::DailyAdmissionConfig;
use crate::sources::hackernews::{self, GapFilter};

/// A deliberately small ceiling for the unattended reflection config.  The
/// interactive topic lists have no reason to grow into an allocation surface.
pub const MAX_REFLECT_TOPICS_CONFIG_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReflectTopicsLoadError {
    SafeConfigUnavailable,
    InvalidConfig,
}

impl std::fmt::Display for ReflectTopicsLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SafeConfigUnavailable => write!(f, "reflection automation config is unavailable"),
            Self::InvalidConfig => write!(f, "reflection automation config is invalid"),
        }
    }
}

impl std::error::Error for ReflectTopicsLoadError {}

#[derive(Args, Debug, Clone)]
pub struct ReflectArgs {
    #[command(subcommand)]
    pub action: ReflectAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ReflectAction {
    /// Scan trending Hacker News stories and show which topics your installed
    /// skills + recent memory don't cover yet (tech-currency self-reflection).
    TechNews {
        /// How many top HN stories to scan (capped at 100).
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Maximum gaps to surface.
        #[arg(long, default_value_t = 7)]
        max_gaps: usize,
    },
    /// Stop surfacing a topic as a gap (e.g. one you already follow elsewhere).
    Ignore { term: String },
    /// Always flag a topic when it trends, even if covered or single-mention.
    Pin { term: String },
    /// Remove a topic from BOTH the ignore and pin lists.
    Forget { term: String },
    /// Turn the weekly auto-refresh on (daemon enqueues a tech-currency
    /// reflection once a week). `--off` turns it back off.
    Weekly {
        #[arg(long)]
        off: bool,
    },
    /// Turn the nightly daily self-reflection on (daemon archives a daily
    /// summary + writes an Obsidian daily note). `--off` turns it back off.
    Daily {
        #[arg(long)]
        off: bool,
    },
    /// Turn the yearly self-reflection on (daemon archives a yearly summary +
    /// writes an Obsidian yearly note once a year). `--off` turns it back off.
    Yearly {
        #[arg(long)]
        off: bool,
    },
    /// Compose a daily or yearly reflection NOW (archive + Obsidian if a vault is
    /// configured) without waiting for the cron — handy to test it.
    Digest {
        #[arg(value_enum)]
        period: DigestPeriod,
    },
    /// Show the current per-operator ignore + pin lists + cadence states.
    Topics,
}

#[derive(clap::ValueEnum, Debug, Clone, Copy)]
pub enum DigestPeriod {
    Daily,
    Yearly,
}

/// Per-operator tuning for the tech-currency gap pass. Stored in its own
/// `<home>/reflect_topics.yaml` (never touches freedom.yaml).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReflectTopics {
    #[serde(default)]
    pub ignore: Vec<String>,
    #[serde(default)]
    pub pin: Vec<String>,
    /// Opt-in: the daemon refreshes the tech-currency reflection once a week
    /// (enqueues it for the operator). Off by default — when on it does a weekly
    /// network fetch to Hacker News; see `crate::daemon::reflection_cron`.
    #[serde(default)]
    pub weekly_refresh: bool,
    /// Opt-in: the daemon composes a nightly daily reflection (top topics of the
    /// day) + writes an Obsidian daily note when a vault is configured.
    #[serde(default)]
    pub daily_notes: bool,
    /// Opt-in: the daemon composes a yearly reflection once a year + writes an
    /// Obsidian yearly summary when a vault is configured.
    #[serde(default)]
    pub yearly_summary: bool,
    /// Absent on historical configurations.  This is intentionally opt-in;
    /// old valid files preserve their existing archive behaviour exactly.
    #[serde(default)]
    pub daily_admission: Option<DailyAdmissionConfig>,
}

impl ReflectTopics {
    pub fn path(home: &std::path::Path) -> std::path::PathBuf {
        home.join("reflect_topics.yaml")
    }
    pub fn load(home: &std::path::Path) -> Self {
        std::fs::read_to_string(Self::path(home))
            .ok()
            .and_then(|s| serde_yaml::from_str(&s).ok())
            .unwrap_or_default()
    }

    /// Load config for an unattended automation.  Only a genuinely missing
    /// file maps to the disabled default; malformed YAML, unknown keys,
    /// symlinks/reparse points, directories and oversized files are typed,
    /// fail-closed errors rather than a surprise default.
    pub fn load_for_automation(
        home: &std::path::Path,
    ) -> std::result::Result<Self, ReflectTopicsLoadError> {
        let path = Self::path(home);
        let Some(directory) = crate::skills::store::open_absolute_bound_directory(
            home,
            false,
            "reflection automation home",
        )
        .map_err(|_| ReflectTopicsLoadError::SafeConfigUnavailable)?
        else {
            return Ok(Self::default());
        };
        let bytes = match directory
            .dir
            .symlink_metadata(OsStr::new("reflect_topics.yaml"))
        {
            Ok(_) => crate::skills::store::read_regular_file_bounded(
                &directory.dir,
                OsStr::new("reflect_topics.yaml"),
                &path,
                MAX_REFLECT_TOPICS_CONFIG_BYTES,
            )
            .map_err(|_| ReflectTopicsLoadError::SafeConfigUnavailable)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(_) => return Err(ReflectTopicsLoadError::SafeConfigUnavailable),
        };
        serde_yaml::from_slice(&bytes).map_err(|_| ReflectTopicsLoadError::InvalidConfig)
    }
    pub fn save(&self, home: &std::path::Path) -> Result<()> {
        let yaml = serde_yaml::to_string(self)?;
        crate::util::atomic_write::atomic_write(&Self::path(home), yaml.as_bytes())?;
        Ok(())
    }
}

pub async fn run_reflect(args: ReflectArgs, output: OutputFormat) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    match args.action {
        ReflectAction::TechNews { limit, max_gaps } => {
            tech_news(&home, limit, max_gaps, output).await
        }
        ReflectAction::Ignore { term } => add_topic(&home, &term, true, output),
        ReflectAction::Pin { term } => add_topic(&home, &term, false, output),
        ReflectAction::Forget { term } => forget_topic(&home, &term, output),
        ReflectAction::Weekly { off } => set_weekly(&home, !off, output),
        ReflectAction::Daily { off } => set_cadence(&home, Cadence::Daily, !off, output),
        ReflectAction::Yearly { off } => set_cadence(&home, Cadence::Yearly, !off, output),
        ReflectAction::Digest { period } => digest(&home, period, output),
        ReflectAction::Topics => show_topics(&home, output),
    }
}

#[derive(Clone, Copy)]
enum Cadence {
    Daily,
    Yearly,
}

fn set_cadence(
    home: &std::path::Path,
    cadence: Cadence,
    on: bool,
    output: OutputFormat,
) -> Result<()> {
    let mut topics = ReflectTopics::load(home);
    let (label, vault_note) = match cadence {
        Cadence::Daily => {
            topics.daily_notes = on;
            ("daily nightly reflection", "Obsidian daily note")
        }
        Cadence::Yearly => {
            topics.yearly_summary = on;
            ("yearly reflection", "Obsidian yearly summary")
        }
    };
    topics.save(home)?;
    emit_topics(
        &topics,
        output,
        &if on {
            format!(
                "{label} ENABLED (daemon archives it + writes the {vault_note} if a vault is set)"
            )
        } else {
            format!("{label} disabled")
        },
    );
    Ok(())
}

fn digest(home: &std::path::Path, period: DigestPeriod, output: OutputFormat) -> Result<()> {
    digest_at(home, period, output, crate::time::now_unix_i64())
}

/// Explicit clock seam keeps daily settlement tests deterministic while the
/// public CLI continues to use the real clock exactly once per invocation.
fn digest_at(
    home: &std::path::Path,
    period: DigestPeriod,
    output: OutputFormat,
    now_unix: i64,
) -> Result<()> {
    use crate::reflection::periodic::{self, PeriodKind, date_tag_from_unix, year_tag_from_unix};

    let now_ns = now_unix.saturating_mul(1_000_000_000);
    let conn = store::open(&home.join("views.db")).context("open views.db")?;
    let (kind, tag, window, n) = match period {
        DigestPeriod::Daily => (PeriodKind::Daily, date_tag_from_unix(now_unix), 1, 5),
        DigestPeriod::Yearly => (PeriodKind::Yearly, year_tag_from_unix(now_unix), 365, 10),
    };
    // GR-fix: idempotency guard mirroring the daemon period-tick. The CLI digest
    // path appended a fresh JSONL record + Obsidian section on EVERY invocation, so
    // two `neoth reflect digest --daily` runs on the same day duplicated the
    // reflection. Share the daemon's marker files so daemon + CLI see each other's
    // completion for this tag.
    let yearly_marker = home.join("reflections").join("yearly-last.txt");
    let already_done = if matches!(period, DigestPeriod::Yearly)
        && yearly_marker
            .try_exists()
            .with_context(|| format!("inspect reflection marker {}", yearly_marker.display()))?
    {
        std::fs::read_to_string(&yearly_marker)
            .with_context(|| format!("read reflection marker {}", yearly_marker.display()))?
            .trim()
            == tag.as_str()
    } else {
        false
    };
    if already_done {
        if matches!(output, OutputFormat::Json | OutputFormat::Jsonl) {
            println!(
                "{}",
                serde_json::json!({ "kind": kind.as_str(), "tag": tag, "written": false, "reason": "already_done" })
            );
        } else {
            println!(
                "{} reflection {tag}: already written this period — skipping.",
                kind.vault_subdir()
            );
        }
        return Ok(());
    }
    // Validate the instance-local operator config before creating either the
    // reflection archive record or an Obsidian side effect. Only a genuinely
    // missing config may use compiled defaults.
    let cfg = FreedomConfig::load_from_path_or_default(&home.join("freedom.yaml"))?;
    let daily_admission = if matches!(period, DigestPeriod::Daily) {
        Some(
            ReflectTopics::load_for_automation(home)
                .map_err(anyhow::Error::from)
                .context("load daily admission policy")?,
        )
    } else {
        None
    };
    let topics =
        crate::reflection::top_topics_in_days(&conn, now_ns, window, n).context("topic query")?;
    let Some(refl) = periodic::build_reflection(kind, &tag, &topics, now_unix) else {
        if matches!(output, OutputFormat::Json | OutputFormat::Jsonl) {
            println!(
                "{}",
                serde_json::json!({ "kind": kind.as_str(), "tag": tag, "written": false })
            );
        } else {
            println!(
                "{} reflection {tag}: no topics in the window — nothing to summarise.",
                kind.vault_subdir()
            );
        }
        return Ok(());
    };
    let mut obsidian_path = None;
    if matches!(period, DigestPeriod::Daily) {
        let obsidian = cfg.obsidian_vault.as_deref().map(|vault| {
            (
                std::path::Path::new(vault),
                cfg.obsidian_subdir.as_deref().unwrap_or("NEOTH"),
            )
        });
        match periodic::settle_daily_admission(
            home,
            &refl,
            daily_admission
                .as_ref()
                .and_then(|topics| topics.daily_admission.as_ref()),
            obsidian,
        )
        .map_err(anyhow::Error::from)
        .context("settle daily reflection")?
        {
            periodic::DailySettlementOutcome::Admitted => {
                if cfg.obsidian_vault.is_some() {
                    // Settlement owns the capability-bound note destination;
                    // the CLI deliberately does not reconstruct its path.
                    obsidian_path = Some("bound daily note".to_string());
                }
            }
            periodic::DailySettlementOutcome::Suppressed => {
                if matches!(output, OutputFormat::Json | OutputFormat::Jsonl) {
                    println!(
                        "{}",
                        serde_json::json!({ "kind": kind.as_str(), "tag": tag, "written": false, "reason": "suppressed" })
                    );
                } else {
                    println!(
                        "Daily reflection {tag}: suppressed by the configured admission policy."
                    );
                }
                return Ok(());
            }
            periodic::DailySettlementOutcome::AlreadyCompleted => {
                if matches!(output, OutputFormat::Json | OutputFormat::Jsonl) {
                    println!(
                        "{}",
                        serde_json::json!({ "kind": kind.as_str(), "tag": tag, "written": false, "reason": "already_done" })
                    );
                } else {
                    println!("Daily reflection {tag}: already settled this period — skipping.");
                }
                return Ok(());
            }
        }
    } else {
        periodic::append(home, &refl).context("archive reflection")?;
        crate::util::atomic_write::atomic_write_private(&yearly_marker, tag.as_bytes())
            .with_context(|| format!("persist reflection marker {}", yearly_marker.display()))?;
        if let Some(vault) = cfg.obsidian_vault.as_deref() {
            let subdir = cfg.obsidian_subdir.as_deref().unwrap_or("NEOTH");
            let o =
                periodic::sync_to_obsidian(home, std::path::Path::new(vault), subdir, kind, &tag)
                    .context("Obsidian sync")?;
            if o.written {
                obsidian_path = Some(o.target_path.display().to_string());
            }
        }
    }

    if matches!(output, OutputFormat::Json | OutputFormat::Jsonl) {
        println!(
            "{}",
            serde_json::json!({
                "kind": kind.as_str(), "tag": tag, "written": true,
                "topics": refl.topics, "body": refl.body, "obsidian": obsidian_path,
            })
        );
        return Ok(());
    }
    println!("{} reflection {tag} composed:", kind.vault_subdir());
    println!("  {}", refl.body);
    if !refl.topics.is_empty() {
        println!("  topics: {}", refl.topics.join(", "));
    }
    if let Some(p) = obsidian_path {
        println!("  → Obsidian: {p}");
    } else {
        println!("  (archived; no Obsidian vault configured — set freedom.yaml::obsidian_vault)");
    }
    Ok(())
}

fn set_weekly(home: &std::path::Path, on: bool, output: OutputFormat) -> Result<()> {
    let mut topics = ReflectTopics::load(home);
    topics.weekly_refresh = on;
    topics.save(home)?;
    emit_topics(
        &topics,
        output,
        if on {
            "weekly tech-currency refresh ENABLED (daemon enqueues it once a week)"
        } else {
            "weekly tech-currency refresh disabled"
        },
    );
    Ok(())
}

async fn tech_news(
    home: &std::path::Path,
    limit: usize,
    max_gaps: usize,
    output: OutputFormat,
) -> Result<()> {
    let config_path = home.join("freedom.yaml");
    let config = FreedomConfig::load_from_path(&config_path).with_context(|| {
        format!(
            "load active reflection policy from {}",
            config_path.display()
        )
    })?;
    let http =
        crate::tools::external_http::ExternalHttpAuthorizer::interactive(config.autonomy_policy())?;
    let stories = hackernews::top_stories(&http, limit)
        .await
        .context("fetch Hacker News top stories")?;
    let topics = ReflectTopics::load(home);
    let filter = GapFilter {
        covered: collect_covered(home),
        ignore: topics.ignore.clone(),
        pin: topics.pin.clone(),
    };
    let gaps = hackernews::tech_currency_gaps(&stories, &filter, max_gaps);

    if matches!(output, OutputFormat::Json | OutputFormat::Jsonl) {
        println!(
            "{}",
            serde_json::json!({
                "scanned": stories.len(),
                "covered_terms": filter.covered.len(),
                "ignored": topics.ignore, "pinned": topics.pin,
                "gaps": gaps,
                "reflection": hackernews::render_tech_currency_reflection(&gaps),
            })
        );
        return Ok(());
    }

    println!(
        "Tech-currency self-reflection ({} HN stories scanned):",
        stories.len()
    );
    if gaps.is_empty() {
        println!("  — keine Lücken: deine Skills/Memory decken die aktuellen Trends ab. ✓");
        return Ok(());
    }
    for g in &gaps {
        let mark = if g.pinned { " 📌" } else { "" };
        println!(
            "  • {}{} ({}×) — z.B. \"{}\"",
            g.term, mark, g.mentions, g.example_title
        );
    }
    if let Some(line) = hackernews::render_tech_currency_reflection(&gaps) {
        println!("\n{line}");
    }
    Ok(())
}

fn add_topic(home: &std::path::Path, term: &str, ignore: bool, output: OutputFormat) -> Result<()> {
    let t = term.trim().to_lowercase();
    if t.is_empty() {
        anyhow::bail!("empty topic");
    }
    let mut topics = ReflectTopics::load(home);
    let list = if ignore {
        &mut topics.ignore
    } else {
        &mut topics.pin
    };
    if !list.iter().any(|x| x.eq_ignore_ascii_case(&t)) {
        list.push(t.clone());
        list.sort();
    }
    topics.save(home)?;
    emit_topics(
        &topics,
        output,
        &format!("{} `{t}`", if ignore { "ignoring" } else { "pinned" }),
    );
    Ok(())
}

fn forget_topic(home: &std::path::Path, term: &str, output: OutputFormat) -> Result<()> {
    let t = term.trim().to_lowercase();
    let mut topics = ReflectTopics::load(home);
    topics.ignore.retain(|x| !x.eq_ignore_ascii_case(&t));
    topics.pin.retain(|x| !x.eq_ignore_ascii_case(&t));
    topics.save(home)?;
    emit_topics(
        &topics,
        output,
        &format!("forgot `{t}` (removed from ignore + pin)"),
    );
    Ok(())
}

fn show_topics(home: &std::path::Path, output: OutputFormat) -> Result<()> {
    emit_topics(
        &ReflectTopics::load(home),
        output,
        "tech-currency topic lists",
    );
    Ok(())
}

fn emit_topics(topics: &ReflectTopics, output: OutputFormat, headline: &str) {
    if matches!(output, OutputFormat::Json | OutputFormat::Jsonl) {
        println!(
            "{}",
            serde_json::json!({
                "ignore": topics.ignore, "pin": topics.pin,
                "weekly_refresh": topics.weekly_refresh,
                "daily_notes": topics.daily_notes,
                "yearly_summary": topics.yearly_summary,
            })
        );
        return;
    }
    println!("{headline}");
    println!(
        "  ignore: {}",
        if topics.ignore.is_empty() {
            "—".to_string()
        } else {
            topics.ignore.join(", ")
        }
    );
    println!(
        "  pin   : {}",
        if topics.pin.is_empty() {
            "—".to_string()
        } else {
            topics.pin.join(", ")
        }
    );
    println!(
        "  weekly: {}",
        if topics.weekly_refresh {
            "on"
        } else {
            "off — `neoth reflect weekly`"
        }
    );
    println!(
        "  daily : {}",
        if topics.daily_notes {
            "on"
        } else {
            "off — `neoth reflect daily`"
        }
    );
    println!(
        "  yearly: {}",
        if topics.yearly_summary {
            "on"
        } else {
            "off — `neoth reflect yearly`"
        }
    );
}

/// The operator's "covered" surface: installed skill dir-names + manifest ids +
/// the top recent conversation topics from `<home>/views.db`. Best-effort — a
/// missing skills dir or views.db just yields fewer covered terms (more gaps
/// surface, never panics). Shared by the CLI + the weekly cron refresh.
pub fn collect_covered(home: &std::path::Path) -> Vec<String> {
    let mut covered = Vec::new();
    let skills_dir = home.join("skills");
    if let Ok(entries) = crate::skills::installer::list_installed(&skills_dir) {
        for entry in entries {
            covered.push(entry.dir_name);
            if let Some(id) = entry.manifest_id {
                covered.push(id);
            }
        }
    }
    if let Ok(conn) = store::open(&home.join("views.db")) {
        let now_ns = crate::time::now_unix_ns_i64();
        if let Ok(topics) = crate::reflection::top_topics_last_7_days(&conn, now_ns, 20) {
            covered.extend(topics);
        }
    }
    covered
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn automation_config_missing_is_disabled_but_unknown_malformed_and_oversized_fail_closed() {
        let home = tempfile::tempdir().unwrap();
        assert_eq!(
            ReflectTopics::load_for_automation(home.path()).unwrap(),
            ReflectTopics::default()
        );
        std::fs::write(
            home.path().join("reflect_topics.yaml"),
            "unknown_key: true\n",
        )
        .unwrap();
        assert_eq!(
            ReflectTopics::load_for_automation(home.path()).unwrap_err(),
            ReflectTopicsLoadError::InvalidConfig
        );
        std::fs::write(
            home.path().join("reflect_topics.yaml"),
            "daily_notes: [not: yaml\n",
        )
        .unwrap();
        assert_eq!(
            ReflectTopics::load_for_automation(home.path()).unwrap_err(),
            ReflectTopicsLoadError::InvalidConfig
        );
        std::fs::write(
            home.path().join("reflect_topics.yaml"),
            vec![b'x'; MAX_REFLECT_TOPICS_CONFIG_BYTES + 1],
        )
        .unwrap();
        assert_eq!(
            ReflectTopics::load_for_automation(home.path()).unwrap_err(),
            ReflectTopicsLoadError::SafeConfigUnavailable
        );
    }

    #[test]
    fn old_valid_config_preserves_disabled_daily_admission() {
        let home = tempfile::tempdir().unwrap();
        std::fs::write(
            home.path().join("reflect_topics.yaml"),
            "daily_notes: true\n",
        )
        .unwrap();
        let config = ReflectTopics::load_for_automation(home.path()).unwrap();
        assert!(config.daily_notes);
        assert_eq!(config.daily_admission, None);
    }

    #[test]
    fn cli_daily_digest_first_settlement_honours_enabled_suppression_policy() {
        use crate::reflection::hygiene::DailyAdmissionConfig;
        use crate::reflection::hygiene_store::{DailyAdmissionOutcome, lock_daily_admission};
        use crate::reflection::periodic::{self, PeriodKind};

        let home = tempfile::tempdir().unwrap();
        let now = 1_787_788_800i64;
        let now_ns = now.saturating_mul(1_000_000_000);
        let conn = store::open(&home.path().join("views.db")).unwrap();
        conn.execute(
            "INSERT INTO idx_episode (event_id, event_type, ts_ns, text, text_hash) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![1i64, crate::wal::events::EVENT_TYPE_RAW_TEXT as i64, now_ns, "rust admission policy", "digest-suppression"],
        ).unwrap();
        let topics = crate::reflection::top_topics_in_days(&conn, now_ns, 1, 5).unwrap();
        assert!(!topics.is_empty());
        let mut admission = DailyAdmissionConfig::default();
        admission.enabled = true;
        let prior = periodic::build_reflection(
            PeriodKind::Daily,
            &periodic::date_tag_from_unix(now.saturating_sub(86_400)),
            &topics,
            now.saturating_sub(86_400),
        )
        .unwrap();
        periodic::settle_daily_admission(home.path(), &prior, Some(&admission), None).unwrap();
        std::fs::write(
            home.path().join("reflect_topics.yaml"),
            "daily_admission:\n  version: 1\n  enabled: true\n  min_jaccard_basis_points: 10000\n",
        )
        .unwrap();

        digest_at(home.path(), DigestPeriod::Daily, OutputFormat::Table, now).unwrap();
        let tag = periodic::date_tag_from_unix(now);
        assert!(!periodic::jsonl_file(home.path(), PeriodKind::Daily, &tag).exists());
        let state = lock_daily_admission(home.path())
            .unwrap()
            .load()
            .unwrap()
            .unwrap();
        assert_eq!(state.tag, tag);
        assert_eq!(state.outcome, DailyAdmissionOutcome::Suppressed);
        assert_eq!(
            std::fs::read_to_string(home.path().join("reflections/daily-last.txt")).unwrap(),
            tag
        );
    }

    #[test]
    fn cli_daily_retry_uses_original_same_tag_record_after_candidate_changes() {
        use crate::reflection::periodic::{self, PeriodKind};

        let home = tempfile::tempdir().unwrap();
        let now = 1_787_788_800i64;
        let now_ns = now.saturating_mul(1_000_000_000);
        let conn = store::open(&home.path().join("views.db")).unwrap();
        conn.execute(
            "INSERT INTO idx_episode (event_id, event_type, ts_ns, text, text_hash) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![1i64, crate::wal::events::EVENT_TYPE_RAW_TEXT as i64, now_ns, "rust obsidian retry", "digest-obsidian"],
        ).unwrap();
        let vault = home.path().join("vault-is-a-file");
        std::fs::write(&vault, b"not a directory").unwrap();
        let config = FreedomConfig {
            obsidian_vault: Some(vault.display().to_string()),
            obsidian_subdir: Some("NEOTH".to_string()),
            ..Default::default()
        };
        std::fs::write(
            home.path().join("freedom.yaml"),
            serde_yaml::to_string(&config).unwrap(),
        )
        .unwrap();

        assert!(digest_at(home.path(), DigestPeriod::Daily, OutputFormat::Table, now).is_err());
        let tag = periodic::date_tag_from_unix(now);
        let archive_path = periodic::jsonl_file(home.path(), PeriodKind::Daily, &tag);
        let archive = std::fs::read(&archive_path).unwrap();
        let original: periodic::PeriodReflection = serde_json::from_slice(&archive).unwrap();
        assert!(!home.path().join("reflections/daily-last.txt").exists());
        let retry_now = now.saturating_add(3_600);
        conn.execute(
            "INSERT INTO idx_episode (event_id, event_type, ts_ns, text, text_hash) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![2i64, crate::wal::events::EVENT_TYPE_RAW_TEXT as i64, retry_now.saturating_mul(1_000_000_000), "replacement replacement replacement replacement replacement", "digest-obsidian-retry"],
        ).unwrap();
        let retry_topics = crate::reflection::top_topics_in_days(
            &conn,
            retry_now.saturating_mul(1_000_000_000),
            1,
            5,
        )
        .unwrap();
        let rebuilt =
            periodic::build_reflection(PeriodKind::Daily, &tag, &retry_topics, retry_now).unwrap();
        assert_ne!(
            rebuilt.topics, original.topics,
            "the retry must exercise distinct same-day topics"
        );
        assert_ne!(
            rebuilt, original,
            "the retry must exercise a distinct same-day candidate"
        );
        std::fs::remove_file(&vault).unwrap();
        std::fs::create_dir(&vault).unwrap();
        digest_at(
            home.path(),
            DigestPeriod::Daily,
            OutputFormat::Table,
            retry_now,
        )
        .unwrap();
        assert_eq!(std::fs::read(&archive_path).unwrap(), archive);
        assert_eq!(
            std::fs::read_to_string(vault.join(format!("NEOTH/Daily/{tag}.md"))).unwrap(),
            original.to_obsidian_md(),
        );
        assert_eq!(
            std::fs::read_to_string(home.path().join("reflections/daily-last.txt")).unwrap(),
            tag
        );
    }

    #[test]
    fn cli_recovers_archive_without_state_before_using_its_new_candidate() {
        use crate::reflection::hygiene_store::lock_daily_admission;
        use crate::reflection::periodic::{self, PeriodKind};

        let home = tempfile::tempdir().unwrap();
        let now = 1_787_788_800i64;
        let conn = store::open(&home.path().join("views.db")).unwrap();
        conn.execute(
            "INSERT INTO idx_episode (event_id, event_type, ts_ns, text, text_hash) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![1i64, crate::wal::events::EVENT_TYPE_RAW_TEXT as i64, now.saturating_mul(1_000_000_000), "cli changed candidate topics", "cli-archive-first"],
        ).unwrap();
        let tag = periodic::date_tag_from_unix(now);
        let original = periodic::build_reflection(
            PeriodKind::Daily,
            &tag,
            &["cli-persisted-original".into()],
            now.saturating_sub(60),
        )
        .unwrap();
        periodic::open_daily_archive_transaction(home.path())
            .unwrap()
            .append_once(&original)
            .unwrap();
        digest_at(home.path(), DigestPeriod::Daily, OutputFormat::Table, now).unwrap();
        let archive =
            std::fs::read(periodic::jsonl_file(home.path(), PeriodKind::Daily, &tag)).unwrap();
        assert_eq!(
            serde_json::from_slice::<periodic::PeriodReflection>(&archive).unwrap(),
            original
        );
        let state = lock_daily_admission(home.path())
            .unwrap()
            .load()
            .unwrap()
            .unwrap();
        assert!(state.archive_sha256.is_some());
    }

    #[test]
    fn collect_covered_reads_skills_from_the_supplied_home() {
        let home = tempfile::tempdir().unwrap();
        let skill_dir = home.path().join("skills").join("home-specific");
        std::fs::create_dir_all(&skill_dir).unwrap();
        std::fs::write(
            skill_dir.join("skill.yaml"),
            "id: home-specific\n\
             description: Home-specific test skill\n\
             trigger_keywords: [home]\n\
             system_prompt: Use this home.\n",
        )
        .unwrap();

        let covered = collect_covered(home.path());
        assert!(covered.iter().any(|item| item == "home-specific"));
    }
}
