//! `neoth reflect` — self-reflection surfaces. `tech-news` pulls trending
//! Hacker News topics and flags the ones the operator's installed skills +
//! recent memory don't cover yet (a "tech-currency" gap). The operator tunes
//! the noisy HN signal with per-operator ignore/pin lists (`reflect ignore` /
//! `reflect pin`). The feed adapter lives in `crate::sources::hackernews`.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::memory::store;
use crate::sources::hackernews::{self, GapFilter};

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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
    use crate::reflection::periodic::{self, PeriodKind, date_tag_from_unix, year_tag_from_unix};

    let now_unix = crate::time::now_unix_i64();
    let now_ns = crate::time::now_unix_ns_i64();
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
    let marker_name = match period {
        DigestPeriod::Daily => "daily-last.txt",
        DigestPeriod::Yearly => "yearly-last.txt",
    };
    let marker_path = home.join("reflections").join(marker_name);
    let already_done = if marker_path
        .try_exists()
        .with_context(|| format!("inspect reflection marker {}", marker_path.display()))?
    {
        std::fs::read_to_string(&marker_path)
            .with_context(|| format!("read reflection marker {}", marker_path.display()))?
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
    periodic::append(home, &refl).context("archive reflection")?;
    // GR-fix: record completion for this tag (same marker the daemon writes) so a
    // re-run on the same day is a no-op.
    crate::util::atomic_write::atomic_write_private(&marker_path, tag.as_bytes())
        .with_context(|| format!("persist reflection marker {}", marker_path.display()))?;

    // Obsidian sync if a vault is configured.
    let mut obsidian_path = None;
    if let Some(vault) = cfg.obsidian_vault.as_deref() {
        let subdir = cfg.obsidian_subdir.as_deref().unwrap_or("NEOTH");
        let o = periodic::sync_to_obsidian(home, std::path::Path::new(vault), subdir, kind, &tag)
            .context("Obsidian sync")?;
        if o.written {
            obsidian_path = Some(o.target_path.display().to_string());
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
    let stories = hackernews::top_stories(limit)
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
    let skills_dir = crate::skills::installer::default_skills_dir();
    for e in crate::skills::installer::list_installed(&skills_dir) {
        covered.push(e.dir_name);
        if let Some(id) = e.manifest_id {
            covered.push(id);
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
