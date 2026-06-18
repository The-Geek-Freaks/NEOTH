//! Daily + yearly self-reflection cadences.
//!
//! Mirrors the weekly OB-02 surface ([`super::WeeklyReflection`]): an archivable
//! record that persists as JSONL under `<home>/reflections/<kind>/<tag>.jsonl`
//! and renders to an Obsidian note at `<vault>/<subdir>/{Daily,Yearly}/<tag>.md`.
//! Builders compose a record from the period's top operator topics. Same
//! deterministic, offline, free rationale as the weekly reflection — no LLM, no
//! network, so the nightly + year-end passes run unattended even with the cloud
//! quota exhausted.

use std::path::{Path, PathBuf};

/// Which cadence a [`PeriodReflection`] belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeriodKind {
    Daily,
    Yearly,
}

impl PeriodKind {
    /// Stable lower-case discriminator (JSONL field + subfolder name).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Daily => "daily",
            Self::Yearly => "yearly",
        }
    }
    /// Obsidian subfolder under `<vault>/<subdir>/` (Title-cased).
    pub fn vault_subdir(self) -> &'static str {
        match self {
            Self::Daily => "Daily",
            Self::Yearly => "Yearly",
        }
    }
    /// How many days of episodes the period summarises.
    pub fn window_days(self) -> i64 {
        match self {
            Self::Daily => 1,
            Self::Yearly => 365,
        }
    }
}

/// German one-line summary template per cadence (mirrors the weekly
/// `REFLECTION_BODY_TEMPLATE`). `{topics}` is replaced with the phrase.
fn body_template(kind: PeriodKind) -> &'static str {
    match kind {
        PeriodKind::Daily => "Heute hast du an {topics} gearbeitet.",
        PeriodKind::Yearly => "Dieses Jahr drehte sich viel um {topics}.",
    }
}

/// One archived daily/yearly reflection. Serde-stable — any new field MUST be
/// `#[serde(default)]` so historical records survive schema evolution.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct PeriodReflection {
    /// `"daily"` | `"yearly"`.
    pub kind: String,
    /// `"YYYY-MM-DD"` (daily) or `"YYYY"` (yearly). The dedup discriminator.
    pub tag: String,
    pub generated_ts_unix: i64,
    pub topics: Vec<String>,
    pub body: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

impl PeriodReflection {
    /// Render to Obsidian markdown — YAML frontmatter + H1 + ## Body + ## Topics.
    /// Field order pinned for Dataview stability (matches WeeklyReflection).
    pub fn to_obsidian_md(&self) -> String {
        let title_kind = if self.kind == "yearly" {
            "Yearly"
        } else {
            "Daily"
        };
        let yaml_list = |key: &str, items: &[String]| -> String {
            if items.is_empty() {
                format!("{key}: []")
            } else {
                let inner = items
                    .iter()
                    .map(|t| format!("\"{}\"", escape_yaml(t)))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("{key}: [{inner}]")
            }
        };
        let topics_body = if self.topics.is_empty() {
            "(no topics)\n".to_string()
        } else {
            self.topics
                .iter()
                .map(|t| format!("- {t}\n"))
                .collect::<String>()
        };
        format!(
            "---\n\
             kind: \"{kind}\"\n\
             tag: \"{tag}\"\n\
             generated_unix: {ts}\n\
             {yaml_topics}\n\
             {yaml_tags}\n\
             ---\n\n\
             # {title_kind} reflection {tag}\n\n\
             ## Body\n\n\
             {body}\n\n\
             ## Topics\n\n\
             {topics_body}",
            kind = escape_yaml(&self.kind),
            tag = escape_yaml(&self.tag),
            ts = self.generated_ts_unix,
            yaml_topics = yaml_list("topics", &self.topics),
            yaml_tags = yaml_list("tags", &self.tags),
            body = self.body,
        )
    }
}

fn escape_yaml(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// `"YYYY-MM-DD"` for a unix timestamp (UTC).
pub fn date_tag_from_unix(ts_unix: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(ts_unix, 0)
        .unwrap_or_else(|| chrono::DateTime::<chrono::Utc>::from_timestamp(0, 0).unwrap())
        .format("%Y-%m-%d")
        .to_string()
}

/// `"YYYY"` for a unix timestamp (UTC).
pub fn year_tag_from_unix(ts_unix: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(ts_unix, 0)
        .unwrap_or_else(|| chrono::DateTime::<chrono::Utc>::from_timestamp(0, 0).unwrap())
        .format("%Y")
        .to_string()
}

/// Compose a [`PeriodReflection`] from extracted topics. `None` on empty topics
/// (no vacuous note), matching `build_weekly_reflection`.
pub fn build_reflection(
    kind: PeriodKind,
    tag: &str,
    topics: &[String],
    generated_ts_unix: i64,
) -> Option<PeriodReflection> {
    if topics.is_empty() {
        return None;
    }
    let body = body_template(kind).replace("{topics}", &format_topics_phrase(topics));
    Some(PeriodReflection {
        kind: kind.as_str().to_string(),
        tag: tag.to_string(),
        generated_ts_unix,
        topics: topics.to_vec(),
        body,
        tags: Vec::new(),
    })
}

/// German "X, Y und Z" phrase (matches the weekly reflection's helper).
fn format_topics_phrase(topics: &[String]) -> String {
    match topics.len() {
        0 => String::new(),
        1 => topics[0].clone(),
        2 => format!("{} und {}", topics[0], topics[1]),
        _ => {
            let head = topics[..topics.len() - 1].join(", ");
            format!("{}, und {}", head, topics[topics.len() - 1])
        }
    }
}

/// `<home>/reflections/<kind>/`.
pub fn periodic_dir(home: &Path, kind: PeriodKind) -> PathBuf {
    home.join("reflections").join(kind.as_str())
}

/// `<home>/reflections/<kind>/<tag>.jsonl`.
pub fn jsonl_file(home: &Path, kind: PeriodKind, tag: &str) -> PathBuf {
    periodic_dir(home, kind).join(format!("{tag}.jsonl"))
}

/// Append one reflection to its per-tag JSONL (creates the dir on demand).
pub fn append(home: &Path, reflection: &PeriodReflection) -> std::io::Result<()> {
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    let kind = if reflection.kind == "yearly" {
        PeriodKind::Yearly
    } else {
        PeriodKind::Daily
    };
    fs::create_dir_all(periodic_dir(home, kind))?;
    let path = jsonl_file(home, kind, &reflection.tag);
    let mut line = serde_json::to_vec(reflection).map_err(std::io::Error::other)?;
    line.push(b'\n');
    let mut f = OpenOptions::new().create(true).append(true).open(&path)?;
    f.write_all(&line)?;
    f.flush()?;
    Ok(())
}

/// Load every reflection for `tag`. Missing file → empty; bad lines skipped.
pub fn load_for_tag(home: &Path, kind: PeriodKind, tag: &str) -> Vec<PeriodReflection> {
    let Ok(body) = std::fs::read_to_string(jsonl_file(home, kind, tag)) else {
        return Vec::new();
    };
    body.lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

/// Outcome of [`sync_to_obsidian`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeriodSyncOutcome {
    pub tag: String,
    pub written: bool,
    pub target_path: PathBuf,
    pub reflection_count: usize,
    pub bytes_written: usize,
}

/// Render every reflection for `tag` into one Obsidian note at
/// `<vault>/<subdir>/<Daily|Yearly>/<tag>.md` (atomic `.tmp` + rename). Empty →
/// `written: false`, no file (keeps the vault clean for quiet days/years).
pub fn sync_to_obsidian(
    neoth_home: &Path,
    vault_root: &Path,
    subdir: &str,
    kind: PeriodKind,
    tag: &str,
) -> std::io::Result<PeriodSyncOutcome> {
    let reflections = load_for_tag(neoth_home, kind, tag);
    let dest_dir = vault_root.join(subdir).join(kind.vault_subdir());
    let target_path = dest_dir.join(format!("{tag}.md"));

    if reflections.is_empty() {
        return Ok(PeriodSyncOutcome {
            tag: tag.to_string(),
            written: false,
            target_path,
            reflection_count: 0,
            bytes_written: 0,
        });
    }

    let body: String = reflections
        .iter()
        .map(PeriodReflection::to_obsidian_md)
        .collect::<Vec<_>>()
        .join("\n---\n\n");

    // Canonical crash-safe write: temp + fsync + atomic rename-replace (std
    // rename is atomic-replace on Windows too — no remove-then-rename gap, which
    // is the bug the hand-rolled pattern had). Creates the parent dir.
    crate::util::atomic_write::atomic_write(&target_path, body.as_bytes())?;

    Ok(PeriodSyncOutcome {
        tag: tag.to_string(),
        written: true,
        target_path,
        reflection_count: reflections.len(),
        bytes_written: body.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn date_and_year_tags_format() {
        let ts = 1_767_225_600; // 2026-01-01 00:00:00 UTC
        assert_eq!(date_tag_from_unix(ts), "2026-01-01");
        assert_eq!(year_tag_from_unix(ts), "2026");
    }

    #[test]
    fn build_reflection_none_on_empty_topics() {
        assert!(build_reflection(PeriodKind::Daily, "2026-06-16", &[], 1).is_none());
        let r = build_reflection(
            PeriodKind::Daily,
            "2026-06-16",
            &["rust".into(), "slint".into()],
            1_700_000_000,
        )
        .unwrap();
        assert_eq!(r.kind, "daily");
        assert!(r.body.contains("rust"));
        let y = build_reflection(PeriodKind::Yearly, "2026", &["neoth".into()], 1).unwrap();
        assert_eq!(y.kind, "yearly");
        assert!(y.body.contains("Jahr"));
    }

    #[test]
    fn obsidian_md_has_frontmatter_and_title() {
        let r = build_reflection(
            PeriodKind::Daily,
            "2026-06-16",
            &["webgpu".into()],
            1_700_000_000,
        )
        .unwrap();
        let md = r.to_obsidian_md();
        assert!(md.starts_with("---\nkind: \"daily\"\n"));
        assert!(md.contains("tag: \"2026-06-16\""));
        assert!(md.contains("# Daily reflection 2026-06-16"));
        assert!(md.contains("topics: [\"webgpu\"]"));
        assert!(md.contains("- webgpu\n"));
    }

    #[test]
    fn append_load_and_sync_roundtrip() {
        let home = TempDir::new().unwrap();
        let vault = TempDir::new().unwrap();
        let r = build_reflection(PeriodKind::Yearly, "2026", &["zig".into()], 1).unwrap();
        append(home.path(), &r).unwrap();
        let loaded = load_for_tag(home.path(), PeriodKind::Yearly, "2026");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0], r);

        let out = sync_to_obsidian(
            home.path(),
            vault.path(),
            "NEOTH",
            PeriodKind::Yearly,
            "2026",
        )
        .unwrap();
        assert!(out.written);
        assert!(out.target_path.ends_with("NEOTH/Yearly/2026.md"));
        assert!(out.target_path.exists());

        // Empty tag → no file, written:false.
        let empty = sync_to_obsidian(
            home.path(),
            vault.path(),
            "NEOTH",
            PeriodKind::Daily,
            "1999-01-01",
        )
        .unwrap();
        assert!(!empty.written);
        assert!(!empty.target_path.exists());
    }
}
