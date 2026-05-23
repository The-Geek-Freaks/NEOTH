//! O-2 + O-3 + O-4 + O-5 — Obsidian vault init + plugin bootstrap +
//! WAL ⇄ vault materialiser primitives.
//!
//! O-2: build a fresh `~/Documents/NEOTH-Vault/` with a curated
//!      `.obsidian/` config so operators get a sane starting point.
//! O-3: list of bootstrap plugins NEOTH recommends (Dataview,
//!      Smart Connections, Templater, Periodic Notes, plus the
//!      custom `neoth-archive-bridge` plugin scaffold).
//! O-4: pure-fn that turns a WAL event into a markdown row for
//!      `Daily/YYYY-MM-DD.md` with episode metadata as frontmatter.
//! O-5: pure-fn that walks a vault markdown frontmatter back into
//!      the WAL-ingest shape so operator edits are first-class.
//!
//! No filesystem mutations happen inside the pure helpers — they
//! return owned strings + Vec<u8> the caller writes. Tests exercise
//! the full round-trip via tempfile-backed fixtures.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Canonical NEOTH vault subdirectory name.
pub const NEOTH_VAULT_DIR_NAME: &str = "NEOTH-Vault";

/// Compute the recommended vault path: `<home>/Documents/NEOTH-Vault`.
/// Operator overrides via wizard prompt.
pub fn default_vault_path() -> Option<PathBuf> {
    let home = if cfg!(target_os = "windows") {
        std::env::var_os("USERPROFILE").map(PathBuf::from)
    } else {
        std::env::var_os("HOME").map(PathBuf::from)
    }?;
    Some(home.join("Documents").join(NEOTH_VAULT_DIR_NAME))
}

/// One bootstrap plugin NEOTH recommends. `community_id` matches
/// the Obsidian community-plugins registry slug; the wizard
/// surfaces these for the operator to enable in one click.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObsidianBootstrapPlugin {
    pub community_id: &'static str,
    pub display_name: &'static str,
    pub why: &'static str,
}

/// Pinned bootstrap plugin list. Adding a sixth needs a wizard UX
/// rethink — 5 already pushes the picker; if NEOTH needs more, the
/// extras belong in a "recommended" + "advanced" split.
pub const BOOTSTRAP_PLUGINS: &[ObsidianBootstrapPlugin] = &[
    ObsidianBootstrapPlugin {
        community_id: "dataview",
        display_name: "Dataview",
        why: "Query the NEOTH-Vault as a structured database — pulls daily-note frontmatter into tables + lists.",
    },
    ObsidianBootstrapPlugin {
        community_id: "smart-connections",
        display_name: "Smart Connections",
        why: "Local-embedding semantic search across the vault — finds related notes from years of NEOTH activity.",
    },
    ObsidianBootstrapPlugin {
        community_id: "templater-obsidian",
        display_name: "Templater",
        why: "Lets NEOTH-Vault auto-generate daily-note templates so every materialised day starts in the same shape.",
    },
    ObsidianBootstrapPlugin {
        community_id: "periodic-notes",
        display_name: "Periodic Notes",
        why: "Drives the daily / weekly / monthly note convention NEOTH writes into. Operator clicks a day, gets the right file.",
    },
    ObsidianBootstrapPlugin {
        community_id: "neoth-archive-bridge",
        display_name: "NEOTH Archive Bridge (custom)",
        why: "Custom NEOTH-side plugin: real-time vault edits stream back into the WAL indexer so operator edits become first-class memory.",
    },
];

/// Frontmatter NEOTH writes at the top of every daily note. Stored
/// as YAML; serde round-trips through `serde_yaml` so a future
/// schema bump is one struct edit.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct DailyNoteFrontmatter {
    /// ISO-8601 date `YYYY-MM-DD` — matches the filename.
    pub date: String,
    /// NEOTH WAL event count materialised into this note.
    pub event_count: usize,
    /// Distinct providers that produced output this day.
    pub providers: Vec<String>,
    /// Top-3 distinct skills invoked this day.
    pub top_skills: Vec<String>,
    /// Operator-readable tags for Dataview queries.
    pub tags: Vec<String>,
}

/// One source WAL event the materialiser knows how to render. The
/// caller filters to noteworthy events (RAW_TEXT / PROVIDER_RESPONSE
/// / CONSENT_DENIED / MEMORY_PROMOTED) before passing them here;
/// the materialiser only formats.
#[derive(Clone, Debug)]
pub struct MaterialiseEvent {
    /// `RAW_TEXT` / `PROVIDER_RESPONSE` / etc. Pinned wire form.
    pub kind: String,
    /// ISO-8601 timestamp with timezone (operator-local).
    pub ts_iso: String,
    /// Operator-readable summary — already truncated to picker size.
    pub summary: String,
    /// Optional provider that produced this row.
    pub provider: Option<String>,
    /// Optional skill slug invoked.
    pub skill: Option<String>,
}

/// Render one MaterialiseEvent as the markdown row that appends
/// into `Daily/YYYY-MM-DD.md`. Format pinned so a future re-render
/// matches existing rows — operators reading old notes expect
/// stable formatting.
pub fn render_daily_row(event: &MaterialiseEvent) -> String {
    let provider_pill = event
        .provider
        .as_deref()
        .map(|p| format!(" `{p}`"))
        .unwrap_or_default();
    let skill_pill = event
        .skill
        .as_deref()
        .map(|s| format!(" `/{s}`"))
        .unwrap_or_default();
    format!(
        "- **{ts}** `{kind}`{provider}{skill} — {summary}",
        ts = event.ts_iso,
        kind = event.kind,
        provider = provider_pill,
        skill = skill_pill,
        summary = event.summary,
    )
}

/// Render the full daily-note document: frontmatter block + a list
/// of rendered rows. Caller writes the result into
/// `<vault>/Daily/YYYY-MM-DD.md`.
pub fn render_daily_note(frontmatter: &DailyNoteFrontmatter, events: &[MaterialiseEvent]) -> Result<String> {
    let fm_yaml = serde_yaml::to_string(frontmatter)
        .context("serialise daily-note frontmatter")?;
    let mut out = String::with_capacity(fm_yaml.len() + events.len() * 80 + 32);
    out.push_str("---\n");
    out.push_str(&fm_yaml);
    out.push_str("---\n\n");
    out.push_str("# NEOTH activity — ");
    out.push_str(&frontmatter.date);
    out.push_str("\n\n");
    for ev in events {
        out.push_str(&render_daily_row(ev));
        out.push('\n');
    }
    Ok(out)
}

/// Parse a daily-note markdown back into its frontmatter — the
/// reverse direction (O-5). Returns the frontmatter when present;
/// `None` when the note carries no YAML frontmatter block (operator
/// hand-wrote a free-form note that the indexer should still
/// pick up as a generic memory).
pub fn parse_daily_note_frontmatter(markdown: &str) -> Option<DailyNoteFrontmatter> {
    let stripped = markdown.trim_start_matches('\u{feff}');
    if !stripped.starts_with("---\n") {
        return None;
    }
    let rest = &stripped[4..];
    let end = rest.find("\n---\n")?;
    let yaml = &rest[..end];
    serde_yaml::from_str(yaml).ok()
}

/// List of files + content NEOTH writes into a fresh vault. Used
/// by the wizard step that builds the vault on first run.
pub struct VaultBootstrapFile<'a> {
    pub relative_path: &'a str,
    pub content: &'a str,
}

/// Canonical bootstrap files for a fresh NEOTH-Vault. Wizard
/// iterates + writes each into `<vault>/<relative_path>` with
/// `mkdir -p` semantics.
pub fn bootstrap_files() -> Vec<VaultBootstrapFile<'static>> {
    vec![
        VaultBootstrapFile {
            relative_path: "README.md",
            content: include_str!("../../assets/obsidian_vault/README.md"),
        },
        VaultBootstrapFile {
            relative_path: ".obsidian/app.json",
            content: include_str!("../../assets/obsidian_vault/.obsidian/app.json"),
        },
        VaultBootstrapFile {
            relative_path: ".obsidian/appearance.json",
            content: include_str!("../../assets/obsidian_vault/.obsidian/appearance.json"),
        },
        VaultBootstrapFile {
            relative_path: "Templates/Daily Note.md",
            content: include_str!("../../assets/obsidian_vault/Templates/Daily Note.md"),
        },
    ]
}

/// Compute the daily-note path inside `vault_root` for `date_iso`
/// (`YYYY-MM-DD`). Pinned: `<vault>/Daily/YYYY-MM-DD.md`.
pub fn daily_note_path(vault_root: &Path, date_iso: &str) -> PathBuf {
    vault_root.join("Daily").join(format!("{date_iso}.md"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(kind: &str, ts: &str, summary: &str) -> MaterialiseEvent {
        MaterialiseEvent {
            kind: kind.into(),
            ts_iso: ts.into(),
            summary: summary.into(),
            provider: None,
            skill: None,
        }
    }

    #[test]
    fn neoth_vault_dir_name_pinned() {
        assert_eq!(NEOTH_VAULT_DIR_NAME, "NEOTH-Vault");
    }

    #[test]
    fn default_vault_path_lands_under_documents() {
        if let Some(p) = default_vault_path() {
            let s = p.to_string_lossy();
            assert!(s.contains("Documents"));
            assert!(s.contains("NEOTH-Vault"));
        }
    }

    #[test]
    fn bootstrap_plugins_pinned_count_and_required_entries() {
        assert_eq!(BOOTSTRAP_PLUGINS.len(), 5);
        let ids: Vec<&str> = BOOTSTRAP_PLUGINS.iter().map(|p| p.community_id).collect();
        for required in [
            "dataview",
            "smart-connections",
            "templater-obsidian",
            "periodic-notes",
            "neoth-archive-bridge",
        ] {
            assert!(ids.contains(&required), "missing plugin: {required}");
        }
    }

    #[test]
    fn every_bootstrap_plugin_carries_distinct_id() {
        let ids: Vec<&str> = BOOTSTRAP_PLUGINS.iter().map(|p| p.community_id).collect();
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(ids.len(), unique.len(), "duplicate plugin id");
    }

    #[test]
    fn every_bootstrap_plugin_explains_why_in_one_line() {
        for p in BOOTSTRAP_PLUGINS {
            assert!(!p.why.is_empty(), "{} missing why", p.community_id);
            assert!(p.why.len() <= 220, "{} why too long for picker", p.community_id);
        }
    }

    // ── render_daily_row ────────────────────────────────────────

    #[test]
    fn render_row_includes_ts_kind_and_summary() {
        let e = ev("RAW_TEXT", "2026-05-23T10:00:00+02:00", "first message");
        let line = render_daily_row(&e);
        assert!(line.contains("2026-05-23T10:00:00+02:00"));
        assert!(line.contains("RAW_TEXT"));
        assert!(line.contains("first message"));
    }

    #[test]
    fn render_row_appends_provider_pill_when_present() {
        let e = MaterialiseEvent {
            provider: Some("claude_cli".into()),
            ..ev("PROVIDER_RESPONSE", "t", "ok")
        };
        let line = render_daily_row(&e);
        assert!(line.contains("`claude_cli`"));
    }

    #[test]
    fn render_row_appends_skill_pill_when_present() {
        let e = MaterialiseEvent {
            skill: Some("repo-map".into()),
            ..ev("SKILL_INVOKED", "t", "ran skill")
        };
        let line = render_daily_row(&e);
        assert!(line.contains("`/repo-map`"));
    }

    #[test]
    fn render_row_starts_with_markdown_list_marker() {
        let e = ev("RAW_TEXT", "t", "hello");
        assert!(render_daily_row(&e).starts_with("- "));
    }

    // ── render_daily_note ───────────────────────────────────────

    #[test]
    fn render_note_wraps_yaml_frontmatter_with_triple_dash() {
        let fm = DailyNoteFrontmatter {
            date: "2026-05-23".into(),
            event_count: 1,
            ..Default::default()
        };
        let note = render_daily_note(&fm, &[ev("RAW_TEXT", "t", "hello")]).unwrap();
        assert!(note.starts_with("---\n"));
        // Two `---\n` markers — opening + closing the frontmatter.
        assert_eq!(note.matches("---\n").count(), 2);
        assert!(note.contains("date: 2026-05-23"));
        assert!(note.contains("# NEOTH activity — 2026-05-23"));
    }

    #[test]
    fn render_note_appends_every_event() {
        let fm = DailyNoteFrontmatter {
            date: "2026-05-23".into(),
            event_count: 2,
            ..Default::default()
        };
        let events = vec![
            ev("RAW_TEXT", "t1", "first"),
            ev("PROVIDER_RESPONSE", "t2", "second"),
        ];
        let note = render_daily_note(&fm, &events).unwrap();
        assert!(note.contains("first"));
        assert!(note.contains("second"));
    }

    // ── parse_daily_note_frontmatter (O-5 reverse) ──────────────

    #[test]
    fn parse_returns_none_for_note_without_frontmatter() {
        let md = "# Just a heading\n\nBody text without frontmatter.";
        assert!(parse_daily_note_frontmatter(md).is_none());
    }

    #[test]
    fn parse_returns_frontmatter_when_present() {
        let fm = DailyNoteFrontmatter {
            date: "2026-05-23".into(),
            event_count: 5,
            providers: vec!["claude_cli".into()],
            top_skills: vec!["repo-map".into()],
            tags: vec!["neoth".into()],
        };
        let note = render_daily_note(&fm, &[]).unwrap();
        let parsed = parse_daily_note_frontmatter(&note).unwrap();
        assert_eq!(parsed, fm);
    }

    #[test]
    fn parse_tolerates_utf8_bom() {
        let mut md = String::from("\u{feff}");
        md.push_str("---\ndate: 2026-05-23\nevent_count: 0\nproviders: []\ntop_skills: []\ntags: []\n---\n\n");
        let parsed = parse_daily_note_frontmatter(&md).unwrap();
        assert_eq!(parsed.date, "2026-05-23");
    }

    // ── daily_note_path ─────────────────────────────────────────

    #[test]
    fn daily_note_path_lands_under_daily_subdir() {
        let root = Path::new("/some/vault");
        let p = daily_note_path(root, "2026-05-23");
        assert_eq!(p, Path::new("/some/vault/Daily/2026-05-23.md"));
    }
}
