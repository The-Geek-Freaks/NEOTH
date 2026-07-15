//! GOLD-ADAPT-JV-MODE-03 — Self-capability awareness map.
//!
//! NEOTH builds a live, read-only self-wiki that indexes every feature the
//! binary ships: bundled skills, daemon crons, slash commands, and the
//! top-level CLI sub-commands. The agent can query this wiki to REASON
//! about and select its own capabilities — a prerequisite for self-activation
//! (JV-MODE-04).
//!
//! ## Design
//!
//! * **Headless / pure**: `build()` has no I/O, no config read, no async.
//!   It walks the compile-time static tables (`BUNDLED_SKILLS`, `DAEMON_CRONS`),
//!   the canonical clap tree (`Cli::command()`), and the in-process
//!   `built_in_commands()` function. No filesystem access means no fragile
//!   startup ordering.
//!
//! * **Structured**: every capability maps to a typed entry so downstream
//!   consumers can filter by kind, search by keyword, or render a summary
//!   without re-parsing YAML.
//!
//! * **No hot files**: this module intentionally avoids `config/`, `serve*`,
//!   `channels/`, `cluster/`, and any file in the collision-prone lane.
//!
//! ## Usage
//!
//! ```rust
//! let wiki = neothd::memory::self_wiki::build();
//! let skill_ids: Vec<&str> = wiki.skills().map(|e| e.id).collect();
//! let cron_ids: Vec<&str> = wiki.crons().map(|e| e.id).collect();
//! ```

use clap::CommandFactory;

use crate::skills::bundled::BUNDLED_SKILLS;
use crate::slash::builtins::built_in_commands;

// ---------------------------------------------------------------------------
// Capability kinds
// ---------------------------------------------------------------------------

/// High-level kind of a self-wiki entry. Drives filtering + rendering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CapabilityKind {
    /// A bundled or operator-installed skill (YAML manifest).
    Skill,
    /// A daemon-managed background cron.
    Cron,
    /// A CLI sub-command (`neoth <command>`).
    CliCommand,
    /// A slash command (`/name`).
    SlashCommand,
}

impl CapabilityKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Skill => "skill",
            Self::Cron => "cron",
            Self::CliCommand => "cli_command",
            Self::SlashCommand => "slash_command",
        }
    }
}

// ---------------------------------------------------------------------------
// Entry type
// ---------------------------------------------------------------------------

/// One capability entry in the self-wiki.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityEntry {
    /// Stable machine-readable identifier (kebab-case or snake_case).
    pub id: &'static str,
    /// Human-readable one-liner description.
    pub description: &'static str,
    /// Capability kind.
    pub kind: CapabilityKind,
    /// Optional feature flag / gate name. `None` = always active. Present when
    /// the capability requires a Cargo feature or a freedom.yaml toggle to be
    /// enabled.
    pub feature_gate: Option<&'static str>,
}

// ---------------------------------------------------------------------------
// Daemon cron registry (static)
// ---------------------------------------------------------------------------

/// A minimal record for each daemon-managed background cron.
/// These are the internal, always-available crons distinct from operator-
/// defined jobs in `~/.neoth/jobs.yaml`.
struct DaemonCron {
    id: &'static str,
    description: &'static str,
    /// `Some("feature_name")` when the cron is gated behind a Cargo feature
    /// or a `freedom.yaml` flag. `None` = unconditionally compiled in.
    gate: Option<&'static str>,
}

/// Every daemon cron NEOTH ships in its binary, derived from `daemon/mod.rs`
/// and the `daemon/*.rs` doc-comments. Sorted by id for deterministic output.
static DAEMON_CRONS: &[DaemonCron] = &[
    DaemonCron {
        id: "audit-rpc",
        description: "Loopback audit-RPC listener for one-shot CLIs to forward audit frames to the WAL-owning daemon.",
        gate: Some("freedom.yaml::audit_rpc.enabled"),
    },
    DaemonCron {
        id: "auto-update",
        description: "Daemon CLI auto-apply loop: applies updates for NEOTH-managed CLIs at Elevated/Full autonomy.",
        gate: None,
    },
    DaemonCron {
        id: "backup",
        description: "Periodic WAL + SQLite backup to the operator-configured destination.",
        gate: None,
    },
    DaemonCron {
        id: "backup-retention",
        description: "Prunes old backup files beyond the configured retention window.",
        gate: None,
    },
    DaemonCron {
        id: "contradiction-resolve",
        description: "Daily contradiction auto-resolution: temporal-supersede, semantic-equiv merge, human-review queue.",
        gate: Some("freedom.yaml::contradiction_resolve.enabled"),
    },
    DaemonCron {
        id: "doctor",
        description: "Periodic self-diagnosis: validates WAL, SQLite schema, channel adapters, and freedom.yaml consistency.",
        gate: None,
    },
    DaemonCron {
        id: "drift-alert",
        description: "Profile drift alert cron: emits WAL 0xBA when operator profile drift exceeds threshold.",
        gate: Some("freedom.yaml::drift_alert.enabled"),
    },
    DaemonCron {
        id: "g02-surfacing",
        description: "Daily proactive surfacing cron: scans idx_profile for novel high-confidence claims.",
        gate: None,
    },
    DaemonCron {
        id: "monitor",
        description: "WAL integrity + crash.log + channel silence monitor; emits 0x48/0x49/0x4A on anomalies.",
        gate: Some("freedom.yaml::monitor.enabled"),
    },
    // OH-14 — alphabetically between "monitor" and "omi-ingest".
    DaemonCron {
        id: "obsidian-wiki-rebuild",
        description: "Periodic NEOTH self-wiki rebuild: re-renders PLAN/ design corpus into the Obsidian vault and refreshes ground-truth pointers (scope neoth-self-wiki). Emits 0xFA on each successful tick.",
        gate: Some("freedom.yaml::obsidian_vault"),
    },
    DaemonCron {
        id: "omi-ingest",
        description: "OMI transcript ingest: polls a local OMI backend, sanitises, promotes to ground-truth.",
        gate: Some("freedom.yaml::omi.enabled"),
    },
    DaemonCron {
        id: "pattern",
        description: "Inactivity-gap detector: enqueues proactive nudge after configured silence period.",
        gate: Some("freedom.yaml::pattern_cron.enabled"),
    },
    DaemonCron {
        id: "proactive-dispatcher",
        description: "Periodic drain of the ProactiveQueue into the proactive_delivered.jsonl sidecar.",
        gate: None,
    },
    DaemonCron {
        id: "profile-adapt",
        description: "Profile adaptation cron: applies skill-routing weight updates from recent session outcomes.",
        gate: None,
    },
    DaemonCron {
        id: "recall-latency",
        description: "Recall p95 latency monitor: emits 0x4B RECALL_LATENCY_ALERT when p95 exceeds threshold.",
        gate: Some("freedom.yaml::recall_latency_monitor.enabled"),
    },
    DaemonCron {
        id: "reflection",
        description: "Periodic reflection builder: emits one reflection ProactiveItem per ISO week.",
        gate: None,
    },
    DaemonCron {
        id: "regression",
        description: "Regression checker: compares current WAL metrics against a baseline snapshot.",
        gate: None,
    },
    // GOLD-ADAPT-GRAPH-05 — alphabetically between "session-health" and "token-anomaly".
    DaemonCron {
        id: "self-map",
        description: "NEOTH self-map cron: runs graphify on own source, writes GRAPH_REPORT to NEOTH-Self/ vault, ingests into idx_groundtruth (scope neoth-self-map). Emits 0xFB SELF_MAP_COMPLETE.",
        gate: Some("freedom.yaml::obsidian_vault + self_map_source_dir"),
    },
    DaemonCron {
        id: "session-health",
        description: "Session health cron: detects stale open sessions and emits health warnings.",
        gate: None,
    },
    DaemonCron {
        id: "token-anomaly",
        description: "Token usage anomaly detector: alerts on sudden spikes in provider token consumption.",
        gate: None,
    },
    DaemonCron {
        id: "updater",
        description: "NEOTH self-update checker: polls for new binary releases per the configured update policy.",
        gate: None,
    },
    DaemonCron {
        id: "watchdog",
        description: "Service watchdog: probes supervised local services and auto-restarts them at Elevated+ autonomy.",
        gate: Some("freedom.yaml::watchdog.enabled"),
    },
];

// ---------------------------------------------------------------------------
// CLI command registry (canonical clap tree)
// ---------------------------------------------------------------------------

/// Minimal record for one top-level `neoth <subcommand>`.
struct CliCmd {
    id: String,
    description: String,
}

/// Top-level commands for the running build, derived once from the same clap
/// tree that parses `neoth`. Feature-gated variants therefore appear exactly
/// when they are compiled in, and GUI/self-wiki consumers cannot drift from CLI.
fn cli_commands() -> &'static [CliCmd] {
    static COMMANDS: std::sync::OnceLock<Vec<CliCmd>> = std::sync::OnceLock::new();

    COMMANDS
        .get_or_init(|| {
            let root = crate::cli::Cli::command();
            let mut commands = root
                .get_subcommands()
                .map(|command| {
                    let description = command
                        .get_about()
                        .map(ToString::to_string)
                        .or_else(|| command.get_long_about().map(ToString::to_string))
                        .and_then(|text| {
                            text.lines()
                                .next()
                                .map(str::trim)
                                .filter(|line| !line.is_empty())
                                .map(str::to_owned)
                        })
                        .unwrap_or_else(|| "CLI command.".to_owned());
                    CliCmd {
                        id: command.get_name().to_owned(),
                        description,
                    }
                })
                .collect::<Vec<_>>();
            commands.sort_unstable_by(|left, right| left.id.cmp(&right.id));
            commands
        })
        .as_slice()
}

// ---------------------------------------------------------------------------
// SelfWiki
// ---------------------------------------------------------------------------

/// The self-capability awareness map. Holds all indexed capability entries
/// for the running binary. Built once via [`build`] and queried read-only.
#[derive(Debug, Clone)]
pub struct SelfWiki {
    entries: Vec<CapabilityEntry>,
}

impl SelfWiki {
    /// Total number of capability entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` when no entries were indexed (should not happen in practice).
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over all entries regardless of kind.
    pub fn all(&self) -> impl Iterator<Item = &CapabilityEntry> {
        self.entries.iter()
    }

    /// Iterate over skill entries only.
    pub fn skills(&self) -> impl Iterator<Item = &CapabilityEntry> {
        self.entries
            .iter()
            .filter(|e| e.kind == CapabilityKind::Skill)
    }

    /// Iterate over daemon cron entries only.
    pub fn crons(&self) -> impl Iterator<Item = &CapabilityEntry> {
        self.entries
            .iter()
            .filter(|e| e.kind == CapabilityKind::Cron)
    }

    /// Iterate over CLI command entries only.
    pub fn cli_commands(&self) -> impl Iterator<Item = &CapabilityEntry> {
        self.entries
            .iter()
            .filter(|e| e.kind == CapabilityKind::CliCommand)
    }

    /// Iterate over slash command entries only.
    pub fn slash_commands(&self) -> impl Iterator<Item = &CapabilityEntry> {
        self.entries
            .iter()
            .filter(|e| e.kind == CapabilityKind::SlashCommand)
    }

    /// Find a single entry by kind + exact id. Returns `None` when not found.
    pub fn find(&self, kind: CapabilityKind, id: &str) -> Option<&CapabilityEntry> {
        self.entries.iter().find(|e| e.kind == kind && e.id == id)
    }

    /// All entries whose description contains `keyword` (case-insensitive).
    pub fn search_description(&self, keyword: &str) -> Vec<&CapabilityEntry> {
        let kw = keyword.to_lowercase();
        self.entries
            .iter()
            .filter(|e| e.description.to_lowercase().contains(&kw))
            .collect()
    }

    /// Render a compact human-readable summary (counts by kind).
    pub fn summary(&self) -> String {
        let skills = self.skills().count();
        let crons = self.crons().count();
        let cli = self.cli_commands().count();
        let slash = self.slash_commands().count();
        format!(
            "SelfWiki: {} skills | {} crons | {} cli-commands | {} slash-commands ({} total)",
            skills,
            crons,
            cli,
            slash,
            self.len(),
        )
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Build the self-wiki by walking every canonical capability registry.
///
/// This is a pure, synchronous, allocation-only function — no I/O, no config
/// read. Call it once at daemon startup (or lazily) and store the result.
pub fn build() -> SelfWiki {
    let mut entries: Vec<CapabilityEntry> = Vec::new();

    // ── 1. Bundled skills ─────────────────────────────────────────────────
    // BUNDLED_SKILLS is &[(&str, &str)] — (id, yaml_body). We take just the
    // id; parsing the YAML here would add cost for no benefit since the agent
    // needs only the identity of the skill, not its full manifest.
    for (id, _yaml) in BUNDLED_SKILLS {
        entries.push(CapabilityEntry {
            id,
            description: "bundled skill",
            kind: CapabilityKind::Skill,
            feature_gate: None,
        });
    }

    // ── 2. Daemon crons ───────────────────────────────────────────────────
    for cron in DAEMON_CRONS {
        entries.push(CapabilityEntry {
            id: cron.id,
            description: cron.description,
            kind: CapabilityKind::Cron,
            feature_gate: cron.gate,
        });
    }

    // ── 3. CLI commands ───────────────────────────────────────────────────
    for cmd in cli_commands() {
        entries.push(CapabilityEntry {
            id: cmd.id.as_str(),
            description: cmd.description.as_str(),
            kind: CapabilityKind::CliCommand,
            feature_gate: None,
        });
    }

    // ── 4. Slash commands (built-in set, in-process) ──────────────────────
    // `built_in_commands()` returns owned `Vec<SlashCommand>` but we need
    // `&'static str` for our entry. We collect into a local owned Vec first,
    // then leak a small Box per name/description string.  The wiki is
    // typically built once per process lifetime so the leak is acceptable.
    for sc in built_in_commands() {
        let id: &'static str = Box::leak(sc.name.into_boxed_str());
        let description: &'static str = Box::leak(sc.description.into_boxed_str());
        entries.push(CapabilityEntry {
            id,
            description,
            kind: CapabilityKind::SlashCommand,
            feature_gate: None,
        });
    }

    SelfWiki { entries }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build must succeed and return entries covering at least the four kinds.
    #[test]
    fn build_self_wiki_has_all_kinds() {
        let wiki = build();
        assert!(!wiki.is_empty(), "SelfWiki must not be empty");
        assert!(wiki.skills().count() > 0, "must have skill entries");
        assert!(wiki.crons().count() > 0, "must have cron entries");
        assert!(
            wiki.cli_commands().count() > 0,
            "must have CLI command entries"
        );
        assert!(
            wiki.slash_commands().count() > 0,
            "must have slash command entries"
        );
    }

    /// A known bundled skill id must appear in the wiki.
    #[test]
    fn known_skill_appears_in_wiki() {
        let wiki = build();
        // "diagnose" and "brainstorming" are long-standing bundled skills.
        let ids: Vec<&str> = wiki.skills().map(|e| e.id).collect();
        assert!(
            ids.contains(&"diagnose"),
            "expected 'diagnose' skill in wiki; found: {ids:?}"
        );
        assert!(
            ids.contains(&"brainstorming"),
            "expected 'brainstorming' skill in wiki; found: {ids:?}"
        );
    }

    /// Daemon cron names must appear.
    #[test]
    fn known_cron_appears_in_wiki() {
        let wiki = build();
        let ids: Vec<&str> = wiki.crons().map(|e| e.id).collect();
        assert!(
            ids.contains(&"watchdog"),
            "expected 'watchdog' cron in wiki; found: {ids:?}"
        );
        assert!(
            ids.contains(&"monitor"),
            "expected 'monitor' cron in wiki; found: {ids:?}"
        );
        assert!(
            ids.contains(&"contradiction-resolve"),
            "expected 'contradiction-resolve' cron in wiki; found: {ids:?}"
        );
    }

    /// Built-in slash commands must appear.
    #[test]
    fn known_slash_command_appears_in_wiki() {
        let wiki = build();
        let ids: Vec<&str> = wiki.slash_commands().map(|e| e.id).collect();
        assert!(
            ids.contains(&"help"),
            "expected '/help' slash command in wiki; found: {ids:?}"
        );
        assert!(
            ids.contains(&"recall"),
            "expected '/recall' slash command in wiki; found: {ids:?}"
        );
        assert!(
            ids.contains(&"status"),
            "expected '/status' slash command in wiki; found: {ids:?}"
        );
    }

    /// CLI sub-commands must appear.
    #[test]
    fn known_cli_command_appears_in_wiki() {
        let wiki = build();
        let ids: Vec<&str> = wiki.cli_commands().map(|e| e.id).collect();
        assert!(
            ids.contains(&"chat"),
            "expected 'chat' CLI command in wiki; found: {ids:?}"
        );
        assert!(
            ids.contains(&"memory"),
            "expected 'memory' CLI command in wiki; found: {ids:?}"
        );
        assert!(
            ids.contains(&"serve"),
            "expected 'serve' CLI command in wiki; found: {ids:?}"
        );
    }

    /// Exact anti-drift guard: self-wiki and therefore the GUI must expose
    /// every canonical top-level clap command, no stale or missing rows.
    #[test]
    fn cli_inventory_exactly_matches_clap_tree() {
        let root = crate::cli::Cli::command();
        let mut expected = root
            .get_subcommands()
            .map(|command| {
                let description = command
                    .get_about()
                    .map(ToString::to_string)
                    .or_else(|| command.get_long_about().map(ToString::to_string))
                    .and_then(|text| {
                        text.lines()
                            .next()
                            .map(str::trim)
                            .filter(|line| !line.is_empty())
                            .map(str::to_owned)
                    })
                    .unwrap_or_else(|| "CLI command.".to_owned());
                (command.get_name().to_owned(), description)
            })
            .collect::<Vec<_>>();
        expected.sort_unstable_by(|left, right| left.0.cmp(&right.0));

        let actual = build()
            .cli_commands()
            .map(|entry| (entry.id.to_owned(), entry.description.to_owned()))
            .collect::<Vec<_>>();

        assert_eq!(
            actual, expected,
            "self-wiki CLI inventory drifted from clap"
        );
    }

    /// `find` must locate known entries by kind + id.
    #[test]
    fn find_returns_entry_for_known_id() {
        let wiki = build();
        let entry = wiki.find(CapabilityKind::Cron, "watchdog");
        assert!(entry.is_some(), "find(Cron, 'watchdog') must return Some");
        assert_eq!(entry.unwrap().kind, CapabilityKind::Cron);

        let missing = wiki.find(CapabilityKind::Skill, "watchdog");
        assert!(missing.is_none(), "watchdog is a cron, not a skill");
    }

    /// `search_description` must match on a keyword substring.
    #[test]
    fn search_description_finds_crons_by_keyword() {
        let wiki = build();
        let hits = wiki.search_description("autonomy");
        assert!(
            !hits.is_empty(),
            "expected at least one entry mentioning 'autonomy'"
        );
    }

    /// Gated crons must carry their gate string.
    #[test]
    fn gated_crons_have_feature_gate() {
        let wiki = build();
        let watchdog = wiki
            .find(CapabilityKind::Cron, "watchdog")
            .expect("watchdog cron must exist");
        assert!(
            watchdog.feature_gate.is_some(),
            "watchdog must have a feature_gate (off by default)"
        );
    }

    /// `summary()` must mention all four kind names.
    #[test]
    fn summary_contains_kind_labels() {
        let wiki = build();
        let s = wiki.summary();
        assert!(s.contains("skills"), "summary must mention skills");
        assert!(s.contains("crons"), "summary must mention crons");
        assert!(
            s.contains("cli-commands"),
            "summary must mention cli-commands"
        );
        assert!(
            s.contains("slash-commands"),
            "summary must mention slash-commands"
        );
    }
}
