//! Foreign-agent ground-truth import drivers — Phase 28c R-24 GT-8.
//!
//! Operator points at another agent's memory store; this module parses the
//! foreign format into [`ImportedClaim`]s ready for `groundtruth::insert`
//! with the appropriate `Source::Import*` tag.
//!
//! ## Supported sources
//!
//! | Source     | Path                                  | Format |
//! |------------|---------------------------------------|--------|
//! | Hermes     | `~/.hermes/memory/hermes.db`          | SQLite `memories(id, content, tags, created_at, importance)` |
//! | OpenClaw   | `~/.openclaw/layers/layer_NN.md` ×12  | Markdown blocks separated by `---`, YAML frontmatter per block |
//! | OpenHuman  | `~/.openhuman/db/profiles.sqlite`     | SQLite triple store `profile_facts(subject, predicate, object, confidence)`. Confidence > 0.7 only. |
//! | Veronica   | `~/.veronica/memory.jsonl`            | JSONL `{statement, scope, ts}` — also the canonical interchange format for any source. |
//!
//! All parsers return `Vec<ImportedClaim>`; the caller decides scope
//! defaults + persistence. None of these talk to the network. None edit
//! the foreign agent's storage.

use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::Connection;
use serde::Deserialize;
use serde_json::Value;

use super::groundtruth::Source;

/// One claim ready to be persisted into `idx_groundtruth`. The caller
/// usually pairs `(source, scope, statement)` with `now_ns` and calls
/// `groundtruth::insert`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportedClaim {
    pub statement: String,
    pub scope: String,
    pub source: Source,
}

// ── Hermes ──────────────────────────────────────────────────────────────────

/// Read `hermes.db`'s `memories` table. Each row becomes one claim with
/// `Source::ImportHermes` and `scope="global"`. Tags become part of the
/// statement so the operator can still see them.
pub fn read_hermes_db(path: &Path) -> Result<Vec<ImportedClaim>> {
    let conn =
        Connection::open(path).with_context(|| format!("open hermes db at {}", path.display()))?;
    let mut stmt = conn
        .prepare(
            "SELECT content, tags, importance \
             FROM memories \
             WHERE content IS NOT NULL AND TRIM(content) != ''",
        )
        .context("prepare hermes SELECT")?;
    let rows = stmt
        .query_map([], |r| {
            let content: String = r.get(0)?;
            let tags: Option<String> = r.get(1).ok();
            let _importance: Option<f64> = r.get(2).ok();
            Ok((content, tags))
        })
        .context("query hermes memories")?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    Ok(rows
        .into_iter()
        .map(|(content, tags)| {
            let statement = match tags {
                Some(t) if !t.trim().is_empty() => format!("{} (tags: {t})", content.trim()),
                _ => content.trim().to_string(),
            };
            ImportedClaim {
                statement,
                scope: "global".into(),
                source: Source::ImportHermes,
            }
        })
        .collect())
}

// ── OpenClaw ────────────────────────────────────────────────────────────────

/// Read one OpenClaw layer markdown file. Blocks are separated by `---`,
/// each starting with YAML frontmatter `key: value` lines that the parser
/// extracts as scope tags. The body after the frontmatter is the claim.
pub fn read_openclaw_layer(path: &Path) -> Result<Vec<ImportedClaim>> {
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("read openclaw layer {}", path.display()))?;
    parse_openclaw_text(&body)
}

/// Read all 12 OpenClaw layers under `dir`. Missing layer files are skipped
/// silently so a partial OpenClaw install still imports what's present.
pub fn read_openclaw_dir(dir: &Path) -> Result<Vec<ImportedClaim>> {
    let mut all = Vec::new();
    for i in 1..=12 {
        let path = dir.join(format!("layer_{:02}.md", i));
        if !path.exists() {
            continue;
        }
        let claims = read_openclaw_layer(&path)?;
        all.extend(claims);
    }
    Ok(all)
}

fn parse_openclaw_text(text: &str) -> Result<Vec<ImportedClaim>> {
    let mut out = Vec::new();
    for block in text.split("\n---\n") {
        let trimmed = block.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Frontmatter is delimited at the top of the block: lines of
        // `key: value` followed by a blank line, then the body.
        let (frontmatter, body) = split_frontmatter(trimmed);
        let scope = frontmatter
            .get("scope")
            .or_else(|| frontmatter.get("layer"))
            .cloned()
            .unwrap_or_else(|| "global".to_string());
        let statement = if body.trim().is_empty() {
            // Header-only block — synthesise a statement from the frontmatter
            // so operators still see the row.
            frontmatter
                .iter()
                .map(|(k, v)| format!("{k}: {v}"))
                .collect::<Vec<_>>()
                .join(", ")
        } else {
            body.trim().to_string()
        };
        if statement.is_empty() {
            continue;
        }
        out.push(ImportedClaim {
            statement,
            scope,
            source: Source::ImportOpenclaw,
        });
    }
    Ok(out)
}

fn split_frontmatter(block: &str) -> (std::collections::HashMap<String, String>, String) {
    let mut map = std::collections::HashMap::new();
    let mut body_start = 0usize;
    let mut saw_blank = false;
    for (i, line) in block.lines().enumerate() {
        if line.trim().is_empty() {
            saw_blank = true;
            body_start = i + 1;
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim();
            let v = v.trim();
            // Reject lines that don't look like keys (contain spaces inside
            // the key half) so we don't misread prose as frontmatter.
            if !k.is_empty() && !k.contains(char::is_whitespace) && !v.is_empty() {
                map.insert(k.to_string(), v.to_string());
                continue;
            }
        }
        // First non-frontmatter line — everything from here is body.
        body_start = i;
        break;
    }
    if !saw_blank && body_start == 0 && !map.is_empty() {
        // The whole block was frontmatter, no body.
        return (map, String::new());
    }
    let body: String = block
        .lines()
        .skip(body_start)
        .collect::<Vec<_>>()
        .join("\n");
    (map, body)
}

// ── OpenHuman ───────────────────────────────────────────────────────────────

/// Read OpenHuman's `profiles.sqlite` triple store. Filters rows by
/// `confidence > 0.7` per the memo spec — low-confidence triples are
/// noise, not ground truth.
pub fn read_openhuman_db(path: &Path) -> Result<Vec<ImportedClaim>> {
    let conn = Connection::open(path)
        .with_context(|| format!("open openhuman db at {}", path.display()))?;
    let mut stmt = conn
        .prepare(
            "SELECT subject, predicate, object, confidence \
             FROM profile_facts \
             WHERE confidence > 0.7",
        )
        .context("prepare openhuman SELECT")?;
    let rows = stmt
        .query_map([], |r| {
            let subject: String = r.get(0)?;
            let predicate: String = r.get(1)?;
            let object: String = r.get(2)?;
            let confidence: f64 = r.get(3)?;
            Ok((subject, predicate, object, confidence))
        })
        .context("query openhuman triples")?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    Ok(rows
        .into_iter()
        .map(|(s, p, o, c)| ImportedClaim {
            statement: format!("{s} {p} {o} (confidence {c:.2})"),
            scope: format!("subject:{s}"),
            source: Source::ImportOpenhuman,
        })
        .collect())
}

// ── Veronica (also the generic JSONL interchange) ───────────────────────────

/// One line of the Veronica JSONL interchange format.
#[derive(Debug, Deserialize)]
pub struct VeronicaRow {
    pub statement: String,
    #[serde(default = "default_global_scope")]
    pub scope: String,
    /// Optional timestamp — accepted but unused at import time (the row
    /// gets `asserted_at = now_ns`).
    #[serde(default)]
    pub ts: Option<i64>,
}

fn default_global_scope() -> String {
    "global".into()
}

/// Read a JSONL file. Any line that fails to parse is skipped with a
/// trace warning so a single corrupt row doesn't tank the whole batch.
/// `import_source` lets the caller stamp the rows as Veronica or as a
/// generic JSONL pull.
pub fn read_veronica_jsonl(path: &Path, import_source: Source) -> Result<Vec<ImportedClaim>> {
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("read veronica jsonl {}", path.display()))?;
    let mut out = Vec::new();
    for (i, line) in body.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<VeronicaRow>(line) {
            Ok(row) if !row.statement.trim().is_empty() => {
                out.push(ImportedClaim {
                    statement: row.statement.trim().to_string(),
                    scope: row.scope,
                    source: import_source.clone(),
                });
            }
            Ok(_) => {
                tracing::debug!(line = i + 1, "skipping veronica row with empty statement");
            }
            Err(e) => {
                tracing::warn!(line = i + 1, error = %e, "skipping malformed jsonl row");
            }
        }
    }
    Ok(out)
}

// ── OpenClaw memory-index (JV-IMP-01 reader 1 of 3) ─────────────────────────

/// Parse an OpenClaw `index.json` whose top-level `memories` array holds
/// memory entries with a `text` or `content` field (and an optional `scope`).
/// Each entry becomes one `ImportedClaim` tagged `Source::ImportOpenclaw`.
///
/// Defensive: missing / malformed entries are skipped; absent or unreadable
/// file returns `Ok(vec![])`.
pub fn read_openclaw_memory_index(path: &Path) -> Result<Vec<ImportedClaim>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("read openclaw memory index {}", path.display()))?;
    if body.trim().is_empty() {
        return Ok(Vec::new());
    }
    let root: Value = serde_json::from_str(&body)
        .with_context(|| format!("parse openclaw memory index {}", path.display()))?;
    let entries = match root.get("memories").and_then(|v| v.as_array()) {
        Some(arr) => arr.clone(),
        None => {
            tracing::debug!(
                path = %path.display(),
                "openclaw memory index: no 'memories' array found"
            );
            return Ok(Vec::new());
        }
    };
    let mut out = Vec::new();
    for (i, entry) in entries.iter().enumerate() {
        // Accept either "text" or "content" as the statement field.
        let text = entry
            .get("text")
            .or_else(|| entry.get("content"))
            .and_then(|v| v.as_str())
            .map(str::trim)
            .unwrap_or("");
        if text.is_empty() {
            tracing::debug!(index = i, "skipping openclaw memory entry with empty text");
            continue;
        }
        let scope = entry
            .get("scope")
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty())
            .unwrap_or("global")
            .to_string();
        out.push(ImportedClaim {
            statement: text.to_string(),
            scope,
            source: Source::ImportOpenclaw,
        });
    }
    Ok(out)
}

// ── OpenClaw MemPalace (JV-IMP-01 reader 2) ─────────────────────────────────

/// OpenClaw MemPalace node as parsed from the JSON array.
///
/// Known observed shapes:
/// ```json
/// {
///   "id": "abc123",
///   "text": "the claim text",
///   "importance": 0.6,
///   "scope": "host:primary",
///   "hebbianLinks": [{"targetId":"def456","strength":0.8}, ...]
/// }
/// ```
/// `text` (or `content`) is the statement. `hebbianLinks` tells us how many
/// times this node was Hebbian-reinforced by other nodes recalling it; we
/// replay that many `hebbian_reinforce_value` passes on the initial importance
/// and embed the result in the statement so the operator can inspect it.
/// Missing `hebbianLinks` → treat as zero reinforcements.
#[derive(Debug, Deserialize)]
struct MempalaceNode {
    #[serde(alias = "content")]
    text: Option<String>,
    #[serde(default = "default_importance")]
    importance: f64,
    scope: Option<String>,
    #[serde(default)]
    hebbian_links: Vec<Value>,
    // Accept camelCase from JSON as well.
    #[serde(rename = "hebbianLinks", default)]
    hebbian_links_camel: Vec<Value>,
}

fn default_importance() -> f64 {
    0.5
}

impl MempalaceNode {
    /// Total number of hebbian links across both field spellings.
    fn link_count(&self) -> usize {
        self.hebbian_links.len() + self.hebbian_links_camel.len()
    }
}

/// Read an OpenClaw MemPalace JSON file.
///
/// The file is expected to be a JSON object with a top-level `"nodes"` array
/// (or bare array) of node objects. Each node with a non-empty `text`/`content`
/// field becomes one `ImportedClaim`. The initial `importance` is Hebbian-
/// reinforced once per `hebbianLink` entry (using the Hot-tier coefficient)
/// so the final value reflects the original recall weight, and is appended to
/// the statement as `(importance→X.XX)` for operator visibility.
///
/// Absent or empty file returns `Ok(vec![])`.
pub fn read_openclaw_mempalace(path: &Path) -> Result<Vec<ImportedClaim>> {
    use crate::memory::tiers::{Tier, hebbian_reinforce_value};

    if !path.exists() {
        return Ok(Vec::new());
    }
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("read openclaw mempalace {}", path.display()))?;
    if body.trim().is_empty() {
        return Ok(Vec::new());
    }
    let root: Value = serde_json::from_str(&body)
        .with_context(|| format!("parse openclaw mempalace {}", path.display()))?;

    // Accept either `{"nodes":[...]}` or a bare `[...]`.
    let node_array = if let Some(arr) = root.get("nodes").and_then(|v| v.as_array()) {
        arr.clone()
    } else if root.is_array() {
        root.as_array().cloned().unwrap_or_default()
    } else {
        tracing::debug!(
            path = %path.display(),
            "openclaw mempalace: no 'nodes' array found"
        );
        return Ok(Vec::new());
    };

    let mut out = Vec::new();
    for (i, raw) in node_array.iter().enumerate() {
        let node: MempalaceNode = match serde_json::from_value(raw.clone()) {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!(index = i, error = %e, "skipping malformed mempalace node");
                continue;
            }
        };
        let text = node
            .text
            .as_deref()
            .map(str::trim)
            .unwrap_or("")
            .to_string();
        if text.is_empty() {
            tracing::debug!(index = i, "skipping mempalace node with empty text");
            continue;
        }
        // Replay Hebbian reinforcement: one pass per hebbianLink present.
        let reinforced_importance = {
            let mut imp = node.importance.clamp(0.0, 1.0);
            for _ in 0..node.link_count() {
                imp = hebbian_reinforce_value(imp, Tier::Hot);
            }
            imp
        };
        let scope = node
            .scope
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or("global")
            .to_string();
        let statement = format!("{text} (importance→{reinforced_importance:.2})");
        out.push(ImportedClaim {
            statement,
            scope,
            source: Source::ImportOpenclaw,
        });
    }
    Ok(out)
}

// ── OpenClaw memory.db (JV-IMP-01 reader 3) ──────────────────────────────────

/// Read OpenClaw's `memory.db` SQLite file.
///
/// The `summaries` table holds two kinds of rows distinguished by the `type`
/// column:
///
/// * `"learned"` — facts the agent distilled from conversations.
/// * `"completed"` — goals / tasks that were accomplished.
///
/// Both become `ImportedClaim`s tagged `Source::ImportOpenclaw`. The scope is
/// set to `"learned"` or `"completed"` respectively so operators can filter by
/// kind. A `subject` column (if present) is prepended to the statement.
///
/// Schema tolerance: the query selects by `type IN ('learned','completed')`; if
/// the `summaries` table does not exist the error is surfaced normally. If the
/// `subject` column is absent the value is simply `None` and the statement is
/// the plain `content`.
///
/// Absent or unreadable file returns `Err`.
pub fn read_openclaw_memory_db(path: &Path) -> Result<Vec<ImportedClaim>> {
    let conn = Connection::open(path)
        .with_context(|| format!("open openclaw memory.db at {}", path.display()))?;

    // Try to detect whether the `subject` column exists. If the column is
    // missing we fall back to the two-column query gracefully.
    let has_subject: bool = {
        let mut check = conn
            .prepare("PRAGMA table_info(summaries)")
            .context("PRAGMA table_info(summaries)")?;
        check
            .query_map([], |r| r.get::<_, String>(1))
            .context("read table_info")?
            .any(|col| col.as_deref() == Ok("subject"))
    };

    let rows: Vec<(String, String, Option<String>)> = if has_subject {
        let mut stmt = conn
            .prepare(
                "SELECT content, type, subject \
                 FROM summaries \
                 WHERE type IN ('learned','completed') \
                   AND content IS NOT NULL AND TRIM(content) != ''",
            )
            .context("prepare summaries SELECT (with subject)")?;
        stmt.query_map([], |r| {
            let content: String = r.get(0)?;
            let kind: String = r.get(1)?;
            let subject: Option<String> = r.get(2).ok();
            Ok((content, kind, subject))
        })
        .context("query summaries (with subject)")?
        .collect::<rusqlite::Result<Vec<_>>>()?
    } else {
        let mut stmt = conn
            .prepare(
                "SELECT content, type \
                 FROM summaries \
                 WHERE type IN ('learned','completed') \
                   AND content IS NOT NULL AND TRIM(content) != ''",
            )
            .context("prepare summaries SELECT (no subject)")?;
        stmt.query_map([], |r| {
            let content: String = r.get(0)?;
            let kind: String = r.get(1)?;
            Ok((content, kind, None::<String>))
        })
        .context("query summaries (no subject)")?
        .collect::<rusqlite::Result<Vec<_>>>()?
    };

    Ok(rows
        .into_iter()
        .map(|(content, kind, subject)| {
            let statement = match subject.filter(|s| !s.trim().is_empty()) {
                Some(subj) => format!("[{subj}] {}", content.trim()),
                None => content.trim().to_string(),
            };
            ImportedClaim {
                statement,
                scope: kind,
                source: Source::ImportOpenclaw,
            }
        })
        .collect())
}

// ── Obsidian vault manual-note import (JV-IMP-06) ───────────────────────────

/// Map an Obsidian folder prefix to a scope tag.
/// Mirrors the folder→scope table from GOLD-ADAPT-JV-IMP-06.
/// Promoted to `pub(crate)` for `daemon::obsidian_vault_reader_cron` (JV-IMP-05).
pub(crate) fn obsidian_folder_scope(folder: &str) -> &'static str {
    match folder {
        "05-Personen" => "people",
        "06-Regeln" => "rules",
        "09-Dokumente" => "documents",
        "00-MOCs" => "moc",
        _ => "global",
    }
}

/// Read an Obsidian vault directory and import every `.md` note that does
/// NOT carry a managed `source: openclaw-*` or `source: neoth-*` YAML
/// frontmatter line. Notes with those source tags are round-trip-managed by
/// the OpenClaw / NEOTH sync pipeline and must not be double-imported.
///
/// For each qualifying note the YAML frontmatter is stripped and the body
/// text becomes the claim statement. The note title (filename without `.md`)
/// is prepended as context so operators can trace back the origin.
///
/// Folder → scope mapping: `05-Personen`→people, `06-Regeln`→rules,
/// `09-Dokumente`→documents, `00-MOCs`→moc, everything else → global.
///
/// Empty or absent `dir` returns `Ok(vec![])`.
pub fn read_obsidian_manual_notes(dir: &Path) -> Result<Vec<ImportedClaim>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    visit_obsidian_dir(dir, dir, &mut out)?;
    Ok(out)
}

fn visit_obsidian_dir(root: &Path, current: &Path, out: &mut Vec<ImportedClaim>) -> Result<()> {
    let entries = std::fs::read_dir(current)
        .with_context(|| format!("read obsidian dir {}", current.display()))?;
    for entry in entries {
        let entry = entry.with_context(|| format!("dir entry in {}", current.display()))?;
        let path = entry.path();
        if path.is_dir() {
            // Recurse; ignore hidden dirs (`.obsidian`, `.git`, etc.)
            let dir_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !dir_name.starts_with('.') {
                visit_obsidian_dir(root, &path, out)?;
            }
            continue;
        }
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext != "md" {
            continue;
        }
        let body = match std::fs::read_to_string(&path) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "skipping unreadable obsidian note");
                continue;
            }
        };
        // Detect managed-source frontmatter: any line `source: openclaw-*`
        // or `source: neoth-*` inside the leading YAML block disqualifies
        // the note from manual import.
        if is_managed_obsidian_note(&body) {
            continue;
        }
        // Strip YAML frontmatter and collect the body.
        let content = strip_yaml_frontmatter(&body);
        let content = content.trim();
        if content.is_empty() {
            continue;
        }
        // Title = filename without extension.
        let title = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("untitled");
        // Scope from the immediate parent folder name relative to the vault root.
        let scope = {
            let rel = path.strip_prefix(root).unwrap_or(&path);
            let folder = rel
                .parent()
                .and_then(|p| p.components().next())
                .and_then(|c| {
                    use std::path::Component;
                    if let Component::Normal(n) = c {
                        n.to_str()
                    } else {
                        None
                    }
                })
                .unwrap_or("");
            obsidian_folder_scope(folder).to_string()
        };
        let statement = format!("[{title}] {content}");
        out.push(ImportedClaim {
            statement,
            scope,
            source: Source::ImportObsidian,
        });
    }
    Ok(())
}

/// Return `true` when the note's YAML frontmatter contains a `source:` line
/// whose value starts with `openclaw-` or `neoth-`.
/// Promoted to `pub(crate)` for `daemon::obsidian_vault_reader_cron` (JV-IMP-05).
pub(crate) fn is_managed_obsidian_note(body: &str) -> bool {
    // Frontmatter is delimited by a leading `---` line.
    let inner = if let Some(rest) = body.strip_prefix("---") {
        // Find the closing `---`.
        if let Some(end) = rest.find("\n---") {
            &rest[..end]
        } else {
            // Malformed or no closing delimiter — treat as no frontmatter.
            return false;
        }
    } else {
        return false;
    };
    for line in inner.lines() {
        let trimmed = line.trim();
        if let Some(val) = trimmed.strip_prefix("source:") {
            let val = val.trim();
            if val.starts_with("openclaw-") || val.starts_with("neoth-") {
                return true;
            }
        }
    }
    false
}

/// Strip the leading YAML frontmatter block (`---…---`) and return the body.
/// Promoted to `pub(crate)` for `daemon::obsidian_vault_reader_cron` (JV-IMP-05).
pub(crate) fn strip_yaml_frontmatter(body: &str) -> &str {
    if !body.starts_with("---") {
        return body;
    }
    let rest = &body[3..];
    // Skip the leading newline after the opening `---` if present.
    let rest = rest.strip_prefix('\n').unwrap_or(rest);
    if let Some(end_pos) = rest.find("\n---") {
        // end_pos points at the `\n` before `---`; skip past `---` + optional newline.
        let after = &rest[end_pos + 4..]; // 4 = len("\n---")
        after.strip_prefix('\n').unwrap_or(after)
    } else {
        body
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn hermes_fixture(dir: &Path) -> std::path::PathBuf {
        let path = dir.join("hermes.db");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE memories (
                id INTEGER PRIMARY KEY,
                content TEXT,
                tags TEXT,
                created_at INTEGER,
                importance REAL
            );
            INSERT INTO memories (content, tags, created_at, importance)
              VALUES ('Operator builds NEOTH on Windows', 'project,build', 1700000000, 0.9);
            INSERT INTO memories (content, tags, created_at, importance)
              VALUES ('Primary server is unraid at 10.0.0.1', 'infra', 1700000100, 0.85);
            INSERT INTO memories (content, tags, created_at, importance)
              VALUES ('  ', NULL, 1700000200, 0.5);
            INSERT INTO memories (content, tags, created_at, importance)
              VALUES ('Solo claim with no tags', NULL, 1700000300, 0.7);",
        )
        .unwrap();
        path
    }

    #[test]
    fn hermes_import_extracts_content_and_tags() {
        let dir = tempdir().unwrap();
        let path = hermes_fixture(dir.path());
        let claims = read_hermes_db(&path).unwrap();
        assert_eq!(claims.len(), 3, "blank-content row must be dropped");
        assert!(
            claims
                .iter()
                .any(|c| c.statement.contains("Operator builds NEOTH")
                    && c.statement.contains("tags: project,build"))
        );
        assert!(
            claims
                .iter()
                .any(|c| c.statement == "Solo claim with no tags")
        );
        for c in &claims {
            assert_eq!(c.scope, "global");
            assert_eq!(c.source, Source::ImportHermes);
        }
    }

    #[test]
    fn openclaw_parses_blocks_with_frontmatter() {
        let text = "\
scope: host:primary
layer: 02

Primary server is at 10.0.0.1 with three GPUs.
Do not remote-reboot.

\n---\n\
scope: global

NEOTH never phones home.
";
        let claims = parse_openclaw_text(text).unwrap();
        assert_eq!(claims.len(), 2);
        assert_eq!(claims[0].scope, "host:primary");
        assert!(
            claims[0]
                .statement
                .contains("Primary server is at 10.0.0.1")
        );
        assert_eq!(claims[1].scope, "global");
        assert!(claims[1].statement.contains("never phones home"));
        for c in &claims {
            assert_eq!(c.source, Source::ImportOpenclaw);
        }
    }

    #[test]
    fn openclaw_handles_block_without_frontmatter() {
        let text = "Just a body line with no frontmatter at all.";
        let claims = parse_openclaw_text(text).unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].scope, "global");
        assert!(claims[0].statement.starts_with("Just a body line"));
    }

    #[test]
    fn openclaw_dir_walks_layers_01_through_12() {
        let dir = tempdir().unwrap();
        // Create layers 01, 05, 12 only — others missing should not error.
        for n in [1u8, 5, 12] {
            std::fs::write(
                dir.path().join(format!("layer_{n:02}.md")),
                format!("scope: layer:{n}\n\nclaim from layer {n}\n"),
            )
            .unwrap();
        }
        let claims = read_openclaw_dir(dir.path()).unwrap();
        assert_eq!(claims.len(), 3);
        assert!(claims.iter().any(|c| c.scope == "layer:5"));
    }

    fn openhuman_fixture(dir: &Path) -> std::path::PathBuf {
        let path = dir.join("profiles.sqlite");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE profile_facts (
                subject TEXT,
                predicate TEXT,
                object TEXT,
                confidence REAL
            );
            INSERT INTO profile_facts VALUES ('operator', 'role', 'developer', 0.95);
            INSERT INTO profile_facts VALUES ('operator', 'language', 'de', 0.80);
            INSERT INTO profile_facts VALUES ('operator', 'maybe-likes', 'jazz', 0.40);",
        )
        .unwrap();
        path
    }

    #[test]
    fn openhuman_import_filters_low_confidence() {
        let dir = tempdir().unwrap();
        let path = openhuman_fixture(dir.path());
        let claims = read_openhuman_db(&path).unwrap();
        assert_eq!(claims.len(), 2, "0.40-confidence row must be filtered");
        assert!(claims.iter().all(|c| c.scope.starts_with("subject:")));
        assert!(
            claims
                .iter()
                .any(|c| c.statement.contains("role developer"))
        );
    }

    #[test]
    fn veronica_jsonl_parses_and_tolerates_bad_rows() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("memory.jsonl");
        std::fs::write(
            &path,
            r#"{"statement":"alpha","scope":"global"}
{"statement":"beta"}
not even json
{"statement":""}
{"statement":"gamma","scope":"host:primary","ts":1700000000}
"#,
        )
        .unwrap();
        let claims = read_veronica_jsonl(&path, Source::ImportVeronica).unwrap();
        // alpha, beta, gamma — empty + malformed rows dropped.
        assert_eq!(claims.len(), 3);
        assert!(claims.iter().any(|c| c.statement == "alpha"));
        assert!(
            claims
                .iter()
                .any(|c| c.statement == "beta" && c.scope == "global")
        );
        assert!(
            claims
                .iter()
                .any(|c| c.statement == "gamma" && c.scope == "host:primary")
        );
    }

    #[test]
    fn jsonl_import_source_is_respected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("data.jsonl");
        std::fs::write(&path, r#"{"statement":"x"}"#).unwrap();
        let veronica = read_veronica_jsonl(&path, Source::ImportVeronica).unwrap();
        assert_eq!(veronica[0].source, Source::ImportVeronica);
        // Same reader, different source tag — proves the interchange-format
        // pattern works for arbitrary JSONL sources.
        let hermes = read_veronica_jsonl(&path, Source::ImportHermes).unwrap();
        assert_eq!(hermes[0].source, Source::ImportHermes);
    }

    // ── JV-IMP-01 tests ─────────────────────────────────────────────────────

    #[test]
    fn memory_index_parses_two_entries_and_sets_source() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("index.json");
        std::fs::write(
            &path,
            r#"{"memories":[
                {"text":"Operator runs NEOTH on Windows","scope":"host:primary"},
                {"content":"Never reboot Cube remotely"}
            ]}"#,
        )
        .unwrap();
        let claims = read_openclaw_memory_index(&path).unwrap();
        assert_eq!(claims.len(), 2);
        assert!(
            claims
                .iter()
                .any(|c| c.statement.contains("NEOTH on Windows") && c.scope == "host:primary")
        );
        assert!(
            claims
                .iter()
                .any(|c| c.statement.contains("Never reboot Cube") && c.scope == "global")
        );
        for c in &claims {
            assert_eq!(c.source, Source::ImportOpenclaw);
        }
    }

    #[test]
    fn memory_index_skips_malformed_entry_missing_text() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("index.json");
        // Entry 1: valid; entry 2: no text/content (should be skipped).
        std::fs::write(
            &path,
            r#"{"memories":[
                {"text":"valid claim"},
                {"scope":"global","importance":0.9}
            ]}"#,
        )
        .unwrap();
        let claims = read_openclaw_memory_index(&path).unwrap();
        assert_eq!(
            claims.len(),
            1,
            "entry without text/content must be skipped"
        );
        assert_eq!(claims[0].statement, "valid claim");
    }

    #[test]
    fn memory_index_absent_file_returns_empty() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nonexistent.json");
        let claims = read_openclaw_memory_index(&path).unwrap();
        assert!(claims.is_empty());
    }

    // ── JV-IMP-01 reader 2: mempalace tests ─────────────────────────────────

    /// Minimal helper: write a mempalace JSON file and return its path.
    fn mempalace_fixture(dir: &Path, json: &str) -> std::path::PathBuf {
        let path = dir.join("mempalace.json");
        std::fs::write(&path, json).unwrap();
        path
    }

    #[test]
    fn mempalace_parses_nodes_array_from_nodes_key() {
        let dir = tempdir().unwrap();
        let json = r#"{
            "nodes": [
                {"text": "Operator prefers terse output", "importance": 0.6, "scope": "global", "hebbianLinks": []},
                {"content": "Server is on unraid", "scope": "host:primary"}
            ]
        }"#;
        let path = mempalace_fixture(dir.path(), json);
        let claims = read_openclaw_mempalace(&path).unwrap();
        assert_eq!(claims.len(), 2);
        assert!(
            claims
                .iter()
                .any(|c| c.statement.contains("terse output") && c.scope == "global")
        );
        assert!(
            claims
                .iter()
                .any(|c| c.statement.contains("Server is on unraid") && c.scope == "host:primary")
        );
        for c in &claims {
            assert_eq!(c.source, Source::ImportOpenclaw);
        }
    }

    #[test]
    fn mempalace_accepts_bare_array() {
        let dir = tempdir().unwrap();
        let json = r#"[
            {"text": "bare node one"},
            {"text": "bare node two", "scope": "project:neoth"}
        ]"#;
        let path = mempalace_fixture(dir.path(), json);
        let claims = read_openclaw_mempalace(&path).unwrap();
        assert_eq!(claims.len(), 2);
        assert!(
            claims
                .iter()
                .any(|c| c.statement.contains("bare node one") && c.scope == "global")
        );
        assert!(claims.iter().any(|c| c.scope == "project:neoth"));
    }

    #[test]
    fn mempalace_replays_hebbian_links_in_statement() {
        use crate::memory::tiers::{Tier, hebbian_reinforce_value};
        let dir = tempdir().unwrap();
        // 2 hebbianLinks on a node with importance 0.5 → two reinforce passes.
        let json = r#"{"nodes":[
            {"text":"reinforced claim","importance":0.5,"hebbianLinks":[{"targetId":"x"},{"targetId":"y"}]}
        ]}"#;
        let path = mempalace_fixture(dir.path(), json);
        let claims = read_openclaw_mempalace(&path).unwrap();
        assert_eq!(claims.len(), 1);
        let mut expected = 0.5f64;
        expected = hebbian_reinforce_value(expected, Tier::Hot);
        expected = hebbian_reinforce_value(expected, Tier::Hot);
        let expected_str = format!("(importance→{expected:.2})");
        assert!(
            claims[0].statement.contains(&expected_str),
            "expected '{}' in statement '{}'",
            expected_str,
            claims[0].statement
        );
    }

    #[test]
    fn mempalace_skips_empty_text_nodes() {
        let dir = tempdir().unwrap();
        let json = r#"{"nodes":[
            {"text":"valid"},
            {"scope":"global"},
            {"text":"  "}
        ]}"#;
        let path = mempalace_fixture(dir.path(), json);
        let claims = read_openclaw_mempalace(&path).unwrap();
        assert_eq!(claims.len(), 1, "empty/missing text nodes must be dropped");
        assert!(claims[0].statement.contains("valid"));
    }

    #[test]
    fn mempalace_absent_file_returns_empty() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("no_mempalace.json");
        let claims = read_openclaw_mempalace(&path).unwrap();
        assert!(claims.is_empty());
    }

    // ── JV-IMP-01 reader 3: memory_db tests ──────────────────────────────────

    fn memory_db_fixture(dir: &Path, with_subject: bool) -> std::path::PathBuf {
        let path = dir.join("memory.db");
        let conn = Connection::open(&path).unwrap();
        if with_subject {
            conn.execute_batch(
                "CREATE TABLE summaries (
                    id      INTEGER PRIMARY KEY,
                    content TEXT,
                    type    TEXT,
                    subject TEXT
                );
                INSERT INTO summaries (content, type, subject)
                    VALUES ('Rust is memory-safe', 'learned', 'programming');
                INSERT INTO summaries (content, type, subject)
                    VALUES ('Finished neoth v0.3', 'completed', 'project:neoth');
                INSERT INTO summaries (content, type, subject)
                    VALUES ('  ', 'learned', NULL);
                INSERT INTO summaries (content, type, subject)
                    VALUES ('irrelevant draft', 'draft', 'misc');",
            )
            .unwrap();
        } else {
            conn.execute_batch(
                "CREATE TABLE summaries (
                    id      INTEGER PRIMARY KEY,
                    content TEXT,
                    type    TEXT
                );
                INSERT INTO summaries (content, type)
                    VALUES ('Rust is memory-safe', 'learned');
                INSERT INTO summaries (content, type)
                    VALUES ('Finished neoth v0.3', 'completed');
                INSERT INTO summaries (content, type)
                    VALUES ('irrelevant draft', 'draft');",
            )
            .unwrap();
        }
        path
    }

    #[test]
    fn memory_db_imports_learned_and_completed_with_subject() {
        let dir = tempdir().unwrap();
        let path = memory_db_fixture(dir.path(), true);
        let claims = read_openclaw_memory_db(&path).unwrap();
        // blank-content + draft rows must be excluded
        assert_eq!(
            claims.len(),
            2,
            "only learned+completed with content; got {claims:?}"
        );
        let learned = claims.iter().find(|c| c.scope == "learned").unwrap();
        assert!(learned.statement.contains("Rust is memory-safe"));
        assert!(learned.statement.contains("[programming]"));
        let completed = claims.iter().find(|c| c.scope == "completed").unwrap();
        assert!(completed.statement.contains("Finished neoth v0.3"));
        assert!(completed.statement.contains("[project:neoth]"));
        for c in &claims {
            assert_eq!(c.source, Source::ImportOpenclaw);
        }
    }

    #[test]
    fn memory_db_imports_without_subject_column() {
        let dir = tempdir().unwrap();
        let path = memory_db_fixture(dir.path(), false);
        let claims = read_openclaw_memory_db(&path).unwrap();
        assert_eq!(
            claims.len(),
            2,
            "draft row must be excluded; got {claims:?}"
        );
        assert!(
            claims
                .iter()
                .any(|c| c.scope == "learned" && c.statement == "Rust is memory-safe")
        );
        assert!(
            claims
                .iter()
                .any(|c| c.scope == "completed" && c.statement == "Finished neoth v0.3")
        );
    }

    #[test]
    fn memory_db_excludes_blank_content_and_wrong_type() {
        let dir = tempdir().unwrap();
        // Only one valid row, one blank, one wrong type.
        let path = dir.path().join("memory.db");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE summaries (id INTEGER PRIMARY KEY, content TEXT, type TEXT);
             INSERT INTO summaries VALUES (1, 'keep me', 'learned');
             INSERT INTO summaries VALUES (2, '   ', 'completed');
             INSERT INTO summaries VALUES (3, 'ignore', 'raw');",
        )
        .unwrap();
        let claims = read_openclaw_memory_db(&path).unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].statement, "keep me");
        assert_eq!(claims[0].scope, "learned");
    }

    // ── JV-IMP-06 tests ─────────────────────────────────────────────────────

    #[test]
    fn obsidian_imports_manual_note_and_skips_managed() {
        let dir = tempdir().unwrap();
        // Manual note — no managed frontmatter.
        std::fs::write(
            dir.path().join("my-note.md"),
            "# Hello\n\nThis is a manual note.\n",
        )
        .unwrap();
        // Managed note — has `source: openclaw-memory`; must be skipped.
        std::fs::write(
            dir.path().join("managed.md"),
            "---\nsource: openclaw-memory\ntitle: managed\n---\n\nshould be ignored\n",
        )
        .unwrap();
        let claims = read_obsidian_manual_notes(dir.path()).unwrap();
        assert_eq!(claims.len(), 1, "managed note must be skipped");
        assert!(claims[0].statement.contains("This is a manual note"));
        assert_eq!(claims[0].source, Source::ImportObsidian);
    }

    #[test]
    fn obsidian_strips_frontmatter_from_manual_note() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("note.md"),
            "---\ntitle: My Note\ntags: [a, b]\n---\n\nBody text here.\n",
        )
        .unwrap();
        let claims = read_obsidian_manual_notes(dir.path()).unwrap();
        assert_eq!(claims.len(), 1);
        assert!(
            claims[0].statement.contains("Body text here"),
            "frontmatter must be stripped; got: {}",
            claims[0].statement
        );
        assert!(
            !claims[0].statement.contains("title:"),
            "frontmatter keys must not appear in statement"
        );
    }

    #[test]
    fn obsidian_folder_to_scope_mapping() {
        let dir = tempdir().unwrap();
        // Create one note in each mapped folder.
        for folder in [
            "05-Personen",
            "06-Regeln",
            "09-Dokumente",
            "00-MOCs",
            "07-Other",
        ] {
            std::fs::create_dir(dir.path().join(folder)).unwrap();
            std::fs::write(
                dir.path().join(folder).join("note.md"),
                format!("content from {folder}\n"),
            )
            .unwrap();
        }
        let claims = read_obsidian_manual_notes(dir.path()).unwrap();
        assert_eq!(claims.len(), 5);
        let scope_for = |folder: &str| -> &'static str { obsidian_folder_scope(folder) };
        assert_eq!(scope_for("05-Personen"), "people");
        assert_eq!(scope_for("06-Regeln"), "rules");
        assert_eq!(scope_for("09-Dokumente"), "documents");
        assert_eq!(scope_for("00-MOCs"), "moc");
        assert_eq!(scope_for("07-Other"), "global");
        // Verify claims carry the right scope.
        let has_scope = |s: &str| claims.iter().any(|c| c.scope == s);
        assert!(has_scope("people"));
        assert!(has_scope("rules"));
        assert!(has_scope("documents"));
        assert!(has_scope("moc"));
        assert!(has_scope("global"));
    }

    #[test]
    fn obsidian_absent_dir_returns_empty() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("no_such_vault");
        let claims = read_obsidian_manual_notes(&missing).unwrap();
        assert!(claims.is_empty());
    }
}
