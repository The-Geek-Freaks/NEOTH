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

// neoth: JV-IMP-01 reader 2 — read_openclaw_mempalace(path: &Path)
// Plan: parse nodes + hebbianLinks, replay hebbian_reinforce.
// Status: UNIMPLEMENTED — the mempalace node/hebbianLinks schema is not
// specified in the GOLD plan (no file:line reference, no field list).
// Implement once the exact JSON shape is extracted from QUELLEN/JARVIS_LIVE/.

// neoth: JV-IMP-01 reader 3 — read_openclaw_memory_db(path: &Path)
// Plan: SQLite `summaries.learned+completed` → groundtruth.
// Status: UNIMPLEMENTED — the `summaries` table DDL (column names, types)
// is not specified in the GOLD plan. Implement once extracted from
// QUELLEN/JARVIS_LIVE/ or `~/.openclaw/memory.db` schema.

// ── Obsidian vault manual-note import (JV-IMP-06) ───────────────────────────

/// Map an Obsidian folder prefix to a scope tag.
/// Mirrors the folder→scope table from GOLD-ADAPT-JV-IMP-06.
fn obsidian_folder_scope(folder: &str) -> &'static str {
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

fn visit_obsidian_dir(
    root: &Path,
    current: &Path,
    out: &mut Vec<ImportedClaim>,
) -> Result<()> {
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
                    if let Component::Normal(n) = c { n.to_str() } else { None }
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
fn is_managed_obsidian_note(body: &str) -> bool {
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
fn strip_yaml_frontmatter(body: &str) -> &str {
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
        assert!(claims
            .iter()
            .any(|c| c.statement.contains("NEOTH on Windows") && c.scope == "host:primary"));
        assert!(claims
            .iter()
            .any(|c| c.statement.contains("Never reboot Cube") && c.scope == "global"));
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
        assert_eq!(claims.len(), 1, "entry without text/content must be skipped");
        assert_eq!(claims[0].statement, "valid claim");
    }

    #[test]
    fn memory_index_absent_file_returns_empty() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nonexistent.json");
        let claims = read_openclaw_memory_index(&path).unwrap();
        assert!(claims.is_empty());
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
        for folder in ["05-Personen", "06-Regeln", "09-Dokumente", "00-MOCs", "07-Other"] {
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
