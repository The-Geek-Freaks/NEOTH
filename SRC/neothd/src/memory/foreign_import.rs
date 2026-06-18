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
}
