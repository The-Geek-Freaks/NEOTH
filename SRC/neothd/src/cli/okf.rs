//! `neoth okf export` — export NEOTH's knowledge as an Open Knowledge Format
//! bundle: interconnected Obsidian-native markdown concept docs. See
//! `crate::memory::okf` for the format.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use std::path::PathBuf;

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::memory::okf::{OkfConcept, OkfLink, slug};
use crate::memory::{entities, groundtruth, store};

#[derive(Args, Debug, Clone)]
pub struct OkfArgs {
    #[command(subcommand)]
    pub action: OkfAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum OkfAction {
    /// Export entities (+ their relations) and ground-truth facts as an OKF
    /// bundle of markdown concept docs (point Obsidian at it / sync to a vault).
    Export {
        /// Output bundle directory. Default: `<neoth_home>/okf`.
        #[arg(long, value_name = "DIR")]
        out: Option<PathBuf>,
        /// Override the views.db path.
        #[arg(long, value_name = "PATH")]
        db: Option<PathBuf>,
    },
    /// Import an OKF bundle BACK into NEOTH memory: facts → ground-truth
    /// (as ImportSession candidates), entities → the entity index.
    Import {
        /// Bundle directory to read. Default: `<neoth_home>/okf`.
        #[arg(long, value_name = "DIR")]
        bundle: Option<PathBuf>,
        #[arg(long, value_name = "PATH")]
        db: Option<PathBuf>,
    },
    /// Export the OKF bundle straight into an Obsidian vault (under
    /// `<vault>/NEOTH-knowledge`) so the graph shows up in your vault.
    Sync {
        #[arg(long, value_name = "PATH")]
        vault: PathBuf,
        #[arg(long, value_name = "PATH")]
        db: Option<PathBuf>,
    },
}

pub fn run_okf(args: OkfArgs, output: OutputFormat) -> Result<()> {
    match args.action {
        OkfAction::Export { out, db } => export(out, db, output),
        OkfAction::Import { bundle, db } => import(bundle, db, output),
        OkfAction::Sync { vault, db } => export(Some(vault.join("NEOTH-knowledge")), db, output),
    }
}

fn import(bundle: Option<PathBuf>, db: Option<PathBuf>, output: OutputFormat) -> Result<()> {
    use crate::memory::groundtruth::{self, Source};
    use crate::memory::okf::parse;
    let db_path = db.unwrap_or_else(store::default_path);
    let conn = store::open(&db_path).context("open views.db")?;
    let bundle = bundle.unwrap_or_else(|| FreedomConfig::default_neoth_home().join("okf"));
    let now_ns = crate::time::now_unix_ns_i64();
    let now_unix = crate::time::now_unix_i64();

    // facts/ → ground-truth (ImportSession = external, lands as a candidate).
    let mut facts = 0usize;
    let mut skipped = 0usize;
    for path in md_files(&bundle.join("facts")) {
        let Ok(content) = std::fs::read_to_string(&path) else {
            skipped += 1;
            continue;
        };
        let Some(doc) = parse(&content) else {
            skipped += 1;
            continue;
        };
        let statement = doc.description.clone().unwrap_or_else(|| doc.title.clone());
        if statement.trim().is_empty() {
            skipped += 1;
            continue;
        }
        let scope = doc.tags.first().cloned().unwrap_or_else(|| "imported".to_string());
        match groundtruth::insert(&conn, &statement, &Source::ImportSession, &scope, now_ns) {
            Ok(_) => facts += 1,
            Err(_) => skipped += 1,
        }
    }

    // entities/ → the entity index (name + type; relations are a follow-on).
    let mut entities = 0usize;
    for path in md_files(&bundle.join("entities")) {
        let Ok(content) = std::fs::read_to_string(&path) else {
            skipped += 1;
            continue;
        };
        let Some(doc) = parse(&content) else {
            skipped += 1;
            continue;
        };
        if doc.title.trim().is_empty() {
            skipped += 1;
            continue;
        }
        let attrs = std::collections::BTreeMap::new();
        match crate::memory::entities::resolve_or_create_entity_with_attrs(
            &conn,
            &doc.title,
            &doc.concept_type,
            &attrs,
            now_unix,
        ) {
            Ok(_) => entities += 1,
            Err(_) => skipped += 1,
        }
    }

    if matches!(output, OutputFormat::Json | OutputFormat::Jsonl) {
        println!(
            "{}",
            serde_json::json!({ "ok": true, "facts": facts, "entities": entities, "skipped": skipped, "bundle": bundle.display().to_string() })
        );
    } else {
        println!(
            "OKF import: {facts} facts + {entities} entities ingested ({skipped} skipped) from {}",
            bundle.display()
        );
    }
    Ok(())
}

/// Every `*.md` file directly under `dir` (non-recursive; ignores README).
fn md_files(dir: &std::path::Path) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    rd.flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.extension().map(|x| x == "md").unwrap_or(false)
                && p.file_name().map(|n| n != "README.md").unwrap_or(true)
        })
        .collect()
}

fn export(out: Option<PathBuf>, db: Option<PathBuf>, output: OutputFormat) -> Result<()> {
    let db_path = db.unwrap_or_else(store::default_path);
    let conn = store::open(&db_path).context("open views.db")?;
    let out_dir = out.unwrap_or_else(|| FreedomConfig::default_neoth_home().join("okf"));
    let ent_dir = out_dir.join("entities");
    let fact_dir = out_dir.join("facts");
    std::fs::create_dir_all(&ent_dir).with_context(|| format!("create {}", ent_dir.display()))?;
    std::fs::create_dir_all(&fact_dir).with_context(|| format!("create {}", fact_dir.display()))?;

    // ── Entities → concepts, with relations as markdown links ────────────
    let ents = entities::list_all(&conn).context("list entities")?;
    let mut ent_count = 0usize;
    for e in &ents {
        let neighbors = entities::get_neighbors(&conn, &e.name, 1).unwrap_or_default();
        let links: Vec<OkfLink> = neighbors
            .iter()
            .filter(|n| n.name != e.name)
            .map(|n| OkfLink {
                label: format!("{} — {}", n.name, n.via_relation),
                href: format!("{}.md", slug(&n.name)), // sibling in entities/
            })
            .collect();
        let etype = if e.entity_type.trim().is_empty() {
            "entity".to_string()
        } else {
            e.entity_type.clone()
        };
        let concept = OkfConcept {
            concept_type: etype.clone(),
            title: e.name.clone(),
            description: describe_attrs(&e.attributes),
            tags: dedup_nonempty(vec!["entity".to_string(), etype]),
            body: format!(
                "Corroborating sources: {}\n\nAttributes:\n\n```json\n{}\n```",
                e.source_count,
                if e.attributes.trim().is_empty() { "{}" } else { e.attributes.trim() }
            ),
            links,
        };
        let path = ent_dir.join(format!("{}.md", slug(&e.name)));
        std::fs::write(&path, concept.render())
            .with_context(|| format!("write {}", path.display()))?;
        ent_count += 1;
    }

    // ── Ground-truth facts → concepts ────────────────────────────────────
    let facts = groundtruth::surface_for_recall(&conn, 100_000, true).context("list facts")?;
    let mut fact_count = 0usize;
    for f in &facts {
        let concept = OkfConcept {
            concept_type: "fact".to_string(),
            title: truncate(&f.statement, 64),
            description: Some(f.statement.clone()),
            tags: dedup_nonempty(vec![f.scope.clone(), f.fact_state.clone()]),
            body: format!(
                "Source: {}\nScope: {}\nState: {}\nWeight: {}",
                f.source, f.scope, f.fact_state, f.source_weight
            ),
            links: vec![],
        };
        let path = fact_dir.join(format!("{}.md", f.id));
        std::fs::write(&path, concept.render())
            .with_context(|| format!("write {}", path.display()))?;
        fact_count += 1;
    }

    // ── Bundle index (OKF reserved README) ───────────────────────────────
    let readme = format!(
        "# NEOTH knowledge — OKF bundle\n\n\
         Open Knowledge Format export of NEOTH's memory: `entities/` (people, \
         places, things + their relations) and `facts/` (ground-truth \
         assertions). Each file is markdown + YAML frontmatter; relations are \
         markdown links — open this folder as an Obsidian vault to browse the \
         graph.\n\n\
         - entities: {ent_count}\n- facts: {fact_count}\n\n\
         Format: Open Knowledge Format (OKF) v0.1.\n"
    );
    std::fs::write(out_dir.join("README.md"), readme).context("write bundle README")?;

    if matches!(output, OutputFormat::Json | OutputFormat::Jsonl) {
        println!(
            "{}",
            serde_json::json!({
                "ok": true, "entities": ent_count, "facts": fact_count,
                "bundle": out_dir.display().to_string(),
            })
        );
    } else {
        println!(
            "OKF bundle written: {} entities + {} facts → {}",
            ent_count,
            fact_count,
            out_dir.display()
        );
        println!("Open the folder as an Obsidian vault to browse the knowledge graph.");
    }
    Ok(())
}

/// First attribute pair as a one-sentence description, e.g. `{"role":"dev"}` →
/// "role: dev". `None` when there are no usable attributes.
fn describe_attrs(attrs_json: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(attrs_json.trim()).ok()?;
    let obj = v.as_object()?;
    let parts: Vec<String> = obj
        .iter()
        .take(3)
        .map(|(k, val)| match val {
            serde_json::Value::String(s) => format!("{k}: {s}"),
            other => format!("{k}: {other}"),
        })
        .collect();
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("; "))
    }
}

fn truncate(s: &str, max: usize) -> String {
    let s = s.trim();
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{cut}…")
    }
}

fn dedup_nonempty(tags: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for t in tags {
        let t = t.trim().to_string();
        if !t.is_empty() && !out.contains(&t) {
            out.push(t);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describe_attrs_renders_first_pairs() {
        // serde_json map ordering isn't guaranteed insertion-order, so assert
        // on content, not exact ordering.
        let d = describe_attrs(r#"{"role":"engineer","city":"Berlin"}"#).expect("some");
        assert!(d.contains("role: engineer"), "got: {d}");
        assert!(d.contains("city: Berlin"), "got: {d}");
        assert_eq!(describe_attrs("{}"), None);
        assert_eq!(describe_attrs("not json"), None);
    }

    #[test]
    fn truncate_respects_char_boundaries() {
        assert_eq!(truncate("short", 64), "short");
        assert_eq!(truncate("aaaaaa", 4), "aaa…");
    }

    #[test]
    fn dedup_drops_empty_and_repeats() {
        assert_eq!(
            dedup_nonempty(vec!["a".into(), "".into(), "a".into(), "b".into()]),
            vec!["a".to_string(), "b".to_string()]
        );
    }
}
