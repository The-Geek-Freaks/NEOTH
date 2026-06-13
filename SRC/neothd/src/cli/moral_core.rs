//! `neoth moral-core` — build + inspect the LOWKEY moral-core directives (GOLD-FEAT-07).
//!
//! The moral core is the operator's sovereign "constitution" injected at
//! enrichment position-0 before every response. This CLI lets the operator
//! BUILD it two ways (operator directive 2026-06-13): as **free text**
//! (`add`/`new`/`remove`/`edit via files`) or by **picking features** from the
//! built-in [`catalog`](crate::memory::moral_core::catalog)
//! (`template list|show|add`). Read surfaces (`list`/`preview`/`doctor`) show
//! exactly what gets injected — full transparency, no hidden content. All
//! mutations go through [`crate::memory::moral_core::writer`] (atomic, owner-
//! only perms, path-traversal-guarded).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::memory::moral_core;

#[derive(Args, Debug, Clone)]
pub struct MoralCoreArgs {
    #[command(subcommand)]
    pub action: MoralCoreAction,
    /// Override the moral-core directory. Defaults to `~/.neoth/moral_core/`.
    #[arg(long, value_name = "PATH", global = true)]
    pub dir: Option<PathBuf>,
    /// Populated from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum MoralCoreAction {
    /// List the parsed blocks (tag, directive count, source file).
    List,
    /// Print the compact directive text that WOULD be injected at enrichment
    /// position 0 (highest priority). Empty when no moral core is configured.
    Preview,
    /// Validate the moral-core directory: report presence + block/directive
    /// counts, and warn when it is empty or has no directives.
    Doctor,
    /// Scaffold a starter moral core (honesty + voice + anti-hedging defaults),
    /// then show what would be injected. Idempotent unless `--force`.
    Init {
        /// Reset the starter blocks even if the directory already has content.
        #[arg(long)]
        force: bool,
    },
    /// Create an empty category block `<category>.md` with a heading, ready for
    /// `add`. (Plain `add` also auto-creates — `new` is for setting a custom heading.)
    New {
        /// Category file stem, `[a-z0-9_-]+` (e.g. `honesty`).
        category: String,
        /// Block heading; defaults to the capitalised category.
        #[arg(long, value_name = "HEADING")]
        heading: Option<String>,
    },
    /// Append a free-text directive to a category (creates the file if missing).
    /// This is the "write your own as text" path.
    Add {
        /// Category file stem, `[a-z0-9_-]+`.
        category: String,
        /// Directive text (the `- ` bullet prefix is added automatically).
        directive: String,
    },
    /// Remove one directive by its 1-based index (as shown by `list`).
    Remove {
        category: String,
        #[arg(value_name = "INDEX")]
        index: usize,
    },
    /// Disable a category block (renamed to `*.md.disabled`; the loader skips
    /// it, so it is not injected). Re-enable with `enable`.
    Disable { category: String },
    /// Re-enable a previously disabled category block.
    Enable { category: String },
    /// Manage the built-in directive-template catalog (the "pick a feature" path).
    Template {
        #[command(subcommand)]
        action: TemplateAction,
    },
}

/// Built-in directive-template catalog operations.
#[derive(Subcommand, Debug, Clone)]
pub enum TemplateAction {
    /// List the built-in templates, optionally filtered by group.
    List {
        /// Filter by display group (e.g. `Honesty`, `Voice`, `Latitude`).
        #[arg(long)]
        group: Option<String>,
    },
    /// Print a template's directives without applying it.
    Show {
        /// Template id `<category>/<slug>` (e.g. `honesty/no-fabrication`).
        id: String,
    },
    /// Apply a template: append its directives to the matching category file.
    Add {
        /// Template id `<category>/<slug>`.
        id: String,
        /// Override the target category file stem (defaults to the template's).
        #[arg(long)]
        into: Option<String>,
    },
}

pub fn run_moral_core(args: MoralCoreArgs) -> Result<()> {
    let dir = args.dir.clone().unwrap_or_else(moral_core::default_dir);
    let blocks = moral_core::load_moral_core(&dir)?;
    let directive_total: usize = blocks.iter().map(|b| b.directive_count()).sum();

    match args.action {
        MoralCoreAction::List => match args.output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                let rows: Vec<_> = blocks
                    .iter()
                    .map(|b| {
                        serde_json::json!({
                            "tag": b.tag,
                            "directives": b.directive_count(),
                            "source": b.source,
                        })
                    })
                    .collect();
                println!("{}", serde_json::json!({ "dir": dir.display().to_string(), "blocks": rows }));
            }
            OutputFormat::Table => {
                if blocks.is_empty() {
                    println!("no moral-core blocks in {}", dir.display());
                } else {
                    println!("moral-core blocks ({}):", blocks.len());
                    for b in &blocks {
                        println!("  [{}] {} directive(s)  ({})", b.tag, b.directive_count(), b.source);
                    }
                }
            }
        },
        MoralCoreAction::Preview => {
            let compact = moral_core::compact_directives(&blocks);
            if compact.is_empty() {
                println!("(no moral core configured — nothing would be injected)");
            } else {
                print!("{compact}");
            }
        }
        MoralCoreAction::Doctor => {
            let exists = dir.exists();
            match args.output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    println!(
                        "{}",
                        serde_json::json!({
                            "dir": dir.display().to_string(),
                            "exists": exists,
                            "blocks": blocks.len(),
                            "directives": directive_total,
                            "ok": exists && directive_total > 0,
                        })
                    );
                }
                OutputFormat::Table => {
                    println!("moral-core doctor — {}", dir.display());
                    println!("  dir exists:   {exists}");
                    println!("  blocks:       {}", blocks.len());
                    println!("  directives:   {directive_total}");
                    if !exists {
                        println!("  ⚠ directory missing — moral core is opt-in; create it + add `*.md` files");
                    } else if directive_total == 0 {
                        println!("  ⚠ no directives parsed — add `- directive` bullets under `# Heading`s");
                    } else {
                        println!("  ✓ {directive_total} directive(s) ready to inject");
                    }
                }
            }
        }
        MoralCoreAction::Init { force } => {
            if dir.exists() && !force && directive_total > 0 {
                println!(
                    "moral core already populated at {} ({directive_total} directive(s)) — use --force to reset the starter blocks",
                    dir.display()
                );
            } else {
                let applied = moral_core::writer::init_starter(&dir, force)?;
                println!(
                    "moral core scaffolded at {} ({} starter template(s))",
                    dir.display(),
                    applied.len()
                );
                let blocks = moral_core::load_moral_core(&dir)?;
                println!("\n--- preview ---");
                print!("{}", moral_core::compact_directives(&blocks));
            }
        }
        MoralCoreAction::New { category, heading } => {
            moral_core::writer::validate_category(&category)?;
            let target = dir.join(format!("{category}.md"));
            if target.exists() {
                println!("block '{category}' already exists at {}", target.display());
            } else {
                let h = heading.unwrap_or_else(|| capitalize(&category));
                moral_core::writer::atomic_write_block(&dir, &category, &format!("# {h}\n"))?;
                println!(
                    "created block '{category}' — add directives with `neoth moral-core add {category} \"<directive>\"`"
                );
            }
        }
        MoralCoreAction::Add { category, directive } => {
            moral_core::writer::append_directive(&dir, &category, &directive)?;
            println!("added to '{category}': {directive}");
        }
        MoralCoreAction::Remove { category, index } => {
            moral_core::writer::remove_directive(&dir, &category, index)?;
            println!("removed directive {index} from '{category}'");
        }
        MoralCoreAction::Disable { category } => {
            moral_core::writer::disable_block(&dir, &category)?;
            println!("disabled block '{category}' — renamed to {category}.md.disabled, not injected");
        }
        MoralCoreAction::Enable { category } => {
            moral_core::writer::enable_block(&dir, &category)?;
            println!("enabled block '{category}'");
        }
        MoralCoreAction::Template { action } => run_template(action, &dir)?,
    }
    Ok(())
}

/// Capitalise the first character — a default `# Heading` from a category stem.
fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

/// Dispatch the `template` sub-surface over the built-in catalog.
fn run_template(action: TemplateAction, dir: &Path) -> Result<()> {
    use crate::memory::moral_core::catalog;
    match action {
        TemplateAction::List { group } => {
            let entries = catalog::list_by_group(group.as_deref());
            if entries.is_empty() {
                match group {
                    Some(g) => println!("no templates in group '{g}'"),
                    None => println!("catalog is empty"),
                }
                return Ok(());
            }
            println!("built-in moral-core templates ({}):", entries.len());
            let mut cur = "";
            for e in entries {
                if e.group != cur {
                    println!("\n{}:", e.group);
                    cur = e.group;
                }
                println!("  {:<32} {}", e.id, e.label);
            }
            println!("\napply one with: neoth moral-core template add <id>");
        }
        TemplateAction::Show { id } => {
            let e = catalog::find(&id)
                .with_context(|| format!("template '{id}' not in catalog (see `template list`)"))?;
            println!("{} — {}", e.id, e.label);
            println!("category: {}  group: {}", e.default_category, e.group);
            for d in e.directives {
                println!("  - {d}");
            }
        }
        TemplateAction::Add { id, into } => {
            let n = moral_core::writer::apply_template(dir, &id, into.as_deref())?;
            let stem = into
                .as_deref()
                .or_else(|| catalog::find(&id).map(|e| e.default_category))
                .unwrap_or("?");
            println!("applied '{id}' — {n} directive(s) added to '{stem}'");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args_with(dir: &Path, action: MoralCoreAction) -> MoralCoreArgs {
        MoralCoreArgs {
            action,
            dir: Some(dir.to_path_buf()),
            output: OutputFormat::Table,
        }
    }

    #[test]
    fn add_then_list_roundtrip_via_cli() {
        let tmp = tempfile::tempdir().unwrap();
        run_moral_core(args_with(
            tmp.path(),
            MoralCoreAction::Add {
                category: "honesty".into(),
                directive: "never fabricate a source".into(),
            },
        ))
        .unwrap();
        let blocks = moral_core::load_moral_core(tmp.path()).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].directives, vec!["never fabricate a source"]);
    }

    #[test]
    fn template_add_via_cli_appends_catalog_directives() {
        let tmp = tempfile::tempdir().unwrap();
        run_moral_core(args_with(
            tmp.path(),
            MoralCoreAction::Template {
                action: TemplateAction::Add {
                    id: "voice/match-register".into(),
                    into: None,
                },
            },
        ))
        .unwrap();
        let blocks = moral_core::load_moral_core(tmp.path()).unwrap();
        assert_eq!(blocks[0].tag, "Voice");
        assert!(!blocks[0].directives.is_empty());
    }

    #[test]
    fn init_then_disable_removes_from_injection() {
        let tmp = tempfile::tempdir().unwrap();
        run_moral_core(args_with(tmp.path(), MoralCoreAction::Init { force: false })).unwrap();
        assert!(
            !moral_core::load_moral_core(tmp.path()).unwrap().is_empty(),
            "init scaffolds blocks"
        );
        run_moral_core(args_with(
            tmp.path(),
            MoralCoreAction::Disable { category: "voice".into() },
        ))
        .unwrap();
        let after = moral_core::load_moral_core(tmp.path()).unwrap();
        assert!(
            after.iter().all(|b| b.tag != "Voice"),
            "disabled voice block must not load"
        );
    }
}
