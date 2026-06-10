//! `neoth recipe` — GOLD-ADOPT-16 declarative parametrized recipe runner.
//!
//! Subcommands:
//!   `run <file|deeplink> --param k=v …` — render + execute through `neoth chat`.
//!   `list`                              — list recipes in `~/.neoth/recipes/`.
//!   `validate <file>`                   — parse + structurally check, no run.
//!   `share <file>`                      — print a `neoth://recipe/…` deeplink.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::recipes::{deeplink, render, schema::RecipeSpec};

#[derive(Args, Debug, Clone)]
pub struct RecipeArgs {
    #[command(subcommand)]
    pub action: RecipeAction,
    /// Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum RecipeAction {
    /// Render a recipe (file path OR `neoth://recipe/…` deeplink) with the given
    /// `--param key=value` pairs and run it through the chat pipeline.
    Run {
        /// Recipe file path, or a `neoth://recipe/<base64>` deeplink.
        source: String,
        /// Parameter value, `key=value`. Repeatable.
        #[arg(long = "param", value_name = "KEY=VALUE")]
        params: Vec<String>,
        /// Render + print the resolved prompt WITHOUT calling the provider.
        #[arg(long)]
        dry_run: bool,
    },
    /// List recipes in `~/.neoth/recipes/` (name + description).
    List,
    /// Parse + structurally validate a recipe file (no run).
    Validate {
        /// Recipe file path.
        file: PathBuf,
    },
    /// Print a shareable `neoth://recipe/<base64>` deeplink for a recipe file.
    Share {
        /// Recipe file path.
        file: PathBuf,
    },
}

pub async fn run_recipe(args: RecipeArgs) -> Result<()> {
    match args.action {
        RecipeAction::Run {
            source,
            params,
            dry_run,
        } => run_one(&source, &params, dry_run, args.output).await,
        RecipeAction::List => list_recipes(args.output),
        RecipeAction::Validate { file } => validate_one(&file, args.output),
        RecipeAction::Share { file } => share_one(&file, args.output),
    }
}

/// `~/.neoth/recipes/`.
fn recipes_dir() -> PathBuf {
    FreedomConfig::default_neoth_home().join("recipes")
}

/// Load a recipe from a file path or a deeplink string.
fn load_recipe(source: &str) -> Result<RecipeSpec> {
    if deeplink::is_deeplink(source) {
        return deeplink::decode(source).context("decode recipe deeplink");
    }
    let body = std::fs::read_to_string(source)
        .with_context(|| format!("read recipe file `{source}`"))?;
    RecipeSpec::parse(&body).with_context(|| format!("parse recipe `{source}`"))
}

/// Parse `--param key=value` strings into a map. A bare `key` (no `=`) maps to an
/// empty value; the first `=` splits key from value (values may contain `=`).
fn parse_params(pairs: &[String]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (k.trim().to_string(), v.to_string()),
            None => (p.trim().to_string(), String::new()),
        })
        .collect()
}

async fn run_one(source: &str, params: &[String], dry_run: bool, output: OutputFormat) -> Result<()> {
    let spec = load_recipe(source)?;
    let supplied = parse_params(params);
    let rendered = render(&spec, &supplied)
        .map_err(|e| anyhow::anyhow!("recipe `{}`: {e}", spec.name))?;

    // ADOPT-16 (core): sub-recipe composition + retry are parsed but not yet
    // executed — surface that rather than silently dropping them so a recipe
    // author isn't misled into thinking they ran.
    if !spec.sub_recipes.is_empty() || spec.retry.is_some() {
        eprintln!(
            "  note: this recipe declares sub_recipes/retry, which are parsed but \
             NOT executed by `recipe run` in this version (core run only)."
        );
    }

    if dry_run {
        match output {
            OutputFormat::Json | OutputFormat::Jsonl => println!(
                "{}",
                serde_json::json!({
                    "recipe": spec.name,
                    "prompt": rendered.prompt,
                    "system": rendered.system,
                    "model": rendered.settings.model,
                })
            ),
            OutputFormat::Table => {
                println!("recipe:  {}", spec.name);
                if let Some(m) = &rendered.settings.model {
                    println!("model:   {m}");
                }
                if let Some(s) = &rendered.system {
                    println!("system:  {s}");
                }
                println!("prompt:  {}", rendered.prompt);
            }
        }
        return Ok(());
    }

    // Build a one-shot ChatArgs from the rendered recipe + run the full chat
    // pipeline (skill routing, MCP tool-loop, council, hooks). `message` MUST be
    // non-empty (render guarantees it) or run_chat would block on stdin.
    let chat_args = crate::cli::chat::ChatArgs {
        message: Some(rendered.prompt),
        model: rendered.settings.model,
        system: rendered.system,
        config: None,
        wal_segment: None,
        stream: matches!(output, OutputFormat::Jsonl),
        temperature: rendered.settings.temperature,
        top_p: None,
        sampling_seed: None,
        resume_from: None,
    };
    crate::cli::chat::run_chat(chat_args).await
}

fn validate_one(file: &Path, output: OutputFormat) -> Result<()> {
    let body =
        std::fs::read_to_string(file).with_context(|| format!("read `{}`", file.display()))?;
    match RecipeSpec::parse(&body) {
        Ok(spec) => {
            match output {
                OutputFormat::Json | OutputFormat::Jsonl => println!(
                    "{}",
                    serde_json::json!({
                        "valid": true,
                        "name": spec.name,
                        "parameters": spec.parameters.len(),
                    })
                ),
                OutputFormat::Table => println!(
                    "valid: {} ({} parameter(s))",
                    spec.name,
                    spec.parameters.len()
                ),
            }
            Ok(())
        }
        Err(e) => match output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                println!("{}", serde_json::json!({ "valid": false, "error": e.to_string() }));
                anyhow::bail!("recipe invalid")
            }
            OutputFormat::Table => {
                eprintln!("invalid: {e}");
                anyhow::bail!("recipe invalid")
            }
        },
    }
}

fn share_one(file: &Path, output: OutputFormat) -> Result<()> {
    let body =
        std::fs::read_to_string(file).with_context(|| format!("read `{}`", file.display()))?;
    let spec = RecipeSpec::parse(&body).context("parse recipe")?;
    let link = deeplink::encode(&spec).map_err(|e| anyhow::anyhow!("{e}"))?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::json!({ "deeplink": link }))
        }
        OutputFormat::Table => println!("{link}"),
    }
    Ok(())
}

fn list_recipes(output: OutputFormat) -> Result<()> {
    let dir = recipes_dir();
    let mut found: Vec<(String, String, String)> = Vec::new(); // (file, name, description)
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for e in entries.flatten() {
            let path = e.path();
            let is_yaml = path
                .extension()
                .and_then(|x| x.to_str())
                .map(|x| x == "yaml" || x == "yml")
                .unwrap_or(false);
            if !is_yaml {
                continue;
            }
            if let Ok(body) = std::fs::read_to_string(&path) {
                if let Ok(spec) = RecipeSpec::parse(&body) {
                    let fname = path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("")
                        .to_string();
                    found.push((fname, spec.name, spec.description));
                }
            }
        }
    }
    found.sort();
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            for (file, name, description) in &found {
                println!(
                    "{}",
                    serde_json::json!({ "file": file, "name": name, "description": description })
                );
            }
        }
        OutputFormat::Table => {
            if found.is_empty() {
                println!(
                    "no recipes in {} — drop a <name>.yaml there, or run a file/deeplink directly",
                    dir.display()
                );
                return Ok(());
            }
            println!("{:<28} {:<22} description", "file", "name");
            println!("{}", "-".repeat(72));
            for (file, name, description) in &found {
                let d: String = description.chars().take(40).collect();
                println!("{file:<28} {name:<22} {d}");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_params_splits_on_first_equals() {
        let m = parse_params(&[
            "host=example.com".into(),
            "query=a=b=c".into(),
            "flag".into(),
        ]);
        assert_eq!(m.get("host").unwrap(), "example.com");
        assert_eq!(m.get("query").unwrap(), "a=b=c", "only the first = splits");
        assert_eq!(m.get("flag").unwrap(), "", "bare key → empty value");
    }

    #[test]
    fn load_recipe_accepts_deeplink() {
        let spec = RecipeSpec::parse("name: g\nprompt: \"hi {{x}}\"\nparameters:\n  - key: x\n").unwrap();
        let link = deeplink::encode(&spec).unwrap();
        let loaded = load_recipe(&link).unwrap();
        assert_eq!(loaded.name, "g");
    }
}
