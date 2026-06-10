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

/// Max sub-recipe nesting depth (cycle / runaway guard).
const MAX_SUBRECIPE_DEPTH: usize = 4;

/// GOLD-ADOPT-16 — sub-recipe composition (TEMPLATE composition, NEOTH's
/// cheap-by-default interpretation: a sub-recipe's RENDERED PROMPT is injected
/// into the parent via `{{key}}`, NOT a nested LLM call — so composing recipes
/// costs zero extra provider calls). Returns the parent's supplied params
/// augmented with one `{sub.key => sub.rendered_prompt}` entry per sub-recipe.
///
/// Sub files resolve relative to the parent recipe's directory. A sub's param
/// VALUES may themselves reference parent params (`{{parent_key}}`), substituted
/// before the sub renders. Deeplinks can't carry file-based sub-recipes (no
/// parent dir) — that's an error.
fn resolve_subrecipes(
    spec: &RecipeSpec,
    parent_dir: Option<&Path>,
    supplied: &BTreeMap<String, String>,
    depth: usize,
) -> Result<BTreeMap<String, String>> {
    let mut augmented = supplied.clone();
    if spec.sub_recipes.is_empty() {
        return Ok(augmented);
    }
    if depth >= MAX_SUBRECIPE_DEPTH {
        anyhow::bail!(
            "recipe `{}`: sub-recipe nesting exceeds depth {MAX_SUBRECIPE_DEPTH} (cycle?)",
            spec.name
        );
    }
    let dir = parent_dir.context(
        "this recipe declares sub_recipes but was loaded from a deeplink — \
         sub-recipes resolve relative files and need a local parent path",
    )?;
    for sub in &spec.sub_recipes {
        let sub_path = dir.join(&sub.file);
        let body = std::fs::read_to_string(&sub_path)
            .with_context(|| format!("read sub-recipe `{}`", sub_path.display()))?;
        let sub_spec = RecipeSpec::parse(&body)
            .with_context(|| format!("parse sub-recipe `{}`", sub_path.display()))?;
        // Sub param values may reference the PARENT's params: substitute those
        // first (a plain key→value pass), so `params: { host: "{{target}}" }`
        // forwards the parent's `target`.
        let sub_supplied: BTreeMap<String, String> = sub
            .params
            .iter()
            .map(|(k, v)| (k.clone(), substitute_parent_tokens(v, supplied)))
            .collect();
        let sub_dir = sub_path.parent().map(Path::to_path_buf);
        let sub_augmented =
            resolve_subrecipes(&sub_spec, sub_dir.as_deref(), &sub_supplied, depth + 1)?;
        let sub_rendered = render(&sub_spec, &sub_augmented)
            .map_err(|e| anyhow::anyhow!("sub-recipe `{}`: {e}", sub_spec.name))?;
        augmented.insert(sub.key.clone(), sub_rendered.prompt);
    }
    Ok(augmented)
}

/// Plain `{{key}}` / `{{ key }}` substitution of parent params into a sub-recipe
/// param value (no type-checking — sub params get type-checked when the sub
/// renders).
fn substitute_parent_tokens(value: &str, parent: &BTreeMap<String, String>) -> String {
    let mut out = value.to_string();
    for (k, v) in parent {
        out = out.replace(&format!("{{{{{k}}}}}"), v);
        out = out.replace(&format!("{{{{ {k} }}}}"), v);
    }
    out
}

async fn run_one(source: &str, params: &[String], dry_run: bool, output: OutputFormat) -> Result<()> {
    let spec = load_recipe(source)?;
    let supplied = parse_params(params);
    // Resolve sub-recipes (template composition) into the param map first.
    let parent_dir = if deeplink::is_deeplink(source) {
        None
    } else {
        Path::new(source).parent().map(Path::to_path_buf)
    };
    let augmented = resolve_subrecipes(&spec, parent_dir.as_deref(), &supplied, 0)?;
    let rendered = render(&spec, &augmented)
        .map_err(|e| anyhow::anyhow!("recipe `{}`: {e}", spec.name))?;

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

    // A one-shot ChatArgs factory from the rendered recipe — rebuilt per attempt
    // because run_chat consumes the args. The full chat pipeline (skill routing,
    // MCP tool-loop, council, hooks) fires; `message` is guaranteed non-empty by
    // render (else run_chat would block on stdin).
    let make_args = || crate::cli::chat::ChatArgs {
        message: Some(rendered.prompt.clone()),
        model: rendered.settings.model.clone(),
        system: rendered.system.clone(),
        edit: false,
        config: None,
        wal_segment: None,
        stream: matches!(output, OutputFormat::Jsonl),
        temperature: rendered.settings.temperature,
        top_p: None,
        sampling_seed: None,
        resume_from: None,
    };

    // GOLD-ADOPT-16 — per-recipe retry with a shell success-check. SECURITY: the
    // success_check is an arbitrary shell command, so it runs ONLY for a recipe
    // loaded from a LOCAL FILE the operator authored. A deeplinked (untrusted)
    // recipe NEVER auto-runs its shell check — we warn + run once.
    match &spec.retry {
        None => crate::cli::chat::run_chat(make_args()).await,
        Some(retry) if deeplink::is_deeplink(source) => {
            eprintln!(
                "  ⚠ this recipe came from a deeplink and declares retry.success_check \
                 (a shell command) — refusing to auto-run untrusted shell. Running once. \
                 Save it to a local file you've reviewed to enable retry."
            );
            let _ = retry;
            crate::cli::chat::run_chat(make_args()).await
        }
        Some(retry) => {
            let attempts = retry.max.saturating_add(1);
            for attempt in 1..=attempts {
                crate::cli::chat::run_chat(make_args()).await?;
                if shell_check_succeeds(&retry.success_check) {
                    return Ok(());
                }
                if attempt < attempts {
                    eprintln!(
                        "  retry {attempt}/{attempts}: success_check `{}` failed — re-running",
                        retry.success_check
                    );
                }
            }
            anyhow::bail!(
                "recipe `{}`: success_check `{}` still failing after {attempts} attempt(s)",
                spec.name,
                retry.success_check
            )
        }
    }
}

/// Run a shell `success_check` and report whether it exited 0. Uses the platform
/// shell (`cmd /C` on Windows, `sh -c` elsewhere). A spawn failure counts as
/// NOT-succeeded (the check couldn't confirm success).
fn shell_check_succeeds(cmd: &str) -> bool {
    let mut command = if cfg!(windows) {
        let mut c = std::process::Command::new("cmd");
        c.args(["/C", cmd]);
        c
    } else {
        let mut c = std::process::Command::new("sh");
        c.args(["-c", cmd]);
        c
    };
    command
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
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

    #[test]
    fn subrecipe_composition_injects_rendered_sub_prompt() {
        // Parent references {{enriched}}; the sub-recipe renders "scan host.x"
        // (its `host` param forwarded from the parent's `target`), and that
        // rendered text is injected into the parent — zero extra LLM calls.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("sub.yaml"),
            "name: sub\nprompt: \"scan {{host}}\"\nparameters:\n  - key: host\n",
        )
        .unwrap();
        let parent_path = dir.path().join("parent.yaml");
        std::fs::write(
            &parent_path,
            "name: parent\nprompt: \"Do this: {{enriched}}\"\nparameters:\n  - key: target\nsub_recipes:\n  - key: enriched\n    file: sub.yaml\n    params:\n      host: \"{{target}}\"\n",
        )
        .unwrap();

        let spec = load_recipe(parent_path.to_str().unwrap()).unwrap();
        let supplied = parse_params(&["target=host.x".into()]);
        let augmented =
            resolve_subrecipes(&spec, dir.path().into(), &supplied, 0).unwrap();
        let rendered = render(&spec, &augmented).unwrap();
        assert_eq!(rendered.prompt, "Do this: scan host.x");
    }

    #[test]
    fn subrecipe_from_deeplink_is_rejected() {
        // A recipe with sub_recipes can't resolve relative files from a deeplink.
        let spec = RecipeSpec::parse(
            "name: p\nprompt: \"{{e}}\"\nsub_recipes:\n  - key: e\n    file: sub.yaml\n",
        )
        .unwrap();
        let err = resolve_subrecipes(&spec, None, &BTreeMap::new(), 0).unwrap_err();
        assert!(err.to_string().contains("deeplink"), "got: {err}");
    }

    #[test]
    fn shell_check_distinguishes_success_and_failure() {
        assert!(shell_check_succeeds("exit 0"), "exit 0 → success");
        assert!(!shell_check_succeeds("exit 1"), "exit 1 → failure");
    }
}
