//! `neoth n8n {status, workflows}` — inspect the n8n integration surface.
//!
//! NEOTH doesn't embed n8n. It exposes a loopback webhook server
//! (`neoth webhook serve`, default `http://localhost:8765`) that n8n workflows
//! POST to, plus a set of operator-ready starter workflows baked into the
//! binary (`installers::n8n_starter_workflows`). This command is READ-ONLY: it
//! reports that integration's local state (webhook base, whether the `n8n`
//! binary is on `PATH`, bundled-workflow count) and lists the bundled
//! workflows. It makes no n8n API calls and never starts anything.

use std::ffi::OsStr;
use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::installers::n8n_starter_workflows::{NEOTH_HTTP_BASE, all_known_workflows};

#[derive(Args, Debug, Clone)]
pub struct N8nArgs {
    #[command(subcommand)]
    pub action: N8nAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum N8nAction {
    /// Report n8n integration status: the webhook base URL n8n POSTs to,
    /// whether the `n8n` binary is on PATH, and the bundled-workflow count.
    Status,
    /// List the NEOTH workflows bundled in the binary (slug / name /
    /// description) that an operator can import into n8n.
    Workflows,
}

/// Executable names npm produces for n8n per platform (the Windows npm shim is
/// a `.cmd`; a global install may also land a `.exe` or bare name).
fn n8n_candidate_names() -> &'static [&'static str] {
    if cfg!(windows) {
        &["n8n.cmd", "n8n.exe", "n8n.bat", "n8n"]
    } else {
        &["n8n"]
    }
}

/// Scan a `PATH`-style variable for the first existing n8n executable. Pure +
/// injectable (the `path_var` is passed in) so it's hermetically testable
/// without depending on the host's real PATH.
fn find_in_path(path_var: Option<&OsStr>, names: &[&str]) -> Option<PathBuf> {
    let path_var = path_var?;
    for dir in std::env::split_paths(path_var) {
        for name in names {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// Locate the `n8n` binary on the live `PATH`, if installed.
fn detect_n8n() -> Option<PathBuf> {
    find_in_path(std::env::var_os("PATH").as_deref(), n8n_candidate_names())
}

pub fn run_n8n(args: N8nArgs, output: OutputFormat) -> Result<()> {
    match args.action {
        N8nAction::Status => run_status(output),
        N8nAction::Workflows => run_workflows(output),
    }
}

fn run_status(output: OutputFormat) -> Result<()> {
    let n8n = detect_n8n();
    let workflow_count = all_known_workflows().len();
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!(
            "{}",
            serde_json::json!({
                "webhook_base": NEOTH_HTTP_BASE,
                "n8n_installed": n8n.is_some(),
                "n8n_path": n8n.as_ref().map(|p| p.display().to_string()),
                "bundled_workflows": workflow_count,
            })
        ),
        OutputFormat::Table => {
            println!("n8n integration");
            println!("  webhook base    : {NEOTH_HTTP_BASE}  (start with `neoth webhook serve`)");
            match &n8n {
                Some(p) => println!("  n8n binary      : {}", p.display()),
                None => println!(
                    "  n8n binary      : not on PATH (install via `neoth init` n8n step, or `npm i -g n8n`)"
                ),
            }
            println!("  bundled workflows: {workflow_count}  (`neoth n8n workflows` to list)");
        }
    }
    Ok(())
}

fn run_workflows(output: OutputFormat) -> Result<()> {
    let workflows = all_known_workflows();
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let rows: Vec<_> = workflows
                .iter()
                .map(|w| {
                    serde_json::json!({
                        "slug": w.slug,
                        "name": w.name,
                        "description": w.description,
                    })
                })
                .collect();
            println!("{}", serde_json::json!({ "workflows": rows }));
        }
        OutputFormat::Table => {
            if workflows.is_empty() {
                println!("(no bundled workflows)");
            } else {
                for w in &workflows {
                    println!("• {}  [{}]", w.name, w.slug);
                    println!("    {}", w.description);
                }
                println!(
                    "\n{} workflow(s). Import into n8n; they POST to {NEOTH_HTTP_BASE}.",
                    workflows.len()
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_in_path_locates_a_fake_n8n() {
        let dir = tempfile::tempdir().unwrap();
        // Create a fake executable matching the first platform candidate.
        let name = n8n_candidate_names()[0];
        let bin = dir.path().join(name);
        std::fs::write(&bin, b"#!/bin/sh\necho n8n\n").unwrap();
        let path_var = dir.path().as_os_str();
        let found = find_in_path(Some(path_var), n8n_candidate_names());
        assert_eq!(found.as_deref(), Some(bin.as_path()));
    }

    #[test]
    fn find_in_path_returns_none_when_absent() {
        let dir = tempfile::tempdir().unwrap(); // empty dir, no n8n
        assert!(find_in_path(Some(dir.path().as_os_str()), n8n_candidate_names()).is_none());
        // No PATH at all → None, never panics.
        assert!(find_in_path(None, n8n_candidate_names()).is_none());
    }

    #[test]
    fn status_and_workflows_are_infallible() {
        // Both read-only views must succeed regardless of host n8n state.
        run_n8n(N8nArgs { action: N8nAction::Status }, OutputFormat::Json).expect("status ok");
        run_n8n(N8nArgs { action: N8nAction::Workflows }, OutputFormat::Table).expect("workflows ok");
    }

    #[test]
    fn bundles_at_least_the_three_starter_workflows() {
        // Pins that `neoth n8n workflows` surfaces the baked-in set.
        assert!(all_known_workflows().len() >= 3);
    }
}
