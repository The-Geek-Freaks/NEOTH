//! GOLD-ADAPT-HARNESS-02 — `neoth trace-replay <session_id>`: render a recorded
//! session trajectory as a human-readable turn-by-turn replay.
//!
//! The writer is [`crate::mcp::harness::append_trajectory`], which appends one
//! [`TurnRecord`] per turn to `~/.neoth/trajectories/<session_id>.jsonl`. This
//! command is the read side (the KB-03 `distill` command is the other consumer,
//! which mines the same files for repeated tool-call sequences). No secrets are
//! stored in a trajectory (the prompt is a hash + length only), so a replay is
//! safe to print.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args;

use crate::mcp::harness::TurnRecord;

#[derive(Args, Debug)]
pub struct TraceReplayArgs {
    /// Session id to replay (the `<id>` in `trajectories/<id>.jsonl`).
    pub session_id: String,
    /// Explicit path to a `.jsonl` trajectory file (overrides the default
    /// `~/.neoth/trajectories/<session_id>.jsonl`).
    #[arg(long)]
    pub file: Option<PathBuf>,
    /// Emit the parsed turns as JSON instead of the narrative table.
    #[arg(long)]
    pub json: bool,
}

/// Resolve the trajectory file path for a session id.
pub fn trajectory_path(session_id: &str) -> PathBuf {
    crate::config::FreedomConfig::default_neoth_home()
        .join("trajectories")
        .join(format!("{session_id}.jsonl"))
}

/// Parse a trajectory `.jsonl` into its turns (skips blank/garbled lines).
pub fn parse_trajectory(content: &str) -> Vec<TurnRecord> {
    content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<TurnRecord>(l).ok())
        .collect()
}

pub fn run_trace_replay(args: TraceReplayArgs) -> Result<()> {
    let path = args
        .file
        .unwrap_or_else(|| trajectory_path(&args.session_id));
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("read trajectory {}", path.display()))?;
    let turns = parse_trajectory(&content);

    if args.json {
        println!("{}", serde_json::to_string_pretty(&turns)?);
        return Ok(());
    }

    if turns.is_empty() {
        println!("trace-replay: no turns found in {}", path.display());
        return Ok(());
    }

    println!(
        "=== session trajectory: {} ({} turn{}) ===",
        args.session_id,
        turns.len(),
        if turns.len() == 1 { "" } else { "s" }
    );
    for t in &turns {
        let tools = if t.tool_calls.is_empty() {
            "-".to_string()
        } else {
            t.tool_calls.join(", ")
        };
        println!(
            "  turn {:>3} | {:<12} | prompt {}... ({}b) | tools: {}",
            t.turn, t.verdict, t.prompt_hash, t.prompt_len, tools
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_trajectory_reads_turns_skipping_garbage() {
        let jsonl = concat!(
            r#"{"turn":1,"prompt_hash":"abc123","prompt_len":42,"tool_calls":["fs/read_file"],"verdict":"tool_calls","ts_unix":100}"#,
            "\n",
            "   \n",             // blank line skipped
            "not json at all\n", // garbled line skipped
            r#"{"turn":2,"prompt_hash":"def456","prompt_len":10,"tool_calls":[],"verdict":"clean_exit","ts_unix":200}"#,
            "\n",
        );
        let turns = parse_trajectory(jsonl);
        assert_eq!(turns.len(), 2);
        assert_eq!(turns[0].turn, 1);
        assert_eq!(turns[0].tool_calls, vec!["fs/read_file".to_string()]);
        assert_eq!(turns[1].verdict, "clean_exit");
        assert!(turns[1].tool_calls.is_empty());
    }

    #[test]
    fn trajectory_path_uses_session_id() {
        let p = trajectory_path("sess_xyz");
        assert!(p.to_string_lossy().ends_with("sess_xyz.jsonl"));
        assert!(p.to_string_lossy().contains("trajectories"));
    }
}
