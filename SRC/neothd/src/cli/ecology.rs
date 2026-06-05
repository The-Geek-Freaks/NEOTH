//! `neoth ecology` — CH-13 / F4-01 operator surface (read-only).
//!
//! `correlation` is the first Ecology slice: a deterministic, LLM-free scan of
//! the `0x63 COUNCIL_WINNER_SELECTED` WAL frames that reports when one provider
//! has won many consecutive outer-council debates (a low-dissent signal). It is
//! purely diagnostic — it changes nothing — so it works whether or not the
//! Ecology auto-scheduler (`ecology.enabled`) is on.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::ecology::correlation_detector::{detect_winner_streaks, scan_winner_records};
use crate::ecology::winner_chain::build_winner_chain;

#[derive(Args, Debug, Clone)]
pub struct EcologyArgs {
    #[command(subcommand)]
    pub action: EcologyAction,
    /// Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum EcologyAction {
    /// Report council-winner correlation: providers that won many consecutive
    /// outer-council debates (a low-dissent fitness signal). Read-only.
    Correlation {
        /// Minimum consecutive-win streak to report. Defaults to
        /// `freedom.yaml::ecology.correlation_min_streak` (5).
        #[arg(long)]
        min_streak: Option<usize>,
        /// Override the WAL directory (mostly for tests).
        #[arg(long, value_name = "DIR")]
        wal_dir: Option<PathBuf>,
    },
    /// KF-05 — report the per-channel Hebbian acceptance weights (which
    /// channels' messages most often produce a successful reply). Read-only.
    ChannelWeights {
        /// Override the NEOTH home (mostly for tests).
        #[arg(long, value_name = "DIR")]
        home: Option<PathBuf>,
    },
    /// F4-01 Phase 3 — tool genealogy: an inventory of the tools NEOTH actually
    /// exercises (MCP tools + plugins, by recorded use-count) plus installed
    /// skills as available-but-untraced nodes. Read-only + deterministic.
    Genealogy {
        /// Override the WAL directory (mostly for tests).
        #[arg(long, value_name = "DIR")]
        wal_dir: Option<PathBuf>,
        /// Override the NEOTH home for the installed-skill inventory.
        #[arg(long, value_name = "DIR")]
        home: Option<PathBuf>,
        /// Show only the top-N most-used tools. Default: all.
        #[arg(long)]
        top: Option<usize>,
    },
    /// F4-01 — council winner-chain: the measured win-distribution over the
    /// `0x63` winner frames (per provider+role, with avg/last score + the
    /// selection-mode mix). Read-only + deterministic — every field is in-frame.
    WinnerChain {
        /// Override the WAL directory (mostly for tests).
        #[arg(long, value_name = "DIR")]
        wal_dir: Option<PathBuf>,
        /// Show only the top-N winning voices. Default: all.
        #[arg(long)]
        top: Option<usize>,
    },
    /// Maturity matrix for the Ecology layer — what is read-only/beta vs
    /// experimental/review-gated, and the scheduler's enabled state. The
    /// Ecology layer is NOT "stable self-improvement"; this is the honest label.
    Status,
}

/// CH-13 — one Ecology surface's maturity + access posture. PURE data for the
/// `neoth ecology status` matrix.
struct EcologySurface {
    name: &'static str,
    maturity: &'static str,
    access: &'static str,
    note: &'static str,
}

/// The honest maturity matrix. Correlation/genealogy/channel-weights are
/// read-only diagnostics; the scheduler is experimental + review-gated (it
/// STAGES proposals, never auto-applies).
fn ecology_surfaces() -> [EcologySurface; 5] {
    [
        EcologySurface {
            name: "correlation",
            maturity: "beta",
            access: "read-only",
            note: "council low-dissent winner streaks (diagnostic)",
        },
        EcologySurface {
            name: "winner-chain",
            maturity: "beta",
            access: "read-only",
            note: "measured council win-distribution per provider/role/mode (diagnostic)",
        },
        EcologySurface {
            name: "genealogy",
            maturity: "beta",
            access: "read-only",
            note: "tool-usage inventory from real WAL frames (diagnostic)",
        },
        EcologySurface {
            name: "channel-weights",
            maturity: "beta",
            access: "read-only",
            note: "per-channel KF-05 acceptance familiarity (diagnostic)",
        },
        EcologySurface {
            name: "scheduler",
            maturity: "experimental",
            access: "review-gated",
            note: "stages self-dev proposals, NEVER auto-applies (0x4C)",
        },
    ]
}

pub async fn run_ecology(args: EcologyArgs) -> Result<()> {
    match args.action {
        EcologyAction::ChannelWeights { home } => {
            run_channel_weights(home, args.output);
            Ok(())
        }
        EcologyAction::Genealogy { wal_dir, home, top } => {
            run_genealogy(wal_dir, home, top, args.output).await;
            Ok(())
        }
        EcologyAction::WinnerChain { wal_dir, top } => {
            run_winner_chain(wal_dir, top, args.output);
            Ok(())
        }
        EcologyAction::Status => {
            let cfg = FreedomConfig::load_from_default_path().unwrap_or_default();
            run_status(cfg.ecology.enabled, args.output);
            Ok(())
        }
        EcologyAction::Correlation {
            min_streak,
            wal_dir,
        } => {
            let cfg = FreedomConfig::load_from_default_path().unwrap_or_default();
            let min_streak = min_streak.unwrap_or(cfg.ecology.correlation_min_streak).max(1);
            let wal_dir = wal_dir.unwrap_or_else(FreedomConfig::default_wal_dir);

            let records = scan_winner_records(&wal_dir);
            let signals = detect_winner_streaks(&records, min_streak);

            match args.output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    println!(
                        "{}",
                        serde_json::json!({
                            "total_winners": records.len(),
                            "min_streak": min_streak,
                            "signals": signals,
                        })
                    );
                }
                OutputFormat::Table => {
                    println!(
                        "council-winner correlation — {} winner(s) scanned, threshold {}",
                        records.len(),
                        min_streak
                    );
                    if signals.is_empty() {
                        println!(
                            "  (no low-dissent streaks ≥ {min_streak} — the council is surfacing diversity)"
                        );
                    } else {
                        for s in &signals {
                            println!(
                                "  ⚠ {} won {} consecutive debates (low-dissent signal)",
                                s.provider, s.streak_len
                            );
                        }
                    }
                }
            }
            Ok(())
        }
    }
}

/// KF-05 — read + report the per-channel Hebbian acceptance weights. Read-only
/// consumer of `memory::channel_weights` (the serve.rs reply path writes them).
fn run_channel_weights(home: Option<PathBuf>, output: OutputFormat) {
    use std::collections::BTreeMap;
    let home = home.unwrap_or_else(crate::config::FreedomConfig::default_neoth_home);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let weights = crate::memory::channel_weights::load_channel_weights(&home);

    // Aggregate per channel: topic-row count + the strongest decayed weight.
    let mut by_channel: BTreeMap<String, (usize, f32)> = BTreeMap::new();
    for row in &weights.rows {
        let w =
            crate::memory::channel_weights::channel_weight_of(&weights, &row.channel, row.topic_hash, now);
        let e = by_channel.entry(row.channel.clone()).or_insert((0, 0.0));
        e.0 += 1;
        if w > e.1 {
            e.1 = w;
        }
    }

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let rows: Vec<_> = by_channel
                .iter()
                .map(|(ch, (topics, max_w))| {
                    serde_json::json!({ "channel": ch, "topics": topics, "max_familiarity": max_w })
                })
                .collect();
            println!("{}", serde_json::json!({ "channels": rows }));
        }
        OutputFormat::Table => {
            if by_channel.is_empty() {
                println!("(no channel-acceptance history yet — it accrues as channels get replies)");
                return;
            }
            println!("per-channel acceptance familiarity (KF-05):");
            for (ch, (topics, max_w)) in &by_channel {
                println!("  {ch}: {topics} topic(s), strongest familiarity {max_w:.2}");
            }
        }
    }
}

/// P1-6 — render the Ecology maturity matrix. `scheduler_enabled` is the live
/// `ecology.enabled` state (the only surface with a runtime toggle).
fn run_status(scheduler_enabled: bool, output: OutputFormat) {
    let surfaces = ecology_surfaces();
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let rows: Vec<_> = surfaces
                .iter()
                .map(|s| {
                    let mut row = serde_json::json!({
                        "surface": s.name,
                        "maturity": s.maturity,
                        "access": s.access,
                        "note": s.note,
                    });
                    if s.name == "scheduler" {
                        row["enabled"] = serde_json::json!(scheduler_enabled);
                    }
                    row
                })
                .collect();
            println!(
                "{}",
                serde_json::json!({
                    "layer": "ecology (CH-13)",
                    "headline": "NOT stable self-improvement — review-gated scheduler + read-only diagnostics",
                    "surfaces": rows,
                })
            );
        }
        OutputFormat::Table => {
            println!("Ecology layer (CH-13) — maturity matrix");
            println!("  (NOT stable self-improvement: read-only diagnostics + a review-gated scheduler)");
            for s in &surfaces {
                let state = if s.name == "scheduler" {
                    if scheduler_enabled {
                        "  [enabled]"
                    } else {
                        "  [disabled]"
                    }
                } else {
                    ""
                };
                println!(
                    "  {:<16} {:<13} {:<13}{}  — {}",
                    s.name, s.maturity, s.access, state, s.note
                );
            }
        }
    }
}

/// F4-01 Phase 3 — build + render the tool genealogy. Read-only: loads the
/// installed-skill inventory + walks the WAL for tool-activity frames, then
/// reports a use-count-ranked node list. Changes nothing.
async fn run_genealogy(
    wal_dir: Option<PathBuf>,
    home: Option<PathBuf>,
    top: Option<usize>,
    output: OutputFormat,
) {
    let wal_dir = wal_dir.unwrap_or_else(FreedomConfig::default_wal_dir);
    let home = home.unwrap_or_else(FreedomConfig::default_neoth_home);
    let skills_dir = home.join("skills");

    // Installed-skill ids (best-effort — a missing/empty skills dir just yields
    // no skill nodes; the WAL-derived tool nodes still report).
    let skill_ids: Vec<String> = match crate::skills::load_all(&skills_dir).await {
        Ok(skills) => skills.iter().map(|s| s.id().to_string()).collect(),
        Err(_) => Vec::new(),
    };

    let genealogy = crate::ecology::genealogy::build_tool_genealogy(&wal_dir, &skill_ids);
    let shown: Vec<&crate::ecology::genealogy::ToolNode> = match top {
        Some(n) => genealogy.top_tools(n),
        None => genealogy.top_tools(genealogy.nodes.len()),
    };

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let rows: Vec<_> = shown
                .iter()
                .map(|n| {
                    serde_json::json!({
                        "tool_id": n.tool_id,
                        "kind": n.kind.as_str(),
                        "use_count": n.use_count,
                        "last_used_unix": n.last_used_unix,
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::json!({
                    "total_tools": genealogy.nodes.len(),
                    "tools": rows,
                })
            );
        }
        OutputFormat::Table => {
            if genealogy.nodes.is_empty() {
                println!(
                    "(no tools recorded yet — install a skill/plugin or invoke an MCP tool)"
                );
                return;
            }
            println!(
                "tool genealogy — {} tool(s) (use-count = recorded MCP calls / plugin hostcalls; \
                 skills show 0 because injection is not WAL-traced):",
                genealogy.nodes.len()
            );
            for n in &shown {
                println!(
                    "  [{}] {} — {} use(s)",
                    n.kind.as_str(),
                    n.tool_id,
                    n.use_count
                );
            }
        }
    }
}

/// F4-01 — build + render the council winner-chain. Read-only: walks the `0x63`
/// winner frames + aggregates the in-frame provider/role/score/mode fields into
/// a win-distribution. Changes nothing.
fn run_winner_chain(wal_dir: Option<PathBuf>, top: Option<usize>, output: OutputFormat) {
    let wal_dir = wal_dir.unwrap_or_else(FreedomConfig::default_wal_dir);
    let records = scan_winner_records(&wal_dir);
    let chain = build_winner_chain(&records);
    let shown: Vec<_> = match top {
        Some(n) => chain.stats.iter().take(n).collect(),
        None => chain.stats.iter().collect(),
    };

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let rows: Vec<_> = shown
                .iter()
                .map(|s| {
                    serde_json::json!({
                        "provider": s.provider,
                        "role": s.role,
                        "wins": s.wins,
                        "win_share": s.win_share,
                        "avg_score": s.avg_score,
                        "last_score": s.last_score,
                    })
                })
                .collect();
            let modes: Vec<_> = chain
                .by_mode
                .iter()
                .map(|(m, n)| serde_json::json!({ "mode": m, "wins": n }))
                .collect();
            println!(
                "{}",
                serde_json::json!({
                    "total_debates": chain.total_debates,
                    "winners": rows,
                    "by_mode": modes,
                })
            );
        }
        OutputFormat::Table => {
            if chain.total_debates == 0 {
                println!(
                    "(no council winners recorded yet — the winner-chain accrues as councils run)"
                );
                return;
            }
            println!(
                "council winner-chain — {} outer-council debate(s) scanned:",
                chain.total_debates
            );
            for s in &shown {
                println!(
                    "  {} [{}] — {} win(s), {:.0}% share, avg score {:.2} (last {:.2})",
                    s.provider,
                    s.role,
                    s.wins,
                    s.win_share * 100.0,
                    s.avg_score,
                    s.last_score
                );
            }
            if !chain.by_mode.is_empty() {
                let modes: Vec<String> = chain
                    .by_mode
                    .iter()
                    .map(|(m, n)| format!("{m}×{n}"))
                    .collect();
                println!("  selection-mode mix: {}", modes.join(", "));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maturity_matrix_is_honest() {
        let s = ecology_surfaces();
        assert_eq!(s.len(), 5);
        // The diagnostics are beta + read-only.
        for name in ["correlation", "winner-chain", "genealogy", "channel-weights"] {
            let row = s.iter().find(|r| r.name == name).unwrap();
            assert_eq!(row.maturity, "beta");
            assert_eq!(row.access, "read-only");
        }
        // The scheduler is explicitly experimental + review-gated — never
        // labelled "stable self-improvement".
        let sched = s.iter().find(|r| r.name == "scheduler").unwrap();
        assert_eq!(sched.maturity, "experimental");
        assert_eq!(sched.access, "review-gated");
        assert!(sched.note.contains("NEVER auto-applies"));
    }
}
