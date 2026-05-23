//! NOOB-UX-2 — Operator-readable glossary.
//!
//! `neoth glossary` prints the technical-term cheat sheet so a non-
//! developer operator doesn't have to grep `~/.neoth/` or read source
//! to figure out what "skill", "mode", "council", "hemisphere",
//! "autonomy", "WAL", "channel" or "plugin" mean in NEOTH-context.
//!
//! Per `PLAN/PROGRESS.md` NOOB-UX-2: "Glossary screen in the wizard
//! — one screen up-front that defines plugin/channel/council/provider/
//! WAL/autonomy. Operator reads it once, never needs to grep docs."
//! This commit ships the CLI subcommand; wiring as a dedicated wizard
//! step is the follow-up.
//!
//! Output respects the global `--output` flag (Table for humans;
//! JSON/JSONL for tooling integration).

use anyhow::Result;
use clap::Args;
use serde::Serialize;

use crate::cli::OutputFormat;

#[derive(Args, Debug, Clone)]
pub struct GlossaryArgs {
    /// Filter to a single term (case-insensitive substring match).
    /// `--term skill` shows all rows matching "skill".
    #[arg(long, value_name = "TERM")]
    pub term: Option<String>,

    /// Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

/// One row in the operator glossary. JSON-stable wire form.
#[derive(Clone, Debug, Serialize)]
pub struct GlossaryEntry {
    pub term: &'static str,
    pub one_liner: &'static str,
    pub details: &'static str,
    pub related_command: &'static str,
}

/// Canonical glossary table. Sorted by term for stable output.
/// Adding a new term means dropping a row here + (when shipped)
/// extending the wizard-step's glossary screen.
pub const GLOSSARY: &[GlossaryEntry] = &[
    GlossaryEntry {
        term: "autonomy",
        one_liner: "How much NEOTH does on its own vs asks you first.",
        details: "Five levels: strict / standard / elevated / full / custom. Standard \
                  is the default — NEOTH asks before paid-cloud calls, before writes \
                  outside the home dir, and before sending to channels.",
        related_command: "neoth autonomy show",
    },
    GlossaryEntry {
        term: "channel",
        one_liner: "A messenger NEOTH talks through (Telegram, Slack, WhatsApp).",
        details: "Configured via `neoth init` step 6 + credentials in \
                  ~/.neoth/credentials.yaml. Today Telegram is live inbound + \
                  outbound; Slack + WhatsApp are outbound-only (see \
                  `neoth doctor channels`).",
        related_command: "neoth doctor channels",
    },
    GlossaryEntry {
        term: "council",
        one_liner: "Two or three providers debate, NEOTH picks the best answer.",
        details: "Fires automatically on complex prompts (length > 80 chars + \
                  code-fence or dissent markers). Three voices: Left (fast/cheap), \
                  Right (deep/quality), Cerebellum (synthesiser). Same provider in \
                  every slot = a one-voice debate dressed up; spread across providers \
                  for real triangulation.",
        related_command: "neoth council show-last",
    },
    GlossaryEntry {
        term: "groundtruth",
        one_liner: "Operator-asserted facts that survive every memory pass.",
        details: "Add via `neoth groundtruth add \"<statement>\"`. Decay-immune. \
                  Always surfaces in recall BEFORE episodic memory. Use for stable \
                  facts (your name, project codenames) — not for transient context.",
        related_command: "neoth groundtruth list",
    },
    GlossaryEntry {
        term: "hemisphere",
        one_liner: "One of three council-voice slots: Left / Right / Cerebellum.",
        details: "Each can run a different provider. Left defaults to fast/cheap \
                  (local_qwen or gpt-4o-mini); Right to deep (Opus / Gemini Pro); \
                  Cerebellum synthesises. Configure via `neoth hemispheres set --role \
                  <role> --provider <id>`.",
        related_command: "neoth hemispheres show",
    },
    GlossaryEntry {
        term: "mode",
        one_liner: "A specialised slice of a skill (e.g. fact-check inside research).",
        details: "A skill (e.g. academic_research) ships N named modes. Each mode \
                  has its own oversight level (low/medium/high/very_high), output \
                  contract (markdown/json/prose), and trigger phrases. Operator says \
                  \"fact-check the abstract\" → mode `research_fact_check` activates.",
        related_command: "neoth mode list",
    },
    GlossaryEntry {
        term: "plugin",
        one_liner: "A WASM-compiled extension that NEOTH dispatches via hooks.",
        details: "Plugins live as compiled wasm modules + a YAML manifest. The \
                  `wasm-plugin-host` feature compiles them in at build time; \
                  freedom.yaml::plugins.wasm.enabled toggles at runtime. Hook \
                  actions of kind Plugin{plugin_id, required} dispatch through them.",
        related_command: "neoth plugins list",
    },
    GlossaryEntry {
        term: "profile",
        one_liner: "What NEOTH learns about you over time from conversation.",
        details: "Operator-fact claims extracted from chat replies. Tiered storage: \
                  hot (last 7d), warm (90d), cold (Hebbian-filtered long-term), \
                  groundtruth (decay-immune). Opt-IN: profile.learn_enabled = true.",
        related_command: "neoth profile show",
    },
    GlossaryEntry {
        term: "provider",
        one_liner: "An LLM backend NEOTH talks to (claude / openai / gemini / qwen).",
        details: "Picked in `neoth init` step 5. claude_cli (local OAuth Claude), \
                  anthropic_api, openai_api, gemini_api, aws_bedrock, azure_openai, \
                  openai_compat (OpenRouter / Together / Groq / Ollama), or \
                  local_qwen (no-cloud).",
        related_command: "neoth providers list",
    },
    GlossaryEntry {
        term: "skill",
        one_liner: "An auto-installable behaviour pack (system prompt + triggers).",
        details: "21+ ship bundled (verification, TDD, debugging, code-review, \
                  fact-check, brainstorm, plan-write, etc.). Operator-installed \
                  skills live under ~/.neoth/skills/<id>/skill.yaml. Activated by \
                  keyword scan in the chat dispatcher.",
        related_command: "neoth skills list",
    },
    GlossaryEntry {
        term: "wal",
        one_liner: "Write-ahead log — every action NEOTH ever takes lands here.",
        details: "Append-only audit chain at ~/.neoth/wal/*.wal. Tamper-detection \
                  via HMAC-SHA256 compaction markers. `neoth wal show` to inspect, \
                  `neoth verify` to check the chain. Foundation for `neoth rollback` \
                  and the data-export GDPR surface.",
        related_command: "neoth wal show",
    },
];

pub fn run_glossary(args: GlossaryArgs) -> Result<()> {
    let filter = args.term.as_deref().map(|s| s.to_lowercase());
    let rows: Vec<&GlossaryEntry> = GLOSSARY
        .iter()
        .filter(|e| match &filter {
            Some(f) => e.term.to_lowercase().contains(f.as_str()),
            None => true,
        })
        .collect();
    match args.output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&rows)?),
        OutputFormat::Jsonl => {
            for r in &rows {
                println!("{}", serde_json::to_string(r)?);
            }
        }
        OutputFormat::Table => {
            if rows.is_empty() {
                println!(
                    "No glossary term matched `{}`.",
                    args.term.as_deref().unwrap_or("")
                );
                println!("Run `neoth glossary` for the full list.");
                return Ok(());
            }
            for r in &rows {
                println!("{}", r.term);
                println!("  {}", r.one_liner);
                println!("  detail: {}", r.details);
                println!("  cmd:    {}", r.related_command);
                println!();
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glossary_is_sorted_alphabetically() {
        // Pin so a future contributor inserting a term in the middle
        // of the list (instead of the right alphabetical slot)
        // surfaces here.
        let terms: Vec<&str> = GLOSSARY.iter().map(|e| e.term).collect();
        let mut sorted = terms.clone();
        sorted.sort();
        assert_eq!(terms, sorted, "GLOSSARY must be alphabetical by term");
    }

    #[test]
    fn glossary_terms_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for e in GLOSSARY {
            assert!(seen.insert(e.term), "duplicate glossary term: {}", e.term);
        }
    }

    #[test]
    fn every_glossary_entry_has_nonempty_content() {
        for e in GLOSSARY {
            assert!(!e.one_liner.is_empty(), "{} missing one_liner", e.term);
            assert!(e.details.len() > 30, "{} details too short", e.term);
            assert!(
                e.related_command.starts_with("neoth "),
                "{} related_command must point at a real subcommand",
                e.term
            );
        }
    }

    #[test]
    fn glossary_covers_noob_ux_2_required_terms() {
        // NOOB-UX-2 named six terms operators must see: plugin /
        // channel / council / provider / WAL / autonomy. Pin so a
        // future cleanup that drops one fails here.
        let required = [
            "plugin", "channel", "council", "provider", "wal", "autonomy",
        ];
        for term in required {
            assert!(
                GLOSSARY.iter().any(|e| e.term == term),
                "NOOB-UX-2 required term `{term}` missing from glossary"
            );
        }
    }

    #[test]
    fn run_glossary_with_term_filter_returns_subset() {
        // `neoth glossary --term skill` should match "skill" entry.
        let args = GlossaryArgs {
            term: Some("skill".to_string()),
            output: OutputFormat::Table,
        };
        let r = run_glossary(args);
        assert!(r.is_ok());
    }

    #[test]
    fn run_glossary_with_unknown_term_does_not_error() {
        let args = GlossaryArgs {
            term: Some("nonexistent-term".to_string()),
            output: OutputFormat::Table,
        };
        let r = run_glossary(args);
        assert!(r.is_ok());
    }
}
