//! `neoth fact-check <claim>` — GOLD-WIRE-11.
//!
//! Exposes the pure `profile::fact_check::assess` proposition classifier as an
//! operator CLI surface. `assess` decomposes the claim into atomic sentence-
//! level propositions, classifies each (verifiable / plausible / opinion /
//! suspect) with deterministic heuristics (NO LLM call), and rolls them up into
//! a `clean` / `needs_framing` / `needs_revision` verdict.

use anyhow::Result;
use clap::Args;

use crate::cli::OutputFormat;
use crate::profile::fact_check::{Confidence, FactCheckReport, assess};

#[derive(Args, Debug, Clone)]
pub struct FactCheckArgs {
    /// The claim / statement to fact-check. Multi-sentence input decomposes to
    /// one proposition per sentence; each is classified independently.
    #[arg(value_name = "CLAIM")]
    pub claim: String,

    /// Populated from the global `--output` flag by `cli::run`.
    #[arg(skip)]
    pub output: OutputFormat,
}

pub fn run_fact_check(args: FactCheckArgs) -> Result<()> {
    let report = assess(&args.claim);
    print!("{}", render_report(&report, args.output)?);
    Ok(())
}

/// Pure render of a [`FactCheckReport`] to the operator's chosen format.
/// Factored out so the formatting is unit-testable without capturing stdout.
fn render_report(report: &FactCheckReport, output: OutputFormat) -> Result<String> {
    Ok(match output {
        OutputFormat::Json => format!("{}\n", serde_json::to_string_pretty(report)?),
        OutputFormat::Jsonl => format!("{}\n", serde_json::to_string(report)?),
        OutputFormat::Table => {
            let mut s = String::new();
            s.push_str(&format!("# fact-check verdict: {}\n", report.verdict.as_str()));
            s.push_str(&format!(
                "#   verifiable={} plausible={} opinion={} suspect={}\n",
                report.count(Confidence::Verifiable),
                report.count(Confidence::Plausible),
                report.count(Confidence::Opinion),
                report.count(Confidence::Suspect),
            ));
            if report.propositions.is_empty() {
                s.push_str("  (no propositions — the input had no sentence of >=6 chars)\n");
            }
            for p in &report.propositions {
                s.push_str(&format!("  [{:<10}] {}\n", p.confidence.as_str(), p.text));
                s.push_str(&format!("               -> {}\n", p.rationale));
            }
            s
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_fact_check_assesses_a_simple_verifiable_claim() {
        // The task's acceptance example: a concrete claim produces a report.
        let report = assess("NEOTH was released in 2026.");
        assert!(!report.propositions.is_empty());
        // A year anchor classifies the proposition as verifiable, so the whole
        // claim rolls up Clean.
        assert_eq!(report.verdict, crate::profile::fact_check::Verdict::Clean);
        // The command itself runs without error.
        run_fact_check(FactCheckArgs {
            claim: "NEOTH was released in 2026.".into(),
            output: OutputFormat::Json,
        })
        .unwrap();
    }

    #[test]
    fn render_table_shows_verdict_counts_and_each_proposition() {
        let report = assess("Everyone always agrees. It launched in 2026.");
        let out = render_report(&report, OutputFormat::Table).unwrap();
        // A suspect absolutism ("Everyone always") forces NeedsRevision.
        assert!(out.contains("needs_revision"), "got: {out}");
        assert!(out.contains("[suspect"), "got: {out}");
        assert!(out.contains("verifiable="), "got: {out}");
        // Every proposition's rationale is shown.
        assert!(out.contains("->"), "got: {out}");
    }

    #[test]
    fn render_json_roundtrips_to_the_same_report() {
        let report = assess("This seems plausible to me.");
        let json = render_report(&report, OutputFormat::Json).unwrap();
        let back: FactCheckReport = serde_json::from_str(json.trim()).unwrap();
        assert_eq!(back, report);
    }

    #[test]
    fn render_table_handles_empty_input_without_panicking() {
        let report = assess("");
        let out = render_report(&report, OutputFormat::Table).unwrap();
        assert!(out.contains("clean"), "empty input rolls up clean: {out}");
        assert!(out.contains("no propositions"), "got: {out}");
    }
}
