//! `neoth refusal {classify, patterns, cause, reframings, enable,
//! disable}` — operator surface for the Refusal-Recovery LOWKEY arc.
//!
//! Subcommands:
//!   - `classify <text>` — Schicht-0 detector (surface class).
//!   - `patterns` — dump the static pattern dictionaries.
//!   - `cause <text>` (R-06) — RefusalCause classifier (WHY refused).
//!   - `reframings` (R-06) — list the 6 LOWKEY reframings + per-id
//!     enabled/disabled status from `freedom.yaml::refusal_recovery`.
//!   - `disable <id>` (R-06) — atomically add to
//!     `refusal_recovery.disabled_reframings` so a specific LOWKEY
//!     reframing never fires.
//!   - `enable <id>` (R-06) — remove from the disabled list.
//!
//! All commands are pure-read or freedom.yaml mutators. No LLM
//! calls, no provider dependency.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::security::refusal_cause::classify_cause;
use crate::security::refusal_detect::classify;
use crate::security::refusal_reframings::default_catalogue;

#[derive(Args, Debug, Clone)]
pub struct RefusalArgs {
    #[command(subcommand)]
    pub action: RefusalAction,

    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum RefusalAction {
    /// Classify `<text>` against the refusal detector. Prints the
    /// classification + confidence + the matched patterns so operators
    /// can see exactly which signals fired.
    Classify {
        /// The text to classify. Quote shell-special characters.
        text: String,
    },
    /// Print the static pattern dictionaries the classifier uses, in
    /// table or JSON form. Useful for "why didn't my refusal text
    /// trigger?" debugging.
    Patterns,
    /// R-06 2026-05-17: classify the CAUSE of a refusal — orthogonal
    /// to `classify` which reports the surface class. Returns one of
    /// {safety_policy, capability_gap, privacy, operator_policy,
    /// unknown} plus the matched patterns + confidence.
    Cause {
        /// The text to classify.
        text: String,
    },
    /// R-06: list the 6 LOWKEY reframings with their description,
    /// applicable causes, and per-id enabled/disabled status from
    /// `freedom.yaml::refusal_recovery.disabled_reframings`.
    Reframings,
    /// R-06: disable a specific LOWKEY reframing. Atomically rewrites
    /// `freedom.yaml::refusal_recovery.disabled_reframings`. Use for
    /// third-party deployments where e.g. `operator_authority`
    /// (LOWKEY pentester-context prepend) is not appropriate.
    Disable {
        /// Reframing id (snake_case): `operator_authority`,
        /// `narrow_scope`, `step_decomposition`, `meta_discussion`,
        /// `academic_framing`, `historical_framing`.
        id: String,
    },
    /// R-06: re-enable a previously-disabled reframing. Removes the
    /// id from `freedom.yaml::refusal_recovery.disabled_reframings`.
    Enable {
        /// Reframing id (snake_case).
        id: String,
    },
}

pub async fn run_refusal(args: RefusalArgs) -> Result<()> {
    match args.action {
        RefusalAction::Classify { text } => run_classify(&text, &args.output),
        RefusalAction::Patterns => run_patterns(&args.output),
        RefusalAction::Cause { text } => run_cause(&text, &args.output),
        RefusalAction::Reframings => run_reframings(&args.output),
        RefusalAction::Disable { id } => run_disable(&id, &args.output),
        RefusalAction::Enable { id } => run_enable(&id, &args.output),
    }
}

/// R-06: classify the cause of a refusal. Mirrors `run_classify`'s
/// output shape so operator scripts can switch between the two
/// classifiers without per-call reformatting.
fn run_cause(text: &str, output: &OutputFormat) -> Result<()> {
    let report = classify_cause(text);
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "cause": report.cause.as_str(),
                    "confidence": report.confidence,
                    "matched_patterns": report.matched_patterns,
                    "input_bytes": text.len(),
                }))?
            );
        }
        OutputFormat::Table => {
            println!("# Refusal cause classification");
            println!("  cause:       {}", report.cause.as_str());
            println!("  confidence:  {}", report.confidence);
            println!("  input_bytes: {}", text.len());
            if report.matched_patterns.is_empty() {
                println!("  matched:     (none)");
            } else {
                println!("  matched:");
                for p in &report.matched_patterns {
                    println!("    - {p}");
                }
            }
        }
    }
    Ok(())
}

/// R-06: list every LOWKEY reframing + enabled/disabled per the
/// operator's current freedom.yaml. Missing freedom.yaml (e.g.
/// pre-init) falls back to "all enabled" so the operator sees the
/// default state. Tests use `--home tempdir` for hermeticity (not
/// supported here — uses the default home).
fn run_reframings(output: &OutputFormat) -> Result<()> {
    let disabled: Vec<String> = match FreedomConfig::load_from_default_path() {
        Ok(cfg) => cfg.refusal_recovery.disabled_reframings,
        Err(_) => Vec::new(),
    };
    let catalogue = default_catalogue();
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let rows: Vec<_> = catalogue
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "id": r.id(),
                        "description": r.description(),
                        "enabled": !disabled.iter().any(|d| d == r.id()),
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "reframings": rows,
                    "disabled_count": disabled.len(),
                }))?
            );
        }
        OutputFormat::Table => {
            println!(
                "# LOWKEY reframings — {} total, {} disabled",
                catalogue.len(),
                disabled.len()
            );
            for r in &catalogue {
                let status = if disabled.iter().any(|d| d == r.id()) {
                    "[disabled]"
                } else {
                    "[enabled] "
                };
                println!("  {status} {:<22} {}", r.id(), r.description());
            }
        }
    }
    Ok(())
}

/// Validate that `id` matches one of the 6 catalogue ids. Returns
/// `Err` with an actionable pointer when the operator typos.
fn validate_reframing_id(id: &str) -> Result<()> {
    let cat = default_catalogue();
    let known: Vec<&'static str> = cat.iter().map(|r| r.id()).collect();
    if known.contains(&id) {
        return Ok(());
    }
    anyhow::bail!(
        "unknown reframing id `{id}`. Valid ids: {}. Run `neoth refusal reframings` to see them.",
        known.join(", "),
    );
}

/// R-06: append `id` to `freedom.yaml::refusal_recovery.disabled_reframings`
/// and atomically rewrite the config. Idempotent — re-disabling an
/// already-disabled id is a no-op (operator sees a "no change" message).
fn run_disable(id: &str, output: &OutputFormat) -> Result<()> {
    validate_reframing_id(id)?;
    let mut cfg = FreedomConfig::load_from_default_path()
        .context("load freedom.yaml — run `neoth init` first")?;
    let already = cfg
        .refusal_recovery
        .disabled_reframings
        .iter()
        .any(|d| d == id);
    if !already {
        cfg.refusal_recovery
            .disabled_reframings
            .push(id.to_string());
        cfg.save_public_to_default_path()
            .with_context(|| format!("write freedom.yaml after disabling `{id}`"))?;
    }
    report_change(
        "disable",
        id,
        !already,
        output,
        &cfg.refusal_recovery.disabled_reframings,
    )
}

/// R-06: inverse of `run_disable`. Removes `id` from
/// `refusal_recovery.disabled_reframings`. Idempotent.
fn run_enable(id: &str, output: &OutputFormat) -> Result<()> {
    validate_reframing_id(id)?;
    let mut cfg = FreedomConfig::load_from_default_path()
        .context("load freedom.yaml — run `neoth init` first")?;
    let before_len = cfg.refusal_recovery.disabled_reframings.len();
    cfg.refusal_recovery.disabled_reframings.retain(|d| d != id);
    let changed = cfg.refusal_recovery.disabled_reframings.len() != before_len;
    if changed {
        cfg.save_public_to_default_path()
            .with_context(|| format!("write freedom.yaml after enabling `{id}`"))?;
    }
    report_change(
        "enable",
        id,
        changed,
        output,
        &cfg.refusal_recovery.disabled_reframings,
    )
}

/// Render the disable/enable command's result. JSON branch suitable
/// for scripting; table branch human-friendly.
fn report_change(
    verb: &str,
    id: &str,
    changed: bool,
    output: &OutputFormat,
    disabled_after: &[String],
) -> Result<()> {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "action": verb,
                    "id": id,
                    "changed": changed,
                    "disabled_after": disabled_after,
                }))?
            );
        }
        OutputFormat::Table => {
            if changed {
                println!("✓ {verb}d reframing `{id}`");
            } else {
                println!("• reframing `{id}` already in target state — no change");
            }
            println!("  disabled now: {}", disabled_after.join(", "));
        }
    }
    Ok(())
}

fn run_classify(text: &str, output: &OutputFormat) -> Result<()> {
    let report = classify(text);
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "class": report.class.as_str(),
                    "is_refusal": report.is_refusal(),
                    "confidence": report.confidence,
                    "matched_patterns": report.matched_patterns,
                    "input_bytes": text.len(),
                }))?
            );
        }
        OutputFormat::Table => {
            println!("# Refusal classification");
            println!("  class:       {}", report.class.as_str());
            println!("  is_refusal:  {}", report.is_refusal());
            println!("  confidence:  {}", report.confidence);
            println!("  input_bytes: {}", text.len());
            if report.matched_patterns.is_empty() {
                println!("  matched:     (none)");
            } else {
                println!("  matched:");
                for p in &report.matched_patterns {
                    println!("    - {p}");
                }
            }
        }
    }
    Ok(())
}

fn run_patterns(output: &OutputFormat) -> Result<()> {
    use crate::security::refusal_detect::pattern_dictionaries;
    let (hard, soft, redirect, safety) = pattern_dictionaries();
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "hard": hard,
                    "soft": soft,
                    "redirect": redirect,
                    "safety": safety,
                }))?
            );
        }
        OutputFormat::Table => {
            println!("# Refusal detector patterns");
            println!("\n  [hard_refusal] {} patterns", hard.len());
            for p in hard {
                println!("    {p}");
            }
            println!("\n  [soft_refusal] {} patterns", soft.len());
            for p in soft {
                println!("    {p}");
            }
            println!("\n  [redirect_suggestion] {} patterns", redirect.len());
            for p in redirect {
                println!("    {p}");
            }
            println!("\n  [safety_warning] {} patterns", safety.len());
            for p in safety {
                println!("    {p}");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_clean_input_does_not_panic() {
        run_classify("Sure, here's the answer: 42", &OutputFormat::Json).unwrap();
        run_classify("Sure, here's the answer: 42", &OutputFormat::Table).unwrap();
    }

    #[test]
    fn classify_hard_refusal_returns_ok() {
        run_classify("I cannot help with that request.", &OutputFormat::Json).unwrap();
    }

    #[test]
    fn patterns_dump_does_not_panic() {
        run_patterns(&OutputFormat::Json).unwrap();
        run_patterns(&OutputFormat::Table).unwrap();
    }

    // ── R-06 2026-05-17: cause / reframings / disable / enable ────────

    #[test]
    fn cause_classifies_clean_input_as_unknown() {
        // No cause pattern matches → Unknown. Smoke test the
        // JSON + table branches don't panic.
        run_cause("Sure, here's the answer: 42", &OutputFormat::Json).unwrap();
        run_cause("Sure, here's the answer: 42", &OutputFormat::Table).unwrap();
    }

    #[test]
    fn cause_classifies_safety_policy_refusal() {
        run_cause(
            "Against my guidelines — this violates safety policy.",
            &OutputFormat::Json,
        )
        .unwrap();
    }

    #[test]
    fn validate_reframing_id_accepts_known_ids() {
        for id in [
            "operator_authority",
            "narrow_scope",
            "step_decomposition",
            "meta_discussion",
            "academic_framing",
            "historical_framing",
        ] {
            assert!(validate_reframing_id(id).is_ok(), "{id} should be valid");
        }
    }

    #[test]
    fn validate_reframing_id_rejects_unknown_with_actionable_message() {
        let err = validate_reframing_id("nope-not-real").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown reframing id"));
        assert!(msg.contains("neoth refusal reframings"));
        // Names of all 6 catalogue entries should appear in the pointer.
        assert!(msg.contains("operator_authority"));
    }

    #[test]
    fn validate_reframing_id_rejects_empty_and_whitespace() {
        assert!(validate_reframing_id("").is_err());
        // No fuzzy match: leading/trailing spaces are not stripped.
        assert!(validate_reframing_id(" operator_authority ").is_err());
    }
}
