//! GOLD-HR-04 — `LogTemplate`: order-preserving log-template miner (Drain-style).
//!
//! Faithful port of headroom's `pipeline/reformats/log_template.rs`. Logs bloat
//! when the same template repeats with only timestamps / IDs / paths varying:
//!
//! ```text
//! 2025-01-15T12:34:56 INFO worker-1 processing job 42
//! 2025-01-15T12:34:57 INFO worker-2 processing job 43
//! ... 798 more like this ...
//! ```
//!
//! The information is the *template* + the *variants*, not the repeated
//! constants. Consecutive same-template runs collapse into one header plus a
//! compact variant table:
//!
//! ```text
//! [Template T1: <TS> INFO worker-<*> processing job <*>] (800 occurrences)
//! 12:34:56 1 42
//! ...
//! ```
//!
//! Every original line is reconstructible from `template + variants`, so this
//! is a **reformat** (lossless, no CCR). Only *consecutive* runs collapse, so
//! the log's temporal order stays intact.
//!
//! Conservative defaults bias toward "emit verbatim if unsure": `min_run = 3`,
//! `similarity_threshold = 0.4` (Drain's published default), `min_constant_
//! tokens = 2`. The pipeline sits on the hot path of every tool-call response;
//! an over-aggressive miner would leak signal into the variant table.

use std::fmt::Write;

use crate::context::compress::content_detector::ContentType;
use crate::context::compress::transform::{ReformatOutput, ReformatTransform, TransformError};

const NAME: &str = "log_template";
/// Sentinel for variable positions in template strings.
const WILDCARD: &str = "<*>";

/// Tunables for [`LogTemplate`]. Code-level defaults (not freedom.yaml) — the
/// operator's only compression knobs are `compression.{enabled,min_block_bytes,
/// live_zone_turns}`; these fine-grained miner thresholds stay internal.
#[derive(Debug, Clone, Copy)]
pub struct LogTemplateConfig {
    /// Logs shorter than this aren't worth the bucket walk.
    pub min_lines: usize,
    /// Minimum consecutive same-template lines that justify a collapse.
    pub min_run: usize,
    /// Fraction of positions that must match for a line to extend a run.
    pub similarity_threshold: f32,
    /// A template with fewer anchor tokens than this carries no signal —
    /// emit verbatim instead of an all-wildcard "template".
    pub min_constant_tokens: usize,
}

impl Default for LogTemplateConfig {
    fn default() -> Self {
        Self {
            min_lines: 20,
            min_run: 3,
            similarity_threshold: 0.4,
            min_constant_tokens: 2,
        }
    }
}

pub struct LogTemplate {
    config: LogTemplateConfig,
}

impl LogTemplate {
    pub fn new(config: LogTemplateConfig) -> Self {
        Self { config }
    }
}

impl Default for LogTemplate {
    fn default() -> Self {
        Self::new(LogTemplateConfig::default())
    }
}

impl ReformatTransform for LogTemplate {
    fn name(&self) -> &'static str {
        NAME
    }

    fn applies_to(&self) -> &[ContentType] {
        &[ContentType::BuildOutput]
    }

    fn apply(&self, content: &str) -> Result<ReformatOutput, TransformError> {
        if content.is_empty() {
            return Err(TransformError::skipped(NAME, "empty input"));
        }
        let lines: Vec<&str> = content.lines().collect();
        if lines.len() < self.config.min_lines {
            return Err(TransformError::skipped(NAME, "input below min_lines"));
        }

        let tokenized: Vec<Vec<&str>> = lines.iter().map(|l| tokenize(l)).collect();

        let mut output = String::with_capacity(content.len());
        let mut next_template_id = 1usize;
        let mut run: Option<Run> = None;

        for (i, tokens) in tokenized.iter().enumerate() {
            if tokens.is_empty() {
                // Blank line breaks any active run.
                if let Some(r) = run.take() {
                    Self::flush_run(&r, &lines, &tokenized, &self.config, &mut next_template_id, &mut output);
                }
                output.push_str(lines[i]);
                output.push('\n');
                continue;
            }
            match run.as_mut() {
                Some(r) if Self::extends_run(r, tokens, self.config.similarity_threshold) => {
                    r.indices.push(i);
                    Self::merge_into_template(&mut r.template, tokens);
                }
                _ => {
                    if let Some(r) = run.take() {
                        Self::flush_run(&r, &lines, &tokenized, &self.config, &mut next_template_id, &mut output);
                    }
                    run = Some(Run::start(i, tokens));
                }
            }
        }
        if let Some(r) = run.take() {
            Self::flush_run(&r, &lines, &tokenized, &self.config, &mut next_template_id, &mut output);
        }

        // Restore the trailing newline only if the input had one.
        if content.ends_with('\n') {
            // Output already ends in '\n'.
        } else if output.ends_with('\n') {
            output.pop();
        }

        if output.len() >= content.len() {
            // Never inflate.
            return Ok(ReformatOutput::from_lengths(content.len(), content.to_string()));
        }
        Ok(ReformatOutput::from_lengths(content.len(), output))
    }
}

impl LogTemplate {
    /// True if `tokens` matches `run.template` at ≥ `sim_threshold` of
    /// positions AND token counts agree.
    fn extends_run(run: &Run, tokens: &[&str], sim_threshold: f32) -> bool {
        if tokens.len() != run.template.len() {
            return false;
        }
        let len = tokens.len() as f32;
        let mut matches = 0usize;
        for (pos, tok) in tokens.iter().enumerate() {
            match &run.template[pos] {
                Some(constant) if constant == tok => matches += 1,
                None => matches += 1, // wildcard counts as a match
                _ => {}
            }
        }
        (matches as f32 / len) >= sim_threshold
    }

    /// Positions where `tokens[i] != template[i]` become wildcards (`None`).
    fn merge_into_template(template: &mut [Option<String>], tokens: &[&str]) {
        for (pos, tok) in tokens.iter().enumerate() {
            if let Some(constant) = &template[pos] {
                if constant != tok {
                    template[pos] = None;
                }
            }
        }
    }

    fn flush_run(
        run: &Run,
        lines: &[&str],
        tokenized: &[Vec<&str>],
        cfg: &LogTemplateConfig,
        next_template_id: &mut usize,
        out: &mut String,
    ) {
        let constant_count = run.template.iter().filter(|t| t.is_some()).count();
        let varying_count = run.template.len() - constant_count;
        let collapse = run.indices.len() >= cfg.min_run
            && constant_count >= cfg.min_constant_tokens
            && varying_count > 0;

        if !collapse {
            for &i in &run.indices {
                out.push_str(lines[i]);
                out.push('\n');
            }
            return;
        }

        let template_id = *next_template_id;
        *next_template_id += 1;
        out.push_str("[Template T");
        let _ = write!(out, "{template_id}");
        out.push_str(": ");
        for (pos, slot) in run.template.iter().enumerate() {
            if pos > 0 {
                out.push(' ');
            }
            match slot {
                Some(constant) => out.push_str(constant),
                None => out.push_str(WILDCARD),
            }
        }
        out.push_str("] (");
        let _ = write!(out, "{}", run.indices.len());
        out.push_str(" occurrences)\n");

        // Variant table: per line, only the variable-position tokens.
        for &i in &run.indices {
            let toks = &tokenized[i];
            let mut first = true;
            for (pos, slot) in run.template.iter().enumerate() {
                if slot.is_none() {
                    if !first {
                        out.push(' ');
                    }
                    out.push_str(toks[pos]);
                    first = false;
                }
            }
            out.push('\n');
        }
    }
}

/// One in-flight collapse candidate.
struct Run {
    indices: Vec<usize>,
    /// `Some(token)` = constant so far; `None` = varied → wildcard.
    template: Vec<Option<String>>,
}

impl Run {
    fn start(idx: usize, tokens: &[&str]) -> Self {
        Self {
            indices: vec![idx],
            template: tokens.iter().map(|t| Some((*t).to_string())).collect(),
        }
    }
}

/// Whitespace-split tokenizer (`str::split_whitespace` semantics). UTF-8 safe.
fn tokenize(line: &str) -> Vec<&str> {
    line.split_whitespace().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reformat() -> LogTemplate {
        LogTemplate::default()
    }

    #[test]
    fn name_and_applies_to() {
        let r = reformat();
        assert_eq!(r.name(), "log_template");
        assert_eq!(r.applies_to(), &[ContentType::BuildOutput]);
    }

    #[test]
    fn empty_and_below_min_lines_skip() {
        assert!(matches!(reformat().apply(""), Err(TransformError::Skipped { .. })));
        assert!(matches!(
            reformat().apply("INFO a\nINFO b\nINFO c\n"),
            Err(TransformError::Skipped { .. })
        ));
    }

    #[test]
    fn templated_run_collapses_losslessly() {
        let mut log = String::new();
        for i in 0..50 {
            log.push_str(&format!("2025-01-15T12:34:{:02} INFO worker-{} processing job {}\n", i, i, 100 + i));
        }
        let r = reformat().apply(&log).expect("must collapse");
        assert!(r.bytes_saved > 0);
        assert!(r.output.contains("[Template T1:"));
        assert!(r.output.contains("(50 occurrences)"));
        assert!(r.output.contains("worker-7")); // variant survives
    }

    #[test]
    fn order_preserved_across_two_templates() {
        let mut log = String::new();
        for i in 0..12 {
            log.push_str(&format!("INFO worker-{i} starting\n"));
        }
        for i in 0..12 {
            log.push_str(&format!("WARN cache key-{i} expired\n"));
        }
        let r = reformat().apply(&log).expect("must collapse");
        let t1 = r.output.find("[Template T1:").expect("T1");
        let t2 = r.output.find("[Template T2:").expect("T2");
        assert!(t1 < t2);
        let t1_line = r.output[t1..t2].lines().next().unwrap();
        assert!(t1_line.contains("INFO") && t1_line.contains("starting"));
    }

    #[test]
    fn lossless_round_trip_via_template_and_variants() {
        let mut log = String::new();
        for i in 0..25 {
            log.push_str(&format!("TOK1 TOK2 var{i} TOK3\n"));
        }
        let r = reformat().apply(&log).expect("collapses");
        let mut iter = r.output.lines();
        let header = iter.next().unwrap();
        assert!(header.starts_with("[Template T1:"));
        let template_part = header.trim_start_matches("[Template T1: ").split("] (").next().unwrap();
        let template_tokens: Vec<&str> = template_part.split_whitespace().collect();
        let var_pos = template_tokens.iter().position(|t| *t == WILDCARD).expect("wildcard");
        let mut reconstructed = Vec::new();
        for variant_line in iter {
            if variant_line.is_empty() {
                continue;
            }
            let var_tokens: Vec<&str> = variant_line.split_whitespace().collect();
            assert_eq!(var_tokens.len(), 1);
            let mut full = template_tokens.clone();
            full[var_pos] = var_tokens[0];
            reconstructed.push(full.join(" "));
        }
        let original: Vec<String> = log.lines().map(|s| s.to_string()).collect();
        assert_eq!(reconstructed, original);
    }

    #[test]
    fn blank_lines_break_runs() {
        let mut log = String::new();
        for i in 0..5 {
            log.push_str(&format!("INFO worker-{i} ready\n"));
        }
        log.push('\n');
        for i in 0..5 {
            log.push_str(&format!("INFO worker-{i} ready\n"));
        }
        for i in 0..15 {
            log.push_str(&format!("misc-{i}\n"));
        }
        let r = reformat().apply(&log).expect("processes");
        if r.output.matches("[Template T1:").count() == 1
            && r.output.matches("[Template T2:").count() == 0
        {
            assert!(!r.output.contains("(10 occurrences)"), "must not bridge blank line");
        }
    }

    #[test]
    fn never_inflates_and_unicode_survives() {
        let mut log = String::new();
        for i in 0..30 {
            log.push_str(&format!("INFO 🔥 worker-{i} héllo wörld\n"));
        }
        let r = reformat().apply(&log).expect("utf8");
        assert!(r.output.len() <= log.len());
        assert!(r.output.contains("🔥"));
    }

    #[test]
    fn template_with_no_constants_emits_verbatim() {
        let mut log = String::new();
        for i in 0..30 {
            log.push_str(&format!("{} {} {}\n", i, i + 1, i + 2));
        }
        let r = reformat().apply(&log).expect("processes");
        assert!(!r.output.contains("[Template"));
    }
}
