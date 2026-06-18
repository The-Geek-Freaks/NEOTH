//! ARCH-05 / SPEC-08 — recall-parity goldset + grade file formats.
//!
//! The on-disk contract (JSONL) between the operator's grading run and the pure
//! [`super::parity`] scorer. A `goldset.jsonl` is the 100-query evaluation set;
//! `grades-<grader>.jsonl` files carry each grader's 0–5 Likert scores per
//! (query, system). Loading validates the Likert range fail-closed so a
//! malformed grade can't silently skew the gate.

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::parity::{Dimension, LIKERT_MAX};

/// Query category (SPEC §1) — the parity weight reflects how hard it is to pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GoldsetCategory {
    Recall,
    Summarize,
    Action,
    Factual,
}

impl GoldsetCategory {
    /// Category weight (SPEC §1): recall/action are the hard cases.
    pub fn category_weight(self) -> f64 {
        match self {
            GoldsetCategory::Recall | GoldsetCategory::Action => 1.5,
            GoldsetCategory::Summarize | GoldsetCategory::Factual => 1.0,
        }
    }
}

/// Which system a grade scored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GradedSystem {
    /// The NEOTH recall under evaluation.
    Neoth,
    /// The reference system (live Jarvis) being matched.
    Reference,
}

/// One evaluation query.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GoldsetEntry {
    pub query_id: String,
    pub query_text: String,
    pub category: GoldsetCategory,
    /// WAL event-ids / sources NEOTH SHOULD cite to answer (used by the
    /// citation-audit; informational for scoring).
    #[serde(default)]
    pub expected_sources: Vec<String>,
    #[serde(default)]
    pub expected_response: String,
}

/// One grader's 5-dimension Likert scores for one (query, system) pair.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraderGrade {
    pub query_id: String,
    pub grader_id: String,
    pub system: GradedSystem,
    pub factual: u8,
    pub completeness: u8,
    pub on_tone: u8,
    pub usefulness: u8,
    pub brevity: u8,
}

impl GraderGrade {
    /// The Likert score for a given dimension.
    pub fn score(&self, dim: Dimension) -> u8 {
        match dim {
            Dimension::Factual => self.factual,
            Dimension::Completeness => self.completeness,
            Dimension::OnTone => self.on_tone,
            Dimension::Usefulness => self.usefulness,
            Dimension::Brevity => self.brevity,
        }
    }

    /// Fail-closed Likert validation — every dimension must be 0..=5.
    pub fn validate(&self) -> Result<()> {
        for dim in Dimension::ALL {
            let s = self.score(dim);
            if s > LIKERT_MAX {
                anyhow::bail!(
                    "grade {}/{} {:?}.{} = {s} out of range (0..={LIKERT_MAX})",
                    self.query_id,
                    self.grader_id,
                    self.system,
                    dim.as_str()
                );
            }
        }
        Ok(())
    }
}

/// Load a goldset JSONL file (one [`GoldsetEntry`] per non-blank line).
pub fn load_goldset(path: &Path) -> Result<Vec<GoldsetEntry>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read goldset {}", path.display()))?;
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let entry: GoldsetEntry =
            serde_json::from_str(line).with_context(|| format!("parse goldset line {}", i + 1))?;
        out.push(entry);
    }
    if out.is_empty() {
        anyhow::bail!("goldset {} contains no queries", path.display());
    }
    Ok(out)
}

/// Load a grades JSONL file (one [`GraderGrade`] per non-blank line), validating
/// every Likert score fail-closed.
pub fn load_grades(path: &Path) -> Result<Vec<GraderGrade>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("read grades {}", path.display()))?;
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let grade: GraderGrade =
            serde_json::from_str(line).with_context(|| format!("parse grades line {}", i + 1))?;
        grade
            .validate()
            .with_context(|| format!("validate grades line {}", i + 1))?;
        out.push(grade);
    }
    if out.is_empty() {
        anyhow::bail!("grades {} contains no records", path.display());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grade(qid: &str, gid: &str, sys: GradedSystem, scores: [u8; 5]) -> GraderGrade {
        GraderGrade {
            query_id: qid.into(),
            grader_id: gid.into(),
            system: sys,
            factual: scores[0],
            completeness: scores[1],
            on_tone: scores[2],
            usefulness: scores[3],
            brevity: scores[4],
        }
    }

    #[test]
    fn category_weights() {
        assert_eq!(GoldsetCategory::Recall.category_weight(), 1.5);
        assert_eq!(GoldsetCategory::Action.category_weight(), 1.5);
        assert_eq!(GoldsetCategory::Summarize.category_weight(), 1.0);
        assert_eq!(GoldsetCategory::Factual.category_weight(), 1.0);
    }

    #[test]
    fn grade_score_maps_dimensions() {
        let g = grade("q1", "A", GradedSystem::Neoth, [5, 4, 3, 2, 1]);
        assert_eq!(g.score(Dimension::Factual), 5);
        assert_eq!(g.score(Dimension::Completeness), 4);
        assert_eq!(g.score(Dimension::OnTone), 3);
        assert_eq!(g.score(Dimension::Usefulness), 2);
        assert_eq!(g.score(Dimension::Brevity), 1);
    }

    #[test]
    fn grade_validate_rejects_out_of_range() {
        assert!(
            grade("q", "A", GradedSystem::Neoth, [5, 5, 5, 5, 5])
                .validate()
                .is_ok()
        );
        assert!(
            grade("q", "A", GradedSystem::Neoth, [6, 0, 0, 0, 0])
                .validate()
                .is_err()
        );
    }

    #[test]
    fn goldset_jsonl_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("goldset.jsonl");
        let entries = vec![
            GoldsetEntry {
                query_id: "q1".into(),
                query_text: "what is my budget?".into(),
                category: GoldsetCategory::Recall,
                expected_sources: vec!["evt-1".into()],
                expected_response: "the budget is X".into(),
            },
            GoldsetEntry {
                query_id: "q2".into(),
                query_text: "summarize last week".into(),
                category: GoldsetCategory::Summarize,
                expected_sources: vec![],
                expected_response: String::new(),
            },
        ];
        let jsonl = entries
            .iter()
            .map(|e| serde_json::to_string(e).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&p, jsonl).unwrap();
        let loaded = load_goldset(&p).unwrap();
        assert_eq!(loaded, entries);
    }

    #[test]
    fn grades_jsonl_load_validates_and_skips_blank_lines() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("grades.jsonl");
        let g1 = grade("q1", "A", GradedSystem::Neoth, [4, 4, 4, 4, 4]);
        let g2 = grade("q1", "A", GradedSystem::Reference, [5, 5, 5, 5, 5]);
        let body = format!(
            "{}\n\n{}\n",
            serde_json::to_string(&g1).unwrap(),
            serde_json::to_string(&g2).unwrap()
        );
        std::fs::write(&p, body).unwrap();
        let loaded = load_grades(&p).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0], g1);

        // An out-of-range Likert in the file fails the whole load (fail-closed).
        let bad = grade("q2", "A", GradedSystem::Neoth, [9, 0, 0, 0, 0]);
        std::fs::write(&p, serde_json::to_string(&bad).unwrap()).unwrap();
        assert!(load_grades(&p).is_err());
    }

    #[test]
    fn empty_files_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("empty.jsonl");
        std::fs::write(&p, "\n\n").unwrap();
        assert!(load_goldset(&p).is_err());
        assert!(load_grades(&p).is_err());
    }
}
