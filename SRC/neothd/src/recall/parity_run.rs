//! ARCH-05 / SPEC-08 — recall-parity run aggregator.
//!
//! Ties grade sheets ([`super::goldset::GraderGrade`]) to the pure scoring math
//! ([`super::parity`]) into one gate result: per-dimension inter-rater kappa,
//! kappa-adjusted per-dimension parity, the weighted-harmonic aggregate, and
//! the per-query CRITICAL divergences. Pure of I/O — the `neoth recall score`
//! CLI loads files + calls [`compute_parity_run`] + emits the WAL frames; this
//! function is fully fixture-testable in memory.

use std::collections::BTreeSet;

use anyhow::{Result, bail};

use super::goldset::{GradedSystem, GraderGrade};
use super::parity::{
    self, Dimension, DivergenceClass, ParityVerdict,
};

/// Full result of a parity scoring run.
#[derive(Debug, Clone, PartialEq)]
pub struct ParityRunResult {
    /// Inter-rater kappa per dimension (graders' agreement on the grading task).
    pub dimension_kappas: Vec<(Dimension, f64)>,
    /// Kappa-adjusted parity per dimension.
    pub dimension_parity_kappa: Vec<(Dimension, f64)>,
    /// Weighted-harmonic aggregate parity.
    pub aggregate: f64,
    /// Mean inter-rater kappa across dimensions (SPEC §5 ≥ 0.6 reliability gate).
    pub mean_kappa: f64,
    /// Queries flagged CRITICAL, with the reason.
    pub critical_queries: Vec<(String, parity::CriticalReason)>,
    /// Final gate verdict.
    pub verdict: ParityVerdict,
}

/// Compute the parity gate result from a flat list of grades (both systems,
/// all graders, all queries). Requires ≥ 2 graders (kappa needs a pair) and
/// every query graded for BOTH systems. Fail-closed on missing data.
pub fn compute_parity_run(grades: &[GraderGrade]) -> Result<ParityRunResult> {
    if grades.is_empty() {
        bail!("no grades supplied");
    }
    let graders: Vec<String> = grades
        .iter()
        .map(|g| g.grader_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if graders.len() < 2 {
        bail!("need >= 2 graders to compute inter-rater kappa, got {}", graders.len());
    }
    let queries: Vec<String> = grades
        .iter()
        .map(|g| g.query_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    // Lookup: (query, grader, system) -> grade.
    let get = |q: &str, gr: &str, sys: GradedSystem| -> Option<&GraderGrade> {
        grades
            .iter()
            .find(|g| g.query_id == q && g.grader_id == gr && g.system == sys)
    };

    let mut dimension_kappas = Vec::new();
    let mut dimension_parity_kappa = Vec::new();
    // Per-query factual/usefulness parity_kappa for the divergence pass.
    let mut per_query_factual_pk: Vec<(String, f64)> = Vec::new();
    let mut per_query_useful_pk: Vec<(String, f64)> = Vec::new();

    for dim in Dimension::ALL {
        // ── inter-rater kappa: pairwise across graders over all (query,system)
        // observations, averaged. Build each grader's score vector in a fixed
        // (query, system) order so the slices align.
        let observation_order: Vec<(&String, GradedSystem)> = queries
            .iter()
            .flat_map(|q| [(q, GradedSystem::Neoth), (q, GradedSystem::Reference)])
            .collect();
        let mut grader_vectors: Vec<Vec<u8>> = Vec::new();
        for gr in &graders {
            let mut v = Vec::with_capacity(observation_order.len());
            let mut complete = true;
            for (q, sys) in &observation_order {
                match get(q, gr, *sys) {
                    Some(g) => v.push(g.score(dim)),
                    None => {
                        complete = false;
                        break;
                    }
                }
            }
            if complete {
                grader_vectors.push(v);
            }
        }
        if grader_vectors.len() < 2 {
            bail!(
                "dimension {}: fewer than 2 graders have complete coverage",
                dim.as_str()
            );
        }
        let mut kappas = Vec::new();
        for i in 0..grader_vectors.len() {
            for j in (i + 1)..grader_vectors.len() {
                kappas.push(parity::cohen_kappa_within1(&grader_vectors[i], &grader_vectors[j])?);
            }
        }
        let kappa = kappas.iter().sum::<f64>() / kappas.len() as f64;
        dimension_kappas.push((dim, kappa));

        // ── parity: per query, mean NEOTH score / mean Reference score across
        // graders, → parity_raw → mean over queries → * kappa.
        let mut per_query_parity = Vec::new();
        for q in &queries {
            let neoth = mean_score(grades, q, dim, GradedSystem::Neoth);
            let reference = mean_score(grades, q, dim, GradedSystem::Reference);
            let (Some(neoth), Some(reference)) = (neoth, reference) else {
                bail!("query {q}: missing NEOTH or Reference grades for {}", dim.as_str());
            };
            let pr = parity::parity_raw(neoth, reference);
            per_query_parity.push(pr);
            // Per-query kappa-parity for the CRITICAL pass.
            let pk_q = pr * kappa;
            if dim == Dimension::Factual {
                per_query_factual_pk.push((q.clone(), pk_q));
            } else if dim == Dimension::Usefulness {
                per_query_useful_pk.push((q.clone(), pk_q));
            }
        }
        let pk = parity::parity_kappa_dim(&per_query_parity, kappa)?;
        dimension_parity_kappa.push((dim, pk));
    }

    let mean_kappa =
        dimension_kappas.iter().map(|(_, k)| k).sum::<f64>() / dimension_kappas.len() as f64;

    let agg_input: Vec<(f64, f64)> = dimension_parity_kappa
        .iter()
        .map(|(d, pk)| (*pk, d.weight()))
        .collect();
    let aggregate = parity::parity_aggregate(&agg_input)?;

    // ── per-query CRITICAL divergence (factual/usefulness floors).
    let mut critical_queries = Vec::new();
    let mut divergences = Vec::new();
    for q in &queries {
        let f = per_query_factual_pk
            .iter()
            .find(|(qid, _)| qid == q)
            .map(|(_, v)| *v)
            .unwrap_or(0.0);
        let u = per_query_useful_pk
            .iter()
            .find(|(qid, _)| qid == q)
            .map(|(_, v)| *v)
            .unwrap_or(0.0);
        let class = parity::classify_divergence_scores(f, u);
        if let DivergenceClass::Critical(reason) = &class {
            critical_queries.push((q.clone(), reason.clone()));
        }
        divergences.push(class);
    }

    let verdict = parity::parity_verdict(aggregate, &divergences);
    Ok(ParityRunResult {
        dimension_kappas,
        dimension_parity_kappa,
        aggregate,
        mean_kappa,
        critical_queries,
        verdict,
    })
}

/// Mean score across graders for one (query, dimension, system), or `None` if
/// no grader scored it.
fn mean_score(grades: &[GraderGrade], q: &str, dim: Dimension, sys: GradedSystem) -> Option<f64> {
    let vals: Vec<f64> = grades
        .iter()
        .filter(|g| g.query_id == q && g.system == sys)
        .map(|g| g.score(dim) as f64)
        .collect();
    if vals.is_empty() {
        None
    } else {
        Some(vals.iter().sum::<f64>() / vals.len() as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recall::goldset::GraderGrade;

    fn g(q: &str, gr: &str, sys: GradedSystem, s: [u8; 5]) -> GraderGrade {
        GraderGrade {
            query_id: q.into(),
            grader_id: gr.into(),
            system: sys,
            factual: s[0],
            completeness: s[1],
            on_tone: s[2],
            usefulness: s[3],
            brevity: s[4],
        }
    }

    #[test]
    fn needs_two_graders() {
        let grades = vec![
            g("q1", "A", GradedSystem::Neoth, [5, 5, 5, 5, 5]),
            g("q1", "A", GradedSystem::Reference, [5, 5, 5, 5, 5]),
        ];
        assert!(compute_parity_run(&grades).is_err(), "1 grader ⇒ no kappa");
    }

    #[test]
    fn neoth_matches_reference_passes_clean() {
        // 2 graders, 2 queries, NEOTH == Reference everywhere ⇒ parity 1.0,
        // high agreement, zero CRITICAL ⇒ PASS.
        let mut grades = Vec::new();
        for q in ["q1", "q2"] {
            for gr in ["A", "B"] {
                grades.push(g(q, gr, GradedSystem::Neoth, [5, 4, 4, 5, 4]));
                grades.push(g(q, gr, GradedSystem::Reference, [5, 4, 4, 5, 4]));
            }
        }
        let r = compute_parity_run(&grades).unwrap();
        assert!(r.aggregate >= parity::PARITY_PASS_THRESHOLD, "agg {}", r.aggregate);
        assert_eq!(r.critical_queries.len(), 0);
        assert!(r.verdict.passed);
    }

    #[test]
    fn neoth_far_worse_on_factual_flags_critical_and_fails() {
        // NEOTH scores 1/5 factual where Reference scores 5/5 ⇒ factual parity
        // ~0.2 ⇒ below the 0.5 floor ⇒ CRITICAL + the gate fails.
        let mut grades = Vec::new();
        for q in ["q1", "q2"] {
            for gr in ["A", "B"] {
                grades.push(g(q, gr, GradedSystem::Neoth, [1, 4, 4, 4, 4]));
                grades.push(g(q, gr, GradedSystem::Reference, [5, 4, 4, 4, 4]));
            }
        }
        let r = compute_parity_run(&grades).unwrap();
        assert!(!r.verdict.passed, "factual collapse must fail the gate");
        assert!(
            r.critical_queries.iter().all(|(_, reason)| *reason
                == parity::CriticalReason::FactualBelow50),
            "all flagged CRITICAL via the factual floor"
        );
        assert!(r.verdict.critical_count >= 1);
    }

    #[test]
    fn missing_reference_grades_fail_closed() {
        let grades = vec![
            g("q1", "A", GradedSystem::Neoth, [5, 5, 5, 5, 5]),
            g("q1", "B", GradedSystem::Neoth, [5, 5, 5, 5, 5]),
            // q1 Reference grades absent for both graders.
        ];
        assert!(compute_parity_run(&grades).is_err());
    }
}
