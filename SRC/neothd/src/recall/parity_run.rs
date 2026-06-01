//! ARCH-05 / SPEC-08 — recall-parity run aggregator.
//!
//! Ties grade sheets ([`super::goldset::GraderGrade`]) to the pure scoring math
//! ([`super::parity`]) into one gate result: per-dimension inter-rater kappa,
//! kappa-adjusted per-dimension parity, the weighted-harmonic aggregate, the
//! SPEC §7.1 absolute-quality floors, and the per-query CRITICAL divergences.
//! Pure of I/O — the `neoth recall-score` CLI loads files + calls
//! [`compute_parity_run`] + emits the WAL frames; this is fixture-testable.
//!
//! Fail-CLOSED throughout: a wrong PASS authorises an irreversible Jarvis→NEOTH
//! memory cutover, so missing/inconsistent data aborts rather than scores a
//! subset, and the gate is STRICTER than pure parity (absolute floors + a
//! single-grader factual-zero safety net).

use std::collections::BTreeSet;

use anyhow::{Result, bail};

use super::goldset::{GradedSystem, GraderGrade};
use super::parity::{self, CriticalReason, Dimension, DivergenceClass, ParityVerdict};

/// One CRITICAL query, with the per-query kappa-parities that flagged it (the
/// durable `0x3E` evidence payload).
#[derive(Debug, Clone, PartialEq)]
pub struct CriticalDivergence {
    pub query_id: String,
    pub reason: CriticalReason,
    pub factual_parity_kappa: f64,
    pub usefulness_parity_kappa: f64,
}

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
    /// Lowest pairwise kappa seen (SPEC §5: no individual pair < 0.4).
    pub min_pairwise_kappa: f64,
    /// Mean NEOTH score per dimension (SPEC §7.1 absolute floor input).
    pub absolute_floors: Vec<(Dimension, f64)>,
    /// True when EVERY dimension's mean NEOTH score ≥ its absolute floor.
    pub absolute_floors_met: bool,
    /// Queries flagged CRITICAL, with their parity evidence.
    pub critical_queries: Vec<CriticalDivergence>,
    /// Final gate verdict.
    pub verdict: ParityVerdict,
}

/// Compute the parity gate result from a flat list of grades (both systems,
/// all graders, all queries). Requires ≥ 2 graders with COMPLETE coverage (the
/// same set drives both kappa AND the parity means, so reliability and quality
/// are measured over the same observations). Fail-closed on missing data.
pub fn compute_parity_run(grades: &[GraderGrade]) -> Result<ParityRunResult> {
    if grades.is_empty() {
        bail!("no grades supplied");
    }
    let all_graders: Vec<String> = grades
        .iter()
        .map(|g| g.grader_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let queries: Vec<String> = grades
        .iter()
        .map(|g| g.query_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    let get = |q: &str, gr: &str, sys: GradedSystem| -> Option<&GraderGrade> {
        grades
            .iter()
            .find(|g| g.query_id == q && g.grader_id == gr && g.system == sys)
    };

    // The SAME grader set feeds kappa AND parity: a grader with COMPLETE
    // coverage (every query, BOTH systems). A grader missing any observation is
    // excluded entirely — it would otherwise inflate parity means without
    // contributing to the reliability kappa (review HIGH: grader-set mismatch).
    let complete_graders: Vec<String> = all_graders
        .iter()
        .filter(|gr| {
            queries.iter().all(|q| {
                get(q, gr, GradedSystem::Neoth).is_some()
                    && get(q, gr, GradedSystem::Reference).is_some()
            })
        })
        .cloned()
        .collect();
    if complete_graders.len() < 2 {
        bail!(
            "need >= 2 graders with COMPLETE coverage (every query, both systems); got {} of {}",
            complete_graders.len(),
            all_graders.len()
        );
    }

    // Mean score across the complete graders for one (query, dimension, system).
    let mean_score = |q: &str, dim: Dimension, sys: GradedSystem| -> f64 {
        let vals: Vec<f64> = complete_graders
            .iter()
            .filter_map(|gr| get(q, gr, sys).map(|g| g.score(dim) as f64))
            .collect();
        vals.iter().sum::<f64>() / vals.len() as f64
    };

    let mut dimension_kappas = Vec::new();
    let mut dimension_parity_kappa = Vec::new();
    let mut absolute_floors = Vec::new();
    let mut absolute_floors_met = true;
    let mut min_pairwise_kappa = f64::INFINITY;
    let mut per_query_factual_pk: Vec<(String, f64)> = Vec::new();
    let mut per_query_useful_pk: Vec<(String, f64)> = Vec::new();

    for dim in Dimension::ALL {
        // Inter-rater kappa over the complete graders (fixed (query, system)
        // observation order so the per-grader vectors align).
        let observation_order: Vec<(&String, GradedSystem)> = queries
            .iter()
            .flat_map(|q| [(q, GradedSystem::Neoth), (q, GradedSystem::Reference)])
            .collect();
        let grader_vectors: Vec<Vec<u8>> = complete_graders
            .iter()
            .map(|gr| {
                observation_order
                    .iter()
                    .map(|(q, sys)| get(q, gr, *sys).map(|g| g.score(dim)).unwrap_or(0))
                    .collect()
            })
            .collect();
        let mut kappas = Vec::new();
        for i in 0..grader_vectors.len() {
            for j in (i + 1)..grader_vectors.len() {
                let k = parity::cohen_kappa_within1(&grader_vectors[i], &grader_vectors[j])?;
                min_pairwise_kappa = min_pairwise_kappa.min(k);
                kappas.push(k);
            }
        }
        let kappa = kappas.iter().sum::<f64>() / kappas.len() as f64;
        dimension_kappas.push((dim, kappa));

        // Parity: per query, mean NEOTH / mean Reference → parity_raw → mean → ×kappa.
        let mut per_query_parity = Vec::new();
        let mut neoth_means = Vec::new();
        for q in &queries {
            let neoth = mean_score(q, dim, GradedSystem::Neoth);
            let reference = mean_score(q, dim, GradedSystem::Reference);
            neoth_means.push(neoth);
            let pr = parity::parity_raw(neoth, reference);
            per_query_parity.push(pr);
            let pk_q = pr * kappa;
            if dim == Dimension::Factual {
                per_query_factual_pk.push((q.clone(), pk_q));
            } else if dim == Dimension::Usefulness {
                per_query_useful_pk.push((q.clone(), pk_q));
            }
        }
        let pk = parity::parity_kappa_dim(&per_query_parity, kappa)?;
        dimension_parity_kappa.push((dim, pk));

        // SPEC §7.1 absolute floor: mean NEOTH score for the dimension across
        // all queries must clear the dimension's floor.
        let mean_neoth = neoth_means.iter().sum::<f64>() / neoth_means.len() as f64;
        absolute_floors.push((dim, mean_neoth));
        if mean_neoth < dim.absolute_floor() {
            absolute_floors_met = false;
        }
    }

    let mean_kappa =
        dimension_kappas.iter().map(|(_, k)| k).sum::<f64>() / dimension_kappas.len() as f64;
    if !min_pairwise_kappa.is_finite() {
        min_pairwise_kappa = mean_kappa;
    }

    let agg_input: Vec<(f64, f64)> = dimension_parity_kappa
        .iter()
        .map(|(d, pk)| (*pk, d.weight()))
        .collect();
    let aggregate = parity::parity_aggregate(&agg_input)?;

    // Per-query CRITICAL: SPEC §7 floors PLUS a single-grader safety net — if
    // ANY complete grader scored factual = 0 (a clear hallucination one grader
    // caught) on NEOTH for the query, flag it even if the MEAN washed it out
    // (review MEDIUM). Stricter = the safe direction for a data-loss gate.
    let mut critical_queries = Vec::new();
    let mut divergences = Vec::new();
    for q in &queries {
        let f = lookup(&per_query_factual_pk, q);
        let u = lookup(&per_query_useful_pk, q);
        let any_grader_factual_zero = complete_graders
            .iter()
            .any(|gr| get(q, gr, GradedSystem::Neoth).map(|g| g.factual == 0).unwrap_or(false));
        let class = if any_grader_factual_zero {
            DivergenceClass::Critical(CriticalReason::FactualBelow50)
        } else {
            parity::classify_divergence_scores(f, u)
        };
        if let DivergenceClass::Critical(reason) = &class {
            critical_queries.push(CriticalDivergence {
                query_id: q.clone(),
                reason: reason.clone(),
                factual_parity_kappa: f,
                usefulness_parity_kappa: u,
            });
        }
        divergences.push(class);
    }

    let verdict = parity::parity_verdict(aggregate, &divergences, absolute_floors_met, mean_kappa);
    Ok(ParityRunResult {
        dimension_kappas,
        dimension_parity_kappa,
        aggregate,
        mean_kappa,
        min_pairwise_kappa,
        absolute_floors,
        absolute_floors_met,
        critical_queries,
        verdict,
    })
}

fn lookup(pairs: &[(String, f64)], q: &str) -> f64 {
    pairs.iter().find(|(qid, _)| qid == q).map(|(_, v)| *v).unwrap_or(0.0)
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

    /// Two graders, two queries, NEOTH == Reference == high scores everywhere.
    fn matched_high() -> Vec<GraderGrade> {
        let mut grades = Vec::new();
        for q in ["q1", "q2"] {
            for gr in ["A", "B"] {
                grades.push(g(q, gr, GradedSystem::Neoth, [5, 4, 4, 5, 4]));
                grades.push(g(q, gr, GradedSystem::Reference, [5, 4, 4, 5, 4]));
            }
        }
        grades
    }

    #[test]
    fn needs_two_complete_graders() {
        let grades = vec![
            g("q1", "A", GradedSystem::Neoth, [5, 5, 5, 5, 5]),
            g("q1", "A", GradedSystem::Reference, [5, 5, 5, 5, 5]),
        ];
        assert!(compute_parity_run(&grades).is_err(), "1 grader ⇒ no kappa");
    }

    #[test]
    fn matched_high_scores_pass_all_gates() {
        let r = compute_parity_run(&matched_high()).unwrap();
        assert!(r.aggregate >= parity::PARITY_PASS_THRESHOLD, "agg {}", r.aggregate);
        assert_eq!(r.critical_queries.len(), 0);
        assert!(r.absolute_floors_met, "high NEOTH scores clear the floors");
        assert!(r.verdict.passed);
    }

    #[test]
    fn both_systems_uniformly_terrible_fails_on_absolute_floor() {
        // THE false-PASS the review found: NEOTH == Reference == 0/5 ⇒ parity
        // 1.0 (constant-grader kappa clamps to 1.0) ⇒ aggregate 1.0, BUT the
        // absolute floor is unmet ⇒ the gate FAILS (no useless cutover).
        let mut grades = Vec::new();
        for q in ["q1", "q2"] {
            for gr in ["A", "B"] {
                grades.push(g(q, gr, GradedSystem::Neoth, [0, 0, 0, 0, 0]));
                grades.push(g(q, gr, GradedSystem::Reference, [0, 0, 0, 0, 0]));
            }
        }
        let r = compute_parity_run(&grades).unwrap();
        assert!(r.aggregate >= 0.85, "parity is high (both equally bad): {}", r.aggregate);
        assert!(!r.absolute_floors_met, "0/5 NEOTH must fail the absolute floor");
        assert!(!r.verdict.passed, "high parity + failed floor ⇒ gate FAILS");
    }

    #[test]
    fn factual_collapse_flags_critical_and_fails() {
        let mut grades = Vec::new();
        for q in ["q1", "q2"] {
            for gr in ["A", "B"] {
                grades.push(g(q, gr, GradedSystem::Neoth, [1, 4, 4, 4, 4]));
                grades.push(g(q, gr, GradedSystem::Reference, [5, 4, 4, 4, 4]));
            }
        }
        let r = compute_parity_run(&grades).unwrap();
        assert!(!r.verdict.passed);
        assert!(r.verdict.critical_count >= 1);
    }

    #[test]
    fn single_grader_factual_zero_is_critical_even_if_mean_survives() {
        // 3 graders score factual 5; 1 grader caught a hallucination (0). The
        // mean (3.75) would NOT trip the mean-based floor, but the single-grader
        // safety net flags it CRITICAL ⇒ gate fails (review MEDIUM, safe side).
        let mut grades = Vec::new();
        for gr in ["A", "B", "C", "D"] {
            let nf = if gr == "D" { 0 } else { 5 };
            grades.push(g("q1", gr, GradedSystem::Neoth, [nf, 5, 5, 5, 5]));
            grades.push(g("q1", gr, GradedSystem::Reference, [5, 5, 5, 5, 5]));
            // a 2nd clean query so the run is well-formed.
            grades.push(g("q2", gr, GradedSystem::Neoth, [5, 5, 5, 5, 5]));
            grades.push(g("q2", gr, GradedSystem::Reference, [5, 5, 5, 5, 5]));
        }
        let r = compute_parity_run(&grades).unwrap();
        assert!(
            r.critical_queries.iter().any(|c| c.query_id == "q1"),
            "a single grader's factual=0 must flag q1 CRITICAL"
        );
        assert!(!r.verdict.passed);
    }

    #[test]
    fn incomplete_grader_excluded_below_two_fails_closed() {
        // A only covers q1; B covers both. After excluding A (incomplete), only
        // B remains ⇒ < 2 complete graders ⇒ fail-closed (no scoring a subset).
        let mut grades = matched_high();
        grades.retain(|gr| !(gr.grader_id == "A" && gr.query_id == "q2"));
        assert!(compute_parity_run(&grades).is_err());
    }
}
