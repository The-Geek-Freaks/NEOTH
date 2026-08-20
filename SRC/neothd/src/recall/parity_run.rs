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

use std::collections::{BTreeMap, BTreeSet};

use super::goldset::{
    GoldsetEntry, GradedSystem, GraderConfig, GraderFamily, GraderGrade, GraderProvider,
    ValidatedGraderConfigFile, validate_goldset_contract,
};
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

/// A configured grader that supplied the complete, validated grade matrix.
///
/// This is configuration metadata, not a claim about live provider provenance;
/// P1-08 owns the cryptographic provenance and batch binding work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParticipatingGrader {
    pub grader_id: String,
    pub provider: GraderProvider,
    pub model_id: String,
    pub family: GraderFamily,
}

/// Fail-closed validation errors for a recall-parity grade matrix.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ParityRunError {
    #[error("invalid recall-parity goldset: {reason}")]
    InvalidGoldset { reason: String },
    #[error("no grades supplied")]
    NoGrades,
    #[error("grader configuration has {found} graders; at least {minimum} are required")]
    InsufficientConfiguredGraders { found: usize, minimum: usize },
    #[error("grade matrix size overflow")]
    MatrixSizeOverflow,
    #[error("grade matrix has {found} records; expected exactly {expected}")]
    UnexpectedObservationCount { found: usize, expected: usize },
    #[error("invalid grade for query {query_id:?}, grader {grader_id:?}: {reason}")]
    InvalidGrade {
        query_id: String,
        grader_id: String,
        reason: String,
    },
    #[error("grade references query {query_id:?} absent from the goldset")]
    GradeQueryAbsentFromGoldset { query_id: String },
    #[error("goldset query {query_id:?} has no grade observations")]
    GoldsetQueryWithoutGrades { query_id: String },
    #[error("grade references unknown grader id {grader_id:?}")]
    UnknownGraderId { grader_id: String },
    #[error("configured grader {grader_id:?} supplied no grades")]
    ConfiguredGraderUnused { grader_id: String },
    #[error(
        "duplicate grade observation for query {query_id:?}, grader {grader_id:?}, system {system:?}"
    )]
    DuplicateObservation {
        query_id: String,
        grader_id: String,
        system: GradedSystem,
    },
    #[error(
        "missing grade observation for query {query_id:?}, grader {grader_id:?}, system {system:?}"
    )]
    MissingObservation {
        query_id: String,
        grader_id: String,
        system: GradedSystem,
    },
    #[error("no fully-covered independent external grader participated")]
    NoIndependentExternalParticipant,
    #[error(transparent)]
    Parity(#[from] parity::ParityError),
}

/// Full result of a parity scoring run.
#[derive(Debug, Clone, PartialEq)]
pub struct ParityRunResult {
    /// Validated graders that contributed, sorted by `grader_id` for stable reports.
    pub participating_graders: Vec<ParticipatingGrader>,
    /// True only when a configured independent-external grader supplied the
    /// complete grade matrix. This is bound into `verdict.passed`.
    pub independent_external_family_gate_met: bool,
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

/// Compute the parity gate result from a validated roster, the canonical
/// 100-query goldset, and a flat grade matrix. Every configured grader must
/// have exactly one observation for every `(goldset query, system)` pair. The
/// whole validated roster drives both kappa and parity means; incomplete grades
/// are never silently filtered out.
pub fn compute_parity_run(
    grader_config: &ValidatedGraderConfigFile,
    goldset: &[GoldsetEntry],
    grades: &[GraderGrade],
) -> std::result::Result<ParityRunResult, ParityRunError> {
    validate_goldset_contract(goldset).map_err(|error| ParityRunError::InvalidGoldset {
        reason: error.to_string(),
    })?;
    if grades.is_empty() {
        return Err(ParityRunError::NoGrades);
    }
    if grader_config.graders().len() < 2 {
        return Err(ParityRunError::InsufficientConfiguredGraders {
            found: grader_config.graders().len(),
            minimum: 2,
        });
    }
    let expected_observations = goldset
        .len()
        .checked_mul(grader_config.graders().len())
        .and_then(|count| count.checked_mul(2))
        .ok_or(ParityRunError::MatrixSizeOverflow)?;
    let has_expected_observation_count = grades.len() == expected_observations;
    // Reject an oversized direct caller before building any indexes. A smaller
    // input is still bounded by the canonical maximum, so we inspect it below
    // to return the more useful missing/unused-cell error rather than hiding
    // the root cause behind a cardinality mismatch.
    if grades.len() > expected_observations {
        return Err(ParityRunError::UnexpectedObservationCount {
            found: grades.len(),
            expected: expected_observations,
        });
    }
    for grade in grades {
        grade
            .validate()
            .map_err(|error| ParityRunError::InvalidGrade {
                query_id: grade.query_id.clone(),
                grader_id: grade.grader_id.clone(),
                reason: error.to_string(),
            })?;
    }

    let configured_graders: BTreeMap<&str, &GraderConfig> = grader_config
        .graders()
        .iter()
        .map(|grader| (grader.grader_id.as_str(), grader))
        .collect();
    let goldset_query_ids: BTreeSet<&str> = goldset
        .iter()
        .map(|entry| entry.query_id.as_str())
        .collect();
    let grade_query_ids: BTreeSet<&str> = grades
        .iter()
        .map(|grade| grade.query_id.as_str())
        .collect();
    for query_id in &grade_query_ids {
        if !goldset_query_ids.contains(query_id) {
            return Err(ParityRunError::GradeQueryAbsentFromGoldset {
                query_id: (*query_id).to_owned(),
            });
        }
    }
    for query_id in &goldset_query_ids {
        if !grade_query_ids.contains(query_id) {
            return Err(ParityRunError::GoldsetQueryWithoutGrades {
                query_id: (*query_id).to_owned(),
            });
        }
    }
    let queries: Vec<String> = goldset_query_ids
        .iter()
        .map(|query_id| (*query_id).to_owned())
        .collect();

    let mut observations: BTreeMap<(&str, &str, bool), &GraderGrade> = BTreeMap::new();
    let mut used_graders = BTreeSet::new();
    for grade in grades {
        if !configured_graders.contains_key(grade.grader_id.as_str()) {
            return Err(ParityRunError::UnknownGraderId {
                grader_id: grade.grader_id.clone(),
            });
        }
        let key = (
            grade.query_id.as_str(),
            grade.grader_id.as_str(),
            system_key(grade.system),
        );
        if observations.insert(key, grade).is_some() {
            return Err(ParityRunError::DuplicateObservation {
                query_id: grade.query_id.clone(),
                grader_id: grade.grader_id.clone(),
                system: grade.system,
            });
        }
        used_graders.insert(grade.grader_id.as_str());
    }

    for grader_id in configured_graders.keys() {
        if !used_graders.contains(grader_id) {
            return Err(ParityRunError::ConfiguredGraderUnused {
                grader_id: (*grader_id).to_owned(),
            });
        }
    }

    let get = |q: &str, grader_id: &str, system: GradedSystem| -> Option<&GraderGrade> {
        observations
            .get(&(q, grader_id, system_key(system)))
            .copied()
    };
    for query_id in &queries {
        for grader_id in configured_graders.keys() {
            for system in [GradedSystem::Neoth, GradedSystem::Reference] {
                if get(query_id, grader_id, system).is_none() {
                    return Err(ParityRunError::MissingObservation {
                        query_id: query_id.clone(),
                        grader_id: (*grader_id).to_owned(),
                        system,
                    });
                }
            }
        }
    }
    if !has_expected_observation_count {
        return Err(ParityRunError::UnexpectedObservationCount {
            found: grades.len(),
            expected: expected_observations,
        });
    }

    let participating_graders: Vec<ParticipatingGrader> = configured_graders
        .iter()
        .map(|(grader_id, grader)| ParticipatingGrader {
            grader_id: (*grader_id).to_owned(),
            provider: grader.provider,
            model_id: grader.model_id.clone(),
            family: grader.family,
        })
        .collect();
    let independent_external_family_gate_met = configured_graders
        .values()
        .any(|grader| grader.is_independent_external());
    if !independent_external_family_gate_met {
        return Err(ParityRunError::NoIndependentExternalParticipant);
    }
    let complete_graders: Vec<&str> = configured_graders.keys().copied().collect();

    // Mean score across the complete graders for one (query, dimension, system).
    let mean_score = |q: &str, dim: Dimension, sys: GradedSystem| -> f64 {
        let vals: Vec<f64> = complete_graders
            .iter()
            .map(|grader_id| {
                get(q, grader_id, sys)
                    .expect("coverage verified before scoring")
                    .score(dim) as f64
            })
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
                    .map(|(q, sys)| {
                        get(q, gr, *sys)
                            .expect("coverage verified before scoring")
                            .score(dim)
                    })
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
        let any_grader_factual_zero = complete_graders.iter().any(|gr| {
            get(q, gr, GradedSystem::Neoth)
                .expect("coverage verified before scoring")
                .factual
                == 0
        });
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

    let mut verdict =
        parity::parity_verdict(aggregate, &divergences, absolute_floors_met, mean_kappa);
    verdict.passed &= independent_external_family_gate_met;
    Ok(ParityRunResult {
        participating_graders,
        independent_external_family_gate_met,
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

const fn system_key(system: GradedSystem) -> bool {
    matches!(system, GradedSystem::Neoth)
}

fn lookup(pairs: &[(String, f64)], q: &str) -> f64 {
    pairs
        .iter()
        .find(|(qid, _)| qid == q)
        .map(|(_, v)| *v)
        .unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recall::goldset::{
        EXPECTED_GOLDSET_QUERIES, GRADER_CONFIG_SCHEMA_VERSION, GoldsetCategory, GraderConfigFile,
    };

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

    fn config_for(grader_ids: &[&str]) -> ValidatedGraderConfigFile {
        let providers = [
            GraderProvider::Anthropic,
            GraderProvider::Mistral,
            GraderProvider::Openai,
            GraderProvider::Deepseek,
            GraderProvider::Google,
            GraderProvider::Qwen,
        ];
        let graders = grader_ids
            .iter()
            .enumerate()
            .map(|(index, grader_id)| {
                let provider = providers[index];
                let family = if matches!(
                    provider,
                    GraderProvider::Mistral | GraderProvider::Deepseek | GraderProvider::Qwen
                ) {
                    GraderFamily::IndependentExternal
                } else {
                    GraderFamily::AnthropicOpenaiGoogle
                };
                GraderConfig {
                    grader_id: (*grader_id).into(),
                    provider,
                    model_id: format!("model-{index}"),
                    family,
                }
            })
            .collect();
        GraderConfigFile {
            schema_version: GRADER_CONFIG_SCHEMA_VERSION,
            graders,
        }
        .into_validated()
        .expect("test grader roster must validate")
    }

    fn run(
        grades: &[GraderGrade],
        grader_ids: &[&str],
    ) -> std::result::Result<ParityRunResult, ParityRunError> {
        run_with_goldset(&canonical_goldset(), grades, grader_ids)
    }

    fn run_with_goldset(
        goldset: &[GoldsetEntry],
        grades: &[GraderGrade],
        grader_ids: &[&str],
    ) -> std::result::Result<ParityRunResult, ParityRunError> {
        compute_parity_run(&config_for(grader_ids), goldset, grades)
    }

    fn canonical_goldset() -> Vec<GoldsetEntry> {
        (0..EXPECTED_GOLDSET_QUERIES)
            .map(|index| GoldsetEntry {
                query_id: format!("q{index:03}"),
                query_text: "fixture".into(),
                category: GoldsetCategory::Recall,
                expected_sources: Vec::new(),
                expected_response: String::new(),
            })
            .collect()
    }

    /// A canonical 100-query corpus with NEOTH == Reference == high scores.
    fn matched_high_for(grader_ids: &[&str]) -> Vec<GraderGrade> {
        let mut grades = Vec::new();
        for entry in canonical_goldset() {
            for grader_id in grader_ids {
                grades.push(g(
                    &entry.query_id,
                    grader_id,
                    GradedSystem::Neoth,
                    [5, 4, 4, 5, 4],
                ));
                grades.push(g(
                    &entry.query_id,
                    grader_id,
                    GradedSystem::Reference,
                    [5, 4, 4, 5, 4],
                ));
            }
        }
        grades
    }

    fn matched_high() -> Vec<GraderGrade> {
        matched_high_for(&["A", "B"])
    }

    #[test]
    fn incomplete_matrix_is_rejected_before_scoring() {
        let mut grades = matched_high();
        grades.retain(|grade| grade.grader_id == "A");
        assert_eq!(
            run(&grades, &["A", "B"]),
            Err(ParityRunError::ConfiguredGraderUnused {
                grader_id: "B".into(),
            })
        );
    }

    #[test]
    fn matched_high_scores_pass_all_gates() {
        let r = run(&matched_high(), &["A", "B"]).unwrap();
        assert!(
            r.aggregate >= parity::PARITY_PASS_THRESHOLD,
            "agg {}",
            r.aggregate
        );
        assert_eq!(r.critical_queries.len(), 0);
        assert!(r.absolute_floors_met, "high NEOTH scores clear the floors");
        assert!(r.verdict.passed);
    }

    #[test]
    fn both_systems_uniformly_terrible_fails_on_absolute_floor() {
        // THE false-PASS the review found: NEOTH == Reference == 0/5 ⇒ parity
        // 1.0 (constant-grader kappa clamps to 1.0) ⇒ aggregate 1.0, BUT the
        // absolute floor is unmet ⇒ the gate FAILS (no useless cutover).
        let mut grades = matched_high();
        for grade in &mut grades {
            grade.factual = 0;
            grade.completeness = 0;
            grade.on_tone = 0;
            grade.usefulness = 0;
            grade.brevity = 0;
        }
        let r = run(&grades, &["A", "B"]).unwrap();
        assert!(
            r.aggregate >= 0.85,
            "parity is high (both equally bad): {}",
            r.aggregate
        );
        assert!(
            !r.absolute_floors_met,
            "0/5 NEOTH must fail the absolute floor"
        );
        assert!(!r.verdict.passed, "high parity + failed floor ⇒ gate FAILS");
    }

    #[test]
    fn factual_collapse_flags_critical_and_fails() {
        let mut grades = matched_high();
        for grade in &mut grades {
            grade.completeness = 4;
            grade.on_tone = 4;
            grade.usefulness = 4;
            grade.brevity = 4;
            grade.factual = if grade.system == GradedSystem::Neoth { 1 } else { 5 };
        }
        let r = run(&grades, &["A", "B"]).unwrap();
        assert!(!r.verdict.passed);
        assert!(r.verdict.critical_count >= 1);
    }

    #[test]
    fn single_grader_factual_zero_is_critical_even_if_mean_survives() {
        // 3 graders score factual 5; 1 grader caught a hallucination (0). The
        // mean (3.75) would NOT trip the mean-based floor, but the single-grader
        // safety net flags it CRITICAL ⇒ gate fails (review MEDIUM, safe side).
        let mut grades = matched_high_for(&["A", "B", "C", "D"]);
        for grade in &mut grades {
            grade.factual = if grade.query_id == "q000"
                && grade.grader_id == "D"
                && grade.system == GradedSystem::Neoth
            {
                0
            } else {
                5
            };
            grade.completeness = 5;
            grade.on_tone = 5;
            grade.usefulness = 5;
            grade.brevity = 5;
        }
        let r = run(&grades, &["A", "B", "C", "D"]).unwrap();
        assert!(
            r.critical_queries.iter().any(|c| c.query_id == "q000"),
            "a single grader's factual=0 must flag q000 CRITICAL"
        );
        assert!(!r.verdict.passed);
    }

    #[test]
    fn incomplete_grader_excluded_below_two_fails_closed() {
        // A misses one matrix cell. Partial coverage cannot be silently filtered.
        let mut grades = matched_high();
        grades.retain(|gr| !(gr.grader_id == "A" && gr.query_id == "q001"));
        assert_eq!(
            run(&grades, &["A", "B"]),
            Err(ParityRunError::MissingObservation {
                query_id: "q001".into(),
                grader_id: "A".into(),
                system: GradedSystem::Neoth,
            })
        );
    }

    #[test]
    fn valid_mixed_roster_has_stable_safe_participant_metadata() {
        let result = run(&matched_high(), &["B", "A"]).unwrap();
        assert!(result.independent_external_family_gate_met);
        assert_eq!(
            result
                .participating_graders
                .iter()
                .map(|grader| grader.grader_id.as_str())
                .collect::<Vec<_>>(),
            vec!["A", "B"],
            "report ordering must not depend on the persisted roster order"
        );
        assert!(result
            .participating_graders
            .iter()
            .any(|grader| grader.family == GraderFamily::IndependentExternal));
        assert!(result.verdict.passed, "family gate is bound into the verdict");
    }

    #[test]
    fn all_shared_roster_cannot_reach_the_scorer() {
        let raw = GraderConfigFile {
            schema_version: GRADER_CONFIG_SCHEMA_VERSION,
            graders: vec![
                GraderConfig {
                    grader_id: "A".into(),
                    provider: GraderProvider::Anthropic,
                    model_id: "model-a".into(),
                    family: GraderFamily::AnthropicOpenaiGoogle,
                },
                GraderConfig {
                    grader_id: "B".into(),
                    provider: GraderProvider::Openai,
                    model_id: "model-b".into(),
                    family: GraderFamily::AnthropicOpenaiGoogle,
                },
            ],
        };
        assert!(raw.into_validated().is_err());
    }

    #[test]
    fn spoofed_or_unknown_grader_id_is_rejected_before_scoring() {
        let mut grades = matched_high();
        grades[0].grader_id = "external-spoof".into();
        assert_eq!(
            run(&grades, &["A", "B"]),
            Err(ParityRunError::UnknownGraderId {
                grader_id: "external-spoof".into(),
            })
        );
    }

    #[test]
    fn grade_query_outside_canonical_goldset_is_rejected() {
        let mut grades = matched_high();
        for grade in &mut grades {
            if grade.query_id == "q099" {
                grade.query_id = "extra-query".into();
            }
        }
        assert_eq!(
            run(&grades, &["A", "B"]),
            Err(ParityRunError::GradeQueryAbsentFromGoldset {
                query_id: "extra-query".into(),
            })
        );
    }

    #[test]
    fn duplicate_observation_is_rejected_before_scoring() {
        let mut grades = matched_high();
        let duplicate = grades[0].clone();
        grades[1] = duplicate;
        assert_eq!(
            run(&grades, &["A", "B"]),
            Err(ParityRunError::DuplicateObservation {
                query_id: "q000".into(),
                grader_id: "A".into(),
                system: GradedSystem::Neoth,
            })
        );
    }

    #[test]
    fn configured_but_unused_grader_is_rejected_before_scoring() {
        assert_eq!(
            run(&matched_high(), &["A", "B", "C"]),
            Err(ParityRunError::ConfiguredGraderUnused {
                grader_id: "C".into(),
            })
        );
    }

    #[test]
    fn oversized_matrix_is_rejected_before_index_allocation() {
        let mut grades = matched_high();
        grades.push(grades[0].clone());
        assert_eq!(
            run(&grades, &["A", "B"]),
            Err(ParityRunError::UnexpectedObservationCount {
                found: EXPECTED_GOLDSET_QUERIES * 2 * 2 + 1,
                expected: EXPECTED_GOLDSET_QUERIES * 2 * 2,
            })
        );
    }

    #[test]
    fn tiny_goldset_cannot_authorize_the_scorer() {
        let mut canonical = canonical_goldset();
        let goldset = vec![canonical.remove(0)];
        assert!(matches!(
            run_with_goldset(&goldset, &matched_high(), &["A", "B"]),
            Err(ParityRunError::InvalidGoldset { .. })
        ));
    }

    #[test]
    fn direct_constructed_invalid_likert_grade_is_rejected() {
        let mut grades = matched_high();
        grades[0].factual = 6;
        assert!(matches!(
            run(&grades, &["A", "B"]),
            Err(ParityRunError::InvalidGrade {
                query_id,
                grader_id,
                ..
            }) if query_id == "q000" && grader_id == "A"
        ));
    }
}
