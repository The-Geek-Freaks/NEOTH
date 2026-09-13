//! Bounded, textual (not semantic) agreement evidence for production councils.
use serde::{Deserialize, Serialize};

use crate::config::inference::HemisphereRole;

pub const PROTOCOL: &str = "v1";
pub const MAX_STATEMENT_BYTES: usize = 512;
pub const PROMPT_SUFFIX: &str = "\n\nAfter your normal answer, append exactly one NEOTH_AGREEMENT_V1 block. Do not put this block in the normal answer.\n[NEOTH_AGREEMENT_V1]\nfactual_claims: <one self-contained factual statement, or NONE>\nrecommendations: <one self-contained actionable recommendation, or NONE>\nrisk_assessment: <one self-contained risk, limit, or uncertainty, or NONE>\n[/NEOTH_AGREEMENT_V1]";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgreementDimension {
    FactualClaims,
    Recommendations,
    RiskAssessment,
}
impl AgreementDimension {
    pub const ALL: [Self; 3] = [
        Self::FactualClaims,
        Self::Recommendations,
        Self::RiskAssessment,
    ];
    pub fn weight(self) -> f32 {
        match self {
            Self::FactualClaims => 0.50,
            Self::Recommendations => 0.30,
            Self::RiskAssessment => 0.20,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeclaredValue {
    Statement(String),
    NotApplicable,
    Missing(ParseReason),
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParseReason {
    Absent,
    NonFinal,
    Malformed,
    Duplicate,
    Oversized,
}
#[derive(Clone, Debug)]
pub struct ParsedAgreement {
    pub body: String,
    pub values: [DeclaredValue; 3],
}

/// Strictly parse one *final* block. Statements never enter the report/WAL.
pub fn parse_final_suffix(text: &str) -> ParsedAgreement {
    let open = "[NEOTH_AGREEMENT_V1]";
    let close = "[/NEOTH_AGREEMENT_V1]";
    // Even malformed envelopes are protocol material, never chat content.
    let marker = [text.find(open), text.find(close)]
        .into_iter()
        .flatten()
        .min();
    let safe_body = marker
        .map(|i| text[..i].trim_end().to_string())
        .unwrap_or_else(|| text.to_string());
    let missing = |reason: ParseReason| ParsedAgreement {
        body: safe_body.clone(),
        values: [
            DeclaredValue::Missing(reason.clone()),
            DeclaredValue::Missing(reason.clone()),
            DeclaredValue::Missing(reason),
        ],
    };
    let Some(start) = text.rfind(open) else {
        return missing(ParseReason::Absent);
    };
    if marker != Some(start) {
        return missing(ParseReason::Malformed);
    }
    let Some(end_rel) = text[start..].find(close) else {
        return missing(ParseReason::Malformed);
    };
    let end = start + end_rel + close.len();
    if !text[end..].trim().is_empty() {
        return missing(ParseReason::NonFinal);
    }
    if text[..start].contains(open) {
        return missing(ParseReason::Duplicate);
    }
    let block = &text[start + open.len()..start + end_rel];
    let lines: Vec<&str> = block.trim_matches(['\r', '\n']).lines().collect();
    if lines.len() != 3 {
        return missing(ParseReason::Malformed);
    }
    let keys = ["factual_claims: ", "recommendations: ", "risk_assessment: "];
    let mut values = Vec::with_capacity(3);
    for (line, key) in lines.iter().zip(keys) {
        let Some(value) = line.strip_prefix(key) else {
            return missing(ParseReason::Malformed);
        };
        if value.trim().is_empty() || value.contains('\n') {
            return missing(ParseReason::Malformed);
        }
        if value.len() > MAX_STATEMENT_BYTES {
            return missing(ParseReason::Oversized);
        }
        values.push(if value == "NONE" {
            DeclaredValue::NotApplicable
        } else {
            DeclaredValue::Statement((*value).to_string())
        });
    }
    ParsedAgreement {
        body: text[..start].trim_end().to_string(),
        values: [values.remove(0), values.remove(0), values.remove(0)],
    }
}

pub fn normalized_identity(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DimensionState {
    NotEvaluated,
    Scored,
    Disagreed,
    NotApplicable,
    Missing,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DimensionAgreement {
    pub dimension: AgreementDimension,
    pub state: DimensionState,
    #[serde(default)]
    pub participating_roles: Vec<String>,
    #[serde(default)]
    pub missing_roles: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub missing_reason: Option<ParseReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f32>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgreementReport {
    pub protocol: String,
    pub textual_identity: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weighted_score: Option<f32>,
    pub dimensions: Vec<DimensionAgreement>,
}
impl Default for AgreementReport {
    fn default() -> Self {
        Self {
            protocol: "not_evaluated".into(),
            textual_identity: false,
            weighted_score: None,
            dimensions: AgreementDimension::ALL
                .into_iter()
                .map(|dimension| DimensionAgreement {
                    dimension,
                    state: DimensionState::NotEvaluated,
                    participating_roles: vec![],
                    missing_roles: vec![],
                    missing_reason: None,
                    score: None,
                })
                .collect(),
        }
    }
}

pub fn evaluate(responses: &[(HemisphereRole, bool, [DeclaredValue; 3])]) -> AgreementReport {
    let mut dimensions = Vec::new();
    let mut weighted_sum = 0.0;
    let mut weights = 0.0;
    let mut identical = true;
    for (index, dimension) in AgreementDimension::ALL.into_iter().enumerate() {
        let mut usable: Vec<_> = responses.iter().filter(|(_, usable, _)| *usable).collect();
        usable.sort_by_key(|(role, _, _)| match role {
            HemisphereRole::Left => 0,
            HemisphereRole::Right => 1,
            HemisphereRole::Cerebellum => 2,
        });
        let roles = usable
            .iter()
            .map(|(r, _, _)| r.as_str().to_string())
            .collect();
        let missing_roles: Vec<_> = usable
            .iter()
            .filter(|(_, _, values)| matches!(values[index], DeclaredValue::Missing(_)))
            .map(|(role, _, _)| role.as_str().to_string())
            .collect();
        let missing_reason = usable
            .iter()
            .find_map(|(_, _, values)| match &values[index] {
                DeclaredValue::Missing(reason) => Some(reason.clone()),
                _ => None,
            });
        let (state, score) = if usable.len() < 2 || !missing_roles.is_empty() {
            (DimensionState::Missing, None)
        } else {
            let vals: Vec<_> = usable.iter().map(|(_, _, v)| &v[index]).collect();
            if vals
                .iter()
                .all(|v| matches!(v, DeclaredValue::NotApplicable))
            {
                (DimensionState::NotApplicable, None)
            } else if vals
                .iter()
                .any(|v| matches!(v, DeclaredValue::NotApplicable))
            {
                (DimensionState::Disagreed, Some(0.0))
            } else {
                let normalized: Vec<String> = vals
                    .iter()
                    .map(|value| match value {
                        DeclaredValue::Statement(statement) => normalized_identity(statement),
                        _ => unreachable!(),
                    })
                    .collect();
                let mut equal_pairs = 0usize;
                let pair_count = normalized.len() * (normalized.len() - 1) / 2;
                for left in 0..normalized.len() {
                    for right in (left + 1)..normalized.len() {
                        if normalized[left] == normalized[right] {
                            equal_pairs += 1;
                        }
                    }
                }
                let score = equal_pairs as f32 / pair_count as f32;
                if score == 1.0 {
                    (DimensionState::Scored, Some(score))
                } else {
                    (DimensionState::Disagreed, Some(score))
                }
            }
        };
        if let Some(value) = score {
            weighted_sum += dimension.weight() * value;
            weights += dimension.weight();
        }
        if !matches!(
            state,
            DimensionState::Scored | DimensionState::NotApplicable
        ) || score == Some(0.0)
        {
            identical = false;
        }
        dimensions.push(DimensionAgreement {
            dimension,
            state,
            participating_roles: roles,
            missing_roles,
            missing_reason,
            score,
        });
    }
    let weighted_score = (weights > 0.0).then(|| weighted_sum / weights);
    AgreementReport {
        protocol: PROTOCOL.into(),
        textual_identity: identical && weighted_score == Some(1.0),
        weighted_score,
        dimensions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn envelope(fact: &str, recommendation: &str, risk: &str) -> String {
        format!(
            "answer\n[NEOTH_AGREEMENT_V1]\nfactual_claims: {fact}\nrecommendations: {recommendation}\nrisk_assessment: {risk}\n[/NEOTH_AGREEMENT_V1]"
        )
    }

    #[test]
    fn invalid_shapes_and_oversized_values_remain_missing() {
        let valid = envelope("fact", "act", "risk");
        for invalid in [
            valid.replace("recommendations: act\n", ""),
            valid.replace("recommendations: act", "factual_claims: act"),
            valid.replace(
                "factual_claims: fact\nrecommendations: act",
                "recommendations: act\nfactual_claims: fact",
            ),
            valid.replace(
                "risk_assessment: risk",
                "risk_assessment: risk\nextra: value",
            ),
            envelope("   ", "act", "risk"),
            envelope(&"x".repeat(MAX_STATEMENT_BYTES + 1), "act", "risk"),
            format!("{valid}\ntrailing prose"),
        ] {
            let parsed = parse_final_suffix(&invalid);
            assert_eq!(parsed.body, "answer");
            assert!(
                parsed
                    .values
                    .iter()
                    .all(|v| matches!(v, DeclaredValue::Missing(_)))
            );
        }
        assert!(
            parse_final_suffix("ordinary answer")
                .values
                .iter()
                .all(|v| matches!(v, DeclaredValue::Missing(ParseReason::Absent)))
        );
        assert_eq!(
            parse_final_suffix(&valid.replace('\n', "\r\n")).body,
            "answer"
        );
        assert!(matches!(
            parse_final_suffix(&envelope(&"x".repeat(MAX_STATEMENT_BYTES), "NONE", "NONE")).values
                [0],
            DeclaredValue::Statement(_)
        ));
    }

    #[test]
    fn weighted_dimensions_and_missing_evidence_have_distinct_states() {
        let first = parse_final_suffix(&envelope("fact", "act", "risk")).values;
        let second = parse_final_suffix(&envelope("fact", "other", "risk")).values;
        let report = evaluate(&[
            (HemisphereRole::Left, true, first.clone()),
            (HemisphereRole::Right, true, second),
        ]);
        assert!((report.weighted_score.unwrap() - 0.7).abs() < f32::EPSILON);
        assert!(!report.textual_identity);
        let missing = parse_final_suffix("ordinary answer").values;
        let report = evaluate(&[
            (HemisphereRole::Left, true, first),
            (HemisphereRole::Right, true, missing),
        ]);
        assert!(
            report
                .dimensions
                .iter()
                .all(|d| d.state == DimensionState::Missing && d.score.is_none())
        );
        assert_eq!(report.weighted_score, None);
        let none = parse_final_suffix(&envelope("NONE", "NONE", "NONE")).values;
        let report = evaluate(&[
            (HemisphereRole::Left, true, none.clone()),
            (HemisphereRole::Right, true, none),
        ]);
        assert!(!report.textual_identity);
        assert_eq!(report.weighted_score, None);
        assert!(
            report
                .dimensions
                .iter()
                .all(|d| d.state == DimensionState::NotApplicable)
        );
    }

    #[test]
    fn report_is_independent_of_completion_order() {
        let values = parse_final_suffix(&envelope("fact", "act", "risk")).values;
        let mut responses = vec![
            (HemisphereRole::Left, true, values.clone()),
            (HemisphereRole::Right, true, values.clone()),
            (HemisphereRole::Cerebellum, true, values),
        ];
        let expected = serde_json::to_value(evaluate(&responses)).unwrap();
        responses.reverse();
        assert_eq!(
            serde_json::to_value(evaluate(&responses)).unwrap(),
            expected
        );
        for (left, right) in [
            ("keep backup", "preserve backup"),
            ("a, b", "a b"),
            ("step 1 then 2", "step 2 then 1"),
        ] {
            assert_ne!(normalized_identity(left), normalized_identity(right));
        }
    }
    #[test]
    fn parser_strips_only_final_valid_block() {
        let p = parse_final_suffix(
            "answer\n[NEOTH_AGREEMENT_V1]\nfactual_claims: A  2.\nrecommendations: NONE\nrisk_assessment: Low.\n[/NEOTH_AGREEMENT_V1]",
        );
        assert_eq!(p.body, "answer");
        assert!(matches!(p.values[1], DeclaredValue::NotApplicable));
    }
    #[test]
    fn identity_preserves_meaningful_tokens() {
        assert_eq!(normalized_identity("A  B"), normalized_identity("a b"));
        assert_ne!(
            normalized_identity("do delete 2."),
            normalized_identity("do not delete 2.")
        );
        assert_ne!(normalized_identity("2."), normalized_identity("3."));
        assert_ne!(normalized_identity("a, b"), normalized_identity("b, a"));
    }
    #[test]
    fn malformed_or_duplicate_suffix_never_leaks() {
        for text in [
            "body\n[NEOTH_AGREEMENT_V1]\nfactual_claims: x",
            "body\n[NEOTH_AGREEMENT_V1]\nfactual_claims: x\nrecommendations: y\nrisk_assessment: z\n[/NEOTH_AGREEMENT_V1]\ntrailing",
            "body\n[NEOTH_AGREEMENT_V1]\nfactual_claims: x\nrecommendations: y\nrisk_assessment: z\n[/NEOTH_AGREEMENT_V1]\n[NEOTH_AGREEMENT_V1]",
            "body\n[/NEOTH_AGREEMENT_V1]\n[NEOTH_AGREEMENT_V1]\nfactual_claims: x\nrecommendations: y\nrisk_assessment: z\n[/NEOTH_AGREEMENT_V1]",
        ] {
            let p = parse_final_suffix(text);
            assert!(!p.body.contains("NEOTH_AGREEMENT_V1"));
            assert!(matches!(p.values[0], DeclaredValue::Missing(_)));
        }
    }
    #[test]
    fn formula_renormalizes_and_mixed_none_disagrees() {
        let same = |s: &str| {
            [
                DeclaredValue::Statement(s.into()),
                DeclaredValue::NotApplicable,
                DeclaredValue::Statement("risk".into()),
            ]
        };
        let report = evaluate(&[
            (HemisphereRole::Left, true, same("fact")),
            (HemisphereRole::Right, true, same("fact")),
        ]);
        assert_eq!(report.weighted_score, Some(1.0));
        assert!(report.textual_identity);
        let mixed = evaluate(&[
            (HemisphereRole::Left, true, same("fact")),
            (
                HemisphereRole::Right,
                true,
                [
                    DeclaredValue::Statement("fact".into()),
                    DeclaredValue::Statement("act".into()),
                    DeclaredValue::Statement("risk".into()),
                ],
            ),
        ]);
        assert!(!mixed.textual_identity);
        assert_eq!(mixed.dimensions[1].score, Some(0.0));
        let third = evaluate(&[
            (HemisphereRole::Left, true, same("fact")),
            (HemisphereRole::Right, true, same("fact")),
            (HemisphereRole::Cerebellum, true, same("other")),
        ]);
        assert_eq!(third.dimensions[0].score, Some(1.0 / 3.0));
        assert!(!third.textual_identity);
    }
}
