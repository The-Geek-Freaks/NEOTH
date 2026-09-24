//! GOLD-LF-P1-08 — offline response-pair preparation for four-grader review.
//!
//! Operators supply the actual two-system answers and rubric text. This module
//! validates complete goldset coverage, then creates deterministic grader input
//! documents and the existing batch-plan digest file. It never calls a model,
//! writes a run, or accepts grades.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{
    goldset::{
        EXPECTED_GOLDSET_QUERIES, GoldsetEntry, GradedSystem, ValidatedGraderConfigFile,
        validate_goldset_contract,
    },
    parity_batch_plan::{
        FOUR_GRADER_BATCH_INPUT_PURPOSE, FOUR_GRADER_BATCH_SCHEMA_VERSION, FOUR_GRADER_COUNT,
        FourGraderInputDigest, FourGraderInputDigestFile,
    },
};

pub const RESPONSE_PAIR_SCHEMA_VERSION: u32 = 1;
pub const RESPONSE_PAIR_PURPOSE: &str = "neoth-recall-parity-response-pairs/v1";
pub const GRADER_INPUT_SCHEMA_VERSION: u32 = 1;
pub const GRADER_INPUT_PURPOSE: &str = "neoth-recall-parity-grader-input/v1";
pub const MAX_RESPONSE_PAIR_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_RUBRIC_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponsePairFile {
    pub schema_version: u32,
    pub purpose: String,
    pub goldset_sha256: String,
    pub responses: Vec<ResponsePair>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponsePair {
    pub query_id: String,
    pub system: GradedSystem,
    pub response: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GraderInputFile {
    pub schema_version: u32,
    pub purpose: String,
    pub grader_id: String,
    pub goldset_sha256: String,
    pub rubric: String,
    pub pairs: Vec<GraderInputPair>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GraderInputPair {
    pub query_id: String,
    pub system: GradedSystem,
    pub query_text: String,
    pub response: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedGraderInputs {
    pub inputs: Vec<(String, Vec<u8>)>,
    pub digests: FourGraderInputDigestFile,
}

pub fn prepare_grader_inputs(
    response_bytes: &[u8],
    rubric_bytes: &[u8],
    goldset: &[GoldsetEntry],
    goldset_bytes: &[u8],
    config: &ValidatedGraderConfigFile,
) -> Result<PreparedGraderInputs> {
    if response_bytes.len() > MAX_RESPONSE_PAIR_BYTES {
        anyhow::bail!("response-pair input exceeds bounded byte limit");
    }
    if rubric_bytes.is_empty() || rubric_bytes.len() > MAX_RUBRIC_BYTES {
        anyhow::bail!("grader rubric input is empty or exceeds bounded byte limit");
    }
    let rubric = std::str::from_utf8(rubric_bytes)
        .context("decode explicit grader rubric as UTF-8")?
        .to_owned();
    let responses: ResponsePairFile = serde_json::from_slice(response_bytes)
        .map_err(|_| anyhow::anyhow!("parse response-pair input"))?;
    validate_goldset_contract(goldset)?;
    let goldset_sha256 = sha256_bytes(goldset_bytes);
    if responses.schema_version != RESPONSE_PAIR_SCHEMA_VERSION
        || responses.purpose != RESPONSE_PAIR_PURPOSE
        || responses.goldset_sha256 != goldset_sha256
    {
        anyhow::bail!("response-pair input does not bind the supplied canonical goldset");
    }
    let pairs = canonical_pairs(&responses.responses, goldset)?;
    if config.graders().len() != FOUR_GRADER_COUNT {
        anyhow::bail!("grader inputs require exactly four validated graders");
    }
    let prompt_sha256 = sha256_bytes(rubric_bytes);
    let mut graders = config.graders().iter().collect::<Vec<_>>();
    graders.sort_by(|left, right| left.grader_id.cmp(&right.grader_id));
    let mut inputs = Vec::with_capacity(FOUR_GRADER_COUNT);
    let mut digests = Vec::with_capacity(FOUR_GRADER_COUNT);
    for grader in graders {
        let input = GraderInputFile {
            schema_version: GRADER_INPUT_SCHEMA_VERSION,
            purpose: GRADER_INPUT_PURPOSE.into(),
            grader_id: grader.grader_id.clone(),
            goldset_sha256: goldset_sha256.clone(),
            rubric: rubric.clone(),
            pairs: pairs.clone(),
        };
        let bytes = serde_json::to_vec(&input).context("serialize canonical grader input")?;
        digests.push(FourGraderInputDigest {
            grader_id: grader.grader_id.clone(),
            prompt_sha256: prompt_sha256.clone(),
            input_sha256: sha256_bytes(&bytes),
        });
        inputs.push((grader.grader_id.clone(), bytes));
    }
    Ok(PreparedGraderInputs {
        inputs,
        digests: FourGraderInputDigestFile {
            schema_version: FOUR_GRADER_BATCH_SCHEMA_VERSION,
            purpose: FOUR_GRADER_BATCH_INPUT_PURPOSE.into(),
            inputs: digests,
        },
    })
}

fn canonical_pairs(
    responses: &[ResponsePair],
    goldset: &[GoldsetEntry],
) -> Result<Vec<GraderInputPair>> {
    if responses.len() != EXPECTED_GOLDSET_QUERIES * 2 {
        anyhow::bail!(
            "response-pair input must contain exactly two answers for every goldset query"
        );
    }
    let queries = goldset
        .iter()
        .map(|entry| (entry.query_id.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let mut found = BTreeSet::new();
    let mut by_key = BTreeMap::new();
    for response in responses {
        let key = (response.query_id.as_str(), system_name(response.system));
        if !queries.contains_key(response.query_id.as_str()) || !found.insert(key) {
            anyhow::bail!("response-pair input contains an unknown or duplicate query/system pair");
        }
        by_key.insert(key, response.response.as_str());
    }
    let mut pairs = Vec::with_capacity(responses.len());
    for (query_id, entry) in queries {
        for system in [GradedSystem::Neoth, GradedSystem::Reference] {
            let response = by_key.get(&(query_id, system_name(system))).context(
                "response-pair input does not cover the complete goldset × two-system matrix",
            )?;
            pairs.push(GraderInputPair {
                query_id: query_id.into(),
                system,
                query_text: entry.query_text.clone(),
                response: (*response).into(),
            });
        }
    }
    Ok(pairs)
}

fn system_name(system: GradedSystem) -> &'static str {
    match system {
        GradedSystem::Neoth => "neoth",
        GradedSystem::Reference => "reference",
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recall::goldset::{
        GoldsetCategory, GraderConfig, GraderConfigFile, GraderFamily, GraderProvider,
    };

    fn goldset() -> Vec<GoldsetEntry> {
        (0..EXPECTED_GOLDSET_QUERIES)
            .map(|index| GoldsetEntry {
                query_id: format!("q{index:03}"),
                query_text: format!("query {index}"),
                category: GoldsetCategory::Recall,
                expected_sources: Vec::new(),
                expected_response: String::new(),
            })
            .collect()
    }
    fn config() -> ValidatedGraderConfigFile {
        GraderConfigFile {
            schema_version: 1,
            graders: vec![
                GraderConfig {
                    grader_id: "a".into(),
                    provider: GraderProvider::Anthropic,
                    model_id: "a".into(),
                    family: GraderFamily::AnthropicOpenaiGoogle,
                },
                GraderConfig {
                    grader_id: "b".into(),
                    provider: GraderProvider::Openai,
                    model_id: "b".into(),
                    family: GraderFamily::AnthropicOpenaiGoogle,
                },
                GraderConfig {
                    grader_id: "c".into(),
                    provider: GraderProvider::Google,
                    model_id: "c".into(),
                    family: GraderFamily::AnthropicOpenaiGoogle,
                },
                GraderConfig {
                    grader_id: "d".into(),
                    provider: GraderProvider::Mistral,
                    model_id: "d".into(),
                    family: GraderFamily::IndependentExternal,
                },
            ],
        }
        .into_validated()
        .unwrap()
    }

    #[test]
    fn response_pairs_produce_actual_four_grader_inputs_and_batch_digests() {
        let goldset = goldset();
        let responses = goldset
            .iter()
            .flat_map(|entry| {
                [
                    ResponsePair {
                        query_id: entry.query_id.clone(),
                        system: GradedSystem::Neoth,
                        response: "neoth response".into(),
                    },
                    ResponsePair {
                        query_id: entry.query_id.clone(),
                        system: GradedSystem::Reference,
                        response: "reference response".into(),
                    },
                ]
            })
            .collect();
        let goldset_bytes = serde_json::to_vec(&goldset).unwrap();
        let source = ResponsePairFile {
            schema_version: RESPONSE_PAIR_SCHEMA_VERSION,
            purpose: RESPONSE_PAIR_PURPOSE.into(),
            goldset_sha256: sha256_bytes(&goldset_bytes),
            responses,
        };
        let prepared = prepare_grader_inputs(
            &serde_json::to_vec(&source).unwrap(),
            b"score every pair",
            &goldset,
            &goldset_bytes,
            &config(),
        )
        .unwrap();
        assert_eq!(prepared.inputs.len(), FOUR_GRADER_COUNT);
        assert_eq!(prepared.digests.inputs.len(), FOUR_GRADER_COUNT);
        assert!(prepared.inputs.iter().all(|(_, input)| !input.is_empty()));
        assert!(
            prepared
                .digests
                .inputs
                .iter()
                .all(|input| input.prompt_sha256 == sha256_bytes(b"score every pair"))
        );
        for ((grader_id, bytes), digest) in prepared.inputs.iter().zip(&prepared.digests.inputs) {
            assert_eq!(grader_id, &digest.grader_id);
            assert_eq!(sha256_bytes(bytes), digest.input_sha256);
            let input: serde_json::Value = serde_json::from_slice(bytes).unwrap();
            assert_eq!(
                input["pairs"].as_array().unwrap().len(),
                EXPECTED_GOLDSET_QUERIES * 2
            );
            assert_eq!(input["pairs"][0]["query_text"], "query 0");
            assert_eq!(input["pairs"][0]["response"], "neoth response");
        }
        let mut reversed = source.clone();
        reversed.responses.reverse();
        let reordered = prepare_grader_inputs(
            &serde_json::to_vec(&reversed).unwrap(),
            b"score every pair",
            &goldset,
            &goldset_bytes,
            &config(),
        )
        .unwrap();
        assert_eq!(prepared.inputs, reordered.inputs);
        assert_eq!(prepared.digests, reordered.digests);
    }

    #[test]
    fn response_pairs_reject_partial_or_mismatched_goldset_matrix() {
        let goldset = goldset();
        let goldset_bytes = serde_json::to_vec(&goldset).unwrap();
        let source = ResponsePairFile {
            schema_version: RESPONSE_PAIR_SCHEMA_VERSION,
            purpose: RESPONSE_PAIR_PURPOSE.into(),
            goldset_sha256: sha256_bytes(&goldset_bytes),
            responses: Vec::new(),
        };
        assert!(
            prepare_grader_inputs(
                &serde_json::to_vec(&source).unwrap(),
                b"rubric",
                &goldset,
                &goldset_bytes,
                &config()
            )
            .is_err()
        );
        let mismatched = ResponsePairFile {
            goldset_sha256: "0".repeat(64),
            ..source
        };
        assert!(
            prepare_grader_inputs(
                &serde_json::to_vec(&mismatched).unwrap(),
                b"rubric",
                &goldset,
                &goldset_bytes,
                &config()
            )
            .is_err()
        );
    }

    #[test]
    fn response_pairs_distinguish_empty_observations_from_missing_unknown_and_duplicate_pairs() {
        let goldset = goldset();
        let goldset_bytes = serde_json::to_vec(&goldset).unwrap();
        let responses = goldset
            .iter()
            .flat_map(|entry| {
                [
                    ResponsePair {
                        query_id: entry.query_id.clone(),
                        system: GradedSystem::Neoth,
                        response: String::new(),
                    },
                    ResponsePair {
                        query_id: entry.query_id.clone(),
                        system: GradedSystem::Reference,
                        response: "reference".into(),
                    },
                ]
            })
            .collect::<Vec<_>>();
        let source = ResponsePairFile {
            schema_version: RESPONSE_PAIR_SCHEMA_VERSION,
            purpose: RESPONSE_PAIR_PURPOSE.into(),
            goldset_sha256: sha256_bytes(&goldset_bytes),
            responses,
        };
        assert!(
            prepare_grader_inputs(
                &serde_json::to_vec(&source).unwrap(),
                b"rubric",
                &goldset,
                &goldset_bytes,
                &config()
            )
            .is_ok()
        );
        let mut missing = source.clone();
        missing.responses.pop();
        assert!(
            prepare_grader_inputs(
                &serde_json::to_vec(&missing).unwrap(),
                b"rubric",
                &goldset,
                &goldset_bytes,
                &config()
            )
            .is_err()
        );
        let mut duplicate = source.clone();
        duplicate.responses[1] = duplicate.responses[0].clone();
        assert!(
            prepare_grader_inputs(
                &serde_json::to_vec(&duplicate).unwrap(),
                b"rubric",
                &goldset,
                &goldset_bytes,
                &config()
            )
            .is_err()
        );
        let mut unknown = source;
        unknown.responses[0].query_id = "unknown".into();
        assert!(
            prepare_grader_inputs(
                &serde_json::to_vec(&unknown).unwrap(),
                b"rubric",
                &goldset,
                &goldset_bytes,
                &config()
            )
            .is_err()
        );
    }
}
