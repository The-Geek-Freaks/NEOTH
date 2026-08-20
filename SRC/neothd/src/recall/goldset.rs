//! ARCH-05 / SPEC-08 — recall-parity goldset + grade file formats.
//!
//! The on-disk contract (JSONL) between the operator's grading run and the pure
//! [`super::parity`] scorer. A `goldset.jsonl` is the 100-query evaluation set;
//! `grades-<grader>.jsonl` files carry each grader's 0–5 Likert scores per
//! (query, system). Loading validates the Likert range fail-closed so a
//! malformed grade can't silently skew the gate.

use std::{collections::HashSet, fs::File, io::Read, path::Path};

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

/// Version of the persisted recall-parity grader configuration contract.
pub const GRADER_CONFIG_SCHEMA_VERSION: u32 = 1;

/// Maximum accepted byte length for a persisted grader configuration file.
pub const MAX_GRADER_CONFIG_BYTES: u64 = 64 * 1024;

/// Maximum number of configured graders in one persisted roster.
pub const MAX_GRADERS: usize = 64;

/// The LLM provider backing a recall-parity grader.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraderProvider {
    Anthropic,
    Openai,
    Google,
    Mistral,
    Deepseek,
    Qwen,
}

impl GraderProvider {
    const fn is_independent_external(self) -> bool {
        matches!(self, Self::Mistral | Self::Deepseek | Self::Qwen)
    }

    const fn required_family(self) -> GraderFamily {
        if self.is_independent_external() {
            GraderFamily::IndependentExternal
        } else {
            GraderFamily::AnthropicOpenaiGoogle
        }
    }
}

/// Independence family used for recall-parity grader diversity requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraderFamily {
    AnthropicOpenaiGoogle,
    IndependentExternal,
}

/// One explicitly configured recall-parity grader.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraderConfig {
    pub grader_id: String,
    pub provider: GraderProvider,
    pub model_id: String,
    pub family: GraderFamily,
}

impl GraderConfig {
    /// Whether this grader's provider belongs to the independent external family.
    ///
    /// This is derived from the provider, never from the persisted `family`
    /// field, so an unvalidated wire value cannot assert independence.
    pub const fn is_independent_external(&self) -> bool {
        self.provider.is_independent_external()
    }
}

/// Versioned on-disk recall-parity grader configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraderConfigFile {
    pub schema_version: u32,
    pub graders: Vec<GraderConfig>,
}

/// A grader configuration that passed every fail-closed contract invariant.
///
/// Fields are intentionally private: parity scoring receives this type rather
/// than raw wire data, and can only inspect its immutable roster.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedGraderConfigFile {
    schema_version: u32,
    graders: Vec<GraderConfig>,
}

impl ValidatedGraderConfigFile {
    /// The validated schema version.
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// The immutable, validated grader roster.
    pub fn graders(&self) -> &[GraderConfig] {
        &self.graders
    }
}

/// Fail-closed validation errors for [`GraderConfigFile`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GraderConfigError {
    #[error("unsupported grader configuration schema version {found}; expected {expected}")]
    UnsupportedSchemaVersion { found: u32, expected: u32 },
    #[error("grader configuration contains no graders")]
    EmptyConfig,
    #[error("grader configuration has {found} graders; maximum is {max}")]
    TooManyGraders { found: usize, max: usize },
    #[error("grader configuration exceeds the {max_bytes}-byte limit")]
    ConfigTooLarge { max_bytes: u64 },
    #[error("invalid grader id {grader_id:?}")]
    InvalidGraderId { grader_id: String },
    #[error("invalid model id for grader {grader_id:?}")]
    InvalidModelId { grader_id: String, model_id: String },
    #[error("duplicate grader id {grader_id:?}")]
    DuplicateGraderId { grader_id: String },
    #[error("grader {grader_id:?} duplicates an existing provider/model pair")]
    DuplicateProviderModel { grader_id: String },
    #[error(
        "grader {grader_id:?} provider {provider:?} must use family {expected:?}, not {family:?}"
    )]
    FamilyProviderMismatch {
        grader_id: String,
        provider: GraderProvider,
        family: GraderFamily,
        expected: GraderFamily,
    },
    #[error("grader configuration has no shared-family grader")]
    MissingSharedFamily,
    #[error("grader configuration has no independent external grader")]
    MissingIndependentExternalFamily,
}

impl GraderConfigFile {
    /// Validate the versioned grader roster before it can enter the parity gate.
    fn validate(&self) -> std::result::Result<(), GraderConfigError> {
        if self.schema_version != GRADER_CONFIG_SCHEMA_VERSION {
            return Err(GraderConfigError::UnsupportedSchemaVersion {
                found: self.schema_version,
                expected: GRADER_CONFIG_SCHEMA_VERSION,
            });
        }
        if self.graders.is_empty() {
            return Err(GraderConfigError::EmptyConfig);
        }
        if self.graders.len() > MAX_GRADERS {
            return Err(GraderConfigError::TooManyGraders {
                found: self.graders.len(),
                max: MAX_GRADERS,
            });
        }

        let mut grader_ids = HashSet::with_capacity(self.graders.len());
        let mut provider_models = HashSet::with_capacity(self.graders.len());
        let mut has_shared_family = false;
        let mut has_independent_external_family = false;
        for grader in &self.graders {
            if !is_valid_grader_id(&grader.grader_id) {
                return Err(GraderConfigError::InvalidGraderId {
                    grader_id: grader.grader_id.clone(),
                });
            }
            if !is_valid_model_id(&grader.model_id) {
                return Err(GraderConfigError::InvalidModelId {
                    grader_id: grader.grader_id.clone(),
                    model_id: grader.model_id.clone(),
                });
            }
            if !grader_ids.insert(grader.grader_id.as_str()) {
                return Err(GraderConfigError::DuplicateGraderId {
                    grader_id: grader.grader_id.clone(),
                });
            }
            if !provider_models.insert((grader.provider, grader.model_id.as_str())) {
                return Err(GraderConfigError::DuplicateProviderModel {
                    grader_id: grader.grader_id.clone(),
                });
            }

            let expected = grader.provider.required_family();
            if grader.family != expected {
                return Err(GraderConfigError::FamilyProviderMismatch {
                    grader_id: grader.grader_id.clone(),
                    provider: grader.provider,
                    family: grader.family,
                    expected,
                });
            }
            if grader.is_independent_external() {
                has_independent_external_family = true;
            } else {
                has_shared_family = true;
            }
        }
        if !has_shared_family {
            return Err(GraderConfigError::MissingSharedFamily);
        }
        if !has_independent_external_family {
            return Err(GraderConfigError::MissingIndependentExternalFamily);
        }
        Ok(())
    }

    /// Consume raw wire data and make it available to parity scoring only after
    /// all persisted-contract invariants have passed.
    pub fn into_validated(
        self,
    ) -> std::result::Result<ValidatedGraderConfigFile, GraderConfigError> {
        ValidatedGraderConfigFile::try_from(self)
    }
}

impl TryFrom<GraderConfigFile> for ValidatedGraderConfigFile {
    type Error = GraderConfigError;

    fn try_from(value: GraderConfigFile) -> std::result::Result<Self, Self::Error> {
        value.validate()?;
        Ok(Self {
            schema_version: value.schema_version,
            graders: value.graders,
        })
    }
}

fn is_valid_grader_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=64).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn is_valid_model_id(value: &str) -> bool {
    let trimmed = value.trim();
    value == trimmed
        && (1..=128).contains(&trimmed.len())
        && value.as_bytes().iter().any(u8::is_ascii_alphanumeric)
        && value.as_bytes().iter().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b'-' | b'/' | b':' | b'@' | b'+')
        })
        && !value.as_bytes().iter().any(u8::is_ascii_control)
}

/// Load, parse, and validate a versioned recall-parity grader configuration.
pub fn load_grader_config(path: &Path) -> Result<ValidatedGraderConfigFile> {
    let mut bytes = Vec::with_capacity(MAX_GRADER_CONFIG_BYTES as usize + 1);
    let mut reader = File::open(path)
        .with_context(|| format!("open grader config {}", path.display()))?
        .take(MAX_GRADER_CONFIG_BYTES + 1);
    reader
        .read_to_end(&mut bytes)
        .with_context(|| format!("read grader config {}", path.display()))?;
    if bytes.len() as u64 > MAX_GRADER_CONFIG_BYTES {
        return Err(GraderConfigError::ConfigTooLarge {
            max_bytes: MAX_GRADER_CONFIG_BYTES,
        }
        .into());
    }
    let config: GraderConfigFile = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse grader config {}", path.display()))?;
    config
        .into_validated()
        .with_context(|| format!("validate grader config {}", path.display()))
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

    fn grader(
        grader_id: &str,
        provider: GraderProvider,
        model_id: &str,
        family: GraderFamily,
    ) -> GraderConfig {
        GraderConfig {
            grader_id: grader_id.into(),
            provider,
            model_id: model_id.into(),
            family,
        }
    }

    fn valid_grader_config() -> GraderConfigFile {
        GraderConfigFile {
            schema_version: GRADER_CONFIG_SCHEMA_VERSION,
            graders: vec![
                grader(
                    "primary",
                    GraderProvider::Anthropic,
                    "anthropic/claude-sonnet-4:2026@stable+1",
                    GraderFamily::AnthropicOpenaiGoogle,
                ),
                grader(
                    "external",
                    GraderProvider::Mistral,
                    "mistral-large",
                    GraderFamily::IndependentExternal,
                ),
            ],
        }
    }

    fn write_grader_config(
        dir: &tempfile::TempDir,
        value: &serde_json::Value,
    ) -> std::path::PathBuf {
        let path = dir.path().join("graders.json");
        std::fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
        path
    }

    #[test]
    fn grader_config_v1_parses_validates_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let expected = valid_grader_config();
        let value = serde_json::to_value(&expected).unwrap();
        let path = write_grader_config(&dir, &value);

        let loaded: ValidatedGraderConfigFile = load_grader_config(&path).unwrap();
        assert_eq!(loaded.schema_version(), expected.schema_version);
        assert_eq!(loaded.graders(), expected.graders.as_slice());
        assert!(!loaded.graders()[0].is_independent_external());
        assert_eq!(
            serde_json::from_value::<GraderConfigFile>(value).unwrap(),
            expected
        );
    }

    #[test]
    fn grader_config_rejects_missing_unknown_fields_and_unknown_tags() {
        let dir = tempfile::tempdir().unwrap();
        let cases = [
            serde_json::json!({"schema_version": 1}),
            serde_json::json!({
                "schema_version": 1,
                "graders": [{
                    "grader_id": "a",
                    "provider": "anthropic",
                    "model_id": "m",
                }],
            }),
            serde_json::json!({
                "schema_version": 1,
                "graders": [],
                "unexpected": true,
            }),
            serde_json::json!({
                "schema_version": 1,
                "graders": [{
                    "grader_id": "a",
                    "provider": "anthropic",
                    "model_id": "m",
                    "family": "anthropic_openai_google",
                    "unexpected": true,
                }],
            }),
            serde_json::json!({
                "schema_version": 1,
                "graders": [{
                    "grader_id": "a",
                    "provider": "unknown",
                    "model_id": "m",
                    "family": "anthropic_openai_google",
                }],
            }),
            serde_json::json!({
                "schema_version": 1,
                "graders": [{
                    "grader_id": "a",
                    "provider": "anthropic",
                    "model_id": "m",
                    "family": "unknown",
                }],
            }),
        ];

        for (index, value) in cases.iter().enumerate() {
            let path = write_grader_config(&dir, value);
            assert!(
                load_grader_config(&path).is_err(),
                "case {} must fail closed",
                index
            );
        }
    }

    #[test]
    fn grader_config_rejects_unsupported_version_and_empty_config() {
        let dir = tempfile::tempdir().unwrap();
        let mut unsupported = valid_grader_config();
        unsupported.schema_version = GRADER_CONFIG_SCHEMA_VERSION + 1;
        let path = write_grader_config(&dir, &serde_json::to_value(unsupported).unwrap());
        assert!(matches!(
            load_grader_config(&path).unwrap_err().downcast_ref(),
            Some(GraderConfigError::UnsupportedSchemaVersion { .. })
        ));

        let empty = GraderConfigFile {
            schema_version: GRADER_CONFIG_SCHEMA_VERSION,
            graders: Vec::new(),
        };
        let path = write_grader_config(&dir, &serde_json::to_value(empty).unwrap());
        assert!(matches!(
            load_grader_config(&path).unwrap_err().downcast_ref(),
            Some(GraderConfigError::EmptyConfig)
        ));
    }

    #[test]
    fn grader_config_rejects_invalid_and_duplicate_ids() {
        let dir = tempfile::tempdir().unwrap();
        let too_long = "a".repeat(65);
        for id in ["", "-bad", "with space", "\u{00E4}", too_long.as_str()] {
            let mut invalid = valid_grader_config();
            invalid.graders[0].grader_id = id.into();
            let path = write_grader_config(&dir, &serde_json::to_value(invalid).unwrap());
            assert!(matches!(
                load_grader_config(&path).unwrap_err().downcast_ref(),
                Some(GraderConfigError::InvalidGraderId { .. })
            ));
        }

        let mut duplicate = valid_grader_config();
        duplicate.graders.push(grader(
            "primary",
            GraderProvider::Google,
            "gemini-2.5-pro",
            GraderFamily::AnthropicOpenaiGoogle,
        ));
        let path = write_grader_config(&dir, &serde_json::to_value(duplicate).unwrap());
        assert!(matches!(
            load_grader_config(&path).unwrap_err().downcast_ref(),
            Some(GraderConfigError::DuplicateGraderId { grader_id }) if grader_id == "primary"
        ));

        let mut duplicate_provider_model = valid_grader_config();
        duplicate_provider_model.graders.push(grader(
            "different-id",
            GraderProvider::Anthropic,
            "anthropic/claude-sonnet-4:2026@stable+1",
            GraderFamily::AnthropicOpenaiGoogle,
        ));
        let path = write_grader_config(
            &dir,
            &serde_json::to_value(duplicate_provider_model).unwrap(),
        );
        assert!(matches!(
            load_grader_config(&path).unwrap_err().downcast_ref(),
            Some(GraderConfigError::DuplicateProviderModel { grader_id })
                if grader_id == "different-id"
        ));
    }

    #[test]
    fn grader_config_rejects_invalid_model_ids() {
        let dir = tempfile::tempdir().unwrap();
        let too_long = "a".repeat(129);
        for model_id in [
            "",
            " \t ",
            " claude-sonnet-4",
            "claude-sonnet-4 ",
            "model name",
            "m\u{200B}odel",
            "model\u{2010}id",
            "///",
            "model\nname",
            too_long.as_str(),
        ] {
            let mut invalid = valid_grader_config();
            invalid.graders[0].model_id = model_id.into();
            let path = write_grader_config(&dir, &serde_json::to_value(invalid).unwrap());
            assert!(matches!(
                load_grader_config(&path).unwrap_err().downcast_ref(),
                Some(GraderConfigError::InvalidModelId { .. })
            ));
        }
    }

    #[test]
    fn grader_config_rejects_every_provider_family_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        for provider in [
            GraderProvider::Anthropic,
            GraderProvider::Openai,
            GraderProvider::Google,
            GraderProvider::Mistral,
            GraderProvider::Deepseek,
            GraderProvider::Qwen,
        ] {
            let family = if provider.is_independent_external() {
                GraderFamily::AnthropicOpenaiGoogle
            } else {
                GraderFamily::IndependentExternal
            };
            let invalid = GraderConfigFile {
                schema_version: GRADER_CONFIG_SCHEMA_VERSION,
                graders: vec![grader("g", provider, "model", family)],
            };
            let path = write_grader_config(&dir, &serde_json::to_value(invalid).unwrap());
            assert!(matches!(
                load_grader_config(&path).unwrap_err().downcast_ref(),
                Some(GraderConfigError::FamilyProviderMismatch {
                    provider: found,
                    ..
                }) if *found == provider
            ));
        }
    }

    #[test]
    fn grader_config_accepts_the_complete_six_provider_matrix() {
        let config = GraderConfigFile {
            schema_version: GRADER_CONFIG_SCHEMA_VERSION,
            graders: vec![
                grader(
                    "anthropic",
                    GraderProvider::Anthropic,
                    "claude",
                    GraderFamily::AnthropicOpenaiGoogle,
                ),
                grader(
                    "openai",
                    GraderProvider::Openai,
                    "gpt",
                    GraderFamily::AnthropicOpenaiGoogle,
                ),
                grader(
                    "google",
                    GraderProvider::Google,
                    "gemini",
                    GraderFamily::AnthropicOpenaiGoogle,
                ),
                grader(
                    "mistral",
                    GraderProvider::Mistral,
                    "mistral-large",
                    GraderFamily::IndependentExternal,
                ),
                grader(
                    "deepseek",
                    GraderProvider::Deepseek,
                    "deepseek-r1",
                    GraderFamily::IndependentExternal,
                ),
                grader(
                    "qwen",
                    GraderProvider::Qwen,
                    "qwen3",
                    GraderFamily::IndependentExternal,
                ),
            ],
        };

        let validated = config.into_validated().unwrap();
        assert_eq!(
            validated
                .graders()
                .iter()
                .filter(|grader| grader.is_independent_external())
                .count(),
            3
        );
    }

    #[test]
    fn grader_config_requires_both_independence_families() {
        let mut shared_only = valid_grader_config();
        shared_only.graders.retain(|grader| !grader.is_independent_external());
        assert!(matches!(
            shared_only.into_validated(),
            Err(GraderConfigError::MissingIndependentExternalFamily)
        ));

        let external_only = GraderConfigFile {
            schema_version: GRADER_CONFIG_SCHEMA_VERSION,
            graders: vec![grader(
                "external-only",
                GraderProvider::Deepseek,
                "deepseek-r1",
                GraderFamily::IndependentExternal,
            )],
        };
        assert!(matches!(
            external_only.into_validated(),
            Err(GraderConfigError::MissingSharedFamily)
        ));
    }

    #[test]
    fn raw_family_mismatch_cannot_become_validated() {
        let raw = GraderConfigFile {
            schema_version: GRADER_CONFIG_SCHEMA_VERSION,
            graders: vec![
                grader(
                    "shared",
                    GraderProvider::Anthropic,
                    "claude",
                    GraderFamily::IndependentExternal,
                ),
                grader(
                    "external",
                    GraderProvider::Mistral,
                    "mistral-large",
                    GraderFamily::IndependentExternal,
                ),
            ],
        };

        assert!(matches!(
            ValidatedGraderConfigFile::try_from(raw),
            Err(GraderConfigError::FamilyProviderMismatch {
                provider: GraderProvider::Anthropic,
                ..
            })
        ));
    }

    #[test]
    fn grader_config_enforces_roster_and_file_size_bounds() {
        let mut too_many = valid_grader_config();
        for index in too_many.graders.len()..=MAX_GRADERS {
            too_many.graders.push(grader(
                &format!("extra-{index}"),
                GraderProvider::Anthropic,
                &format!("model-{index}"),
                GraderFamily::AnthropicOpenaiGoogle,
            ));
        }
        assert!(matches!(
            too_many.into_validated(),
            Err(GraderConfigError::TooManyGraders {
                found,
                max: MAX_GRADERS,
            }) if found == MAX_GRADERS + 1
        ));

        let dir = tempfile::tempdir().unwrap();
        let mut oversized = serde_json::to_string(&valid_grader_config()).unwrap();
        oversized.push_str(&" ".repeat(MAX_GRADER_CONFIG_BYTES as usize + 1));
        let path = dir.path().join("oversized-graders.json");
        std::fs::write(&path, oversized).unwrap();
        assert!(matches!(
            load_grader_config(&path).unwrap_err().downcast_ref(),
            Some(GraderConfigError::ConfigTooLarge { max_bytes })
                if *max_bytes == MAX_GRADER_CONFIG_BYTES
        ));
    }
}
