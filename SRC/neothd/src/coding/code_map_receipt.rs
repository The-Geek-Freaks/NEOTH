//! Hash-bound provenance for code-map context supplied to the coding decomposer.
//!
//! A receipt deliberately records selection metadata and commitments only.  The
//! assembled context and provider prompt remain transient; persisting either
//! would turn the kanban index into an unbounded source-code/prompt archive.

use std::io::{self, Write};
use std::path::{Component, Path};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::types::KanbanSessionId;

/// Stable wire schema for [`CodingCodeMapReceipt`].
pub const CODING_CODE_MAP_RECEIPT_SCHEMA: &str = "neoth.coding.code_map_receipt.v1";

/// Receipt payloads are kept small enough to remain a session attribute, not a
/// second context store.
pub const MAX_CODE_MAP_RECEIPT_BYTES: usize = 128 * 1024;
/// Maximum serialized metadata for one context source after sanitization.
/// Two sources therefore consume at most 112 KiB of the 128 KiB session field;
/// the repair receipt stores only its changing commitments rather than a second
/// source copy.
pub(crate) const MAX_CODE_MAP_SOURCE_BYTES: usize = 56 * 1024;
const MAX_CONTEXT_BYTES: usize = 64 * 1024;
const MAX_SOURCES: usize = 3;
const MAX_ROOT_BYTES: usize = 4 * 1024;
const MAX_ROOT_IDENTITY_BYTES: usize = 4 * 1024;
const MAX_PATH_BYTES: usize = 4 * 1024;
const MAX_SYMBOL_BYTES: usize = 512;
const MAX_DIFF_IMPACT_SEEDS: usize = 256;
const MAX_DIFF_IMPACT_AFFECTED_IDENTITIES: usize = 96;
const MAX_DIFF_IMPACT_KIND_BYTES: usize = 128;
const MAX_DIFF_IMPACT_PROMPT_PROJECTION_BYTES: usize = 16 * 1024;
const MAX_IMPACT_TEST_GAP_NODES: usize = 24;
const MAX_IMPACT_TEST_GAP_OBSERVED_TESTS_PER_NODE: usize = 8;

/// Why a code-map selection was included in the original assembled context.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeMapContextKind {
    TargetedRecall,
    RepoMapSummary,
    DiffImpact,
}

/// A bounded node identity from an advisory diff-impact traversal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiffImpactAffectedIdentity {
    pub path: String,
    pub symbol: String,
    pub line: u32,
    pub kind: String,
}

/// Typed evidence carried from an explicit diff-impact analysis into the
/// pre-provider receipt. It intentionally has no unified-diff or source-text
/// field; the SHA-256 commits the acquisition without retaining its bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiffImpactCitation {
    pub source: crate::code_map::diff_impact::DiffImpactSourceDescriptor,
    pub diff_sha256: String,
    pub impact_digest: String,
    pub exact_symbol_seeds: Vec<CodeMapSelectedFile>,
    pub file_fallback_seeds: Vec<CodeMapSelectedFile>,
    pub affected_identities: Vec<DiffImpactAffectedIdentity>,
    /// The citation projection is bounded independently of the impact result.
    /// This marker prevents a prompt from mistaking the retained identities for
    /// the whole traversal result.
    pub affected_identities_truncated: bool,
    pub unresolved_seed_count: usize,
    pub unresolved_edge_count: usize,
    pub impact_truncated: bool,
    pub budget_truncated: bool,
    pub evidence_truncated: bool,
    pub root_snapshot_complete: bool,
    pub allow_stale: bool,
    /// Optional W48 advisory derived from this exact impact digest. Older
    /// receipts decode without it; a present citation is validation-bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impact_test_gap: Option<ImpactTestGapCitation>,
}

/// Bounded structural test evidence. Empty observations are explicitly not an
/// absence claim and neither raw diff nor source/test body is retained.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImpactTestGapCitation {
    pub impact_digest: String,
    pub root_identity: String,
    pub index_generation: i64,
    pub graph_generation: i64,
    pub outcome: crate::code_map::test_coverage::ImpactTestGapOutcome,
    pub impact_partial: bool,
    pub work_budget_capped: bool,
    /// Aggregate-only classifier exclusions from the same root/generation.
    /// A missing value means the input was rejected before a database read;
    /// it never converts an empty observation into an absence claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclusion_provenance: Option<crate::code_map::graph::TestEvidenceExclusionSummary>,
    pub no_observed_test_is_not_absence: bool,
    pub nodes: Vec<ImpactTestGapNodeCitation>,
}

/// Bounded test evidence for one concrete impact declaration. A missing
/// coverage result stays an explicit uncertainty; it is never converted into
/// a statement that no test exists.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImpactTestGapNodeCitation {
    pub impact_node: DiffImpactAffectedIdentity,
    pub identity: crate::code_map::test_coverage::ImpactTestGapIdentity,
    pub coverage_unknown: bool,
    pub no_observed_test_in_indexed_map: bool,
    pub observed_tests: Vec<ImpactTestGapObservedTestCitation>,
}

/// A name-only observed test relation. Source or test bodies are deliberately
/// absent from this persisted and prompt-projected form.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImpactTestGapObservedTestCitation {
    pub path: String,
    pub symbol: String,
    pub confidence: u8,
}

impl DiffImpactCitation {
    /// Render the actionable, bounded structural projection supplied to the
    /// provider. This consumes the same already-sanitized citation persisted
    /// in the pre-provider receipt; raw diff/source text cannot enter here.
    pub(crate) fn render_prompt_projection(&self) -> String {
        let mut out = String::from("diff-impact structural identities:\n");
        append_projection_line(&mut out, "source", &render_diff_source(&self.source));
        append_projection_line(&mut out, "exact_symbol_seeds", "");
        for seed in &self.exact_symbol_seeds {
            let symbol = seed
                .symbols
                .first()
                .map(String::as_str)
                .unwrap_or("<invalid-missing-symbol>");
            append_projection_line(&mut out, "  exact", &format!("{} :: {}", seed.path, symbol));
        }
        append_projection_line(&mut out, "file_fallback_seeds", "");
        for seed in &self.file_fallback_seeds {
            append_projection_line(&mut out, "  fallback_file", &seed.path);
        }
        append_projection_line(&mut out, "affected_identities", "");
        for identity in &self.affected_identities {
            append_projection_line(
                &mut out,
                "  affected",
                &format!(
                    "{} :: {} @{} ({})",
                    identity.path, identity.symbol, identity.line, identity.kind
                ),
            );
        }
        append_projection_line(
            &mut out,
            "uncertainty",
            &format!(
                "unresolved_seeds={}; unresolved_edges={}; traversal_truncated={}; budget_truncated={}; evidence_truncated={}; projection_truncated={}",
                self.unresolved_seed_count,
                self.unresolved_edge_count,
                self.impact_truncated,
                self.budget_truncated,
                self.evidence_truncated,
                self.affected_identities_truncated,
            ),
        );
        if let Some(gap) = &self.impact_test_gap {
            out.push_str(&gap.render_prompt_projection());
        }
        out
    }
    pub(crate) fn from_receipt(
        receipt: &crate::code_map::diff_impact::DiffImpactReceipt,
    ) -> Result<(Self, bool)> {
        receipt.require_prompt_admissible()?;
        let mut metadata_redacted = false;
        let mut source = receipt.source.clone();
        sanitize_diff_source(&mut source, &mut metadata_redacted);
        let exact_symbol_seeds =
            sanitize_diff_seeds(&receipt.exact_symbol_seeds, &mut metadata_redacted);
        let file_fallback_seeds =
            sanitize_diff_seeds(&receipt.file_fallback_seeds, &mut metadata_redacted);
        let mut affected_identities = Vec::new();
        let mut affected_identities_truncated =
            receipt.impact.impacted_nodes.len() > MAX_DIFF_IMPACT_AFFECTED_IDENTITIES;
        for node in receipt
            .impact
            .impacted_nodes
            .iter()
            .take(MAX_DIFF_IMPACT_AFFECTED_IDENTITIES)
        {
            let mut path = node.node.file.clone();
            let mut symbol = node.node.symbol.clone();
            let mut kind = node.node.kind.clone();
            sanitize_metadata_field(&mut path, &mut metadata_redacted);
            sanitize_metadata_field(&mut symbol, &mut metadata_redacted);
            sanitize_metadata_field(&mut kind, &mut metadata_redacted);
            affected_identities.push(DiffImpactAffectedIdentity {
                path,
                symbol,
                line: node.node.line,
                kind,
            });
        }
        // The retained list may be shorter after a future producer applies an
        // independent cap; make that condition visible too.
        affected_identities_truncated |=
            receipt.impact.impacted_nodes.len() > affected_identities.len();
        let citation = Self {
            source,
            diff_sha256: receipt.diff_sha256.clone(),
            impact_digest: receipt.impact.digest.clone(),
            exact_symbol_seeds,
            file_fallback_seeds,
            affected_identities,
            affected_identities_truncated,
            unresolved_seed_count: receipt.impact.unresolved_seeds.len(),
            unresolved_edge_count: receipt.impact.unresolved_edges.len(),
            impact_truncated: receipt.impact.truncated,
            budget_truncated: receipt.impact.budget_truncated,
            evidence_truncated: receipt.impact.evidence_truncated,
            root_snapshot_complete: receipt.root_snapshot_complete,
            allow_stale: receipt.allow_stale,
            impact_test_gap: None,
        };
        citation.validate()?;
        Ok((citation, metadata_redacted))
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            is_lowercase_sha256(&self.diff_sha256),
            "diff-impact diff digest is not lowercase SHA-256"
        );
        ensure!(
            is_lowercase_sha256(&self.impact_digest),
            "diff-impact impact digest is not lowercase SHA-256"
        );
        ensure!(
            self.root_snapshot_complete,
            "partial code-map scan cannot enter coding diff-impact citation"
        );
        ensure!(
            !self.allow_stale,
            "allow-stale diff-impact output cannot enter coding citation"
        );
        if let Some(gap) = &self.impact_test_gap {
            gap.validate_against(self)?;
        }
        validate_diff_source(&self.source)?;
        validate_diff_seed_files("exact diff-impact seeds", &self.exact_symbol_seeds)?;
        validate_diff_seed_files("fallback diff-impact seeds", &self.file_fallback_seeds)?;
        ensure!(
            self.exact_symbol_seeds.len() + self.file_fallback_seeds.len() <= MAX_DIFF_IMPACT_SEEDS,
            "diff-impact seed metadata exceeds bounded citation limit"
        );
        ensure!(
            self.affected_identities.len() <= MAX_DIFF_IMPACT_AFFECTED_IDENTITIES,
            "diff-impact affected identities exceed bounded citation limit"
        );
        for identity in &self.affected_identities {
            relative_contained_path("diff-impact affected path", &identity.path)?;
            bounded_nonempty(
                "diff-impact affected symbol",
                &identity.symbol,
                MAX_SYMBOL_BYTES,
            )?;
            bounded_nonempty(
                "diff-impact affected kind",
                &identity.kind,
                MAX_DIFF_IMPACT_KIND_BYTES,
            )?;
            ensure!(
                identity.line > 0,
                "diff-impact affected identity line must be positive"
            );
        }
        Ok(())
    }
}

impl ImpactTestGapCitation {
    pub(crate) fn from_result(
        diff: &DiffImpactCitation,
        root_identity: &str,
        result: &crate::code_map::test_coverage::ImpactTestGapResult,
    ) -> Result<Self> {
        ensure!(
            result.impact_digest == diff.impact_digest,
            "test-gap digest differs from diff-impact citation"
        );
        let mut nodes = Vec::new();
        for node in result.per_node.iter().take(MAX_IMPACT_TEST_GAP_NODES) {
            let mut path = node.impact_node.file.clone();
            let mut symbol = node.impact_node.symbol.clone();
            let mut kind = node.impact_node.kind.clone();
            let mut redacted = false;
            sanitize_metadata_field(&mut path, &mut redacted);
            sanitize_metadata_field(&mut symbol, &mut redacted);
            sanitize_metadata_field(&mut kind, &mut redacted);
            let (coverage_unknown, no_observed_test_in_indexed_map, observed_tests) =
                match &node.coverage {
                    None => (true, false, Vec::new()),
                    Some(coverage) => {
                        let mut observed_tests = Vec::new();
                        for observed in coverage
                            .observed_tests
                            .iter()
                            .take(MAX_IMPACT_TEST_GAP_OBSERVED_TESTS_PER_NODE)
                        {
                            let mut path = observed.test.file.clone();
                            let mut symbol = observed.test.symbol.clone();
                            let mut redacted = false;
                            sanitize_metadata_field(&mut path, &mut redacted);
                            sanitize_metadata_field(&mut symbol, &mut redacted);
                            observed_tests.push(ImpactTestGapObservedTestCitation {
                                path,
                                symbol,
                                confidence: observed.confidence,
                            });
                        }
                        let uncertainty = &coverage.uncertainty;
                        let coverage_unknown = uncertainty.stale_graph
                            || uncertainty.partial_graph
                            || uncertainty.depth_capped
                            || uncertainty.node_capped
                            || uncertainty.edge_rows_capped
                            || uncertainty.unresolved_or_ambiguous
                            || uncertainty.unsupported_or_unclassified;
                        (
                            coverage_unknown,
                            uncertainty.no_observed_test,
                            observed_tests,
                        )
                    }
                };
            nodes.push(ImpactTestGapNodeCitation {
                impact_node: DiffImpactAffectedIdentity {
                    path,
                    symbol,
                    line: node.impact_node.line,
                    kind,
                },
                identity: node.identity.clone(),
                coverage_unknown,
                no_observed_test_in_indexed_map,
                observed_tests,
            });
        }
        let citation = Self {
            impact_digest: result.impact_digest.clone(),
            root_identity: root_identity.to_owned(),
            index_generation: result.index_generation,
            graph_generation: result.graph_generation,
            outcome: result.outcome.clone(),
            impact_partial: result.impact_partial,
            work_budget_capped: result.work_budget.capped,
            exclusion_provenance: result.exclusion_provenance.clone(),
            no_observed_test_is_not_absence: result.no_observed_test_is_not_absence,
            nodes,
        };
        citation.validate_against(diff)?;
        Ok(citation)
    }
    fn render_prompt_projection(&self) -> String {
        let mut out = String::from("impact-test-gap structural evidence:\n");
        append_projection_line(&mut out, "outcome", &format!("{:?}", self.outcome));
        append_projection_line(&mut out, "no_observed_test_is_not_absence", "true");
        append_projection_line(
            &mut out,
            "partial_flags",
            &format!(
                "impact={}; work_budget={}",
                self.impact_partial, self.work_budget_capped
            ),
        );
        if let Some(exclusions) = &self.exclusion_provenance {
            let categories = exclusions
                .categories
                .iter()
                .map(|(category, count)| format!("{category:?}={count}"))
                .collect::<Vec<_>>()
                .join(",");
            append_projection_line(
                &mut out,
                "root_exclusion_provenance",
                &format!(
                    "categories=[{categories}]; files={}; symbols={}; capped={}; relevance_to_node=unknown",
                    exclusions.source_files_examined,
                    exclusions.source_symbols_examined,
                    exclusions.capped
                ),
            );
        }
        for node in &self.nodes {
            append_projection_line(
                &mut out,
                "  impact_node",
                &format!(
                    "{} :: {} @{} ({}) identity={:?} coverage_unknown={}",
                    node.impact_node.path,
                    node.impact_node.symbol,
                    node.impact_node.line,
                    node.impact_node.kind,
                    node.identity,
                    node.coverage_unknown
                ),
            );
            for observed in &node.observed_tests {
                append_projection_line(
                    &mut out,
                    "    observed_test",
                    &format!(
                        "{} :: {} confidence={}",
                        observed.path, observed.symbol, observed.confidence
                    ),
                );
            }
            if node.no_observed_test_in_indexed_map {
                append_projection_line(
                    &mut out,
                    "    observed_test",
                    "no observed test in this indexed map",
                );
            }
        }
        out
    }
    fn validate_against(&self, diff: &DiffImpactCitation) -> Result<()> {
        ensure!(
            is_lowercase_sha256(&self.impact_digest) && self.impact_digest == diff.impact_digest,
            "test-gap citation impact digest mismatch"
        );
        bounded_nonempty(
            "test-gap root identity",
            &self.root_identity,
            MAX_ROOT_IDENTITY_BYTES,
        )?;
        ensure!(
            sanitize_metadata_value(&self.root_identity) == self.root_identity,
            "test-gap root identity contains unsanitized metadata"
        );
        ensure!(
            self.index_generation > 0 && self.index_generation == self.graph_generation,
            "test-gap citation generation binding is invalid"
        );
        ensure!(
            self.no_observed_test_is_not_absence,
            "test-gap citation must retain non-absence truth marker"
        );
        if matches!(
            &self.outcome,
            crate::code_map::test_coverage::ImpactTestGapOutcome::RejectedInput(_)
        ) {
            ensure!(
                self.exclusion_provenance.is_none(),
                "rejected test-gap citation cannot retain exclusion provenance"
            );
            ensure!(
                self.nodes.is_empty(),
                "rejected test-gap citation cannot retain node evidence"
            );
        }
        if let Some(exclusions) = &self.exclusion_provenance {
            ensure!(
                exclusions.categories.len() <= 4,
                "test-gap exclusion provenance has unsupported categories"
            );
            let minimum_work = exclusions
                .source_files_examined
                .checked_add(exclusions.source_symbols_examined)
                .context("test-gap exclusion provenance work overflow")?;
            let maximum_work = minimum_work
                .checked_add(if exclusions.capped { 1 } else { 0 })
                .context("test-gap exclusion provenance sentinel work overflow")?;
            ensure!(
                exclusions.work_units >= minimum_work && exclusions.work_units <= maximum_work,
                "test-gap exclusion provenance work receipt is invalid"
            );
            for count in exclusions.categories.values() {
                ensure!(
                    *count > 0,
                    "test-gap exclusion provenance cannot retain zero counts"
                );
            }
        }
        ensure!(
            self.nodes.len() <= MAX_IMPACT_TEST_GAP_NODES,
            "test-gap citation nodes exceed bound"
        );
        for node in &self.nodes {
            relative_contained_path("test-gap node path", &node.impact_node.path)?;
            bounded_nonempty(
                "test-gap node symbol",
                &node.impact_node.symbol,
                MAX_SYMBOL_BYTES,
            )?;
            bounded_nonempty(
                "test-gap node kind",
                &node.impact_node.kind,
                MAX_DIFF_IMPACT_KIND_BYTES,
            )?;
            ensure!(
                sanitize_metadata_value(&node.impact_node.path) == node.impact_node.path,
                "test-gap node path contains unsanitized metadata"
            );
            ensure!(
                sanitize_metadata_value(&node.impact_node.symbol) == node.impact_node.symbol,
                "test-gap node symbol contains unsanitized metadata"
            );
            ensure!(
                sanitize_metadata_value(&node.impact_node.kind) == node.impact_node.kind,
                "test-gap node kind contains unsanitized metadata"
            );
            ensure!(
                node.impact_node.line > 0,
                "test-gap node line must be positive"
            );
            ensure!(
                node.observed_tests.len() <= MAX_IMPACT_TEST_GAP_OBSERVED_TESTS_PER_NODE,
                "test-gap observed tests exceed bound"
            );
            if node.no_observed_test_in_indexed_map {
                ensure!(
                    node.observed_tests.is_empty(),
                    "no-observed-test node cannot retain observed test identities"
                );
            }
            for observed in &node.observed_tests {
                relative_contained_path("observed test path", &observed.path)?;
                bounded_nonempty("observed test symbol", &observed.symbol, MAX_SYMBOL_BYTES)?;
                ensure!(
                    sanitize_metadata_value(&observed.path) == observed.path,
                    "observed test path contains unsanitized metadata"
                );
                ensure!(
                    sanitize_metadata_value(&observed.symbol) == observed.symbol,
                    "observed test symbol contains unsanitized metadata"
                );
                ensure!(
                    observed.confidence <= 100,
                    "observed test confidence exceeds 100"
                );
            }
        }
        Ok(())
    }
}

fn render_diff_source(source: &crate::code_map::diff_impact::DiffImpactSourceDescriptor) -> String {
    match source {
        crate::code_map::diff_impact::DiffImpactSourceDescriptor::WorkingTree => {
            "working_tree".to_owned()
        }
        crate::code_map::diff_impact::DiffImpactSourceDescriptor::Staged => "staged".to_owned(),
        crate::code_map::diff_impact::DiffImpactSourceDescriptor::Stdin => "stdin".to_owned(),
        crate::code_map::diff_impact::DiffImpactSourceDescriptor::Committed { base, target } => {
            format!("committed base={base} target={target}")
        }
    }
}

fn append_projection_line(out: &mut String, label: &str, value: &str) {
    let line = if value.is_empty() {
        format!("{label}:\n")
    } else {
        format!("{label}: {value}\n")
    };
    if out.len().saturating_add(line.len()) <= MAX_DIFF_IMPACT_PROMPT_PROJECTION_BYTES {
        out.push_str(&line);
    } else if !out.ends_with("prompt_projection_truncated: true\n") {
        out.push_str("prompt_projection_truncated: true\n");
    }
}

/// Symbols selected from one repository-relative file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeMapSelectedFile {
    pub path: String,
    pub symbols: Vec<String>,
}

/// A depth-one caller retained with the original context selection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeMapCaller {
    pub target_symbol: String,
    pub caller_symbol: String,
    pub caller_path: String,
}

/// Typed, freshness-bound provenance for one portion of the original context.
///
/// This type intentionally contains names and paths only. It has no field for
/// source code, context text, an operator prompt, or provider output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeMapContextSource {
    pub kind: CodeMapContextKind,
    pub root: String,
    pub root_identity: String,
    pub index_generation: i64,
    pub graph_generation: i64,
    pub stale: bool,
    pub selection_truncated: bool,
    /// True when source metadata was redacted at the prepared-context boundary.
    /// Old clean receipts deserialize as false; a raw secret-shaped value is
    /// never accepted merely because this field is absent.
    #[serde(default)]
    pub metadata_redacted: bool,
    /// Present only for an explicit, prompt-admissible diff-impact input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff_impact: Option<DiffImpactCitation>,
    pub selected_files: Vec<CodeMapSelectedFile>,
    pub callers: Vec<CodeMapCaller>,
}

impl CodeMapContextSource {
    /// Validate one source independently of the other sources in an assembled
    /// context. [`PreparedCodeMapContext::new`] also checks that all sources
    /// describe the same snapshot.
    pub fn validate(&self) -> Result<()> {
        self.validate_shape()?;
        ensure!(
            sanitize_metadata_value(&self.root_identity) == self.root_identity,
            "code-map root identity contains unsanitized metadata"
        );
        ensure!(
            source_metadata_is_sanitized(self),
            "code-map source contains unsanitized metadata"
        );
        ensure!(
            self.metadata_redacted || !source_contains_redaction_marker(self),
            "redacted code-map metadata must set metadata_redacted"
        );
        ensure_source_payload_bounded(self)?;
        Ok(())
    }

    /// Sanitize the metadata that may be persisted in a receipt. Root identity
    /// is a physical-root binding and cannot be transformed without changing
    /// its meaning, so it fails closed if canonical sanitization would alter it.
    pub(crate) fn sanitize_metadata_for_receipt(&mut self) -> Result<()> {
        self.validate_shape()?;
        ensure!(
            sanitize_metadata_value(&self.root_identity) == self.root_identity,
            "code-map root identity cannot be redacted without losing its physical binding"
        );

        // Retain a prior true value: sanitization is a boundary operation and
        // must be idempotent when a bounded producer pre-sanitizes metadata
        // before it hands the source to `PreparedCodeMapContext::new`.
        let mut metadata_redacted = self.metadata_redacted;
        sanitize_metadata_field(&mut self.root, &mut metadata_redacted);
        for file in &mut self.selected_files {
            sanitize_metadata_field(&mut file.path, &mut metadata_redacted);
            for symbol in &mut file.symbols {
                sanitize_metadata_field(symbol, &mut metadata_redacted);
            }
        }
        for caller in &mut self.callers {
            sanitize_metadata_field(&mut caller.target_symbol, &mut metadata_redacted);
            sanitize_metadata_field(&mut caller.caller_symbol, &mut metadata_redacted);
            sanitize_metadata_field(&mut caller.caller_path, &mut metadata_redacted);
        }
        if let Some(citation) = &mut self.diff_impact {
            // Its constructor pre-sanitizes every displayed field. A later
            // decode cannot silently turn a malformed/stale citation into
            // prompt authority, so validation below is deliberately strict.
            citation.validate()?;
        }
        self.metadata_redacted = metadata_redacted;
        self.validate_shape()?;
        Ok(())
    }

    fn validate_shape(&self) -> Result<()> {
        bounded_nonempty("code-map root", &self.root, MAX_ROOT_BYTES)?;
        bounded_nonempty(
            "code-map root identity",
            &self.root_identity,
            MAX_ROOT_IDENTITY_BYTES,
        )?;
        ensure!(
            self.index_generation > 0
                && self.graph_generation > 0
                && self.index_generation == self.graph_generation,
            "code-map source must have matching positive index and graph generations"
        );
        ensure!(
            !self.stale,
            "stale code-map sources must not be used for coding context"
        );
        match (&self.kind, &self.diff_impact) {
            (CodeMapContextKind::DiffImpact, Some(citation)) => {
                citation.validate()?;
                if let Some(gap) = &citation.impact_test_gap {
                    ensure!(
                        gap.root_identity == self.root_identity,
                        "test-gap citation root identity differs from enclosing code-map source"
                    );
                    ensure!(
                        gap.index_generation == self.index_generation,
                        "test-gap citation index generation differs from enclosing code-map source"
                    );
                    ensure!(
                        gap.graph_generation == self.graph_generation,
                        "test-gap citation graph generation differs from enclosing code-map source"
                    );
                }
            }
            (CodeMapContextKind::DiffImpact, None) => {
                anyhow::bail!("diff-impact code-map source requires a typed citation")
            }
            (_, Some(_)) => {
                anyhow::bail!("only a diff-impact source may carry a diff-impact citation")
            }
            (_, None) => {}
        }
        for file in &self.selected_files {
            relative_contained_path("code-map selected-file path", &file.path)?;
            for symbol in &file.symbols {
                bounded_nonempty("code-map selected symbol", symbol, MAX_SYMBOL_BYTES)?;
            }
        }
        for caller in &self.callers {
            bounded_nonempty(
                "code-map target symbol",
                &caller.target_symbol,
                MAX_SYMBOL_BYTES,
            )?;
            bounded_nonempty(
                "code-map caller symbol",
                &caller.caller_symbol,
                MAX_SYMBOL_BYTES,
            )?;
            relative_contained_path("code-map caller path", &caller.caller_path)?;
        }
        Ok(())
    }
}

/// The assembled code-map text before the decomposer applies its independent
/// input budget. The text is intentionally private and never serializable.
#[derive(Clone, Debug)]
pub struct PreparedCodeMapContext {
    text: String,
    sources: Vec<CodeMapContextSource>,
}

impl PreparedCodeMapContext {
    /// Bind the exact pre-budget context to validated source provenance.
    pub fn new(text: String, mut sources: Vec<CodeMapContextSource>) -> Result<Self> {
        ensure!(
            !text.is_empty(),
            "prepared code-map context must contain the original assembled text"
        );
        ensure!(
            text.len() <= MAX_CONTEXT_BYTES,
            "prepared code-map context exceeds {} bytes",
            MAX_CONTEXT_BYTES
        );
        for source in &mut sources {
            source.sanitize_metadata_for_receipt()?;
        }
        validate_sources(&sources)?;
        Ok(Self { text, sources })
    }

    /// Original assembled code-map text, before decomposer truncation.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Immutable provenance for the original selection.
    pub fn sources(&self) -> &[CodeMapContextSource] {
        &self.sources
    }

    /// Commit the exact strings used in a decomposition attempt without
    /// retaining those strings in the serializable receipt.
    pub fn receipt(
        &self,
        session_id: KanbanSessionId,
        attempt: u8,
        operator_prompt: &str,
        submitted_context: &str,
        provider_prompt: &str,
    ) -> Result<CodingCodeMapReceipt> {
        ensure!(
            submitted_context.len() <= MAX_CONTEXT_BYTES,
            "submitted code-map context exceeds {} bytes",
            MAX_CONTEXT_BYTES
        );
        let receipt = CodingCodeMapReceipt {
            schema: CODING_CODE_MAP_RECEIPT_SCHEMA.to_owned(),
            session_id: session_id.raw(),
            attempt,
            operator_prompt_sha256: sha256_hex(operator_prompt),
            assembled_context_sha256: sha256_hex(&self.text),
            submitted_context_sha256: sha256_hex(submitted_context),
            submitted_context_bytes: submitted_context.len(),
            context_truncated: submitted_context != self.text,
            provider_prompt_sha256: sha256_hex(provider_prompt),
            sources: self.sources.clone(),
        };
        receipt.validate()?;
        Ok(receipt)
    }
}

/// Persistable commitment to one provider decomposition attempt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodingCodeMapReceipt {
    pub schema: String,
    pub session_id: i64,
    pub attempt: u8,
    pub operator_prompt_sha256: String,
    pub assembled_context_sha256: String,
    pub submitted_context_sha256: String,
    pub submitted_context_bytes: usize,
    pub context_truncated: bool,
    pub provider_prompt_sha256: String,
    pub sources: Vec<CodeMapContextSource>,
}

impl CodingCodeMapReceipt {
    /// Validate a receipt loaded from persistence or supplied by a caller.
    /// No fallback is allowed: malformed receipts are evidence of corruption.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == CODING_CODE_MAP_RECEIPT_SCHEMA,
            "unsupported coding code-map receipt schema"
        );
        ensure!(self.session_id > 0, "receipt session id must be positive");
        ensure!(
            matches!(self.attempt, 1 | 2),
            "receipt attempt must be either 1 or 2"
        );
        for (name, digest) in [
            ("operator prompt", &self.operator_prompt_sha256),
            ("assembled context", &self.assembled_context_sha256),
            ("submitted context", &self.submitted_context_sha256),
            ("provider prompt", &self.provider_prompt_sha256),
        ] {
            ensure!(
                is_lowercase_sha256(digest),
                "{name} digest is not lowercase SHA-256"
            );
        }
        ensure!(
            self.submitted_context_bytes <= MAX_CONTEXT_BYTES,
            "submitted code-map context byte length exceeds bound"
        );
        ensure!(
            self.context_truncated
                == (self.assembled_context_sha256 != self.submitted_context_sha256),
            "context_truncated must exactly match the assembled/submitted commitments"
        );
        validate_sources(&self.sources)
    }
}

fn validate_sources(sources: &[CodeMapContextSource]) -> Result<()> {
    ensure!(
        !sources.is_empty() && sources.len() <= MAX_SOURCES,
        "prepared code-map context must have one or two provenance sources"
    );
    let first = &sources[0];
    first.validate()?;
    for source in &sources[1..] {
        source.validate()?;
        ensure!(
            source.root == first.root
                && source.root_identity == first.root_identity
                && source.index_generation == first.index_generation
                && source.graph_generation == first.graph_generation,
            "all code-map context sources must describe the same snapshot"
        );
        ensure!(
            source.kind != first.kind,
            "duplicate code-map context source kind"
        );
    }
    Ok(())
}

fn bounded_nonempty(name: &str, value: &str, max_bytes: usize) -> Result<()> {
    ensure!(!value.is_empty(), "{name} must not be empty");
    ensure!(value.len() <= max_bytes, "{name} exceeds {max_bytes} bytes");
    ensure!(
        !value.contains('\0') && !value.contains('\r') && !value.contains('\n'),
        "{name} contains an unsafe control character"
    );
    Ok(())
}

fn relative_contained_path(name: &str, value: &str) -> Result<()> {
    bounded_nonempty(name, value, MAX_PATH_BYTES)?;
    // `Path` follows the host platform. Reject Windows separators and drive
    // prefixes explicitly too so a receipt has the same containment semantics
    // when inspected on a different host.
    ensure!(
        !value.contains('\\') && path_colons_are_redaction_markers(value),
        "{name} must use a relative slash-separated repository path"
    );
    let path = Path::new(value);
    ensure!(!path.is_absolute(), "{name} must be relative");
    for component in path.components() {
        ensure!(
            matches!(component, Component::Normal(_)),
            "{name} must remain contained within its repository root"
        );
    }
    Ok(())
}

fn sanitize_metadata_value(value: &str) -> String {
    crate::security::redact::sanitize_tool_output(value)
}

fn ensure_source_payload_bounded(source: &CodeMapContextSource) -> Result<()> {
    // Keep the size proof exact without allocating a second, potentially
    // attacker-influenced JSON buffer. The source itself is trusted in-process
    // data and producers budget it too, but a bounded writer ensures this
    // validation step cannot add an unbounded allocation of its own.
    let mut writer = BoundedJsonWriter::new(MAX_CODE_MAP_SOURCE_BYTES);
    match serde_json::to_writer(&mut writer, source) {
        Ok(()) => {}
        Err(_error) if writer.exceeded => {
            anyhow::bail!(
                "serialized code-map source exceeds {} bytes",
                MAX_CODE_MAP_SOURCE_BYTES
            );
        }
        Err(error) => return Err(error).context("serialize code-map source for size check"),
    }
    Ok(())
}

struct BoundedJsonWriter {
    limit: usize,
    written: usize,
    exceeded: bool,
}

impl BoundedJsonWriter {
    const fn new(limit: usize) -> Self {
        Self {
            limit,
            written: 0,
            exceeded: false,
        }
    }
}

impl Write for BoundedJsonWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.written) {
            self.exceeded = true;
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "code-map source byte budget exceeded",
            ));
        }
        self.written += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn sanitize_metadata_field(value: &mut String, metadata_redacted: &mut bool) {
    let sanitized = sanitize_metadata_value(value);
    if sanitized != *value {
        *metadata_redacted = true;
        *value = sanitized;
    }
}

fn source_contains_redaction_marker(source: &CodeMapContextSource) -> bool {
    source.root.contains("[REDACTED:")
        || source.selected_files.iter().any(|file| {
            file.path.contains("[REDACTED:")
                || file
                    .symbols
                    .iter()
                    .any(|symbol| symbol.contains("[REDACTED:"))
        })
        || source.callers.iter().any(|caller| {
            caller.target_symbol.contains("[REDACTED:")
                || caller.caller_symbol.contains("[REDACTED:")
                || caller.caller_path.contains("[REDACTED:")
        })
        || source
            .diff_impact
            .as_ref()
            .is_some_and(diff_impact_contains_redaction_marker)
}

fn source_metadata_is_sanitized(source: &CodeMapContextSource) -> bool {
    sanitize_metadata_value(&source.root) == source.root
        && source.selected_files.iter().all(|file| {
            sanitize_metadata_value(&file.path) == file.path
                && file
                    .symbols
                    .iter()
                    .all(|symbol| sanitize_metadata_value(symbol) == symbol.as_str())
        })
        && source.callers.iter().all(|caller| {
            sanitize_metadata_value(&caller.target_symbol) == caller.target_symbol.as_str()
                && sanitize_metadata_value(&caller.caller_symbol) == caller.caller_symbol.as_str()
                && sanitize_metadata_value(&caller.caller_path) == caller.caller_path.as_str()
        })
        && source
            .diff_impact
            .as_ref()
            .is_none_or(diff_impact_metadata_is_sanitized)
}

fn sanitize_diff_source(
    source: &mut crate::code_map::diff_impact::DiffImpactSourceDescriptor,
    metadata_redacted: &mut bool,
) {
    if let crate::code_map::diff_impact::DiffImpactSourceDescriptor::Committed { base, target } =
        source
    {
        sanitize_metadata_field(base, metadata_redacted);
        sanitize_metadata_field(target, metadata_redacted);
    }
}

fn validate_diff_source(
    source: &crate::code_map::diff_impact::DiffImpactSourceDescriptor,
) -> Result<()> {
    use crate::code_map::diff_impact::DiffImpactSourceDescriptor;
    if let DiffImpactSourceDescriptor::Committed { base, target } = source {
        bounded_nonempty("diff-impact base ref", base, MAX_SYMBOL_BYTES)?;
        bounded_nonempty("diff-impact target ref", target, MAX_SYMBOL_BYTES)?;
        ensure!(
            sanitize_metadata_value(base) == *base && sanitize_metadata_value(target) == *target,
            "diff-impact committed ref contains unsanitized metadata"
        );
    }
    Ok(())
}

fn sanitize_diff_seeds(
    seeds: &[crate::code_map::diff_impact::DiffImpactSeedReceipt],
    metadata_redacted: &mut bool,
) -> Vec<CodeMapSelectedFile> {
    seeds
        .iter()
        .map(|seed| {
            let mut path = seed.file.clone();
            sanitize_metadata_field(&mut path, metadata_redacted);
            let mut symbols = Vec::new();
            if let Some(symbol) = &seed.symbol {
                let mut symbol = symbol.clone();
                sanitize_metadata_field(&mut symbol, metadata_redacted);
                symbols.push(symbol);
            }
            CodeMapSelectedFile { path, symbols }
        })
        .collect()
}

fn validate_diff_seed_files(name: &str, seeds: &[CodeMapSelectedFile]) -> Result<()> {
    for seed in seeds {
        relative_contained_path(name, &seed.path)?;
        ensure!(
            seed.symbols.len() <= 1,
            "{name} must retain at most one exact symbol per seed"
        );
        for symbol in &seed.symbols {
            bounded_nonempty(name, symbol, MAX_SYMBOL_BYTES)?;
        }
    }
    Ok(())
}

fn diff_impact_contains_redaction_marker(citation: &DiffImpactCitation) -> bool {
    let source = match &citation.source {
        crate::code_map::diff_impact::DiffImpactSourceDescriptor::Committed { base, target } => {
            base.contains("[REDACTED:") || target.contains("[REDACTED:")
        }
        _ => false,
    };
    source
        || citation
            .exact_symbol_seeds
            .iter()
            .chain(&citation.file_fallback_seeds)
            .any(|seed| {
                seed.path.contains("[REDACTED:")
                    || seed
                        .symbols
                        .iter()
                        .any(|symbol| symbol.contains("[REDACTED:"))
            })
        || citation.affected_identities.iter().any(|identity| {
            identity.path.contains("[REDACTED:")
                || identity.symbol.contains("[REDACTED:")
                || identity.kind.contains("[REDACTED:")
        })
}

fn diff_impact_metadata_is_sanitized(citation: &DiffImpactCitation) -> bool {
    let source = match &citation.source {
        crate::code_map::diff_impact::DiffImpactSourceDescriptor::Committed { base, target } => {
            sanitize_metadata_value(base) == *base && sanitize_metadata_value(target) == *target
        }
        _ => true,
    };
    source
        && citation
            .exact_symbol_seeds
            .iter()
            .chain(&citation.file_fallback_seeds)
            .all(|seed| {
                sanitize_metadata_value(&seed.path) == seed.path
                    && seed
                        .symbols
                        .iter()
                        .all(|symbol| sanitize_metadata_value(symbol) == *symbol)
            })
        && citation.affected_identities.iter().all(|identity| {
            sanitize_metadata_value(&identity.path) == identity.path
                && sanitize_metadata_value(&identity.symbol) == identity.symbol
                && sanitize_metadata_value(&identity.kind) == identity.kind
        })
}

/// Sanitization markers contain a colon (`[REDACTED:kind]`), which is not a
/// Windows drive prefix. Every other colon remains forbidden so receipt paths
/// stay portable and contained even when inspected off their source host.
fn path_colons_are_redaction_markers(value: &str) -> bool {
    let mut remaining = value;
    while let Some(colon) = remaining.find(':') {
        let before = &remaining[..colon];
        if !before.ends_with("[REDACTED") {
            return false;
        }
        let after = &remaining[colon + 1..];
        let Some(end) = after.find(']') else {
            return false;
        };
        let kind = &after[..end];
        if kind.is_empty()
            || !kind
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_' || byte.is_ascii_digit())
        {
            return false;
        }
        remaining = &after[end + 1..];
    }
    true
}

fn sha256_hex(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| {
            byte.is_ascii_digit() || (byte.is_ascii_lowercase() && byte.is_ascii_hexdigit())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(kind: CodeMapContextKind) -> CodeMapContextSource {
        CodeMapContextSource {
            kind,
            root: "C:/repo".to_owned(),
            root_identity: "volume-serial:repo-id".to_owned(),
            index_generation: 7,
            graph_generation: 7,
            stale: false,
            selection_truncated: false,
            metadata_redacted: false,
            diff_impact: None,
            selected_files: vec![CodeMapSelectedFile {
                path: "src/lib.rs".to_owned(),
                symbols: vec!["entrypoint".to_owned()],
            }],
            callers: vec![CodeMapCaller {
                target_symbol: "entrypoint".to_owned(),
                caller_symbol: "main".to_owned(),
                caller_path: "src/main.rs".to_owned(),
            }],
        }
    }

    fn diff_citation() -> DiffImpactCitation {
        DiffImpactCitation {
            source: crate::code_map::diff_impact::DiffImpactSourceDescriptor::WorkingTree,
            diff_sha256: "a".repeat(64),
            impact_digest: "b".repeat(64),
            exact_symbol_seeds: vec![CodeMapSelectedFile {
                path: "src/lib.rs".to_owned(),
                symbols: vec!["changed".to_owned()],
            }],
            file_fallback_seeds: vec![CodeMapSelectedFile {
                path: "src/fallback.rs".to_owned(),
                symbols: Vec::new(),
            }],
            affected_identities: vec![DiffImpactAffectedIdentity {
                path: "src/lib.rs".to_owned(),
                symbol: "changed".to_owned(),
                line: 7,
                kind: "function".to_owned(),
            }],
            affected_identities_truncated: false,
            unresolved_seed_count: 0,
            unresolved_edge_count: 0,
            impact_truncated: false,
            budget_truncated: false,
            evidence_truncated: false,
            root_snapshot_complete: true,
            allow_stale: false,
            impact_test_gap: None,
        }
    }

    #[test]
    fn diff_impact_source_refuses_missing_stale_or_partial_citation() {
        let missing = source(CodeMapContextKind::DiffImpact);
        assert!(
            missing.validate().is_err(),
            "typed diff-impact provenance is mandatory"
        );

        let mut partial = source(CodeMapContextKind::DiffImpact);
        let mut citation = diff_citation();
        citation.root_snapshot_complete = false;
        partial.diff_impact = Some(citation);
        assert!(
            partial.validate().is_err(),
            "partial map scan cannot reach a coding receipt"
        );

        let mut stale = source(CodeMapContextKind::DiffImpact);
        let mut citation = diff_citation();
        citation.allow_stale = true;
        stale.diff_impact = Some(citation);
        assert!(
            stale.validate().is_err(),
            "allow-stale analysis cannot reach a coding receipt"
        );

        let mut admissible = source(CodeMapContextKind::DiffImpact);
        admissible.diff_impact = Some(diff_citation());
        assert!(
            admissible.validate().is_ok(),
            "fresh complete typed citation remains receiptable"
        );
    }

    #[test]
    fn diff_impact_prompt_projection_uses_the_receipted_structural_identities() {
        let mut citation = diff_citation();
        citation.unresolved_seed_count = 1;
        citation.budget_truncated = true;
        let projection = citation.render_prompt_projection();
        assert!(projection.contains("exact: src/lib.rs :: changed"));
        assert!(projection.contains("fallback_file: src/fallback.rs"));
        assert!(projection.contains("affected: src/lib.rs :: changed @7 (function)"));
        assert!(projection.contains("unresolved_seeds=1"));
        assert!(projection.contains("budget_truncated=true"));
        assert!(!projection.contains("diff --git"));
    }

    #[test]
    fn test_gap_citation_is_backward_optional_and_validation_bound_to_its_diff() {
        let old_json = serde_json::to_string(&diff_citation()).unwrap();
        assert!(!old_json.contains("impact_test_gap"));
        assert!(
            serde_json::from_str::<DiffImpactCitation>(&old_json)
                .unwrap()
                .impact_test_gap
                .is_none()
        );

        let mut source = source(CodeMapContextKind::DiffImpact);
        let mut citation = diff_citation();
        let impact_digest = citation.impact_digest.clone();
        let impact_node = citation.affected_identities[0].clone();
        citation.impact_test_gap = Some(ImpactTestGapCitation {
            impact_digest,
            root_identity: source.root_identity.clone(),
            index_generation: source.index_generation,
            graph_generation: source.graph_generation,
            outcome: crate::code_map::test_coverage::ImpactTestGapOutcome::Complete,
            impact_partial: false,
            work_budget_capped: false,
            exclusion_provenance: None,
            no_observed_test_is_not_absence: true,
            nodes: vec![ImpactTestGapNodeCitation {
                impact_node,
                identity: crate::code_map::test_coverage::ImpactTestGapIdentity::Exact,
                coverage_unknown: false,
                no_observed_test_in_indexed_map: false,
                observed_tests: vec![ImpactTestGapObservedTestCitation {
                    path: "tests/changed_test.rs".to_owned(),
                    symbol: "changed_is_covered".to_owned(),
                    confidence: 80,
                }],
            }],
        });
        source.diff_impact = Some(citation);
        assert!(source.validate().is_ok());
        let projection = source
            .diff_impact
            .as_ref()
            .unwrap()
            .render_prompt_projection();
        assert!(projection.contains("impact-test-gap structural evidence:"));
        assert!(projection.contains("no_observed_test_is_not_absence: true"));
        assert!(projection.contains("tests/changed_test.rs :: changed_is_covered confidence=80"));
        assert!(!projection.contains("diff --git"));

        source
            .diff_impact
            .as_mut()
            .unwrap()
            .impact_test_gap
            .as_mut()
            .unwrap()
            .exclusion_provenance = Some(crate::code_map::graph::TestEvidenceExclusionSummary {
            categories: std::collections::BTreeMap::from([(
                crate::code_map::graph::TestEvidenceExclusionCategory::Generated,
                1,
            )]),
            source_files_examined: 4,
            source_symbols_examined: 7,
            work_units: 11,
            capped: false,
        });
        assert!(source.validate().is_ok());
        let provenance_projection = source
            .diff_impact
            .as_ref()
            .unwrap()
            .render_prompt_projection();
        assert!(provenance_projection.contains("root_exclusion_provenance"));
        assert!(provenance_projection.contains("relevance_to_node=unknown"));

        source
            .diff_impact
            .as_mut()
            .unwrap()
            .impact_test_gap
            .as_mut()
            .unwrap()
            .impact_digest = "c".repeat(64);
        assert!(
            source.validate().is_err(),
            "test-gap data cannot detach from its diff"
        );

        let expected_digest = source.diff_impact.as_ref().unwrap().impact_digest.clone();
        source
            .diff_impact
            .as_mut()
            .unwrap()
            .impact_test_gap
            .as_mut()
            .unwrap()
            .impact_digest = expected_digest;
        source
            .diff_impact
            .as_mut()
            .unwrap()
            .impact_test_gap
            .as_mut()
            .unwrap()
            .root_identity = "other-volume:other-root".to_owned();
        assert!(
            source.validate().is_err(),
            "nested root identity cannot detach from its source"
        );
        let expected_root_identity = source.root_identity.clone();
        source
            .diff_impact
            .as_mut()
            .unwrap()
            .impact_test_gap
            .as_mut()
            .unwrap()
            .root_identity = expected_root_identity;
        source
            .diff_impact
            .as_mut()
            .unwrap()
            .impact_test_gap
            .as_mut()
            .unwrap()
            .index_generation += 1;
        source
            .diff_impact
            .as_mut()
            .unwrap()
            .impact_test_gap
            .as_mut()
            .unwrap()
            .graph_generation += 1;
        assert!(
            source.validate().is_err(),
            "nested index generation cannot detach from its source"
        );
        let expected_index_generation = source.index_generation;
        source
            .diff_impact
            .as_mut()
            .unwrap()
            .impact_test_gap
            .as_mut()
            .unwrap()
            .index_generation = expected_index_generation;
        let mismatched_graph_generation = source.graph_generation + 1;
        source
            .diff_impact
            .as_mut()
            .unwrap()
            .impact_test_gap
            .as_mut()
            .unwrap()
            .graph_generation = mismatched_graph_generation;
        assert!(
            source.validate().is_err(),
            "nested graph generation cannot detach from its source"
        );
    }

    #[test]
    fn rejected_test_gap_receipt_cannot_retain_deserialized_evidence_payloads() {
        let mut source = source(CodeMapContextKind::DiffImpact);
        let mut citation = diff_citation();
        let impact_digest = citation.impact_digest.clone();
        let impact_node = citation.affected_identities[0].clone();
        citation.impact_test_gap = Some(ImpactTestGapCitation {
            impact_digest,
            root_identity: source.root_identity.clone(),
            index_generation: source.index_generation,
            graph_generation: source.graph_generation,
            outcome: crate::code_map::test_coverage::ImpactTestGapOutcome::RejectedInput(
                crate::code_map::test_coverage::ImpactTestGapRejection::Stale,
            ),
            impact_partial: true,
            work_budget_capped: false,
            exclusion_provenance: None,
            no_observed_test_is_not_absence: true,
            nodes: Vec::new(),
        });
        source.diff_impact = Some(citation);
        let persisted = serde_json::to_string(&source).expect("serialize rejected receipt");
        let mut decoded: CodeMapContextSource =
            serde_json::from_str(&persisted).expect("deserialize rejected receipt");
        assert!(
            decoded.validate().is_ok(),
            "an empty rejected receipt remains a valid typed result"
        );

        decoded
            .diff_impact
            .as_mut()
            .unwrap()
            .impact_test_gap
            .as_mut()
            .unwrap()
            .exclusion_provenance = Some(crate::code_map::graph::TestEvidenceExclusionSummary {
            categories: std::collections::BTreeMap::from([(
                crate::code_map::graph::TestEvidenceExclusionCategory::Generated,
                1,
            )]),
            source_files_examined: 1,
            source_symbols_examined: 0,
            work_units: 1,
            capped: false,
        });
        assert!(
            decoded.validate().is_err(),
            "a persisted rejected receipt cannot retain exclusion provenance"
        );

        let rejected = decoded
            .diff_impact
            .as_mut()
            .unwrap()
            .impact_test_gap
            .as_mut()
            .unwrap();
        rejected.exclusion_provenance = None;
        rejected.nodes.push(ImpactTestGapNodeCitation {
            impact_node,
            identity: crate::code_map::test_coverage::ImpactTestGapIdentity::Exact,
            coverage_unknown: true,
            no_observed_test_in_indexed_map: false,
            observed_tests: Vec::new(),
        });
        assert!(
            decoded.validate().is_err(),
            "a persisted rejected receipt cannot retain node evidence independently of provenance"
        );
    }

    #[test]
    fn source_validation_rejects_stale_cross_root_and_escaping_paths() {
        let mut stale = source(CodeMapContextKind::TargetedRecall);
        stale.stale = true;
        assert!(stale.validate().is_err());

        let first = source(CodeMapContextKind::TargetedRecall);
        let mut other_root = source(CodeMapContextKind::RepoMapSummary);
        other_root.root = "C:/other".to_owned();
        assert!(
            PreparedCodeMapContext::new("context".to_owned(), vec![first, other_root]).is_err()
        );

        let mut escaping = source(CodeMapContextKind::TargetedRecall);
        escaping.selected_files[0].path = "../secret.rs".to_owned();
        assert!(escaping.validate().is_err());
    }

    #[test]
    fn prepared_context_redacts_metadata_and_refuses_raw_or_mutable_identity() {
        let root_secret = "sk-proj-0123456789abcdefghijklmnop";
        let path_secret = "ghp_123456789012345678901234567890";
        let aws_secret = "AKIA1234567890ABCDEF";
        let mut raw = source(CodeMapContextKind::TargetedRecall);
        raw.root = format!("C:/repo/{root_secret}");
        raw.selected_files[0].path = format!("src/{path_secret}.rs");
        raw.selected_files[0].symbols = vec![aws_secret.to_owned()];
        raw.callers[0].target_symbol = root_secret.to_owned();
        raw.callers[0].caller_symbol = path_secret.to_owned();
        raw.callers[0].caller_path = format!("src/{aws_secret}.rs");
        assert!(
            raw.validate().is_err(),
            "public raw metadata cannot bypass validation"
        );

        let prepared = PreparedCodeMapContext::new("context".to_owned(), vec![raw]).unwrap();
        let sanitized_source = &prepared.sources()[0];
        assert!(sanitized_source.metadata_redacted);
        let prepared_again =
            PreparedCodeMapContext::new("context".to_owned(), prepared.sources().to_vec()).unwrap();
        assert!(
            prepared_again.sources()[0].metadata_redacted,
            "metadata redaction provenance must survive repeated preparation"
        );
        let mut marker_without_flag = sanitized_source.clone();
        marker_without_flag.metadata_redacted = false;
        assert!(marker_without_flag.validate().is_err());
        let receipt = prepared
            .receipt(KanbanSessionId(1), 1, "operator", "context", "provider")
            .unwrap();
        let serialized = serde_json::to_string(&receipt).unwrap();
        for secret in [root_secret, path_secret, aws_secret] {
            assert!(!serialized.contains(secret), "raw metadata secret leaked");
        }
        assert!(serialized.contains("[REDACTED:"));

        let mut mutable_identity = source(CodeMapContextKind::TargetedRecall);
        mutable_identity.root_identity = root_secret.to_owned();
        assert!(
            PreparedCodeMapContext::new("context".to_owned(), vec![mutable_identity]).is_err(),
            "root identity must remain the exact physical-root identifier"
        );
    }

    #[test]
    fn receipt_hashes_exact_utf8_bytes_and_records_truncation_without_leaking_input() {
        let prepared = PreparedCodeMapContext::new(
            "é context".to_owned(),
            vec![source(CodeMapContextKind::TargetedRecall)],
        )
        .unwrap();
        let receipt = prepared
            .receipt(KanbanSessionId(42), 1, "operator 🔒", "é", "provider 🔒")
            .unwrap();
        assert_eq!(receipt.submitted_context_bytes, "é".len());
        assert!(receipt.context_truncated);
        assert_eq!(receipt.operator_prompt_sha256, sha256_hex("operator 🔒"));
        assert_eq!(receipt.submitted_context_sha256, sha256_hex("é"));

        let serialized = serde_json::to_string(&receipt).unwrap();
        assert!(!serialized.contains("operator 🔒"));
        assert!(!serialized.contains("provider 🔒"));
        assert!(!serialized.contains("é context"));
    }

    #[test]
    fn receipt_rejects_unknown_fields_and_noncanonical_digest() {
        let prepared = PreparedCodeMapContext::new(
            "context".to_owned(),
            vec![source(CodeMapContextKind::TargetedRecall)],
        )
        .unwrap();
        let mut receipt = prepared
            .receipt(KanbanSessionId(1), 1, "operator", "context", "provider")
            .unwrap();
        receipt.operator_prompt_sha256.make_ascii_uppercase();
        assert!(receipt.validate().is_err());

        let json = serde_json::to_string(
            &prepared
                .receipt(KanbanSessionId(1), 1, "o", "context", "p")
                .unwrap(),
        )
        .unwrap();
        let injected = json.replacen('}', ",\"raw_context\":\"leak\"}", 1);
        assert!(serde_json::from_str::<CodingCodeMapReceipt>(&injected).is_err());
    }
}
